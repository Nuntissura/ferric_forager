//! Shared, non-shipped conformance helpers for versioned Ferric Forager contracts.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum size of one canonical conformance fixture.
pub const MAX_FIXTURE_BYTES: u64 = 1_048_576;

/// Fail-closed fixture loading errors.
#[derive(Debug)]
pub enum FixtureError {
    EscapesRoot,
    Io(std::io::Error),
    Oversized { actual: u64, maximum: u64 },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fixture error: {self:?}")
    }
}

impl std::error::Error for FixtureError {}

/// Returns the repository-local canonical contract fixture root.
#[must_use]
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/contracts")
}

/// Loads one bounded fixture without allowing absolute paths or parent traversal.
///
/// # Errors
///
/// Returns [`FixtureError`] for an unsafe path, I/O failure, or oversized fixture.
pub fn read_fixture(relative: &str) -> Result<Vec<u8>, FixtureError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(FixtureError::EscapesRoot);
    }
    let bytes = fs::read(fixture_root().join(path)).map_err(FixtureError::Io)?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > MAX_FIXTURE_BYTES {
        return Err(FixtureError::Oversized {
            actual,
            maximum: MAX_FIXTURE_BYTES,
        });
    }
    Ok(bytes)
}

/// Produces the canonical four-byte big-endian framing used by process protocols.
///
/// # Errors
///
/// Returns [`FixtureError::Oversized`] when the payload cannot be represented by the frame header.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, FixtureError> {
    let length = u32::try_from(payload.len()).map_err(|_| FixtureError::Oversized {
        actual: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        maximum: u64::from(u32::MAX),
    })?;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fforager_contracts::{
        CompatibilityRange, FrameDecoder, FrameError, FrameLimits, SchemaVersion,
    };
    use fforager_diagnostics_contract as diagnostics;
    use std::collections::BTreeSet;

    #[test]
    fn prior_and_current_wire_versions_are_accepted_but_next_major_is_rejected() {
        let supported = CompatibilityRange {
            major: 1,
            minimum_minor: 0,
            maximum_minor: 1,
        };
        for fixture in ["schema-version-v1.0.json", "schema-version-v1.1.json"] {
            let bytes = read_fixture(fixture).expect("registered fixture must load");
            let version: SchemaVersion =
                serde_json::from_slice(&bytes).expect("fixture is typed JSON");
            assert!(supported.check(version).is_ok());
        }
        let bytes = read_fixture("schema-version-v2.0.json").expect("registered fixture must load");
        let version: SchemaVersion = serde_json::from_slice(&bytes).expect("fixture is typed JSON");
        assert!(supported.check(version).is_err());
    }

    #[test]
    fn shared_framing_harness_covers_partial_oversized_and_unknown_kind() {
        let payload = read_fixture("unknown-mandatory-process-kind.json")
            .expect("registered fixture must load");
        assert!(matches!(
            FrameDecoder::decode_process(&payload, FrameLimits::default()),
            Err(FrameError::UnknownMandatoryKind { .. })
        ));

        let mut partial = FrameDecoder::new(FrameLimits::default());
        assert_eq!(
            partial.push(&[0, 0]).expect("prefix is accepted"),
            (2, None)
        );
        assert!(matches!(
            partial.finish(),
            Err(FrameError::PartialHeader { received: 2 })
        ));

        let mut oversized = FrameDecoder::new(FrameLimits {
            maximum_frame_bytes: 8,
        });
        assert!(matches!(
            oversized.push(&9_u32.to_be_bytes()),
            Err(FrameError::Oversized {
                declared: 9,
                maximum: 8
            })
        ));
    }

    #[test]
    fn diagnostic_version_range_rejects_invalid_and_incompatible_ranges() {
        assert!(diagnostics::CompatibilityRange::new(1, 0, 1).is_ok());
        assert!(diagnostics::CompatibilityRange::new(0, 0, 1).is_err());
        assert!(diagnostics::CompatibilityRange::new(1, 2, 1).is_err());
    }

    #[test]
    fn inventory_is_unique_complete_and_references_existing_fixtures() {
        let bytes = read_fixture("inventory.json").expect("inventory must load");
        let inventory: serde_json::Value =
            serde_json::from_slice(&bytes).expect("inventory must be JSON");
        assert_eq!(inventory["schema_id"], "ff.contract-inventory@1");
        let entries = inventory["entries"]
            .as_array()
            .expect("entries are required");
        let states = inventory["state_machines"]
            .as_array()
            .expect("state machines are required");
        assert!(entries.len() >= 12);
        assert!(states.len() >= 12);
        let mut ids = BTreeSet::new();
        for row in entries.iter().chain(states.iter()) {
            let id = row["id"].as_str().expect("stable ID is required");
            assert!(ids.insert(id), "duplicate inventory ID {id}");
            for key in ["owner", "proof_id", "readiness_gate"] {
                assert!(
                    !row[key].as_str().unwrap_or_default().is_empty(),
                    "{id} omits {key}"
                );
            }
            for fixture in row["fixture_ids"]
                .as_array()
                .expect("fixture IDs are required")
            {
                let fixture = fixture.as_str().expect("fixture ID must be a string");
                assert!(
                    fixture_root().join(fixture).is_file(),
                    "{id} fixture {fixture} is absent"
                );
            }
        }
    }

    #[test]
    fn fixture_loader_rejects_parent_traversal() {
        assert!(matches!(
            read_fixture("../Cargo.toml"),
            Err(FixtureError::EscapesRoot)
        ));
    }
}
