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
        AcquisitionSource, ArchiveCandidate, AssetId, BackpressureMode,
        CancellationAcknowledgement, CancellationRequest, CompatibilityRange, ConfigEnvelope,
        DerivedOutputId, ErrorEnvelope, EventEnvelope, ExtensionLimits, FilesystemCapability,
        FrameDecoder, FrameError, FrameLimits, GraphLimits, ItemId, JavaScriptWorkerEnvelope,
        OutputSinkSpec, PluginEnvelope, ProcessEnvelope, ProtocolLimits, RepresentationId,
        SchemaVersion, SinkSemantics, SourceGraph, TrackId,
    };
    use fforager_core::lifecycle::{Event, MachineKind, StateMachine};
    use fforager_core::resource::{Admission, OwnerId, ResourceLedger, ResourceVector};
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
        for required_id in [
            "FF-CONTRACT-ACQUISITION-001",
            "FF-CONTRACT-OUTPUT-SINK-001",
            "FF-CONTRACT-CONFIG-001",
            "FF-CONTRACT-EVENT-001",
            "FF-CONTRACT-ERROR-001",
            "FF-CONTRACT-CANCELLATION-001",
        ] {
            assert!(ids.contains(required_id), "inventory omits {required_id}");
        }
    }

    #[test]
    fn fixture_loader_rejects_parent_traversal() {
        assert!(matches!(
            read_fixture("../Cargo.toml"),
            Err(FixtureError::EscapesRoot)
        ));
    }

    #[test]
    fn canonical_wire_fixtures_decode_as_their_registered_contract_types() {
        let identities: serde_json::Value = serde_json::from_slice(
            &read_fixture("identity-set-v1.0.json").expect("identity fixture must load"),
        )
        .expect("identity fixture is JSON");
        assert!(ItemId::new(identities["item"].as_str().unwrap_or_default()).is_ok());
        assert!(
            RepresentationId::new(identities["representation"].as_str().unwrap_or_default())
                .is_ok()
        );
        assert!(TrackId::new(identities["track"].as_str().unwrap_or_default()).is_ok());
        assert!(AssetId::new(identities["asset"].as_str().unwrap_or_default()).is_ok());
        assert!(
            DerivedOutputId::new(identities["derived_output"].as_str().unwrap_or_default()).is_ok()
        );

        let graph: SourceGraph = serde_json::from_slice(
            &read_fixture("source-graph-v1.1.json").expect("graph fixture must load"),
        )
        .expect("graph fixture must decode");
        assert!(graph.validate(GraphLimits::default()).is_ok());
        let encoded = serde_json::to_vec(&graph).expect("graph must serialize");
        assert_eq!(
            serde_json::from_slice::<SourceGraph>(&encoded).ok(),
            Some(graph)
        );

        let process_bytes =
            read_fixture("process-request-v1.0.json").expect("process fixture must load");
        assert!(matches!(
            FrameDecoder::decode_process(&process_bytes, FrameLimits::default()),
            Ok(ProcessEnvelope::Request(_))
        ));

        let plugin: PluginEnvelope = serde_json::from_slice(
            &read_fixture("plugin-envelope-v1.0.json").expect("plugin fixture must load"),
        )
        .expect("plugin fixture must decode");
        assert!(plugin.validate(ProtocolLimits::default()).is_ok());
        let javascript: JavaScriptWorkerEnvelope = serde_json::from_slice(
            &read_fixture("javascript-worker-envelope-v1.0.json")
                .expect("javascript fixture must load"),
        )
        .expect("javascript fixture must decode");
        assert!(javascript.validate(ProtocolLimits::default()).is_ok());

        let archive: ArchiveCandidate = serde_json::from_slice(
            &read_fixture("archive-candidate-v1.0.json").expect("archive fixture must load"),
        )
        .expect("archive fixture must decode");
        assert!(archive.validate().is_ok());
        let filesystem: FilesystemCapability = serde_json::from_slice(
            &read_fixture("filesystem-capability-v1.0.json").expect("filesystem fixture must load"),
        )
        .expect("filesystem fixture must decode");
        assert!(filesystem.validate_secure_write().is_ok());

        let diagnostic_bytes =
            read_fixture("diagnostic-envelope-v1.2.json").expect("diagnostic fixture must load");
        assert!(
            diagnostics::decode_json_frame(
                &diagnostic_bytes,
                diagnostics::FrameCompleteness::Complete
            )
            .is_ok()
        );
        let offer: diagnostics::ProtocolOffer = serde_json::from_slice(
            &read_fixture("diagnostic-protocol-offer-v1.0.json")
                .expect("protocol offer fixture must load"),
        )
        .expect("protocol offer must decode");
        assert!(offer.negotiate(&offer).is_ok());
        let lifecycle: diagnostics::LifecycleSnapshot = serde_json::from_slice(
            &read_fixture("diagnostic-lifecycle-v1.0.json")
                .expect("diagnostic lifecycle fixture must load"),
        )
        .expect("diagnostic lifecycle must decode");
        assert_eq!(lifecycle, diagnostics::LifecycleSnapshot::starting());
    }

    #[test]
    fn canonical_public_contract_fixtures_decode_and_validate() {
        let acquisition_sink: serde_json::Value = serde_json::from_slice(
            &read_fixture("acquisition-sink-v1.0.json")
                .expect("acquisition and sink fixture must load"),
        )
        .expect("acquisition and sink fixture is JSON");
        let acquisition: AcquisitionSource =
            serde_json::from_value(acquisition_sink["source"].clone())
                .expect("acquisition source must decode");
        assert!(matches!(
            &acquisition,
            AcquisitionSource::DirectUrl { url } if !url.is_empty()
        ));
        let sink: OutputSinkSpec = serde_json::from_value(acquisition_sink["sink"].clone())
            .expect("output sink must decode");
        assert!(matches!(
            &sink,
            OutputSinkSpec::AtomicFile { rooted_path }
                if !rooted_path.is_empty()
                    && !Path::new(rooted_path).is_absolute()
                    && !Path::new(rooted_path).components().any(|component| matches!(
                        component,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    ))
        ));
        let semantics: SinkSemantics =
            serde_json::from_value(acquisition_sink["semantics"].clone())
                .expect("sink semantics must decode");
        assert_eq!(semantics.backpressure, BackpressureMode::BlockProducer);
        assert!(semantics.seekable && semantics.atomic);
        assert!(!semantics.postprocessing_requires_seekable_temporary);

        let config: ConfigEnvelope = serde_json::from_slice(
            &read_fixture("config-envelope-v1.0.json").expect("config fixture must load"),
        )
        .expect("config fixture must decode");
        assert!(config.header.validate(ProtocolLimits::default()).is_ok());
        assert!(config.compatibility.check(config.header.version).is_ok());
        assert!(config.values.validate(ExtensionLimits::default()).is_ok());

        let event: EventEnvelope = serde_json::from_slice(
            &read_fixture("event-envelope-v1.0.json").expect("event fixture must load"),
        )
        .expect("event fixture must decode");
        assert!(
            ProcessEnvelope::Event(event.clone())
                .validate(ProtocolLimits::default())
                .is_ok()
        );

        let error: ErrorEnvelope = serde_json::from_slice(
            &read_fixture("error-envelope-v1.0.json").expect("error fixture must load"),
        )
        .expect("error fixture must decode");
        assert!(
            ProcessEnvelope::Error(error.clone())
                .validate(ProtocolLimits::default())
                .is_ok()
        );

        let cancellation: serde_json::Value = serde_json::from_slice(
            &read_fixture("cancellation-v1.0.json").expect("cancellation fixture must load"),
        )
        .expect("cancellation fixture is JSON");
        let request: CancellationRequest = serde_json::from_value(cancellation["request"].clone())
            .expect("cancellation request must decode");
        let acknowledgement: CancellationAcknowledgement =
            serde_json::from_value(cancellation["acknowledgement"].clone())
                .expect("cancellation acknowledgement must decode");
        assert!(
            ProcessEnvelope::Cancel(request.clone())
                .validate(ProtocolLimits::default())
                .is_ok()
        );
        assert!(
            ProcessEnvelope::CancelAcknowledged(acknowledgement.clone())
                .validate(ProtocolLimits::default())
                .is_ok()
        );
        assert_eq!(request.target_request_id, acknowledgement.target_request_id);
        assert_eq!(request.generation, acknowledgement.generation);
        assert!(acknowledgement.header.sequence > request.header.sequence);

        let encoded = serde_json::to_vec(&(
            acquisition,
            sink,
            semantics,
            config,
            event,
            error,
            request,
            acknowledgement,
        ))
        .expect("canonical public contracts must serialize");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn lifecycle_fixture_replays_every_registered_machine() {
        let fixture: serde_json::Value = serde_json::from_slice(
            &read_fixture("lifecycle-scenarios-v1.0.json").expect("lifecycle fixture must load"),
        )
        .expect("lifecycle fixture must be JSON");
        let scenarios = fixture["scenarios"]
            .as_array()
            .expect("scenarios are required");
        assert_eq!(scenarios.len(), 12);
        for scenario in scenarios {
            let kind = machine_kind(scenario["machine_kind"].as_str().unwrap_or_default())
                .expect("registered machine kind");
            let events = scenario["events"].as_array().expect("events are required");
            let mut model = StateMachine::new(kind, events.len());
            for event in events {
                let event = lifecycle_event(event.as_str().unwrap_or_default())
                    .expect("registered lifecycle event");
                assert!(model.apply(event).is_ok());
            }
            assert_eq!(
                format!("{:?}", model.state()),
                scenario["expected_state"].as_str().unwrap_or_default()
            );
        }
    }

    #[test]
    fn resource_fixture_executes_exact_capacity_and_queues_one_over() {
        let fixture: serde_json::Value = serde_json::from_slice(
            &read_fixture("resource-boundary-scenario.json").expect("resource fixture must load"),
        )
        .expect("resource fixture must be JSON");
        let bytes = fixture["capacity"]["bytes"]
            .as_u64()
            .expect("capacity bytes");
        let mut ledger = ResourceLedger::new(
            ResourceVector {
                memory_bytes: bytes,
                ..ResourceVector::default()
            },
            1,
            2,
            bytes.saturating_add(1),
        );
        let requests = fixture["requests"]
            .as_array()
            .expect("requests are required");
        let first = ResourceVector {
            memory_bytes: requests[0]["bytes"].as_u64().expect("first bytes"),
            ..ResourceVector::default()
        };
        let second = ResourceVector {
            memory_bytes: requests[1]["bytes"].as_u64().expect("second bytes"),
            ..ResourceVector::default()
        };
        assert!(matches!(
            ledger.request(OwnerId(1), first),
            Ok(Admission::Granted(_))
        ));
        assert!(matches!(
            ledger.request(OwnerId(2), second),
            Ok(Admission::Queued(_))
        ));
        assert!(ledger.verify().is_ok());
    }

    fn machine_kind(value: &str) -> Option<MachineKind> {
        Some(match value {
            "JobCancellation" => MachineKind::JobCancellation,
            "SourceRedirect" => MachineKind::SourceRedirect,
            "AtomicAdmission" => MachineKind::AtomicAdmission,
            "ByteCreditDurability" => MachineKind::ByteCreditDurability,
            "Live" => MachineKind::Live,
            "Sink" => MachineKind::Sink,
            "Ffmpeg" => MachineKind::Ffmpeg,
            "JavascriptWorker" => MachineKind::JavascriptWorker,
            "PluginIpc" => MachineKind::PluginIpc,
            "CommitArchiveReconciliation" => MachineKind::CommitArchiveReconciliation,
            "FilesystemCapability" => MachineKind::FilesystemCapability,
            "Watcher" => MachineKind::Watcher,
            _ => return None,
        })
    }

    fn lifecycle_event(value: &str) -> Option<Event> {
        Some(match value {
            "Start" => Event::Start,
            "Assign" => Event::Assign,
            "Admit" => Event::Admit,
            "Receive" => Event::Receive,
            "Validate" => Event::Validate,
            "PersistDurably" => Event::PersistDurably,
            "Redirect" => Event::Redirect,
            "Continue" => Event::Continue,
            "Ready" => Event::Ready,
            "Serve" => Event::Serve,
            "Drain" => Event::Drain,
            "Spawn" => Event::Spawn,
            "Acknowledge" => Event::Acknowledge,
            "Prepare" => Event::Prepare,
            "Rename" => Event::Rename,
            "Archive" => Event::Archive,
            "Cleanup" => Event::Cleanup,
            "Reconcile" => Event::Reconcile,
            "Probe" => Event::Probe,
            "Confine" => Event::Confine,
            "Release" => Event::Release,
            "Complete" => Event::Complete,
            _ => return None,
        })
    }
}
