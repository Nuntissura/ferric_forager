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
        AcquisitionSource, ArchiveCandidate, ArchiveCommitted, AssetId, BackpressureMode,
        CancellationAcknowledgement, CancellationRequest, CommitPrepared, CommitRenamed,
        CompatibilityRange, ConfigEnvelope, DerivedOutputId, DurabilityPosition, ErrorEnvelope,
        EventEnvelope, ExtensionLimits, FilesystemCapability, FrameDecoder, FrameError,
        FrameLimits, GraphLimits, ItemId, JavaScriptWorkerEnvelope, JournalRecord, OutputSinkSpec,
        PluginEnvelope, ProcessEnvelope, ProtocolLimits, RepresentationId, SchemaVersion,
        SinkSemantics, SourceGraph, TrackId,
    };
    use fforager_core::lifecycle::{
        Event, MachineInstanceId, MachineKind, StateMachine, TransitionError, durable_states,
    };
    use fforager_core::resource::{
        Admission, ByteCreditLedger, CreditError, OwnerId, ResourceLedger, ResourceVector,
    };
    use fforager_diagnostics_contract as diagnostics;
    use std::collections::BTreeSet;

    const CANONICAL_INVENTORY_FNV1A64: u64 = 0x1e27_ca36_4d14_9206;

    fn inventory_digest(bytes: &[u8]) -> u64 {
        bytes
            .iter()
            .filter(|byte| **byte != b'\r')
            .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            })
    }

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
    #[allow(clippy::too_many_lines)]
    fn inventory_is_unique_complete_and_references_existing_fixtures() {
        let bytes = read_fixture("inventory.json").expect("inventory must load");
        assert_eq!(
            inventory_digest(&bytes),
            CANONICAL_INVENTORY_FNV1A64,
            "canonical inventory byte digest drifted; every semantic change requires an explicit reviewed digest update"
        );
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
        let canonical_contracts = [
            (
                "FF-CONTRACT-IDENTITY-001",
                "ItemId|RepresentationId|TrackId|AssetId|DerivedOutputId",
                "contracts::identity::tests::typed_ids_reject_wrong_prefix_and_uppercase",
            ),
            (
                "FF-CONTRACT-SOURCE-GRAPH-001",
                "SourceGraph",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-ACQUISITION-001",
                "AcquisitionSource|FragmentDescriptor",
                "testkit::tests::canonical_public_contract_fixtures_decode_and_validate",
            ),
            (
                "FF-CONTRACT-OUTPUT-SINK-001",
                "OutputSinkSpec|SinkSemantics|PlayerTransport|BackpressureMode",
                "testkit::tests::canonical_public_contract_fixtures_decode_and_validate",
            ),
            (
                "FF-CONTRACT-TRISTATE-001",
                "TriState<T>",
                "contracts::graph::tests::round_trip_preserves_tri_state",
            ),
            (
                "FF-CONTRACT-EXTENSION-001",
                "ExtensionMap",
                "contracts::identity::tests::extensions_require_namespace_and_budget",
            ),
            (
                "FF-CONTRACT-CONFIG-001",
                "ConfigEnvelope",
                "testkit::tests::canonical_public_contract_fixtures_decode_and_validate",
            ),
            (
                "FF-CONTRACT-EVENT-001",
                "EventEnvelope|EventCriticality|Sensitivity",
                "testkit::tests::canonical_public_contract_fixtures_decode_and_validate",
            ),
            (
                "FF-CONTRACT-ERROR-001",
                "ErrorEnvelope|ErrorCode",
                "testkit::tests::canonical_public_contract_fixtures_decode_and_validate",
            ),
            (
                "FF-CONTRACT-CANCELLATION-001",
                "CancellationRequest|CancellationAcknowledgement|CancellationOutcome",
                "testkit::tests::canonical_public_contract_fixtures_decode_and_validate",
            ),
            (
                "FF-CONTRACT-PROCESS-001",
                "ProcessEnvelope",
                "testkit::tests::shared_framing_harness_covers_partial_oversized_and_unknown_kind",
            ),
            (
                "FF-CONTRACT-PLUGIN-IPC-001",
                "PluginMessage",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-JS-WORKER-001",
                "JavaScriptWorkerMessage",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-FRAMING-001",
                "FrameDecoder|ProcessConformance",
                "testkit::tests::shared_framing_harness_covers_partial_oversized_and_unknown_kind",
            ),
            (
                "FF-CONTRACT-DURABILITY-001",
                "JournalRecord|DurabilityPosition|CommitPrepared|CommitRenamed|ArchiveCommitted|ArchiveCandidate",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-FILESYSTEM-001",
                "FilesystemCapability|RootedPath",
                "contracts::storage::tests::unsupported_path_confinement_fails_closed",
            ),
            (
                "FF-CONTRACT-DIAGNOSTIC-ENVELOPE-001",
                "DiagnosticEnvelope|CrashEnvelope|DiagnosticAck",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-DIAGNOSTIC-PROTOCOL-001",
                "ProtocolOffer|SequenceTracker",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-DIAGNOSTIC-LIFECYCLE-001",
                "LifecycleSnapshot|HealthSnapshot|WatcherState",
                "testkit::tests::canonical_wire_fixtures_decode_as_their_registered_contract_types",
            ),
            (
                "FF-CONTRACT-RESOURCE-VECTOR-001",
                "ResourceVector|ResourceLedger|ByteCreditLedger|CreditAttribution",
                "core::resource::tests::receive_requires_exact_claim_owner_and_records_attribution",
            ),
        ];
        assert_eq!(entries.len(), canonical_contracts.len());
        for (id, rust_type, proof_id) in canonical_contracts {
            let row = entries
                .iter()
                .find(|row| row["id"] == id)
                .unwrap_or_else(|| panic!("missing canonical contract {id}"));
            assert_eq!(row["rust_type"], rust_type, "{id} rust_type drift");
            assert_eq!(row["proof_id"], proof_id, "{id} proof_id drift");
        }

        let canonical_states = [
            (
                "FF-STATE-JOB-CANCEL-001",
                "JobQueued|JobRunning|JobCancelling|JobVerifying|JobSucceeded|JobFailed|JobCancelled",
                "verification intent cannot directly produce success|trace is bounded",
                "core::lifecycle::tests::success_and_durable_prefixes_require_effect_acknowledgements",
            ),
            (
                "FF-STATE-SOURCE-REDIRECT-001",
                "SourceNew|SourceResolving|SourceRedirecting|SourceResolved|SourceFailed|SourceCancelled",
                "redirect resolution is explicit",
                "core::lifecycle::tests::every_named_lifecycle_has_a_success_path",
            ),
            (
                "FF-STATE-ADMISSION-001",
                "AdmissionWaiting|AdmissionGranted|AdmissionReleased|AdmissionCancelled",
                "vector grants are atomic|capacity never underflows",
                "core::resource::tests::atomic_zero_exact_one_over_and_release_identity",
            ),
            (
                "FF-STATE-FRAGMENT-DURABILITY-001",
                "BytesEmpty|BytesReceived|BytesWriting|BytesWritten|BytesSynchronizing|BytesDurable|BytesFailed|BytesCancelled",
                "write and synchronization effects require correlated acknowledgement|durable never exceeds validated or received|positions never regress|released unused credits cannot authorize receive|received-byte consumption is attributable to one claim owner|consumed claims cannot transfer ownership",
                "core::resource::tests::receive_requires_exact_claim_owner_and_records_attribution",
            ),
            (
                "FF-STATE-LIVE-001",
                "LiveStarting|LiveRefreshing|LiveStreaming|LiveStopped|LiveFailed|LiveCancelled",
                "drain precedes stop",
                "core::lifecycle::tests::every_named_lifecycle_has_a_success_path",
            ),
            (
                "FF-STATE-SINK-001",
                "SinkPending|SinkActive|SinkDraining|SinkCompleted|SinkDropped|SinkFailed|SinkCancelled",
                "partial output cannot be archived",
                "core::lifecycle::tests::failure_and_restart_preserve_diagnostics_and_reset_safely",
            ),
            (
                "FF-STATE-FFMPEG-001",
                "FfmpegPrepared|FfmpegSpawned|FfmpegRunning|FfmpegReaping|FfmpegCancelling|FfmpegExited|FfmpegFailed|FfmpegCancelled",
                "process effects are explicit",
                "core::lifecycle::tests::cancellation_paths_are_explicit_and_release_or_drain",
            ),
            (
                "FF-STATE-JS-WORKER-001",
                "JavascriptIdle|JavascriptAssigned|JavascriptRunning|JavascriptRecycling|JavascriptQuarantined|JavascriptCompleted|JavascriptCancelled",
                "terminal response is unique",
                "core::lifecycle::tests::illegal_transitions_are_typed_and_do_not_mutate_or_trace",
            ),
            (
                "FF-STATE-PLUGIN-IPC-001",
                "PluginDisconnected|PluginHandshaking|PluginReady|PluginInFlight|PluginDraining|PluginStopped|PluginFailed",
                "negotiation precedes invoke",
                "core::lifecycle::tests::cancellation_paths_are_explicit_and_release_or_drain",
            ),
            (
                "FF-STATE-COMMIT-ARCHIVE-001",
                "CommitWorking|CommitPreparing|CommitPrepared|CommitRenaming|CommitRenamed|CommitArchiving|CommitArchived|CommitCleaning|CommitCleaned|CommitReconciling|CommitVerifyingPrepared|CommitVerifyingRenamed|CommitVerifyingArchived|CommitVerifyingCleaned|CommitCancelling|CommitReconciled|CommitInconsistent|CommitCancelled",
                "archive requires acknowledged rename|restart verification is acknowledged before archive or cleanup|restart never invents success|effect intent advances only after matching instance identity, effect, and generation acknowledgement|only enumerated durable prefixes can be restored",
                "core::lifecycle::tests::transient_restore_and_stale_or_wrong_acknowledgements_are_rejected",
            ),
            (
                "FF-STATE-FILESYSTEM-CAPABILITY-001",
                "FilesystemUnknown|FilesystemProbing|FilesystemConfined|FilesystemDegraded|FilesystemUnsupported|FilesystemCancelled",
                "degraded never claims confinement",
                "core::lifecycle::tests::degraded_filesystem_never_claims_confinement",
            ),
            (
                "FF-STATE-WATCHER-001",
                "WatcherStarting|WatcherReady|WatcherServing|WatcherDegraded|WatcherStale|WatcherDraining|WatcherStopped",
                "readiness and producer canary are separate",
                "core::lifecycle::tests::cancellation_paths_are_explicit_and_release_or_drain",
            ),
        ];
        assert_eq!(states.len(), canonical_states.len());
        for (id, expected_states, expected_invariants, proof_id) in canonical_states {
            let row = states
                .iter()
                .find(|row| row["id"] == id)
                .unwrap_or_else(|| panic!("missing canonical state machine {id}"));
            assert_eq!(
                json_strings(&row["states"]),
                expected_states,
                "{id} state drift"
            );
            assert_eq!(
                json_strings(&row["invariants"]),
                expected_invariants,
                "{id} invariant drift"
            );
            assert_eq!(row["proof_id"], proof_id, "{id} proof_id drift");
            let expected_durable = durable_states(inventory_machine_kind(id))
                .iter()
                .map(|state| format!("{state:?}"))
                .collect::<Vec<_>>()
                .join("|");
            let expected_durable = if expected_durable.is_empty() {
                "none"
            } else {
                &expected_durable
            };
            assert_eq!(
                json_strings(&row["durable_prefixes"]),
                expected_durable,
                "{id} durable-prefix whitelist drift"
            );
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
    fn inventory_digest_rejects_semantic_field_mutations() {
        let bytes = read_fixture("inventory.json").expect("inventory must load");
        assert_eq!(inventory_digest(&bytes), CANONICAL_INVENTORY_FNV1A64);
        for field in [
            "version_policy",
            "limits_errors",
            "design_anchors",
            "residual_uncertainty",
            "preconditions",
            "postconditions",
            "invalid_transitions",
            "cancellation_outcomes",
            "durable_prefixes",
            "finite_assumptions",
        ] {
            let mut mutated = bytes.clone();
            let needle = field.as_bytes();
            let key_offset = mutated
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap_or_else(|| panic!("canonical inventory omits {field}"));
            let value_offset = key_offset
                + needle.len()
                + mutated[key_offset + needle.len()..]
                    .iter()
                    .position(u8::is_ascii_alphabetic)
                    .unwrap_or_else(|| panic!("{field} has no textual canonical value"));
            mutated[value_offset] ^= 0x20;
            assert_ne!(
                inventory_digest(&mutated),
                CANONICAL_INVENTORY_FNV1A64,
                "{field} mutation bypassed the canonical digest"
            );
        }
    }

    fn json_strings(value: &serde_json::Value) -> String {
        value
            .as_array()
            .expect("canonical field must be an array")
            .iter()
            .map(|value| value.as_str().expect("canonical item must be a string"))
            .collect::<Vec<_>>()
            .join("|")
    }

    fn inventory_machine_kind(id: &str) -> MachineKind {
        match id {
            "FF-STATE-JOB-CANCEL-001" => MachineKind::JobCancellation,
            "FF-STATE-SOURCE-REDIRECT-001" => MachineKind::SourceRedirect,
            "FF-STATE-ADMISSION-001" => MachineKind::AtomicAdmission,
            "FF-STATE-FRAGMENT-DURABILITY-001" => MachineKind::ByteCreditDurability,
            "FF-STATE-LIVE-001" => MachineKind::Live,
            "FF-STATE-SINK-001" => MachineKind::Sink,
            "FF-STATE-FFMPEG-001" => MachineKind::Ffmpeg,
            "FF-STATE-JS-WORKER-001" => MachineKind::JavascriptWorker,
            "FF-STATE-PLUGIN-IPC-001" => MachineKind::PluginIpc,
            "FF-STATE-COMMIT-ARCHIVE-001" => MachineKind::CommitArchiveReconciliation,
            "FF-STATE-FILESYSTEM-CAPABILITY-001" => MachineKind::FilesystemCapability,
            "FF-STATE-WATCHER-001" => MachineKind::Watcher,
            _ => panic!("unregistered inventory state-machine ID {id}"),
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

        let durability: serde_json::Value = serde_json::from_slice(
            &read_fixture("durability-contracts-v1.0.json").expect("durability fixture must load"),
        )
        .expect("durability fixture must be JSON");
        let position: DurabilityPosition = serde_json::from_value(durability["position"].clone())
            .expect("durability position must decode");
        assert!(position.validate().is_ok());
        let _: CommitPrepared = serde_json::from_value(durability["commit_prepared"].clone())
            .expect("prepared commit must decode");
        let _: CommitRenamed = serde_json::from_value(durability["commit_renamed"].clone())
            .expect("renamed commit must decode");
        let _: ArchiveCommitted = serde_json::from_value(durability["archive_committed"].clone())
            .expect("archive commit must decode");
        let _: JournalRecord = serde_json::from_value(durability["journal_record"].clone())
            .expect("journal record must decode");
        let durable_archive: ArchiveCandidate =
            serde_json::from_value(durability["archive_candidate"].clone())
                .expect("durability archive candidate must decode");
        assert!(durable_archive.validate().is_ok());
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
    #[allow(clippy::too_many_lines)]
    fn lifecycle_fixture_executes_success_failure_cancel_restart_and_invalid_paths() {
        let fixture: serde_json::Value = serde_json::from_slice(
            &read_fixture("lifecycle-scenarios-v1.0.json").expect("lifecycle fixture must load"),
        )
        .expect("lifecycle fixture must be JSON");
        let scenarios = fixture["scenarios"]
            .as_array()
            .expect("scenarios are required");
        let all_machines = [
            "JobCancellation",
            "SourceRedirect",
            "AtomicAdmission",
            "ByteCreditDurability",
            "Live",
            "Sink",
            "Ffmpeg",
            "JavascriptWorker",
            "PluginIpc",
            "CommitArchiveReconciliation",
            "FilesystemCapability",
            "Watcher",
        ];
        let restart_machines = [
            "JobCancellation",
            "SourceRedirect",
            "ByteCreditDurability",
            "Live",
            "Ffmpeg",
            "JavascriptWorker",
            "PluginIpc",
            "CommitArchiveReconciliation",
            "FilesystemCapability",
            "Watcher",
        ];
        let failure_machines = [
            "JobCancellation",
            "SourceRedirect",
            "ByteCreditDurability",
            "Live",
            "Sink",
            "Ffmpeg",
            "JavascriptWorker",
            "PluginIpc",
            "CommitArchiveReconciliation",
            "FilesystemCapability",
            "Watcher",
        ];
        let mut coverage = BTreeSet::new();
        for scenario in scenarios {
            let machine_name = scenario["machine_kind"].as_str().unwrap_or_default();
            let case = scenario["case"]
                .as_str()
                .expect("scenario case is required");
            let kind = machine_kind(machine_name).expect("registered machine kind");
            let events = scenario["events"].as_array().expect("events are required");
            let instance_id = MachineInstanceId::new(1).expect("fixture instance is nonzero");
            let mut model = StateMachine::new(
                kind,
                instance_id,
                events.len().saturating_mul(2).saturating_add(2),
            );
            for event in events {
                let event = lifecycle_event(event.as_str().unwrap_or_default())
                    .expect("registered lifecycle event");
                if event == Event::Acknowledge {
                    acknowledge_pending(&mut model);
                } else {
                    assert!(model.apply(event).is_ok());
                }
            }
            if case == "invalid" {
                let prior_state = model.state();
                let prior_trace_length = model.trace().len();
                let invalid = lifecycle_event(
                    scenario["invalid_event"]
                        .as_str()
                        .expect("invalid event is required"),
                )
                .expect("registered invalid lifecycle event");
                assert!(matches!(
                    model.apply(invalid),
                    Err(TransitionError::InvalidTransition { .. })
                ));
                assert_eq!(model.state(), prior_state);
                assert_eq!(model.trace().len(), prior_trace_length);
                assert_eq!(scenario["expected_error"], "InvalidTransition");
            }
            assert_eq!(
                format!("{:?}", model.state()),
                scenario["expected_state"].as_str().unwrap_or_default()
            );
            assert!(coverage.insert((case.to_owned(), machine_name.to_owned())));
        }
        for machine in all_machines {
            for case in ["success", "cancel", "invalid"] {
                assert!(
                    coverage.contains(&(case.to_owned(), machine.to_owned())),
                    "{machine} omits {case} coverage"
                );
            }
        }
        for machine in failure_machines {
            assert!(
                coverage.contains(&("failure".to_owned(), machine.to_owned())),
                "{machine} omits applicable failure coverage"
            );
        }
        for machine in restart_machines {
            assert!(
                coverage.contains(&("restart".to_owned(), machine.to_owned())),
                "{machine} omits applicable restart coverage"
            );
        }
    }

    #[test]
    fn resource_fixture_executes_all_dimensions_and_byte_credit_release() {
        let fixture: serde_json::Value = serde_json::from_slice(
            &read_fixture("resource-boundary-scenario.json").expect("resource fixture must load"),
        )
        .expect("resource fixture must be JSON");
        let capacity = resource_vector(&fixture["capacity"]);
        let mut ledger = ResourceLedger::new(capacity, 1, 2, u64::MAX);
        let requests = fixture["requests"]
            .as_array()
            .expect("requests are required");
        let first = resource_vector(&requests[0]);
        let second = resource_vector(&requests[1]);
        assert_eq!(
            first, capacity,
            "fixture must exercise every exact-capacity dimension"
        );
        assert!(matches!(
            ledger.request(OwnerId(1), first),
            Ok(Admission::Granted(_))
        ));
        assert!(matches!(
            ledger.request(OwnerId(2), second),
            Ok(Admission::Queued(_))
        ));
        assert!(ledger.verify().is_ok());

        let credit_fixture = &fixture["byte_credit"];
        let capacity = credit_fixture["capacity"]
            .as_u64()
            .expect("credit capacity");
        let claim_bytes = credit_fixture["claim_bytes"].as_u64().expect("claim bytes");
        let received = credit_fixture["received_before_release"]
            .as_u64()
            .expect("received bytes");
        let mut credits = ByteCreditLedger::new(capacity, 1);
        let claim = credits
            .claim(OwnerId(1), claim_bytes)
            .expect("claim must fit");
        assert!(credits.receive(claim, OwnerId(1), received).is_ok());
        assert!(
            credits
                .advance(DurabilityPosition {
                    received_bytes: received,
                    validated_bytes: received,
                    durable_bytes: received,
                })
                .is_ok()
        );
        assert!(credits.release(claim, OwnerId(1)).is_ok());
        assert!(matches!(
            credits.advance(DurabilityPosition {
                received_bytes: received.saturating_add(1),
                validated_bytes: received,
                durable_bytes: received,
            }),
            Err(CreditError::ReceivedBytesRequireClaim)
        ));
        assert!(credits.verify().is_ok());
    }

    fn acknowledge_pending(model: &mut StateMachine) {
        let pending = model.pending_acknowledgements().to_vec();
        assert!(
            !pending.is_empty(),
            "fixture acknowledgement requires an effect"
        );
        for acknowledgement in pending {
            assert!(
                model
                    .apply(Event::EffectAcknowledged {
                        instance_id: acknowledgement.instance_id,
                        effect: acknowledgement.effect,
                        generation: acknowledgement.generation,
                    })
                    .is_ok()
            );
        }
    }

    fn resource_vector(value: &serde_json::Value) -> ResourceVector {
        ResourceVector {
            metadata_requests: u32::try_from(
                value["metadata_requests"].as_u64().unwrap_or_default(),
            )
            .expect("metadata requests fit u32"),
            media_requests: u32::try_from(value["media_requests"].as_u64().unwrap_or_default())
                .expect("media requests fit u32"),
            memory_bytes: value["memory_bytes"].as_u64().expect("memory bytes"),
            disk_read_bytes_in_flight: value["disk_read_bytes_in_flight"]
                .as_u64()
                .expect("disk read bytes"),
            disk_write_bytes_in_flight: value["disk_write_bytes_in_flight"]
                .as_u64()
                .expect("disk write bytes"),
            open_handles: u32::try_from(value["open_handles"].as_u64().unwrap_or_default())
                .expect("open handles fit u32"),
            cpu_light_slots: u32::try_from(value["cpu_light_slots"].as_u64().unwrap_or_default())
                .expect("light slots fit u32"),
            cpu_heavy_slots: u32::try_from(value["cpu_heavy_slots"].as_u64().unwrap_or_default())
                .expect("heavy slots fit u32"),
            javascript_workers: u32::try_from(
                value["javascript_workers"].as_u64().unwrap_or_default(),
            )
            .expect("javascript workers fit u32"),
            ffmpeg_processes: u32::try_from(value["ffmpeg_processes"].as_u64().unwrap_or_default())
                .expect("ffmpeg processes fit u32"),
            ffmpeg_cpu_threads: u32::try_from(
                value["ffmpeg_cpu_threads"].as_u64().unwrap_or_default(),
            )
            .expect("ffmpeg threads fit u32"),
            archive_writer_slots: u32::try_from(
                value["archive_writer_slots"].as_u64().unwrap_or_default(),
            )
            .expect("archive slots fit u32"),
            sink_bytes: value["sink_bytes"].as_u64().expect("sink bytes"),
        }
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
            "Refresh" => Event::Refresh,
            "Drain" => Event::Drain,
            "Spawn" => Event::Spawn,
            "Reap" => Event::Reap,
            "Acknowledge" => Event::Acknowledge,
            "Recycle" => Event::Recycle,
            "Quarantine" => Event::Quarantine,
            "Prepare" => Event::Prepare,
            "Rename" => Event::Rename,
            "Archive" => Event::Archive,
            "Cleanup" => Event::Cleanup,
            "Reconcile" => Event::Reconcile,
            "Probe" => Event::Probe,
            "Confine" => Event::Confine,
            "Degrade" => Event::Degrade,
            "MarkStale" => Event::MarkStale,
            "Reject" => Event::Reject,
            "Release" => Event::Release,
            "Complete" => Event::Complete,
            "Fail" => Event::Fail,
            "Cancel" => Event::Cancel,
            "Restart" => Event::Restart,
            _ => return None,
        })
    }
}
