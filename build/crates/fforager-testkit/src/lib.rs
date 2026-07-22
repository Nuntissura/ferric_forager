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
        CompatibilityRange, ConfigEnvelope, DerivedOutputId, DurabilityPosition, EdgeId, EdgeKind,
        ErrorEnvelope, EventEnvelope, ExtensionLimits, FilesystemCapability, FrameDecoder,
        FrameError, FrameLimits, GraphError, GraphLimits, ItemId, JavaScriptWorkerEnvelope,
        JournalRecord, OutputSinkSpec, PluginEnvelope, ProcessEnvelope, ProtocolLimits,
        RepresentationId, SchemaVersion, SinkSemantics, SourceEdge, SourceGraph, TrackId,
    };
    use fforager_core::lifecycle::{
        EffectAcknowledgement, EffectIntent, Event, MachineInstanceId, MachineKind, State,
        StateMachine, TransitionError, durable_states,
    };
    use fforager_core::resource::{
        Admission, ByteCreditLedger, CreditError, OwnerId, ResourceLedger, ResourceVector,
    };
    use fforager_diagnostics_contract as diagnostics;
    use std::collections::BTreeSet;

    const CANONICAL_INVENTORY_FNV1A64: u64 = 0x4500_038f_d33a_8d64;

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
                "testkit::tests::public_boundary_counterexamples_reject_audit_failures",
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
                "testkit::tests::public_boundary_counterexamples_reject_audit_failures",
            ),
            (
                "FF-CONTRACT-DIAGNOSTIC-PROTOCOL-001",
                "ProtocolOfferV1|ProtocolOffer|SequenceTracker",
                "testkit::tests::public_boundary_counterexamples_reject_audit_failures",
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
                "EffectPending|EffectRecovery|JobQueued|JobRunning|JobCancelling|JobVerifying|JobSucceeded|JobFailed|JobCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|verification intent cannot directly produce success|trace is bounded",
                "core::lifecycle::tests::success_and_durable_prefixes_require_effect_acknowledgements",
            ),
            (
                "FF-STATE-SOURCE-REDIRECT-001",
                "EffectPending|EffectRecovery|SourceNew|SourceResolving|SourceRedirecting|SourceResolved|SourceFailed|SourceCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|redirect resolution is explicit",
                "core::lifecycle::tests::every_named_lifecycle_has_a_success_path",
            ),
            (
                "FF-STATE-ADMISSION-001",
                "EffectPending|EffectRecovery|AdmissionWaiting|AdmissionGranted|AdmissionReleased|AdmissionCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|vector grants are atomic|capacity never underflows",
                "core::resource::tests::atomic_zero_exact_one_over_and_release_identity",
            ),
            (
                "FF-STATE-FRAGMENT-DURABILITY-001",
                "EffectPending|EffectRecovery|BytesEmpty|BytesReceived|BytesWriting|BytesWritten|BytesSynchronizing|BytesDurable|BytesFailed|BytesCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|write and synchronization effects require correlated acknowledgement|durable never exceeds validated or received|positions never regress|released unused credits cannot authorize receive|received-byte consumption is attributable to one claim owner|consumed claims cannot transfer ownership",
                "core::resource::tests::receive_requires_exact_claim_owner_and_records_attribution",
            ),
            (
                "FF-STATE-LIVE-001",
                "EffectPending|EffectRecovery|LiveStarting|LiveRefreshing|LiveStreaming|LiveStopped|LiveFailed|LiveCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|drain precedes stop",
                "core::lifecycle::tests::every_named_lifecycle_has_a_success_path",
            ),
            (
                "FF-STATE-SINK-001",
                "EffectPending|EffectRecovery|SinkPending|SinkActive|SinkDraining|SinkCompleted|SinkDropped|SinkFailed|SinkCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|partial output cannot be archived",
                "core::lifecycle::tests::failure_paths_complete_required_effects_before_their_outcome_state",
            ),
            (
                "FF-STATE-FFMPEG-001",
                "FfmpegPrepared|FfmpegSpawning|FfmpegSpawned|FfmpegRunning|FfmpegReaping|FfmpegCancelling|FfmpegFailing|FfmpegExitReleasing|FfmpegCancellationReleasing|FfmpegFailureReleasing|FfmpegSpawnRecovering|FfmpegReapRecovering|FfmpegCancellationRecovering|FfmpegFailureRecovering|FfmpegExitReleaseRecovering|FfmpegCancellationReleaseRecovering|FfmpegFailureReleaseRecovering|FfmpegExited|FfmpegFailed|FfmpegCancelled",
                "spawn, process cleanup, diagnostic preservation, and resource release effects require exact correlated outcomes|terminal success, cancellation, and failure await process and release-resource acknowledgement|all releasing and recovery states are non-durable|all original process cleanup outcomes settle before recovery; failed or cancelled effect outcomes require recovery acknowledgement and exact retry",
                "testkit::tests::public_boundary_counterexamples_reject_audit_failures",
            ),
            (
                "FF-STATE-JS-WORKER-001",
                "EffectPending|EffectRecovery|JavascriptIdle|JavascriptAssigned|JavascriptRunning|JavascriptRecycling|JavascriptQuarantined|JavascriptCompleted|JavascriptCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|terminal response is unique",
                "core::lifecycle::tests::illegal_transitions_are_typed_and_do_not_mutate_or_trace",
            ),
            (
                "FF-STATE-PLUGIN-IPC-001",
                "EffectPending|EffectRecovery|PluginDisconnected|PluginHandshaking|PluginReady|PluginInFlight|PluginDraining|PluginStopped|PluginFailed",
                "every emitted effect requires an exact correlated outcome before the target state is visible|negotiation precedes invoke",
                "core::lifecycle::tests::cancellation_paths_reach_expected_states",
            ),
            (
                "FF-STATE-COMMIT-ARCHIVE-001",
                "EffectPending|EffectRecovery|CommitWorking|CommitPreparing|CommitPrepared|CommitRenaming|CommitRenamed|CommitArchiving|CommitArchived|CommitCleaning|CommitCleaned|CommitReconciling|CommitVerifyingPrepared|CommitVerifyingRenamed|CommitVerifyingArchived|CommitVerifyingCleaned|CommitCancelling|CommitReconciled|CommitInconsistent|CommitCancelled",
                "every emitted effect requires an exact correlated outcome before the target state is visible|archive requires acknowledged rename|restart verification is acknowledged before archive or cleanup|restart never invents success|effect intent advances only after matching instance identity, effect, and generation acknowledgement|only enumerated durable prefixes can be restored",
                "core::lifecycle::tests::transient_restore_and_stale_or_wrong_acknowledgements_are_rejected",
            ),
            (
                "FF-STATE-FILESYSTEM-CAPABILITY-001",
                "FilesystemUnknown|FilesystemProbing|FilesystemProbed|FilesystemProbeFailed|FilesystemProbeCancelled|FilesystemConfining|FilesystemConfinementFailed|FilesystemConfinementCancelled|FilesystemConfined|FilesystemDegrading|FilesystemDegradationFailed|FilesystemDegradationCancelled|FilesystemDegraded|FilesystemRejecting|FilesystemRejectionFailed|FilesystemRejectionCancelled|FilesystemUnsupported|FilesystemCancelled",
                "probe, confinement, degradation reporting, and rejection effects require exact correlated outcomes|degraded never claims confinement|requested confinement is non-durable until correlated establishment acknowledgement|all failed and cancelled effect outcomes remain non-durable and recoverable",
                "testkit::tests::public_boundary_counterexamples_reject_audit_failures",
            ),
            (
                "FF-STATE-WATCHER-001",
                "EffectPending|EffectRecovery|WatcherStarting|WatcherReady|WatcherServing|WatcherDegraded|WatcherStale|WatcherDraining|WatcherStopped",
                "every emitted effect requires an exact correlated outcome before the target state is visible|readiness and producer canary are separate",
                "core::lifecycle::tests::cancellation_paths_reach_expected_states",
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
        canonical_wire_decodes_typed_identities();
        canonical_wire_decodes_source_graph();
        canonical_wire_decodes_process_and_worker_envelopes();
        canonical_wire_decodes_durability_and_filesystem_contracts();
        canonical_wire_decodes_diagnostics_contracts();
    }

    fn canonical_wire_decodes_typed_identities() {
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
    }

    fn canonical_wire_decodes_source_graph() {
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
    }

    fn canonical_wire_decodes_process_and_worker_envelopes() {
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
    }

    fn canonical_wire_decodes_durability_and_filesystem_contracts() {
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
    }

    fn canonical_wire_decodes_diagnostics_contracts() {
        let diagnostic_bytes =
            read_fixture("diagnostic-envelope-v1.2.json").expect("diagnostic fixture must load");
        assert!(
            diagnostics::decode_json_frame(
                &diagnostic_bytes,
                diagnostics::FrameCompleteness::Complete
            )
            .is_ok()
        );
        let legacy_offer: diagnostics::ProtocolOfferV1 = serde_json::from_slice(
            &read_fixture("diagnostic-protocol-offer-v1.0.json")
                .expect("protocol offer fixture must load"),
        )
        .expect("legacy protocol offer must decode");
        let offer = legacy_offer
            .into_v2()
            .expect("legacy protocol offer must migrate into v2");
        let current_offer: diagnostics::ProtocolOffer = serde_json::from_slice(
            &read_fixture("diagnostic-protocol-offer-v2.0.json")
                .expect("current protocol offer fixture must load"),
        )
        .expect("current protocol offer must decode");
        let strict_authority = diagnostics::SchemaCompatibilityAuthority::strict();
        assert!(offer.negotiate(&offer, strict_authority).is_ok());
        assert!(
            current_offer
                .negotiate(&current_offer, strict_authority)
                .is_ok()
        );
        let lifecycle: diagnostics::LifecycleSnapshot = serde_json::from_slice(
            &read_fixture("diagnostic-lifecycle-v1.0.json")
                .expect("diagnostic lifecycle fixture must load"),
        )
        .expect("diagnostic lifecycle must decode");
        assert_eq!(lifecycle, diagnostics::LifecycleSnapshot::starting());
    }

    #[test]
    fn public_boundary_counterexamples_reject_audit_failures() {
        public_boundary_rejects_source_graph_cycle();
        public_boundary_enforces_filesystem_effect_correlation();
        public_boundary_enforces_ffmpeg_terminal_effects();
        public_boundary_waits_for_all_ffmpeg_cleanup_outcomes_before_recovery();
        public_boundary_rejects_out_of_order_mixed_ffmpeg_cleanup_outcomes();
        public_boundary_rejects_diagnostics_counterexamples();
        public_boundary_requires_every_emitted_effect_to_clear_before_durability();
        println!(
            "FF-PUBLIC-COUNTEREXAMPLE-RECEIPT:v3:source-graph-cycle,filesystem-effect-correlation,ffmpeg-terminal-release,ffmpeg-partial-unsuccessful-outcomes,schema-authority,sequence-zero,unknown-envelope-field,nested-wire-unknown-fields,acknowledged-effect-prefixes"
        );
    }

    fn public_boundary_rejects_source_graph_cycle() {
        let mut graph: SourceGraph = serde_json::from_slice(
            &read_fixture("source-graph-v1.1.json").expect("graph fixture must load"),
        )
        .expect("graph fixture must decode");
        let root = graph.roots[0].clone();
        graph.edges.push(SourceEdge {
            id: EdgeId::new("edge_public_cycle").expect("stable edge id"),
            from: root.clone(),
            to: root,
            kind: EdgeKind::Contains,
        });
        assert!(matches!(
            graph.validate(GraphLimits::default()),
            Err(GraphError::RelationshipCycle { .. })
        ));
    }

    fn public_boundary_enforces_filesystem_effect_correlation() {
        let mut filesystem = StateMachine::new(
            MachineKind::FilesystemCapability,
            MachineInstanceId::new(901).expect("nonzero instance"),
            8,
        );
        assert!(filesystem.apply(Event::Probe).is_ok());
        assert_eq!(filesystem.state(), State::FilesystemProbing);
        acknowledge_all_pending_effects(&mut filesystem);
        assert_eq!(filesystem.state(), State::FilesystemProbed);
        assert!(filesystem.apply(Event::Confine).is_ok());
        assert_eq!(filesystem.state(), State::FilesystemConfining);
        assert_ne!(filesystem.state(), State::FilesystemConfined);
        let filesystem_ack = filesystem.pending_acknowledgements()[0];
        assert_eq!(filesystem_ack.effect, EffectIntent::EstablishConfinedPath);
        assert!(
            filesystem
                .apply(Event::EffectAcknowledged {
                    instance_id: filesystem_ack.instance_id,
                    effect: filesystem_ack.effect,
                    generation: filesystem_ack.generation,
                })
                .is_ok()
        );
        assert_eq!(filesystem.state(), State::FilesystemConfined);

        let mut failed_filesystem = StateMachine::new(
            MachineKind::FilesystemCapability,
            MachineInstanceId::new(903).expect("nonzero instance"),
            8,
        );
        assert!(failed_filesystem.apply(Event::Probe).is_ok());
        acknowledge_all_pending_effects(&mut failed_filesystem);
        assert!(failed_filesystem.apply(Event::Confine).is_ok());
        let failed_confinement = failed_filesystem.pending_acknowledgements()[0];
        assert!(
            failed_filesystem
                .apply(Event::EffectFailed {
                    instance_id: MachineInstanceId::new(904).expect("wrong nonzero instance"),
                    effect: failed_confinement.effect,
                    generation: failed_confinement.generation,
                })
                .is_err()
        );
        assert_eq!(failed_filesystem.state(), State::FilesystemConfining);
        assert!(
            failed_filesystem
                .apply(Event::EffectFailed {
                    instance_id: failed_confinement.instance_id,
                    effect: failed_confinement.effect,
                    generation: failed_confinement.generation,
                })
                .is_ok()
        );
        assert_eq!(
            failed_filesystem.state(),
            State::FilesystemConfinementFailed
        );
        assert_ne!(failed_filesystem.state(), State::FilesystemConfined);

        let mut cancelled_filesystem = StateMachine::new(
            MachineKind::FilesystemCapability,
            MachineInstanceId::new(905).expect("nonzero instance"),
            8,
        );
        assert!(cancelled_filesystem.apply(Event::Probe).is_ok());
        acknowledge_all_pending_effects(&mut cancelled_filesystem);
        assert!(cancelled_filesystem.apply(Event::Confine).is_ok());
        let cancellation = cancelled_filesystem.pending_acknowledgements()[0];
        let before_wrong_cancellation = cancelled_filesystem.clone();
        assert!(matches!(
            cancelled_filesystem.apply(Event::EffectCancelled {
                instance_id: MachineInstanceId::new(908).expect("wrong nonzero instance"),
                effect: cancellation.effect,
                generation: cancellation.generation,
            }),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
        assert_eq!(cancelled_filesystem, before_wrong_cancellation);
        assert!(matches!(
            cancelled_filesystem.apply(Event::EffectCancelled {
                instance_id: cancellation.instance_id,
                effect: cancellation.effect,
                generation: cancellation.generation.saturating_add(1),
            }),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
        assert_eq!(cancelled_filesystem, before_wrong_cancellation);
        assert!(
            cancelled_filesystem
                .apply(Event::EffectCancelled {
                    instance_id: cancellation.instance_id,
                    effect: cancellation.effect,
                    generation: cancellation.generation,
                })
                .is_ok()
        );
        assert_eq!(
            cancelled_filesystem.state(),
            State::FilesystemConfinementCancelled
        );
    }

    fn public_boundary_enforces_ffmpeg_terminal_effects() {
        public_boundary_requires_ffmpeg_cancellation_release();
        public_boundary_requires_ffmpeg_exit_release();
        public_boundary_requires_ffmpeg_failure_release();
    }

    fn public_boundary_waits_for_all_ffmpeg_cleanup_outcomes_before_recovery() {
        let cases: &[(&str, Event, State, State, &[EffectIntent])] = &[
            (
                "cancellation-cleanup",
                Event::Cancel,
                State::FfmpegCancellationRecovering,
                State::FfmpegCancelling,
                &[EffectIntent::TerminateProcess, EffectIntent::ReapProcess],
            ),
            (
                "failure-cleanup",
                Event::Fail,
                State::FfmpegFailureRecovering,
                State::FfmpegFailing,
                &[
                    EffectIntent::TerminateProcess,
                    EffectIntent::ReapProcess,
                    EffectIntent::PreserveDiagnostics,
                ],
            ),
        ];

        for (case_index, (label, start_cleanup, recovery, waiting, expected_reissue)) in
            cases.iter().enumerate()
        {
            for cancelled in [false, true] {
                for unsuccessful_index in 0..expected_reissue.len() {
                    let instance = 920 + (case_index as u64 * 16) + unsuccessful_index as u64;
                    let mut ffmpeg = StateMachine::new(
                        MachineKind::Ffmpeg,
                        MachineInstanceId::new(instance).expect("nonzero instance"),
                        24,
                    );
                    assert!(ffmpeg.apply(Event::Spawn).is_ok());
                    acknowledge_all_pending_effects(&mut ffmpeg);
                    assert!(ffmpeg.apply(Event::Start).is_ok());
                    assert!(ffmpeg.apply(*start_cleanup).is_ok());
                    let original = ffmpeg.pending_acknowledgements().to_vec();
                    assert_eq!(
                        original.iter().map(|ack| ack.effect).collect::<Vec<_>>(),
                        *expected_reissue,
                        "{label} must issue the complete cleanup set"
                    );

                    for acknowledgement in &original[..unsuccessful_index] {
                        assert!(
                            ffmpeg
                                .apply(Event::EffectAcknowledged {
                                    instance_id: acknowledgement.instance_id,
                                    effect: acknowledgement.effect,
                                    generation: acknowledgement.generation,
                                })
                                .is_ok()
                        );
                    }
                    let unsuccessful = original[unsuccessful_index];
                    let result = if cancelled {
                        ffmpeg.apply(Event::EffectCancelled {
                            instance_id: unsuccessful.instance_id,
                            effect: unsuccessful.effect,
                            generation: unsuccessful.generation,
                        })
                    } else {
                        ffmpeg.apply(Event::EffectFailed {
                            instance_id: unsuccessful.instance_id,
                            effect: unsuccessful.effect,
                            generation: unsuccessful.generation,
                        })
                    };
                    assert!(result.is_ok(), "{label} outcome must be correlated");

                    let remaining = original.len() - unsuccessful_index - 1;
                    if remaining > 0 {
                        assert_eq!(ffmpeg.state(), *waiting);
                        assert_eq!(ffmpeg.pending_acknowledgements().len(), remaining);
                        assert!(ffmpeg.apply(Event::Restart).is_err());
                        for acknowledgement in &original[unsuccessful_index + 1..] {
                            assert!(
                                ffmpeg
                                    .apply(Event::EffectAcknowledged {
                                        instance_id: acknowledgement.instance_id,
                                        effect: acknowledgement.effect,
                                        generation: acknowledgement.generation,
                                    })
                                    .is_ok()
                            );
                        }
                    }

                    assert_eq!(ffmpeg.state(), *recovery);
                    assert_eq!(ffmpeg.pending_acknowledgements().len(), 1);
                    assert_eq!(
                        ffmpeg.pending_acknowledgements()[0].effect,
                        EffectIntent::PreserveDiagnostics
                    );
                    acknowledge_all_pending_effects(&mut ffmpeg);
                    let retry = ffmpeg.apply(Event::Restart).expect("explicit exact retry");
                    assert_eq!(retry.next, *waiting);
                    assert_eq!(retry.effects, *expected_reissue);
                }
            }
        }
    }

    fn public_boundary_rejects_out_of_order_cancellation_cleanup_outcomes() {
        let mut cancelling = StateMachine::new(
            MachineKind::Ffmpeg,
            MachineInstanceId::new(950).expect("nonzero instance"),
            48,
        );
        assert!(cancelling.apply(Event::Spawn).is_ok());
        acknowledge_all_pending_effects(&mut cancelling);
        assert!(cancelling.apply(Event::Start).is_ok());
        assert!(cancelling.apply(Event::Cancel).is_ok());
        let original = cancelling.pending_acknowledgements().to_vec();
        let original_effects = original
            .iter()
            .map(|acknowledgement| acknowledgement.effect)
            .collect::<Vec<_>>();
        let original_generation = original[0].generation;
        let terminate = original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::TerminateProcess)
            .copied()
            .expect("terminate must be pending");
        let reap = original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::ReapProcess)
            .copied()
            .expect("reap must be pending");

        assert!(cancelling.apply(unsuccessful_outcome(false, reap)).is_ok());
        assert_eq!(cancelling.state(), State::FfmpegCancelling);
        assert_eq!(cancelling.pending_acknowledgements(), &[terminate]);
        let before_stale_reap = cancelling.clone();
        assert!(matches!(
            cancelling.apply(unsuccessful_outcome(false, reap)),
            Err(TransitionError::UnexpectedEffectFailure { .. })
        ));
        assert_eq!(cancelling, before_stale_reap);
        assert!(cancelling.apply(Event::Restart).is_err());

        assert!(
            cancelling
                .apply(unsuccessful_outcome(true, terminate))
                .is_ok()
        );
        assert_eq!(cancelling.state(), State::FfmpegCancellationRecovering);
        assert_eq!(
            cancelling.pending_acknowledgements()[0].effect,
            EffectIntent::PreserveDiagnostics
        );
        acknowledge_all_pending_effects(&mut cancelling);
        let retry = cancelling
            .apply(Event::Restart)
            .expect("every cancellation cleanup receipt settles before recovery retry");
        assert_eq!(retry.next, State::FfmpegCancelling);
        assert_eq!(retry.effects, original_effects);
        assert!(
            cancelling
                .pending_acknowledgements()
                .iter()
                .all(|acknowledgement| acknowledgement.generation != original_generation)
        );
    }

    fn public_boundary_rejects_out_of_order_failure_cleanup_outcomes() {
        let mut failing = StateMachine::new(
            MachineKind::Ffmpeg,
            MachineInstanceId::new(951).expect("nonzero instance"),
            64,
        );
        assert!(failing.apply(Event::Spawn).is_ok());
        acknowledge_all_pending_effects(&mut failing);
        assert!(failing.apply(Event::Fail).is_ok());
        let original = failing.pending_acknowledgements().to_vec();
        let original_effects = original
            .iter()
            .map(|acknowledgement| acknowledgement.effect)
            .collect::<Vec<_>>();
        let original_generation = original[0].generation;
        let terminate = original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::TerminateProcess)
            .copied()
            .expect("terminate must be pending");
        let reap = original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::ReapProcess)
            .copied()
            .expect("reap must be pending");
        let preserve = original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::PreserveDiagnostics)
            .copied()
            .expect("diagnostic preservation must be pending");

        assert!(failing.apply(unsuccessful_outcome(true, reap)).is_ok());
        assert_eq!(failing.state(), State::FfmpegFailing);
        assert_eq!(failing.pending_acknowledgements(), &[terminate, preserve]);
        assert!(failing.apply(unsuccessful_outcome(false, preserve)).is_ok());
        assert_eq!(failing.state(), State::FfmpegFailing);
        assert_eq!(failing.pending_acknowledgements(), &[terminate]);
        let before_stale_reap = failing.clone();
        assert!(matches!(
            failing.apply(unsuccessful_outcome(true, reap)),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
        assert_eq!(failing, before_stale_reap);
        assert!(failing.apply(Event::Restart).is_err());

        assert!(
            failing
                .apply(Event::EffectAcknowledged {
                    instance_id: terminate.instance_id,
                    effect: terminate.effect,
                    generation: terminate.generation,
                })
                .is_ok()
        );
        assert_eq!(failing.state(), State::FfmpegFailureRecovering);
        assert_eq!(
            failing.pending_acknowledgements()[0].effect,
            EffectIntent::PreserveDiagnostics
        );
        acknowledge_all_pending_effects(&mut failing);
        let retry = failing
            .apply(Event::Restart)
            .expect("every failure cleanup receipt settles before recovery retry");
        assert_eq!(retry.next, State::FfmpegFailing);
        assert_eq!(retry.effects, original_effects);
        assert!(
            failing
                .pending_acknowledgements()
                .iter()
                .all(|acknowledgement| acknowledgement.generation != original_generation)
        );
    }

    fn public_boundary_rejects_out_of_order_mixed_ffmpeg_cleanup_outcomes() {
        public_boundary_rejects_out_of_order_cancellation_cleanup_outcomes();
        public_boundary_rejects_out_of_order_failure_cleanup_outcomes();
    }

    fn public_boundary_requires_ffmpeg_cancellation_release() {
        let mut ffmpeg = StateMachine::new(
            MachineKind::Ffmpeg,
            MachineInstanceId::new(902).expect("nonzero instance"),
            12,
        );
        assert!(ffmpeg.apply(Event::Spawn).is_ok());
        acknowledge_all_pending_effects(&mut ffmpeg);
        assert!(ffmpeg.apply(Event::Start).is_ok());
        assert!(ffmpeg.apply(Event::Cancel).is_ok());
        let terminate = ffmpeg
            .pending_acknowledgements()
            .iter()
            .find(|ack| ack.effect == EffectIntent::TerminateProcess)
            .copied()
            .expect("terminate acknowledgement must be pending");
        assert!(
            ffmpeg
                .apply(Event::EffectAcknowledged {
                    instance_id: terminate.instance_id,
                    effect: terminate.effect,
                    generation: terminate.generation,
                })
                .is_ok()
        );
        assert_eq!(ffmpeg.state(), State::FfmpegCancelling);
        assert_ne!(ffmpeg.state(), State::FfmpegCancelled);
        assert_eq!(ffmpeg.pending_acknowledgements().len(), 1);
        let reap = ffmpeg.pending_acknowledgements()[0];
        assert_eq!(reap.effect, EffectIntent::ReapProcess);
        assert!(
            ffmpeg
                .apply(Event::EffectAcknowledged {
                    instance_id: reap.instance_id,
                    effect: reap.effect,
                    generation: reap.generation,
                })
                .is_ok()
        );
        assert_eq!(ffmpeg.state(), State::FfmpegCancellationReleasing);
        assert_ne!(ffmpeg.state(), State::FfmpegCancelled);
        let release = ffmpeg.pending_acknowledgements()[0];
        assert_eq!(release.effect, EffectIntent::ReleaseResources);
        assert!(
            ffmpeg
                .apply(Event::EffectAcknowledged {
                    instance_id: release.instance_id,
                    effect: release.effect,
                    generation: release.generation,
                })
                .is_ok()
        );
        assert_eq!(ffmpeg.state(), State::FfmpegCancelled);
    }

    fn public_boundary_requires_ffmpeg_exit_release() {
        let mut completed_ffmpeg = StateMachine::new(
            MachineKind::Ffmpeg,
            MachineInstanceId::new(906).expect("nonzero instance"),
            12,
        );
        assert!(completed_ffmpeg.apply(Event::Spawn).is_ok());
        acknowledge_all_pending_effects(&mut completed_ffmpeg);
        assert!(completed_ffmpeg.apply(Event::Start).is_ok());
        assert!(completed_ffmpeg.apply(Event::Complete).is_ok());
        let complete_reap = completed_ffmpeg.pending_acknowledgements()[0];
        assert!(
            completed_ffmpeg
                .apply(Event::EffectAcknowledged {
                    instance_id: complete_reap.instance_id,
                    effect: complete_reap.effect,
                    generation: complete_reap.generation,
                })
                .is_ok()
        );
        assert_eq!(completed_ffmpeg.state(), State::FfmpegExitReleasing);
        let complete_release = completed_ffmpeg.pending_acknowledgements()[0];
        assert_eq!(complete_release.effect, EffectIntent::ReleaseResources);
        assert!(
            completed_ffmpeg
                .apply(Event::EffectAcknowledged {
                    instance_id: complete_release.instance_id,
                    effect: complete_release.effect,
                    generation: complete_release.generation,
                })
                .is_ok()
        );
        assert_eq!(completed_ffmpeg.state(), State::FfmpegExited);
    }

    fn public_boundary_requires_ffmpeg_failure_release() {
        let mut failed_ffmpeg = StateMachine::new(
            MachineKind::Ffmpeg,
            MachineInstanceId::new(907).expect("nonzero instance"),
            12,
        );
        assert!(failed_ffmpeg.apply(Event::Spawn).is_ok());
        acknowledge_all_pending_effects(&mut failed_ffmpeg);
        assert!(failed_ffmpeg.apply(Event::Fail).is_ok());
        for acknowledgement in failed_ffmpeg.pending_acknowledgements().to_vec() {
            assert!(
                failed_ffmpeg
                    .apply(Event::EffectAcknowledged {
                        instance_id: acknowledgement.instance_id,
                        effect: acknowledgement.effect,
                        generation: acknowledgement.generation,
                    })
                    .is_ok()
            );
        }
        assert_eq!(failed_ffmpeg.state(), State::FfmpegFailureReleasing);
        let failure_release = failed_ffmpeg.pending_acknowledgements()[0];
        assert_eq!(failure_release.effect, EffectIntent::ReleaseResources);
        assert!(
            failed_ffmpeg
                .apply(Event::EffectAcknowledged {
                    instance_id: failure_release.instance_id,
                    effect: failure_release.effect,
                    generation: failure_release.generation,
                })
                .is_ok()
        );
        assert_eq!(failed_ffmpeg.state(), State::FfmpegFailed);
    }

    fn public_boundary_rejects_diagnostics_counterexamples() {
        let key = diagnostics::SequenceKey {
            producer_instance: diagnostics::ProducerInstanceId::new("producer-a")
                .expect("producer id"),
            boot_session: diagnostics::BootSessionId::new("boot-a").expect("boot id"),
            channel: diagnostics::ChannelId::new("diagnostic-a").expect("channel id"),
        };
        let mut tracker = diagnostics::SequenceTracker::new(key.clone());
        let first = diagnostics::SequenceIdentity::new(key.clone(), 1).expect("sequence one");
        assert!(tracker.admit(&first).is_ok());
        let zero_replay = diagnostics::SequenceIdentity { key, sequence: 0 };
        assert_eq!(
            tracker.admit_replay(&zero_replay, u64::MAX),
            Err(diagnostics::ContractError::Sequence {
                fault: diagnostics::SequenceFault::InvalidStart
            })
        );
        assert!(matches!(
            tracker.acknowledge_durable(0),
            Err(diagnostics::ContractError::Sequence {
                fault: diagnostics::SequenceFault::InvalidStart
            })
        ));

        let legacy_offer: diagnostics::ProtocolOfferV1 = serde_json::from_slice(
            &read_fixture("diagnostic-protocol-offer-v1.0.json")
                .expect("protocol offer fixture must load"),
        )
        .expect("legacy protocol offer must decode");
        let offer = legacy_offer
            .into_v2()
            .expect("legacy protocol offer must migrate into v2");
        let unrelated_schema = diagnostics::SchemaIdentity::new(
            diagnostics::SchemaHashAlgorithm::Sha256,
            3,
            diagnostics::SchemaHash::new(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .expect("canonical schema hash"),
        )
        .expect("schema identity");
        let current_offer: diagnostics::ProtocolOffer = serde_json::from_slice(
            &read_fixture("diagnostic-protocol-offer-v2.0.json")
                .expect("current protocol offer fixture must load"),
        )
        .expect("current target offer must decode");
        let strict_authority = diagnostics::SchemaCompatibilityAuthority::strict();
        assert!(matches!(
            offer.negotiate(&current_offer, strict_authority),
            Err(diagnostics::ContractError::SchemaIncompatible)
        ));
        assert!(matches!(
            current_offer.negotiate(&offer, strict_authority),
            Err(diagnostics::ContractError::SchemaIncompatible)
        ));
        let unrelated_offer =
            diagnostics::ProtocolOffer::new(offer.versions(), vec![unrelated_schema])
                .expect("unrelated target offer");
        assert!(matches!(
            offer.negotiate(&unrelated_offer, strict_authority),
            Err(diagnostics::ContractError::SchemaIncompatible)
        ));

        let mut envelope: serde_json::Value = serde_json::from_slice(
            &read_fixture("diagnostic-envelope-v1.2.json").expect("diagnostic fixture must load"),
        )
        .expect("diagnostic envelope fixture is JSON");
        envelope["undeclared_top_level"] = serde_json::json!(true);
        let encoded = serde_json::to_vec(&envelope).expect("mutated envelope serializes");
        assert!(
            diagnostics::decode_json_frame(&encoded, diagnostics::FrameCompleteness::Complete)
                .is_err()
        );
        assert_nested_envelope_unknown_fields_rejected();
        for fixture in [
            "diagnostic-protocol-offer-v1.0.json",
            "diagnostic-protocol-offer-v2.0.json",
        ] {
            let mut offer: serde_json::Value = serde_json::from_slice(
                &read_fixture(fixture).expect("protocol offer fixture must load"),
            )
            .expect("protocol offer fixture is JSON");
            offer["undeclared_nested"] = serde_json::json!(true);
            let encoded = serde_json::to_vec(&offer).expect("offer mutation serializes");
            if fixture.ends_with("v1.0.json") {
                assert!(serde_json::from_slice::<diagnostics::ProtocolOfferV1>(&encoded).is_err());
            } else {
                assert!(serde_json::from_slice::<diagnostics::ProtocolOffer>(&encoded).is_err());
            }
        }
    }

    fn assert_nested_envelope_unknown_fields_rejected() {
        for path in [
            ["sequence", "undeclared_nested"].as_slice(),
            ["descriptor", "undeclared_nested"].as_slice(),
            ["fields", "0", "undeclared_nested"].as_slice(),
        ] {
            let mut nested: serde_json::Value = serde_json::from_slice(
                &read_fixture("diagnostic-envelope-v1.2.json")
                    .expect("diagnostic fixture must load"),
            )
            .expect("diagnostic envelope fixture is JSON");
            if path[0] == "fields" {
                nested["fields"][0][path[2]] = serde_json::json!(true);
            } else {
                nested[path[0]][path[1]] = serde_json::json!(true);
            }
            let encoded = serde_json::to_vec(&nested).expect("nested mutation serializes");
            assert!(
                diagnostics::decode_json_frame(&encoded, diagnostics::FrameCompleteness::Complete)
                    .is_err(),
                "nested unknown field at {path:?} must fail closed"
            );
        }
    }

    fn acknowledge_all_pending_effects(machine: &mut StateMachine) {
        let mut observed = false;
        for _ in 0..64 {
            let pending = machine.pending_acknowledgements().to_vec();
            if pending.is_empty() {
                assert!(observed, "expected one or more pending effects");
                return;
            }
            observed = true;
            for acknowledgement in pending {
                assert!(
                    machine
                        .apply(Event::EffectAcknowledged {
                            instance_id: acknowledgement.instance_id,
                            effect: acknowledgement.effect,
                            generation: acknowledgement.generation,
                        })
                        .is_ok(),
                    "pending effect {:?} must acknowledge through its exact token",
                    acknowledgement.effect
                );
            }
        }
        panic!("effect acknowledgement chain exceeded the bounded public-test guard");
    }

    fn unsuccessful_outcome(cancelled: bool, acknowledgement: EffectAcknowledgement) -> Event {
        if cancelled {
            Event::EffectCancelled {
                instance_id: acknowledgement.instance_id,
                effect: acknowledgement.effect,
                generation: acknowledgement.generation,
            }
        } else {
            Event::EffectFailed {
                instance_id: acknowledgement.instance_id,
                effect: acknowledgement.effect,
                generation: acknowledgement.generation,
            }
        }
    }

    fn public_boundary_requires_every_emitted_effect_to_clear_before_durability() {
        let kinds = [
            MachineKind::JobCancellation,
            MachineKind::SourceRedirect,
            MachineKind::AtomicAdmission,
            MachineKind::ByteCreditDurability,
            MachineKind::Live,
            MachineKind::Sink,
            MachineKind::Ffmpeg,
            MachineKind::JavascriptWorker,
            MachineKind::PluginIpc,
            MachineKind::CommitArchiveReconciliation,
            MachineKind::FilesystemCapability,
            MachineKind::Watcher,
        ];
        let events = [
            Event::Start,
            Event::Assign,
            Event::Admit,
            Event::Receive,
            Event::Validate,
            Event::PersistDurably,
            Event::Redirect,
            Event::Continue,
            Event::Ready,
            Event::Serve,
            Event::Refresh,
            Event::Drain,
            Event::Spawn,
            Event::Reap,
            Event::Recycle,
            Event::Quarantine,
            Event::Prepare,
            Event::Rename,
            Event::Archive,
            Event::Cleanup,
            Event::Reconcile,
            Event::Probe,
            Event::Confine,
            Event::Degrade,
            Event::MarkStale,
            Event::Reject,
            Event::Release,
            Event::Complete,
            Event::Fail,
            Event::Cancel,
            Event::Restart,
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            let instance = MachineInstanceId::new(10_000 + u64::try_from(index).expect("index"))
                .expect("nonzero instance");
            let mut frontier = vec![StateMachine::new(kind, instance, 96)];
            let mut visited = BTreeSet::new();
            let mut observed_effect = false;
            for _ in 0..12 {
                let mut next_frontier = Vec::new();
                for machine in frontier {
                    for event in events {
                        let mut next = machine.clone();
                        if next.apply(event).is_err() {
                            continue;
                        }
                        if !next.pending_acknowledgements().is_empty() {
                            observed_effect = true;
                            assert!(
                                !durable_states(kind).contains(&next.state()),
                                "{kind:?} reached durable state {:?} with pending effects {:?}",
                                next.state(),
                                next.pending_acknowledgements()
                            );
                            acknowledge_all_pending_effects(&mut next);
                        }
                        let key =
                            format!("{:?}:{:?}", next.state(), next.pending_acknowledgements());
                        if visited.insert(key) {
                            next_frontier.push(next);
                        }
                    }
                }
                frontier = next_frontier;
                if frontier.is_empty() {
                    break;
                }
            }
            assert!(
                observed_effect,
                "{kind:?} emitted no discoverable required effect"
            );
        }
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
                let event_name = event.as_str().unwrap_or_default();
                if matches!(event_name, "EffectFailed" | "EffectCancelled") {
                    let acknowledgement = model.pending_acknowledgements()[0];
                    let outcome = if event_name == "EffectFailed" {
                        Event::EffectFailed {
                            instance_id: acknowledgement.instance_id,
                            effect: acknowledgement.effect,
                            generation: acknowledgement.generation,
                        }
                    } else {
                        Event::EffectCancelled {
                            instance_id: acknowledgement.instance_id,
                            effect: acknowledgement.effect,
                            generation: acknowledgement.generation,
                        }
                    };
                    assert!(model.apply(outcome).is_ok());
                    continue;
                }
                let event = lifecycle_event(event_name).expect("registered lifecycle event");
                if event == Event::Acknowledge {
                    assert!(
                        !model.pending_acknowledgements().is_empty(),
                        "fixture acknowledgement requires an effect: case={case}, machine={machine_name}, state={:?}",
                        model.state()
                    );
                    acknowledge_pending(&mut model);
                } else {
                    assert!(
                        model.apply(event).is_ok(),
                        "fixture event must be legal: case={case}, machine={machine_name}, event={event_name}, state={:?}",
                        model.state()
                    );
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
        let mut observed = false;
        for _ in 0..64 {
            let pending = model.pending_acknowledgements().to_vec();
            if pending.is_empty() {
                assert!(observed, "fixture acknowledgement requires an effect");
                return;
            }
            observed = true;
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
        panic!("fixture acknowledgement chain exceeded its bounded guard");
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
