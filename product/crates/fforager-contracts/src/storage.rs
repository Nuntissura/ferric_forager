//! Journal, commit/archive, durability, and filesystem-capability DTOs.

use crate::{AssetId, DerivedOutputId, JobId, SchemaVersion, TransactionId};
use serde::{Deserialize, Serialize};

/// Journal durability class selected by policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityClass {
    Fast,
    Balanced,
    Durable,
}

/// Ordered positions; validation requires durable <= validated <= received.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurabilityPosition {
    pub received_bytes: u64,
    pub validated_bytes: u64,
    pub durable_bytes: u64,
}

impl DurabilityPosition {
    /// Verifies the monotonic durable/validated/received ordering.
    ///
    /// # Errors
    ///
    /// Returns [`DurabilityError`] when a later stage is ahead of its prerequisite.
    pub fn validate(self) -> Result<(), DurabilityError> {
        if self.durable_bytes > self.validated_bytes {
            return Err(DurabilityError::DurableAheadOfValidated);
        }
        if self.validated_bytes > self.received_bytes {
            return Err(DurabilityError::ValidatedAheadOfReceived);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurabilityError {
    DurableAheadOfValidated,
    ValidatedAheadOfReceived,
}

/// Append-only journal record with hash-chain and payload checksum fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub schema: SchemaVersion,
    pub job_id: JobId,
    pub producer_instance: String,
    pub sequence: u64,
    pub prior_record_hash: Option<String>,
    pub payload_checksum: String,
    pub durability: DurabilityClass,
    pub payload: JournalPayload,
}

/// Stable journal payload kinds. Fields are descriptors, never open handles.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum JournalPayload {
    JobCreated,
    ExtractionCompleted {
        source_graph_digest: String,
    },
    SelectedFormats {
        representation_ids: Vec<String>,
    },
    OutputPlan {
        sink_count: usize,
    },
    ManifestIdentity {
        identity: String,
    },
    FragmentVerified {
        sequence: u64,
        bytes: u64,
        checksum: String,
    },
    OutputCheckpoint {
        position: DurabilityPosition,
    },
    FfmpegStarted {
        invocation_digest: String,
    },
    FfmpegCompleted {
        exit_code: i32,
    },
    FinalValidationCompleted {
        artifact_digest: String,
    },
    CommitPrepared(CommitPrepared),
    CommitRenamed(CommitRenamed),
    ArchiveCommitted(ArchiveCommitted),
    CleanupCompleted {
        retained_diagnostics: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPrepared {
    pub final_rooted_path: String,
    pub working_path_identity: String,
    pub artifacts: Vec<ArtifactIdentity>,
    pub required_sidecars: Vec<String>,
    pub filesystem_profile_id: String,
    pub data_synchronized: bool,
    pub parent_directory_synchronized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRenamed {
    pub final_identity: String,
    pub collision_decision: CollisionDecision,
    pub directory_synchronized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollisionDecision {
    CreatedNew,
    ReplacedAuthorized,
    ReusedIdentical,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCommitted {
    pub transaction_id: TransactionId,
    pub archive_row_id: String,
    pub asset_ids: Vec<AssetId>,
    pub derived_output_ids: Vec<DerivedOutputId>,
    pub output_provenance_digest: String,
    pub commit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub identity: String,
    pub size_bytes: u64,
    pub checksum: String,
}

/// Candidate output checked before archive insertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCandidate {
    pub artifact: ArtifactIdentity,
    pub completeness: ArtifactCompleteness,
    pub final_validation_passed: bool,
    pub committed_output_identity: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCompleteness {
    Partial,
    Complete,
}

impl ArchiveCandidate {
    /// Rejects partial, unvalidated, or uncommitted output before archive insertion.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveEligibilityError`] for the first unmet archive prerequisite.
    pub fn validate(&self) -> Result<(), ArchiveEligibilityError> {
        if self.completeness != ArtifactCompleteness::Complete {
            return Err(ArchiveEligibilityError::PartialOutput);
        }
        if !self.final_validation_passed {
            return Err(ArchiveEligibilityError::FinalValidationMissing);
        }
        if self.committed_output_identity.is_none() {
            return Err(ArchiveEligibilityError::CommittedIdentityMissing);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveEligibilityError {
    PartialOutput,
    FinalValidationMissing,
    CommittedIdentityMissing,
}

/// Durable commit prefix. Success is legal only after `Cleaned` reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitState {
    Collecting,
    Prepared,
    Renamed,
    Archived,
    Cleaned,
    Inconsistent,
}

/// Archive/output reconciliation observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReconcileState {
    BeforePrepared,
    PreparedNotRenamed,
    OutputWithoutArchive { final_identity: String },
    ArchiveWithoutOutput { archive_row_id: String },
    ArchivedNotCleaned,
    Reconciled,
    Inconsistent { reason: String },
}

/// Declared path-confinement and filesystem durability capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemCapability {
    pub profile_id: String,
    pub platform: PlatformFamily,
    pub filesystem: String,
    pub path_confinement: PathConfinement,
    pub atomic_replace: CapabilitySupport,
    pub file_sync: CapabilitySupport,
    pub directory_sync: CapabilitySupport,
    pub locking: CapabilitySupport,
    pub sparse_files: CapabilitySupport,
    pub case_sensitive: bool,
    pub unicode_normalization: UnicodeNormalization,
    pub maximum_path_bytes: Option<u32>,
    pub crash_recovery: CapabilitySupport,
    pub cross_volume_commit: CrossVolumeCommit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformFamily {
    Linux,
    Windows,
    MacOs,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathConfinement {
    RootHandleBeneathNoSymlink,
    RootHandleComponentWalk,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Supported,
    Degraded,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnicodeNormalization {
    None,
    Nfc,
    Nfd,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossVolumeCommit {
    CopySyncRenameNotAtomic,
    Unsupported,
}

impl FilesystemCapability {
    /// Security-sensitive writes fail closed if root-handle confinement is unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemCapabilityError::PathConfinementUnavailable`] when confinement is unsupported.
    pub fn validate_secure_write(&self) -> Result<(), FilesystemCapabilityError> {
        if self.path_confinement == PathConfinement::Unsupported {
            Err(FilesystemCapabilityError::PathConfinementUnavailable)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilesystemCapabilityError {
    PathConfinementUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_position_cannot_advance_past_data() {
        assert_eq!(
            DurabilityPosition {
                received_bytes: 9,
                validated_bytes: 10,
                durable_bytes: 9
            }
            .validate(),
            Err(DurabilityError::ValidatedAheadOfReceived)
        );
        assert_eq!(
            DurabilityPosition {
                received_bytes: 10,
                validated_bytes: 9,
                durable_bytes: 10
            }
            .validate(),
            Err(DurabilityError::DurableAheadOfValidated)
        );
    }

    #[test]
    fn unsupported_path_confinement_fails_closed() {
        let capability = FilesystemCapability {
            profile_id: "fixture".into(),
            platform: PlatformFamily::Other,
            filesystem: "unknown".into(),
            path_confinement: PathConfinement::Unsupported,
            atomic_replace: CapabilitySupport::Unsupported,
            file_sync: CapabilitySupport::Unsupported,
            directory_sync: CapabilitySupport::Unsupported,
            locking: CapabilitySupport::Unsupported,
            sparse_files: CapabilitySupport::Unsupported,
            case_sensitive: false,
            unicode_normalization: UnicodeNormalization::Unknown,
            maximum_path_bytes: None,
            crash_recovery: CapabilitySupport::Unsupported,
            cross_volume_commit: CrossVolumeCommit::Unsupported,
        };
        assert_eq!(
            capability.validate_secure_write(),
            Err(FilesystemCapabilityError::PathConfinementUnavailable)
        );
    }

    #[test]
    fn partial_output_is_archive_ineligible() {
        let candidate = ArchiveCandidate {
            artifact: ArtifactIdentity {
                identity: "partial".into(),
                size_bytes: 4,
                checksum: "hash".into(),
            },
            completeness: ArtifactCompleteness::Partial,
            final_validation_passed: true,
            committed_output_identity: Some("final".into()),
        };
        assert_eq!(
            candidate.validate(),
            Err(ArchiveEligibilityError::PartialOutput)
        );
    }
}
