//! Typed configuration, event, error, cancellation, process, plugin, and worker envelopes.

use crate::{
    CompatibilityRange, ExtensionLimits, ExtensionMap, JobId, ProducerId, RequestId, SchemaVersion,
};
use serde::{Deserialize, Serialize};

/// Common envelope metadata used at every framed process boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeHeader {
    pub schema_id: String,
    pub version: SchemaVersion,
    pub request_id: RequestId,
    pub producer_id: ProducerId,
    pub job_id: Option<JobId>,
    pub sequence: u64,
}

/// Bounded product configuration crossing a public boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigEnvelope {
    pub header: EnvelopeHeader,
    pub compatibility: CompatibilityRange,
    pub values: ExtensionMap,
}

/// Stable event criticality controls legal loss behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCriticality {
    Telemetry,
    Operational,
    Terminal,
    Crash,
    InvariantBreach,
}

/// Typed event; `kind` is separately validated against the negotiated inventory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub header: EnvelopeHeader,
    pub kind: String,
    pub criticality: EventCriticality,
    pub sensitivity: Sensitivity,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Operational,
    SensitiveRedacted,
}

/// Stable failure categories safe to transport across process boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    UnsupportedVersion,
    UnknownMandatoryKind,
    ResourceExhausted,
    Cancelled,
    TimedOut,
    DependencyFailed,
    InvariantViolation,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub header: EnvelopeHeader,
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: ExtensionMap,
}

/// Cancellation command names the request and the latest acceptable completion generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequest {
    pub header: EnvelopeHeader,
    pub target_request_id: RequestId,
    pub generation: u64,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationOutcome {
    Accepted,
    AlreadyCompleted,
    AlreadyCancelled,
    UnknownRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationAcknowledgement {
    pub header: EnvelopeHeader,
    pub target_request_id: RequestId,
    pub generation: u64,
    pub outcome: CancellationOutcome,
}

/// Process protocol union. Unknown JSON tags fail deserialization as unknown mandatory kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProcessEnvelope {
    Hello(Hello),
    Request(ProcessRequest),
    Event(EventEnvelope),
    Error(ErrorEnvelope),
    Cancel(CancellationRequest),
    CancelAcknowledged(CancellationAcknowledgement),
    Goodbye(Goodbye),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub header: EnvelopeHeader,
    pub accepted: CompatibilityRange,
    pub artifact_id: String,
    pub schema_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRequest {
    pub header: EnvelopeHeader,
    pub operation: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Goodbye {
    pub header: EnvelopeHeader,
    pub completed: bool,
}

/// Plugin-specific wire request, nested inside a process request when applicable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum PluginMessage {
    Describe,
    Invoke {
        plugin_id: String,
        capability: String,
        input: serde_json::Value,
    },
    Result {
        output: serde_json::Value,
    },
    Failed {
        error: ErrorCode,
        message: String,
    },
}

/// JavaScript worker wire request. Source code and secrets are referenced, not embedded.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum JavaScriptWorkerMessage {
    Evaluate {
        program_reference: String,
        input: serde_json::Value,
        deadline_millis: u64,
        memory_limit_bytes: u64,
    },
    Result {
        output: serde_json::Value,
    },
    Failed {
        error: ErrorCode,
        message: String,
    },
    Cancelled {
        generation: u64,
    },
}

/// Validation limits applied after bounded framing and before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolLimits {
    pub maximum_schema_id_bytes: usize,
    pub maximum_kind_bytes: usize,
    pub maximum_message_bytes: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            maximum_schema_id_bytes: 128,
            maximum_kind_bytes: 128,
            maximum_message_bytes: 8 * 1024,
        }
    }
}

/// Protocol-level validation error independent of JSON syntax errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    FieldTooLong {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    UnknownMandatoryKind {
        kind: String,
    },
    DuplicateRequestId {
        request_id: RequestId,
    },
    InvalidSequence,
    InvalidVersion,
    IncompatibleVersion {
        received: SchemaVersion,
        accepted: CompatibilityRange,
    },
    InvalidExtensions,
    CorrelationMismatch {
        field: &'static str,
    },
}

impl EnvelopeHeader {
    /// Validates header-local bounds before dispatch.
    ///
    /// # Errors
    ///
    /// Returns a typed field or sequence error.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        validate_text("schema_id", &self.schema_id, limits.maximum_schema_id_bytes)?;
        if self.sequence == 0 {
            return Err(ProtocolError::InvalidSequence);
        }
        let major = self
            .schema_id
            .rsplit_once('@')
            .and_then(|(_, value)| value.parse::<u16>().ok());
        if major != Some(self.version.major) || self.version.major == 0 {
            return Err(ProtocolError::InvalidVersion);
        }
        Ok(())
    }
}

impl ConfigEnvelope {
    /// Validates the header/version relationship, compatibility range, and extension budget.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol error when any direct public-boundary field is invalid.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        validate_compatibility(self.header.version, self.compatibility)?;
        self.values
            .validate(ExtensionLimits::default())
            .map_err(|_| ProtocolError::InvalidExtensions)
    }
}

impl EventEnvelope {
    /// Validates direct event use outside a process-envelope decoder.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid headers, kinds, or payload bounds.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        validate_text("event_kind", &self.kind, limits.maximum_kind_bytes)?;
        validate_json("event_payload", &self.payload, limits.maximum_message_bytes)
    }
}

impl ErrorEnvelope {
    /// Validates direct error-envelope use and bounded extension details.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid headers, messages, or details.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        validate_text("error_message", &self.message, limits.maximum_message_bytes)?;
        self.details
            .validate(ExtensionLimits::default())
            .map_err(|_| ProtocolError::InvalidExtensions)
    }
}

impl CancellationRequest {
    /// Validates a direct cancellation request.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid headers, generations, or reasons.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        if self.generation == 0 {
            return Err(ProtocolError::InvalidSequence);
        }
        validate_text("cancel_reason", &self.reason, limits.maximum_message_bytes)
    }
}

impl CancellationAcknowledgement {
    /// Validates a direct cancellation acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid headers or generations.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        if self.generation == 0 {
            return Err(ProtocolError::InvalidSequence);
        }
        Ok(())
    }
}

/// Validates request/acknowledgement identity, version, generation, and sequence correlation.
///
/// # Errors
///
/// Returns a typed correlation error when the acknowledgement does not answer the request.
pub fn validate_cancellation_correlation(
    request: &CancellationRequest,
    acknowledgement: &CancellationAcknowledgement,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    request.validate(limits)?;
    acknowledgement.validate(limits)?;
    for (matches, field) in [
        (
            request.header.request_id == acknowledgement.header.request_id,
            "header.request_id",
        ),
        (
            request.header.schema_id == acknowledgement.header.schema_id,
            "header.schema_id",
        ),
        (
            request.header.version == acknowledgement.header.version,
            "header.version",
        ),
        (
            request.header.job_id == acknowledgement.header.job_id,
            "header.job_id",
        ),
        (
            request.target_request_id == acknowledgement.target_request_id,
            "target_request_id",
        ),
        (
            request.generation == acknowledgement.generation,
            "generation",
        ),
        (
            acknowledgement.header.sequence > request.header.sequence,
            "header.sequence",
        ),
    ] {
        if !matches {
            return Err(ProtocolError::CorrelationMismatch { field });
        }
    }
    Ok(())
}

impl ProcessEnvelope {
    /// Recursively validates every process-boundary field after deserialization.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid headers, over-limit strings/payloads, or extensions.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        match self {
            Self::Hello(value) => {
                value.header.validate(limits)?;
                validate_compatibility(value.header.version, value.accepted)?;
                validate_text("artifact_id", &value.artifact_id, limits.maximum_kind_bytes)?;
                validate_text("schema_hash", &value.schema_hash, limits.maximum_kind_bytes)
            }
            Self::Request(value) => {
                value.header.validate(limits)?;
                validate_text("operation", &value.operation, limits.maximum_kind_bytes)?;
                validate_json(
                    "request_payload",
                    &value.payload,
                    limits.maximum_message_bytes,
                )
            }
            Self::Event(value) => value.validate(limits),
            Self::Error(value) => value.validate(limits),
            Self::Cancel(value) => value.validate(limits),
            Self::CancelAcknowledged(value) => value.validate(limits),
            Self::Goodbye(value) => value.header.validate(limits),
        }
    }
}

/// Provenance required on isolated plugin and JavaScript-worker exchanges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryProvenance {
    pub artifact_id: String,
    pub schema_hash: String,
    pub capability_grant_id: String,
}

/// Complete plugin boundary envelope; callers cannot dispatch a bare plugin payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginEnvelope {
    pub header: EnvelopeHeader,
    pub compatibility: CompatibilityRange,
    pub provenance: BoundaryProvenance,
    pub message: PluginMessage,
}

/// Complete JavaScript-worker boundary envelope with explicit provenance and correlation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JavaScriptWorkerEnvelope {
    pub header: EnvelopeHeader,
    pub compatibility: CompatibilityRange,
    pub provenance: BoundaryProvenance,
    pub message: JavaScriptWorkerMessage,
}

impl PluginEnvelope {
    /// Validates plugin metadata and recursively bounded payloads.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol bound or header error.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        validate_compatibility(self.header.version, self.compatibility)?;
        validate_provenance(&self.provenance, limits)?;
        match &self.message {
            PluginMessage::Describe => Ok(()),
            PluginMessage::Invoke {
                plugin_id,
                capability,
                input,
            } => {
                validate_text("plugin_id", plugin_id, limits.maximum_kind_bytes)?;
                validate_text("plugin_capability", capability, limits.maximum_kind_bytes)?;
                validate_json("plugin_input", input, limits.maximum_message_bytes)
            }
            PluginMessage::Result { output } => {
                validate_json("plugin_output", output, limits.maximum_message_bytes)
            }
            PluginMessage::Failed { message, .. } => {
                validate_text("plugin_error", message, limits.maximum_message_bytes)
            }
        }
    }
}

impl JavaScriptWorkerEnvelope {
    /// Validates worker metadata and recursively bounded payloads.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol bound or header error.
    pub fn validate(&self, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        self.header.validate(limits)?;
        validate_compatibility(self.header.version, self.compatibility)?;
        validate_provenance(&self.provenance, limits)?;
        match &self.message {
            JavaScriptWorkerMessage::Evaluate {
                program_reference,
                input,
                deadline_millis,
                memory_limit_bytes,
            } => {
                validate_text(
                    "program_reference",
                    program_reference,
                    limits.maximum_kind_bytes,
                )?;
                if *deadline_millis == 0 || *memory_limit_bytes == 0 {
                    return Err(ProtocolError::InvalidSequence);
                }
                validate_json("javascript_input", input, limits.maximum_message_bytes)
            }
            JavaScriptWorkerMessage::Result { output } => {
                validate_json("javascript_output", output, limits.maximum_message_bytes)
            }
            JavaScriptWorkerMessage::Failed { message, .. } => {
                validate_text("javascript_error", message, limits.maximum_message_bytes)
            }
            JavaScriptWorkerMessage::Cancelled { generation } => {
                if *generation == 0 {
                    return Err(ProtocolError::InvalidSequence);
                }
                Ok(())
            }
        }
    }
}

fn validate_provenance(
    provenance: &BoundaryProvenance,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    for (field, value) in [
        ("artifact_id", &provenance.artifact_id),
        ("schema_hash", &provenance.schema_hash),
        ("capability_grant_id", &provenance.capability_grant_id),
    ] {
        validate_text(field, value, limits.maximum_kind_bytes)?;
    }
    Ok(())
}

fn validate_compatibility(
    version: SchemaVersion,
    compatibility: CompatibilityRange,
) -> Result<(), ProtocolError> {
    if compatibility.minimum_minor > compatibility.maximum_minor
        || compatibility.check(version).is_err()
    {
        return Err(ProtocolError::IncompatibleVersion {
            received: version,
            accepted: compatibility,
        });
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ProtocolError::FieldTooLong {
            field,
            actual: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn validate_json(
    field: &'static str,
    value: &serde_json::Value,
    maximum: usize,
) -> Result<(), ProtocolError> {
    let actual = serde_json::to_vec(value)
        .map_err(|_| ProtocolError::FieldTooLong {
            field,
            actual: usize::MAX,
            maximum,
        })?
        .len();
    if actual > maximum {
        return Err(ProtocolError::FieldTooLong {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

/// Bounded registry of request IDs for duplicate/replay detection.
#[derive(Clone, Debug)]
pub struct RequestRegistry {
    maximum_entries: usize,
    entries: std::collections::BTreeSet<RequestId>,
}

impl RequestRegistry {
    #[must_use]
    pub fn new(maximum_entries: usize) -> Self {
        Self {
            maximum_entries,
            entries: std::collections::BTreeSet::new(),
        }
    }

    /// Registers a request once. At capacity, callers must retire entries before accepting more.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when the ID is duplicated or the registry is full.
    pub fn register(&mut self, request_id: RequestId) -> Result<(), ProtocolError> {
        if self.entries.contains(&request_id) {
            return Err(ProtocolError::DuplicateRequestId { request_id });
        }
        if self.entries.len() >= self.maximum_entries {
            return Err(ProtocolError::FieldTooLong {
                field: "request_registry",
                actual: self.entries.len() + 1,
                maximum: self.maximum_entries,
            });
        }
        self.entries.insert(request_id);
        Ok(())
    }

    #[must_use]
    pub fn retire(&mut self, request_id: &RequestId) -> bool {
        self.entries.remove(request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(
        schema_id: &str,
        request_id: &str,
        sequence: u64,
    ) -> Result<EnvelopeHeader, crate::IdError> {
        Ok(EnvelopeHeader {
            schema_id: schema_id.into(),
            version: SchemaVersion { major: 1, minor: 0 },
            request_id: RequestId::new(request_id)?,
            producer_id: ProducerId::new("producer_test")?,
            job_id: Some(JobId::new("job_test")?),
            sequence,
        })
    }

    #[test]
    fn unknown_mandatory_process_kind_is_rejected() {
        let json = br#"{"kind":"future_required","body":{}}"#;
        let result = serde_json::from_slice::<ProcessEnvelope>(json);
        assert!(result.is_err());
    }

    #[test]
    fn direct_envelopes_enforce_version_and_payload_bounds() -> Result<(), crate::IdError> {
        let config = ConfigEnvelope {
            header: header("ff.config@1", "request_config", 1)?,
            compatibility: CompatibilityRange {
                major: 2,
                minimum_minor: 0,
                maximum_minor: 0,
            },
            values: ExtensionMap::default(),
        };
        assert!(matches!(
            config.validate(ProtocolLimits::default()),
            Err(ProtocolError::IncompatibleVersion { .. })
        ));

        let event = EventEnvelope {
            header: header("ff.event@1", "request_event", 1)?,
            kind: "progress".into(),
            criticality: EventCriticality::Operational,
            sensitivity: Sensitivity::Operational,
            payload: serde_json::Value::String("x".repeat(32)),
        };
        assert!(matches!(
            event.validate(ProtocolLimits {
                maximum_message_bytes: 8,
                ..ProtocolLimits::default()
            }),
            Err(ProtocolError::FieldTooLong {
                field: "event_payload",
                ..
            })
        ));
        let error = ErrorEnvelope {
            header: header("ff.error@1", "request_error", 1)?,
            code: ErrorCode::InvalidInput,
            message: String::new(),
            retryable: false,
            details: ExtensionMap::default(),
        };
        assert!(matches!(
            error.validate(ProtocolLimits::default()),
            Err(ProtocolError::FieldTooLong {
                field: "error_message",
                actual: 0,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn cancellation_validation_rejects_zero_and_mismatched_ack() -> Result<(), crate::IdError> {
        let target = RequestId::new("request_target")?;
        let request = CancellationRequest {
            header: header("ff.cancel@1", "request_cancel", 1)?,
            target_request_id: target.clone(),
            generation: 1,
            reason: "operator_cancelled".into(),
        };
        let zero = CancellationRequest {
            generation: 0,
            ..request.clone()
        };
        assert_eq!(
            zero.validate(ProtocolLimits::default()),
            Err(ProtocolError::InvalidSequence)
        );
        let mut acknowledgement = CancellationAcknowledgement {
            header: header("ff.cancel@1", "request_cancel", 2)?,
            target_request_id: target,
            generation: 1,
            outcome: CancellationOutcome::Accepted,
        };
        assert_eq!(
            validate_cancellation_correlation(
                &request,
                &acknowledgement,
                ProtocolLimits::default()
            ),
            Ok(())
        );
        acknowledgement.header.request_id = RequestId::new("request_other")?;
        assert_eq!(
            validate_cancellation_correlation(
                &request,
                &acknowledgement,
                ProtocolLimits::default()
            ),
            Err(ProtocolError::CorrelationMismatch {
                field: "header.request_id"
            })
        );
        Ok(())
    }
}
