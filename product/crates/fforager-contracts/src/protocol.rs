//! Typed configuration, event, error, cancellation, process, plugin, and worker envelopes.

use crate::{CompatibilityRange, ExtensionMap, JobId, ProducerId, RequestId, SchemaVersion};
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
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
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

    #[test]
    fn unknown_mandatory_process_kind_is_rejected() {
        let json = br#"{"kind":"future_required","body":{}}"#;
        let result = serde_json::from_slice::<ProcessEnvelope>(json);
        assert!(result.is_err());
    }
}
