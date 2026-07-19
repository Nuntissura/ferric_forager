use crate::{
    BootSessionId, ChannelId, ContractError, FIRST_SEQUENCE, LAST_SEQUENCE, LimitKind,
    MAX_SCHEMA_IDENTITIES, ProducerInstanceId, SequenceFault,
};
use serde::{Deserialize, Serialize};

/// Diagnostic protocol version. Major changes are incompatible; minor versions negotiate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ProtocolVersionWire")]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolVersionWire {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Creates a version with a nonzero protocol major.
    ///
    /// # Errors
    /// Returns [`ContractError`] for major zero.
    pub fn new(major: u16, minor: u16) -> Result<Self, ContractError> {
        if major == 0 {
            return Err(ContractError::InvalidRange);
        }
        Ok(Self { major, minor })
    }

    /// Revalidates a protocol version assembled by Rust code.
    ///
    /// # Errors
    /// Returns [`ContractError`] for major zero.
    pub fn validate(self) -> Result<(), ContractError> {
        Self::new(self.major, self.minor).map(|_| ())
    }
}

impl TryFrom<ProtocolVersionWire> for ProtocolVersion {
    type Error = ContractError;

    fn try_from(value: ProtocolVersionWire) -> Result<Self, Self::Error> {
        Self::new(value.major, value.minor)
    }
}

/// Inclusive minor-version range supported for one protocol major.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "CompatibilityRangeWire")]
pub struct CompatibilityRange {
    pub major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityRangeWire {
    major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
}

impl CompatibilityRange {
    /// Creates an inclusive minor range for a nonzero major version.
    ///
    /// # Errors
    /// Returns [`ContractError`] for major zero or an inverted minor range.
    pub fn new(major: u16, minimum_minor: u16, maximum_minor: u16) -> Result<Self, ContractError> {
        if major == 0 || minimum_minor > maximum_minor {
            return Err(ContractError::InvalidRange);
        }
        Ok(Self {
            major,
            minimum_minor,
            maximum_minor,
        })
    }

    /// Revalidates a compatibility range assembled by Rust code.
    ///
    /// # Errors
    /// Returns [`ContractError`] for major zero or an inverted range.
    pub fn validate(self) -> Result<(), ContractError> {
        Self::new(self.major, self.minimum_minor, self.maximum_minor).map(|_| ())
    }
}

impl TryFrom<CompatibilityRangeWire> for CompatibilityRange {
    type Error = ContractError;

    fn try_from(value: CompatibilityRangeWire) -> Result<Self, Self::Error> {
        Self::new(value.major, value.minimum_minor, value.maximum_minor)
    }
}

/// Canonical schema digest algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaHashAlgorithm {
    Sha256,
}

/// Lowercase 64-digit SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SchemaHash(String);

impl SchemaHash {
    /// Creates a canonical lowercase SHA-256 hexadecimal digest.
    ///
    /// # Errors
    /// Returns [`ContractError`] unless exactly 64 lowercase hexadecimal digits are supplied.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidSchemaHash);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SchemaHash {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SchemaHash> for String {
    fn from(value: SchemaHash) -> Self {
        value.0
    }
}

/// Schema identity and the canonical-input revision hashed to produce it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "SchemaIdentityWire")]
pub struct SchemaIdentity {
    pub algorithm: SchemaHashAlgorithm,
    pub canonical_input_version: u16,
    pub digest: SchemaHash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaIdentityWire {
    algorithm: SchemaHashAlgorithm,
    canonical_input_version: u16,
    digest: SchemaHash,
}

impl SchemaIdentity {
    /// Creates a schema identity over a nonzero canonical-input revision.
    ///
    /// # Errors
    /// Returns [`ContractError`] for canonical-input revision zero.
    pub fn new(
        algorithm: SchemaHashAlgorithm,
        canonical_input_version: u16,
        digest: SchemaHash,
    ) -> Result<Self, ContractError> {
        if canonical_input_version == 0 {
            return Err(ContractError::InvalidRange);
        }
        Ok(Self {
            algorithm,
            canonical_input_version,
            digest,
        })
    }

    /// Revalidates a schema identity assembled by Rust code.
    ///
    /// # Errors
    /// Returns [`ContractError`] for canonical-input revision zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.canonical_input_version == 0 {
            return Err(ContractError::InvalidRange);
        }
        Ok(())
    }
}

impl TryFrom<SchemaIdentityWire> for SchemaIdentity {
    type Error = ContractError;

    fn try_from(value: SchemaIdentityWire) -> Result<Self, Self::Error> {
        Self::new(value.algorithm, value.canonical_input_version, value.digest)
    }
}

/// Protocol and schema compatibility offered by one peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ProtocolOfferWire")]
pub struct ProtocolOffer {
    pub versions: CompatibilityRange,
    pub accepted_schemas: Vec<SchemaIdentity>,
    pub allow_compatible_schema_drift: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolOfferWire {
    versions: CompatibilityRange,
    accepted_schemas: Vec<SchemaIdentity>,
    allow_compatible_schema_drift: bool,
}

impl ProtocolOffer {
    /// Creates a bounded peer compatibility offer.
    ///
    /// # Errors
    /// Returns [`ContractError`] when the schema set is empty or oversized.
    pub fn new(
        versions: CompatibilityRange,
        accepted_schemas: Vec<SchemaIdentity>,
        allow_compatible_schema_drift: bool,
    ) -> Result<Self, ContractError> {
        versions.validate()?;
        if accepted_schemas.is_empty() {
            return Err(ContractError::Empty {
                field: "accepted_schemas",
            });
        }
        if accepted_schemas.len() > MAX_SCHEMA_IDENTITIES {
            return Err(ContractError::LimitExceeded {
                kind: LimitKind::SchemaSet,
                limit: MAX_SCHEMA_IDENTITIES,
                actual: accepted_schemas.len(),
            });
        }
        for (index, schema) in accepted_schemas.iter().enumerate() {
            schema.validate()?;
            if accepted_schemas[..index].contains(schema) {
                return Err(ContractError::DuplicateSchema);
            }
        }
        Ok(Self {
            versions,
            accepted_schemas,
            allow_compatible_schema_drift,
        })
    }

    /// Negotiates the greatest mutually supported minor and schema relationship.
    ///
    /// # Errors
    /// Returns [`ContractError`] for major, minor, or schema incompatibility.
    pub fn negotiate(&self, peer: &Self) -> Result<NegotiatedProtocol, ContractError> {
        if self.versions.major != peer.versions.major {
            return Err(ContractError::IncompatibleMajor);
        }
        let minimum = self.versions.minimum_minor.max(peer.versions.minimum_minor);
        let maximum = self.versions.maximum_minor.min(peer.versions.maximum_minor);
        if minimum > maximum {
            return Err(ContractError::NoCompatibleMinor);
        }
        let exact_schema = self.accepted_schemas.iter().find(|schema| {
            peer.accepted_schemas
                .iter()
                .any(|candidate| candidate == *schema)
        });
        let schema = if let Some(identity) = exact_schema {
            SchemaDisposition::Exact(identity.clone())
        } else if self.allow_compatible_schema_drift && peer.allow_compatible_schema_drift {
            SchemaDisposition::CompatibleDrift
        } else {
            return Err(ContractError::SchemaIncompatible);
        };
        Ok(NegotiatedProtocol {
            version: ProtocolVersion {
                major: self.versions.major,
                minor: maximum,
            },
            schema,
        })
    }
}

impl TryFrom<ProtocolOfferWire> for ProtocolOffer {
    type Error = ContractError;

    fn try_from(value: ProtocolOfferWire) -> Result<Self, Self::Error> {
        Self::new(
            value.versions,
            value.accepted_schemas,
            value.allow_compatible_schema_drift,
        )
    }
}

/// Result of schema compatibility negotiation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaDisposition {
    Exact(SchemaIdentity),
    CompatibleDrift,
}

/// Negotiated protocol version and schema relationship.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiatedProtocol {
    pub version: ProtocolVersion,
    pub schema: SchemaDisposition,
}

/// Stable stream identity excluding its sequence number.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceKey {
    pub producer_instance: ProducerInstanceId,
    pub boot_session: BootSessionId,
    pub channel: ChannelId,
}

/// Full event identity used for ordering and durable acknowledgements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "SequenceIdentityWire")]
pub struct SequenceIdentity {
    pub key: SequenceKey,
    pub sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SequenceIdentityWire {
    key: SequenceKey,
    sequence: u64,
}

impl SequenceIdentity {
    /// Creates a legal nonzero sequence identity.
    ///
    /// # Errors
    /// Returns [`ContractError`] for sequence zero.
    pub fn new(key: SequenceKey, sequence: u64) -> Result<Self, ContractError> {
        if !(FIRST_SEQUENCE..=LAST_SEQUENCE).contains(&sequence) {
            return Err(ContractError::Sequence {
                fault: SequenceFault::InvalidStart,
            });
        }
        Ok(Self { key, sequence })
    }

    /// Revalidates a sequence identity that may have been constructed in memory.
    ///
    /// # Errors
    /// Returns [`ContractError`] when the sequence is zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !(FIRST_SEQUENCE..=LAST_SEQUENCE).contains(&self.sequence) {
            return Err(ContractError::Sequence {
                fault: SequenceFault::InvalidStart,
            });
        }
        Ok(())
    }

    /// Advances without wrapping.
    ///
    /// # Errors
    /// Returns [`ContractError`] when the sequence space is exhausted.
    pub fn checked_next(&self) -> Result<Self, ContractError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ContractError::Sequence {
                fault: SequenceFault::Exhausted,
            })?;
        Self::new(self.key.clone(), sequence)
    }
}

impl TryFrom<SequenceIdentityWire> for SequenceIdentity {
    type Error = ContractError;

    fn try_from(value: SequenceIdentityWire) -> Result<Self, Self::Error> {
        Self::new(value.key, value.sequence)
    }
}

/// Successful admission classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceDisposition {
    First,
    Contiguous,
    Replay,
}

/// Pure sequence validator. It stores only admitted and durable positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceTracker {
    key: SequenceKey,
    last_admitted: Option<u64>,
    last_durable: Option<u64>,
}

impl SequenceTracker {
    #[must_use]
    pub const fn new(key: SequenceKey) -> Self {
        Self {
            key,
            last_admitted: None,
            last_durable: None,
        }
    }

    /// Admits the first or next contiguous identity.
    ///
    /// # Errors
    /// Returns [`ContractError`] for identity changes, bad starts, duplicates, gaps, or reordering.
    pub fn admit(
        &mut self,
        identity: &SequenceIdentity,
    ) -> Result<SequenceDisposition, ContractError> {
        self.ensure_key(identity)?;
        match self.last_admitted {
            None if identity.sequence == FIRST_SEQUENCE => {
                self.last_admitted = Some(identity.sequence);
                Ok(SequenceDisposition::First)
            }
            None => Err(ContractError::Sequence {
                fault: SequenceFault::InvalidStart,
            }),
            Some(last) if identity.sequence == last => Err(ContractError::Sequence {
                fault: SequenceFault::Duplicate,
            }),
            Some(last) if identity.sequence < last => Err(ContractError::Sequence {
                fault: SequenceFault::Reordered,
            }),
            Some(last) => {
                let expected = last.checked_add(1).ok_or(ContractError::Sequence {
                    fault: SequenceFault::Exhausted,
                })?;
                if identity.sequence != expected {
                    return Err(ContractError::Sequence {
                        fault: SequenceFault::Gap,
                    });
                }
                self.last_admitted = Some(identity.sequence);
                Ok(SequenceDisposition::Contiguous)
            }
        }
    }

    /// Validates an explicit reconnect replay without advancing admission.
    ///
    /// # Errors
    /// Returns [`ContractError`] if no stream exists or the identity is outside the replay window.
    pub fn admit_replay(
        &self,
        identity: &SequenceIdentity,
        replay_window: u64,
    ) -> Result<SequenceDisposition, ContractError> {
        self.ensure_key(identity)?;
        let last = self.last_admitted.ok_or(ContractError::Sequence {
            fault: SequenceFault::ReplayOutsideWindow,
        })?;
        if identity.sequence > last || last.saturating_sub(identity.sequence) >= replay_window {
            return Err(ContractError::Sequence {
                fault: SequenceFault::ReplayOutsideWindow,
            });
        }
        Ok(SequenceDisposition::Replay)
    }

    /// Advances durability without passing admitted data or moving backward.
    ///
    /// # Errors
    /// Returns [`ContractError`] for ahead-of-admission or reordered acknowledgement.
    pub fn acknowledge_durable(&mut self, sequence: u64) -> Result<(), ContractError> {
        let admitted = self.last_admitted.ok_or(ContractError::Sequence {
            fault: SequenceFault::DurableAheadOfAdmitted,
        })?;
        if sequence > admitted {
            return Err(ContractError::Sequence {
                fault: SequenceFault::DurableAheadOfAdmitted,
            });
        }
        if self.last_durable.is_some_and(|durable| sequence < durable) {
            return Err(ContractError::Sequence {
                fault: SequenceFault::DurableReordered,
            });
        }
        self.last_durable = Some(sequence);
        Ok(())
    }

    #[must_use]
    pub const fn last_admitted(&self) -> Option<u64> {
        self.last_admitted
    }

    #[must_use]
    pub const fn last_durable(&self) -> Option<u64> {
        self.last_durable
    }

    fn ensure_key(&self, identity: &SequenceIdentity) -> Result<(), ContractError> {
        if identity.key != self.key {
            return Err(ContractError::Sequence {
                fault: SequenceFault::IdentityChanged,
            });
        }
        Ok(())
    }
}
