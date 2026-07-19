use fforager_diagnostics_contract::*;
use std::error::Error;

fn schema(fill: char) -> Result<SchemaIdentity, ContractError> {
    SchemaIdentity::new(
        SchemaHashAlgorithm::Sha256,
        1,
        SchemaHash::new(fill.to_string().repeat(64))?,
    )
}

fn key() -> Result<SequenceKey, ContractError> {
    Ok(SequenceKey {
        producer_instance: ProducerInstanceId::new("producer-1")?,
        boot_session: BootSessionId::new("boot-1")?,
        channel: ChannelId::new("events")?,
    })
}

fn descriptor() -> Result<EventDescriptor, ContractError> {
    EventDescriptor::new(
        EventId::new("ff.event.request-started.v1")?,
        EventKind::RequestStarted,
        Criticality::Normal,
        Sensitivity::Internal,
        WatcherPolicy::PersistRedacted,
    )
}

fn envelope(fields: Vec<DiagnosticField>) -> Result<DiagnosticEnvelope, ContractError> {
    let sequence_key = key()?;
    let value = DiagnosticEnvelope {
        protocol: ProtocolVersion::new(1, 2)?,
        schema: schema('a')?,
        producer_instance: sequence_key.producer_instance.clone(),
        capability_id: CapabilityId::new("ff.capability.transport")?,
        sequence: SequenceIdentity::new(sequence_key, 1)?,
        observed_monotonic_ns: 100,
        descriptor: descriptor()?,
        fields,
    };
    value.validate()?;
    Ok(value)
}

fn health_snapshot(loops: Vec<LoopHealth>) -> Result<HealthSnapshot, ContractError> {
    Ok(HealthSnapshot {
        producer_instance: ProducerInstanceId::new("producer-1")?,
        boot_session: BootSessionId::new("boot-1")?,
        process_start_id: ProcessStartId::new("start-1")?,
        ferric_artifact_id: ArtifactId::new("ferric-artifact")?,
        watcher_artifact_id: ArtifactId::new("watcher-artifact")?,
        build_id: BuildId::new("build-1")?,
        protocol: ProtocolVersion::new(1, 0)?,
        schema: schema('a')?,
        observed_monotonic_ns: 1,
        last_admitted: None,
        last_durable: None,
        counters: HealthCounters::new(0, 0, 1, 0, 0, 0)?,
        lifecycle: LifecycleSnapshot::starting(),
        loops,
    })
}

#[test]
fn negotiation_selects_highest_mutual_minor_and_exact_schema() -> Result<(), Box<dyn Error>> {
    let producer = ProtocolOffer::new(
        CompatibilityRange::new(1, 1, 4)?,
        vec![schema('a')?, schema('b')?],
        false,
    )?;
    let watcher = ProtocolOffer::new(CompatibilityRange::new(1, 2, 3)?, vec![schema('b')?], false)?;
    let negotiated = producer.negotiate(&watcher)?;
    assert_eq!(negotiated.version, ProtocolVersion::new(1, 3)?);
    assert!(matches!(negotiated.schema, SchemaDisposition::Exact(_)));
    Ok(())
}

#[test]
fn negotiation_handles_schema_drift_and_rejects_incompatibility() -> Result<(), Box<dyn Error>> {
    let drift_a = ProtocolOffer::new(CompatibilityRange::new(1, 1, 2)?, vec![schema('a')?], true)?;
    let drift_b = ProtocolOffer::new(CompatibilityRange::new(1, 2, 3)?, vec![schema('b')?], true)?;
    assert!(matches!(
        drift_a.negotiate(&drift_b)?.schema,
        SchemaDisposition::CompatibleDrift
    ));

    let strict_b =
        ProtocolOffer::new(CompatibilityRange::new(1, 2, 3)?, vec![schema('b')?], false)?;
    assert_eq!(
        drift_a.negotiate(&strict_b),
        Err(ContractError::SchemaIncompatible)
    );

    let major_two =
        ProtocolOffer::new(CompatibilityRange::new(2, 1, 2)?, vec![schema('a')?], true)?;
    assert_eq!(
        drift_a.negotiate(&major_two),
        Err(ContractError::IncompatibleMajor)
    );

    let minor_four =
        ProtocolOffer::new(CompatibilityRange::new(1, 4, 5)?, vec![schema('a')?], true)?;
    assert_eq!(
        drift_a.negotiate(&minor_four),
        Err(ContractError::NoCompatibleMinor)
    );
    Ok(())
}

#[test]
fn invalid_versions_and_hashes_fail_closed() {
    assert_eq!(ProtocolVersion::new(0, 1), Err(ContractError::InvalidRange));
    assert_eq!(
        CompatibilityRange::new(0, 0, 0),
        Err(ContractError::InvalidRange)
    );
    assert_eq!(
        CompatibilityRange::new(1, 2, 1),
        Err(ContractError::InvalidRange)
    );
    assert_eq!(
        SchemaHash::new("ABC"),
        Err(ContractError::InvalidSchemaHash)
    );
    assert_eq!(
        SchemaHash::new("g".repeat(64)),
        Err(ContractError::InvalidSchemaHash)
    );
}

#[test]
fn unknown_mandatory_and_illegal_policy_are_rejected() -> Result<(), Box<dyn Error>> {
    let mandatory = EventDescriptor::new(
        EventId::new("ff.event.future")?,
        EventKind::Unknown {
            id: BoundedText::new("future")?,
            mandatory: true,
        },
        Criticality::Normal,
        Sensitivity::Public,
        WatcherPolicy::PersistRedacted,
    );
    assert_eq!(mandatory, Err(ContractError::UnknownMandatoryKind));

    let illegal_drop = EventDescriptor::new(
        EventId::new("ff.event.error")?,
        EventKind::Error,
        Criticality::Normal,
        Sensitivity::Public,
        WatcherPolicy::DropWithCounter,
    );
    assert_eq!(illegal_drop, Err(ContractError::IllegalEventPolicy));

    let illegal_terminal = EventDescriptor::new(
        EventId::new("ff.event.terminal")?,
        EventKind::Terminal,
        Criticality::Normal,
        Sensitivity::Public,
        WatcherPolicy::PersistRedacted,
    );
    assert_eq!(illegal_terminal, Err(ContractError::IllegalEventPolicy));
    Ok(())
}

#[test]
fn sequence_rejects_start_gap_duplicate_reorder_and_identity_change() -> Result<(), Box<dyn Error>>
{
    let stream = key()?;
    let mut tracker = SequenceTracker::new(stream.clone());
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(stream.clone(), 2)?),
        Err(ContractError::Sequence {
            fault: SequenceFault::InvalidStart
        })
    );
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(stream.clone(), 1)?)?,
        SequenceDisposition::First
    );
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(stream.clone(), 3)?),
        Err(ContractError::Sequence {
            fault: SequenceFault::Gap
        })
    );
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(stream.clone(), 1)?),
        Err(ContractError::Sequence {
            fault: SequenceFault::Duplicate
        })
    );
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(stream.clone(), 2)?)?,
        SequenceDisposition::Contiguous
    );
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(stream.clone(), 1)?),
        Err(ContractError::Sequence {
            fault: SequenceFault::Reordered
        })
    );
    let other = SequenceKey {
        channel: ChannelId::new("health")?,
        ..stream
    };
    assert_eq!(
        tracker.admit(&SequenceIdentity::new(other, 3)?),
        Err(ContractError::Sequence {
            fault: SequenceFault::IdentityChanged
        })
    );
    Ok(())
}

#[test]
fn sequence_replay_ack_and_exhaustion_are_bounded() -> Result<(), Box<dyn Error>> {
    let stream = key()?;
    let mut tracker = SequenceTracker::new(stream.clone());
    tracker.admit(&SequenceIdentity::new(stream.clone(), 1)?)?;
    tracker.admit(&SequenceIdentity::new(stream.clone(), 2)?)?;
    assert_eq!(
        tracker.admit_replay(&SequenceIdentity::new(stream.clone(), 1)?, 2)?,
        SequenceDisposition::Replay
    );
    assert_eq!(
        tracker.admit_replay(&SequenceIdentity::new(stream.clone(), 1)?, 1),
        Err(ContractError::Sequence {
            fault: SequenceFault::ReplayOutsideWindow
        })
    );
    assert_eq!(
        tracker.acknowledge_durable(3),
        Err(ContractError::Sequence {
            fault: SequenceFault::DurableAheadOfAdmitted
        })
    );
    tracker.acknowledge_durable(2)?;
    assert_eq!(
        tracker.acknowledge_durable(1),
        Err(ContractError::Sequence {
            fault: SequenceFault::DurableReordered
        })
    );
    let maximum = SequenceIdentity::new(stream, LAST_SEQUENCE)?;
    assert_eq!(
        maximum.checked_next(),
        Err(ContractError::Sequence {
            fault: SequenceFault::Exhausted
        })
    );
    Ok(())
}

#[test]
fn identifiers_text_and_schema_sets_are_bounded() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        CapabilityId::new("x".repeat(MAX_ID_BYTES + 1)),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::Identifier,
            ..
        })
    ));
    assert_eq!(
        CapabilityId::new("bad id"),
        Err(ContractError::InvalidIdentifier {
            field: "capability_id"
        })
    );
    assert!(matches!(
        BoundedText::new("x".repeat(MAX_TEXT_BYTES + 1)),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::Text,
            ..
        })
    ));

    assert_eq!(
        ProtocolOffer::new(CompatibilityRange::new(1, 0, 0)?, Vec::new(), false),
        Err(ContractError::Empty {
            field: "accepted_schemas"
        })
    );
    assert!(matches!(
        ProtocolOffer::new(
            CompatibilityRange::new(1, 0, 0)?,
            vec![schema('a')?; MAX_SCHEMA_IDENTITIES + 1],
            false,
        ),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::SchemaSet,
            ..
        })
    ));
    let duplicate_schema = schema('a')?;
    assert_eq!(
        ProtocolOffer::new(
            CompatibilityRange::new(1, 0, 0)?,
            vec![duplicate_schema.clone(), duplicate_schema],
            false,
        ),
        Err(ContractError::DuplicateSchema)
    );
    Ok(())
}

#[test]
fn envelope_frame_and_health_collections_are_bounded() -> Result<(), Box<dyn Error>> {
    let mut fields = Vec::new();
    for index in 0..=MAX_FIELDS {
        fields.push(DiagnosticField::public(
            BoundedText::new(format!("field-{index}"))?,
            BoundedText::new("value")?,
        )?);
    }
    let sequence_key = key()?;
    let oversized_envelope = DiagnosticEnvelope {
        protocol: ProtocolVersion::new(1, 0)?,
        schema: schema('a')?,
        producer_instance: sequence_key.producer_instance.clone(),
        capability_id: CapabilityId::new("ff.capability.test")?,
        sequence: SequenceIdentity::new(sequence_key, 1)?,
        observed_monotonic_ns: 1,
        descriptor: descriptor()?,
        fields,
    };
    assert!(matches!(
        oversized_envelope.validate(),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::Fields,
            ..
        })
    ));

    assert_eq!(
        decode_json_frame(b"{}", FrameCompleteness::Partial),
        Err(ContractError::PartialFrame)
    );
    assert_eq!(
        decode_json_frame(b"not-json", FrameCompleteness::Complete),
        Err(ContractError::MalformedFrame)
    );
    assert!(matches!(
        decode_json_frame(
            &vec![b'x'; MAX_FRAME_BYTES + 1],
            FrameCompleteness::Complete
        ),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::Frame,
            ..
        })
    ));

    let mut loops = Vec::new();
    for index in 0..=MAX_HEALTH_LOOPS {
        loops.push(LoopHealth::new(
            CapabilityId::new(format!("ff.capability.loop-{index}"))?,
            LoopState::Idle {
                expected_next_monotonic_ns: None,
                dependency: None,
            },
        ));
    }
    assert!(matches!(
        health_snapshot(loops)?.validate(),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::Loops,
            ..
        })
    ));
    Ok(())
}

#[test]
fn privacy_requires_producer_redaction_and_non_exportable_unknowns() -> Result<(), Box<dyn Error>> {
    let secret_plain = DiagnosticField::new(
        BoundedText::new("authorization")?,
        Sensitivity::Secret,
        ValueRepresentation::Plain {
            value: BoundedText::new("Bearer secret")?,
        },
    );
    assert_eq!(secret_plain, Err(ContractError::PrivacyViolation));

    let secret_redacted = DiagnosticField::redacted(
        BoundedText::new("authorization")?,
        Sensitivity::Secret,
        BoundedText::new("[redacted]")?,
    )?;
    assert!(matches!(
        secret_redacted.value,
        ValueRepresentation::Redacted { .. }
    ));

    assert_eq!(
        DiagnosticField::unknown_optional(
            BoundedText::new("future-secret")?,
            Sensitivity::Secret,
            12,
        ),
        Err(ContractError::PrivacyViolation)
    );
    assert!(matches!(
        DiagnosticField::unknown_optional(
            BoundedText::new("future")?,
            Sensitivity::Internal,
            u32::try_from(MAX_OPAQUE_VALUE_BYTES + 1)?,
        ),
        Err(ContractError::LimitExceeded {
            kind: LimitKind::OpaqueValue,
            ..
        })
    ));
    Ok(())
}

#[test]
fn wire_round_trip_validates_and_rejects_deserialization_bypasses() -> Result<(), Box<dyn Error>> {
    let field = DiagnosticField::public(BoundedText::new("method")?, BoundedText::new("GET")?)?;
    let value = envelope(vec![field])?;
    let encoded = encode_json_frame(&value)?;
    assert_eq!(
        decode_json_frame(&encoded, FrameCompleteness::Complete)?,
        value
    );
    let mut additive_minor: serde_json::Value = serde_json::from_slice(&encoded)?;
    additive_minor["future_optional"] = serde_json::json!({"opaque": true});
    assert_eq!(
        decode_json_frame(
            &serde_json::to_vec(&additive_minor)?,
            FrameCompleteness::Complete
        )?,
        value
    );

    let mut invalid_sequence = value.clone();
    invalid_sequence.sequence.sequence = 0;
    assert!(invalid_sequence.validate().is_err());
    assert!(encode_json_frame(&invalid_sequence).is_err());

    let invalid_range = br#"{"major":1,"minimum_minor":9,"maximum_minor":2}"#;
    assert!(serde_json::from_slice::<CompatibilityRange>(invalid_range).is_err());

    let plaintext_secret = br#"{"name":"authorization","sensitivity":"secret","value":{"representation":"plain","value":"secret"}}"#;
    assert!(serde_json::from_slice::<DiagnosticField>(plaintext_secret).is_err());

    let unknown_mandatory = br#"{"stable_id":"ff.event.future","kind":{"kind":"unknown","id":"future","mandatory":true},"criticality":"normal","sensitivity":"public","watcher_policy":"persist_redacted"}"#;
    assert!(serde_json::from_slice::<EventDescriptor>(unknown_mandatory).is_err());

    let mut unknown_envelope: serde_json::Value = serde_json::from_slice(&encoded)?;
    unknown_envelope["descriptor"]["kind"] = serde_json::json!({
        "kind": "unknown",
        "id": "future-event",
        "mandatory": true
    });
    let unknown_bytes = serde_json::to_vec(&unknown_envelope)?;
    assert_eq!(
        decode_json_frame(&unknown_bytes, FrameCompleteness::Complete),
        Err(ContractError::UnknownMandatoryKind)
    );
    Ok(())
}

#[test]
fn lifecycle_distinguishes_ready_serving_stale_drain_and_stop() -> Result<(), Box<dyn Error>> {
    let incomplete = ReadyEvidence {
        protocol_negotiated: CheckStatus::Passed,
        storage_self_test: CheckStatus::Passed,
        retention_policy: CheckStatus::Failed,
        watcher_canary: CheckStatus::Passed,
    };
    let starting = LifecycleSnapshot::starting();
    assert_eq!(
        starting.transition(LifecycleInput::LocalReady(incomplete)),
        Err(ContractError::MissingReadyEvidence)
    );
    let complete = ReadyEvidence {
        protocol_negotiated: CheckStatus::Passed,
        storage_self_test: CheckStatus::Passed,
        retention_policy: CheckStatus::Passed,
        watcher_canary: CheckStatus::Passed,
    };
    let ready = starting.transition(LifecycleInput::LocalReady(complete))?;
    assert_eq!(ready.state, WatcherState::Ready);
    let serving = ready.transition(LifecycleInput::ProducerCanary)?;
    assert_eq!(serving.state, WatcherState::Serving);
    let stale = serving.transition(LifecycleInput::MarkStale(ReasonCode::new(
        "heartbeat-missed",
    )?))?;
    assert!(matches!(stale.state, WatcherState::Stale { .. }));
    let recovered = stale.transition(LifecycleInput::RecoverServing)?;
    let draining = recovered.transition(LifecycleInput::BeginDrain)?;
    let stopped = draining.transition(LifecycleInput::Stop)?;
    assert_eq!(stopped.state, WatcherState::Stopped);
    assert_eq!(
        stopped.transition(LifecycleInput::Stop),
        Err(ContractError::InvalidTransition)
    );
    Ok(())
}

#[test]
fn loop_completion_and_queue_health_preserve_counter_invariants() -> Result<(), Box<dyn Error>> {
    let mut health = LoopHealth::new(
        CapabilityId::new("ff.capability.watcher-ingest")?,
        LoopState::Idle {
            expected_next_monotonic_ns: Some(10),
            dependency: None,
        },
    );
    assert_eq!(
        health.complete_admitted(1),
        Err(ContractError::CounterInvariant)
    );
    let generation = health.admit_work()?;
    health.complete_admitted(generation)?;
    assert_eq!(
        health.complete_admitted(generation),
        Err(ContractError::CounterInvariant)
    );
    health.record_responsiveness()?;

    assert!(HealthCounters::new(2, 3, 3, 0, 0, 0).is_ok());
    assert_eq!(
        HealthCounters::new(3, 2, 3, 0, 0, 0),
        Err(ContractError::CounterInvariant)
    );
    assert_eq!(
        HealthCounters::new(0, 0, 0, 0, 0, 0),
        Err(ContractError::CounterInvariant)
    );
    Ok(())
}

#[test]
fn crash_evidence_requires_matching_producer_and_terminal_retention() -> Result<(), Box<dyn Error>>
{
    let sequence = SequenceIdentity::new(key()?, 4)?;
    let crash = CrashEnvelope::new(
        sequence.key.producer_instance.clone(),
        ArtifactId::new("watcher-artifact")?,
        ExitKind::Signal { signal: 9 },
        500,
        Some(sequence),
    )?;
    assert_eq!(crash.retention, EvidenceRetention::Retained);
    let collected = crash.retention.acknowledge(CollectionAck {
        request_id: RequestId::new("collection-1")?,
        acknowledged_monotonic_ns: 600,
    })?;
    assert!(matches!(collected, EvidenceRetention::Collected { .. }));
    assert_eq!(collected.expire(700), Err(ContractError::RetentionTerminal));

    let mismatch = CrashEnvelope::new(
        ProducerInstanceId::new("another-producer")?,
        ArtifactId::new("watcher-artifact")?,
        ExitKind::Unknown,
        500,
        Some(SequenceIdentity::new(key()?, 1)?),
    );
    assert_eq!(
        mismatch,
        Err(ContractError::Sequence {
            fault: SequenceFault::IdentityChanged
        })
    );
    Ok(())
}
