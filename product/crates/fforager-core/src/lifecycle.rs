//! Bounded deterministic lifecycle transition models and trace replay.

/// Every lifecycle required by WP-005 has one explicit model identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineKind {
    JobCancellation,
    SourceRedirect,
    AtomicAdmission,
    ByteCreditDurability,
    Live,
    Sink,
    Ffmpeg,
    JavascriptWorker,
    PluginIpc,
    CommitArchiveReconciliation,
    FilesystemCapability,
    Watcher,
}

/// Caller-supplied stable identity for one state-machine instance.
///
/// The value must remain unchanged across durable restoration. Callers must
/// allocate distinct values for concurrently routable instances.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MachineInstanceId(u64);

impl MachineInstanceId {
    /// Construct a nonzero instance identity.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The complete finite state space. Variants retain lifecycle-specific names so
/// traces remain unambiguous without ambient context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Generic non-durable wrapper while a lifecycle-owned adapter effect is pending.
    EffectPending,
    /// Generic non-durable recovery point after a correlated adapter effect outcome failed.
    EffectRecovery,
    JobQueued,
    JobRunning,
    JobCancelling,
    JobVerifying,
    JobSucceeded,
    JobFailed,
    JobCancelled,
    SourceNew,
    SourceResolving,
    SourceRedirecting,
    SourceResolved,
    SourceFailed,
    SourceCancelled,
    AdmissionWaiting,
    AdmissionGranted,
    AdmissionReleased,
    AdmissionCancelled,
    BytesEmpty,
    BytesReceived,
    BytesWriting,
    BytesWritten,
    BytesSynchronizing,
    BytesDurable,
    BytesFailed,
    BytesCancelled,
    LiveStarting,
    LiveRefreshing,
    LiveStreaming,
    LiveStopped,
    LiveFailed,
    LiveCancelled,
    SinkPending,
    SinkActive,
    SinkDraining,
    SinkCompleted,
    SinkDropped,
    SinkFailed,
    SinkCancelled,
    FfmpegPrepared,
    FfmpegSpawning,
    FfmpegSpawned,
    FfmpegRunning,
    FfmpegReaping,
    FfmpegCancelling,
    FfmpegFailing,
    FfmpegExitReleasing,
    FfmpegCancellationReleasing,
    FfmpegFailureReleasing,
    FfmpegSpawnRecovering,
    FfmpegReapRecovering,
    FfmpegCancellationRecovering,
    FfmpegFailureRecovering,
    FfmpegExitReleaseRecovering,
    FfmpegCancellationReleaseRecovering,
    FfmpegFailureReleaseRecovering,
    FfmpegExited,
    FfmpegFailed,
    FfmpegCancelled,
    JavascriptIdle,
    JavascriptAssigned,
    JavascriptRunning,
    JavascriptRecycling,
    JavascriptQuarantined,
    JavascriptCompleted,
    JavascriptCancelled,
    PluginDisconnected,
    PluginHandshaking,
    PluginReady,
    PluginInFlight,
    PluginDraining,
    PluginStopped,
    PluginFailed,
    CommitWorking,
    CommitPreparing,
    CommitPrepared,
    CommitRenaming,
    CommitRenamed,
    CommitArchiving,
    CommitArchived,
    CommitCleaning,
    CommitCleaned,
    CommitReconciling,
    CommitVerifyingPrepared,
    CommitVerifyingRenamed,
    CommitVerifyingArchived,
    CommitVerifyingCleaned,
    CommitCancelling,
    CommitReconciled,
    CommitInconsistent,
    CommitCancelled,
    FilesystemUnknown,
    FilesystemProbing,
    FilesystemProbed,
    FilesystemProbeFailed,
    FilesystemProbeCancelled,
    FilesystemConfining,
    FilesystemConfinementFailed,
    FilesystemConfinementCancelled,
    FilesystemConfined,
    FilesystemDegrading,
    FilesystemDegradationFailed,
    FilesystemDegradationCancelled,
    FilesystemDegraded,
    FilesystemRejecting,
    FilesystemRejectionFailed,
    FilesystemRejectionCancelled,
    FilesystemUnsupported,
    FilesystemCancelled,
    WatcherStarting,
    WatcherReady,
    WatcherServing,
    WatcherDegraded,
    WatcherStale,
    WatcherDraining,
    WatcherStopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Start,
    Assign,
    Admit,
    Receive,
    Validate,
    PersistDurably,
    Redirect,
    Continue,
    Ready,
    Serve,
    Refresh,
    Drain,
    Spawn,
    Reap,
    /// Legacy uncorrelated acknowledgement marker. Applying it is always invalid.
    /// Callers must use [`Event::EffectAcknowledged`].
    Acknowledge,
    EffectAcknowledged {
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
    },
    /// Correlated failure outcome for one effect adapter request.
    EffectFailed {
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
    },
    /// Correlated cancellation outcome for one effect adapter request.
    EffectCancelled {
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
    },
    Recycle,
    Quarantine,
    Prepare,
    Rename,
    Archive,
    Cleanup,
    Reconcile,
    Probe,
    Confine,
    Degrade,
    MarkStale,
    Reject,
    Release,
    Complete,
    Fail,
    Cancel,
    Restart,
}

/// Declarative requests to an effect adapter. These are data, not execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectIntent {
    BeginJob,
    RequestCancellation,
    ReleaseResources,
    ResolveSource,
    FollowRedirect,
    ReserveResources,
    AcceptBoundedBytes,
    ValidateAndWrite,
    SynchronizeData,
    RefreshManifest,
    DeliverToSink,
    DrainSink,
    SpawnProcess,
    TerminateProcess,
    ReapProcess,
    DispatchWorker,
    RecycleWorker,
    IsolateWorker,
    OpenPluginChannel,
    SendPluginRequest,
    ClosePluginChannel,
    ValidateOutput,
    RenameOutput,
    InsertArchiveRow,
    RemoveTemporaryState,
    RevalidatePreparedOutput,
    VerifyFinalArtifact,
    VerifyArchiveOutputPair,
    ProbeFilesystem,
    EstablishConfinedPath,
    ReportDegradedGuarantees,
    RejectFilesystem,
    NegotiateWatcher,
    SelfTestWatcherStorage,
    VerifyProducerCanary,
    ReportDiagnosticsDegraded,
    FlushWatcher,
    PreserveDiagnostics,
    DrainInFlightEffect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    StateDoesNotBelongToMachine {
        kind: MachineKind,
        state: State,
    },
    StateIsNotDurable {
        kind: MachineKind,
        state: State,
    },
    InvalidRestorationGeneration,
    EffectGenerationExhausted,
    UnexpectedAcknowledgement {
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
        expected: Vec<EffectAcknowledgement>,
    },
    UnexpectedEffectFailure {
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
        expected: Vec<EffectAcknowledgement>,
    },
    UnexpectedEffectCancellation {
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
        expected: Vec<EffectAcknowledgement>,
    },
    InvalidTransition {
        kind: MachineKind,
        state: State,
        event: Event,
    },
    TraceLimitReached {
        limit: usize,
    },
    ReplayMismatch {
        index: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub previous: State,
    pub event: Event,
    pub next: State,
    pub effects: Vec<EffectIntent>,
}

/// Correlation token for one effect completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectAcknowledgement {
    pub instance_id: MachineInstanceId,
    pub effect: EffectIntent,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeferredEffects {
    target: State,
    effects: Vec<EffectIntent>,
    has_unsuccessful_outcome: bool,
}

/// One bounded, deterministic state machine instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMachine {
    instance_id: MachineInstanceId,
    kind: MachineKind,
    state: State,
    trace_limit: usize,
    trace: Vec<Transition>,
    pending_acknowledgements: Vec<EffectAcknowledgement>,
    pending_unsuccessful_effect_outcome: bool,
    deferred_effects: Option<DeferredEffects>,
    next_effect_generation: u64,
}

impl StateMachine {
    #[must_use]
    pub fn new(kind: MachineKind, instance_id: MachineInstanceId, trace_limit: usize) -> Self {
        Self {
            instance_id,
            kind,
            state: initial(kind),
            trace_limit,
            trace: Vec::new(),
            pending_acknowledgements: Vec::new(),
            pending_unsuccessful_effect_outcome: false,
            deferred_effects: None,
            next_effect_generation: 1,
        }
    }

    /// Restore a machine at a validated durable prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when `state` does not belong to `kind`, is transient,
    /// or the caller does not provide a nonzero persisted generation seed.
    pub fn from_state(
        kind: MachineKind,
        state: State,
        instance_id: MachineInstanceId,
        trace_limit: usize,
        next_effect_generation: u64,
    ) -> Result<Self, TransitionError> {
        if !belongs(kind, state) {
            return Err(TransitionError::StateDoesNotBelongToMachine { kind, state });
        }
        if !is_durable_state(kind, state) {
            return Err(TransitionError::StateIsNotDurable { kind, state });
        }
        if next_effect_generation == 0 {
            return Err(TransitionError::InvalidRestorationGeneration);
        }
        Ok(Self {
            instance_id,
            kind,
            state,
            trace_limit,
            trace: Vec::new(),
            pending_acknowledgements: Vec::new(),
            pending_unsuccessful_effect_outcome: false,
            deferred_effects: None,
            next_effect_generation,
        })
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub fn instance_id(&self) -> MachineInstanceId {
        self.instance_id
    }

    #[must_use]
    pub fn trace(&self) -> &[Transition] {
        &self.trace
    }

    #[must_use]
    pub fn pending_acknowledgements(&self) -> &[EffectAcknowledgement] {
        &self.pending_acknowledgements
    }

    fn record_transition(
        &mut self,
        event: Event,
        next: State,
        effects: Vec<EffectIntent>,
        required: Vec<EffectIntent>,
        deferred_effects: Option<DeferredEffects>,
    ) -> Result<usize, TransitionError> {
        let next_generation = if required.is_empty() {
            self.next_effect_generation
        } else {
            self.next_effect_generation
                .checked_add(1)
                .ok_or(TransitionError::EffectGenerationExhausted)?
        };
        let pending_acknowledgements = required
            .into_iter()
            .map(|effect| EffectAcknowledgement {
                instance_id: self.instance_id,
                effect,
                generation: self.next_effect_generation,
            })
            .collect();
        let record = Transition {
            previous: self.state,
            event,
            next,
            effects,
        };
        self.state = next;
        self.pending_acknowledgements = pending_acknowledgements;
        self.pending_unsuccessful_effect_outcome = false;
        self.deferred_effects = deferred_effects;
        self.next_effect_generation = next_generation;
        self.trace.push(record);
        Ok(self.trace.len() - 1)
    }

    fn apply_transition_index(
        &mut self,
        event: Event,
        next: State,
        effects: Vec<EffectIntent>,
    ) -> Result<usize, TransitionError> {
        if uses_generic_effect_wrapper(self.kind) && !effects.is_empty() {
            let deferred_effects = DeferredEffects {
                target: next,
                effects: effects.clone(),
                has_unsuccessful_outcome: false,
            };
            return self.record_transition(
                event,
                State::EffectPending,
                effects.clone(),
                effects,
                Some(deferred_effects),
            );
        }

        let required = acknowledgement_effects(next, &effects);
        if !uses_generic_effect_wrapper(self.kind) && required.len() != effects.len() {
            return Err(TransitionError::InvalidTransition {
                kind: self.kind,
                state: self.state,
                event,
            });
        }
        self.record_transition(event, next, effects, required, None)
    }

    fn apply_transition(
        &mut self,
        event: Event,
        next: State,
        effects: Vec<EffectIntent>,
    ) -> Result<&Transition, TransitionError> {
        let index = self.apply_transition_index(event, next, effects)?;
        self.trace
            .get(index)
            .ok_or(TransitionError::ReplayMismatch { index })
    }

    fn outcome_error(
        &self,
        event: Event,
        instance_id: MachineInstanceId,
        effect: EffectIntent,
        generation: u64,
    ) -> TransitionError {
        let expected = self.pending_acknowledgements.clone();
        match event {
            Event::EffectAcknowledged { .. } => TransitionError::UnexpectedAcknowledgement {
                instance_id,
                effect,
                generation,
                expected,
            },
            Event::EffectFailed { .. } => TransitionError::UnexpectedEffectFailure {
                instance_id,
                effect,
                generation,
                expected,
            },
            Event::EffectCancelled { .. } => TransitionError::UnexpectedEffectCancellation {
                instance_id,
                effect,
                generation,
                expected,
            },
            _ => TransitionError::InvalidTransition {
                kind: self.kind,
                state: self.state,
                event,
            },
        }
    }

    fn deferred_effect_outcome(
        &self,
        event: Event,
    ) -> Result<(MachineInstanceId, EffectIntent, u64, bool), TransitionError> {
        Ok(match event {
            Event::EffectAcknowledged {
                instance_id,
                effect,
                generation,
            } => (instance_id, effect, generation, true),
            Event::EffectFailed {
                instance_id,
                effect,
                generation,
            }
            | Event::EffectCancelled {
                instance_id,
                effect,
                generation,
            } => (instance_id, effect, generation, false),
            _ => {
                return Err(TransitionError::InvalidTransition {
                    kind: self.kind,
                    state: self.state,
                    event,
                });
            }
        })
    }

    fn restart_deferred_effect(&mut self, event: Event) -> Result<usize, TransitionError> {
        if event != Event::Restart {
            return Err(TransitionError::InvalidTransition {
                kind: self.kind,
                state: self.state,
                event,
            });
        }
        let deferred = self
            .deferred_effects
            .take()
            .ok_or(TransitionError::ReplayMismatch {
                index: self.trace.len(),
            })?;
        let preserved = deferred.clone();
        match self.apply_transition_index(event, deferred.target, deferred.effects) {
            Ok(index) => Ok(index),
            Err(error) => {
                self.deferred_effects = Some(preserved);
                Err(error)
            }
        }
    }

    fn complete_deferred_effect(&mut self, event: Event) -> Result<usize, TransitionError> {
        let (instance_id, effect, generation, successful) = self.deferred_effect_outcome(event)?;
        let Some(index) = self.pending_acknowledgements.iter().position(|expected| {
            expected.instance_id == instance_id
                && expected.effect == effect
                && expected.generation == generation
        }) else {
            return Err(self.outcome_error(event, instance_id, effect, generation));
        };
        let mut remaining = self.pending_acknowledgements.clone();
        remaining.remove(index);
        let mut deferred = self
            .deferred_effects
            .take()
            .ok_or(TransitionError::ReplayMismatch {
                index: self.trace.len(),
            })?;
        deferred.has_unsuccessful_outcome |= !successful;

        if !remaining.is_empty() {
            self.pending_acknowledgements = remaining;
            self.deferred_effects = Some(deferred);
            let record = Transition {
                previous: self.state,
                event,
                next: State::EffectPending,
                effects: Vec::new(),
            };
            self.trace.push(record);
            return Ok(self.trace.len() - 1);
        }

        if deferred.has_unsuccessful_outcome {
            return self.record_transition(
                event,
                State::EffectRecovery,
                Vec::new(),
                Vec::new(),
                Some(deferred),
            );
        }

        let (next, effects) = match transition(self.kind, deferred.target, event) {
            Ok(transition) => transition,
            Err(TransitionError::InvalidTransition { .. }) => (deferred.target, Vec::new()),
            Err(error) => return Err(error),
        };
        let preserved = deferred.clone();
        let index = match self.apply_transition_index(event, next, effects) {
            Ok(index) => index,
            Err(error) => {
                self.deferred_effects = Some(preserved);
                return Err(error);
            }
        };
        Ok(index)
    }

    fn apply_deferred_effect(&mut self, event: Event) -> Result<&Transition, TransitionError> {
        let index = if self.state == State::EffectRecovery {
            self.restart_deferred_effect(event)?
        } else {
            self.complete_deferred_effect(event)?
        };
        self.trace
            .get(index)
            .ok_or(TransitionError::ReplayMismatch { index })
    }

    /// Apply one event atomically, recording it only after validation.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-transition or trace-bound error.
    pub fn apply(&mut self, event: Event) -> Result<&Transition, TransitionError> {
        if self.trace.len() >= self.trace_limit {
            return Err(TransitionError::TraceLimitReached {
                limit: self.trace_limit,
            });
        }
        if self.deferred_effects.is_some() {
            return self.apply_deferred_effect(event);
        }
        if !self.pending_acknowledgements.is_empty()
            && !matches!(
                event,
                Event::EffectAcknowledged { .. }
                    | Event::EffectFailed { .. }
                    | Event::EffectCancelled { .. }
            )
        {
            return Err(TransitionError::InvalidTransition {
                kind: self.kind,
                state: self.state,
                event,
            });
        }
        let outcome = match event {
            Event::EffectAcknowledged {
                instance_id,
                effect,
                generation,
            } => Some((instance_id, effect, generation, true)),
            Event::EffectFailed {
                instance_id,
                effect,
                generation,
            }
            | Event::EffectCancelled {
                instance_id,
                effect,
                generation,
            } => Some((instance_id, effect, generation, false)),
            _ => None,
        };
        if let Some((instance_id, effect, generation, successful)) = outcome
            && (!successful || !self.pending_acknowledgements.is_empty())
        {
            let mut remaining_acknowledgements = self.pending_acknowledgements.clone();
            let Some(index) = remaining_acknowledgements.iter().position(|expected| {
                expected.instance_id == instance_id
                    && expected.effect == effect
                    && expected.generation == generation
            }) else {
                return Err(self.outcome_error(event, instance_id, effect, generation));
            };
            remaining_acknowledgements.remove(index);
            self.pending_unsuccessful_effect_outcome |= !successful;
            if !remaining_acknowledgements.is_empty() {
                let record = Transition {
                    previous: self.state,
                    event,
                    next: self.state,
                    effects: Vec::new(),
                };
                self.pending_acknowledgements = remaining_acknowledgements;
                self.trace.push(record);
                let index = self.trace.len() - 1;
                return self
                    .trace
                    .get(index)
                    .ok_or(TransitionError::ReplayMismatch { index });
            }
            let has_unsuccessful_outcome = self.pending_unsuccessful_effect_outcome;
            self.pending_acknowledgements.clear();
            self.pending_unsuccessful_effect_outcome = false;
            if has_unsuccessful_outcome
                && let Some((next, effects)) = unsuccessful_effect_recovery(self.kind, self.state)
            {
                return self.apply_transition(event, next, effects);
            }
        }
        let (next, effects) = transition(self.kind, self.state, event)?;
        self.apply_transition(event, next, effects)
    }

    /// Replay a recorded trace and require each state/effect record to match.
    ///
    /// # Errors
    ///
    /// Returns the first transition, bound, or record mismatch.
    pub fn replay(
        kind: MachineKind,
        instance_id: MachineInstanceId,
        trace_limit: usize,
        expected: &[Transition],
    ) -> Result<Self, TransitionError> {
        let mut machine = Self::new(kind, instance_id, trace_limit);
        for (index, record) in expected.iter().enumerate() {
            let actual = machine.apply(record.event)?;
            if actual != record {
                return Err(TransitionError::ReplayMismatch { index });
            }
        }
        Ok(machine)
    }
}

fn uses_generic_effect_wrapper(kind: MachineKind) -> bool {
    !matches!(
        kind,
        MachineKind::Ffmpeg | MachineKind::FilesystemCapability
    )
}

fn initial(kind: MachineKind) -> State {
    match kind {
        MachineKind::JobCancellation => State::JobQueued,
        MachineKind::SourceRedirect => State::SourceNew,
        MachineKind::AtomicAdmission => State::AdmissionWaiting,
        MachineKind::ByteCreditDurability => State::BytesEmpty,
        MachineKind::Live => State::LiveStarting,
        MachineKind::Sink => State::SinkPending,
        MachineKind::Ffmpeg => State::FfmpegPrepared,
        MachineKind::JavascriptWorker => State::JavascriptIdle,
        MachineKind::PluginIpc => State::PluginDisconnected,
        MachineKind::CommitArchiveReconciliation => State::CommitWorking,
        MachineKind::FilesystemCapability => State::FilesystemUnknown,
        MachineKind::Watcher => State::WatcherStarting,
    }
}

#[allow(clippy::too_many_lines)]
fn belongs(kind: MachineKind, state: State) -> bool {
    if matches!(state, State::EffectPending | State::EffectRecovery) {
        return uses_generic_effect_wrapper(kind);
    }
    matches!(
        (kind, state),
        (
            MachineKind::JobCancellation,
            State::JobQueued
                | State::JobRunning
                | State::JobCancelling
                | State::JobVerifying
                | State::JobSucceeded
                | State::JobFailed
                | State::JobCancelled
        ) | (
            MachineKind::SourceRedirect,
            State::SourceNew
                | State::SourceResolving
                | State::SourceRedirecting
                | State::SourceResolved
                | State::SourceFailed
                | State::SourceCancelled
        ) | (
            MachineKind::AtomicAdmission,
            State::AdmissionWaiting
                | State::AdmissionGranted
                | State::AdmissionReleased
                | State::AdmissionCancelled
        ) | (
            MachineKind::ByteCreditDurability,
            State::BytesEmpty
                | State::BytesReceived
                | State::BytesWriting
                | State::BytesWritten
                | State::BytesSynchronizing
                | State::BytesDurable
                | State::BytesFailed
                | State::BytesCancelled
        ) | (
            MachineKind::Live,
            State::LiveStarting
                | State::LiveRefreshing
                | State::LiveStreaming
                | State::LiveStopped
                | State::LiveFailed
                | State::LiveCancelled
        ) | (
            MachineKind::Sink,
            State::SinkPending
                | State::SinkActive
                | State::SinkDraining
                | State::SinkCompleted
                | State::SinkDropped
                | State::SinkFailed
                | State::SinkCancelled
        ) | (
            MachineKind::Ffmpeg,
            State::FfmpegPrepared
                | State::FfmpegSpawning
                | State::FfmpegSpawned
                | State::FfmpegRunning
                | State::FfmpegReaping
                | State::FfmpegCancelling
                | State::FfmpegFailing
                | State::FfmpegExitReleasing
                | State::FfmpegCancellationReleasing
                | State::FfmpegFailureReleasing
                | State::FfmpegSpawnRecovering
                | State::FfmpegReapRecovering
                | State::FfmpegCancellationRecovering
                | State::FfmpegFailureRecovering
                | State::FfmpegExitReleaseRecovering
                | State::FfmpegCancellationReleaseRecovering
                | State::FfmpegFailureReleaseRecovering
                | State::FfmpegExited
                | State::FfmpegFailed
                | State::FfmpegCancelled
        ) | (
            MachineKind::JavascriptWorker,
            State::JavascriptIdle
                | State::JavascriptAssigned
                | State::JavascriptRunning
                | State::JavascriptRecycling
                | State::JavascriptQuarantined
                | State::JavascriptCompleted
                | State::JavascriptCancelled
        ) | (
            MachineKind::PluginIpc,
            State::PluginDisconnected
                | State::PluginHandshaking
                | State::PluginReady
                | State::PluginInFlight
                | State::PluginDraining
                | State::PluginStopped
                | State::PluginFailed
        ) | (
            MachineKind::CommitArchiveReconciliation,
            State::CommitWorking
                | State::CommitPreparing
                | State::CommitPrepared
                | State::CommitRenaming
                | State::CommitRenamed
                | State::CommitArchiving
                | State::CommitArchived
                | State::CommitCleaning
                | State::CommitCleaned
                | State::CommitReconciling
                | State::CommitVerifyingPrepared
                | State::CommitVerifyingRenamed
                | State::CommitVerifyingArchived
                | State::CommitVerifyingCleaned
                | State::CommitCancelling
                | State::CommitReconciled
                | State::CommitInconsistent
                | State::CommitCancelled
        ) | (
            MachineKind::FilesystemCapability,
            State::FilesystemUnknown
                | State::FilesystemProbing
                | State::FilesystemProbed
                | State::FilesystemProbeFailed
                | State::FilesystemProbeCancelled
                | State::FilesystemConfining
                | State::FilesystemConfinementFailed
                | State::FilesystemConfinementCancelled
                | State::FilesystemConfined
                | State::FilesystemDegrading
                | State::FilesystemDegradationFailed
                | State::FilesystemDegradationCancelled
                | State::FilesystemDegraded
                | State::FilesystemRejecting
                | State::FilesystemRejectionFailed
                | State::FilesystemRejectionCancelled
                | State::FilesystemUnsupported
                | State::FilesystemCancelled
        ) | (
            MachineKind::Watcher,
            State::WatcherStarting
                | State::WatcherReady
                | State::WatcherServing
                | State::WatcherDegraded
                | State::WatcherStale
                | State::WatcherDraining
                | State::WatcherStopped
        )
    )
}

/// Exact public-restoration whitelist represented by the contract inventory's
/// `durable_prefixes` field. An empty slice is represented as `["none"]` in
/// the inventory because its schema requires a nonempty explanatory array.
#[must_use]
pub const fn durable_states(kind: MachineKind) -> &'static [State] {
    match kind {
        MachineKind::JobCancellation => &[State::JobSucceeded],
        MachineKind::SourceRedirect => &[State::SourceResolved],
        MachineKind::AtomicAdmission | MachineKind::JavascriptWorker | MachineKind::PluginIpc => {
            &[]
        }
        MachineKind::ByteCreditDurability => &[
            State::BytesReceived,
            State::BytesWritten,
            State::BytesDurable,
        ],
        MachineKind::Live => &[State::LiveStreaming],
        MachineKind::Sink => &[State::SinkActive, State::SinkCompleted],
        MachineKind::Ffmpeg => &[State::FfmpegExited],
        MachineKind::CommitArchiveReconciliation => &[
            State::CommitPrepared,
            State::CommitRenamed,
            State::CommitArchived,
            State::CommitCleaned,
            State::CommitReconciled,
        ],
        MachineKind::FilesystemCapability => &[
            State::FilesystemConfined,
            State::FilesystemDegraded,
            State::FilesystemUnsupported,
        ],
        MachineKind::Watcher => &[
            State::WatcherReady,
            State::WatcherServing,
            State::WatcherDegraded,
            State::WatcherStale,
            State::WatcherStopped,
        ],
    }
}

fn is_durable_state(kind: MachineKind, state: State) -> bool {
    durable_states(kind).contains(&state)
}

fn acknowledgement_effects(state: State, emitted: &[EffectIntent]) -> Vec<EffectIntent> {
    let required: &[EffectIntent] = match state {
        State::JobCancelling => &[EffectIntent::RequestCancellation],
        State::JobVerifying
        | State::CommitReconciling
        | State::CommitVerifyingArchived
        | State::CommitVerifyingCleaned => &[EffectIntent::VerifyArchiveOutputPair],
        State::BytesWriting => &[EffectIntent::ValidateAndWrite],
        State::BytesSynchronizing => &[EffectIntent::SynchronizeData],
        State::FfmpegSpawning => &[EffectIntent::SpawnProcess],
        State::FfmpegReaping => &[EffectIntent::ReapProcess],
        State::FfmpegCancelling => &[EffectIntent::TerminateProcess, EffectIntent::ReapProcess],
        State::FfmpegFailing => &[
            EffectIntent::TerminateProcess,
            EffectIntent::ReapProcess,
            EffectIntent::PreserveDiagnostics,
        ],
        State::FfmpegExitReleasing
        | State::FfmpegCancellationReleasing
        | State::FfmpegFailureReleasing => &[EffectIntent::ReleaseResources],
        State::FfmpegSpawnRecovering
        | State::FfmpegReapRecovering
        | State::FfmpegCancellationRecovering
        | State::FfmpegFailureRecovering
        | State::FfmpegExitReleaseRecovering
        | State::FfmpegCancellationReleaseRecovering
        | State::FfmpegFailureReleaseRecovering => &[EffectIntent::PreserveDiagnostics],
        State::JavascriptRecycling => &[EffectIntent::RecycleWorker],
        State::PluginDraining => &[EffectIntent::ClosePluginChannel],
        State::CommitPreparing => &[EffectIntent::ValidateOutput, EffectIntent::SynchronizeData],
        State::CommitRenaming => &[EffectIntent::RenameOutput],
        State::CommitArchiving => &[EffectIntent::InsertArchiveRow],
        State::CommitCleaning => &[EffectIntent::RemoveTemporaryState],
        State::CommitVerifyingPrepared => &[EffectIntent::RevalidatePreparedOutput],
        State::CommitVerifyingRenamed => &[EffectIntent::VerifyFinalArtifact],
        State::CommitCancelling => &[EffectIntent::DrainInFlightEffect],
        State::FilesystemProbing => &[EffectIntent::ProbeFilesystem],
        State::FilesystemConfining => &[EffectIntent::EstablishConfinedPath],
        State::FilesystemDegrading => &[EffectIntent::ReportDegradedGuarantees],
        State::FilesystemRejecting => &[EffectIntent::RejectFilesystem],
        State::WatcherDraining => &[EffectIntent::FlushWatcher],
        _ => &[],
    };
    required
        .iter()
        .copied()
        .filter(|effect| emitted.contains(effect))
        .collect()
}

fn unsuccessful_effect_recovery(
    kind: MachineKind,
    state: State,
) -> Option<(State, Vec<EffectIntent>)> {
    match kind {
        MachineKind::Ffmpeg => ffmpeg_recovery_after_all_outcomes(state),
        _ => None,
    }
}

fn transition(
    kind: MachineKind,
    state: State,
    event: Event,
) -> Result<(State, Vec<EffectIntent>), TransitionError> {
    if !belongs(kind, state) {
        return Err(TransitionError::StateDoesNotBelongToMachine { kind, state });
    }
    let result = match kind {
        MachineKind::JobCancellation => job(state, event),
        MachineKind::SourceRedirect => source(state, event),
        MachineKind::AtomicAdmission => admission(state, event),
        MachineKind::ByteCreditDurability => bytes(state, event),
        MachineKind::Live => live(state, event),
        MachineKind::Sink => sink(state, event),
        MachineKind::Ffmpeg => ffmpeg(state, event),
        MachineKind::JavascriptWorker => javascript(state, event),
        MachineKind::PluginIpc => plugin(state, event),
        MachineKind::CommitArchiveReconciliation => commit(state, event),
        MachineKind::FilesystemCapability => filesystem(state, event),
        MachineKind::Watcher => watcher(state, event),
    };
    result.ok_or(TransitionError::InvalidTransition { kind, state, event })
}

#[allow(clippy::unnecessary_wraps)]
fn step(next: State, effects: &[EffectIntent]) -> Option<(State, Vec<EffectIntent>)> {
    Some((next, effects.to_vec()))
}

fn job(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::JobQueued, Event::Start) => step(State::JobRunning, &[EffectIntent::BeginJob]),
        (State::JobQueued, Event::Cancel) => step(State::JobCancelled, &[]),
        (State::JobRunning | State::JobVerifying, Event::Cancel) => {
            step(State::JobCancelling, &[EffectIntent::RequestCancellation])
        }
        (State::JobCancelling, Event::EffectAcknowledged { .. }) => {
            step(State::JobCancelled, &[EffectIntent::ReleaseResources])
        }
        (State::JobRunning, Event::Reconcile) => step(
            State::JobVerifying,
            &[EffectIntent::VerifyArchiveOutputPair],
        ),
        (State::JobVerifying, Event::EffectAcknowledged { .. }) => {
            step(State::JobSucceeded, &[EffectIntent::ReleaseResources])
        }
        (State::JobRunning | State::JobCancelling | State::JobVerifying, Event::Fail) => step(
            State::JobFailed,
            &[
                EffectIntent::PreserveDiagnostics,
                EffectIntent::ReleaseResources,
            ],
        ),
        (State::JobFailed | State::JobCancelled, Event::Restart) => step(State::JobQueued, &[]),
        _ => None,
    }
}

fn source(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::SourceNew, Event::Start) | (State::SourceRedirecting, Event::Continue) => {
            step(State::SourceResolving, &[EffectIntent::ResolveSource])
        }
        (State::SourceResolving, Event::Redirect) => {
            step(State::SourceRedirecting, &[EffectIntent::FollowRedirect])
        }
        (State::SourceResolving, Event::Complete) => step(State::SourceResolved, &[]),
        (State::SourceNew | State::SourceResolving | State::SourceRedirecting, Event::Cancel) => {
            step(State::SourceCancelled, &[])
        }
        (State::SourceResolving | State::SourceRedirecting, Event::Fail) => {
            step(State::SourceFailed, &[EffectIntent::PreserveDiagnostics])
        }
        (State::SourceFailed | State::SourceCancelled, Event::Restart) => {
            step(State::SourceNew, &[])
        }
        _ => None,
    }
}

fn admission(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::AdmissionWaiting, Event::Admit) => {
            step(State::AdmissionGranted, &[EffectIntent::ReserveResources])
        }
        (State::AdmissionGranted, Event::Release) => {
            step(State::AdmissionReleased, &[EffectIntent::ReleaseResources])
        }
        (State::AdmissionWaiting, Event::Cancel) => step(State::AdmissionCancelled, &[]),
        (State::AdmissionGranted, Event::Cancel) => {
            step(State::AdmissionCancelled, &[EffectIntent::ReleaseResources])
        }
        _ => None,
    }
}

fn bytes(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::BytesEmpty | State::BytesReceived, Event::Receive) => {
            step(State::BytesReceived, &[EffectIntent::AcceptBoundedBytes])
        }
        (State::BytesReceived, Event::Validate) => {
            step(State::BytesWriting, &[EffectIntent::ValidateAndWrite])
        }
        (State::BytesWriting, Event::EffectAcknowledged { .. }) => step(State::BytesWritten, &[]),
        (State::BytesWritten, Event::PersistDurably) => {
            step(State::BytesSynchronizing, &[EffectIntent::SynchronizeData])
        }
        (State::BytesSynchronizing, Event::EffectAcknowledged { .. }) => {
            step(State::BytesDurable, &[])
        }
        (
            State::BytesEmpty
            | State::BytesReceived
            | State::BytesWriting
            | State::BytesWritten
            | State::BytesSynchronizing,
            Event::Cancel,
        ) => step(State::BytesCancelled, &[EffectIntent::ReleaseResources]),
        (
            State::BytesReceived
            | State::BytesWriting
            | State::BytesWritten
            | State::BytesSynchronizing,
            Event::Fail,
        ) => step(
            State::BytesFailed,
            &[
                EffectIntent::PreserveDiagnostics,
                EffectIntent::ReleaseResources,
            ],
        ),
        (State::BytesFailed | State::BytesCancelled, Event::Restart) => {
            step(State::BytesEmpty, &[])
        }
        _ => None,
    }
}

fn live(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::LiveStarting, Event::Ready) | (State::LiveStreaming, Event::Refresh) => {
            step(State::LiveRefreshing, &[EffectIntent::RefreshManifest])
        }
        (State::LiveRefreshing, Event::Serve) => {
            step(State::LiveStreaming, &[EffectIntent::DeliverToSink])
        }
        (State::LiveStreaming | State::LiveRefreshing, Event::Drain) => {
            step(State::LiveStopped, &[EffectIntent::DrainSink])
        }
        (State::LiveStarting | State::LiveRefreshing | State::LiveStreaming, Event::Cancel) => {
            step(State::LiveCancelled, &[EffectIntent::ReleaseResources])
        }
        (State::LiveRefreshing | State::LiveStreaming, Event::Fail) => {
            step(State::LiveFailed, &[EffectIntent::PreserveDiagnostics])
        }
        (State::LiveFailed | State::LiveCancelled, Event::Restart) => {
            step(State::LiveStarting, &[])
        }
        _ => None,
    }
}

fn sink(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::SinkPending, Event::Start) => {
            step(State::SinkActive, &[EffectIntent::DeliverToSink])
        }
        (State::SinkActive, Event::Drain) => step(State::SinkDraining, &[EffectIntent::DrainSink]),
        (State::SinkDraining, Event::Complete) => step(State::SinkCompleted, &[]),
        (State::SinkActive, Event::Reject) => {
            step(State::SinkDropped, &[EffectIntent::ReleaseResources])
        }
        (State::SinkPending | State::SinkActive | State::SinkDraining, Event::Cancel) => {
            step(State::SinkCancelled, &[EffectIntent::ReleaseResources])
        }
        (State::SinkActive | State::SinkDraining, Event::Fail) => step(
            State::SinkFailed,
            &[
                EffectIntent::PreserveDiagnostics,
                EffectIntent::ReleaseResources,
            ],
        ),
        _ => None,
    }
}

fn ffmpeg(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    ffmpeg_recovery(state, event).or_else(|| match (state, event) {
        (State::FfmpegPrepared, Event::Spawn) | (State::FfmpegSpawnRecovering, Event::Restart) => {
            step(State::FfmpegSpawning, &[EffectIntent::SpawnProcess])
        }
        (State::FfmpegSpawning, Event::EffectAcknowledged { .. }) => {
            step(State::FfmpegSpawned, &[])
        }
        (State::FfmpegSpawned, Event::Start) => step(State::FfmpegRunning, &[]),
        (State::FfmpegRunning, Event::Complete) | (State::FfmpegReapRecovering, Event::Restart) => {
            step(State::FfmpegReaping, &[EffectIntent::ReapProcess])
        }
        (State::FfmpegReaping, Event::EffectAcknowledged { .. })
        | (State::FfmpegExitReleaseRecovering, Event::Restart) => step(
            State::FfmpegExitReleasing,
            &[EffectIntent::ReleaseResources],
        ),
        (State::FfmpegExitReleasing, Event::EffectAcknowledged { .. }) => {
            step(State::FfmpegExited, &[])
        }
        (State::FfmpegPrepared, Event::Cancel)
        | (State::FfmpegCancelling, Event::EffectAcknowledged { .. })
        | (State::FfmpegCancellationReleaseRecovering, Event::Restart) => step(
            State::FfmpegCancellationReleasing,
            &[EffectIntent::ReleaseResources],
        ),
        (State::FfmpegCancellationReleasing, Event::EffectAcknowledged { .. }) => {
            step(State::FfmpegCancelled, &[])
        }
        (State::FfmpegSpawned | State::FfmpegRunning, Event::Cancel)
        | (State::FfmpegCancellationRecovering, Event::Restart) => step(
            State::FfmpegCancelling,
            &[EffectIntent::TerminateProcess, EffectIntent::ReapProcess],
        ),
        (State::FfmpegSpawned | State::FfmpegRunning | State::FfmpegReaping, Event::Fail)
        | (State::FfmpegFailureRecovering, Event::Restart) => step(
            State::FfmpegFailing,
            &[
                EffectIntent::TerminateProcess,
                EffectIntent::ReapProcess,
                EffectIntent::PreserveDiagnostics,
            ],
        ),
        (State::FfmpegFailing, Event::EffectAcknowledged { .. })
        | (State::FfmpegFailureReleaseRecovering, Event::Restart) => step(
            State::FfmpegFailureReleasing,
            &[EffectIntent::ReleaseResources],
        ),
        (State::FfmpegFailureReleasing, Event::EffectAcknowledged { .. }) => {
            step(State::FfmpegFailed, &[])
        }
        (State::FfmpegFailed | State::FfmpegCancelled, Event::Restart) => {
            step(State::FfmpegPrepared, &[])
        }
        _ => None,
    })
}

fn ffmpeg_recovery(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    if matches!(
        event,
        Event::EffectFailed { .. } | Event::EffectCancelled { .. }
    ) && let Some(recovery) = ffmpeg_recovery_after_all_outcomes(state)
    {
        return Some(recovery);
    }
    match (state, event) {
        (
            State::FfmpegSpawnRecovering
            | State::FfmpegReapRecovering
            | State::FfmpegCancellationRecovering
            | State::FfmpegFailureRecovering
            | State::FfmpegExitReleaseRecovering
            | State::FfmpegCancellationReleaseRecovering
            | State::FfmpegFailureReleaseRecovering,
            Event::EffectAcknowledged { .. }
            | Event::EffectFailed { .. }
            | Event::EffectCancelled { .. },
        ) => step(state, &[]),
        _ => None,
    }
}

fn ffmpeg_recovery_after_all_outcomes(state: State) -> Option<(State, Vec<EffectIntent>)> {
    match state {
        State::FfmpegSpawning => step(
            State::FfmpegSpawnRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        State::FfmpegReaping => step(
            State::FfmpegReapRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        State::FfmpegCancelling => step(
            State::FfmpegCancellationRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        State::FfmpegFailing => step(
            State::FfmpegFailureRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        State::FfmpegExitReleasing => step(
            State::FfmpegExitReleaseRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        State::FfmpegCancellationReleasing => step(
            State::FfmpegCancellationReleaseRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        State::FfmpegFailureReleasing => step(
            State::FfmpegFailureReleaseRecovering,
            &[EffectIntent::PreserveDiagnostics],
        ),
        _ => None,
    }
}

fn javascript(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::JavascriptIdle, Event::Assign) => {
            step(State::JavascriptAssigned, &[EffectIntent::DispatchWorker])
        }
        (State::JavascriptAssigned, Event::Start) => step(State::JavascriptRunning, &[]),
        (State::JavascriptRunning, Event::Complete) => step(State::JavascriptCompleted, &[]),
        (State::JavascriptRunning, Event::Recycle) => {
            step(State::JavascriptRecycling, &[EffectIntent::RecycleWorker])
        }
        (State::JavascriptRecycling, Event::EffectAcknowledged { .. }) => {
            step(State::JavascriptIdle, &[])
        }
        (State::JavascriptAssigned | State::JavascriptRunning, Event::Quarantine) => step(
            State::JavascriptQuarantined,
            &[
                EffectIntent::IsolateWorker,
                EffectIntent::PreserveDiagnostics,
            ],
        ),
        (State::JavascriptQuarantined, Event::Restart) => {
            step(State::JavascriptIdle, &[EffectIntent::RecycleWorker])
        }
        (State::JavascriptAssigned | State::JavascriptRunning, Event::Cancel) => step(
            State::JavascriptCancelled,
            &[EffectIntent::ReleaseResources],
        ),
        _ => None,
    }
}

fn plugin(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::PluginDisconnected, Event::Start) => {
            step(State::PluginHandshaking, &[EffectIntent::OpenPluginChannel])
        }
        (State::PluginHandshaking, Event::Ready) | (State::PluginInFlight, Event::Complete) => {
            step(State::PluginReady, &[])
        }
        (State::PluginReady, Event::Assign) => {
            step(State::PluginInFlight, &[EffectIntent::SendPluginRequest])
        }
        (
            State::PluginHandshaking | State::PluginReady | State::PluginInFlight,
            Event::Drain | Event::Cancel,
        ) => step(State::PluginDraining, &[EffectIntent::ClosePluginChannel]),
        (State::PluginDraining, Event::EffectAcknowledged { .. }) => {
            step(State::PluginStopped, &[])
        }
        (
            State::PluginHandshaking
            | State::PluginReady
            | State::PluginInFlight
            | State::PluginDraining,
            Event::Fail,
        ) => step(
            State::PluginFailed,
            &[
                EffectIntent::ClosePluginChannel,
                EffectIntent::PreserveDiagnostics,
            ],
        ),
        (State::PluginFailed | State::PluginStopped, Event::Restart) => {
            step(State::PluginDisconnected, &[])
        }
        _ => None,
    }
}

fn commit(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::CommitWorking, Event::Prepare) => step(
            State::CommitPreparing,
            &[EffectIntent::ValidateOutput, EffectIntent::SynchronizeData],
        ),
        (
            State::CommitPreparing | State::CommitVerifyingPrepared,
            Event::EffectAcknowledged { .. },
        ) => step(State::CommitPrepared, &[]),
        (State::CommitPrepared, Event::Rename) => {
            step(State::CommitRenaming, &[EffectIntent::RenameOutput])
        }
        (
            State::CommitRenaming | State::CommitVerifyingRenamed,
            Event::EffectAcknowledged { .. },
        ) => step(State::CommitRenamed, &[]),
        (State::CommitRenamed, Event::Archive) => {
            step(State::CommitArchiving, &[EffectIntent::InsertArchiveRow])
        }
        (
            State::CommitArchiving | State::CommitVerifyingArchived,
            Event::EffectAcknowledged { .. },
        ) => step(State::CommitArchived, &[]),
        (State::CommitArchived, Event::Cleanup) => {
            step(State::CommitCleaning, &[EffectIntent::RemoveTemporaryState])
        }
        (
            State::CommitCleaning | State::CommitVerifyingCleaned,
            Event::EffectAcknowledged { .. },
        ) => step(State::CommitCleaned, &[]),
        (State::CommitCleaned, Event::Reconcile) => step(
            State::CommitReconciling,
            &[EffectIntent::VerifyArchiveOutputPair],
        ),
        (State::CommitReconciling, Event::EffectAcknowledged { .. }) => {
            step(State::CommitReconciled, &[])
        }
        (State::CommitPrepared, Event::Restart | Event::Reconcile) => step(
            State::CommitVerifyingPrepared,
            &[EffectIntent::RevalidatePreparedOutput],
        ),
        (State::CommitRenamed, Event::Restart | Event::Reconcile) => step(
            State::CommitVerifyingRenamed,
            &[EffectIntent::VerifyFinalArtifact],
        ),
        (State::CommitArchived, Event::Restart | Event::Reconcile) => step(
            State::CommitVerifyingArchived,
            &[EffectIntent::VerifyArchiveOutputPair],
        ),
        (State::CommitCleaned, Event::Restart) => step(
            State::CommitVerifyingCleaned,
            &[EffectIntent::VerifyArchiveOutputPair],
        ),
        (
            State::CommitWorking
            | State::CommitPreparing
            | State::CommitPrepared
            | State::CommitRenaming
            | State::CommitRenamed
            | State::CommitArchiving
            | State::CommitArchived
            | State::CommitCleaning
            | State::CommitCleaned,
            Event::Fail,
        ) => step(
            State::CommitInconsistent,
            &[EffectIntent::PreserveDiagnostics],
        ),
        (
            State::CommitWorking
            | State::CommitPreparing
            | State::CommitPrepared
            | State::CommitRenaming
            | State::CommitRenamed
            | State::CommitArchiving
            | State::CommitArchived
            | State::CommitCleaning
            | State::CommitCleaned
            | State::CommitReconciling
            | State::CommitVerifyingPrepared
            | State::CommitVerifyingRenamed
            | State::CommitVerifyingArchived
            | State::CommitVerifyingCleaned,
            Event::Cancel,
        ) => step(
            State::CommitCancelling,
            &[
                EffectIntent::PreserveDiagnostics,
                EffectIntent::DrainInFlightEffect,
            ],
        ),
        (State::CommitCancelling, Event::EffectAcknowledged { .. }) => {
            step(State::CommitCancelled, &[EffectIntent::ReleaseResources])
        }
        _ => None,
    }
}

fn filesystem(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::FilesystemUnknown, Event::Probe) => {
            step(State::FilesystemProbing, &[EffectIntent::ProbeFilesystem])
        }
        (State::FilesystemProbing, Event::EffectAcknowledged { .. }) => {
            step(State::FilesystemProbed, &[])
        }
        (State::FilesystemProbing, Event::EffectFailed { .. }) => {
            step(State::FilesystemProbeFailed, &[])
        }
        (State::FilesystemProbing, Event::EffectCancelled { .. }) => {
            step(State::FilesystemProbeCancelled, &[])
        }
        (State::FilesystemProbed, Event::Confine) => step(
            State::FilesystemConfining,
            &[EffectIntent::EstablishConfinedPath],
        ),
        (State::FilesystemConfining, Event::EffectAcknowledged { .. }) => {
            step(State::FilesystemConfined, &[])
        }
        (State::FilesystemConfining, Event::EffectFailed { .. }) => {
            step(State::FilesystemConfinementFailed, &[])
        }
        (State::FilesystemConfining, Event::EffectCancelled { .. }) => {
            step(State::FilesystemConfinementCancelled, &[])
        }
        (State::FilesystemProbed, Event::Degrade) => step(
            State::FilesystemDegrading,
            &[EffectIntent::ReportDegradedGuarantees],
        ),
        (State::FilesystemDegrading, Event::EffectAcknowledged { .. }) => {
            step(State::FilesystemDegraded, &[])
        }
        (State::FilesystemDegrading, Event::EffectFailed { .. }) => {
            step(State::FilesystemDegradationFailed, &[])
        }
        (State::FilesystemDegrading, Event::EffectCancelled { .. }) => {
            step(State::FilesystemDegradationCancelled, &[])
        }
        (State::FilesystemProbed, Event::Reject) => step(
            State::FilesystemRejecting,
            &[EffectIntent::RejectFilesystem],
        ),
        (State::FilesystemRejecting, Event::EffectAcknowledged { .. }) => {
            step(State::FilesystemUnsupported, &[])
        }
        (State::FilesystemRejecting, Event::EffectFailed { .. }) => {
            step(State::FilesystemRejectionFailed, &[])
        }
        (State::FilesystemRejecting, Event::EffectCancelled { .. }) => {
            step(State::FilesystemRejectionCancelled, &[])
        }
        (State::FilesystemProbed, Event::Cancel) => step(State::FilesystemCancelled, &[]),
        (State::FilesystemProbeFailed | State::FilesystemProbeCancelled, Event::Restart) => {
            step(State::FilesystemUnknown, &[])
        }
        (
            State::FilesystemConfinementFailed
            | State::FilesystemConfinementCancelled
            | State::FilesystemDegradationFailed
            | State::FilesystemDegradationCancelled
            | State::FilesystemRejectionFailed
            | State::FilesystemRejectionCancelled,
            Event::Restart,
        ) => step(State::FilesystemProbed, &[]),
        (
            State::FilesystemDegraded | State::FilesystemUnsupported | State::FilesystemCancelled,
            Event::Restart,
        ) => step(State::FilesystemUnknown, &[]),
        _ => None,
    }
}

fn watcher(state: State, event: Event) -> Option<(State, Vec<EffectIntent>)> {
    match (state, event) {
        (State::WatcherStarting, Event::Ready) => step(
            State::WatcherReady,
            &[
                EffectIntent::NegotiateWatcher,
                EffectIntent::SelfTestWatcherStorage,
            ],
        ),
        (State::WatcherReady, Event::Serve) => {
            step(State::WatcherServing, &[EffectIntent::VerifyProducerCanary])
        }
        (
            State::WatcherStarting
            | State::WatcherReady
            | State::WatcherServing
            | State::WatcherStale,
            Event::Degrade,
        ) => step(
            State::WatcherDegraded,
            &[EffectIntent::ReportDiagnosticsDegraded],
        ),
        (State::WatcherServing, Event::MarkStale) => step(
            State::WatcherStale,
            &[EffectIntent::ReportDiagnosticsDegraded],
        ),
        (
            State::WatcherStarting
            | State::WatcherReady
            | State::WatcherServing
            | State::WatcherDegraded
            | State::WatcherStale,
            Event::Drain | Event::Cancel,
        ) => step(State::WatcherDraining, &[EffectIntent::FlushWatcher]),
        (State::WatcherDraining, Event::EffectAcknowledged { .. }) => {
            step(State::WatcherStopped, &[])
        }
        (State::WatcherDegraded | State::WatcherStale | State::WatcherStopped, Event::Restart) => {
            step(State::WatcherStarting, &[EffectIntent::PreserveDiagnostics])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(value: u64) -> MachineInstanceId {
        MachineInstanceId::new(value).expect("test instance identity must be nonzero")
    }

    fn machine(kind: MachineKind, trace_limit: usize) -> StateMachine {
        StateMachine::new(kind, instance(1), trace_limit)
    }

    fn acknowledge_effect(model: &mut StateMachine, effect: EffectIntent) {
        let acknowledgement = model
            .pending_acknowledgements()
            .iter()
            .find(|acknowledgement| acknowledgement.effect == effect)
            .copied()
            .expect("requested effect must be pending");
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

    fn started_ffmpeg(trace_limit: usize) -> StateMachine {
        let mut model = machine(MachineKind::Ffmpeg, trace_limit);
        assert!(model.apply(Event::Spawn).is_ok());
        acknowledge_all(&mut model);
        assert!(model.apply(Event::Start).is_ok());
        model
    }

    fn probed_filesystem(trace_limit: usize) -> StateMachine {
        let mut model = machine(MachineKind::FilesystemCapability, trace_limit);
        assert!(model.apply(Event::Probe).is_ok());
        acknowledge_all(&mut model);
        assert_eq!(model.state(), State::FilesystemProbed);
        model
    }

    fn acknowledge_all(model: &mut StateMachine) {
        let pending = model.pending_acknowledgements().to_vec();
        assert!(!pending.is_empty(), "ack marker requires pending effects");
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

    fn complete_pending_effects(model: &mut StateMachine) {
        while !model.pending_acknowledgements().is_empty() {
            acknowledge_all(model);
        }
    }

    fn assert_not_durable_ffmpeg_releasing(state: State) {
        assert!(matches!(
            StateMachine::from_state(MachineKind::Ffmpeg, state, instance(9), 1, 1,),
            Err(TransitionError::StateIsNotDurable { .. })
        ));
    }

    fn run(kind: MachineKind, events: &[Event], expected: State) -> StateMachine {
        let mut model = machine(kind, events.len().saturating_mul(2).saturating_add(2));
        for event in events {
            if *event == Event::Acknowledge {
                complete_pending_effects(&mut model);
            } else {
                assert!(model.apply(*event).is_ok());
            }
        }
        assert_eq!(model.state(), expected);
        model
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_named_lifecycle_has_a_success_path() {
        let cases: &[(MachineKind, &[Event], State)] = &[
            (
                MachineKind::JobCancellation,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Reconcile,
                    Event::Acknowledge,
                ],
                State::JobSucceeded,
            ),
            (
                MachineKind::SourceRedirect,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Redirect,
                    Event::Acknowledge,
                    Event::Continue,
                    Event::Acknowledge,
                    Event::Complete,
                ],
                State::SourceResolved,
            ),
            (
                MachineKind::AtomicAdmission,
                &[
                    Event::Admit,
                    Event::Acknowledge,
                    Event::Release,
                    Event::Acknowledge,
                ],
                State::AdmissionReleased,
            ),
            (
                MachineKind::ByteCreditDurability,
                &[
                    Event::Receive,
                    Event::Acknowledge,
                    Event::Validate,
                    Event::Acknowledge,
                    Event::PersistDurably,
                    Event::Acknowledge,
                ],
                State::BytesDurable,
            ),
            (
                MachineKind::Live,
                &[
                    Event::Ready,
                    Event::Acknowledge,
                    Event::Serve,
                    Event::Acknowledge,
                    Event::Drain,
                    Event::Acknowledge,
                ],
                State::LiveStopped,
            ),
            (
                MachineKind::Sink,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Drain,
                    Event::Acknowledge,
                    Event::Complete,
                ],
                State::SinkCompleted,
            ),
            (
                MachineKind::Ffmpeg,
                &[
                    Event::Spawn,
                    Event::Acknowledge,
                    Event::Start,
                    Event::Complete,
                    Event::Acknowledge,
                ],
                State::FfmpegExited,
            ),
            (
                MachineKind::JavascriptWorker,
                &[
                    Event::Assign,
                    Event::Acknowledge,
                    Event::Start,
                    Event::Complete,
                ],
                State::JavascriptCompleted,
            ),
            (
                MachineKind::PluginIpc,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Ready,
                    Event::Assign,
                    Event::Acknowledge,
                    Event::Complete,
                    Event::Drain,
                    Event::Acknowledge,
                ],
                State::PluginStopped,
            ),
            (
                MachineKind::CommitArchiveReconciliation,
                &[
                    Event::Prepare,
                    Event::Acknowledge,
                    Event::Rename,
                    Event::Acknowledge,
                    Event::Archive,
                    Event::Acknowledge,
                    Event::Cleanup,
                    Event::Acknowledge,
                    Event::Reconcile,
                    Event::Acknowledge,
                ],
                State::CommitReconciled,
            ),
            (
                MachineKind::FilesystemCapability,
                &[
                    Event::Probe,
                    Event::Acknowledge,
                    Event::Confine,
                    Event::Acknowledge,
                ],
                State::FilesystemConfined,
            ),
            (
                MachineKind::Watcher,
                &[
                    Event::Ready,
                    Event::Acknowledge,
                    Event::Serve,
                    Event::Acknowledge,
                    Event::Drain,
                    Event::Acknowledge,
                ],
                State::WatcherStopped,
            ),
        ];
        for (kind, events, expected) in cases {
            let model = run(*kind, events, *expected);
            let replay =
                StateMachine::replay(*kind, instance(1), model.trace().len(), model.trace());
            assert!(matches!(replay, Ok(replayed) if replayed.state() == *expected));
        }
    }

    #[test]
    fn cancellation_effects_release_or_drain_resources() {
        let job = run(
            MachineKind::JobCancellation,
            &[
                Event::Start,
                Event::Acknowledge,
                Event::Cancel,
                Event::Acknowledge,
            ],
            State::JobCancelled,
        );
        assert!(
            job.trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::ReleaseResources))
        );
        let ffmpeg = run(
            MachineKind::Ffmpeg,
            &[
                Event::Spawn,
                Event::Acknowledge,
                Event::Start,
                Event::Cancel,
                Event::Acknowledge,
            ],
            State::FfmpegCancelled,
        );
        assert!(
            ffmpeg
                .trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::TerminateProcess))
        );
        assert!(
            ffmpeg
                .trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::ReapProcess))
        );
        let watcher = run(
            MachineKind::Watcher,
            &[
                Event::Ready,
                Event::Acknowledge,
                Event::Cancel,
                Event::Acknowledge,
            ],
            State::WatcherStopped,
        );
        assert!(
            watcher
                .trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::FlushWatcher))
        );
    }

    #[test]
    fn cancellation_paths_reach_expected_states() {
        let cases: &[(MachineKind, &[Event], State)] = &[
            (
                MachineKind::SourceRedirect,
                &[Event::Start, Event::Acknowledge, Event::Cancel],
                State::SourceCancelled,
            ),
            (
                MachineKind::AtomicAdmission,
                &[Event::Cancel],
                State::AdmissionCancelled,
            ),
            (
                MachineKind::ByteCreditDurability,
                &[
                    Event::Receive,
                    Event::Acknowledge,
                    Event::Cancel,
                    Event::Acknowledge,
                ],
                State::BytesCancelled,
            ),
            (
                MachineKind::Live,
                &[Event::Cancel, Event::Acknowledge],
                State::LiveCancelled,
            ),
            (
                MachineKind::Sink,
                &[Event::Cancel, Event::Acknowledge],
                State::SinkCancelled,
            ),
            (
                MachineKind::JavascriptWorker,
                &[
                    Event::Assign,
                    Event::Acknowledge,
                    Event::Cancel,
                    Event::Acknowledge,
                ],
                State::JavascriptCancelled,
            ),
            (
                MachineKind::PluginIpc,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Ready,
                    Event::Cancel,
                    Event::Acknowledge,
                ],
                State::PluginStopped,
            ),
            (
                MachineKind::Ffmpeg,
                &[Event::Cancel, Event::Acknowledge],
                State::FfmpegCancelled,
            ),
            (
                MachineKind::FilesystemCapability,
                &[Event::Probe, Event::Acknowledge, Event::Cancel],
                State::FilesystemCancelled,
            ),
            (
                MachineKind::Watcher,
                &[Event::Cancel, Event::Acknowledge],
                State::WatcherStopped,
            ),
            (
                MachineKind::CommitArchiveReconciliation,
                &[
                    Event::Prepare,
                    Event::Acknowledge,
                    Event::Cancel,
                    Event::Acknowledge,
                ],
                State::CommitCancelled,
            ),
        ];
        for (kind, events, expected) in cases {
            run(*kind, events, *expected);
        }
    }

    #[test]
    fn restart_preserves_diagnostics_and_resets_safely() {
        let source = run(
            MachineKind::SourceRedirect,
            &[
                Event::Start,
                Event::Acknowledge,
                Event::Fail,
                Event::Acknowledge,
                Event::Restart,
                Event::Acknowledge,
            ],
            State::SourceNew,
        );
        assert!(
            source
                .trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::PreserveDiagnostics))
        );
        let js = run(
            MachineKind::JavascriptWorker,
            &[
                Event::Assign,
                Event::Acknowledge,
                Event::Quarantine,
                Event::Acknowledge,
                Event::Restart,
                Event::Acknowledge,
            ],
            State::JavascriptIdle,
        );
        assert!(
            js.trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::IsolateWorker))
        );
    }

    #[test]
    fn failure_paths_complete_required_effects_before_their_outcome_state() {
        let failures: &[(MachineKind, &[Event], State)] = &[
            (
                MachineKind::JobCancellation,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                ],
                State::JobFailed,
            ),
            (
                MachineKind::ByteCreditDurability,
                &[
                    Event::Receive,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                ],
                State::BytesFailed,
            ),
            (
                MachineKind::Live,
                &[
                    Event::Ready,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                ],
                State::LiveFailed,
            ),
            (
                MachineKind::Sink,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                ],
                State::SinkFailed,
            ),
            (
                MachineKind::Ffmpeg,
                &[
                    Event::Spawn,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                    Event::Acknowledge,
                ],
                State::FfmpegFailed,
            ),
            (
                MachineKind::PluginIpc,
                &[
                    Event::Start,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                ],
                State::PluginFailed,
            ),
            (
                MachineKind::CommitArchiveReconciliation,
                &[
                    Event::Prepare,
                    Event::Acknowledge,
                    Event::Fail,
                    Event::Acknowledge,
                ],
                State::CommitInconsistent,
            ),
            (
                MachineKind::FilesystemCapability,
                &[
                    Event::Probe,
                    Event::Acknowledge,
                    Event::Reject,
                    Event::Acknowledge,
                ],
                State::FilesystemUnsupported,
            ),
            (
                MachineKind::Watcher,
                &[Event::Degrade, Event::Acknowledge],
                State::WatcherDegraded,
            ),
        ];
        for (kind, events, expected) in failures {
            run(*kind, events, *expected);
        }
    }

    #[test]
    fn commit_restart_replays_each_durable_prefix_without_false_success() -> Result<(), String> {
        let prefixes = [
            (
                State::CommitPrepared,
                State::CommitVerifyingPrepared,
                EffectIntent::RevalidatePreparedOutput,
            ),
            (
                State::CommitRenamed,
                State::CommitVerifyingRenamed,
                EffectIntent::VerifyFinalArtifact,
            ),
            (
                State::CommitArchived,
                State::CommitVerifyingArchived,
                EffectIntent::VerifyArchiveOutputPair,
            ),
            (
                State::CommitCleaned,
                State::CommitVerifyingCleaned,
                EffectIntent::VerifyArchiveOutputPair,
            ),
        ];
        for (state, _verifying, required) in prefixes {
            let model = StateMachine::from_state(
                MachineKind::CommitArchiveReconciliation,
                state,
                instance(1),
                3,
                100,
            );
            let Ok(mut model) = model else {
                return Err("commit prefix must belong to commit model".to_owned());
            };
            let result = model.apply(Event::Restart);
            assert!(matches!(result, Ok(record) if record.effects == [required]));
            assert_eq!(model.state(), State::EffectPending);
            assert_ne!(model.state(), State::CommitReconciled);
            acknowledge_all(&mut model);
            assert_eq!(model.state(), state);
        }
        Ok(())
    }

    #[test]
    fn success_and_durable_prefixes_require_effect_acknowledgements() {
        let mut job = machine(MachineKind::JobCancellation, 6);
        assert!(job.apply(Event::Start).is_ok());
        assert_eq!(job.state(), State::EffectPending);
        acknowledge_all(&mut job);
        assert_eq!(job.state(), State::JobRunning);
        assert!(job.apply(Event::Reconcile).is_ok());
        assert_eq!(job.state(), State::EffectPending);
        assert_ne!(job.state(), State::JobSucceeded);
        complete_pending_effects(&mut job);
        assert_eq!(job.state(), State::JobSucceeded);

        let mut commit = machine(MachineKind::CommitArchiveReconciliation, 11);
        for (request, acknowledged) in [
            (Event::Prepare, State::CommitPrepared),
            (Event::Rename, State::CommitRenamed),
            (Event::Archive, State::CommitArchived),
            (Event::Cleanup, State::CommitCleaned),
            (Event::Reconcile, State::CommitReconciled),
        ] {
            assert!(commit.apply(request).is_ok());
            assert_eq!(commit.state(), State::EffectPending);
            assert_ne!(commit.state(), acknowledged);
            acknowledge_all(&mut commit);
            assert_eq!(commit.state(), acknowledged);
        }

        let mut bytes = machine(MachineKind::ByteCreditDurability, 6);
        assert!(bytes.apply(Event::Receive).is_ok());
        assert_eq!(bytes.state(), State::EffectPending);
        acknowledge_all(&mut bytes);
        assert_eq!(bytes.state(), State::BytesReceived);
        assert!(bytes.apply(Event::Validate).is_ok());
        assert_eq!(bytes.state(), State::EffectPending);
        acknowledge_all(&mut bytes);
        assert_eq!(bytes.state(), State::BytesWritten);
        assert!(bytes.apply(Event::PersistDurably).is_ok());
        assert_eq!(bytes.state(), State::EffectPending);
        acknowledge_all(&mut bytes);
        assert_eq!(bytes.state(), State::BytesDurable);

        let mut cancelling = machine(MachineKind::CommitArchiveReconciliation, 8);
        assert!(cancelling.apply(Event::Prepare).is_ok());
        acknowledge_all(&mut cancelling);
        let cancel = cancelling
            .apply(Event::Cancel)
            .expect("cancel begins draining");
        assert_eq!(cancel.next, State::EffectPending);
        assert!(cancel.effects.contains(&EffectIntent::DrainInFlightEffect));
        assert!(!cancel.effects.contains(&EffectIntent::ReleaseResources));
        acknowledge_all(&mut cancelling);
        let acknowledged = cancelling.trace().last().expect("release is requested");
        assert!(
            acknowledged
                .effects
                .contains(&EffectIntent::ReleaseResources)
        );
        assert_eq!(cancelling.state(), State::EffectPending);
        acknowledge_all(&mut cancelling);
        assert_eq!(cancelling.state(), State::CommitCancelled);
    }

    #[test]
    fn generic_effect_wrapper_blocks_strict_acknowledgement_prefixes() {
        for mask in 0_u8..4 {
            let mut commit = machine(MachineKind::CommitArchiveReconciliation, 8);
            let prepare = commit
                .apply(Event::Prepare)
                .expect("prepare requests effects");
            assert_eq!(prepare.next, State::EffectPending);
            assert_eq!(
                prepare.effects,
                [EffectIntent::ValidateOutput, EffectIntent::SynchronizeData]
            );
            for (bit, effect) in [EffectIntent::ValidateOutput, EffectIntent::SynchronizeData]
                .into_iter()
                .enumerate()
            {
                if mask & (1 << bit) != 0 {
                    acknowledge_effect(&mut commit, effect);
                }
            }
            if mask == 3 {
                assert_eq!(commit.state(), State::CommitPrepared);
            } else {
                assert_eq!(commit.state(), State::EffectPending);
                assert_ne!(commit.state(), State::CommitPrepared);
                assert!(matches!(
                    StateMachine::from_state(
                        MachineKind::CommitArchiveReconciliation,
                        State::EffectPending,
                        instance(9),
                        1,
                        1,
                    ),
                    Err(TransitionError::StateIsNotDurable { .. })
                ));
            }
        }

        let mut job = machine(MachineKind::JobCancellation, 8);
        assert!(job.apply(Event::Start).is_ok());
        complete_pending_effects(&mut job);
        assert_eq!(job.state(), State::JobRunning);
        assert!(job.apply(Event::Cancel).is_ok());
        assert_eq!(job.state(), State::EffectPending);
        assert_eq!(
            job.pending_acknowledgements()[0].effect,
            EffectIntent::RequestCancellation
        );
        acknowledge_all(&mut job);
        assert_eq!(job.state(), State::EffectPending);
        assert_eq!(
            job.pending_acknowledgements()[0].effect,
            EffectIntent::ReleaseResources
        );
        assert_ne!(job.state(), State::JobCancelled);
        acknowledge_all(&mut job);
        assert_eq!(job.state(), State::JobCancelled);
    }

    #[test]
    fn generic_effect_outcomes_are_correlated_and_reissue_exact_work() {
        for cancellation in [false, true] {
            let mut commit = machine(MachineKind::CommitArchiveReconciliation, 12);
            assert!(commit.apply(Event::Prepare).is_ok());
            let failed = commit.pending_acknowledgements()[0];
            let wrong = if cancellation {
                commit.apply(Event::EffectCancelled {
                    instance_id: instance(99),
                    effect: failed.effect,
                    generation: failed.generation,
                })
            } else {
                commit.apply(Event::EffectFailed {
                    instance_id: instance(99),
                    effect: failed.effect,
                    generation: failed.generation,
                })
            };
            assert!(matches!(
                wrong,
                Err(TransitionError::UnexpectedEffectFailure { .. }
                    | TransitionError::UnexpectedEffectCancellation { .. })
            ));

            let result = if cancellation {
                commit.apply(Event::EffectCancelled {
                    instance_id: failed.instance_id,
                    effect: failed.effect,
                    generation: failed.generation,
                })
            } else {
                commit.apply(Event::EffectFailed {
                    instance_id: failed.instance_id,
                    effect: failed.effect,
                    generation: failed.generation,
                })
            };
            assert!(result.is_ok());
            assert_eq!(commit.state(), State::EffectPending);
            assert!(matches!(
                commit.apply(Event::Restart),
                Err(TransitionError::InvalidTransition { .. })
            ));
            let stale = if cancellation {
                commit.apply(Event::EffectCancelled {
                    instance_id: failed.instance_id,
                    effect: failed.effect,
                    generation: failed.generation,
                })
            } else {
                commit.apply(Event::EffectFailed {
                    instance_id: failed.instance_id,
                    effect: failed.effect,
                    generation: failed.generation,
                })
            };
            assert!(matches!(
                stale,
                Err(TransitionError::UnexpectedEffectFailure { .. }
                    | TransitionError::UnexpectedEffectCancellation { .. })
            ));
            complete_pending_effects(&mut commit);
            assert_eq!(commit.state(), State::EffectRecovery);
            assert!(matches!(
                StateMachine::from_state(
                    MachineKind::CommitArchiveReconciliation,
                    State::EffectRecovery,
                    instance(9),
                    1,
                    1,
                ),
                Err(TransitionError::StateIsNotDurable { .. })
            ));
            let retry = commit
                .apply(Event::Restart)
                .expect("restart retries exact work");
            assert_eq!(retry.next, State::EffectPending);
            assert_eq!(
                retry.effects,
                [EffectIntent::ValidateOutput, EffectIntent::SynchronizeData]
            );
            complete_pending_effects(&mut commit);
            assert_eq!(commit.state(), State::CommitPrepared);
        }
    }

    #[test]
    fn watcher_restart_cannot_claim_ready_before_diagnostics_preserve_completes() {
        let mut watcher = machine(MachineKind::Watcher, 8);
        assert!(watcher.apply(Event::Degrade).is_ok());
        complete_pending_effects(&mut watcher);
        assert_eq!(watcher.state(), State::WatcherDegraded);
        let restart = watcher
            .apply(Event::Restart)
            .expect("restart requests preservation");
        assert_eq!(restart.next, State::EffectPending);
        assert_eq!(restart.effects, [EffectIntent::PreserveDiagnostics]);
        assert_ne!(watcher.state(), State::WatcherStarting);
        acknowledge_all(&mut watcher);
        assert_eq!(watcher.state(), State::WatcherStarting);
    }

    #[test]
    fn filesystem_confinement_waits_for_establishment_acknowledgement() {
        let mut model = machine(MachineKind::FilesystemCapability, 5);
        assert!(model.apply(Event::Probe).is_ok());
        assert_eq!(model.state(), State::FilesystemProbing);
        assert!(matches!(
            model.apply(Event::Confine),
            Err(TransitionError::InvalidTransition { .. })
        ));
        acknowledge_all(&mut model);
        assert_eq!(model.state(), State::FilesystemProbed);
        let confining = model
            .apply(Event::Confine)
            .expect("confinement requests establishment");
        assert_eq!(confining.next, State::FilesystemConfining);
        assert_eq!(model.state(), State::FilesystemConfining);
        assert_ne!(model.state(), State::FilesystemConfined);
        assert_eq!(
            model
                .pending_acknowledgements()
                .iter()
                .map(|acknowledgement| acknowledgement.effect)
                .collect::<Vec<_>>(),
            vec![EffectIntent::EstablishConfinedPath]
        );
        assert!(matches!(
            StateMachine::from_state(
                MachineKind::FilesystemCapability,
                State::FilesystemConfining,
                instance(9),
                1,
                1,
            ),
            Err(TransitionError::StateIsNotDurable { .. })
        ));

        acknowledge_all(&mut model);
        assert_eq!(model.state(), State::FilesystemConfined);
    }

    #[test]
    fn filesystem_confinement_failure_is_correlated() {
        let mut failed = machine(MachineKind::FilesystemCapability, 9);
        assert!(failed.apply(Event::Probe).is_ok());
        acknowledge_all(&mut failed);
        assert!(failed.apply(Event::Confine).is_ok());
        let pending = failed.pending_acknowledgements()[0];
        let before_wrong_failure = failed.clone();
        assert!(matches!(
            failed.apply(Event::EffectFailed {
                instance_id: instance(2),
                effect: pending.effect,
                generation: pending.generation,
            }),
            Err(TransitionError::UnexpectedEffectFailure { .. })
        ));
        assert_eq!(failed, before_wrong_failure);
        assert!(matches!(
            failed.apply(Event::EffectFailed {
                instance_id: pending.instance_id,
                effect: EffectIntent::ProbeFilesystem,
                generation: pending.generation,
            }),
            Err(TransitionError::UnexpectedEffectFailure { .. })
        ));
        assert!(matches!(
            failed.apply(Event::EffectFailed {
                instance_id: pending.instance_id,
                effect: pending.effect,
                generation: pending.generation.saturating_add(1),
            }),
            Err(TransitionError::UnexpectedEffectFailure { .. })
        ));
        assert!(
            failed
                .apply(Event::EffectFailed {
                    instance_id: pending.instance_id,
                    effect: pending.effect,
                    generation: pending.generation,
                })
                .is_ok()
        );
        assert_eq!(failed.state(), State::FilesystemConfinementFailed);
        assert_ne!(failed.state(), State::FilesystemConfined);
        assert!(failed.pending_acknowledgements().is_empty());
        assert!(matches!(
            StateMachine::from_state(
                MachineKind::FilesystemCapability,
                State::FilesystemConfinementFailed,
                instance(9),
                1,
                1,
            ),
            Err(TransitionError::StateIsNotDurable { .. })
        ));
        assert!(failed.apply(Event::Restart).is_ok());
        assert_eq!(failed.state(), State::FilesystemProbed);
    }

    #[test]
    fn filesystem_confinement_cancellation_is_correlated() {
        let mut cancelled = machine(MachineKind::FilesystemCapability, 7);
        assert!(cancelled.apply(Event::Probe).is_ok());
        acknowledge_all(&mut cancelled);
        assert!(cancelled.apply(Event::Confine).is_ok());
        let pending = cancelled.pending_acknowledgements()[0];
        let before_wrong_cancellation = cancelled.clone();
        assert!(matches!(
            cancelled.apply(Event::EffectCancelled {
                instance_id: instance(2),
                effect: pending.effect,
                generation: pending.generation,
            }),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
        assert_eq!(cancelled, before_wrong_cancellation);
        assert!(matches!(
            cancelled.apply(Event::EffectCancelled {
                instance_id: pending.instance_id,
                effect: EffectIntent::ProbeFilesystem,
                generation: pending.generation,
            }),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
        assert!(matches!(
            cancelled.apply(Event::EffectCancelled {
                instance_id: pending.instance_id,
                effect: pending.effect,
                generation: pending.generation.saturating_add(1),
            }),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
        assert!(
            cancelled
                .apply(Event::EffectCancelled {
                    instance_id: pending.instance_id,
                    effect: pending.effect,
                    generation: pending.generation,
                })
                .is_ok()
        );
        assert_eq!(cancelled.state(), State::FilesystemConfinementCancelled);
        assert!(cancelled.pending_acknowledgements().is_empty());
        assert!(matches!(
            cancelled.apply(Event::EffectCancelled {
                instance_id: pending.instance_id,
                effect: pending.effect,
                generation: pending.generation,
            }),
            Err(TransitionError::UnexpectedEffectCancellation { .. })
        ));
    }

    #[test]
    fn filesystem_probe_requires_correlated_completion_or_recovery() {
        let mut probing = machine(MachineKind::FilesystemCapability, 8);
        assert!(probing.apply(Event::Probe).is_ok());
        assert_eq!(probing.state(), State::FilesystemProbing);
        assert_eq!(
            probing.pending_acknowledgements()[0].effect,
            EffectIntent::ProbeFilesystem
        );
        for premature in [
            Event::Confine,
            Event::Degrade,
            Event::Reject,
            Event::Restart,
        ] {
            assert!(matches!(
                probing.apply(premature),
                Err(TransitionError::InvalidTransition { .. })
            ));
        }
        for (outcome, expected) in [
            (false, State::FilesystemProbeFailed),
            (true, State::FilesystemProbeCancelled),
        ] {
            let mut model = machine(MachineKind::FilesystemCapability, 8);
            assert!(model.apply(Event::Probe).is_ok());
            let pending = model.pending_acknowledgements()[0];
            let result = if outcome {
                model.apply(Event::EffectCancelled {
                    instance_id: pending.instance_id,
                    effect: pending.effect,
                    generation: pending.generation,
                })
            } else {
                model.apply(Event::EffectFailed {
                    instance_id: pending.instance_id,
                    effect: pending.effect,
                    generation: pending.generation,
                })
            };
            assert!(result.is_ok());
            assert_eq!(model.state(), expected);
            assert!(model.pending_acknowledgements().is_empty());
            assert!(model.apply(Event::Restart).is_ok());
            let retry = model
                .apply(Event::Probe)
                .expect("probe retry must reissue effect");
            assert_eq!(retry.effects, [EffectIntent::ProbeFilesystem]);
        }
    }

    #[test]
    fn filesystem_post_probe_effects_require_acknowledgement_and_retry() {
        let cases: &[(Event, State, EffectIntent, State, State)] = &[
            (
                Event::Confine,
                State::FilesystemConfining,
                EffectIntent::EstablishConfinedPath,
                State::FilesystemConfinementFailed,
                State::FilesystemConfinementCancelled,
            ),
            (
                Event::Degrade,
                State::FilesystemDegrading,
                EffectIntent::ReportDegradedGuarantees,
                State::FilesystemDegradationFailed,
                State::FilesystemDegradationCancelled,
            ),
            (
                Event::Reject,
                State::FilesystemRejecting,
                EffectIntent::RejectFilesystem,
                State::FilesystemRejectionFailed,
                State::FilesystemRejectionCancelled,
            ),
        ];
        for (request, waiting, effect, failed, cancelled) in cases {
            let mut acknowledged = probed_filesystem(16);
            let transition = acknowledged.apply(*request).expect("effect is requested");
            assert_eq!(transition.next, *waiting);
            assert_eq!(transition.effects, [*effect]);
            assert_eq!(acknowledged.state(), *waiting);
            assert_ne!(acknowledged.state(), State::FilesystemConfined);
            assert_ne!(acknowledged.state(), State::FilesystemDegraded);
            assert_ne!(acknowledged.state(), State::FilesystemUnsupported);
            assert!(matches!(
                StateMachine::from_state(
                    MachineKind::FilesystemCapability,
                    *waiting,
                    instance(9),
                    1,
                    1,
                ),
                Err(TransitionError::StateIsNotDurable { .. })
            ));
            acknowledge_effect(&mut acknowledged, *effect);
            let terminal = match request {
                Event::Confine => State::FilesystemConfined,
                Event::Degrade => State::FilesystemDegraded,
                Event::Reject => State::FilesystemUnsupported,
                _ => unreachable!("filesystem case list is closed"),
            };
            assert_eq!(acknowledged.state(), terminal);

            for cancellation in [false, true] {
                let mut model = probed_filesystem(16);
                assert!(model.apply(*request).is_ok());
                let pending = model.pending_acknowledgements()[0];
                let result = if cancellation {
                    model.apply(Event::EffectCancelled {
                        instance_id: pending.instance_id,
                        effect: pending.effect,
                        generation: pending.generation,
                    })
                } else {
                    model.apply(Event::EffectFailed {
                        instance_id: pending.instance_id,
                        effect: pending.effect,
                        generation: pending.generation,
                    })
                };
                assert!(result.is_ok());
                assert_eq!(
                    model.state(),
                    if cancellation { *cancelled } else { *failed }
                );
                assert!(model.pending_acknowledgements().is_empty());
                assert!(model.apply(Event::Restart).is_ok());
                assert_eq!(model.state(), State::FilesystemProbed);
                let retry = model
                    .apply(*request)
                    .expect("operation retry must reissue effect");
                assert_eq!(retry.effects, [*effect]);
            }
        }
    }

    #[test]
    fn ffmpeg_terminal_states_wait_for_process_and_release_effects() {
        let mut completed = machine(MachineKind::Ffmpeg, 8);
        assert!(completed.apply(Event::Spawn).is_ok());
        acknowledge_all(&mut completed);
        assert!(completed.apply(Event::Start).is_ok());
        assert!(completed.apply(Event::Complete).is_ok());
        acknowledge_all(&mut completed);
        assert_eq!(completed.state(), State::FfmpegExitReleasing);
        assert_ne!(completed.state(), State::FfmpegExited);
        assert_not_durable_ffmpeg_releasing(State::FfmpegExitReleasing);
        acknowledge_all(&mut completed);
        assert_eq!(completed.state(), State::FfmpegExited);

        let mut prepared_cancel = machine(MachineKind::Ffmpeg, 4);
        assert!(prepared_cancel.apply(Event::Cancel).is_ok());
        assert_eq!(prepared_cancel.state(), State::FfmpegCancellationReleasing);
        acknowledge_all(&mut prepared_cancel);
        assert_eq!(prepared_cancel.state(), State::FfmpegCancelled);

        for order in [
            [EffectIntent::TerminateProcess, EffectIntent::ReapProcess],
            [EffectIntent::ReapProcess, EffectIntent::TerminateProcess],
        ] {
            let mut model = machine(MachineKind::Ffmpeg, 8);
            assert!(model.apply(Event::Spawn).is_ok());
            acknowledge_all(&mut model);
            assert!(model.apply(Event::Start).is_ok());
            let cancelling = model.apply(Event::Cancel).expect("cancel begins reaping");
            assert_eq!(cancelling.next, State::FfmpegCancelling);
            assert!(!cancelling.effects.contains(&EffectIntent::ReleaseResources));

            let first = model
                .pending_acknowledgements()
                .iter()
                .find(|acknowledgement| acknowledgement.effect == order[0])
                .copied()
                .expect("requested effect must be pending");
            let partial = model
                .apply(Event::EffectAcknowledged {
                    instance_id: first.instance_id,
                    effect: first.effect,
                    generation: first.generation,
                })
                .expect("first acknowledgement remains pending");
            assert_eq!(partial.next, State::FfmpegCancelling);
            assert!(partial.effects.is_empty());
            assert_eq!(model.state(), State::FfmpegCancelling);
            assert_ne!(model.state(), State::FfmpegCancelled);
            assert_eq!(model.pending_acknowledgements().len(), 1);

            let final_acknowledgement = model.pending_acknowledgements()[0];
            let completed = model
                .apply(Event::EffectAcknowledged {
                    instance_id: final_acknowledgement.instance_id,
                    effect: final_acknowledgement.effect,
                    generation: final_acknowledgement.generation,
                })
                .expect("both process effects complete cancellation");
            assert_eq!(completed.next, State::FfmpegCancellationReleasing);
            assert!(completed.effects.contains(&EffectIntent::ReleaseResources));
            assert_eq!(model.state(), State::FfmpegCancellationReleasing);
            assert_ne!(model.state(), State::FfmpegCancelled);
            assert_eq!(model.pending_acknowledgements().len(), 1);
            acknowledge_all(&mut model);
            assert_eq!(model.state(), State::FfmpegCancelled);
        }

        let mut failing = machine(MachineKind::Ffmpeg, 8);
        assert!(failing.apply(Event::Spawn).is_ok());
        acknowledge_all(&mut failing);
        let failure = failing
            .apply(Event::Fail)
            .expect("failure begins process cleanup");
        assert_eq!(failure.next, State::FfmpegFailing);
        assert!(failure.effects.contains(&EffectIntent::TerminateProcess));
        assert!(failure.effects.contains(&EffectIntent::ReapProcess));
        assert!(!failure.effects.contains(&EffectIntent::ReleaseResources));

        let preserve = failing
            .pending_acknowledgements()
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::PreserveDiagnostics)
            .copied()
            .expect("diagnostic preservation must be pending");
        assert!(
            failing
                .apply(Event::EffectAcknowledged {
                    instance_id: preserve.instance_id,
                    effect: preserve.effect,
                    generation: preserve.generation,
                })
                .is_ok()
        );
        assert_eq!(failing.state(), State::FfmpegFailing);
        assert_eq!(failing.pending_acknowledgements().len(), 2);
        acknowledge_all(&mut failing);
        assert_eq!(failing.state(), State::FfmpegFailureReleasing);
        assert!(
            failing
                .trace()
                .last()
                .is_some_and(|record| record.effects.contains(&EffectIntent::ReleaseResources))
        );
        assert_ne!(failing.state(), State::FfmpegFailed);
        assert_eq!(failing.pending_acknowledgements().len(), 1);
        acknowledge_all(&mut failing);
        assert_eq!(failing.state(), State::FfmpegFailed);
    }

    #[test]
    fn ffmpeg_acknowledgement_prefixes_cannot_skip_cleanup_or_release() {
        for mask in 0_u8..4 {
            let mut model = started_ffmpeg(16);
            assert!(model.apply(Event::Cancel).is_ok());
            for (bit, effect) in [EffectIntent::TerminateProcess, EffectIntent::ReapProcess]
                .into_iter()
                .enumerate()
            {
                if mask & (1 << bit) != 0 {
                    acknowledge_effect(&mut model, effect);
                }
            }
            if mask == 3 {
                assert_eq!(model.state(), State::FfmpegCancellationReleasing);
                assert_eq!(
                    model.pending_acknowledgements()[0].effect,
                    EffectIntent::ReleaseResources
                );
            } else {
                assert_eq!(model.state(), State::FfmpegCancelling);
                assert_ne!(model.state(), State::FfmpegCancellationReleasing);
                assert_ne!(model.state(), State::FfmpegCancelled);
            }
        }

        for mask in 0_u8..8 {
            let mut model = started_ffmpeg(20);
            assert!(model.apply(Event::Fail).is_ok());
            for (bit, effect) in [
                EffectIntent::TerminateProcess,
                EffectIntent::ReapProcess,
                EffectIntent::PreserveDiagnostics,
            ]
            .into_iter()
            .enumerate()
            {
                if mask & (1 << bit) != 0 {
                    acknowledge_effect(&mut model, effect);
                }
            }
            if mask == 7 {
                assert_eq!(model.state(), State::FfmpegFailureReleasing);
                assert_eq!(
                    model.pending_acknowledgements()[0].effect,
                    EffectIntent::ReleaseResources
                );
            } else {
                assert_eq!(model.state(), State::FfmpegFailing);
                assert_ne!(model.state(), State::FfmpegFailureReleasing);
                assert_ne!(model.state(), State::FfmpegFailed);
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ffmpeg_effect_outcomes_are_correlated_nonterminal_and_recoverable() {
        fn spawning() -> StateMachine {
            let mut model = machine(MachineKind::Ffmpeg, 32);
            assert!(model.apply(Event::Spawn).is_ok());
            model
        }

        fn reaping() -> StateMachine {
            let mut model = started_ffmpeg(32);
            assert!(model.apply(Event::Complete).is_ok());
            model
        }

        fn cancelling() -> StateMachine {
            let mut model = started_ffmpeg(32);
            assert!(model.apply(Event::Cancel).is_ok());
            model
        }

        fn failing() -> StateMachine {
            let mut model = started_ffmpeg(32);
            assert!(model.apply(Event::Fail).is_ok());
            model
        }

        fn exit_releasing() -> StateMachine {
            let mut model = reaping();
            acknowledge_all(&mut model);
            model
        }

        fn cancellation_releasing() -> StateMachine {
            let mut model = cancelling();
            acknowledge_all(&mut model);
            model
        }

        fn failure_releasing() -> StateMachine {
            let mut model = failing();
            acknowledge_all(&mut model);
            model
        }

        type Builder = fn() -> StateMachine;
        let cases: &[(&str, Builder, State, State, &[EffectIntent])] = &[
            (
                "spawn",
                spawning,
                State::FfmpegSpawnRecovering,
                State::FfmpegSpawning,
                &[EffectIntent::SpawnProcess],
            ),
            (
                "reap",
                reaping,
                State::FfmpegReapRecovering,
                State::FfmpegReaping,
                &[EffectIntent::ReapProcess],
            ),
            (
                "exit-release",
                exit_releasing,
                State::FfmpegExitReleaseRecovering,
                State::FfmpegExitReleasing,
                &[EffectIntent::ReleaseResources],
            ),
            (
                "cancellation-release",
                cancellation_releasing,
                State::FfmpegCancellationReleaseRecovering,
                State::FfmpegCancellationReleasing,
                &[EffectIntent::ReleaseResources],
            ),
            (
                "failure-release",
                failure_releasing,
                State::FfmpegFailureReleaseRecovering,
                State::FfmpegFailureReleasing,
                &[EffectIntent::ReleaseResources],
            ),
        ];

        for (label, build, recovery, retry_state, retry_effects) in cases {
            for cancellation in [false, true] {
                for pending in build().pending_acknowledgements().to_vec() {
                    let mut model = build();
                    let before_wrong_receipt = model.clone();
                    let wrong_instance = if cancellation {
                        model.apply(Event::EffectCancelled {
                            instance_id: instance(99),
                            effect: pending.effect,
                            generation: pending.generation,
                        })
                    } else {
                        model.apply(Event::EffectFailed {
                            instance_id: instance(99),
                            effect: pending.effect,
                            generation: pending.generation,
                        })
                    };
                    assert!(
                        matches!(
                            wrong_instance,
                            Err(TransitionError::UnexpectedEffectFailure { .. }
                                | TransitionError::UnexpectedEffectCancellation { .. })
                        ),
                        "{label} must reject cross-instance outcome receipts"
                    );
                    assert_eq!(model, before_wrong_receipt);

                    let result = if cancellation {
                        model.apply(Event::EffectCancelled {
                            instance_id: pending.instance_id,
                            effect: pending.effect,
                            generation: pending.generation,
                        })
                    } else {
                        model.apply(Event::EffectFailed {
                            instance_id: pending.instance_id,
                            effect: pending.effect,
                            generation: pending.generation,
                        })
                    };
                    assert!(result.is_ok(), "{label} must accept its correlated outcome");
                    assert_eq!(model.state(), *recovery);
                    assert_ne!(model.state(), State::FfmpegExited);
                    assert_ne!(model.state(), State::FfmpegCancelled);
                    assert_ne!(model.state(), State::FfmpegFailed);
                    assert_eq!(
                        model.pending_acknowledgements()[0].effect,
                        EffectIntent::PreserveDiagnostics
                    );
                    assert!(matches!(
                        StateMachine::from_state(MachineKind::Ffmpeg, *recovery, instance(9), 1, 1),
                        Err(TransitionError::StateIsNotDurable { .. })
                    ));
                    assert!(matches!(
                        model.apply(Event::Restart),
                        Err(TransitionError::InvalidTransition { .. })
                    ));

                    let stale = if cancellation {
                        model.apply(Event::EffectCancelled {
                            instance_id: pending.instance_id,
                            effect: pending.effect,
                            generation: pending.generation,
                        })
                    } else {
                        model.apply(Event::EffectFailed {
                            instance_id: pending.instance_id,
                            effect: pending.effect,
                            generation: pending.generation,
                        })
                    };
                    assert!(
                        matches!(
                            stale,
                            Err(TransitionError::UnexpectedEffectFailure { .. }
                                | TransitionError::UnexpectedEffectCancellation { .. })
                        ),
                        "{label} must reject stale outcome receipts"
                    );

                    let mut acknowledged = model.clone();
                    acknowledge_effect(&mut acknowledged, EffectIntent::PreserveDiagnostics);
                    assert_eq!(acknowledged.state(), *recovery);
                    assert!(acknowledged.pending_acknowledgements().is_empty());
                    let restart = acknowledged
                        .apply(Event::Restart)
                        .expect("retry is explicit");
                    assert_eq!(restart.next, *retry_state);
                    assert_eq!(restart.effects, *retry_effects);

                    for diagnostic_cancellation in [false, true] {
                        let mut diagnostic_outcome = model.clone();
                        let diagnostic = diagnostic_outcome.pending_acknowledgements()[0];
                        let result = if diagnostic_cancellation {
                            diagnostic_outcome.apply(Event::EffectCancelled {
                                instance_id: diagnostic.instance_id,
                                effect: diagnostic.effect,
                                generation: diagnostic.generation,
                            })
                        } else {
                            diagnostic_outcome.apply(Event::EffectFailed {
                                instance_id: diagnostic.instance_id,
                                effect: diagnostic.effect,
                                generation: diagnostic.generation,
                            })
                        };
                        assert!(result.is_ok(), "{label} diagnostic outcome remains typed");
                        assert_eq!(diagnostic_outcome.state(), *recovery);
                        assert!(diagnostic_outcome.pending_acknowledgements().is_empty());
                        let restart = diagnostic_outcome
                            .apply(Event::Restart)
                            .expect("failed diagnostic remains recoverable");
                        assert_eq!(restart.next, *retry_state);
                        assert_eq!(restart.effects, *retry_effects);
                    }
                }
            }
        }
    }

    #[test]
    fn ffmpeg_partial_unsuccessful_outcomes_wait_for_every_original_receipt() {
        type Builder = fn() -> StateMachine;
        let cases: &[(&str, Builder, State, State, &[EffectIntent])] = &[
            (
                "cancellation-cleanup",
                || {
                    let mut model = started_ffmpeg(48);
                    assert!(model.apply(Event::Cancel).is_ok());
                    model
                },
                State::FfmpegCancellationRecovering,
                State::FfmpegCancelling,
                &[EffectIntent::TerminateProcess, EffectIntent::ReapProcess],
            ),
            (
                "failure-cleanup",
                || {
                    let mut model = started_ffmpeg(48);
                    assert!(model.apply(Event::Fail).is_ok());
                    model
                },
                State::FfmpegFailureRecovering,
                State::FfmpegFailing,
                &[
                    EffectIntent::TerminateProcess,
                    EffectIntent::ReapProcess,
                    EffectIntent::PreserveDiagnostics,
                ],
            ),
        ];

        for (label, build, recovery, waiting, expected_reissue) in cases {
            for cancelled in [false, true] {
                let original_count = build().pending_acknowledgements().len();
                for unsuccessful_index in 0..original_count {
                    let mut model = build();
                    let original = model.pending_acknowledgements().to_vec();
                    for acknowledgement in &original[..unsuccessful_index] {
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

                    let unsuccessful = original[unsuccessful_index];
                    let result = if cancelled {
                        model.apply(Event::EffectCancelled {
                            instance_id: unsuccessful.instance_id,
                            effect: unsuccessful.effect,
                            generation: unsuccessful.generation,
                        })
                    } else {
                        model.apply(Event::EffectFailed {
                            instance_id: unsuccessful.instance_id,
                            effect: unsuccessful.effect,
                            generation: unsuccessful.generation,
                        })
                    };
                    assert!(result.is_ok(), "{label} outcome must be correlated");

                    let remaining = original_count - unsuccessful_index - 1;
                    if remaining > 0 {
                        assert_eq!(model.state(), *waiting, "{label} must retain cleanup state");
                        assert_eq!(model.pending_acknowledgements().len(), remaining);
                        assert!(matches!(
                            model.apply(Event::Restart),
                            Err(TransitionError::InvalidTransition { .. })
                        ));
                        acknowledge_all(&mut model);
                    }

                    assert_eq!(
                        model.state(),
                        *recovery,
                        "{label} recovers only after every outcome"
                    );
                    assert_eq!(
                        model.pending_acknowledgements()[0].effect,
                        EffectIntent::PreserveDiagnostics
                    );
                    acknowledge_all(&mut model);
                    let retry = model.apply(Event::Restart).expect("explicit exact retry");
                    assert_eq!(retry.next, *waiting);
                    assert_eq!(retry.effects, *expected_reissue);
                }
            }
        }
    }

    fn assert_ffmpeg_cancellation_waits_for_out_of_order_unsuccessful_receipts() {
        let mut cancelling = started_ffmpeg(48);
        assert!(cancelling.apply(Event::Cancel).is_ok());
        let cancellation_original = cancelling.pending_acknowledgements().to_vec();
        let cancellation_effects = cancellation_original
            .iter()
            .map(|acknowledgement| acknowledgement.effect)
            .collect::<Vec<_>>();
        let cancellation_generation = cancellation_original[0].generation;
        let terminate = cancellation_original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::TerminateProcess)
            .copied()
            .expect("termination must be pending");
        let reap = cancellation_original
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
        assert!(matches!(
            cancelling.apply(Event::Restart),
            Err(TransitionError::InvalidTransition { .. })
        ));

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
        acknowledge_all(&mut cancelling);
        let cancellation_retry = cancelling
            .apply(Event::Restart)
            .expect("recovery must reissue the exact cancellation cleanup set");
        assert_eq!(cancellation_retry.next, State::FfmpegCancelling);
        assert_eq!(cancellation_retry.effects, cancellation_effects);
        assert!(
            cancelling
                .pending_acknowledgements()
                .iter()
                .all(|acknowledgement| acknowledgement.generation != cancellation_generation)
        );
    }

    fn assert_ffmpeg_failure_waits_for_out_of_order_unsuccessful_receipts() {
        let mut failing = started_ffmpeg(64);
        assert!(failing.apply(Event::Fail).is_ok());
        let failure_original = failing.pending_acknowledgements().to_vec();
        let failure_effects = failure_original
            .iter()
            .map(|acknowledgement| acknowledgement.effect)
            .collect::<Vec<_>>();
        let failure_generation = failure_original[0].generation;
        let terminate = failure_original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::TerminateProcess)
            .copied()
            .expect("termination must be pending");
        let reap = failure_original
            .iter()
            .find(|acknowledgement| acknowledgement.effect == EffectIntent::ReapProcess)
            .copied()
            .expect("reap must be pending");
        let preserve = failure_original
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
        assert!(matches!(
            failing.apply(Event::Restart),
            Err(TransitionError::InvalidTransition { .. })
        ));

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
        acknowledge_all(&mut failing);
        let failure_retry = failing
            .apply(Event::Restart)
            .expect("recovery must reissue the exact failure cleanup set");
        assert_eq!(failure_retry.next, State::FfmpegFailing);
        assert_eq!(failure_retry.effects, failure_effects);
        assert!(
            failing
                .pending_acknowledgements()
                .iter()
                .all(|acknowledgement| acknowledgement.generation != failure_generation)
        );
    }

    #[test]
    fn ffmpeg_out_of_order_mixed_unsuccessful_outcomes_recover_after_all_original_receipts() {
        assert_ffmpeg_cancellation_waits_for_out_of_order_unsuccessful_receipts();
        assert_ffmpeg_failure_waits_for_out_of_order_unsuccessful_receipts();
    }

    #[test]
    fn recovery_retries_reject_prior_generation_effect_outcomes() {
        for (event, recovery, retry_state) in [
            (
                Event::Cancel,
                State::FfmpegCancellationRecovering,
                State::FfmpegCancelling,
            ),
            (
                Event::Fail,
                State::FfmpegFailureRecovering,
                State::FfmpegFailing,
            ),
        ] {
            let mut ffmpeg = started_ffmpeg(64);
            assert!(ffmpeg.apply(event).is_ok());
            let stale = ffmpeg.pending_acknowledgements()[0];
            assert!(ffmpeg.apply(unsuccessful_outcome(false, stale)).is_ok());
            complete_pending_effects(&mut ffmpeg);
            assert_eq!(ffmpeg.state(), recovery);
            assert!(ffmpeg.apply(Event::Restart).is_ok());
            assert_eq!(ffmpeg.state(), retry_state);

            let before_stale_receipts = ffmpeg.clone();
            assert!(matches!(
                ffmpeg.apply(Event::EffectAcknowledged {
                    instance_id: stale.instance_id,
                    effect: stale.effect,
                    generation: stale.generation,
                }),
                Err(TransitionError::UnexpectedAcknowledgement { .. })
            ));
            assert!(matches!(
                ffmpeg.apply(unsuccessful_outcome(false, stale)),
                Err(TransitionError::UnexpectedEffectFailure { .. })
            ));
            assert!(matches!(
                ffmpeg.apply(unsuccessful_outcome(true, stale)),
                Err(TransitionError::UnexpectedEffectCancellation { .. })
            ));
            assert_eq!(ffmpeg, before_stale_receipts);
        }

        for cancellation in [false, true] {
            let mut filesystem = probed_filesystem(16);
            assert!(filesystem.apply(Event::Confine).is_ok());
            let stale = filesystem.pending_acknowledgements()[0];
            assert!(
                filesystem
                    .apply(unsuccessful_outcome(cancellation, stale))
                    .is_ok()
            );
            assert!(filesystem.apply(Event::Restart).is_ok());
            assert_eq!(filesystem.state(), State::FilesystemProbed);
            assert!(filesystem.apply(Event::Confine).is_ok());

            let before_stale_receipts = filesystem.clone();
            assert!(matches!(
                filesystem.apply(Event::EffectAcknowledged {
                    instance_id: stale.instance_id,
                    effect: stale.effect,
                    generation: stale.generation,
                }),
                Err(TransitionError::UnexpectedAcknowledgement { .. })
            ));
            assert!(matches!(
                filesystem.apply(unsuccessful_outcome(false, stale)),
                Err(TransitionError::UnexpectedEffectFailure { .. })
            ));
            assert!(matches!(
                filesystem.apply(unsuccessful_outcome(true, stale)),
                Err(TransitionError::UnexpectedEffectCancellation { .. })
            ));
            assert_eq!(filesystem, before_stale_receipts);
        }
    }

    #[test]
    fn illegal_transitions_are_typed_and_do_not_mutate_or_trace() {
        let mut model = machine(MachineKind::CommitArchiveReconciliation, 2);
        assert!(matches!(
            model.apply(Event::Archive),
            Err(TransitionError::InvalidTransition { .. })
        ));
        assert_eq!(model.state(), State::CommitWorking);
        assert!(model.trace().is_empty());
        assert!(matches!(
            StateMachine::from_state(MachineKind::Watcher, State::JobQueued, instance(1), 1, 1,),
            Err(TransitionError::StateDoesNotBelongToMachine { .. })
        ));
    }

    #[test]
    fn trace_bound_is_checked_before_transition() {
        let mut model = machine(MachineKind::SourceRedirect, 1);
        assert!(model.apply(Event::Start).is_ok());
        assert!(matches!(
            model.apply(Event::Complete),
            Err(TransitionError::TraceLimitReached { limit: 1 })
        ));
        assert_eq!(model.state(), State::EffectPending);
    }

    #[test]
    fn replay_detects_counterfactual_trace_mutation() {
        let model = run(
            MachineKind::ByteCreditDurability,
            &[
                Event::Receive,
                Event::Acknowledge,
                Event::Validate,
                Event::Acknowledge,
                Event::PersistDurably,
                Event::Acknowledge,
            ],
            State::BytesDurable,
        );
        let mut mutated = model.trace().to_vec();
        if let Some(record) = mutated.get_mut(1) {
            record.next = State::BytesDurable;
        }
        assert!(matches!(
            StateMachine::replay(MachineKind::ByteCreditDurability, instance(1), 5, &mutated,),
            Err(TransitionError::ReplayMismatch { index: 1 })
        ));
    }

    #[test]
    fn degraded_filesystem_never_claims_confinement() {
        let degraded = run(
            MachineKind::FilesystemCapability,
            &[
                Event::Probe,
                Event::Acknowledge,
                Event::Degrade,
                Event::Acknowledge,
            ],
            State::FilesystemDegraded,
        );
        assert!(degraded.trace().iter().any(|record| {
            record
                .effects
                .contains(&EffectIntent::ReportDegradedGuarantees)
        }));
        let model = StateMachine::from_state(
            MachineKind::FilesystemCapability,
            State::FilesystemDegraded,
            instance(1),
            1,
            1,
        );
        let Ok(mut model) = model else {
            return assert!(matches!(
                model,
                Err(TransitionError::StateDoesNotBelongToMachine { .. })
            ));
        };
        assert!(matches!(
            model.apply(Event::Confine),
            Err(TransitionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn transient_restore_and_stale_or_wrong_acknowledgements_are_rejected() {
        assert!(matches!(
            StateMachine::from_state(
                MachineKind::CommitArchiveReconciliation,
                State::CommitRenaming,
                instance(1),
                4,
                40,
            ),
            Err(TransitionError::StateIsNotDurable { .. })
        ));

        let mut model = machine(MachineKind::CommitArchiveReconciliation, 8);
        assert!(model.apply(Event::Prepare).is_ok());
        let stale = model.pending_acknowledgements()[0];
        complete_pending_effects(&mut model);
        assert!(model.apply(Event::Cancel).is_ok());
        let cancellation = model.pending_acknowledgements()[0];
        assert_ne!(stale.generation, cancellation.generation);
        assert!(matches!(
            model.apply(Event::EffectAcknowledged {
                instance_id: stale.instance_id,
                effect: stale.effect,
                generation: stale.generation,
            }),
            Err(TransitionError::UnexpectedAcknowledgement { .. })
        ));
        assert!(matches!(
            model.apply(Event::EffectAcknowledged {
                instance_id: cancellation.instance_id,
                effect: EffectIntent::RenameOutput,
                generation: cancellation.generation,
            }),
            Err(TransitionError::UnexpectedAcknowledgement { .. })
        ));
        assert!(matches!(
            model.apply(Event::Acknowledge),
            Err(TransitionError::InvalidTransition { .. })
        ));
        assert_eq!(model.state(), State::EffectPending);
        assert!(model.pending_acknowledgements().contains(&cancellation));
    }

    #[test]
    fn acknowledgement_rejects_cross_instance_routing() {
        let mut first =
            StateMachine::new(MachineKind::CommitArchiveReconciliation, instance(41), 4);
        let mut second =
            StateMachine::new(MachineKind::CommitArchiveReconciliation, instance(42), 4);
        assert!(first.apply(Event::Prepare).is_ok());
        assert!(second.apply(Event::Prepare).is_ok());
        let first_ack = first.pending_acknowledgements()[0];
        let second_ack = second.pending_acknowledgements()[0];
        assert_eq!(first_ack.effect, second_ack.effect);
        assert_eq!(first_ack.generation, second_ack.generation);
        assert_ne!(first_ack.instance_id, second_ack.instance_id);

        let prior = second.clone();
        assert!(matches!(
            second.apply(Event::EffectAcknowledged {
                instance_id: first_ack.instance_id,
                effect: first_ack.effect,
                generation: first_ack.generation,
            }),
            Err(TransitionError::UnexpectedAcknowledgement { .. })
        ));
        assert_eq!(second, prior);
    }

    #[test]
    fn restoration_accepts_only_inventory_enumerated_durable_states() {
        for state in [
            State::CommitPrepared,
            State::CommitRenamed,
            State::CommitArchived,
            State::CommitCleaned,
            State::CommitReconciled,
        ] {
            assert!(
                StateMachine::from_state(
                    MachineKind::CommitArchiveReconciliation,
                    state,
                    instance(7),
                    1,
                    2,
                )
                .is_ok()
            );
        }
        for state in [
            State::CommitWorking,
            State::CommitPreparing,
            State::CommitRenaming,
            State::CommitInconsistent,
            State::CommitCancelled,
            State::EffectPending,
            State::EffectRecovery,
        ] {
            assert!(matches!(
                StateMachine::from_state(
                    MachineKind::CommitArchiveReconciliation,
                    state,
                    instance(7),
                    1,
                    2,
                ),
                Err(TransitionError::StateIsNotDurable { .. })
            ));
        }
        for (kind, state) in [
            (MachineKind::AtomicAdmission, State::AdmissionReleased),
            (MachineKind::JavascriptWorker, State::JavascriptCompleted),
            (MachineKind::PluginIpc, State::PluginStopped),
        ] {
            assert!(matches!(
                StateMachine::from_state(kind, state, instance(7), 1, 2),
                Err(TransitionError::StateIsNotDurable { .. })
            ));
        }
    }
}
