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
    FfmpegSpawned,
    FfmpegRunning,
    FfmpegReaping,
    FfmpegCancelling,
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
    FilesystemConfined,
    FilesystemDegraded,
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

/// One bounded, deterministic state machine instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMachine {
    instance_id: MachineInstanceId,
    kind: MachineKind,
    state: State,
    trace_limit: usize,
    trace: Vec<Transition>,
    pending_acknowledgements: Vec<EffectAcknowledgement>,
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
        let mut remaining_acknowledgements = self.pending_acknowledgements.clone();
        if let Event::EffectAcknowledged {
            instance_id,
            effect,
            generation,
        } = event
        {
            let Some(index) = remaining_acknowledgements.iter().position(|expected| {
                expected.instance_id == instance_id
                    && expected.effect == effect
                    && expected.generation == generation
            }) else {
                return Err(TransitionError::UnexpectedAcknowledgement {
                    instance_id,
                    effect,
                    generation,
                    expected: self.pending_acknowledgements.clone(),
                });
            };
            remaining_acknowledgements.remove(index);
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
        }
        let (next, effects) = transition(self.kind, self.state, event)?;
        let required = acknowledgement_effects(next, &effects);
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
        self.next_effect_generation = next_generation;
        self.trace.push(record);
        let index = self.trace.len() - 1;
        self.trace
            .get(index)
            .ok_or(TransitionError::ReplayMismatch { index })
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
                | State::FfmpegSpawned
                | State::FfmpegRunning
                | State::FfmpegReaping
                | State::FfmpegCancelling
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
                | State::FilesystemConfined
                | State::FilesystemDegraded
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
        State::FfmpegReaping => &[EffectIntent::ReapProcess],
        State::FfmpegCancelling => &[EffectIntent::TerminateProcess],
        State::JavascriptRecycling => &[EffectIntent::RecycleWorker],
        State::PluginDraining => &[EffectIntent::ClosePluginChannel],
        State::CommitPreparing => &[EffectIntent::ValidateOutput, EffectIntent::SynchronizeData],
        State::CommitRenaming => &[EffectIntent::RenameOutput],
        State::CommitArchiving => &[EffectIntent::InsertArchiveRow],
        State::CommitCleaning => &[EffectIntent::RemoveTemporaryState],
        State::CommitVerifyingPrepared => &[EffectIntent::RevalidatePreparedOutput],
        State::CommitVerifyingRenamed => &[EffectIntent::VerifyFinalArtifact],
        State::CommitCancelling => &[EffectIntent::DrainInFlightEffect],
        State::WatcherDraining => &[EffectIntent::FlushWatcher],
        _ => &[],
    };
    required
        .iter()
        .copied()
        .filter(|effect| emitted.contains(effect))
        .collect()
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
    match (state, event) {
        (State::FfmpegPrepared, Event::Spawn) => {
            step(State::FfmpegSpawned, &[EffectIntent::SpawnProcess])
        }
        (State::FfmpegSpawned, Event::Start) => step(State::FfmpegRunning, &[]),
        (State::FfmpegRunning, Event::Complete) => {
            step(State::FfmpegReaping, &[EffectIntent::ReapProcess])
        }
        (State::FfmpegReaping, Event::EffectAcknowledged { .. }) => {
            step(State::FfmpegExited, &[EffectIntent::ReleaseResources])
        }
        (State::FfmpegPrepared, Event::Cancel)
        | (State::FfmpegCancelling, Event::EffectAcknowledged { .. }) => {
            step(State::FfmpegCancelled, &[EffectIntent::ReleaseResources])
        }
        (State::FfmpegSpawned | State::FfmpegRunning, Event::Cancel) => step(
            State::FfmpegCancelling,
            &[EffectIntent::TerminateProcess, EffectIntent::ReapProcess],
        ),
        (State::FfmpegSpawned | State::FfmpegRunning | State::FfmpegReaping, Event::Fail) => step(
            State::FfmpegFailed,
            &[EffectIntent::ReapProcess, EffectIntent::PreserveDiagnostics],
        ),
        (State::FfmpegFailed | State::FfmpegCancelled, Event::Restart) => {
            step(State::FfmpegPrepared, &[])
        }
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
        (State::FilesystemProbing, Event::Confine) => step(
            State::FilesystemConfined,
            &[EffectIntent::EstablishConfinedPath],
        ),
        (State::FilesystemProbing, Event::Degrade) => step(
            State::FilesystemDegraded,
            &[EffectIntent::ReportDegradedGuarantees],
        ),
        (State::FilesystemProbing, Event::Reject) => step(
            State::FilesystemUnsupported,
            &[EffectIntent::RejectFilesystem],
        ),
        (State::FilesystemProbing, Event::Cancel) => step(State::FilesystemCancelled, &[]),
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

    fn run(kind: MachineKind, events: &[Event], expected: State) -> StateMachine {
        let mut model = machine(kind, events.len().saturating_mul(2).saturating_add(2));
        for event in events {
            if *event == Event::Acknowledge {
                acknowledge_all(&mut model);
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
                &[Event::Start, Event::Reconcile, Event::Acknowledge],
                State::JobSucceeded,
            ),
            (
                MachineKind::SourceRedirect,
                &[
                    Event::Start,
                    Event::Redirect,
                    Event::Continue,
                    Event::Complete,
                ],
                State::SourceResolved,
            ),
            (
                MachineKind::AtomicAdmission,
                &[Event::Admit, Event::Release],
                State::AdmissionReleased,
            ),
            (
                MachineKind::ByteCreditDurability,
                &[
                    Event::Receive,
                    Event::Validate,
                    Event::Acknowledge,
                    Event::PersistDurably,
                    Event::Acknowledge,
                ],
                State::BytesDurable,
            ),
            (
                MachineKind::Live,
                &[Event::Ready, Event::Serve, Event::Drain],
                State::LiveStopped,
            ),
            (
                MachineKind::Sink,
                &[Event::Start, Event::Drain, Event::Complete],
                State::SinkCompleted,
            ),
            (
                MachineKind::Ffmpeg,
                &[
                    Event::Spawn,
                    Event::Start,
                    Event::Complete,
                    Event::Acknowledge,
                ],
                State::FfmpegExited,
            ),
            (
                MachineKind::JavascriptWorker,
                &[Event::Assign, Event::Start, Event::Complete],
                State::JavascriptCompleted,
            ),
            (
                MachineKind::PluginIpc,
                &[
                    Event::Start,
                    Event::Ready,
                    Event::Assign,
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
                &[Event::Probe, Event::Confine],
                State::FilesystemConfined,
            ),
            (
                MachineKind::Watcher,
                &[Event::Ready, Event::Serve, Event::Drain, Event::Acknowledge],
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
    fn cancellation_paths_are_explicit_and_release_or_drain() {
        let job = run(
            MachineKind::JobCancellation,
            &[Event::Start, Event::Cancel, Event::Acknowledge],
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
        let watcher = run(
            MachineKind::Watcher,
            &[Event::Ready, Event::Cancel, Event::Acknowledge],
            State::WatcherStopped,
        );
        assert!(
            watcher
                .trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::FlushWatcher))
        );

        let cases: &[(MachineKind, &[Event], State)] = &[
            (
                MachineKind::SourceRedirect,
                &[Event::Start, Event::Cancel],
                State::SourceCancelled,
            ),
            (
                MachineKind::AtomicAdmission,
                &[Event::Cancel],
                State::AdmissionCancelled,
            ),
            (
                MachineKind::ByteCreditDurability,
                &[Event::Receive, Event::Cancel],
                State::BytesCancelled,
            ),
            (MachineKind::Live, &[Event::Cancel], State::LiveCancelled),
            (MachineKind::Sink, &[Event::Cancel], State::SinkCancelled),
            (
                MachineKind::JavascriptWorker,
                &[Event::Assign, Event::Cancel],
                State::JavascriptCancelled,
            ),
            (
                MachineKind::PluginIpc,
                &[
                    Event::Start,
                    Event::Ready,
                    Event::Cancel,
                    Event::Acknowledge,
                ],
                State::PluginStopped,
            ),
            (
                MachineKind::Ffmpeg,
                &[Event::Cancel],
                State::FfmpegCancelled,
            ),
            (
                MachineKind::FilesystemCapability,
                &[Event::Probe, Event::Cancel],
                State::FilesystemCancelled,
            ),
            (
                MachineKind::Watcher,
                &[Event::Cancel, Event::Acknowledge],
                State::WatcherStopped,
            ),
            (
                MachineKind::CommitArchiveReconciliation,
                &[Event::Prepare, Event::Cancel, Event::Acknowledge],
                State::CommitCancelled,
            ),
        ];
        for (kind, events, expected) in cases {
            run(*kind, events, *expected);
        }
    }

    #[test]
    fn failure_and_restart_preserve_diagnostics_and_reset_safely() {
        let source = run(
            MachineKind::SourceRedirect,
            &[Event::Start, Event::Fail, Event::Restart],
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
            &[Event::Assign, Event::Quarantine, Event::Restart],
            State::JavascriptIdle,
        );
        assert!(
            js.trace()
                .iter()
                .any(|record| record.effects.contains(&EffectIntent::IsolateWorker))
        );

        let failures: &[(MachineKind, &[Event], State)] = &[
            (
                MachineKind::JobCancellation,
                &[Event::Start, Event::Fail],
                State::JobFailed,
            ),
            (
                MachineKind::ByteCreditDurability,
                &[Event::Receive, Event::Fail],
                State::BytesFailed,
            ),
            (
                MachineKind::Live,
                &[Event::Ready, Event::Fail],
                State::LiveFailed,
            ),
            (
                MachineKind::Sink,
                &[Event::Start, Event::Fail],
                State::SinkFailed,
            ),
            (
                MachineKind::Ffmpeg,
                &[Event::Spawn, Event::Fail],
                State::FfmpegFailed,
            ),
            (
                MachineKind::PluginIpc,
                &[Event::Start, Event::Fail],
                State::PluginFailed,
            ),
            (
                MachineKind::CommitArchiveReconciliation,
                &[Event::Prepare, Event::Fail],
                State::CommitInconsistent,
            ),
            (
                MachineKind::FilesystemCapability,
                &[Event::Probe, Event::Reject],
                State::FilesystemUnsupported,
            ),
            (
                MachineKind::Watcher,
                &[Event::Degrade],
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
        for (state, verifying, required) in prefixes {
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
            assert_eq!(model.state(), verifying);
            assert_ne!(model.state(), State::CommitReconciled);
            acknowledge_all(&mut model);
            assert_eq!(model.state(), state);
        }
        Ok(())
    }

    #[test]
    fn success_and_durable_prefixes_require_effect_acknowledgements() {
        let mut job = machine(MachineKind::JobCancellation, 3);
        assert!(job.apply(Event::Start).is_ok());
        assert!(job.apply(Event::Reconcile).is_ok());
        assert_eq!(job.state(), State::JobVerifying);
        assert_ne!(job.state(), State::JobSucceeded);
        acknowledge_all(&mut job);
        assert_eq!(job.state(), State::JobSucceeded);

        let mut commit = machine(MachineKind::CommitArchiveReconciliation, 11);
        for (request, pending, acknowledged) in [
            (
                Event::Prepare,
                State::CommitPreparing,
                State::CommitPrepared,
            ),
            (Event::Rename, State::CommitRenaming, State::CommitRenamed),
            (
                Event::Archive,
                State::CommitArchiving,
                State::CommitArchived,
            ),
            (Event::Cleanup, State::CommitCleaning, State::CommitCleaned),
            (
                Event::Reconcile,
                State::CommitReconciling,
                State::CommitReconciled,
            ),
        ] {
            assert!(commit.apply(request).is_ok());
            assert_eq!(commit.state(), pending);
            assert_ne!(commit.state(), acknowledged);
            acknowledge_all(&mut commit);
            assert_eq!(commit.state(), acknowledged);
        }

        let mut bytes = machine(MachineKind::ByteCreditDurability, 5);
        assert!(bytes.apply(Event::Receive).is_ok());
        assert!(bytes.apply(Event::Validate).is_ok());
        assert_eq!(bytes.state(), State::BytesWriting);
        acknowledge_all(&mut bytes);
        assert_eq!(bytes.state(), State::BytesWritten);
        assert!(bytes.apply(Event::PersistDurably).is_ok());
        assert_eq!(bytes.state(), State::BytesSynchronizing);
        acknowledge_all(&mut bytes);
        assert_eq!(bytes.state(), State::BytesDurable);

        let mut cancelling = machine(MachineKind::CommitArchiveReconciliation, 3);
        assert!(cancelling.apply(Event::Prepare).is_ok());
        let cancel = cancelling
            .apply(Event::Cancel)
            .expect("cancel begins draining");
        assert_eq!(cancel.next, State::CommitCancelling);
        assert!(cancel.effects.contains(&EffectIntent::DrainInFlightEffect));
        assert!(!cancel.effects.contains(&EffectIntent::ReleaseResources));
        let pending = cancelling.pending_acknowledgements()[0];
        let acknowledged = cancelling
            .apply(Event::EffectAcknowledged {
                instance_id: pending.instance_id,
                effect: pending.effect,
                generation: pending.generation,
            })
            .expect("drain acknowledgement completes cancellation");
        assert!(
            acknowledged
                .effects
                .contains(&EffectIntent::ReleaseResources)
        );
        assert_eq!(cancelling.state(), State::CommitCancelled);
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
        assert_eq!(model.state(), State::SourceResolving);
    }

    #[test]
    fn replay_detects_counterfactual_trace_mutation() {
        let model = run(
            MachineKind::ByteCreditDurability,
            &[
                Event::Receive,
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
            &[Event::Probe, Event::Degrade],
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
        assert_eq!(model.state(), State::CommitCancelling);
        assert_eq!(model.pending_acknowledgements(), &[cancellation]);
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
