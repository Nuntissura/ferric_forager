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
    Acknowledge,
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

/// One bounded, deterministic state machine instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMachine {
    kind: MachineKind,
    state: State,
    trace_limit: usize,
    trace: Vec<Transition>,
}

impl StateMachine {
    #[must_use]
    pub fn new(kind: MachineKind, trace_limit: usize) -> Self {
        Self {
            kind,
            state: initial(kind),
            trace_limit,
            trace: Vec::new(),
        }
    }

    /// Restore a machine at a validated durable prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when `state` does not belong to `kind`.
    pub fn from_state(
        kind: MachineKind,
        state: State,
        trace_limit: usize,
    ) -> Result<Self, TransitionError> {
        if !belongs(kind, state) {
            return Err(TransitionError::StateDoesNotBelongToMachine { kind, state });
        }
        Ok(Self {
            kind,
            state,
            trace_limit,
            trace: Vec::new(),
        })
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub fn trace(&self) -> &[Transition] {
        &self.trace
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
        let (next, effects) = transition(self.kind, self.state, event)?;
        let record = Transition {
            previous: self.state,
            event,
            next,
            effects,
        };
        self.state = next;
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
        trace_limit: usize,
        expected: &[Transition],
    ) -> Result<Self, TransitionError> {
        let mut machine = Self::new(kind, trace_limit);
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
        (State::JobCancelling, Event::Acknowledge) => {
            step(State::JobCancelled, &[EffectIntent::ReleaseResources])
        }
        (State::JobRunning, Event::Reconcile) => step(
            State::JobVerifying,
            &[EffectIntent::VerifyArchiveOutputPair],
        ),
        (State::JobVerifying, Event::Acknowledge) => {
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
        (State::BytesWriting, Event::Acknowledge) => step(State::BytesWritten, &[]),
        (State::BytesWritten, Event::PersistDurably) => {
            step(State::BytesSynchronizing, &[EffectIntent::SynchronizeData])
        }
        (State::BytesSynchronizing, Event::Acknowledge) => step(State::BytesDurable, &[]),
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
        (State::FfmpegReaping, Event::Acknowledge) => {
            step(State::FfmpegExited, &[EffectIntent::ReleaseResources])
        }
        (State::FfmpegPrepared, Event::Cancel) | (State::FfmpegCancelling, Event::Acknowledge) => {
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
        (State::JavascriptRecycling, Event::Acknowledge) => step(State::JavascriptIdle, &[]),
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
        (State::PluginDraining, Event::Acknowledge) => step(State::PluginStopped, &[]),
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
        (State::CommitPreparing | State::CommitVerifyingPrepared, Event::Acknowledge) => {
            step(State::CommitPrepared, &[])
        }
        (State::CommitPrepared, Event::Rename) => {
            step(State::CommitRenaming, &[EffectIntent::RenameOutput])
        }
        (State::CommitRenaming | State::CommitVerifyingRenamed, Event::Acknowledge) => {
            step(State::CommitRenamed, &[])
        }
        (State::CommitRenamed, Event::Archive) => {
            step(State::CommitArchiving, &[EffectIntent::InsertArchiveRow])
        }
        (State::CommitArchiving | State::CommitVerifyingArchived, Event::Acknowledge) => {
            step(State::CommitArchived, &[])
        }
        (State::CommitArchived, Event::Cleanup) => {
            step(State::CommitCleaning, &[EffectIntent::RemoveTemporaryState])
        }
        (State::CommitCleaning | State::CommitVerifyingCleaned, Event::Acknowledge) => {
            step(State::CommitCleaned, &[])
        }
        (State::CommitCleaned, Event::Reconcile) => step(
            State::CommitReconciling,
            &[EffectIntent::VerifyArchiveOutputPair],
        ),
        (State::CommitReconciling, Event::Acknowledge) => step(State::CommitReconciled, &[]),
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
        (State::CommitCancelling, Event::Acknowledge) => {
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
        (State::WatcherDraining, Event::Acknowledge) => step(State::WatcherStopped, &[]),
        (State::WatcherDegraded | State::WatcherStale | State::WatcherStopped, Event::Restart) => {
            step(State::WatcherStarting, &[EffectIntent::PreserveDiagnostics])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(kind: MachineKind, events: &[Event], expected: State) -> StateMachine {
        let mut model = StateMachine::new(kind, events.len());
        for event in events {
            assert!(model.apply(*event).is_ok());
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
            let replay = StateMachine::replay(*kind, events.len(), model.trace());
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
            let model =
                StateMachine::from_state(MachineKind::CommitArchiveReconciliation, state, 2);
            let Ok(mut model) = model else {
                return Err("commit prefix must belong to commit model".to_owned());
            };
            let result = model.apply(Event::Restart);
            assert!(matches!(result, Ok(record) if record.effects == [required]));
            assert_eq!(model.state(), verifying);
            assert_ne!(model.state(), State::CommitReconciled);
            assert!(model.apply(Event::Acknowledge).is_ok());
            assert_eq!(model.state(), state);
        }
        Ok(())
    }

    #[test]
    fn success_and_durable_prefixes_require_effect_acknowledgements() {
        let mut job = StateMachine::new(MachineKind::JobCancellation, 3);
        assert!(job.apply(Event::Start).is_ok());
        assert!(job.apply(Event::Reconcile).is_ok());
        assert_eq!(job.state(), State::JobVerifying);
        assert_ne!(job.state(), State::JobSucceeded);
        assert!(job.apply(Event::Acknowledge).is_ok());
        assert_eq!(job.state(), State::JobSucceeded);

        let mut commit = StateMachine::new(MachineKind::CommitArchiveReconciliation, 10);
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
            assert!(commit.apply(Event::Acknowledge).is_ok());
            assert_eq!(commit.state(), acknowledged);
        }

        let mut bytes = StateMachine::new(MachineKind::ByteCreditDurability, 5);
        assert!(bytes.apply(Event::Receive).is_ok());
        assert!(bytes.apply(Event::Validate).is_ok());
        assert_eq!(bytes.state(), State::BytesWriting);
        assert!(bytes.apply(Event::Acknowledge).is_ok());
        assert_eq!(bytes.state(), State::BytesWritten);
        assert!(bytes.apply(Event::PersistDurably).is_ok());
        assert_eq!(bytes.state(), State::BytesSynchronizing);
        assert!(bytes.apply(Event::Acknowledge).is_ok());
        assert_eq!(bytes.state(), State::BytesDurable);

        let mut cancelling = StateMachine::new(MachineKind::CommitArchiveReconciliation, 3);
        assert!(cancelling.apply(Event::Prepare).is_ok());
        let cancel = cancelling
            .apply(Event::Cancel)
            .expect("cancel begins draining");
        assert_eq!(cancel.next, State::CommitCancelling);
        assert!(cancel.effects.contains(&EffectIntent::DrainInFlightEffect));
        assert!(!cancel.effects.contains(&EffectIntent::ReleaseResources));
        let acknowledged = cancelling
            .apply(Event::Acknowledge)
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
        let mut model = StateMachine::new(MachineKind::CommitArchiveReconciliation, 2);
        assert!(matches!(
            model.apply(Event::Archive),
            Err(TransitionError::InvalidTransition { .. })
        ));
        assert_eq!(model.state(), State::CommitWorking);
        assert!(model.trace().is_empty());
        assert!(matches!(
            StateMachine::from_state(MachineKind::Watcher, State::JobQueued, 1),
            Err(TransitionError::StateDoesNotBelongToMachine { .. })
        ));
    }

    #[test]
    fn trace_bound_is_checked_before_transition() {
        let mut model = StateMachine::new(MachineKind::SourceRedirect, 1);
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
            StateMachine::replay(MachineKind::ByteCreditDurability, 5, &mutated),
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
}
