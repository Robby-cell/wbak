use crate::error::DomainResult;

#[derive(Debug, Clone)]
pub enum ProgressPhase {
    ScanningFiles,
    ExportingRegistry,
    CapturingWinget,
    PackingChunks,
    VerifyingArchive,
    RestoringFiles,
    RestoringRegistry,
    RestoringWinget,
    Completed,
}

#[derive(Debug, Clone)]
pub struct ProgressEvent {
    pub phase: ProgressPhase,
    pub current: u64,
    pub total: Option<u64>,
    pub message: String,
}

/// Port for receiving real-time progress events in CLI (`indicatif`) or GUI (`egui`).
pub trait ProgressSinkPort: Send + Sync {
    fn on_progress(&self, event: ProgressEvent);
}

/// No-op implementation for tests or quiet mode.
pub struct NoopProgressSink;

impl ProgressSinkPort for NoopProgressSink {
    fn on_progress(&self, _event: ProgressEvent) {}
}

/// Port for prompting the user for an encryption passphrase when `.ssh` secrets or encrypted archives are encountered.
pub trait SecretPromptPort: Send + Sync {
    fn prompt_passphrase(&self, reason: &str, confirm: bool) -> DomainResult<String>;
}
