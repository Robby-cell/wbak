use crate::entities::{EnvVarsSnapshot, WingetManifest};
use crate::error::DomainResult;

/// Port for capturing and restoring `winget` packages and Windows environment variables.
pub trait EnvironmentRepositoryPort: Send + Sync {
    /// Captures installed `winget` packages from the current Windows machine.
    fn capture_winget(&self) -> DomainResult<WingetManifest>;

    /// Installs or imports `winget` packages from a captured manifest.
    fn restore_winget(&self, manifest: &WingetManifest, dry_run: bool) -> DomainResult<usize>;

    /// Captures User and System environment variables.
    fn capture_env_vars(&self) -> DomainResult<EnvVarsSnapshot>;

    /// Restores User environment variables safely.
    fn restore_user_env_vars(
        &self,
        snapshot: &EnvVarsSnapshot,
        dry_run: bool,
    ) -> DomainResult<usize>;
}
