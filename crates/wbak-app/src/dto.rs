use std::path::PathBuf;

use wbak_domain::{ConflictPolicy, ProfileConfig};

#[derive(Debug, Clone)]
pub struct CreateBackupRequest {
    pub profile: ProfileConfig,
    pub output_archive: PathBuf,
    pub passphrase: Option<String>,
    /// Explicit override to allow storing `.ssh` / secret files unencrypted (not recommended).
    pub allow_unencrypted_secrets: bool,
}

#[derive(Debug, Clone)]
pub struct RestoreBackupRequest {
    pub archive_path: PathBuf,
    pub passphrase: Option<String>,
    /// If set, extracts all files relative to this root directory instead of their live system paths.
    pub target_dir_override: Option<PathBuf>,
    pub restore_files: bool,
    pub restore_registry: bool,
    pub restore_winget: bool,
    pub restore_env_vars: bool,
    pub dry_run: bool,
    pub conflict_policy: ConflictPolicy,
    /// Optional substring or logical path filter for selective restore.
    pub path_filter: Option<String>,
}

impl Default for RestoreBackupRequest {
    fn default() -> Self {
        Self {
            archive_path: PathBuf::new(),
            passphrase: None,
            target_dir_override: None,
            restore_files: true,
            restore_registry: true,
            restore_winget: false,
            restore_env_vars: false,
            dry_run: false,
            conflict_policy: ConflictPolicy::Overwrite,
            path_filter: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RestoreSummary {
    pub dry_run: bool,
    pub files_restored: usize,
    pub files_skipped: usize,
    pub dirs_restored: usize,
    pub secret_acls_hardened: usize,
    pub registry_values_restored: usize,
    pub rollback_reg_file: Option<PathBuf>,
    pub winget_packages_restored: usize,
    pub env_vars_restored: usize,
}
