use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::services::default_sensitive_patterns;

/// Declarative enterprise & workstation backup profile (`wbak.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProfileConfig {
    #[serde(default)]
    pub profile: ProfileMetadata,
    #[serde(default)]
    pub security: SecurityPolicy,
    #[serde(default)]
    pub files: FileBackupConfig,
    #[serde(default)]
    pub registry: RegistryBackupConfig,
    #[serde(default)]
    pub environment: EnvironmentBackupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileMetadata {
    pub name: String,
    pub description: String,
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,
}

fn default_compression_level() -> i32 {
    3
}

impl Default for ProfileMetadata {
    fn default() -> Self {
        Self {
            name: "workstation-backup".to_string(),
            description: "Reproducible Windows workstation & configuration backup".to_string(),
            compression_level: default_compression_level(),
        }
    }
}

/// Controls whole-archive encryption and automatic secret encryption (e.g. `.ssh` keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// Whether the entire archive (all files, registry, and manifest) must be encrypted.
    #[serde(default)]
    pub encrypt_full_archive: bool,

    /// Whether sensitive files (such as `.ssh` keys, `.gnupg`, `*.pem`, `*.pfx`) are
    /// automatically encrypted by default even in an otherwise unencrypted archive.
    #[serde(default)]
    pub encrypt_sensitive_by_default: bool,

    /// Glob patterns classified as `SensitivityLevel::Secret`.
    #[serde(default = "default_sensitive_patterns")]
    pub sensitive_patterns: Vec<String>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            encrypt_full_archive: false,
            encrypt_sensitive_by_default: false,
            sensitive_patterns: default_sensitive_patterns(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FileBackupConfig {
    /// Paths to include. Supports portable tokens like `${USERPROFILE}`, `${APPDATA}`, `${LOCALAPPDATA}`.
    #[serde(default)]
    pub include: Vec<String>,

    /// Optional path to a `.wbakignore` file.
    #[serde(default)]
    pub ignore_file: Option<PathBuf>,

    /// Inline ignore rules (supports `/node_modules`, `/target`, globs, and `!` exemptions).
    #[serde(default = "default_ignore_patterns")]
    pub ignore_patterns: Vec<String>,

    /// Whether to honor local `.wbakignore` files encountered inside traversed directories.
    #[serde(default)]
    pub respect_local_ignore_files: bool,
}

pub fn default_ignore_patterns() -> Vec<String> {
    Vec::new()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RegistryBackupConfig {
    /// Registry key paths to recursively export (e.g. `HKCU\Environment`, `HKCU\Console`).
    #[serde(default)]
    pub include_keys: Vec<String>,

    /// Glob patterns for registry subkeys or values to exclude.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EnvironmentBackupConfig {
    /// Capture installed `winget` packages into the archive for reproducible machine setup.
    #[serde(default)]
    pub capture_winget: bool,

    /// Capture User environment variables.
    #[serde(default)]
    pub capture_env_vars: bool,
}
