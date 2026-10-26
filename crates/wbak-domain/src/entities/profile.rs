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
    #[serde(default = "default_true")]
    pub encrypt_sensitive_by_default: bool,

    /// Glob patterns classified as `SensitivityLevel::Secret`.
    #[serde(default = "default_sensitive_patterns")]
    pub sensitive_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            encrypt_full_archive: false,
            encrypt_sensitive_by_default: true,
            sensitive_patterns: default_sensitive_patterns(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default = "default_true")]
    pub respect_local_ignore_files: bool,
}

pub fn default_ignore_patterns() -> Vec<String> {
    vec![
        "/node_modules/".to_string(),
        "/target/".to_string(),
        "/.git/objects/".to_string(),
        "**/*.tmp".to_string(),
        "**/*.bak".to_string(),
        "**/Thumbs.db".to_string(),
        "**/desktop.ini".to_string(),
    ]
}

impl Default for FileBackupConfig {
    fn default() -> Self {
        Self {
            include: vec![
                "${USERPROFILE}/.ssh".to_string(),
                "${USERPROFILE}/.gitconfig".to_string(),
                "${APPDATA}/Code/User/settings.json".to_string(),
                "${APPDATA}/Code/User/keybindings.json".to_string(),
            ],
            ignore_file: Some(PathBuf::from(".wbakignore")),
            ignore_patterns: default_ignore_patterns(),
            respect_local_ignore_files: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryBackupConfig {
    /// Registry key paths to recursively export (e.g. `HKCU\Environment`, `HKCU\Console`).
    #[serde(default)]
    pub include_keys: Vec<String>,

    /// Glob patterns for registry subkeys or values to exclude.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

impl Default for RegistryBackupConfig {
    fn default() -> Self {
        Self {
            include_keys: vec![r"HKCU\Environment".to_string(), r"HKCU\Console".to_string()],
            exclude_patterns: vec![r"*\BagMRU*".to_string(), r"*\RecentDocs*".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentBackupConfig {
    /// Capture installed `winget` packages into the archive for reproducible machine setup.
    #[serde(default = "default_true")]
    pub capture_winget: bool,

    /// Capture User environment variables.
    #[serde(default = "default_true")]
    pub capture_env_vars: bool,
}

impl Default for EnvironmentBackupConfig {
    fn default() -> Self {
        Self {
            capture_winget: true,
            capture_env_vars: true,
        }
    }
}
