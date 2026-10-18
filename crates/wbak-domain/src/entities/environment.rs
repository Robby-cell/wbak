use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents an installed `winget` package for reproducible Windows provisioning.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WingetPackage {
    /// Package identifier (e.g., `Microsoft.VisualStudioCode`, `Git.Git`, `Rustlang.Rustup`).
    pub id: String,
    /// Human-readable package name if available.
    pub name: Option<String>,
    /// Installed version at backup time.
    pub version: Option<String>,
    /// Winget source name (typically `winget` or `msstore`).
    pub source: String,
}

/// Snapshot of installed `winget` packages captured during backup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WingetManifest {
    pub captured_at: Option<DateTime<Utc>>,
    pub packages: Vec<WingetPackage>,
    /// Raw JSON output from `winget export` if available, enabling direct `winget import`.
    pub raw_winget_export_json: Option<String>,
}

/// Snapshot of User & System environment variables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVarsSnapshot {
    pub user_vars: BTreeMap<String, String>,
    pub system_vars: BTreeMap<String, String>,
}
