use serde::{Deserialize, Serialize};

use crate::entities::SensitivityLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftStatus {
    /// Entry exists in archive and matches live system identically.
    Identical,
    /// Entry exists in archive, but is missing on the live system (needs restore).
    MissingOnSystem,
    /// Entry exists in both archive and live system, but contents/values differ.
    ModifiedOnSystem,
    /// Entry exists only on the live system (not in archive).
    AddedOnSystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDriftItem {
    pub logical_path: String,
    pub target_path: String,
    pub status: DriftStatus,
    pub sensitivity: SensitivityLevel,
    pub archive_size: Option<u64>,
    pub system_size: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryDriftItem {
    pub key_path: String,
    pub value_name: Option<String>,
    pub status: DriftStatus,
    pub archive_value: Option<String>,
    pub system_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageDriftItem {
    pub package_id: String,
    pub status: DriftStatus,
    pub archive_version: Option<String>,
    pub system_version: Option<String>,
}

/// Complete drift analysis comparing a `.wbak` archive against the live Windows machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemDriftReport {
    pub files: Vec<FileDriftItem>,
    pub registry: Vec<RegistryDriftItem>,
    pub packages: Vec<PackageDriftItem>,
}

impl SystemDriftReport {
    pub fn changed_files_count(&self) -> usize {
        self.files
            .iter()
            .filter(|f| f.status != DriftStatus::Identical)
            .count()
    }

    pub fn changed_registry_count(&self) -> usize {
        self.registry
            .iter()
            .filter(|r| r.status != DriftStatus::Identical)
            .count()
    }

    pub fn missing_packages_count(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| p.status == DriftStatus::MissingOnSystem)
            .count()
    }

    pub fn is_clean(&self) -> bool {
        self.changed_files_count() == 0
            && self.changed_registry_count() == 0
            && self.missing_packages_count() == 0
    }
}
