use std::path::Path;

use crate::entities::{RegistryBackupConfig, RegistryHive, RegistryTree};
use crate::error::DomainResult;

/// Summary of a registry subkey used by the GUI Registry Browser.
#[derive(Debug, Clone)]
pub struct RegistryBrowseItem {
    pub hive: RegistryHive,
    pub subkey_path: String,
    pub full_path: String,
    pub has_subkeys: bool,
    pub value_count: usize,
}

/// Port for reading, exporting, diff-probing, and safely restoring the Windows Registry.
pub trait RegistryRepositoryPort: Send + Sync {
    /// Exports all registry keys and values matching `config`.
    fn export_keys(&self, config: &RegistryBackupConfig) -> DomainResult<RegistryTree>;

    /// Exports a `.reg` rollback file for all keys existing on the live system that are about to be modified.
    fn create_rollback_reg_file(
        &self,
        tree_to_restore: &RegistryTree,
        rollback_file_path: &Path,
    ) -> DomainResult<()>;

    /// Writes `tree` into the live Windows Registry.
    fn restore_tree(&self, tree: &RegistryTree) -> DomainResult<usize>;

    /// Lists direct child subkeys under `(hive, parent_subkey)` for interactive GUI browsing.
    fn list_subkeys(
        &self,
        hive: RegistryHive,
        parent_subkey: &str,
    ) -> DomainResult<Vec<RegistryBrowseItem>>;
}
