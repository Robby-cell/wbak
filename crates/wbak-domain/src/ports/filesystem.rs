use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::entities::{ConflictPolicy, SensitivityLevel, WindowsFileAttributes};
use crate::error::DomainResult;
use crate::ports::{FilterDecision, PathFilterPort};

#[derive(Debug, Clone)]
pub enum ScannedEntryKind {
    RegularFile { size: u64 },
    Directory,
    Symlink { target: String, is_dir: bool },
}

/// A filesystem entry discovered during scanning.
#[derive(Debug, Clone)]
pub struct ScannedEntry {
    pub physical_path: PathBuf,
    pub logical_path: String,
    pub kind: ScannedEntryKind,
    pub attributes: WindowsFileAttributes,
    pub sensitivity: SensitivityLevel,
    pub filter_decision: FilterDecision,
    pub modified_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

/// Port for scanning directories/files on Windows and collecting NTFS metadata.
pub trait FileScannerPort: Send + Sync {
    /// Walks the requested `include_paths` (resolved to physical paths), applying `filter`.
    /// When `include_ignored_for_preview` is true, ignored entries are returned with their
    /// `FilterDecision::Ignored` status so the GUI can display a live preview tree.
    fn scan_paths(
        &self,
        include_paths: &[PathBuf],
        filter: &dyn PathFilterPort,
        respect_local_ignore: bool,
        include_ignored_for_preview: bool,
    ) -> DomainResult<Vec<ScannedEntry>>;
}

/// Port for writing restored files, directories, symlinks, Windows attributes, and `.ssh` NTFS ACLs.
pub trait FileRestorerPort: Send + Sync {
    fn restore_directory(
        &self,
        target_path: &Path,
        attributes: &WindowsFileAttributes,
    ) -> DomainResult<()>;

    fn restore_regular_file(
        &self,
        target_path: &Path,
        contents: &[u8],
        attributes: &WindowsFileAttributes,
        modified_at: Option<DateTime<Utc>>,
        conflict_policy: ConflictPolicy,
    ) -> DomainResult<bool>;

    fn restore_symlink(
        &self,
        target_path: &Path,
        link_target: &str,
        is_dir: bool,
        conflict_policy: ConflictPolicy,
    ) -> DomainResult<bool>;

    /// Applies restricted Windows NTFS ACL permissions (owner-only read/write, inheritance disabled)
    /// required by Windows OpenSSH for `.ssh` private keys.
    fn tighten_secret_file_acl(&self, target_path: &Path) -> DomainResult<()>;
}
