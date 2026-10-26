use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::{EnvVarsSnapshot, ProfileMetadata, RegistryTree, WingetManifest};

/// Content-addressed BLAKE3 hash (64-char lowercase hex string).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChunkId(pub String);

impl ChunkId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChunkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Classification of a file's sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitivityLevel {
    /// Standard configuration or user file. Encrypted only when full-archive encryption is enabled.
    Public,
    /// Sensitive file (e.g., `.ssh` private keys, `.gnupg`, `*.pem`, `*.pfx`).
    /// Encrypted by default even in standard archives, and restored with restricted Windows NTFS ACLs.
    Secret,
}

/// Describes a stored data chunk in the `.wbak` container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkDescriptor {
    /// BLAKE3 hash of the uncompressed plaintext bytes.
    pub id: ChunkId,
    /// Byte offset inside the `.wbak` file's chunk store section.
    pub offset: u64,
    /// Length in bytes of the stored (compressed + optionally encrypted) payload.
    pub stored_size: u64,
    /// Original uncompressed plaintext length in bytes.
    pub original_size: u64,
    /// Whether this chunk is encrypted with `ChaCha20-Poly1305`.
    pub encrypted: bool,
    /// Unique 12-byte nonce used if `encrypted == true` (hex or bytes).
    pub nonce: Option<[u8; 12]>,
}

/// Windows file attribute flags preserved across backup and restore.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsFileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    /// Raw Win32 `dwFileAttributes` bitmask.
    pub raw_attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileNodeKind {
    RegularFile {
        size: u64,
        /// Ordered list of chunks composing this file.
        chunks: Vec<ChunkId>,
        /// Overall BLAKE3 hash of the full file content.
        content_hash: ChunkId,
    },
    Directory,
    Symlink {
        target: String,
        is_dir: bool,
    },
}

/// Represents a backed-up filesystem entry inside the archive manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileNode {
    /// Logical portable path (e.g. `${USERPROFILE}/.ssh/id_ed25519` or `C:/Projects/app/src/main.rs`).
    pub logical_path: String,
    /// Original physical path on the source machine at backup time.
    pub original_path: String,
    pub kind: FileNodeKind,
    pub sensitivity: SensitivityLevel,
    pub attributes: WindowsFileAttributes,
    pub modified_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

impl FileNode {
    pub fn is_secret(&self) -> bool {
        self.sensitivity == SensitivityLevel::Secret
    }

    pub fn size(&self) -> u64 {
        match &self.kind {
            FileNodeKind::RegularFile { size, .. } => *size,
            _ => 0,
        }
    }
}

/// High-level statistics for an archive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveStats {
    pub total_files: usize,
    pub total_directories: usize,
    pub total_symlinks: usize,
    pub secret_files_count: usize,
    pub total_logical_bytes: u64,
    pub deduplicated_plaintext_bytes: u64,
    pub compressed_stored_bytes: u64,
    pub unique_chunks: usize,
    #[serde(default)]
    pub reclaimable_chunks: usize,
    #[serde(default)]
    pub reclaimable_bytes: u64,
    #[serde(default)]
    pub last_incremental: Option<IncrementalStats>,
    pub registry_keys_count: usize,
    pub registry_values_count: usize,
    pub winget_packages_count: usize,
}

/// Breakdown of changes during an incremental backup update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalStats {
    pub files_unchanged: usize,
    pub files_added: usize,
    pub files_modified: usize,
    pub files_deleted: usize,
    pub bytes_reused: u64,
    pub bytes_appended: u64,
}

/// Complete manifest stored in the index section of a `.wbak` archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub format_version: u16,
    pub created_at: DateTime<Utc>,
    pub source_hostname: String,
    pub source_username: String,
    pub profile: ProfileMetadata,
    pub full_archive_encrypted: bool,
    pub has_encrypted_secrets: bool,
    /// Map of `ChunkId` -> `ChunkDescriptor` for random-access extraction.
    pub chunks: BTreeMap<ChunkId, ChunkDescriptor>,
    /// All backed up files, directories, and symlinks.
    pub files: Vec<FileNode>,
    /// Captured Windows Registry keys and values.
    pub registry: RegistryTree,
    /// Optional captured `winget` package manifest.
    pub winget: Option<WingetManifest>,
    /// Optional captured Windows environment variables.
    pub env_vars: Option<EnvVarsSnapshot>,
    /// Summary metrics.
    pub stats: ArchiveStats,
}

/// Conflict resolution strategy when restoring files onto a target machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConflictPolicy {
    /// Overwrite existing files on disk.
    #[default]
    Overwrite,
    /// Skip files that already exist on disk.
    SkipExisting,
    /// Rename existing file on disk with a `.wbak.bak` suffix before writing the restored file.
    BackupExisting,
}
