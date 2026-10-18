use std::path::Path;

use crate::entities::{
    ArchiveManifest, ChunkId, EnvVarsSnapshot, FileNode, ProfileMetadata, RegistryTree,
    WingetManifest,
};
use crate::error::DomainResult;
use crate::ports::ProgressSinkPort;

/// Input payload for creating a `.wbak` archive container.
pub struct ArchiveBuildInput {
    pub profile: ProfileMetadata,
    pub compression_level: i32,
    pub encrypt_full_archive: bool,
    pub encrypt_secrets_by_default: bool,
    pub passphrase: Option<String>,
    pub files: Vec<FileNode>,
    pub registry: RegistryTree,
    pub winget: Option<WingetManifest>,
    pub env_vars: Option<EnvVarsSnapshot>,
}

/// Port for writing `.wbak` deduplicated, compressed, and encrypted archives.
pub trait ArchiveWriterPort: Send + Sync {
    fn write_archive(
        &self,
        output_path: &Path,
        input: ArchiveBuildInput,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest>;
}

/// Port for random-access reading, verification, and chunk extraction from `.wbak` archives.
pub trait ArchiveReaderPort: Send + Sync {
    /// Reads only the archive header, footer, and manifest index without decompressing file chunks.
    fn read_manifest(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
    ) -> DomainResult<ArchiveManifest>;

    /// Recomputes and verifies BLAKE3 hashes (and AEAD tags if passphrase is provided) for all chunks.
    fn verify_archive(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest>;

    /// Reconstructs the complete plaintext bytes of a `FileNode` from its deduplicated chunks.
    fn extract_file_bytes(
        &self,
        archive_path: &Path,
        manifest: &ArchiveManifest,
        node: &FileNode,
        passphrase: Option<&str>,
    ) -> DomainResult<Vec<u8>>;

    /// Reads a single raw chunk by `ChunkId`.
    fn read_chunk(
        &self,
        archive_path: &Path,
        manifest: &ArchiveManifest,
        chunk_id: &ChunkId,
        passphrase: Option<&str>,
    ) -> DomainResult<Vec<u8>>;
}
