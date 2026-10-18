use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use wbak_domain::{
    ArchiveManifest, ArchiveReaderPort, ChunkDescriptor, ChunkId, CryptoProviderPort, DerivedKey,
    DomainError, DomainResult, FileNode, FileNodeKind, ProgressEvent, ProgressPhase,
    ProgressSinkPort,
};

use crate::wire_format::{ArchiveFooter, ArchiveHeader, FOOTER_SIZE, HEADER_SIZE};

pub struct WbakArchiveReader {
    crypto: Arc<dyn CryptoProviderPort>,
}

impl WbakArchiveReader {
    pub fn new(crypto: Arc<dyn CryptoProviderPort>) -> Self {
        Self { crypto }
    }

    fn read_header_and_footer(file: &mut File) -> DomainResult<(ArchiveHeader, ArchiveFooter)> {
        let file_len = file
            .metadata()
            .map_err(|e| {
                DomainError::StorageError(format!("Failed reading archive metadata: {e}"))
            })?
            .len();

        if file_len < (HEADER_SIZE + FOOTER_SIZE) as u64 {
            return Err(DomainError::StorageError(
                "File is too small to be a valid .wbak archive".to_string(),
            ));
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|e| DomainError::StorageError(format!("Seek start failed: {e}")))?;
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)
            .map_err(|e| DomainError::StorageError(format!("Failed reading header: {e}")))?;
        let header = ArchiveHeader::from_bytes(&header_buf)?;

        file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))
            .map_err(|e| DomainError::StorageError(format!("Seek footer failed: {e}")))?;
        let mut footer_buf = [0u8; FOOTER_SIZE];
        file.read_exact(&mut footer_buf)
            .map_err(|e| DomainError::StorageError(format!("Failed reading footer: {e}")))?;
        let footer = ArchiveFooter::from_bytes(&footer_buf)?;

        Ok((header, footer))
    }

    fn decode_chunk(
        &self,
        file: &mut File,
        descriptor: &ChunkDescriptor,
        derived_key: Option<&DerivedKey>,
    ) -> DomainResult<Vec<u8>> {
        file.seek(SeekFrom::Start(descriptor.offset))
            .map_err(|e| DomainError::StorageError(format!("Failed seeking to chunk: {e}")))?;

        let mut raw_stored = vec![0u8; descriptor.stored_size as usize];
        file.read_exact(&mut raw_stored)
            .map_err(|e| DomainError::StorageError(format!("Failed reading chunk bytes: {e}")))?;

        let compressed = if descriptor.encrypted {
            let key = derived_key.ok_or_else(|| {
                DomainError::PassphraseRequired(format!("encrypted chunk {}", descriptor.id))
            })?;
            let nonce = descriptor.nonce.as_ref().ok_or_else(|| {
                DomainError::StorageError(format!(
                    "Encrypted chunk {} is missing its 12-byte nonce",
                    descriptor.id
                ))
            })?;
            self.crypto
                .decrypt(key, nonce, &raw_stored, descriptor.id.as_str().as_bytes())?
        } else {
            raw_stored
        };

        let plaintext = zstd::decode_all(compressed.as_slice()).map_err(|e| {
            DomainError::StorageError(format!("Failed decompressing chunk {}: {e}", descriptor.id))
        })?;

        let actual_hash = self.crypto.hash_bytes(&plaintext);
        if actual_hash != descriptor.id {
            return Err(DomainError::IntegrityMismatch {
                path: format!("chunk:{}", descriptor.id),
                expected: descriptor.id.to_string(),
                actual: actual_hash.to_string(),
            });
        }

        Ok(plaintext)
    }
}

impl ArchiveReaderPort for WbakArchiveReader {
    fn read_manifest(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
    ) -> DomainResult<ArchiveManifest> {
        let mut file = File::open(archive_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed to open archive '{}': {e}",
                archive_path.display()
            ))
        })?;

        let (header, footer) = Self::read_header_and_footer(&mut file)?;

        file.seek(SeekFrom::Start(footer.manifest_offset))
            .map_err(|e| DomainError::StorageError(format!("Seek manifest failed: {e}")))?;

        let mut stored_manifest = vec![0u8; footer.manifest_stored_size as usize];
        file.read_exact(&mut stored_manifest)
            .map_err(|e| DomainError::StorageError(format!("Failed reading manifest: {e}")))?;

        let compressed_manifest = if header.is_full_encrypted() {
            let pass = passphrase.ok_or_else(|| {
                DomainError::PassphraseRequired(
                    "Full archive is encrypted; passphrase required to read manifest".to_string(),
                )
            })?;
            let key = self.crypto.derive_key(pass, &header.kdf_salt)?;
            self.crypto.decrypt(
                &key,
                &footer.manifest_nonce,
                &stored_manifest,
                b"wbak-manifest-v1",
            )?
        } else {
            stored_manifest
        };

        let manifest_json = zstd::decode_all(compressed_manifest.as_slice()).map_err(|e| {
            DomainError::StorageError(format!("Failed decompressing archive manifest: {e}"))
        })?;

        let manifest: ArchiveManifest = serde_json::from_slice(&manifest_json).map_err(|e| {
            DomainError::StorageError(format!("Failed deserializing archive manifest: {e}"))
        })?;

        Ok(manifest)
    }

    fn verify_archive(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest> {
        let manifest = self.read_manifest(archive_path, passphrase)?;
        let mut file = File::open(archive_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed to open archive '{}': {e}",
                archive_path.display()
            ))
        })?;

        let (header, _) = Self::read_header_and_footer(&mut file)?;
        let derived_key = if let Some(pass) = passphrase {
            Some(self.crypto.derive_key(pass, &header.kdf_salt)?)
        } else {
            None
        };

        let total_chunks = manifest.chunks.len() as u64;
        for (idx, (chunk_id, descriptor)) in manifest.chunks.iter().enumerate() {
            progress.on_progress(ProgressEvent {
                phase: ProgressPhase::VerifyingArchive,
                current: idx as u64 + 1,
                total: Some(total_chunks),
                message: format!("Verifying chunk {chunk_id}"),
            });

            if descriptor.encrypted && derived_key.is_none() {
                return Err(DomainError::PassphraseRequired(format!(
                    "Archive contains encrypted secret chunks ({chunk_id}); provide passphrase to verify"
                )));
            }

            let _ = self.decode_chunk(&mut file, descriptor, derived_key.as_ref())?;
        }

        Ok(manifest)
    }

    fn extract_file_bytes(
        &self,
        archive_path: &Path,
        manifest: &ArchiveManifest,
        node: &FileNode,
        passphrase: Option<&str>,
    ) -> DomainResult<Vec<u8>> {
        let FileNodeKind::RegularFile {
            size,
            chunks,
            content_hash,
        } = &node.kind
        else {
            return Ok(Vec::new());
        };

        let mut file = File::open(archive_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed to open archive '{}': {e}",
                archive_path.display()
            ))
        })?;

        let (header, _) = Self::read_header_and_footer(&mut file)?;

        let needs_key = chunks.iter().any(|cid| {
            manifest
                .chunks
                .get(cid)
                .map(|d| d.encrypted)
                .unwrap_or(false)
        });

        let derived_key = if needs_key {
            let pass = passphrase
                .ok_or_else(|| DomainError::PassphraseRequired(node.logical_path.clone()))?;
            Some(self.crypto.derive_key(pass, &header.kdf_salt)?)
        } else {
            None
        };

        let mut output = Vec::with_capacity(*size as usize);
        for chunk_id in chunks {
            let descriptor = manifest.chunks.get(chunk_id).ok_or_else(|| {
                DomainError::StorageError(format!(
                    "Missing chunk {} for file '{}'",
                    chunk_id, node.logical_path
                ))
            })?;
            let chunk_bytes = self.decode_chunk(&mut file, descriptor, derived_key.as_ref())?;
            output.extend_from_slice(&chunk_bytes);
        }

        let actual_file_hash = self.crypto.hash_bytes(&output);
        if &actual_file_hash != content_hash {
            return Err(DomainError::IntegrityMismatch {
                path: node.logical_path.clone(),
                expected: content_hash.to_string(),
                actual: actual_file_hash.to_string(),
            });
        }

        Ok(output)
    }

    fn read_chunk(
        &self,
        archive_path: &Path,
        manifest: &ArchiveManifest,
        chunk_id: &ChunkId,
        passphrase: Option<&str>,
    ) -> DomainResult<Vec<u8>> {
        let descriptor = manifest.chunks.get(chunk_id).ok_or_else(|| {
            DomainError::StorageError(format!("Chunk {chunk_id} not found in manifest"))
        })?;

        let mut file = File::open(archive_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed to open archive '{}': {e}",
                archive_path.display()
            ))
        })?;

        let (header, _) = Self::read_header_and_footer(&mut file)?;
        let derived_key = if descriptor.encrypted {
            let pass = passphrase
                .ok_or_else(|| DomainError::PassphraseRequired(format!("chunk {chunk_id}")))?;
            Some(self.crypto.derive_key(pass, &header.kdf_salt)?)
        } else {
            None
        };

        self.decode_chunk(&mut file, descriptor, derived_key.as_ref())
    }
}
