use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;

use wbak_domain::{
    ArchiveBuildInput, ArchiveManifest, ArchiveStats, ArchiveWriterPort, ChunkDescriptor, ChunkId,
    CryptoProviderPort, DerivedKey, DomainError, DomainResult, FileNodeKind, ProgressEvent,
    ProgressPhase, ProgressSinkPort, SensitivityLevel,
};

use crate::wire_format::{
    ArchiveFooter, ArchiveHeader, DEFAULT_CHUNK_SIZE, FLAG_FULL_ARCHIVE_ENCRYPTED,
    FLAG_HAS_ENCRYPTED_SECRETS, FORMAT_VERSION, HEADER_SIZE,
};

pub struct WbakArchiveWriter {
    crypto: Arc<dyn CryptoProviderPort>,
    chunk_size: usize,
}

impl WbakArchiveWriter {
    pub fn new(crypto: Arc<dyn CryptoProviderPort>) -> Self {
        Self {
            crypto,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(1024);
        self
    }
}

impl ArchiveWriterPort for WbakArchiveWriter {
    fn write_archive(
        &self,
        output_path: &Path,
        mut input: ArchiveBuildInput,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest> {
        let secret_files: Vec<String> = input
            .files
            .iter()
            .filter(|f| f.sensitivity == SensitivityLevel::Secret)
            .map(|f| f.logical_path.clone())
            .collect();

        let has_encrypted_secrets = input.encrypt_secrets_by_default && !secret_files.is_empty();
        let needs_encryption = input.encrypt_full_archive || has_encrypted_secrets;

        let salt = self.crypto.generate_salt();
        let derived_key: Option<DerivedKey> = if needs_encryption {
            let pass = input.passphrase.as_deref().ok_or_else(|| {
                let sample = secret_files
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "full archive".to_string());
                DomainError::PassphraseRequired(sample)
            })?;
            if pass.is_empty() {
                return Err(DomainError::PassphraseRequired(
                    "Passphrase cannot be empty when encrypting sensitive files or archive"
                        .to_string(),
                ));
            }
            Some(self.crypto.derive_key(pass, &salt)?)
        } else {
            None
        };

        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    DomainError::StorageError(format!(
                        "Failed to create output directory '{}': {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        let file = File::create(output_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed to create archive file '{}': {e}",
                output_path.display()
            ))
        })?;
        let mut writer = BufWriter::new(file);

        let mut flags = 0u16;
        if input.encrypt_full_archive {
            flags |= FLAG_FULL_ARCHIVE_ENCRYPTED;
        }
        if has_encrypted_secrets {
            flags |= FLAG_HAS_ENCRYPTED_SECRETS;
        }

        let header = ArchiveHeader {
            version: FORMAT_VERSION,
            flags,
            kdf_salt: salt,
        };
        writer
            .write_all(&header.to_bytes())
            .map_err(|e| DomainError::StorageError(format!("Failed writing header: {e}")))?;

        let mut current_offset = HEADER_SIZE as u64;
        let mut chunks_map: BTreeMap<ChunkId, ChunkDescriptor> = BTreeMap::new();

        let mut stats = ArchiveStats {
            registry_keys_count: input.registry.keys.len(),
            registry_values_count: input.registry.total_values(),
            winget_packages_count: input.winget.as_ref().map(|w| w.packages.len()).unwrap_or(0),
            ..Default::default()
        };

        let total_nodes = input.files.len() as u64;
        let mut buffer = vec![0u8; self.chunk_size];

        for (idx, node) in input.files.iter_mut().enumerate() {
            let display_path = node
                .logical_path
                .strip_prefix("${USERPROFILE}/")
                .unwrap_or(&node.logical_path);
            progress.on_progress(ProgressEvent {
                phase: ProgressPhase::PackingChunks,
                current: idx as u64 + 1,
                total: Some(total_nodes),
                message: format!("Packing {display_path}"),
            });

            let is_secret = node.is_secret();
            if is_secret {
                stats.secret_files_count += 1;
            }

            match &mut node.kind {
                FileNodeKind::Directory => {
                    stats.total_directories += 1;
                }
                FileNodeKind::Symlink { .. } => {
                    stats.total_symlinks += 1;
                }
                FileNodeKind::RegularFile {
                    size,
                    chunks,
                    content_hash,
                } => {
                    stats.total_files += 1;
                    let src_file = File::open(&node.original_path).map_err(|e| {
                        DomainError::FilesystemError(format!(
                            "Failed to open source file '{}': {e}",
                            node.original_path
                        ))
                    })?;
                    let mut reader = BufReader::new(src_file);
                    let mut file_hasher = blake3::Hasher::new();
                    let mut file_chunks = Vec::new();
                    let mut actual_size = 0u64;

                    let encrypt_this_file = input.encrypt_full_archive
                        || (input.encrypt_secrets_by_default && is_secret);

                    loop {
                        let bytes_read =
                            read_full_chunk(&mut reader, &mut buffer).map_err(|e| {
                                DomainError::FilesystemError(format!(
                                    "Failed reading '{}': {e}",
                                    node.original_path
                                ))
                            })?;

                        if bytes_read == 0 {
                            break;
                        }

                        let slice = &buffer[..bytes_read];
                        actual_size += bytes_read as u64;
                        file_hasher.update(slice);

                        let chunk_id = self.crypto.hash_bytes(slice);
                        file_chunks.push(chunk_id.clone());

                        let needs_store = match chunks_map.get(&chunk_id) {
                            None => true,
                            Some(existing) => encrypt_this_file && !existing.encrypted,
                        };

                        if needs_store {
                            let compressed = zstd::encode_all(slice, input.compression_level)
                                .map_err(|e| {
                                    DomainError::StorageError(format!(
                                        "Zstd compression failed: {e}"
                                    ))
                                })?;

                            let (payload_to_write, nonce_opt, is_encrypted) = if encrypt_this_file {
                                let key = derived_key.as_ref().ok_or_else(|| {
                                    DomainError::PassphraseRequired(node.logical_path.clone())
                                })?;
                                let (ciphertext, nonce) = self.crypto.encrypt(
                                    key,
                                    &compressed,
                                    chunk_id.as_str().as_bytes(),
                                )?;
                                (ciphertext, Some(nonce), true)
                            } else {
                                (compressed, None, false)
                            };

                            writer.write_all(&payload_to_write).map_err(|e| {
                                DomainError::StorageError(format!("Failed writing chunk: {e}"))
                            })?;

                            let stored_size = payload_to_write.len() as u64;
                            let descriptor = ChunkDescriptor {
                                id: chunk_id.clone(),
                                offset: current_offset,
                                stored_size,
                                original_size: bytes_read as u64,
                                encrypted: is_encrypted,
                                nonce: nonce_opt,
                            };

                            current_offset += stored_size;
                            stats.deduplicated_plaintext_bytes += bytes_read as u64;
                            stats.compressed_stored_bytes += stored_size;
                            chunks_map.insert(chunk_id, descriptor);
                        }
                    }

                    *size = actual_size;
                    *chunks = file_chunks;
                    *content_hash = ChunkId(file_hasher.finalize().to_hex().to_string());
                    stats.total_logical_bytes += actual_size;
                }
            }
        }

        stats.unique_chunks = chunks_map.len();

        let manifest = ArchiveManifest {
            format_version: FORMAT_VERSION,
            created_at: Utc::now(),
            source_hostname: std::env::var("COMPUTERNAME")
                .unwrap_or_else(|_| "windows-host".to_string()),
            source_username: std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string()),
            profile: input.profile,
            full_archive_encrypted: input.encrypt_full_archive,
            has_encrypted_secrets,
            chunks: chunks_map,
            files: input.files,
            registry: input.registry,
            winget: input.winget,
            env_vars: input.env_vars,
            stats,
        };

        let manifest_json = serde_json::to_vec(&manifest).map_err(|e| {
            DomainError::StorageError(format!("Failed to serialize archive manifest: {e}"))
        })?;
        let compressed_manifest =
            zstd::encode_all(manifest_json.as_slice(), input.compression_level).map_err(|e| {
                DomainError::StorageError(format!("Failed to compress archive manifest: {e}"))
            })?;

        let (manifest_bytes, manifest_nonce) = if input.encrypt_full_archive {
            let key = derived_key
                .as_ref()
                .ok_or_else(|| DomainError::PassphraseRequired("archive manifest".to_string()))?;
            self.crypto
                .encrypt(key, &compressed_manifest, b"wbak-manifest-v1")?
        } else {
            (compressed_manifest, [0u8; 12])
        };

        let manifest_offset = current_offset;
        let manifest_stored_size = manifest_bytes.len() as u64;

        writer
            .write_all(&manifest_bytes)
            .map_err(|e| DomainError::StorageError(format!("Failed writing manifest: {e}")))?;

        let footer = ArchiveFooter {
            manifest_offset,
            manifest_stored_size,
            manifest_nonce,
        };
        writer
            .write_all(&footer.to_bytes())
            .map_err(|e| DomainError::StorageError(format!("Failed writing footer: {e}")))?;

        writer
            .flush()
            .map_err(|e| DomainError::StorageError(format!("Failed flushing archive: {e}")))?;

        // Ensure current file position matches expected size
        let _ = writer.seek(SeekFrom::End(0));

        Ok(manifest)
    }
}

fn read_full_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
