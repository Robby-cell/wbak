use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;

use wbak_domain::{
    ArchiveBuildInput, ArchiveManifest, ArchiveReaderPort, ArchiveStats, ArchiveWriterPort,
    ChunkDescriptor, ChunkId, CryptoProviderPort, DerivedKey, DomainError, DomainResult,
    FileNodeKind, ProgressEvent, ProgressPhase, ProgressSinkPort, SensitivityLevel,
};

use crate::archive_reader::WbakArchiveReader;
use crate::wire_format::{
    ArchiveFooter, ArchiveHeader, DEFAULT_CHUNK_SIZE, FLAG_FULL_ARCHIVE_ENCRYPTED,
    FLAG_HAS_ENCRYPTED_SECRETS, FOOTER_SIZE, FORMAT_VERSION, HEADER_SIZE,
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

    fn read_existing_header_and_footer(file: &mut File) -> DomainResult<(ArchiveHeader, ArchiveFooter)> {
        let len = file
            .metadata()
            .map_err(|e| DomainError::StorageError(format!("Failed reading metadata: {e}")))?
            .len();
        if len < (HEADER_SIZE + FOOTER_SIZE) as u64 {
            return Err(DomainError::StorageError(
                "Existing archive is too small to update incrementally".to_string(),
            ));
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|e| DomainError::StorageError(format!("Seek start failed: {e}")))?;
        let mut h_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut h_buf)
            .map_err(|e| DomainError::StorageError(format!("Read header failed: {e}")))?;
        let header = ArchiveHeader::from_bytes(&h_buf)?;

        file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))
            .map_err(|e| DomainError::StorageError(format!("Seek footer failed: {e}")))?;
        let mut f_buf = [0u8; FOOTER_SIZE];
        file.read_exact(&mut f_buf)
            .map_err(|e| DomainError::StorageError(format!("Read footer failed: {e}")))?;
        let footer = ArchiveFooter::from_bytes(&f_buf)?;

        Ok((header, footer))
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

        let has_encrypted_secrets =
            input.encrypt_secrets_by_default && !secret_files.is_empty();

        // Check whether we can perform Strategy 1: In-Place Tail Append on an existing archive
        let is_incremental = input.previous_manifest.is_some() && output_path.exists();

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

        let (mut writer, salt, mut current_offset, mut chunks_map, prev_had_encrypted_secrets) =
            if is_incremental {
                let prev_manifest = input.previous_manifest.take().unwrap();
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(output_path)
                    .map_err(|e| {
                        DomainError::StorageError(format!(
                            "Failed opening existing archive '{}' for incremental update: {e}",
                            output_path.display()
                        ))
                    })?;

                let (existing_header, existing_footer) =
                    Self::read_existing_header_and_footer(&mut file)?;

                // Truncate only the old manifest + footer at the end of the file, keeping all existing chunks intact
                file.set_len(existing_footer.manifest_offset).map_err(|e| {
                    DomainError::StorageError(format!(
                        "Failed truncating old manifest tail during incremental update: {e}"
                    ))
                })?;

                let mut flags = existing_header.flags;
                if input.encrypt_full_archive {
                    flags |= FLAG_FULL_ARCHIVE_ENCRYPTED;
                }
                if has_encrypted_secrets || prev_manifest.has_encrypted_secrets {
                    flags |= FLAG_HAS_ENCRYPTED_SECRETS;
                }

                let updated_header = ArchiveHeader {
                    version: FORMAT_VERSION,
                    flags,
                    kdf_salt: existing_header.kdf_salt,
                };
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| DomainError::StorageError(format!("Seek header failed: {e}")))?;
                file.write_all(&updated_header.to_bytes())
                    .map_err(|e| DomainError::StorageError(format!("Update header failed: {e}")))?;

                file.seek(SeekFrom::Start(existing_footer.manifest_offset))
                    .map_err(|e| {
                        DomainError::StorageError(format!("Seek tail offset failed: {e}"))
                    })?;

                (
                    BufWriter::new(file),
                    existing_header.kdf_salt,
                    existing_footer.manifest_offset,
                    prev_manifest.chunks,
                    prev_manifest.has_encrypted_secrets,
                )
            } else {
                let salt = self.crypto.generate_salt();
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

                (
                    writer,
                    salt,
                    HEADER_SIZE as u64,
                    BTreeMap::new(),
                    false,
                )
            };

        // Determine if any file actually needs encryption (i.e. full archive encryption OR a new/modified secret file)
        let has_unpacked_secret_file = input.files.iter().any(|f| {
            f.is_secret()
                && match &f.kind {
                    FileNodeKind::RegularFile {
                        size,
                        chunks,
                        content_hash,
                    } => *size > 0 && (chunks.is_empty() || content_hash.0.is_empty()),
                    _ => false,
                }
        });

        let needs_key_derivation = input.encrypt_full_archive
            || (input.encrypt_secrets_by_default && has_unpacked_secret_file);

        let derived_key: Option<DerivedKey> = if needs_key_derivation {
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
        } else if let Some(pass) = input.passphrase.as_deref().filter(|p| !p.is_empty()) {
            Some(self.crypto.derive_key(pass, &salt)?)
        } else {
            None
        };

        let mut stats = ArchiveStats {
            registry_keys_count: input.registry.keys.len(),
            registry_values_count: input.registry.total_values(),
            winget_packages_count: input
                .winget
                .as_ref()
                .map(|w| w.packages.len())
                .unwrap_or(0),
            ..Default::default()
        };

        let total_nodes = input.files.len() as u64;
        let mut buffer = vec![0u8; self.chunk_size];

        for (idx, node) in input.files.iter_mut().enumerate() {
            let display_path = node
                .logical_path
                .strip_prefix("${USERPROFILE}/")
                .unwrap_or(&node.logical_path)
                .to_string();

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

                    let encrypt_this_file = input.encrypt_full_archive
                        || (input.encrypt_secrets_by_default && is_secret);

                    // Fast path (Strategy 1): If `WbakApplication` pre-populated `chunks` and `content_hash`
                    // from `previous_manifest` (because `size` and `modified_at` were identical) and all
                    // referenced chunks exist in `chunks_map` with sufficient encryption, skip disk read!
                    let can_reuse_without_disk_read = !chunks.is_empty()
                        && !content_hash.0.is_empty()
                        && chunks.iter().all(|cid| {
                            chunks_map
                                .get(cid)
                                .map(|desc| !encrypt_this_file || desc.encrypted)
                                .unwrap_or(false)
                        });

                    if can_reuse_without_disk_read {
                        progress.on_progress(ProgressEvent {
                            phase: ProgressPhase::PackingChunks,
                            current: idx as u64 + 1,
                            total: Some(total_nodes),
                            message: format!("Reusing unchanged {display_path}"),
                        });
                        stats.total_logical_bytes += *size;
                        continue;
                    }

                    progress.on_progress(ProgressEvent {
                        phase: ProgressPhase::PackingChunks,
                        current: idx as u64 + 1,
                        total: Some(total_nodes),
                        message: format!("Packing {display_path}"),
                    });

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

                    loop {
                        let bytes_read = read_full_chunk(&mut reader, &mut buffer).map_err(|e| {
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
                            let compressed =
                                zstd::encode_all(slice, input.compression_level).map_err(|e| {
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

        // Calculate live vs unreferenced (reclaimable) chunks across `input.files`
        let mut referenced_chunks: BTreeSet<&ChunkId> = BTreeSet::new();
        for node in &input.files {
            if let FileNodeKind::RegularFile { chunks, .. } = &node.kind {
                for cid in chunks {
                    referenced_chunks.insert(cid);
                }
            }
        }

        for (cid, desc) in &chunks_map {
            if referenced_chunks.contains(cid) {
                stats.unique_chunks += 1;
                stats.deduplicated_plaintext_bytes += desc.original_size;
                stats.compressed_stored_bytes += desc.stored_size;
            } else {
                stats.reclaimable_chunks += 1;
                stats.reclaimable_bytes += desc.stored_size;
            }
        }

        let manifest = ArchiveManifest {
            format_version: FORMAT_VERSION,
            created_at: Utc::now(),
            source_hostname: std::env::var("COMPUTERNAME")
                .unwrap_or_else(|_| "windows-host".to_string()),
            source_username: std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string()),
            profile: input.profile,
            full_archive_encrypted: input.encrypt_full_archive,
            has_encrypted_secrets: has_encrypted_secrets || prev_had_encrypted_secrets,
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

        Ok(manifest)
    }

    fn compact_archive(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest> {
        let reader = WbakArchiveReader::new(self.crypto.clone());
        let mut manifest = reader.read_manifest(archive_path, passphrase)?;

        let mut old_file = File::open(archive_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed to open archive '{}' for compaction: {e}",
                archive_path.display()
            ))
        })?;
        let (header, _) = Self::read_existing_header_and_footer(&mut old_file)?;

        let mut referenced_ids: BTreeSet<ChunkId> = BTreeSet::new();
        for node in &manifest.files {
            if let FileNodeKind::RegularFile { chunks, .. } = &node.kind {
                for cid in chunks {
                    referenced_ids.insert(cid.clone());
                }
            }
        }

        let temp_path = archive_path.with_extension("wbak.compact.tmp");
        let new_file = File::create(&temp_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed creating temporary compaction file '{}': {e}",
                temp_path.display()
            ))
        })?;
        let mut writer = BufWriter::new(new_file);

        // Preserve original header (including kdf_salt) so encrypted chunks can be copied raw without re-encryption!
        writer
            .write_all(&header.to_bytes())
            .map_err(|e| DomainError::StorageError(format!("Failed writing header: {e}")))?;

        let mut current_offset = HEADER_SIZE as u64;
        let mut new_chunks_map = BTreeMap::new();
        let mut deduplicated_plaintext = 0u64;
        let mut compressed_stored = 0u64;

        let total_live = referenced_ids.len() as u64;
        for (idx, cid) in referenced_ids.iter().enumerate() {
            let Some(old_desc) = manifest.chunks.get(cid) else {
                return Err(DomainError::StorageError(format!(
                    "Missing referenced chunk {cid} during compaction"
                )));
            };

            progress.on_progress(ProgressEvent {
                phase: ProgressPhase::PackingChunks,
                current: idx as u64 + 1,
                total: Some(total_live),
                message: format!("Compacting live chunk {cid}"),
            });

            old_file
                .seek(SeekFrom::Start(old_desc.offset))
                .map_err(|e| DomainError::StorageError(format!("Seek old chunk failed: {e}")))?;

            let mut raw_payload = vec![0u8; old_desc.stored_size as usize];
            old_file
                .read_exact(&mut raw_payload)
                .map_err(|e| DomainError::StorageError(format!("Read old chunk failed: {e}")))?;

            writer
                .write_all(&raw_payload)
                .map_err(|e| DomainError::StorageError(format!("Write compacted chunk failed: {e}")))?;

            let new_desc = ChunkDescriptor {
                id: cid.clone(),
                offset: current_offset,
                stored_size: old_desc.stored_size,
                original_size: old_desc.original_size,
                encrypted: old_desc.encrypted,
                nonce: old_desc.nonce,
            };

            current_offset += old_desc.stored_size;
            deduplicated_plaintext += old_desc.original_size;
            compressed_stored += old_desc.stored_size;
            new_chunks_map.insert(cid.clone(), new_desc);
        }

        manifest.chunks = new_chunks_map;
        manifest.stats.unique_chunks = manifest.chunks.len();
        manifest.stats.deduplicated_plaintext_bytes = deduplicated_plaintext;
        manifest.stats.compressed_stored_bytes = compressed_stored;
        manifest.stats.reclaimable_chunks = 0;
        manifest.stats.reclaimable_bytes = 0;

        let manifest_json = serde_json::to_vec(&manifest).map_err(|e| {
            DomainError::StorageError(format!("Failed serializing compacted manifest: {e}"))
        })?;
        let compressed_manifest =
            zstd::encode_all(manifest_json.as_slice(), manifest.profile.compression_level)
                .map_err(|e| {
                    DomainError::StorageError(format!("Failed compressing manifest: {e}"))
                })?;

        let (manifest_bytes, manifest_nonce) = if header.is_full_encrypted() {
            let pass = passphrase.ok_or_else(|| {
                DomainError::PassphraseRequired(
                    "Full archive is encrypted; passphrase required to re-encrypt compacted manifest"
                        .to_string(),
                )
            })?;
            let key = self.crypto.derive_key(pass, &header.kdf_salt)?;
            self.crypto
                .encrypt(&key, &compressed_manifest, b"wbak-manifest-v1")?
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
            .map_err(|e| DomainError::StorageError(format!("Failed flushing compacted file: {e}")))?;
        drop(writer);
        drop(old_file);

        std::fs::rename(&temp_path, archive_path).map_err(|e| {
            DomainError::StorageError(format!(
                "Failed replacing archive with compacted file: {e}"
            ))
        })?;

        progress.on_progress(ProgressEvent {
            phase: ProgressPhase::Completed,
            current: 1,
            total: Some(1),
            message: "Compaction completed".to_string(),
        });

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
