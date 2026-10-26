use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use wbak_domain::{
    ArchiveBuildInput, ArchiveManifest, ArchiveReaderPort, ArchiveWriterPort, ChunkId,
    CryptoProviderPort, DiffCalculator, DomainError, DomainResult, EnvironmentRepositoryPort,
    FileNode, FileNodeKind, FileRestorerPort, FileScannerPort, IncrementalStats, LiveFileProbe,
    PathFilterFactoryPort, PortablePathTokenizer, ProgressEvent, ProgressPhase, ProgressSinkPort,
    RegistryBackupConfig, RegistryBrowseItem, RegistryHive, RegistryRepositoryPort, ScannedEntry,
    ScannedEntryKind, SecretPromptPort, SensitivityLevel, SystemDriftReport, is_ssh_path,
};

use crate::dto::{CreateBackupRequest, RestoreBackupRequest, RestoreSummary};

/// Core application orchestrator coordinating Domain logic and Driven Adapters via Ports.
#[derive(Clone)]
pub struct WbakApplication {
    filter_factory: Arc<dyn PathFilterFactoryPort>,
    scanner: Arc<dyn FileScannerPort>,
    restorer: Arc<dyn FileRestorerPort>,
    registry: Arc<dyn RegistryRepositoryPort>,
    environment: Arc<dyn EnvironmentRepositoryPort>,
    archive_writer: Arc<dyn ArchiveWriterPort>,
    archive_reader: Arc<dyn ArchiveReaderPort>,
    crypto: Arc<dyn CryptoProviderPort>,
    tokenizer: PortablePathTokenizer,
}

impl WbakApplication {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        filter_factory: Arc<dyn PathFilterFactoryPort>,
        scanner: Arc<dyn FileScannerPort>,
        restorer: Arc<dyn FileRestorerPort>,
        registry: Arc<dyn RegistryRepositoryPort>,
        environment: Arc<dyn EnvironmentRepositoryPort>,
        archive_writer: Arc<dyn ArchiveWriterPort>,
        archive_reader: Arc<dyn ArchiveReaderPort>,
        crypto: Arc<dyn CryptoProviderPort>,
        tokenizer: PortablePathTokenizer,
    ) -> Self {
        Self {
            filter_factory,
            scanner,
            restorer,
            registry,
            environment,
            archive_writer,
            archive_reader,
            crypto,
            tokenizer,
        }
    }

    pub fn tokenizer(&self) -> &PortablePathTokenizer {
        &self.tokenizer
    }

    pub fn list_registry_subkeys(
        &self,
        hive: RegistryHive,
        parent_subkey: &str,
    ) -> DomainResult<Vec<RegistryBrowseItem>> {
        self.registry.list_subkeys(hive, parent_subkey)
    }

    /// Runs a live filesystem scan returning both included, ignored, and `!`-exempted entries
    /// for interactive `.wbakignore` previewing in GUI or CLI.
    pub fn preview_scan(
        &self,
        include_paths: &[String],
        ignore_patterns: &[String],
        ignore_file: Option<&Path>,
        respect_local_ignore: bool,
    ) -> DomainResult<Vec<ScannedEntry>> {
        let filter = self
            .filter_factory
            .build_filter(ignore_patterns, ignore_file)?;
        let physical_includes: Vec<PathBuf> = include_paths
            .iter()
            .map(|p| self.tokenizer.detokenize(p))
            .collect();

        self.scanner.scan_paths(
            &physical_includes,
            filter.as_ref(),
            respect_local_ignore,
            true,
        )
    }

    /// Executes a complete or incremental backup workflow:
    /// 1. Builds `.wbakignore` filter (with `!` exemptions)
    /// 2. Scans filesystem & auto-detects `.ssh` / sensitive files
    /// 3. If `output_archive` already exists and `!force_full_rebuild`, matches against previous
    ///    manifest (`size` + `modified_at`) so unchanged files are reused with zero disk reads,
    ///    and deleted files are pruned from the manifest (unless `keep_deleted` is set).
    /// 4. Enforces default encryption for sensitive files (prompting if needed)
    /// 5. Exports Windows Registry keys & values
    /// 6. Optionally captures `winget` packages & environment variables
    /// 7. Writes or incrementally appends `.wbak` archive (and optionally compacts dead chunks)
    pub fn create_backup(
        &self,
        request: CreateBackupRequest,
        progress: &dyn ProgressSinkPort,
        secret_prompt: Option<&dyn SecretPromptPort>,
    ) -> DomainResult<ArchiveManifest> {
        let profile = &request.profile;

        progress.on_progress(ProgressEvent {
            phase: ProgressPhase::ScanningFiles,
            current: 0,
            total: None,
            message: "Building .wbakignore rules and scanning paths...".to_string(),
        });

        let filter = self.filter_factory.build_filter(
            &profile.files.ignore_patterns,
            profile.files.ignore_file.as_deref(),
        )?;

        let include_paths: Vec<PathBuf> = profile
            .files
            .include
            .iter()
            .map(|p| self.tokenizer.detokenize(p))
            .collect();

        let scanned = self.scanner.scan_paths(
            &include_paths,
            filter.as_ref(),
            profile.files.respect_local_ignore_files,
            false,
        )?;

        // Load existing manifest if updating an existing `.wbak` archive incrementally
        let previous_manifest = if !request.force_full_rebuild && request.output_archive.exists() {
            match self
                .archive_reader
                .read_manifest(&request.output_archive, request.passphrase.as_deref())
            {
                Ok(m) => Some(m),
                Err(DomainError::PassphraseRequired(reason)) => {
                    if let Some(prompter) = secret_prompt {
                        let pass = prompter.prompt_passphrase(&reason, false)?;
                        self.archive_reader
                            .read_manifest(&request.output_archive, Some(&pass))
                            .ok()
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };

        let prev_files_map: BTreeMap<String, &FileNode> = previous_manifest
            .as_ref()
            .map(|m| {
                m.files
                    .iter()
                    .map(|f| (f.logical_path.clone(), f))
                    .collect()
            })
            .unwrap_or_default();

        let mut seen_logical_paths = BTreeSet::new();
        let mut inc_stats = IncrementalStats::default();
        let mut file_nodes = Vec::with_capacity(scanned.len());
        let mut first_new_secret_path: Option<String> = None;

        for entry in scanned {
            if !entry.filter_decision.is_included() {
                continue;
            }
            seen_logical_paths.insert(entry.logical_path.clone());

            let kind = match entry.kind {
                ScannedEntryKind::RegularFile { size } => {
                    let mut reused = None;
                    if let (Some(prev_manifest), Some(prev_node)) = (
                        previous_manifest.as_ref(),
                        prev_files_map.get(&entry.logical_path),
                    ) && let FileNodeKind::RegularFile {
                        size: prev_size,
                        chunks: prev_chunks,
                        content_hash: prev_hash,
                    } = &prev_node.kind
                    {
                        let same_size = *prev_size == size;
                        let same_mtime = timestamps_match(prev_node.modified_at, entry.modified_at);
                        let chunks_present = !prev_chunks.is_empty()
                            && prev_chunks
                                .iter()
                                .all(|cid| prev_manifest.chunks.contains_key(cid));

                        if same_size && same_mtime && chunks_present {
                            reused = Some((prev_chunks.clone(), prev_hash.clone()));
                        }
                    }

                    if let Some((chunks, content_hash)) = reused {
                        inc_stats.files_unchanged += 1;
                        inc_stats.bytes_reused += size;
                        FileNodeKind::RegularFile {
                            size,
                            chunks,
                            content_hash,
                        }
                    } else {
                        if prev_files_map.contains_key(&entry.logical_path) {
                            inc_stats.files_modified += 1;
                        } else {
                            inc_stats.files_added += 1;
                        }
                        inc_stats.bytes_appended += size;
                        if entry.sensitivity == SensitivityLevel::Secret
                            && first_new_secret_path.is_none()
                        {
                            first_new_secret_path = Some(entry.logical_path.clone());
                        }
                        FileNodeKind::RegularFile {
                            size,
                            chunks: Vec::new(),
                            content_hash: ChunkId(String::new()),
                        }
                    }
                }
                ScannedEntryKind::Directory => FileNodeKind::Directory,
                ScannedEntryKind::Symlink { target, is_dir } => {
                    FileNodeKind::Symlink { target, is_dir }
                }
            };

            file_nodes.push(FileNode {
                logical_path: entry.logical_path,
                original_path: entry.physical_path.to_string_lossy().to_string(),
                kind,
                sensitivity: entry.sensitivity,
                attributes: entry.attributes,
                modified_at: entry.modified_at,
                created_at: entry.created_at,
            });
        }

        // Check for deleted files that were in `previous_manifest` but are no longer on disk
        if let Some(prev_m) = &previous_manifest {
            for old_node in &prev_m.files {
                if !seen_logical_paths.contains(&old_node.logical_path) {
                    if matches!(old_node.kind, FileNodeKind::RegularFile { .. }) {
                        inc_stats.files_deleted += 1;
                    }
                    if request.keep_deleted {
                        file_nodes.push(old_node.clone());
                    }
                }
            }
        }

        let encrypt_secrets_by_default =
            profile.security.encrypt_sensitive_by_default && !request.allow_unencrypted_secrets;
        let needs_passphrase = profile.security.encrypt_full_archive
            || (encrypt_secrets_by_default && first_new_secret_path.is_some());

        let passphrase = match (&request.passphrase, needs_passphrase) {
            (Some(p), _) if !p.is_empty() => Some(p.clone()),
            (_, true) => {
                let reason = if profile.security.encrypt_full_archive {
                    "Full archive encryption is enabled".to_string()
                } else {
                    format!(
                        "Sensitive file detected ({}) — encrypted by default",
                        first_new_secret_path.as_deref().unwrap_or(".ssh")
                    )
                };
                if let Some(prompter) = secret_prompt {
                    Some(prompter.prompt_passphrase(&reason, true)?)
                } else {
                    return Err(DomainError::PassphraseRequired(reason));
                }
            }
            _ => None,
        };

        progress.on_progress(ProgressEvent {
            phase: ProgressPhase::ExportingRegistry,
            current: 0,
            total: Some(profile.registry.include_keys.len() as u64),
            message: "Exporting selected Windows Registry keys...".to_string(),
        });

        let registry_tree = if profile.registry.include_keys.is_empty() {
            Default::default()
        } else {
            self.registry.export_keys(&profile.registry)?
        };

        let winget = if profile.environment.capture_winget {
            progress.on_progress(ProgressEvent {
                phase: ProgressPhase::CapturingWinget,
                current: 0,
                total: None,
                message: "Capturing installed winget packages...".to_string(),
            });
            Some(self.environment.capture_winget()?)
        } else {
            None
        };

        let env_vars = if profile.environment.capture_env_vars {
            Some(self.environment.capture_env_vars()?)
        } else {
            None
        };

        let was_incremental = previous_manifest.is_some();
        let build_input = ArchiveBuildInput {
            profile: profile.profile.clone(),
            compression_level: profile.profile.compression_level,
            encrypt_full_archive: profile.security.encrypt_full_archive,
            encrypt_secrets_by_default,
            passphrase: passphrase.clone(),
            files: file_nodes,
            registry: registry_tree,
            winget,
            env_vars,
            previous_manifest,
        };

        let mut manifest =
            self.archive_writer
                .write_archive(&request.output_archive, build_input, progress)?;

        if request.compact_after_update && manifest.stats.reclaimable_chunks > 0 {
            manifest = self.archive_writer.compact_archive(
                &request.output_archive,
                passphrase.as_deref(),
                progress,
            )?;
        }

        if was_incremental {
            manifest.stats.last_incremental = Some(inc_stats);
        }

        progress.on_progress(ProgressEvent {
            phase: ProgressPhase::Completed,
            current: 1,
            total: Some(1),
            message: format!(
                "Backup complete: {} files, {} unique chunks, {} registry values",
                manifest.stats.total_files,
                manifest.stats.unique_chunks,
                manifest.stats.registry_values_count
            ),
        });

        Ok(manifest)
    }

    /// Reclaims unreferenced dead chunks (from deleted or modified files) by streaming
    /// live compressed chunks into a compacted archive without decompressing or re-compressing.
    pub fn compact_archive(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest> {
        self.archive_writer
            .compact_archive(archive_path, passphrase, progress)
    }

    pub fn inspect_archive(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
    ) -> DomainResult<ArchiveManifest> {
        self.archive_reader.read_manifest(archive_path, passphrase)
    }

    pub fn verify_archive(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
        progress: &dyn ProgressSinkPort,
    ) -> DomainResult<ArchiveManifest> {
        self.archive_reader
            .verify_archive(archive_path, passphrase, progress)
    }

    /// Compares an archive against the live Windows filesystem, Registry, and `winget` packages.
    pub fn diff_system(
        &self,
        archive_path: &Path,
        passphrase: Option<&str>,
    ) -> DomainResult<SystemDriftReport> {
        let manifest = self
            .archive_reader
            .read_manifest(archive_path, passphrase)?;

        let mut live_probes = BTreeMap::new();
        for node in &manifest.files {
            if !matches!(node.kind, FileNodeKind::RegularFile { .. }) {
                continue;
            }
            let target_path = self.tokenizer.detokenize(&node.logical_path);
            let target_str = target_path.to_string_lossy().to_string();

            if !target_path.exists() {
                live_probes.insert(
                    node.logical_path.clone(),
                    LiveFileProbe {
                        target_path: target_str,
                        exists: false,
                        size: None,
                        content_hash: None,
                    },
                );
            } else {
                let meta = std::fs::metadata(&target_path).ok();
                let size = meta.as_ref().map(|m| m.len());
                let content_hash = std::fs::read(&target_path)
                    .ok()
                    .map(|bytes| self.crypto.hash_bytes(&bytes).0);
                live_probes.insert(
                    node.logical_path.clone(),
                    LiveFileProbe {
                        target_path: target_str,
                        exists: true,
                        size,
                        content_hash,
                    },
                );
            }
        }

        let reg_keys_to_check: Vec<String> = manifest.registry.keys.keys().cloned().collect();
        let live_registry = if reg_keys_to_check.is_empty() {
            Default::default()
        } else {
            self.registry
                .export_keys(&RegistryBackupConfig {
                    include_keys: reg_keys_to_check,
                    exclude_patterns: Vec::new(),
                })
                .unwrap_or_default()
        };

        let live_winget = if manifest.winget.is_some() {
            self.environment.capture_winget().ok()
        } else {
            None
        };

        Ok(DiffCalculator::compute_report(
            &manifest.files,
            &live_probes,
            &manifest.registry,
            &live_registry,
            manifest.winget.as_ref(),
            live_winget.as_ref(),
        ))
    }

    /// Restores files, registry keys (with automatic `.reg` rollback file), `.ssh` NTFS ACLs,
    /// and optional `winget` packages from a `.wbak` archive.
    pub fn restore_backup(
        &self,
        request: RestoreBackupRequest,
        progress: &dyn ProgressSinkPort,
        secret_prompt: Option<&dyn SecretPromptPort>,
    ) -> DomainResult<RestoreSummary> {
        let mut active_passphrase = request.passphrase.clone();

        let manifest = match self
            .archive_reader
            .read_manifest(&request.archive_path, active_passphrase.as_deref())
        {
            Ok(m) => m,
            Err(DomainError::PassphraseRequired(reason)) => {
                if let Some(prompter) = secret_prompt {
                    let pass = prompter.prompt_passphrase(&reason, false)?;
                    let m = self
                        .archive_reader
                        .read_manifest(&request.archive_path, Some(&pass))?;
                    active_passphrase = Some(pass);
                    m
                } else {
                    return Err(DomainError::PassphraseRequired(reason));
                }
            }
            Err(e) => return Err(e),
        };

        let mut summary = RestoreSummary {
            dry_run: request.dry_run,
            ..Default::default()
        };

        if request.restore_files {
            let matching_nodes: Vec<&FileNode> = manifest
                .files
                .iter()
                .filter(|node| {
                    request
                        .path_filter
                        .as_ref()
                        .map(|flt| {
                            node.logical_path
                                .to_ascii_lowercase()
                                .contains(&flt.to_ascii_lowercase())
                        })
                        .unwrap_or(true)
                })
                .collect();

            // Check if any selected file requires decrypting secret chunks
            let needs_secret_key = matching_nodes.iter().any(|n| match &n.kind {
                FileNodeKind::RegularFile { chunks, .. } => chunks.iter().any(|cid| {
                    manifest
                        .chunks
                        .get(cid)
                        .map(|d| d.encrypted)
                        .unwrap_or(false)
                }),
                _ => false,
            });

            if needs_secret_key && active_passphrase.is_none() {
                if let Some(prompter) = secret_prompt {
                    let pass = prompter.prompt_passphrase(
                        "Archive contains encrypted sensitive files (e.g. .ssh keys)",
                        false,
                    )?;
                    active_passphrase = Some(pass);
                } else {
                    return Err(DomainError::PassphraseRequired(
                        "Encrypted sensitive files require a passphrase to restore".to_string(),
                    ));
                }
            }

            let common_parent = if request.target_dir_override.is_some() {
                compute_common_parent_prefix(&manifest.files)
            } else {
                None
            };

            let total = matching_nodes.len() as u64;
            for (idx, node) in matching_nodes.into_iter().enumerate() {
                let target_path = self.resolve_restore_target(
                    &node.logical_path,
                    request.target_dir_override.as_deref(),
                    common_parent.as_deref(),
                );

                progress.on_progress(ProgressEvent {
                    phase: ProgressPhase::RestoringFiles,
                    current: idx as u64 + 1,
                    total: Some(total),
                    message: format!("Restoring {}", target_path.display()),
                });

                match &node.kind {
                    FileNodeKind::Directory => {
                        if !request.dry_run {
                            self.restorer
                                .restore_directory(&target_path, &node.attributes)?;
                        }
                        summary.dirs_restored += 1;
                    }
                    FileNodeKind::Symlink { target, is_dir } => {
                        if !request.dry_run {
                            let written = self.restorer.restore_symlink(
                                &target_path,
                                target,
                                *is_dir,
                                request.conflict_policy,
                            )?;
                            if written {
                                summary.files_restored += 1;
                            } else {
                                summary.files_skipped += 1;
                            }
                        } else {
                            summary.files_restored += 1;
                        }
                    }
                    FileNodeKind::RegularFile { .. } => {
                        let bytes = self.archive_reader.extract_file_bytes(
                            &request.archive_path,
                            &manifest,
                            node,
                            active_passphrase.as_deref(),
                        )?;

                        if !request.dry_run {
                            let written = self.restorer.restore_regular_file(
                                &target_path,
                                &bytes,
                                &node.attributes,
                                node.modified_at,
                                request.conflict_policy,
                            )?;
                            if written {
                                summary.files_restored += 1;
                                if node.is_secret() || is_ssh_path(&node.logical_path) {
                                    self.restorer.tighten_secret_file_acl(&target_path)?;
                                    summary.secret_acls_hardened += 1;
                                }
                            } else {
                                summary.files_skipped += 1;
                            }
                        } else {
                            summary.files_restored += 1;
                        }
                    }
                }
            }
        }

        if request.restore_registry && !manifest.registry.keys.is_empty() {
            progress.on_progress(ProgressEvent {
                phase: ProgressPhase::RestoringRegistry,
                current: 0,
                total: Some(manifest.registry.keys.len() as u64),
                message: "Restoring Windows Registry keys...".to_string(),
            });

            if !request.dry_run {
                let rollback_path = request.archive_path.with_file_name(format!(
                    "wbak-rollback-{}.reg",
                    Utc::now().format("%Y%m%d-%H%M%S")
                ));
                self.registry
                    .create_rollback_reg_file(&manifest.registry, &rollback_path)?;
                summary.rollback_reg_file = Some(rollback_path);
                summary.registry_values_restored =
                    self.registry.restore_tree(&manifest.registry)?;
            } else {
                summary.registry_values_restored = manifest.registry.total_values();
            }
        }

        if request.restore_winget
            && let Some(winget_manifest) = &manifest.winget
        {
            progress.on_progress(ProgressEvent {
                phase: ProgressPhase::RestoringWinget,
                current: 0,
                total: Some(winget_manifest.packages.len() as u64),
                message: "Restoring winget packages...".to_string(),
            });
            summary.winget_packages_restored = self
                .environment
                .restore_winget(winget_manifest, request.dry_run)?;
        }

        if request.restore_env_vars
            && let Some(env_snapshot) = &manifest.env_vars
        {
            summary.env_vars_restored = self
                .environment
                .restore_user_env_vars(env_snapshot, request.dry_run)?;
        }

        progress.on_progress(ProgressEvent {
            phase: ProgressPhase::Completed,
            current: 1,
            total: Some(1),
            message: "Restore completed successfully".to_string(),
        });

        Ok(summary)
    }

    fn resolve_restore_target(
        &self,
        logical_path: &str,
        target_dir_override: Option<&Path>,
        common_parent: Option<&str>,
    ) -> PathBuf {
        let Some(override_root) = target_dir_override else {
            return self.tokenizer.detokenize(logical_path);
        };

        let norm = logical_path.replace('\\', "/");

        // 1. If all entries in the archive share a common parent directory (e.g. `${USERPROFILE}/Languages`),
        // strip that prefix so `-t Output` extracts directly into `Output/`.
        if let Some(prefix) = common_parent
            && !prefix.is_empty()
        {
            let prefix_with_slash = format!("{prefix}/");
            if let Some(stripped) = norm.strip_prefix(&prefix_with_slash)
                && !stripped.is_empty()
            {
                return override_root.join(stripped.replace('/', std::path::MAIN_SEPARATOR_STR));
            }
        }

        // 2. Otherwise strip any leading `${TOKEN}/` or drive prefix (`C:/`) completely.
        let rel = strip_leading_token_or_drive(&norm);
        override_root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))
    }
}

fn timestamps_match(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> bool {
    match (a, b) {
        (Some(ta), Some(tb)) => ta.timestamp_millis() == tb.timestamp_millis(),
        _ => false,
    }
}

/// Computes the longest common parent directory shared by all `FileNode` entries in an archive.
pub fn compute_common_parent_prefix(files: &[FileNode]) -> Option<String> {
    let mut common_segments: Option<Vec<&str>> = None;

    for node in files {
        let norm = node.logical_path.trim_end_matches('/');
        let parent = match norm.rsplit_once('/') {
            Some((p, _)) => p,
            None => "",
        };
        let segments: Vec<&str> = if parent.is_empty() {
            Vec::new()
        } else {
            parent.split('/').collect()
        };

        match &mut common_segments {
            None => common_segments = Some(segments),
            Some(existing) => {
                let match_len = existing
                    .iter()
                    .zip(segments.iter())
                    .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
                    .count();
                existing.truncate(match_len);
            }
        }
    }

    common_segments.map(|segs| segs.join("/"))
}

/// Strips a leading `${TOKEN}/` (e.g. `${USERPROFILE}/`) or Windows drive prefix (`C:/`) from a path.
pub fn strip_leading_token_or_drive(norm_path: &str) -> &str {
    let s = norm_path.trim_start_matches('/');
    if s.starts_with("${")
        && let Some(close_idx) = s.find('}')
    {
        let after = &s[close_idx + 1..];
        return after.trim_start_matches('/');
    }
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        return s[2..].trim_start_matches('/');
    }
    s
}

#[cfg(test)]
mod tests {
    use wbak_domain::{ChunkId, FileNode, FileNodeKind, SensitivityLevel, WindowsFileAttributes};

    use super::*;

    fn dummy_node(logical_path: &str, is_dir: bool) -> FileNode {
        FileNode {
            logical_path: logical_path.to_string(),
            original_path: logical_path.to_string(),
            kind: if is_dir {
                FileNodeKind::Directory
            } else {
                FileNodeKind::RegularFile {
                    size: 10,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                }
            },
            sensitivity: SensitivityLevel::Public,
            attributes: WindowsFileAttributes::default(),
            modified_at: None,
            created_at: None,
        }
    }

    #[test]
    fn single_directory_backup_extracts_contents_without_userprofile_folder() {
        let files = vec![
            dummy_node("${USERPROFILE}/Languages/rust", true),
            dummy_node("${USERPROFILE}/Languages/rust/main.rs", false),
            dummy_node("${USERPROFILE}/Languages/cpp", true),
            dummy_node("${USERPROFILE}/Languages/cpp/main.cpp", false),
        ];

        let common = compute_common_parent_prefix(&files);
        assert_eq!(common.as_deref(), Some("${USERPROFILE}/Languages"));

        let prefix = format!("{}/", common.unwrap());
        assert_eq!(files[0].logical_path.strip_prefix(&prefix), Some("rust"));
        assert_eq!(
            files[1].logical_path.strip_prefix(&prefix),
            Some("rust/main.rs")
        );
    }

    #[test]
    fn strip_leading_token_removes_entire_token_not_just_braces() {
        assert_eq!(
            strip_leading_token_or_drive("${USERPROFILE}/Languages/main.rs"),
            "Languages/main.rs"
        );
        assert_eq!(
            strip_leading_token_or_drive("C:/Projects/app/src/lib.rs"),
            "Projects/app/src/lib.rs"
        );
    }
}
