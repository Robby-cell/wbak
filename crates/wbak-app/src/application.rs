use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;

use wbak_domain::{
    is_ssh_path, ArchiveBuildInput, ArchiveManifest, ArchiveReaderPort, ArchiveWriterPort, ChunkId,
    CryptoProviderPort, DiffCalculator, DomainError, DomainResult, EnvironmentRepositoryPort,
    FileNode, FileNodeKind, FileRestorerPort, FileScannerPort, LiveFileProbe,
    PathFilterFactoryPort, PortablePathTokenizer, ProgressEvent, ProgressPhase, ProgressSinkPort,
    RegistryBackupConfig, RegistryBrowseItem, RegistryHive, RegistryRepositoryPort, ScannedEntry,
    ScannedEntryKind, SecretPromptPort, SensitivityLevel, SystemDriftReport,
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

    /// Executes a complete backup workflow:
    /// 1. Builds `.wbakignore` filter (with `!` exemptions)
    /// 2. Scans filesystem & auto-detects `.ssh` / sensitive files
    /// 3. Enforces default encryption for sensitive files (prompting if needed)
    /// 4. Exports Windows Registry keys & values
    /// 5. Optionally captures `winget` packages & environment variables
    /// 6. Writes deduplicated, compressed `.wbak` archive
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

        let mut file_nodes = Vec::with_capacity(scanned.len());
        let mut first_secret_path: Option<String> = None;

        for entry in scanned {
            if !entry.filter_decision.is_included() {
                continue;
            }
            if entry.sensitivity == SensitivityLevel::Secret && first_secret_path.is_none() {
                first_secret_path = Some(entry.logical_path.clone());
            }

            let kind = match entry.kind {
                ScannedEntryKind::RegularFile { size } => FileNodeKind::RegularFile {
                    size,
                    chunks: Vec::new(),
                    content_hash: ChunkId(String::new()),
                },
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

        let encrypt_secrets_by_default =
            profile.security.encrypt_sensitive_by_default && !request.allow_unencrypted_secrets;
        let needs_passphrase = profile.security.encrypt_full_archive
            || (encrypt_secrets_by_default && first_secret_path.is_some());

        let passphrase = match (&request.passphrase, needs_passphrase) {
            (Some(p), _) if !p.is_empty() => Some(p.clone()),
            (_, true) => {
                let reason = if profile.security.encrypt_full_archive {
                    "Full archive encryption is enabled".to_string()
                } else {
                    format!(
                        "Sensitive file detected ({}) — encrypted by default",
                        first_secret_path.as_deref().unwrap_or(".ssh")
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

        let build_input = ArchiveBuildInput {
            profile: profile.profile.clone(),
            compression_level: profile.profile.compression_level,
            encrypt_full_archive: profile.security.encrypt_full_archive,
            encrypt_secrets_by_default,
            passphrase,
            files: file_nodes,
            registry: registry_tree,
            winget,
            env_vars,
        };

        let manifest =
            self.archive_writer
                .write_archive(&request.output_archive, build_input, progress)?;

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

            let total = matching_nodes.len() as u64;
            for (idx, node) in matching_nodes.into_iter().enumerate() {
                let target_path = self.resolve_restore_target(
                    &node.logical_path,
                    request.target_dir_override.as_deref(),
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

        if request.restore_winget {
            if let Some(winget_manifest) = &manifest.winget {
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
        }

        if request.restore_env_vars {
            if let Some(env_snapshot) = &manifest.env_vars {
                summary.env_vars_restored = self
                    .environment
                    .restore_user_env_vars(env_snapshot, request.dry_run)?;
            }
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
    ) -> PathBuf {
        let Some(override_root) = target_dir_override else {
            return self.tokenizer.detokenize(logical_path);
        };

        // Strip `${TOKEN}/` or drive letter (`C:/`) when extracting into a sandbox target directory
        let sanitized = logical_path
            .replace('\\', "/")
            .replace("${", "")
            .replace('}', "")
            .replace(':', "");
        let rel = sanitized.trim_start_matches('/');
        override_root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))
    }
}
