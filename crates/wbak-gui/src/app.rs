use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use eframe::egui::{self, Color32, RichText, ScrollArea, Ui};

use wbak_app::{
    CreateBackupRequest, ProfileService, RestoreBackupRequest, RestoreSummary, WbakApplication,
};
use wbak_domain::{
    ArchiveManifest, ConflictPolicy, DriftStatus, FileNodeKind, FilterDecision, ProgressEvent,
    ProgressSinkPort, RegistryBrowseItem, RegistryHive, ScannedEntry, SensitivityLevel,
    SystemDriftReport,
};

use crate::viewer_panel::{ContentViewerPanel, ViewerAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    BackupComposer,
    IgnoreRules,
    RegistrySelector,
    RestoreAndDiff,
    ContentViewer,
    EnterpriseProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreSubTab {
    Files,
    Registry,
    Winget,
    SystemDiff,
}

enum WorkerMessage {
    Progress(ProgressEvent),
    PreviewCompleted(Result<Vec<ScannedEntry>, String>),
    BackupCompleted(Result<ArchiveManifest, String>),
    InspectCompleted(Result<ArchiveManifest, String>),
    DiffCompleted(Result<SystemDriftReport, String>),
    RestoreCompleted(Result<RestoreSummary, String>),
    VerifyCompleted(Result<ArchiveManifest, String>),
    FileLoadedIntoMemory(Result<(String, Arc<[u8]>), String>),
    PreloadMemoryCompleted(Result<BTreeMap<String, Arc<[u8]>>, String>),
    #[allow(clippy::type_complexity)]
    ArchiveMutated(Result<(ArchiveManifest, BTreeMap<String, Arc<[u8]>>, String), String>),
    ItemsRemoved(Result<(ArchiveManifest, Vec<String>, String), String>),
    PasswordChanged(Result<(ArchiveManifest, String), String>),
}

struct GuiProgressSink {
    tx: Sender<WorkerMessage>,
}

impl ProgressSinkPort for GuiProgressSink {
    fn on_progress(&self, event: ProgressEvent) {
        let _ = self.tx.send(WorkerMessage::Progress(event));
    }
}

pub struct WbakGuiApp {
    app: WbakApplication,
    active_tab: ActiveTab,

    // Shared profile state being edited
    profile: wbak_domain::ProfileConfig,
    ignore_patterns_text: String,
    use_portable_tokens: bool,
    new_include_path_input: String,
    backup_output_path: String,
    backup_passphrase: String,
    show_passphrase: bool,

    // Ignore live preview state
    preview_entries: Vec<ScannedEntry>,
    preview_show_included: bool,
    preview_show_ignored: bool,
    preview_show_exempted: bool,

    // Registry browser state
    selected_hive: RegistryHive,
    current_reg_subkey: String,
    browsed_subkeys: Vec<RegistryBrowseItem>,
    new_reg_key_input: String,
    new_reg_exclude_input: String,

    // Restore & Inspect state
    restore_archive_path: String,
    restore_passphrase: String,
    new_archive_passphrase: String,
    show_change_password_panel: bool,
    restore_target_override: String,
    restore_files: bool,
    restore_registry: bool,
    restore_winget: bool,
    restore_env_vars: bool,
    restore_dry_run: bool,
    restore_conflict_policy: ConflictPolicy,
    restore_path_filter: String,
    restore_subtab: RestoreSubTab,
    loaded_manifest: Option<ArchiveManifest>,
    loaded_drift: Option<SystemDriftReport>,
    viewer_panel: ContentViewerPanel,

    // Background worker & status bar
    worker_rx: Arc<Mutex<Receiver<WorkerMessage>>>,
    worker_tx: Sender<WorkerMessage>,
    is_busy: bool,
    status_line: String,
    progress_ratio: Option<f32>,
    last_error: Option<String>,
}

impl WbakGuiApp {
    pub fn new(app: WbakApplication) -> Self {
        let (tx, rx) = channel();
        let profile = wbak_domain::ProfileConfig::default();
        let ignore_patterns_text = profile.files.ignore_patterns.join("\n");

        let mut gui = Self {
            app,
            active_tab: ActiveTab::BackupComposer,
            profile,
            ignore_patterns_text,
            use_portable_tokens: true,
            new_include_path_input: String::new(),
            backup_output_path: "workstation-backup.wbak".to_string(),
            backup_passphrase: String::new(),
            show_passphrase: false,
            preview_entries: Vec::new(),
            preview_show_included: true,
            preview_show_ignored: true,
            preview_show_exempted: true,
            selected_hive: RegistryHive::HKCU,
            current_reg_subkey: "Software".to_string(),
            browsed_subkeys: Vec::new(),
            new_reg_key_input: String::new(),
            new_reg_exclude_input: String::new(),
            restore_archive_path: "workstation-backup.wbak".to_string(),
            restore_passphrase: String::new(),
            new_archive_passphrase: String::new(),
            show_change_password_panel: false,
            restore_target_override: String::new(),
            restore_files: true,
            restore_registry: false,
            restore_winget: false,
            restore_env_vars: false,
            restore_dry_run: false,
            restore_conflict_policy: ConflictPolicy::Overwrite,
            restore_path_filter: String::new(),
            restore_subtab: RestoreSubTab::Files,
            loaded_manifest: None,
            loaded_drift: None,
            viewer_panel: ContentViewerPanel::new(),
            worker_rx: Arc::new(Mutex::new(rx)),
            worker_tx: tx,
            is_busy: false,
            status_line: "Ready.".to_string(),
            progress_ratio: None,
            last_error: None,
        };
        gui.refresh_registry_browser();
        gui
    }

    fn sync_ignore_text_to_profile(&mut self) {
        self.profile.files.ignore_patterns = self
            .ignore_patterns_text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
    }

    fn refresh_registry_browser(&mut self) {
        match self
            .app
            .list_registry_subkeys(self.selected_hive, &self.current_reg_subkey)
        {
            Ok(list) => {
                self.browsed_subkeys = list;
            }
            Err(e) => {
                self.browsed_subkeys.clear();
                self.status_line = format!("Registry browse notice: {e}");
            }
        }
    }

    fn poll_worker_messages(&mut self) {
        let Ok(rx) = self.worker_rx.lock() else {
            return;
        };
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMessage::Progress(ev) => {
                    self.status_line = ev.message;
                    self.progress_ratio = ev.total.and_then(|t| {
                        if t > 0 {
                            Some((ev.current as f32 / t as f32).clamp(0.0, 1.0))
                        } else {
                            None
                        }
                    });
                }
                WorkerMessage::PreviewCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(entries) => {
                            self.status_line =
                                format!("Preview completed: {} entries scanned.", entries.len());
                            self.preview_entries = entries;
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::BackupCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(manifest) => {
                            self.status_line = format!(
                                "✔ Backup saved ({} files, {} unique chunks, {} secret 🔒 files).",
                                manifest.stats.total_files,
                                manifest.stats.unique_chunks,
                                manifest.stats.secret_files_count
                            );
                            self.viewer_panel.on_manifest_loaded(&manifest);
                            self.loaded_manifest = Some(manifest);
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::InspectCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(manifest) => {
                            self.status_line = format!(
                                "Loaded archive: {} files, {} registry keys.",
                                manifest.stats.total_files, manifest.stats.registry_keys_count
                            );
                            self.viewer_panel.clear_memory_cache();
                            self.viewer_panel.on_manifest_loaded(&manifest);
                            self.loaded_manifest = Some(manifest);
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::DiffCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(report) => {
                            self.status_line = format!(
                                "System Diff finished: {} file diffs, {} registry diffs, {} missing packages.",
                                report.changed_files_count(),
                                report.changed_registry_count(),
                                report.missing_packages_count()
                            );
                            self.loaded_drift = Some(report);
                            self.restore_subtab = RestoreSubTab::SystemDiff;
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::RestoreCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(summary) => {
                            let mode = if summary.dry_run { "[DRY RUN] " } else { "" };
                            self.status_line = format!(
                                "✔ {mode}Restored {} files ({} .ssh/secret ACLs locked), {} registry values.",
                                summary.files_restored,
                                summary.secret_acls_hardened,
                                summary.registry_values_restored
                            );
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::VerifyCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(m) => {
                            self.status_line = format!(
                                "✔ Archive integrity verified: all {} chunks passed BLAKE3 & AEAD checks!",
                                m.stats.unique_chunks
                            );
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::FileLoadedIntoMemory(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok((logical_path, bytes)) => {
                            self.status_line = format!(
                                "✔ Loaded '{}' ({} B) into memory.",
                                logical_path,
                                bytes.len()
                            );
                            self.viewer_panel.insert_cached_file(logical_path, bytes);
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::PreloadMemoryCompleted(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok(map) => {
                            let count = map.len();
                            for (k, v) in map {
                                self.viewer_panel.insert_cached_file(k, v);
                            }
                            self.status_line =
                                format!("✔ Loaded all {count} archive files into RAM.");
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::ArchiveMutated(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok((manifest, new_mem_files, msg)) => {
                            for (k, v) in new_mem_files {
                                self.viewer_panel.insert_cached_file(k, v);
                            }
                            self.viewer_panel.on_manifest_loaded(&manifest);
                            self.loaded_manifest = Some(manifest);
                            self.status_line = msg;
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::ItemsRemoved(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok((manifest, removed_paths, msg)) => {
                            self.viewer_panel.prune_removed_paths(&removed_paths);
                            self.viewer_panel.on_manifest_loaded(&manifest);
                            self.loaded_manifest = Some(manifest);
                            self.status_line = msg;
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
                WorkerMessage::PasswordChanged(res) => {
                    self.is_busy = false;
                    self.progress_ratio = None;
                    match res {
                        Ok((manifest, new_pass)) => {
                            self.restore_passphrase = new_pass;
                            self.new_archive_passphrase.clear();
                            self.show_change_password_panel = false;
                            self.viewer_panel.on_manifest_loaded(&manifest);
                            self.loaded_manifest = Some(manifest);
                            self.status_line =
                                "✔ Archive password changed successfully.".to_string();
                            self.last_error = None;
                        }
                        Err(e) => {
                            self.last_error = Some(e);
                        }
                    }
                }
            }
        }
    }

    fn execute_viewer_action(&mut self, action: ViewerAction) {
        let Some(manifest) = self.loaded_manifest.clone() else {
            return;
        };
        let archive_path = PathBuf::from(self.restore_archive_path.trim());
        let pass = if self.restore_passphrase.is_empty() {
            None
        } else {
            Some(self.restore_passphrase.clone())
        };
        let app = self.app.clone();
        let tx = self.worker_tx.clone();

        match action {
            ViewerAction::LoadFileIntoMemory { logical_path } => {
                self.is_busy = true;
                self.last_error = None;
                self.status_line = format!("Reading '{logical_path}' into memory...");
                thread::spawn(move || {
                    let res = app
                        .read_archive_file_bytes(
                            &archive_path,
                            &manifest,
                            &logical_path,
                            pass.as_deref(),
                        )
                        .map(|(node, vec)| (node.logical_path, Arc::from(vec)))
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::FileLoadedIntoMemory(res));
                });
            }
            ViewerAction::PreloadAllIntoMemory => {
                self.is_busy = true;
                self.last_error = None;
                self.status_line = "Preloading all archive files into memory...".to_string();
                thread::spawn(move || {
                    let progress = GuiProgressSink { tx: tx.clone() };
                    let res = app
                        .preload_archive_files_in_memory(
                            &archive_path,
                            &manifest,
                            pass.as_deref(),
                            &progress,
                        )
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::PreloadMemoryCompleted(res));
                });
            }
            ViewerAction::CreateDirectory { logical_dir } => {
                self.is_busy = true;
                self.last_error = None;
                self.status_line = format!("Creating folder '{logical_dir}' in archive...");
                thread::spawn(move || {
                    let progress = GuiProgressSink { tx: tx.clone() };
                    let res = app
                        .create_directory_in_archive(
                            &archive_path,
                            &logical_dir,
                            pass.as_deref(),
                            &progress,
                        )
                        .map(|m| {
                            (
                                m,
                                BTreeMap::new(),
                                format!("✔ Created directory '{logical_dir}' in archive."),
                            )
                        })
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::ArchiveMutated(res));
                });
            }
            ViewerAction::InjectDroppedPaths {
                target_logical_dir,
                paths,
                encrypt_added,
            } => {
                self.is_busy = true;
                self.last_error = None;
                let count = paths.len();
                self.status_line = format!(
                    "Adding {count} item(s) into '{}'...",
                    if target_logical_dir.is_empty() {
                        "/"
                    } else {
                        &target_logical_dir
                    }
                );
                thread::spawn(move || {
                    let progress = GuiProgressSink { tx: tx.clone() };
                    let res = app
                        .inject_paths_into_archive(
                            &archive_path,
                            &target_logical_dir,
                            &paths,
                            pass.as_deref(),
                            encrypt_added,
                            &progress,
                        )
                        .map(|(m, mem_files)| {
                            let added_count = mem_files.len();
                            (
                                m,
                                mem_files,
                                format!(
                                    "✔ Added {added_count} file(s) into '{}' (and loaded into RAM).",
                                    if target_logical_dir.is_empty() {
                                        "/"
                                    } else {
                                        &target_logical_dir
                                    }
                                ),
                            )
                        })
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::ArchiveMutated(res));
                });
            }
            ViewerAction::RemoveItems { logical_paths } => {
                self.is_busy = true;
                self.last_error = None;
                self.status_line =
                    format!("Removing {} item(s) from archive...", logical_paths.len());
                let targets_for_worker = logical_paths.clone();
                thread::spawn(move || {
                    let progress = GuiProgressSink { tx: tx.clone() };
                    let res = app
                        .remove_items_from_archive(
                            &archive_path,
                            &targets_for_worker,
                            pass.as_deref(),
                            false,
                            &progress,
                        )
                        .map(|(m, removed_count)| {
                            (
                                m,
                                targets_for_worker,
                                format!("✔ Removed {removed_count} item(s) from archive."),
                            )
                        })
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::ItemsRemoved(res));
                });
            }
        }
    }

    fn trigger_change_password(&mut self) {
        if self.is_busy || self.new_archive_passphrase.is_empty() {
            return;
        }
        self.is_busy = true;
        self.last_error = None;
        self.status_line = "Updating archive encryption passphrase...".to_string();

        let app = self.app.clone();
        let archive_path = PathBuf::from(self.restore_archive_path.trim());
        let old_pass = if self.restore_passphrase.is_empty() {
            None
        } else {
            Some(self.restore_passphrase.clone())
        };
        let new_pass = self.new_archive_passphrase.clone();
        let tx = self.worker_tx.clone();

        thread::spawn(move || {
            let progress = GuiProgressSink { tx: tx.clone() };
            let res = app
                .change_archive_passphrase(&archive_path, old_pass.as_deref(), &new_pass, &progress)
                .map(|m| (m, new_pass))
                .map_err(|e| e.to_string());
            let _ = tx.send(WorkerMessage::PasswordChanged(res));
        });
    }

    fn render_change_password_bar(&mut self, ui: &mut Ui) {
        if !self.show_change_password_panel {
            return;
        }

        egui::Frame::new()
            .fill(Color32::from_rgba_unmultiplied(40, 48, 64, 140))
            .inner_margin(6.0)
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("🔑 Change Archive Password:").strong());
                    ui.label("Current Passphrase:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.restore_passphrase)
                            .password(true)
                            .desired_width(120.0),
                    );
                    ui.label("New Passphrase:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_archive_passphrase)
                            .password(true)
                            .desired_width(140.0),
                    );
                    if ui
                        .add_enabled(
                            !self.is_busy && !self.new_archive_passphrase.is_empty(),
                            egui::Button::new("✔ Apply New Password"),
                        )
                        .clicked()
                    {
                        self.trigger_change_password();
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_change_password_panel = false;
                        self.new_archive_passphrase.clear();
                    }
                });
            });
    }

    fn trigger_preview_scan(&mut self) {
        if self.is_busy {
            return;
        }
        self.sync_ignore_text_to_profile();
        self.is_busy = true;
        self.last_error = None;
        self.status_line = "Scanning paths & evaluating .wbakignore rules...".to_string();

        let app = self.app.clone();
        let include = self.profile.files.include.clone();
        let patterns = self.profile.files.ignore_patterns.clone();
        let ignore_file = self.profile.files.ignore_file.clone();
        let respect_local = self.profile.files.respect_local_ignore_files;
        let tx = self.worker_tx.clone();

        thread::spawn(move || {
            let res = app
                .preview_scan(&include, &patterns, ignore_file.as_deref(), respect_local)
                .map_err(|e| e.to_string());
            let _ = tx.send(WorkerMessage::PreviewCompleted(res));
        });
    }

    fn trigger_backup(&mut self) {
        if self.is_busy {
            return;
        }
        self.sync_ignore_text_to_profile();
        self.is_busy = true;
        self.last_error = None;
        self.status_line = "Starting backup...".to_string();

        let app = self.app.clone();
        let profile = self.profile.clone();
        let output_archive = PathBuf::from(self.backup_output_path.trim());
        let passphrase = if self.backup_passphrase.is_empty() {
            None
        } else {
            Some(self.backup_passphrase.clone())
        };
        let tx = self.worker_tx.clone();

        thread::spawn(move || {
            let progress = GuiProgressSink { tx: tx.clone() };
            let res = app
                .create_backup(
                    CreateBackupRequest {
                        profile,
                        output_archive,
                        passphrase,
                        allow_unencrypted_secrets: false,
                        force_full_rebuild: false,
                        keep_deleted: false,
                        compact_after_update: false,
                    },
                    &progress,
                    None,
                )
                .map_err(|e| e.to_string());
            let _ = tx.send(WorkerMessage::BackupCompleted(res));
        });
    }

    fn render_backup_composer(&mut self, ui: &mut Ui) {
        ui.heading("Create Backup & Select Sources");
        ui.add_space(4.0);

        egui::Grid::new("profile_meta_grid")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Profile Name:");
                ui.text_edit_singleline(&mut self.profile.profile.name);
                ui.end_row();

                ui.label("Description:");
                ui.text_edit_singleline(&mut self.profile.profile.description);
                ui.end_row();

                ui.label("Zstd Compression Level:");
                ui.add(egui::Slider::new(
                    &mut self.profile.profile.compression_level,
                    1..=19,
                ));
                ui.end_row();
            });

        ui.separator();
        ui.label(RichText::new("Quick-Add Common Windows & Developer Paths:").strong());
        ui.horizontal_wrapped(|ui| {
            for (label, token_path) in [
                ("🔒 .ssh Keys", "${USERPROFILE}/.ssh"),
                ("VS Code Settings", "${APPDATA}/Code/User"),
                (".gitconfig", "${USERPROFILE}/.gitconfig"),
                ("Cargo Config", "${USERPROFILE}/.cargo/config.toml"),
                ("Documents", "${USERPROFILE}/Documents"),
            ] {
                if ui.button(format!("+ {label}")).clicked()
                    && !self.profile.files.include.contains(&token_path.to_string())
                {
                    self.profile.files.include.push(token_path.to_string());
                }
            }
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.use_portable_tokens,
                "Tokenize paths (${USERPROFILE}, ${APPDATA}) for reproducible restores",
            );
            if ui.button("📁 Add Folder...").clicked()
                && let Some(folder) = rfd::FileDialog::new().pick_folder()
            {
                let entry = if self.use_portable_tokens {
                    self.app.tokenizer().tokenize(&folder)
                } else {
                    folder.to_string_lossy().to_string()
                };
                if !self.profile.files.include.contains(&entry) {
                    self.profile.files.include.push(entry);
                }
            }
            if ui.button("📄 Add File...").clicked()
                && let Some(file) = rfd::FileDialog::new().pick_file()
            {
                let entry = if self.use_portable_tokens {
                    self.app.tokenizer().tokenize(&file)
                } else {
                    file.to_string_lossy().to_string()
                };
                if !self.profile.files.include.contains(&entry) {
                    self.profile.files.include.push(entry);
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label("Custom Path:");
            ui.text_edit_singleline(&mut self.new_include_path_input);
            if ui.button("Add").clicked() && !self.new_include_path_input.trim().is_empty() {
                self.profile
                    .files
                    .include
                    .push(self.new_include_path_input.trim().to_string());
                self.new_include_path_input.clear();
            }
        });

        ui.add_space(6.0);
        ui.label(
            RichText::new(format!(
                "Included Backup Paths ({}):",
                self.profile.files.include.len()
            ))
            .strong(),
        );

        let mut remove_idx = None;
        ScrollArea::vertical()
            .id_salt("included_paths_scroll")
            .max_height(150.0)
            .show(ui, |ui| {
                for (i, path) in self.profile.files.include.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("✖").clicked() {
                            remove_idx = Some(i);
                        }
                        let is_secret = wbak_domain::classify_builtin_sensitivity(path)
                            == SensitivityLevel::Secret;
                        if is_secret {
                            ui.colored_label(
                                Color32::from_rgb(245, 194, 66),
                                "[SECRET 🔒 Encrypted by Default]",
                            );
                        }
                        ui.monospace(path);
                    });
                }
            });
        if let Some(idx) = remove_idx {
            self.profile.files.include.remove(idx);
        }

        ui.separator();
        ui.label(RichText::new("Enterprise Reproducibility & Security:").strong());
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut self.profile.environment.capture_winget,
                "Capture installed winget packages",
            );
            ui.checkbox(
                &mut self.profile.environment.capture_env_vars,
                "Capture User/System Environment Variables",
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut self.profile.security.encrypt_sensitive_by_default,
                "🔒 Encrypt .ssh keys & sensitive files by default",
            );
            ui.checkbox(
                &mut self.profile.security.encrypt_full_archive,
                "🔐 Encrypt entire archive (all files, registry & manifest)",
            );
        });

        ui.horizontal(|ui| {
            ui.label("Encryption Passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut self.backup_passphrase)
                    .password(!self.show_passphrase)
                    .hint_text("Required when backing up .ssh keys or full encryption"),
            );
            ui.checkbox(&mut self.show_passphrase, "Show");
        });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Output Archive (.wbak):");
            ui.text_edit_singleline(&mut self.backup_output_path);
            if ui.button("Browse...").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("wbak Archive", &["wbak"])
                    .set_file_name("workstation-backup.wbak")
                    .save_file()
            {
                self.backup_output_path = path.to_string_lossy().to_string();
            }
            let btn = egui::Button::new(RichText::new("▶ Run Backup Now").strong())
                .fill(Color32::from_rgb(35, 134, 54));
            if ui.add_enabled(!self.is_busy, btn).clicked() {
                self.trigger_backup();
            }
        });
    }

    fn render_ignore_rules(&mut self, ui: &mut Ui) {
        ui.heading("Ignore Rules (.wbakignore) & '!' Exemption Tester");
        ui.label("Supports standard .gitignore patterns. Prefix a pattern with '!' to exempt matching files from earlier exclusions.");

        ui.horizontal_wrapped(|ui| {
            ui.label("Quick Insert:");
            for snippet in [
                "/node_modules/",
                "/target/",
                "/.git/objects/",
                "*.tmp",
                "*.log",
                "!/target/release/keep.exe",
                "!important.log",
            ] {
                if ui.small_button(format!("+ {snippet}")).clicked() {
                    if !self.ignore_patterns_text.ends_with('\n')
                        && !self.ignore_patterns_text.is_empty()
                    {
                        self.ignore_patterns_text.push('\n');
                    }
                    self.ignore_patterns_text.push_str(snippet);
                }
            }
        });

        ui.add_space(6.0);
        ui.columns(2, |cols| {
            cols[0].label(RichText::new("Ignore & Exemption Patterns:").strong());
            cols[0].add(
                egui::TextEdit::multiline(&mut self.ignore_patterns_text)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(18)
                    .desired_width(f32::INFINITY),
            );
            cols[0].checkbox(
                &mut self.profile.files.respect_local_ignore_files,
                "Also respect local .wbakignore files inside traversed directories",
            );

            cols[1].horizontal(|ui| {
                ui.label(RichText::new("Live Scan Preview:").strong());
                if ui
                    .add_enabled(!self.is_busy, egui::Button::new("🔄 Run Live Preview"))
                    .clicked()
                {
                    self.trigger_preview_scan();
                }
            });
            cols[1].horizontal(|ui| {
                ui.checkbox(&mut self.preview_show_included, "Included");
                ui.checkbox(&mut self.preview_show_exempted, "Exempted (!)");
                ui.checkbox(&mut self.preview_show_ignored, "Ignored");
            });

            ScrollArea::vertical()
                .id_salt("ignore_preview_scroll")
                .max_height(320.0)
                .show(&mut cols[1], |ui| {
                    if self.preview_entries.is_empty() {
                        ui.weak("Click '🔄 Run Live Preview' to evaluate your .wbakignore rules against the selected backup paths.");
                    }
                    for entry in &self.preview_entries {
                        match &entry.filter_decision {
                            FilterDecision::Included if self.preview_show_included => {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        Color32::from_rgb(75, 210, 110),
                                        "[INCLUDED]",
                                    );
                                    if entry.sensitivity == SensitivityLevel::Secret {
                                        ui.colored_label(
                                            Color32::from_rgb(245, 194, 66),
                                            "[SECRET 🔒]",
                                        );
                                    }
                                    ui.monospace(&entry.logical_path);
                                });
                            }
                            FilterDecision::Exempted { matched_pattern }
                                if self.preview_show_exempted =>
                            {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        Color32::from_rgb(80, 200, 255),
                                        format!("[EXEMPT! by {matched_pattern}]"),
                                    );
                                    ui.monospace(&entry.logical_path);
                                });
                            }
                            FilterDecision::Ignored { matched_pattern }
                                if self.preview_show_ignored =>
                            {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        Color32::from_rgb(210, 85, 85),
                                        format!("[IGNORED by {matched_pattern}]"),
                                    );
                                    ui.weak(&entry.logical_path);
                                });
                            }
                            _ => {}
                        }
                    }
                });
        });
    }

    fn render_registry_selector(&mut self, ui: &mut Ui) {
        ui.heading("Windows Registry Settings Backup");
        ui.label("Select Registry keys to capture into the archive. During restore, wbak automatically saves a .reg rollback file first.");

        ui.horizontal(|ui| {
            ui.label("Add Registry Key Path:");
            ui.text_edit_singleline(&mut self.new_reg_key_input);
            if ui.button("+ Add Key").clicked() && !self.new_reg_key_input.trim().is_empty() {
                let k = self.new_reg_key_input.trim().to_string();
                if !self.profile.registry.include_keys.contains(&k) {
                    self.profile.registry.include_keys.push(k);
                }
                self.new_reg_key_input.clear();
            }
        });

        ui.columns(2, |cols| {
            cols[0].label(
                RichText::new(format!(
                    "Selected Registry Keys ({}):",
                    self.profile.registry.include_keys.len()
                ))
                .strong(),
            );
            let mut remove_idx = None;
            ScrollArea::vertical()
                .id_salt("selected_reg_keys_scroll")
                .max_height(140.0)
                .show(&mut cols[0], |ui| {
                    for (idx, k) in self.profile.registry.include_keys.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.small_button("✖").clicked() {
                                remove_idx = Some(idx);
                            }
                            ui.monospace(k);
                        });
                    }
                });
            if let Some(i) = remove_idx {
                self.profile.registry.include_keys.remove(i);
            }

            cols[0].separator();
            cols[0].label(RichText::new("Registry Exclude Glob Patterns:").strong());
            cols[0].horizontal(|ui| {
                ui.text_edit_singleline(&mut self.new_reg_exclude_input);
                if ui.button("+ Exclude").clicked() && !self.new_reg_exclude_input.trim().is_empty()
                {
                    self.profile
                        .registry
                        .exclude_patterns
                        .push(self.new_reg_exclude_input.trim().to_string());
                    self.new_reg_exclude_input.clear();
                }
            });
            let mut rem_ex = None;
            for (idx, pat) in self.profile.registry.exclude_patterns.iter().enumerate() {
                cols[0].horizontal(|ui| {
                    if ui.small_button("✖").clicked() {
                        rem_ex = Some(idx);
                    }
                    ui.monospace(pat);
                });
            }
            if let Some(i) = rem_ex {
                self.profile.registry.exclude_patterns.remove(i);
            }

            // Right column: Interactive Live Windows Registry Browser
            cols[1].label(RichText::new("Live Windows Registry Explorer:").strong());
            let mut should_refresh = false;
            cols[1].horizontal(|ui| {
                for hive in [
                    RegistryHive::HKCU,
                    RegistryHive::HKLM,
                    RegistryHive::HKCR,
                    RegistryHive::HKU,
                ] {
                    if ui
                        .selectable_value(&mut self.selected_hive, hive, hive.short_name())
                        .clicked()
                    {
                        self.current_reg_subkey.clear();
                        should_refresh = true;
                    }
                }
                if ui.button("⬆ Up").clicked() {
                    if let Some((parent, _)) = self.current_reg_subkey.rsplit_once('\\') {
                        self.current_reg_subkey = parent.to_string();
                    } else {
                        self.current_reg_subkey.clear();
                    }
                    should_refresh = true;
                }
            });

            cols[1].horizontal(|ui| {
                ui.label("Subkey:");
                if ui
                    .text_edit_singleline(&mut self.current_reg_subkey)
                    .lost_focus()
                {
                    should_refresh = true;
                }
                if ui.button("Browse").clicked() {
                    should_refresh = true;
                }
            });

            let mut navigate_to: Option<String> = None;
            ScrollArea::vertical()
                .id_salt("live_reg_browser_scroll")
                .max_height(240.0)
                .show(&mut cols[1], |ui| {
                    for item in &self.browsed_subkeys {
                        ui.horizontal(|ui| {
                            if ui.small_button("+ Include").clicked()
                                && !self.profile.registry.include_keys.contains(&item.full_path)
                            {
                                self.profile
                                    .registry
                                    .include_keys
                                    .push(item.full_path.clone());
                            }
                            let label =
                                format!("📁 {} ({} values)", item.full_path, item.value_count);
                            if ui.selectable_label(false, label).clicked() && item.has_subkeys {
                                navigate_to = Some(item.subkey_path.clone());
                            }
                        });
                    }
                });

            if let Some(sub) = navigate_to {
                self.current_reg_subkey = sub;
                should_refresh = true;
            }
            if should_refresh {
                self.refresh_registry_browser();
            }
        });
    }

    fn render_restore_and_diff(&mut self, ui: &mut Ui) {
        ui.heading("Inspect Archive, Compare System Drift & Restore");

        ui.horizontal(|ui| {
            ui.label("Archive (.wbak):");
            ui.text_edit_singleline(&mut self.restore_archive_path);
            if ui.button("Browse...").clicked()
                && let Some(file) = rfd::FileDialog::new()
                    .add_filter("wbak Archive", &["wbak"])
                    .pick_file()
            {
                self.restore_archive_path = file.to_string_lossy().to_string();
            }
            ui.label("Passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut self.restore_passphrase)
                    .password(true)
                    .desired_width(140.0),
            );
            if ui
                .selectable_label(self.show_change_password_panel, "🔑 Change Password...")
                .clicked()
            {
                self.show_change_password_panel = !self.show_change_password_panel;
            }
        });

        self.render_change_password_bar(ui);

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.is_busy, egui::Button::new("📦 Load & Inspect"))
                .clicked()
            {
                self.is_busy = true;
                let app = self.app.clone();
                let path = PathBuf::from(self.restore_archive_path.trim());
                let pass = if self.restore_passphrase.is_empty() {
                    None
                } else {
                    Some(self.restore_passphrase.clone())
                };
                let tx = self.worker_tx.clone();
                thread::spawn(move || {
                    let res = app
                        .inspect_archive(&path, pass.as_deref())
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::InspectCompleted(res));
                });
            }

            if ui
                .add_enabled(
                    !self.is_busy,
                    egui::Button::new("🔍 Compare Live System (Diff)"),
                )
                .clicked()
            {
                self.is_busy = true;
                let app = self.app.clone();
                let path = PathBuf::from(self.restore_archive_path.trim());
                let pass = if self.restore_passphrase.is_empty() {
                    None
                } else {
                    Some(self.restore_passphrase.clone())
                };
                let tx = self.worker_tx.clone();
                thread::spawn(move || {
                    let res = app
                        .diff_system(&path, pass.as_deref())
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::DiffCompleted(res));
                });
            }

            if ui
                .add_enabled(
                    !self.is_busy,
                    egui::Button::new("🛡 Verify BLAKE3 & AEAD Integrity"),
                )
                .clicked()
            {
                self.is_busy = true;
                let app = self.app.clone();
                let path = PathBuf::from(self.restore_archive_path.trim());
                let pass = if self.restore_passphrase.is_empty() {
                    None
                } else {
                    Some(self.restore_passphrase.clone())
                };
                let tx = self.worker_tx.clone();
                thread::spawn(move || {
                    let progress = GuiProgressSink { tx: tx.clone() };
                    let res = app
                        .verify_archive(&path, pass.as_deref(), &progress)
                        .map_err(|e| e.to_string());
                    let _ = tx.send(WorkerMessage::VerifyCompleted(res));
                });
            }
        });

        ui.separator();

        if let Some(m) = &self.loaded_manifest {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "Profile: {} | Host: {} (User: {}) | Files: {} ({} secret 🔒) | Chunks: {} | Logical: {} B -> Stored: {} B",
                        m.profile.name,
                        m.source_hostname,
                        m.source_username,
                        m.stats.total_files,
                        m.stats.secret_files_count,
                        m.stats.unique_chunks,
                        m.stats.total_logical_bytes,
                        m.stats.compressed_stored_bytes,
                    ))
                    .strong(),
                );
            });

            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.restore_subtab,
                    RestoreSubTab::Files,
                    format!("📄 Files ({})", m.files.len()),
                );
                ui.selectable_value(
                    &mut self.restore_subtab,
                    RestoreSubTab::Registry,
                    format!("🗂 Registry ({} keys)", m.registry.keys.len()),
                );
                ui.selectable_value(
                    &mut self.restore_subtab,
                    RestoreSubTab::Winget,
                    format!(
                        "📦 Winget ({})",
                        m.winget.as_ref().map(|w| w.packages.len()).unwrap_or(0)
                    ),
                );
                ui.selectable_value(
                    &mut self.restore_subtab,
                    RestoreSubTab::SystemDiff,
                    "🔍 System Drift Report",
                );
            });

            let mut jump_to_view_file: Option<String> = None;
            let mut remove_file_path: Option<String> = None;
            ScrollArea::vertical()
                .id_salt("restore_inspector_scroll")
                .max_height(190.0)
                .show(ui, |ui| match self.restore_subtab {
                    RestoreSubTab::Files => {
                        for f in &m.files {
                            if !self.restore_path_filter.is_empty()
                                && !f
                                    .logical_path
                                    .to_ascii_lowercase()
                                    .contains(&self.restore_path_filter.to_ascii_lowercase())
                            {
                                continue;
                            }
                            ui.horizontal(|ui| {
                                if matches!(f.kind, FileNodeKind::RegularFile { .. })
                                    && ui
                                        .small_button("👁 View")
                                        .on_hover_text("Open file in memory in the Content & Media Viewer")
                                        .clicked()
                                {
                                    jump_to_view_file = Some(f.logical_path.clone());
                                }
                                if ui
                                    .add_enabled(!self.is_busy, egui::Button::new("🗑 Remove").small())
                                    .on_hover_text("Remove this item from the archive")
                                    .clicked()
                                {
                                    remove_file_path = Some(f.logical_path.clone());
                                }
                                if f.is_secret() {
                                    ui.colored_label(
                                        Color32::from_rgb(245, 194, 66),
                                        "[SECRET 🔒]",
                                    );
                                }
                                ui.monospace(&f.logical_path);
                                ui.weak(format!("({} B)", f.size()));
                            });
                        }
                    }
                    RestoreSubTab::Registry => {
                        for (path, node) in &m.registry.keys {
                            ui.collapsing(
                                format!("{path} ({} values)", node.values.len()),
                                |ui| {
                                    for val in node.values.values() {
                                        let name = if val.name.is_empty() {
                                            "(Default)"
                                        } else {
                                            &val.name
                                        };
                                        ui.monospace(format!(
                                            "{name} [{}] = {}",
                                            val.data.type_name(),
                                            val.data.display_summary()
                                        ));
                                    }
                                },
                            );
                        }
                    }
                    RestoreSubTab::Winget => {
                        if let Some(wg) = &m.winget {
                            for pkg in &wg.packages {
                                ui.monospace(format!(
                                    "{} (version: {}, source: {})",
                                    pkg.id,
                                    pkg.version.as_deref().unwrap_or("latest"),
                                    pkg.source
                                ));
                            }
                        } else {
                            ui.weak("No winget manifest captured in this archive.");
                        }
                    }
                    RestoreSubTab::SystemDiff => {
                        if let Some(drift) = &self.loaded_drift {
                            for f in &drift.files {
                                if f.status != DriftStatus::Identical {
                                    ui.colored_label(
                                        Color32::from_rgb(240, 150, 90),
                                        format!(
                                            "[FILE {:?}] {} -> {} ({})",
                                            f.status, f.logical_path, f.target_path, f.detail
                                        ),
                                    );
                                }
                            }
                            for r in &drift.registry {
                                if r.status != DriftStatus::Identical {
                                    ui.colored_label(
                                        Color32::from_rgb(210, 130, 240),
                                        format!(
                                            "[REG {:?}] {}\\{} (archive={:?}, live={:?})",
                                            r.status,
                                            r.key_path,
                                            r.value_name.as_deref().unwrap_or("(Key)"),
                                            r.archive_value,
                                            r.system_value
                                        ),
                                    );
                                }
                            }
                            for p in &drift.packages {
                                if p.status == DriftStatus::MissingOnSystem {
                                    ui.colored_label(
                                        Color32::from_rgb(100, 200, 245),
                                        format!(
                                            "[WINGET MISSING] {} ({:?})",
                                            p.package_id, p.archive_version
                                        ),
                                    );
                                }
                            }
                            if drift.is_clean() {
                                ui.colored_label(
                                    Color32::from_rgb(75, 210, 110),
                                    "✔ Live machine matches archive with zero drift!",
                                );
                            }
                        } else {
                            ui.weak("Click '🔍 Compare Live System (Diff)' above to analyze system drift.");
                        }
                    }
                });

            if let Some(logical_path) = jump_to_view_file {
                self.active_tab = ActiveTab::ContentViewer;
                if let Some(act) = self.viewer_panel.select_and_view(logical_path) {
                    self.execute_viewer_action(act);
                }
            } else if let Some(logical_path) = remove_file_path {
                self.execute_viewer_action(ViewerAction::RemoveItems {
                    logical_paths: vec![logical_path],
                });
            }
        }

        ui.separator();
        ui.label(RichText::new("Restore Options:").strong());
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.restore_files, "Restore Files");
            ui.checkbox(
                &mut self.restore_registry,
                "Restore Registry (auto-creates .reg rollback)",
            );
            ui.checkbox(&mut self.restore_winget, "Reinstall winget Packages");
            ui.checkbox(&mut self.restore_env_vars, "Restore User Env Vars");
            ui.checkbox(&mut self.restore_dry_run, "Dry Run (Simulate Only)");
        });

        ui.horizontal(|ui| {
            ui.label("Conflict Policy:");
            ui.selectable_value(
                &mut self.restore_conflict_policy,
                ConflictPolicy::Overwrite,
                "Overwrite",
            );
            ui.selectable_value(
                &mut self.restore_conflict_policy,
                ConflictPolicy::SkipExisting,
                "Skip Existing",
            );
            ui.selectable_value(
                &mut self.restore_conflict_policy,
                ConflictPolicy::BackupExisting,
                "Backup (.wbak.bak)",
            );
        });

        ui.horizontal(|ui| {
            ui.label("Filter Path Substring:");
            ui.text_edit_singleline(&mut self.restore_path_filter);
            ui.label("Sandbox Target Dir (optional):");
            ui.text_edit_singleline(&mut self.restore_target_override);
            if ui.button("📁").clicked()
                && let Some(dir) = rfd::FileDialog::new().pick_folder()
            {
                self.restore_target_override = dir.to_string_lossy().to_string();
            }
        });

        let restore_btn = egui::Button::new(RichText::new("♻ Execute Restore").strong())
            .fill(Color32::from_rgb(40, 110, 195));
        if ui.add_enabled(!self.is_busy, restore_btn).clicked() {
            self.is_busy = true;
            self.last_error = None;
            let app = self.app.clone();
            let req = RestoreBackupRequest {
                archive_path: PathBuf::from(self.restore_archive_path.trim()),
                passphrase: if self.restore_passphrase.is_empty() {
                    None
                } else {
                    Some(self.restore_passphrase.clone())
                },
                target_dir_override: if self.restore_target_override.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.restore_target_override.trim()))
                },
                restore_files: self.restore_files,
                restore_registry: self.restore_registry,
                restore_winget: self.restore_winget,
                restore_env_vars: self.restore_env_vars,
                dry_run: self.restore_dry_run,
                conflict_policy: self.restore_conflict_policy,
                path_filter: if self.restore_path_filter.trim().is_empty() {
                    None
                } else {
                    Some(self.restore_path_filter.trim().to_string())
                },
            };
            let tx = self.worker_tx.clone();
            thread::spawn(move || {
                let progress = GuiProgressSink { tx: tx.clone() };
                let res = app
                    .restore_backup(req, &progress, None)
                    .map_err(|e| e.to_string());
                let _ = tx.send(WorkerMessage::RestoreCompleted(res));
            });
        }
    }

    fn render_content_viewer(&mut self, ctx: &egui::Context, ui: &mut Ui) {
        if !self.viewer_panel.is_video_mode_active() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Archive (.wbak):").strong());
                ui.text_edit_singleline(&mut self.restore_archive_path);
                if ui.button("Browse...").clicked()
                    && let Some(file) = rfd::FileDialog::new()
                        .add_filter("wbak Archive", &["wbak", "bak"])
                        .pick_file()
                {
                    self.restore_archive_path = file.to_string_lossy().to_string();
                }
                ui.label("Passphrase:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.restore_passphrase)
                        .password(true)
                        .desired_width(130.0),
                );
                if ui
                    .add_enabled(!self.is_busy, egui::Button::new("📦 Load Archive"))
                    .clicked()
                {
                    self.is_busy = true;
                    self.last_error = None;
                    let app = self.app.clone();
                    let path = PathBuf::from(self.restore_archive_path.trim());
                    let pass = if self.restore_passphrase.is_empty() {
                        None
                    } else {
                        Some(self.restore_passphrase.clone())
                    };
                    let tx = self.worker_tx.clone();
                    thread::spawn(move || {
                        let res = app
                            .inspect_archive(&path, pass.as_deref())
                            .map_err(|e| e.to_string());
                        let _ = tx.send(WorkerMessage::InspectCompleted(res));
                    });
                }
                if ui
                    .selectable_label(self.show_change_password_panel, "🔑 Change Password...")
                    .clicked()
                {
                    self.show_change_password_panel = !self.show_change_password_panel;
                }
            });

            self.render_change_password_bar(ui);
            ui.separator();
        }

        let action = self
            .viewer_panel
            .render(ctx, ui, self.loaded_manifest.as_ref(), self.is_busy);
        if let Some(act) = action {
            self.execute_viewer_action(act);
        }
    }

    fn render_enterprise_profile(&mut self, ui: &mut Ui) {
        ui.heading("Enterprise Reproducible Profile (wbak.toml)");
        ui.label("Save or load declarative TOML profiles for repeatable team workstation setup.");

        ui.horizontal(|ui| {
            if ui.button("📂 Load Profile (wbak.toml)...").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("TOML Profile", &["toml"])
                    .pick_file()
            {
                match ProfileService::load_from_file(&path) {
                    Ok(cfg) => {
                        self.ignore_patterns_text = cfg.files.ignore_patterns.join("\n");
                        self.profile = cfg;
                        self.status_line = format!("Loaded profile from {}", path.display());
                    }
                    Err(e) => self.last_error = Some(e.to_string()),
                }
            }

            if ui.button("💾 Save Profile (wbak.toml)...").clicked() {
                self.sync_ignore_text_to_profile();
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("TOML Profile", &["toml"])
                    .set_file_name("wbak.toml")
                    .save_file()
                {
                    match ProfileService::save_to_file(&self.profile, &path) {
                        Ok(()) => {
                            self.status_line = format!("Saved profile to {}", path.display());
                        }
                        Err(e) => self.last_error = Some(e.to_string()),
                    }
                }
            }
        });

        ui.separator();
        self.sync_ignore_text_to_profile();
        let toml_preview = toml::to_string_pretty(&self.profile).unwrap_or_else(|e| e.to_string());
        ScrollArea::vertical()
            .id_salt("toml_preview_scroll")
            .max_height(340.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut toml_preview.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
    }
}

impl eframe::App for WbakGuiApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_worker_messages();
        if self.is_busy {
            ctx.request_repaint();
        }

        let fullscreen_video =
            self.active_tab == ActiveTab::ContentViewer && self.viewer_panel.is_video_mode_active();

        if !fullscreen_video {
            egui::Panel::top("top_nav_bar").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("🛡 wbak").strong());
                    ui.separator();
                    ui.selectable_value(
                        &mut self.active_tab,
                        ActiveTab::BackupComposer,
                        "📦 Backup Composer",
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        ActiveTab::IgnoreRules,
                        "🚫 Ignore Rules (.wbakignore)",
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        ActiveTab::RegistrySelector,
                        "🗂 Windows Registry",
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        ActiveTab::RestoreAndDiff,
                        "♻ Restore & System Diff",
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        ActiveTab::ContentViewer,
                        "👁 Content & Media Viewer",
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        ActiveTab::EnterpriseProfile,
                        "🏢 Enterprise Profile (TOML)",
                    );
                });
            });
        }

        if !fullscreen_video || self.last_error.is_some() {
            egui::Panel::bottom("bottom_status_bar").show(ui, |ui| {
                if let Some(err) = &self.last_error {
                    ui.colored_label(Color32::from_rgb(245, 95, 95), format!("⚠ Error: {err}"));
                }
                ui.horizontal(|ui| {
                    if let Some(ratio) = self.progress_ratio {
                        ui.add(
                            egui::ProgressBar::new(ratio)
                                .desired_width(180.0)
                                .show_percentage(),
                        );
                    }
                    ui.label(&self.status_line);
                });
            });
        }

        egui::CentralPanel::default().show(ui, |ui| match self.active_tab {
            ActiveTab::BackupComposer => self.render_backup_composer(ui),
            ActiveTab::IgnoreRules => self.render_ignore_rules(ui),
            ActiveTab::RegistrySelector => self.render_registry_selector(ui),
            ActiveTab::RestoreAndDiff => self.render_restore_and_diff(ui),
            ActiveTab::ContentViewer => self.render_content_viewer(&ctx, ui),
            ActiveTab::EnterpriseProfile => self.render_enterprise_profile(ui),
        });
    }
}
