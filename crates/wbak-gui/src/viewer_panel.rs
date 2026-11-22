use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Color32, ColorImage, Pos2, Rect, RichText, ScrollArea, Sense, Stroke, TextureHandle,
    TextureOptions, Ui, Vec2,
};

use wbak_app::compute_common_parent_prefix;
use wbak_domain::{ArchiveManifest, FileNode, FileNodeKind, SensitivityLevel};

use crate::viewer::{
    AudioSession, DecodedImageAsset, MediaBackendRegistry, MediaKind, VideoSession,
    classify_media_kind, decode_text_preview,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorOverrideMode {
    Auto,
    Text,
    Hex,
}

enum LoadedViewerAsset {
    Text(String),
    Binary,
    Image {
        asset: DecodedImageAsset,
        textures: Vec<TextureHandle>,
        current_frame: usize,
        last_frame_switch: Instant,
    },
    Audio {
        session: Box<dyn AudioSession>,
    },
    Video {
        session: Box<dyn VideoSession>,
        texture: Option<TextureHandle>,
    },
    UnsupportedMedia {
        error: String,
    },
}

pub enum ViewerAction {
    LoadFileIntoMemory {
        logical_path: String,
    },
    PreloadAllIntoMemory,
    CreateDirectory {
        logical_dir: String,
    },
    InjectDroppedPaths {
        target_logical_dir: String,
        paths: Vec<std::path::PathBuf>,
        encrypt_added: bool,
    },
    RemoveItems {
        logical_paths: Vec<String>,
    },
}

pub struct ContentViewerPanel {
    backends: MediaBackendRegistry,
    pub memory_cache: BTreeMap<String, Arc<[u8]>>,
    pub current_dir: String,
    pub selected_file: Option<String>,
    pub path_filter: String,
    pub new_subfolder_name: String,
    pub encrypt_dropped_files: bool,

    // Active viewer state for `selected_file`
    active_asset_path: Option<String>,
    active_media_kind: MediaKind,
    override_mode: InspectorOverrideMode,
    loaded_asset: Option<LoadedViewerAsset>,
    video_fullscreen: bool,

    // Text viewer options
    text_search_query: String,
    text_show_line_numbers: bool,
    text_word_wrap: bool,

    // Image/Video display options
    fit_to_window: bool,
    zoom_factor: f32,
}

impl ContentViewerPanel {
    pub fn new() -> Self {
        Self {
            backends: MediaBackendRegistry::default_for_platform(),
            memory_cache: BTreeMap::new(),
            current_dir: String::new(),
            selected_file: None,
            path_filter: String::new(),
            new_subfolder_name: String::new(),
            encrypt_dropped_files: false,
            active_asset_path: None,
            active_media_kind: MediaKind::Binary,
            override_mode: InspectorOverrideMode::Auto,
            loaded_asset: None,
            video_fullscreen: false,
            text_search_query: String::new(),
            text_show_line_numbers: true,
            text_word_wrap: false,
            fit_to_window: true,
            zoom_factor: 1.0,
        }
    }

    pub fn on_manifest_loaded(&mut self, manifest: &ArchiveManifest) {
        if self.current_dir.is_empty()
            && let Some(common) = compute_common_parent_prefix(&manifest.files)
        {
            self.current_dir = common;
        }
        if manifest.full_archive_encrypted || manifest.has_encrypted_secrets {
            self.encrypt_dropped_files = true;
        }
    }

    pub fn clear_memory_cache(&mut self) {
        self.memory_cache.clear();
        self.loaded_asset = None;
        self.active_asset_path = None;
        self.video_fullscreen = false;
    }

    pub fn total_cached_bytes(&self) -> usize {
        self.memory_cache.values().map(|b| b.len()).sum()
    }

    pub fn insert_cached_file(&mut self, logical_path: String, bytes: Arc<[u8]>) {
        self.memory_cache.insert(logical_path.clone(), bytes);
        if self.selected_file.as_deref() == Some(logical_path.as_str()) {
            self.active_asset_path = None;
            self.loaded_asset = None;
        }
    }

    pub fn select_and_view(&mut self, logical_path: String) -> Option<ViewerAction> {
        if let Some(parent) = logical_path.rsplit_once('/').map(|(p, _)| p.to_string()) {
            self.current_dir = parent;
        }
        self.selected_file = Some(logical_path.clone());
        self.active_asset_path = None;
        self.loaded_asset = None;
        self.override_mode = InspectorOverrideMode::Auto;
        self.video_fullscreen = false;

        if self.memory_cache.contains_key(&logical_path) {
            None
        } else {
            Some(ViewerAction::LoadFileIntoMemory { logical_path })
        }
    }

    pub fn is_video_mode_active(&self) -> bool {
        if !self.video_fullscreen || self.override_mode != InspectorOverrideMode::Auto {
            return false;
        }
        let Some(ref selected) = self.selected_file else {
            return false;
        };
        let bytes = self
            .memory_cache
            .get(selected)
            .map(|b| b.as_ref())
            .unwrap_or(&[]);
        classify_media_kind(selected, bytes) == MediaKind::Video
    }

    pub fn exit_selected_file(&mut self) {
        self.selected_file = None;
        self.active_asset_path = None;
        self.loaded_asset = None;
        self.override_mode = InspectorOverrideMode::Auto;
        self.video_fullscreen = false;
    }

    pub fn prune_removed_paths(&mut self, removed_targets: &[String]) {
        self.memory_cache
            .retain(|k, _| !matches_removed_target(k, removed_targets));

        if let Some(ref sel) = self.selected_file
            && matches_removed_target(sel, removed_targets)
        {
            self.exit_selected_file();
        }

        while !self.current_dir.is_empty()
            && matches_removed_target(&self.current_dir, removed_targets)
        {
            if let Some((parent, _)) = self.current_dir.rsplit_once('/') {
                self.current_dir = parent.to_string();
            } else {
                self.current_dir.clear();
            }
        }
    }

    fn prepare_active_asset(&mut self, ctx: &egui::Context, logical_path: &str, bytes: &Arc<[u8]>) {
        if self.active_asset_path.as_deref() == Some(logical_path) && self.loaded_asset.is_some() {
            return;
        }

        self.active_asset_path = Some(logical_path.to_string());
        let kind = classify_media_kind(logical_path, bytes);
        self.active_media_kind = kind;

        self.loaded_asset = Some(match kind {
            MediaKind::Text => {
                let text = decode_text_preview(bytes)
                    .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned());
                LoadedViewerAsset::Text(text)
            }
            MediaKind::Binary => LoadedViewerAsset::Binary,
            MediaKind::Image => match self.backends.image.decode(bytes, logical_path) {
                Ok(asset) => {
                    let textures = asset
                        .frames
                        .iter()
                        .enumerate()
                        .map(|(i, f)| {
                            let img = ColorImage::from_rgba_unmultiplied(
                                [f.width as usize, f.height as usize],
                                &f.rgba,
                            );
                            ctx.load_texture(
                                format!("wbak_img_{logical_path}_{i}"),
                                img,
                                TextureOptions::LINEAR,
                            )
                        })
                        .collect();
                    LoadedViewerAsset::Image {
                        asset,
                        textures,
                        current_frame: 0,
                        last_frame_switch: Instant::now(),
                    }
                }
                Err(error) => LoadedViewerAsset::UnsupportedMedia { error },
            },
            MediaKind::Audio => {
                match self.backends.audio.open_memory(bytes.clone(), logical_path) {
                    Ok(session) => LoadedViewerAsset::Audio { session },
                    Err(error) => LoadedViewerAsset::UnsupportedMedia { error },
                }
            }
            MediaKind::Video => {
                match self.backends.video.open_memory(bytes.clone(), logical_path) {
                    Ok(session) => LoadedViewerAsset::Video {
                        session,
                        texture: None,
                    },
                    Err(error) => LoadedViewerAsset::UnsupportedMedia { error },
                }
            }
        });
    }

    pub fn render(
        &mut self,
        ctx: &egui::Context,
        ui: &mut Ui,
        manifest: Option<&ArchiveManifest>,
        is_busy: bool,
    ) -> Option<ViewerAction> {
        let mut action: Option<ViewerAction> = None;

        // Check for OS drag-and-drop onto the viewer
        let hovered_files = ctx.input(|i| i.raw.hovered_files.clone());
        let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());

        if !dropped_files.is_empty() && manifest.is_some() && !is_busy {
            let paths: Vec<std::path::PathBuf> =
                dropped_files.into_iter().filter_map(|df| df.path).collect();
            if !paths.is_empty() {
                action = Some(ViewerAction::InjectDroppedPaths {
                    target_logical_dir: self.current_dir.clone(),
                    paths,
                    encrypt_added: self.encrypt_dropped_files,
                });
            }
        }

        let Some(manifest) = manifest else {
            ui.vertical_centered(|ui| {
                ui.add_space(36.0);
                ui.heading("👁 In-Memory Archive Explorer & Media Viewer");
                ui.add_space(8.0);
                ui.label("Load a .wbak archive above using '📦 Load & Inspect' to browse folders, read files, view photos, watch videos, listen to music, or drag-and-drop new files directly into any folder.");
            });
            return None;
        };

        if self.is_video_mode_active() {
            self.render_fullscreen_video_mode(ctx, ui, manifest, &mut action);
            return action;
        }

        // Top memory & drag-drop toolbar
        let regular_file_count = manifest
            .files
            .iter()
            .filter(|f| matches!(f.kind, FileNodeKind::RegularFile { .. }))
            .count();
        let cached_count = self.memory_cache.len();
        let cached_mb = self.total_cached_bytes() as f64 / (1024.0 * 1024.0);

        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                Color32::from_rgb(95, 205, 245),
                format!(
                    "🧠 In-Memory Store: {cached_count}/{regular_file_count} files ({cached_mb:.2} MB in RAM)"
                ),
            );
            if ui
                .add_enabled(
                    !is_busy && cached_count < regular_file_count,
                    egui::Button::new("⚡ Keep All Contents in Memory"),
                )
                .clicked()
            {
                action = Some(ViewerAction::PreloadAllIntoMemory);
            }
            if ui
                .add_enabled(cached_count > 0, egui::Button::new("🧹 Free RAM Cache"))
                .clicked()
            {
                self.clear_memory_cache();
            }

            ui.separator();
            ui.checkbox(
                &mut self.encrypt_dropped_files,
                "🔒 Encrypt newly added/dropped files",
            );
        });

        if !hovered_files.is_empty() {
            let dest_label = if self.current_dir.is_empty() {
                "/ (Archive Root)".to_string()
            } else {
                self.current_dir.clone()
            };
            let enc_badge = if self.encrypt_dropped_files || manifest.full_archive_encrypted {
                "🔒 Encrypted"
            } else {
                "Public"
            };
            egui::Frame::none()
                .fill(Color32::from_rgba_unmultiplied(30, 110, 190, 60))
                .stroke(Stroke::new(2.0_f32, Color32::from_rgb(80, 180, 255)))
                .inner_margin(8.0)
                .rounding(6.0)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "📥 Drop {} item(s) to add into '{dest_label}' [{enc_badge}]",
                            hovered_files.len()
                        ))
                        .strong()
                        .color(Color32::from_rgb(150, 225, 255)),
                    );
                });
        }

        ui.separator();

        // Directory Breadcrumb & Folder Controls
        self.render_breadcrumb_bar(ui, is_busy, &mut action);

        ui.add_space(4.0);

        // Split Pane: Left = Directory Tree & Files, Right = Active In-Memory Viewer
        let available_height = (ui.available_height() - 12.0).max(280.0);
        ui.columns(2, |cols| {
            cols[0].set_min_height(available_height);
            self.render_directory_entries(
                &mut cols[0],
                manifest,
                available_height,
                is_busy,
                &mut action,
            );

            cols[1].set_min_height(available_height);
            self.render_active_viewer_pane(
                ctx,
                &mut cols[1],
                manifest,
                available_height,
                is_busy,
                &mut action,
            );
        });

        action
    }

    fn render_breadcrumb_bar(
        &mut self,
        ui: &mut Ui,
        is_busy: bool,
        action: &mut Option<ViewerAction>,
    ) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("⬆ Up")
                .on_hover_text("Go to parent folder")
                .clicked()
                && !self.current_dir.is_empty()
            {
                if let Some((parent, _)) = self.current_dir.rsplit_once('/') {
                    self.current_dir = parent.to_string();
                } else {
                    self.current_dir.clear();
                }
            }

            if ui
                .selectable_label(self.current_dir.is_empty(), "🏠 Root")
                .clicked()
            {
                self.current_dir.clear();
            }

            let segments: Vec<String> = self
                .current_dir
                .split('/')
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect();

            let mut accum = String::new();
            for (idx, seg) in segments.iter().enumerate() {
                ui.weak("/");
                if !accum.is_empty() {
                    accum.push('/');
                }
                accum.push_str(seg);
                let is_last = idx + 1 == segments.len();
                if ui.selectable_label(is_last, format!("📁 {seg}")).clicked() {
                    self.current_dir = accum.clone();
                }
            }

            ui.separator();
            if ui
                .add_enabled(!is_busy, egui::Button::new("➕ Add Files Here..."))
                .on_hover_text("Pick files to inject into the current archive directory (or drag & drop files onto the window)")
                .clicked()
                && let Some(files) = rfd::FileDialog::new().pick_files()
                && !files.is_empty()
            {
                *action = Some(ViewerAction::InjectDroppedPaths {
                    target_logical_dir: self.current_dir.clone(),
                    paths: files,
                    encrypt_added: self.encrypt_dropped_files,
                });
            }

            if ui
                .add_enabled(!is_busy, egui::Button::new("📁+ Add Folder..."))
                .on_hover_text("Pick a folder to inject recursively into the current archive directory")
                .clicked()
                && let Some(folder) = rfd::FileDialog::new().pick_folder()
            {
                *action = Some(ViewerAction::InjectDroppedPaths {
                    target_logical_dir: self.current_dir.clone(),
                    paths: vec![folder],
                    encrypt_added: self.encrypt_dropped_files,
                });
            }
        });

        ui.horizontal(|ui| {
            ui.label("🔍 Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.path_filter)
                    .hint_text("Search files in current folder or archive...")
                    .desired_width(180.0),
            );
            if !self.path_filter.is_empty() && ui.small_button("✖").clicked() {
                self.path_filter.clear();
            }

            ui.separator();
            ui.label("New Subfolder:");
            ui.add(
                egui::TextEdit::singleline(&mut self.new_subfolder_name)
                    .hint_text("e.g. MyImages")
                    .desired_width(120.0),
            );
            if ui
                .add_enabled(
                    !is_busy && !self.new_subfolder_name.trim().is_empty(),
                    egui::Button::new("+ Create Folder"),
                )
                .clicked()
            {
                let sub = self
                    .new_subfolder_name
                    .trim()
                    .replace('\\', "/")
                    .trim_matches('/')
                    .to_string();
                let full_dir = if self.current_dir.is_empty() {
                    sub
                } else {
                    format!("{}/{sub}", self.current_dir)
                };
                self.new_subfolder_name.clear();
                self.current_dir = full_dir.clone();
                *action = Some(ViewerAction::CreateDirectory {
                    logical_dir: full_dir,
                });
            }
        });
    }

    fn render_directory_entries(
        &mut self,
        ui: &mut Ui,
        manifest: &ArchiveManifest,
        max_height: f32,
        is_busy: bool,
        action: &mut Option<ViewerAction>,
    ) {
        let prefix = if self.current_dir.is_empty() {
            String::new()
        } else {
            format!("{}/", self.current_dir)
        };

        let filter_lower = self.path_filter.trim().to_ascii_lowercase();
        let mut child_dirs: BTreeSet<String> = BTreeSet::new();
        let mut direct_files: Vec<&FileNode> = Vec::new();

        for node in &manifest.files {
            let norm = node.logical_path.trim_end_matches('/');
            if !filter_lower.is_empty() {
                if matches!(node.kind, FileNodeKind::RegularFile { .. })
                    && norm.to_ascii_lowercase().contains(&filter_lower)
                {
                    direct_files.push(node);
                }
                continue;
            }

            let Some(rest) = (if prefix.is_empty() {
                Some(norm)
            } else {
                norm.strip_prefix(&prefix)
            }) else {
                continue;
            };

            if rest.is_empty() {
                continue;
            }

            if let Some((first_seg, _)) = rest.split_once('/') {
                child_dirs.insert(first_seg.to_string());
            } else {
                match node.kind {
                    FileNodeKind::Directory => {
                        child_dirs.insert(rest.to_string());
                    }
                    _ => {
                        direct_files.push(node);
                    }
                }
            }
        }

        ui.label(
            RichText::new(format!(
                "Folders ({}) & Files ({}) — Drag & drop files here:",
                child_dirs.len(),
                direct_files.len()
            ))
            .strong(),
        );

        ScrollArea::vertical()
            .id_salt("viewer_dir_entries_scroll")
            .max_height(max_height - 28.0)
            .show(ui, |ui| {
                let mut enter_dir: Option<String> = None;
                for dir_name in &child_dirs {
                    let full_sub = if self.current_dir.is_empty() {
                        dir_name.clone()
                    } else {
                        format!("{}/{dir_name}", self.current_dir)
                    };
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(
                                false,
                                RichText::new(format!("📁 {dir_name}/")).strong(),
                            )
                            .clicked()
                        {
                            enter_dir = Some(full_sub.clone());
                        }
                        if ui
                            .add_enabled(!is_busy, egui::Button::new("🗑").small())
                            .on_hover_text("Remove folder and its contents from archive")
                            .clicked()
                        {
                            *action = Some(ViewerAction::RemoveItems {
                                logical_paths: vec![full_sub],
                            });
                        }
                    });
                }
                if let Some(d) = enter_dir {
                    self.current_dir = d;
                }

                for file_node in direct_files {
                    let is_selected =
                        self.selected_file.as_deref() == Some(file_node.logical_path.as_str());
                    let short_name = if filter_lower.is_empty() {
                        file_node
                            .logical_path
                            .rsplit_once('/')
                            .map(|(_, n)| n)
                            .unwrap_or(&file_node.logical_path)
                    } else {
                        &file_node.logical_path
                    };

                    let kind = classify_media_kind(&file_node.logical_path, &[]);
                    let in_ram = self.memory_cache.contains_key(&file_node.logical_path);

                    ui.horizontal(|ui| {
                        let label = format!("{} {short_name}", kind.icon());
                        if ui.selectable_label(is_selected, label).clicked() {
                            self.selected_file = Some(file_node.logical_path.clone());
                            self.active_asset_path = None;
                            self.loaded_asset = None;
                            self.video_fullscreen = false;
                            if !in_ram {
                                *action = Some(ViewerAction::LoadFileIntoMemory {
                                    logical_path: file_node.logical_path.clone(),
                                });
                            }
                        }

                        ui.weak(format!("({})", format_bytes(file_node.size())));
                        if file_node.sensitivity == SensitivityLevel::Secret {
                            ui.colored_label(Color32::from_rgb(245, 194, 66), "🔒");
                        }
                        if in_ram {
                            ui.colored_label(
                                Color32::from_rgb(80, 210, 120),
                                RichText::new("[RAM]").small(),
                            );
                        }
                        if ui
                            .add_enabled(!is_busy, egui::Button::new("🗑").small())
                            .on_hover_text("Remove file from archive")
                            .clicked()
                        {
                            *action = Some(ViewerAction::RemoveItems {
                                logical_paths: vec![file_node.logical_path.clone()],
                            });
                        }
                    });
                }
            });
    }

    fn render_active_viewer_pane(
        &mut self,
        ctx: &egui::Context,
        ui: &mut Ui,
        manifest: &ArchiveManifest,
        max_height: f32,
        is_busy: bool,
        action: &mut Option<ViewerAction>,
    ) {
        let Some(selected_path) = self.selected_file.clone() else {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(RichText::new("Select any file on the left to view or play it in memory").weak());
                ui.label(
                    RichText::new("Supports: 📄 Text/Code, 🖼 Photos/GIFs, 🎵 Music/Audio, 🎬 Videos, and 🔢 Hex")
                        .weak(),
                );
            });
            return;
        };

        let Some(bytes) = self.memory_cache.get(&selected_path).cloned() else {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.spinner();
                ui.label(format!(
                    "Decrypting & decompressing '{selected_path}' into RAM..."
                ));
                if ui.button("Retry Load into Memory").clicked() {
                    *action = Some(ViewerAction::LoadFileIntoMemory {
                        logical_path: selected_path,
                    });
                }
            });
            return;
        };

        self.prepare_active_asset(ctx, &selected_path, &bytes);

        let is_secret = manifest
            .files
            .iter()
            .find(|f| f.logical_path == selected_path)
            .map(|f| f.is_secret())
            .unwrap_or(false);

        // Header bar for the selected file
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} {}",
                    self.active_media_kind.icon(),
                    selected_path
                        .rsplit_once('/')
                        .map(|(_, n)| n)
                        .unwrap_or(&selected_path)
                ))
                .strong(),
            );
            ui.weak(format!("({} in RAM)", format_bytes(bytes.len() as u64)));
            if is_secret {
                ui.colored_label(
                    Color32::from_rgb(245, 194, 66),
                    "[SECRET 🔒 Decrypted in RAM]",
                );
            }

            if ui.small_button("💾 Save Copy As...").clicked() {
                let default_name = selected_path
                    .rsplit_once('/')
                    .map(|(_, n)| n)
                    .unwrap_or("extracted.bin");
                if let Some(save_path) = rfd::FileDialog::new()
                    .set_file_name(default_name)
                    .save_file()
                {
                    let _ = std::fs::write(save_path, bytes.as_ref());
                }
            }

            if ui
                .add_enabled(!is_busy, egui::Button::new("🗑 Remove from Archive").small())
                .on_hover_text("Remove this file from the .wbak archive")
                .clicked()
            {
                *action = Some(ViewerAction::RemoveItems {
                    logical_paths: vec![selected_path.clone()],
                });
            }

            ui.separator();
            ui.selectable_value(
                &mut self.override_mode,
                InspectorOverrideMode::Auto,
                format!("Auto ({})", self.active_media_kind.label()),
            );
            ui.selectable_value(
                &mut self.override_mode,
                InspectorOverrideMode::Text,
                "📄 Text",
            );
            ui.selectable_value(
                &mut self.override_mode,
                InspectorOverrideMode::Hex,
                "🔢 Hex",
            );
        });

        ui.separator();

        let body_height = (max_height - 56.0).max(200.0);

        match self.override_mode {
            InspectorOverrideMode::Hex => {
                self.render_hex_view(ui, &bytes, body_height);
                return;
            }
            InspectorOverrideMode::Text => {
                let text = decode_text_preview(&bytes)
                    .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
                self.render_text_view(ctx, ui, &text, body_height);
                return;
            }
            InspectorOverrideMode::Auto => {}
        }

        // Render based on `loaded_asset`
        let mut fallback_hex = false;
        let mut text_to_render: Option<String> = None;

        if let Some(asset) = &mut self.loaded_asset {
            match asset {
                LoadedViewerAsset::Text(text) => {
                    text_to_render = Some(text.clone());
                }
                LoadedViewerAsset::Binary => {
                    fallback_hex = true;
                }
                LoadedViewerAsset::Image {
                    asset,
                    textures,
                    current_frame,
                    last_frame_switch,
                } => {
                    if textures.len() > 1 {
                        let delay = asset
                            .frames
                            .get(*current_frame)
                            .map(|f| f.delay_ms.max(20) as u64)
                            .unwrap_or(80);
                        if last_frame_switch.elapsed() >= Duration::from_millis(delay) {
                            *current_frame = (*current_frame + 1) % textures.len();
                            *last_frame_switch = Instant::now();
                        }
                        ctx.request_repaint_after(Duration::from_millis(delay));
                    }

                    ui.horizontal(|ui| {
                        if let Some(first) = asset.frames.first() {
                            ui.label(format!(
                                "{} — {} × {} px",
                                asset.format_label, first.width, first.height
                            ));
                        }
                        ui.separator();
                        ui.checkbox(&mut self.fit_to_window, "Fit to Window");
                        if !self.fit_to_window {
                            if ui.small_button("🔍-").clicked() {
                                self.zoom_factor = (self.zoom_factor * 0.8).clamp(0.1, 8.0);
                            }
                            if ui.small_button("100%").clicked() {
                                self.zoom_factor = 1.0;
                            }
                            if ui.small_button("🔍+").clicked() {
                                self.zoom_factor = (self.zoom_factor * 1.25).clamp(0.1, 8.0);
                            }
                            ui.add(
                                egui::Slider::new(&mut self.zoom_factor, 0.1..=8.0).text("Zoom"),
                            );
                        }
                    });

                    if let Some(tex) = textures.get(*current_frame) {
                        let native_size = tex.size_vec2();
                        let avail = Vec2::new(ui.available_width() - 8.0, body_height - 34.0);
                        let target_size =
                            if self.fit_to_window && native_size.x > 0.0 && native_size.y > 0.0 {
                                let scale = (avail.x / native_size.x)
                                    .min(avail.y / native_size.y)
                                    .min(1.0);
                                native_size * scale
                            } else {
                                native_size * self.zoom_factor
                            };

                        ScrollArea::both()
                            .id_salt("image_viewer_canvas")
                            .max_height(body_height - 30.0)
                            .show(ui, |ui| {
                                ui.image((tex.id(), target_size));
                            });
                    }
                }
                LoadedViewerAsset::Audio { session } => {
                    let status = session.status();
                    if status.is_playing {
                        ctx.request_repaint_after(Duration::from_millis(50));
                    }

                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!("🎵 Audio Engine: {}", status.backend_name))
                                .weak(),
                        );
                        ui.add_space(6.0);

                        // Waveform visualizer (click or drag to seek)
                        let desired = Vec2::new(ui.available_width(), 92.0);
                        let (rect, response) =
                            ui.allocate_exact_size(desired, Sense::click_and_drag());
                        let painter = ui.painter_at(rect);
                        painter.rect_filled(rect, 6.0, Color32::from_rgb(24, 28, 36));

                        let progress_ratio = status
                            .duration_ms
                            .filter(|&d| d > 0)
                            .map(|d| (status.elapsed_ms as f32 / d as f32).clamp(0.0, 1.0))
                            .unwrap_or(0.0);

                        let bar_count = status.waveform_bars.len();
                        let bar_w = rect.width() / (bar_count as f32 * 1.4);
                        let step_x = rect.width() / bar_count as f32;

                        for (i, &amp) in status.waveform_bars.iter().enumerate() {
                            let bar_ratio = i as f32 / bar_count as f32;
                            let h = (amp * (rect.height() - 16.0)).max(4.0);
                            let x = rect.left() + i as f32 * step_x + (step_x - bar_w) * 0.5;
                            let y_top = rect.center().y - h * 0.5;
                            let bar_rect =
                                Rect::from_min_size(Pos2::new(x, y_top), Vec2::new(bar_w, h));
                            let color = if bar_ratio <= progress_ratio {
                                Color32::from_rgb(75, 200, 255)
                            } else {
                                Color32::from_rgb(70, 80, 98)
                            };
                            painter.rect_filled(bar_rect, 2.0, color);
                        }

                        if (response.clicked() || response.dragged())
                            && let Some(dur) = status.duration_ms
                            && let Some(pos) = response.interact_pointer_pos()
                        {
                            let ratio = ((pos.x - rect.left()) / rect.width()).clamp(0.0, 1.0);
                            session.seek_ms((dur as f32 * ratio) as u64);
                            ctx.request_repaint();
                        }

                        ui.add_space(8.0);
                        ui.horizontal_wrapped(|ui| {
                            if status.is_playing {
                                if ui.button("⏸ Pause").clicked() {
                                    session.pause();
                                }
                            } else if ui.button("▶ Play").clicked() {
                                session.play();
                            }

                            if ui.button("⏹ Stop").clicked() {
                                session.stop();
                            }
                            if ui.button("⏮ 0:00").clicked() {
                                session.seek_ms(0);
                            }
                            if ui.button("⏪ -10s").clicked() {
                                session.seek_ms(status.elapsed_ms.saturating_sub(10_000));
                            }
                            if ui.button("⏪ -5s").clicked() {
                                session.seek_ms(status.elapsed_ms.saturating_sub(5_000));
                            }
                            if ui.button("⏩ +5s").clicked() {
                                session.seek_ms(status.elapsed_ms.saturating_add(5_000));
                            }
                            if ui.button("⏩ +10s").clicked() {
                                session.seek_ms(status.elapsed_ms.saturating_add(10_000));
                            }

                            ui.separator();
                            let mut muted = status.muted;
                            if ui.checkbox(&mut muted, "🔇 Mute").changed() {
                                session.set_muted(muted);
                            }
                            let mut vol = status.volume;
                            if ui
                                .add(egui::Slider::new(&mut vol, 0.0..=1.5).text("🔊 Volume"))
                                .changed()
                            {
                                session.set_volume(vol);
                            }
                        });

                        // Push the seek bar to the bottom across the full available width
                        let remaining_h = (ui.available_height() - 34.0).max(6.0);
                        ui.add_space(remaining_h);

                        let max_dur_ms = status
                            .duration_ms
                            .unwrap_or(status.elapsed_ms.max(60_000))
                            .max(1);
                        let mut seek_secs = status.elapsed_ms as f64 / 1000.0;
                        let max_secs = max_dur_ms as f64 / 1000.0;
                        let dur_str = status
                            .duration_ms
                            .map(format_duration_ms)
                            .unwrap_or_else(|| "--:--".to_string());

                        ui.horizontal(|ui| {
                            ui.monospace(format_duration_ms(status.elapsed_ms));
                            let slider_w = (ui.available_width() - 56.0).max(120.0);
                            ui.spacing_mut().slider_width = slider_w;
                            let slider = egui::Slider::new(&mut seek_secs, 0.0..=max_secs)
                                .show_value(false)
                                .trailing_fill(true);
                            if ui.add_sized([slider_w, 20.0], slider).changed() {
                                session.seek_ms((seek_secs * 1000.0) as u64);
                                ctx.request_repaint();
                            }
                            ui.monospace(&dur_str);
                        });
                    });
                }
                LoadedViewerAsset::Video { session, texture } => {
                    let canvas_height = (body_height - 64.0).max(120.0);
                    render_video_player_ui(
                        ctx,
                        ui,
                        &selected_path,
                        session,
                        texture,
                        canvas_height,
                        false,
                        &mut self.fit_to_window,
                        &mut self.zoom_factor,
                        &mut self.video_fullscreen,
                    );
                }
                LoadedViewerAsset::UnsupportedMedia { error } => {
                    ui.colored_label(
                        Color32::from_rgb(245, 165, 85),
                        format!("Media notice: {error}"),
                    );
                    fallback_hex = true;
                }
            }
        }

        if let Some(text) = text_to_render {
            self.render_text_view(ctx, ui, &text, body_height);
        } else if fallback_hex {
            self.render_hex_view(ui, &bytes, body_height);
        }
    }

    fn render_fullscreen_video_mode(
        &mut self,
        ctx: &egui::Context,
        ui: &mut Ui,
        manifest: &ArchiveManifest,
        action: &mut Option<ViewerAction>,
    ) {
        let Some(selected_path) = self.selected_file.clone() else {
            return;
        };

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.video_fullscreen = false;
            return;
        }

        let short_name = selected_path
            .rsplit_once('/')
            .map(|(_, n)| n)
            .unwrap_or(&selected_path);

        let is_secret = manifest
            .files
            .iter()
            .find(|f| f.logical_path == selected_path)
            .map(|f| f.is_secret())
            .unwrap_or(false);

        let Some(bytes) = self.memory_cache.get(&selected_path).cloned() else {
            ui.horizontal(|ui| {
                if ui.button("⬅ Back").clicked() {
                    self.video_fullscreen = false;
                    return;
                }
                ui.label(RichText::new(format!("🎬 {short_name}")).strong());
            });
            ui.separator();
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);
                ui.spinner();
                ui.label(format!(
                    "Decrypting & decompressing '{selected_path}' into RAM..."
                ));
                if ui.button("Retry Load into Memory").clicked() {
                    *action = Some(ViewerAction::LoadFileIntoMemory {
                        logical_path: selected_path,
                    });
                }
            });
            return;
        };

        self.prepare_active_asset(ctx, &selected_path, &bytes);

        // Top compact header bar with little Back button to exit fullscreen video mode
        let mut should_exit_fullscreen = false;
        ui.horizontal(|ui| {
            let back_btn = egui::Button::new(RichText::new("⬅ Back").strong());
            if ui
                .add(back_btn)
                .on_hover_text(
                    "Exit fullscreen video player and return to side-by-side viewer (Esc)",
                )
                .clicked()
            {
                should_exit_fullscreen = true;
            }

            ui.separator();
            ui.label(RichText::new(format!("🎬 {short_name}")).strong());
            ui.weak(format!("({} in RAM)", format_bytes(bytes.len() as u64)));
            if is_secret {
                ui.colored_label(Color32::from_rgb(245, 194, 66), "[SECRET 🔒]");
            }

            if ui.small_button("💾 Save Copy As...").clicked()
                && let Some(save_path) =
                    rfd::FileDialog::new().set_file_name(short_name).save_file()
            {
                let _ = std::fs::write(save_path, bytes.as_ref());
            }
            if ui.small_button("🔢 View Hex").clicked() {
                self.override_mode = InspectorOverrideMode::Hex;
                self.video_fullscreen = false;
            }
        });

        if should_exit_fullscreen {
            self.video_fullscreen = false;
            return;
        }

        ui.add_space(2.0);

        let mut fallback_error: Option<String> = None;
        if let Some(asset) = &mut self.loaded_asset {
            match asset {
                LoadedViewerAsset::Video { session, texture } => {
                    let bottom_bar_height = 60.0;
                    let canvas_height = (ui.available_height() - bottom_bar_height).max(120.0);
                    render_video_player_ui(
                        ctx,
                        ui,
                        &selected_path,
                        session,
                        texture,
                        canvas_height,
                        true,
                        &mut self.fit_to_window,
                        &mut self.zoom_factor,
                        &mut self.video_fullscreen,
                    );
                }
                LoadedViewerAsset::UnsupportedMedia { error } => {
                    fallback_error = Some(error.clone());
                }
                _ => {}
            }
        }

        if let Some(error) = fallback_error {
            ui.colored_label(
                Color32::from_rgb(245, 165, 85),
                format!("Media notice: {error}"),
            );
            let h = (ui.available_height() - 16.0).max(200.0);
            self.render_hex_view(ui, &bytes, h);
        }
    }

    fn render_text_view(&mut self, ctx: &egui::Context, ui: &mut Ui, text: &str, max_height: f32) {
        ui.horizontal(|ui| {
            ui.label("🔍 Find:");
            ui.add(
                egui::TextEdit::singleline(&mut self.text_search_query)
                    .hint_text("Filter or highlight lines...")
                    .desired_width(160.0),
            );
            ui.checkbox(&mut self.text_show_line_numbers, "Line Numbers");
            ui.checkbox(&mut self.text_word_wrap, "Wrap");
            if ui.small_button("📋 Copy All").clicked() {
                ctx.copy_text(text.to_string());
            }
        });

        let query_lower = self.text_search_query.trim().to_ascii_lowercase();
        let lines: Vec<(usize, &str)> = text
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                query_lower.is_empty() || line.to_ascii_lowercase().contains(&query_lower)
            })
            .collect();

        let row_height = 17.0;
        ScrollArea::both()
            .id_salt("in_memory_text_reader")
            .max_height(max_height - 28.0)
            .auto_shrink([false, false])
            .show_rows(ui, row_height, lines.len(), |ui, row_range| {
                ui.style_mut().wrap_mode = Some(if self.text_word_wrap {
                    egui::TextWrapMode::Wrap
                } else {
                    egui::TextWrapMode::Extend
                });
                for idx in row_range {
                    let (line_no, line_str) = lines[idx];
                    ui.horizontal(|ui| {
                        if self.text_show_line_numbers {
                            ui.colored_label(
                                Color32::from_rgb(110, 120, 140),
                                RichText::new(format!("{:>5} │", line_no + 1)).monospace(),
                            );
                        }
                        if !query_lower.is_empty() {
                            ui.colored_label(
                                Color32::from_rgb(130, 225, 165),
                                RichText::new(line_str).monospace(),
                            );
                        } else {
                            ui.monospace(line_str);
                        }
                    });
                }
            });
    }

    fn render_hex_view(&self, ui: &mut Ui, bytes: &[u8], max_height: f32) {
        let total_rows = bytes.len().div_ceil(16);
        let row_height = 17.0;

        ScrollArea::vertical()
            .id_salt("in_memory_hex_reader")
            .max_height(max_height)
            .auto_shrink([false, false])
            .show_rows(ui, row_height, total_rows, |ui, row_range| {
                for row in row_range {
                    let offset = row * 16;
                    let end = (offset + 16).min(bytes.len());
                    let slice = &bytes[offset..end];

                    let mut hex_col = String::with_capacity(48);
                    let mut ascii_col = String::with_capacity(16);
                    for i in 0..16 {
                        if i < slice.len() {
                            let b = slice[i];
                            hex_col.push_str(&format!("{b:02X} "));
                            let ch = if (0x20..=0x7E).contains(&b) {
                                b as char
                            } else {
                                '.'
                            };
                            ascii_col.push(ch);
                        } else {
                            hex_col.push_str("   ");
                            ascii_col.push(' ');
                        }
                        if i == 7 {
                            hex_col.push(' ');
                        }
                    }

                    ui.monospace(format!("{offset:08X}  {hex_col} │{ascii_col}│"));
                }
            });
    }
}

impl Default for ContentViewerPanel {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments, clippy::borrowed_box)]
fn render_video_player_ui(
    ctx: &egui::Context,
    ui: &mut Ui,
    selected_path: &str,
    session: &mut Box<dyn VideoSession>,
    texture: &mut Option<TextureHandle>,
    canvas_height: f32,
    is_fullscreen: bool,
    fit_to_window: &mut bool,
    zoom_factor: &mut f32,
    video_fullscreen: &mut bool,
) {
    if let Some(frame) = session.poll_frame() {
        let img = ColorImage::from_rgba_unmultiplied(
            [frame.width as usize, frame.height as usize],
            &frame.rgba,
        );
        match texture {
            Some(tex) => tex.set(img, TextureOptions::LINEAR),
            None => {
                *texture = Some(ctx.load_texture(
                    format!("wbak_video_{selected_path}"),
                    img,
                    TextureOptions::LINEAR,
                ));
            }
        }
    }

    let status = session.status();
    if status.is_playing {
        ctx.request_repaint_after(Duration::from_millis(16));
    }

    let canvas_size = Vec2::new(ui.available_width(), canvas_height);
    let (canvas_rect, canvas_response) = ui.allocate_exact_size(canvas_size, Sense::click());
    let painter = ui.painter_at(canvas_rect);
    painter.rect_filled(canvas_rect, 4.0, Color32::from_rgb(10, 12, 16));

    if let Some(tex) = texture {
        let native = tex.size_vec2();
        let draw_size = if native.x > 0.0 && native.y > 0.0 {
            if *fit_to_window {
                let scale = (canvas_rect.width() / native.x).min(canvas_rect.height() / native.y);
                native * scale
            } else {
                native * *zoom_factor
            }
        } else {
            canvas_rect.size()
        };

        let video_rect = Rect::from_center_size(canvas_rect.center(), draw_size);
        let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
        painter.image(tex.id(), video_rect, uv, Color32::WHITE);
    } else {
        painter.text(
            canvas_rect.center(),
            egui::Align2::CENTER_CENTER,
            "Decoding video stream in memory...",
            egui::FontId::proportional(16.0),
            Color32::from_rgb(180, 190, 210),
        );
    }

    if !status.is_playing {
        let badge_rect = Rect::from_center_size(canvas_rect.center(), Vec2::new(150.0, 42.0));
        painter.rect_filled(
            badge_rect,
            8.0,
            Color32::from_rgba_unmultiplied(15, 18, 24, 195),
        );
        painter.text(
            badge_rect.center(),
            egui::Align2::CENTER_CENTER,
            "⏸ Paused",
            egui::FontId::proportional(18.0),
            Color32::WHITE,
        );
    }

    // Clicking anywhere on the viewable video area pauses/resumes the video
    if canvas_response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
    {
        if status.is_playing {
            session.pause();
        } else {
            session.play();
        }
        ctx.request_repaint();
    }

    ui.add_space(4.0);

    // Transport controls row right above the bottom seek bar
    ui.horizontal_wrapped(|ui| {
        if status.is_playing {
            if ui.button("⏸ Pause").clicked() {
                session.pause();
            }
        } else if ui.button("▶ Play").clicked() {
            session.play();
        }
        if ui.button("⏮ Restart").clicked() {
            session.restart();
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        if ui.button("⏪ -10s").clicked() {
            session.seek_ms(status.position_ms.saturating_sub(10_000));
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        if ui.button("⏪ -5s").clicked() {
            session.seek_ms(status.position_ms.saturating_sub(5_000));
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        if ui.button("⏩ +5s").clicked() {
            session.seek_ms(status.position_ms.saturating_add(5_000));
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        if ui.button("⏩ +10s").clicked() {
            session.seek_ms(status.position_ms.saturating_add(10_000));
            ctx.request_repaint_after(Duration::from_millis(16));
        }

        ui.separator();
        ui.weak(format!("{}×{}", status.width, status.height));
        ui.checkbox(fit_to_window, "Fit");

        let mut muted = status.muted;
        if ui.checkbox(&mut muted, "🔇").changed() {
            session.set_muted(muted);
        }
        let mut vol = status.volume;
        if ui
            .add(
                egui::Slider::new(&mut vol, 0.0..=1.5)
                    .show_value(false)
                    .text("🔊"),
            )
            .changed()
        {
            session.set_volume(vol);
        }

        ui.separator();
        if is_fullscreen {
            if ui.button("🗗 Exit Fullscreen").clicked() {
                *video_fullscreen = false;
            }
        } else if ui.button("⛶ Fullscreen").clicked() {
            *video_fullscreen = true;
        }
    });

    // Seek bar spanning full width of the video area
    let max_vid_ms = status
        .duration_ms
        .unwrap_or(status.position_ms.saturating_add(30_000).max(60_000))
        .max(1);
    let mut vid_seek_secs = status.position_ms as f64 / 1000.0;
    let max_vid_secs = max_vid_ms as f64 / 1000.0;
    let dur_str = status
        .duration_ms
        .map(format_duration_ms)
        .unwrap_or_else(|| "--:--".to_string());

    ui.horizontal(|ui| {
        ui.monospace(format_duration_ms(status.position_ms));
        let slider_w = (ui.available_width() - 56.0).max(120.0);
        ui.spacing_mut().slider_width = slider_w;
        let slider = egui::Slider::new(&mut vid_seek_secs, 0.0..=max_vid_secs)
            .show_value(false)
            .trailing_fill(true);
        if ui.add_sized([slider_w, 20.0], slider).changed() {
            session.seek_ms((vid_seek_secs * 1000.0) as u64);
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        ui.monospace(&dur_str);
    });
}

fn matches_removed_target(path: &str, removed_targets: &[String]) -> bool {
    let norm = path
        .replace('\\', "/")
        .trim_matches('/')
        .to_ascii_lowercase();
    removed_targets.iter().any(|target| {
        let t = target
            .replace('\\', "/")
            .trim_matches('/')
            .to_ascii_lowercase();
        !t.is_empty() && (norm == t || norm.starts_with(&format!("{t}/")))
    })
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration_ms(ms: u64) -> String {
    let total_secs = ms / 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    format!("{mins:02}:{secs:02}")
}
