use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use wbak_domain::{
    DomainError, DomainResult, FileScannerPort, FilterDecision, PathFilterPort,
    PortablePathTokenizer, ScannedEntry, ScannedEntryKind, SensitivityClassifierPort,
    WindowsFileAttributes,
};
use wbak_filter::GitignoreMatcher;

pub struct WindowsFileScanner {
    tokenizer: PortablePathTokenizer,
    sensitivity_classifier: Arc<dyn SensitivityClassifierPort>,
}

impl WindowsFileScanner {
    pub fn new(
        tokenizer: PortablePathTokenizer,
        sensitivity_classifier: Arc<dyn SensitivityClassifierPort>,
    ) -> Self {
        Self {
            tokenizer,
            sensitivity_classifier,
        }
    }

    pub fn tokenizer(&self) -> &PortablePathTokenizer {
        &self.tokenizer
    }

    fn walk_recursive(
        &self,
        scan_root: &Path,
        current_path: &Path,
        filter: &dyn PathFilterPort,
        local_git_matcher: Option<&GitignoreMatcher>,
        respect_local_ignore: bool,
        include_ignored_for_preview: bool,
        out: &mut Vec<ScannedEntry>,
    ) -> DomainResult<()> {
        let symlink_meta = match fs::symlink_metadata(current_path) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };

        let file_type = symlink_meta.file_type();
        let is_symlink = file_type.is_symlink();
        let is_dir = file_type.is_dir();

        // Check active filter (either refined local `.wbakignore` or root filter)
        let decision = if let Some(local_m) = local_git_matcher {
            local_m.evaluate(scan_root, current_path, is_dir)
        } else {
            filter.evaluate(scan_root, current_path, is_dir)
        };

        if !decision.is_included() && !include_ignored_for_preview {
            // If this is an ignored directory, check if we can prune it in O(1)
            // (or if there is a `!` exemption rule that might match inside it).
            if is_dir {
                let can_have_exemption = local_git_matcher
                    .map(|m| m.has_potential_exemption_in_dir(scan_root, current_path))
                    .unwrap_or(true);
                if !can_have_exemption {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        let logical_path = self.tokenizer.tokenize(current_path);
        let sensitivity = self
            .sensitivity_classifier
            .classify(&logical_path, current_path);
        let attributes = extract_windows_attributes(&symlink_meta);
        let modified_at = symlink_meta.modified().ok().map(DateTime::<Utc>::from);
        let created_at = symlink_meta.created().ok().map(DateTime::<Utc>::from);

        if is_symlink {
            if decision.is_included() || include_ignored_for_preview {
                let link_target = fs::read_link(current_path)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let target_is_dir = fs::metadata(current_path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                out.push(ScannedEntry {
                    physical_path: current_path.to_path_buf(),
                    logical_path,
                    kind: ScannedEntryKind::Symlink {
                        target: link_target,
                        is_dir: target_is_dir,
                    },
                    attributes,
                    sensitivity,
                    filter_decision: decision,
                    modified_at,
                    created_at,
                });
            }
            return Ok(());
        }

        if is_dir {
            // Check for a local `.wbakignore` inside this directory if enabled
            let mut refined_matcher: Option<GitignoreMatcher> = None;
            if respect_local_ignore {
                let local_ignore = current_path.join(".wbakignore");
                if local_ignore.is_file() {
                    if let Some(existing) = local_git_matcher {
                        refined_matcher = existing.with_additional_ignore_file(&local_ignore).ok();
                    } else if let Ok(m) =
                        GitignoreMatcher::from_patterns_and_file(&[], Some(&local_ignore))
                    {
                        refined_matcher = Some(m);
                    }
                }
            }

            if (decision.is_included() || include_ignored_for_preview) && current_path != scan_root
            {
                out.push(ScannedEntry {
                    physical_path: current_path.to_path_buf(),
                    logical_path,
                    kind: ScannedEntryKind::Directory,
                    attributes,
                    sensitivity,
                    filter_decision: decision.clone(),
                    modified_at,
                    created_at,
                });
            }

            let read_dir = match fs::read_dir(current_path) {
                Ok(rd) => rd,
                Err(_) => return Ok(()),
            };

            let mut children: Vec<PathBuf> = read_dir
                .filter_map(|e| e.ok().map(|entry| entry.path()))
                .collect();
            children.sort();

            let active_local = refined_matcher.as_ref().or(local_git_matcher);
            for child in children {
                self.walk_recursive(
                    scan_root,
                    &child,
                    filter,
                    active_local,
                    respect_local_ignore,
                    include_ignored_for_preview,
                    out,
                )?;
            }
        } else if decision.is_included() || include_ignored_for_preview {
            out.push(ScannedEntry {
                physical_path: current_path.to_path_buf(),
                logical_path,
                kind: ScannedEntryKind::RegularFile {
                    size: symlink_meta.len(),
                },
                attributes,
                sensitivity,
                filter_decision: decision,
                modified_at,
                created_at,
            });
        }

        Ok(())
    }
}

impl FileScannerPort for WindowsFileScanner {
    fn scan_paths(
        &self,
        include_paths: &[PathBuf],
        filter: &dyn PathFilterPort,
        respect_local_ignore: bool,
        include_ignored_for_preview: bool,
    ) -> DomainResult<Vec<ScannedEntry>> {
        let mut results = Vec::new();

        for raw_path in include_paths {
            let mut resolved = if raw_path.to_string_lossy().contains("${") {
                self.tokenizer.detokenize(&raw_path.to_string_lossy())
            } else {
                raw_path.clone()
            };

            if resolved.is_relative() {
                if let Ok(cwd) = std::env::current_dir() {
                    resolved = cwd.join(&resolved);
                }
            }

            if !resolved.exists() {
                continue;
            }

            if let Ok(canon) = fs::canonicalize(&resolved) {
                resolved = PathBuf::from(
                    wbak_domain::normalize_slashes(&canon.to_string_lossy())
                        .replace('/', std::path::MAIN_SEPARATOR_STR),
                );
            }

            if resolved.is_file() {
                let meta = fs::symlink_metadata(&resolved).map_err(|e| {
                    DomainError::FilesystemError(format!(
                        "Failed to read metadata for '{}': {e}",
                        resolved.display()
                    ))
                })?;
                let logical_path = self.tokenizer.tokenize(&resolved);
                let sensitivity = self
                    .sensitivity_classifier
                    .classify(&logical_path, &resolved);
                let parent_root = resolved.parent().unwrap_or(Path::new(""));
                let decision = filter.evaluate(parent_root, &resolved, false);

                if decision.is_included() || include_ignored_for_preview {
                    results.push(ScannedEntry {
                        physical_path: resolved,
                        logical_path,
                        kind: ScannedEntryKind::RegularFile { size: meta.len() },
                        attributes: extract_windows_attributes(&meta),
                        sensitivity,
                        filter_decision: if matches!(decision, FilterDecision::Ignored { .. })
                            && !include_ignored_for_preview
                        {
                            FilterDecision::Included
                        } else {
                            decision
                        },
                        modified_at: meta.modified().ok().map(DateTime::<Utc>::from),
                        created_at: meta.created().ok().map(DateTime::<Utc>::from),
                    });
                }
            } else {
                self.walk_recursive(
                    &resolved,
                    &resolved,
                    filter,
                    None,
                    respect_local_ignore,
                    include_ignored_for_preview,
                    &mut results,
                )?;
            }
        }

        Ok(results)
    }
}

#[cfg(windows)]
pub fn extract_windows_attributes(meta: &fs::Metadata) -> WindowsFileAttributes {
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

    let raw = meta.file_attributes();
    WindowsFileAttributes {
        readonly: (raw & FILE_ATTRIBUTE_READONLY) != 0,
        hidden: (raw & FILE_ATTRIBUTE_HIDDEN) != 0,
        system: (raw & FILE_ATTRIBUTE_SYSTEM) != 0,
        archive: (raw & FILE_ATTRIBUTE_ARCHIVE) != 0,
        raw_attributes: raw,
    }
}

#[cfg(not(windows))]
pub fn extract_windows_attributes(meta: &fs::Metadata) -> WindowsFileAttributes {
    WindowsFileAttributes {
        readonly: meta.permissions().readonly(),
        ..Default::default()
    }
}
