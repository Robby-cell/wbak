use std::collections::BTreeMap;

use crate::entities::{
    DriftStatus, FileDriftItem, FileNode, FileNodeKind, PackageDriftItem, RegistryDriftItem,
    RegistryTree, SystemDriftReport, WingetManifest,
};

/// Live file probe summary used for deterministic diff calculation without coupling to OS I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFileProbe {
    pub target_path: String,
    pub exists: bool,
    pub size: Option<u64>,
    pub content_hash: Option<String>,
}

pub struct DiffCalculator;

impl DiffCalculator {
    /// Compares archived `FileNode` entries against live filesystem probes.
    pub fn diff_files(
        archived_files: &[FileNode],
        live_probes: &BTreeMap<String, LiveFileProbe>,
    ) -> Vec<FileDriftItem> {
        let mut items = Vec::new();

        for node in archived_files {
            let FileNodeKind::RegularFile {
                size, content_hash, ..
            } = &node.kind
            else {
                continue;
            };

            match live_probes.get(&node.logical_path) {
                None => {
                    items.push(FileDriftItem {
                        logical_path: node.logical_path.clone(),
                        target_path: node.original_path.clone(),
                        status: DriftStatus::MissingOnSystem,
                        sensitivity: node.sensitivity,
                        archive_size: Some(*size),
                        system_size: None,
                        detail: "File does not exist on target system".to_string(),
                    });
                }
                Some(probe) if !probe.exists => {
                    items.push(FileDriftItem {
                        logical_path: node.logical_path.clone(),
                        target_path: probe.target_path.clone(),
                        status: DriftStatus::MissingOnSystem,
                        sensitivity: node.sensitivity,
                        archive_size: Some(*size),
                        system_size: None,
                        detail: "Missing on target system".to_string(),
                    });
                }
                Some(probe) => {
                    let size_matches = probe.size == Some(*size);
                    let hash_matches = probe
                        .content_hash
                        .as_deref()
                        .map(|h| h == content_hash.as_str())
                        .unwrap_or(size_matches);

                    if size_matches && hash_matches {
                        items.push(FileDriftItem {
                            logical_path: node.logical_path.clone(),
                            target_path: probe.target_path.clone(),
                            status: DriftStatus::Identical,
                            sensitivity: node.sensitivity,
                            archive_size: Some(*size),
                            system_size: probe.size,
                            detail: "Identical".to_string(),
                        });
                    } else {
                        items.push(FileDriftItem {
                            logical_path: node.logical_path.clone(),
                            target_path: probe.target_path.clone(),
                            status: DriftStatus::ModifiedOnSystem,
                            sensitivity: node.sensitivity,
                            archive_size: Some(*size),
                            system_size: probe.size,
                            detail: "Content or size differs from archive".to_string(),
                        });
                    }
                }
            }
        }

        items
    }

    /// Compares an archived `RegistryTree` against a live `RegistryTree`.
    pub fn diff_registry(archived: &RegistryTree, live: &RegistryTree) -> Vec<RegistryDriftItem> {
        let mut items = Vec::new();

        for (key_path, arch_key) in &archived.keys {
            let Some(live_key) = live.keys.get(key_path) else {
                items.push(RegistryDriftItem {
                    key_path: key_path.clone(),
                    value_name: None,
                    status: DriftStatus::MissingOnSystem,
                    archive_value: Some(format!("({} values)", arch_key.values.len())),
                    system_value: None,
                });
                continue;
            };

            for (val_name, arch_val) in &arch_key.values {
                match live_key.values.get(val_name) {
                    None => {
                        items.push(RegistryDriftItem {
                            key_path: key_path.clone(),
                            value_name: Some(val_name.clone()),
                            status: DriftStatus::MissingOnSystem,
                            archive_value: Some(arch_val.data.display_summary()),
                            system_value: None,
                        });
                    }
                    Some(live_val) if live_val.data == arch_val.data => {
                        items.push(RegistryDriftItem {
                            key_path: key_path.clone(),
                            value_name: Some(val_name.clone()),
                            status: DriftStatus::Identical,
                            archive_value: Some(arch_val.data.display_summary()),
                            system_value: Some(live_val.data.display_summary()),
                        });
                    }
                    Some(live_val) => {
                        items.push(RegistryDriftItem {
                            key_path: key_path.clone(),
                            value_name: Some(val_name.clone()),
                            status: DriftStatus::ModifiedOnSystem,
                            archive_value: Some(arch_val.data.display_summary()),
                            system_value: Some(live_val.data.display_summary()),
                        });
                    }
                }
            }
        }

        items
    }

    /// Compares an archived `WingetManifest` against the live system's `WingetManifest`.
    pub fn diff_packages(
        archived: Option<&WingetManifest>,
        live: Option<&WingetManifest>,
    ) -> Vec<PackageDriftItem> {
        let Some(arch) = archived else {
            return Vec::new();
        };

        let live_map: BTreeMap<String, Option<String>> = live
            .map(|l| {
                l.packages
                    .iter()
                    .map(|p| (p.id.to_ascii_lowercase(), p.version.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let mut items = Vec::new();
        for pkg in &arch.packages {
            let key = pkg.id.to_ascii_lowercase();
            match live_map.get(&key) {
                None => items.push(PackageDriftItem {
                    package_id: pkg.id.clone(),
                    status: DriftStatus::MissingOnSystem,
                    archive_version: pkg.version.clone(),
                    system_version: None,
                }),
                Some(sys_ver) if sys_ver == &pkg.version => items.push(PackageDriftItem {
                    package_id: pkg.id.clone(),
                    status: DriftStatus::Identical,
                    archive_version: pkg.version.clone(),
                    system_version: sys_ver.clone(),
                }),
                Some(sys_ver) => items.push(PackageDriftItem {
                    package_id: pkg.id.clone(),
                    status: DriftStatus::ModifiedOnSystem,
                    archive_version: pkg.version.clone(),
                    system_version: sys_ver.clone(),
                }),
            }
        }
        items
    }

    pub fn compute_report(
        archived_files: &[FileNode],
        live_probes: &BTreeMap<String, LiveFileProbe>,
        archived_registry: &RegistryTree,
        live_registry: &RegistryTree,
        archived_winget: Option<&WingetManifest>,
        live_winget: Option<&WingetManifest>,
    ) -> SystemDriftReport {
        SystemDriftReport {
            files: Self::diff_files(archived_files, live_probes),
            registry: Self::diff_registry(archived_registry, live_registry),
            packages: Self::diff_packages(archived_winget, live_winget),
        }
    }
}
