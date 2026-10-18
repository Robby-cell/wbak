use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

use wbak_domain::{
    DomainError, DomainResult, RegistryBackupConfig, RegistryBrowseItem, RegistryHive,
    RegistryKeyNode, RegistryRepositoryPort, RegistryTree, RegistryValueData, RegistryValueEntry,
};

#[derive(Debug, Default, Clone)]
pub struct WindowsRegistryRepository;

impl WindowsRegistryRepository {
    pub fn new() -> Self {
        Self
    }

    fn open_hive(hive: RegistryHive) -> RegKey {
        match hive {
            RegistryHive::HKCU => RegKey::predef(HKEY_CURRENT_USER),
            RegistryHive::HKLM => RegKey::predef(HKEY_LOCAL_MACHINE),
            RegistryHive::HKCR => RegKey::predef(HKEY_CLASSES_ROOT),
            RegistryHive::HKU => RegKey::predef(HKEY_USERS),
            RegistryHive::HKCC => RegKey::predef(HKEY_CURRENT_CONFIG),
        }
    }

    fn compile_exclude_set(patterns: &[String]) -> DomainResult<GlobSet> {
        let mut builder = GlobSetBuilder::new();
        for pat in patterns {
            let normalized = pat.replace('/', "\\");
            let glob = GlobBuilder::new(&normalized)
                .case_insensitive(true)
                .build()
                .map_err(|e| {
                    DomainError::RegistryError(format!(
                        "Invalid registry exclude pattern '{pat}': {e}"
                    ))
                })?;
            builder.add(glob);
        }
        builder.build().map_err(|e| {
            DomainError::RegistryError(format!("Failed building registry exclude set: {e}"))
        })
    }

    fn export_recursive(
        hive: RegistryHive,
        subkey_path: &str,
        exclude_set: &GlobSet,
        tree: &mut RegistryTree,
    ) {
        let full_path = if subkey_path.is_empty() {
            hive.short_name().to_string()
        } else {
            format!("{}\\{}", hive.short_name(), subkey_path)
        };

        if exclude_set.is_match(&full_path) || exclude_set.is_match(subkey_path) {
            return;
        }

        let root = Self::open_hive(hive);
        let Ok(key) = root.open_subkey_with_flags(subkey_path, KEY_READ) else {
            return;
        };

        let mut values = BTreeMap::new();
        for val_res in key.enum_values() {
            let Ok((name, raw_val)) = val_res else {
                continue;
            };
            let full_val_path = format!("{full_path}\\{name}");
            if exclude_set.is_match(&full_val_path) {
                continue;
            }
            if let Some(typed_data) = parse_reg_value(&raw_val) {
                values.insert(
                    name.clone(),
                    RegistryValueEntry {
                        name,
                        data: typed_data,
                    },
                );
            }
        }

        let node = RegistryKeyNode {
            hive,
            subkey_path: subkey_path.to_string(),
            values,
        };
        tree.keys.insert(full_path, node);

        for sub_res in key.enum_keys() {
            if let Ok(child_name) = sub_res {
                let next_subkey = if subkey_path.is_empty() {
                    child_name
                } else {
                    format!("{subkey_path}\\{child_name}")
                };
                Self::export_recursive(hive, &next_subkey, exclude_set, tree);
            }
        }
    }
}

impl RegistryRepositoryPort for WindowsRegistryRepository {
    fn export_keys(&self, config: &RegistryBackupConfig) -> DomainResult<RegistryTree> {
        let exclude_set = Self::compile_exclude_set(&config.exclude_patterns)?;
        let mut tree = RegistryTree::default();

        for raw_key in &config.include_keys {
            let Some((hive, subkey)) = RegistryHive::parse_key_path(raw_key) else {
                return Err(DomainError::RegistryError(format!(
                    "Unrecognized registry hive in key path '{raw_key}'"
                )));
            };
            Self::export_recursive(hive, &subkey, &exclude_set, &mut tree);
        }

        Ok(tree)
    }

    fn create_rollback_reg_file(
        &self,
        tree_to_restore: &RegistryTree,
        rollback_file_path: &Path,
    ) -> DomainResult<()> {
        let mut live_snapshot = RegistryTree::default();
        let empty_excludes = GlobSet::empty();

        for node in tree_to_restore.keys.values() {
            Self::export_recursive(
                node.hive,
                &node.subkey_path,
                &empty_excludes,
                &mut live_snapshot,
            );
        }

        if let Some(parent) = rollback_file_path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let mut file = File::create(rollback_file_path).map_err(|e| {
            DomainError::RegistryError(format!(
                "Failed to create rollback .reg file '{}': {e}",
                rollback_file_path.display()
            ))
        })?;

        writeln!(file, "Windows Registry Editor Version 5.00\r").map_err(|e| {
            DomainError::RegistryError(format!("Failed writing .reg header: {e}"))
        })?;
        writeln!(file, "; Generated automatically by wbak before registry restore\r")
            .map_err(|e| DomainError::RegistryError(format!("Failed writing .reg comment: {e}")))?;

        for node in live_snapshot.keys.values() {
            writeln!(
                file,
                "\r\n[{}\\{}]\r",
                node.hive.full_name(),
                node.subkey_path
            )
            .map_err(|e| DomainError::RegistryError(format!("Failed writing .reg key: {e}")))?;

            for val in node.values.values() {
                let line = format_reg_file_value(val);
                writeln!(file, "{line}\r").map_err(|e| {
                    DomainError::RegistryError(format!("Failed writing .reg value: {e}"))
                })?;
            }
        }

        Ok(())
    }

    fn restore_tree(&self, tree: &RegistryTree) -> DomainResult<usize> {
        let mut restored_values_count = 0usize;

        for node in tree.keys.values() {
            let root = Self::open_hive(node.hive);
            let (key, _disp) = root.create_subkey(&node.subkey_path).map_err(|e| {
                DomainError::RegistryError(format!(
                    "Failed to open/create registry key '{}': {e} (Note: HKLM keys require Administrator privileges)",
                    node.full_path()
                ))
            })?;

            for val in node.values.values() {
                let raw = to_winreg_value(&val.data);
                key.set_raw_value(&val.name, &raw).map_err(|e| {
                    DomainError::RegistryError(format!(
                        "Failed setting registry value '{}' in '{}': {e}",
                        val.name,
                        node.full_path()
                    ))
                })?;
                restored_values_count += 1;
            }
        }

        Ok(restored_values_count)
    }

    fn list_subkeys(
        &self,
        hive: RegistryHive,
        parent_subkey: &str,
    ) -> DomainResult<Vec<RegistryBrowseItem>> {
        let root = Self::open_hive(hive);
        let key = if parent_subkey.is_empty() {
            root
        } else {
            root.open_subkey_with_flags(parent_subkey, KEY_READ)
                .map_err(|e| {
                    DomainError::RegistryError(format!(
                        "Cannot open {}\\{}: {e}",
                        hive.short_name(),
                        parent_subkey
                    ))
                })?
        };

        let mut items = Vec::new();
        for name_res in key.enum_keys() {
            let Ok(name) = name_res else {
                continue;
            };
            let subkey_path = if parent_subkey.is_empty() {
                name.clone()
            } else {
                format!("{parent_subkey}\\{name}")
            };
            let full_path = format!("{}\\{subkey_path}", hive.short_name());

            let (has_subkeys, value_count) = key
                .open_subkey_with_flags(&name, KEY_READ)
                .and_then(|child| child.query_info())
                .map(|info| (info.sub_keys > 0, info.values as usize))
                .unwrap_or((false, 0));

            items.push(RegistryBrowseItem {
                hive,
                subkey_path,
                full_path,
                has_subkeys,
                value_count,
            });
        }

        items.sort_by(|a, b| a.full_path.cmp(&b.full_path));
        Ok(items)
    }
}

fn parse_reg_value(raw: &RegValue) -> Option<RegistryValueData> {
    match raw.vtype {
        REG_SZ => Some(RegistryValueData::Sz(decode_utf16_reg_str(&raw.bytes))),
        REG_EXPAND_SZ => Some(RegistryValueData::ExpandSz(decode_utf16_reg_str(&raw.bytes))),
        REG_MULTI_SZ => Some(RegistryValueData::MultiSz(decode_utf16_multi_str(
            &raw.bytes,
        ))),
        REG_DWORD => {
            if raw.bytes.len() >= 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&raw.bytes[0..4]);
                Some(RegistryValueData::Dword(u32::from_le_bytes(arr)))
            } else {
                None
            }
        }
        REG_QWORD => {
            if raw.bytes.len() >= 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&raw.bytes[0..8]);
                Some(RegistryValueData::Qword(u64::from_le_bytes(arr)))
            } else {
                None
            }
        }
        REG_BINARY => Some(RegistryValueData::Binary(raw.bytes.clone())),
        REG_NONE => Some(RegistryValueData::None),
        _ => Some(RegistryValueData::Binary(raw.bytes.clone())),
    }
}

fn decode_utf16_reg_str(bytes: &[u8]) -> String {
    let mut u16_slice: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    while u16_slice.last() == Some(&0) {
        u16_slice.pop();
    }
    String::from_utf16_lossy(&u16_slice)
}

fn decode_utf16_multi_str(bytes: &[u8]) -> Vec<String> {
    let u16_slice: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    u16_slice
        .split(|&c| c == 0)
        .filter(|seg| !seg.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

fn encode_utf16_null_terminated(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity((s.len() + 1) * 2);
    for code_unit in s.encode_utf16() {
        out.extend_from_slice(&code_unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn to_winreg_value(data: &RegistryValueData) -> RegValue {
    match data {
        RegistryValueData::Sz(s) => RegValue {
            bytes: encode_utf16_null_terminated(s),
            vtype: REG_SZ,
        },
        RegistryValueData::ExpandSz(s) => RegValue {
            bytes: encode_utf16_null_terminated(s),
            vtype: REG_EXPAND_SZ,
        },
        RegistryValueData::MultiSz(list) => {
            let mut bytes = Vec::new();
            for item in list {
                bytes.extend_from_slice(&encode_utf16_null_terminated(item));
            }
            bytes.extend_from_slice(&0u16.to_le_bytes());
            RegValue {
                bytes,
                vtype: REG_MULTI_SZ,
            }
        }
        RegistryValueData::Dword(v) => RegValue {
            bytes: v.to_le_bytes().to_vec(),
            vtype: REG_DWORD,
        },
        RegistryValueData::Qword(v) => RegValue {
            bytes: v.to_le_bytes().to_vec(),
            vtype: REG_QWORD,
        },
        RegistryValueData::Binary(b) => RegValue {
            bytes: b.clone(),
            vtype: REG_BINARY,
        },
        RegistryValueData::None => RegValue {
            bytes: Vec::new(),
            vtype: REG_NONE,
        },
    }
}

fn format_reg_file_value(val: &RegistryValueEntry) -> String {
    let lhs = if val.name.is_empty() {
        "@".to_string()
    } else {
        let escaped_name = val.name.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped_name}\"")
    };

    let rhs = match &val.data {
        RegistryValueData::Sz(s) => {
            let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
        RegistryValueData::Dword(v) => format!("dword:{v:08x}"),
        RegistryValueData::Qword(v) => {
            let bytes = v.to_le_bytes();
            let hex_list: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
            format!("hex(b):{}", hex_list.join(","))
        }
        RegistryValueData::Binary(b) => {
            let hex_list: Vec<String> = b.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("hex:{}", hex_list.join(","))
        }
        RegistryValueData::ExpandSz(s) => {
            let bytes = encode_utf16_null_terminated(s);
            let hex_list: Vec<String> = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("hex(2):{}", hex_list.join(","))
        }
        RegistryValueData::MultiSz(list) => {
            let raw = to_winreg_value(&RegistryValueData::MultiSz(list.clone()));
            let hex_list: Vec<String> =
                raw.bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("hex(7):{}", hex_list.join(","))
        }
        RegistryValueData::None => "hex(0):".to_string(),
    };

    format!("{lhs}={rhs}")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn registry_roundtrip_and_rollback_file_under_hkcu_test_key() {
        let repo = WindowsRegistryRepository::new();
        let test_subkey = r"Software\wbak_unit_test_temp";
        let full_test_key = format!(r"HKCU\{test_subkey}");

        // 1. Populate a temporary test key in HKCU
        let mut values = BTreeMap::new();
        values.insert(
            "InstallChannel".to_string(),
            RegistryValueEntry {
                name: "InstallChannel".to_string(),
                data: RegistryValueData::Sz("enterprise-stable".to_string()),
            },
        );
        values.insert(
            "MaxWorkers".to_string(),
            RegistryValueEntry {
                name: "MaxWorkers".to_string(),
                data: RegistryValueData::Dword(16),
            },
        );

        let mut tree = RegistryTree::default();
        tree.keys.insert(
            full_test_key.clone(),
            RegistryKeyNode {
                hive: RegistryHive::HKCU,
                subkey_path: test_subkey.to_string(),
                values,
            },
        );

        let count = repo.restore_tree(&tree).unwrap();
        assert_eq!(count, 2);

        // 2. Export it back via RegistryRepositoryPort
        let cfg = RegistryBackupConfig {
            include_keys: vec![full_test_key.clone()],
            exclude_patterns: vec![],
        };
        let exported = repo.export_keys(&cfg).unwrap();
        let exported_node = exported.keys.get(&full_test_key).unwrap();
        assert_eq!(
            exported_node.values.get("InstallChannel").unwrap().data,
            RegistryValueData::Sz("enterprise-stable".to_string())
        );
        assert_eq!(
            exported_node.values.get("MaxWorkers").unwrap().data,
            RegistryValueData::Dword(16)
        );

        // 3. Generate a `.reg` rollback file and verify its syntax
        let dir = tempdir().unwrap();
        let reg_file = dir.path().join("rollback.reg");
        repo.create_rollback_reg_file(&tree, &reg_file).unwrap();
        let reg_text = std::fs::read_to_string(&reg_file).unwrap();
        assert!(reg_text.contains("Windows Registry Editor Version 5.00"));
        assert!(reg_text.contains("\"InstallChannel\"=\"enterprise-stable\""));
        assert!(reg_text.contains("\"MaxWorkers\"=dword:00000010"));

        // 4. Clean up temporary test key from HKCU
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(test_subkey);
    }
}
