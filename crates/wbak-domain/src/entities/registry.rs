use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Supported Windows Registry root hives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegistryHive {
    HKCU,
    HKLM,
    HKCR,
    HKU,
    HKCC,
}

impl RegistryHive {
    pub fn parse_key_path(full_path: &str) -> Option<(Self, String)> {
        let normalized = full_path.trim().replace('/', "\\");
        let (hive_str, rest) = match normalized.split_once('\\') {
            Some((h, r)) => (h, r.to_string()),
            None => (normalized.as_str(), String::new()),
        };

        let hive = match hive_str.to_ascii_uppercase().as_str() {
            "HKCU" | "HKEY_CURRENT_USER" => Self::HKCU,
            "HKLM" | "HKEY_LOCAL_MACHINE" => Self::HKLM,
            "HKCR" | "HKEY_CLASSES_ROOT" => Self::HKCR,
            "HKU" | "HKEY_USERS" => Self::HKU,
            "HKCC" | "HKEY_CURRENT_CONFIG" => Self::HKCC,
            _ => return None,
        };

        Some((hive, rest))
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Self::HKCU => "HKCU",
            Self::HKLM => "HKLM",
            Self::HKCR => "HKCR",
            Self::HKU => "HKU",
            Self::HKCC => "HKCC",
        }
    }

    pub fn full_name(&self) -> &'static str {
        match self {
            Self::HKCU => "HKEY_CURRENT_USER",
            Self::HKLM => "HKEY_LOCAL_MACHINE",
            Self::HKCR => "HKEY_CLASSES_ROOT",
            Self::HKU => "HKEY_USERS",
            Self::HKCC => "HKEY_CURRENT_CONFIG",
        }
    }

    pub fn requires_elevation(&self) -> bool {
        matches!(self, Self::HKLM | Self::HKCR | Self::HKU | Self::HKCC)
    }
}

/// Typed representation of a Windows Registry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryValueData {
    Sz(String),
    ExpandSz(String),
    MultiSz(Vec<String>),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
    None,
}

impl RegistryValueData {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Sz(_) => "REG_SZ",
            Self::ExpandSz(_) => "REG_EXPAND_SZ",
            Self::MultiSz(_) => "REG_MULTI_SZ",
            Self::Dword(_) => "REG_DWORD",
            Self::Qword(_) => "REG_QWORD",
            Self::Binary(_) => "REG_BINARY",
            Self::None => "REG_NONE",
        }
    }

    pub fn display_summary(&self) -> String {
        match self {
            Self::Sz(s) | Self::ExpandSz(s) => format!("\"{s}\""),
            Self::MultiSz(list) => format!("{:?}", list),
            Self::Dword(v) => format!("0x{v:08x} ({v})"),
            Self::Qword(v) => format!("0x{v:016x} ({v})"),
            Self::Binary(bytes) => format!("({} bytes)", bytes.len()),
            Self::None => "(none)".to_string(),
        }
    }
}

/// A single named (or default `""`) value inside a Registry key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValueEntry {
    /// Empty string `""` represents the `(Default)` key value.
    pub name: String,
    pub data: RegistryValueData,
}

/// A captured Windows Registry key and its values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryKeyNode {
    pub hive: RegistryHive,
    /// Path relative to the hive root, e.g. `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`.
    pub subkey_path: String,
    /// Values sorted by value name.
    pub values: BTreeMap<String, RegistryValueEntry>,
}

impl RegistryKeyNode {
    pub fn full_path(&self) -> String {
        if self.subkey_path.is_empty() {
            self.hive.short_name().to_string()
        } else {
            format!("{}\\{}", self.hive.short_name(), self.subkey_path)
        }
    }
}

/// A collection of captured Registry keys stored in an archive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryTree {
    /// Keyed by canonical path (e.g. `HKCU\Environment`).
    pub keys: BTreeMap<String, RegistryKeyNode>,
}

impl RegistryTree {
    pub fn total_values(&self) -> usize {
        self.keys.values().map(|k| k.values.len()).sum()
    }
}
