use std::collections::BTreeMap;
use std::process::Command;

use chrono::Utc;
use serde::Deserialize;
use winreg::enums::*;
use winreg::RegKey;

use wbak_domain::{
    DomainError, DomainResult, EnvVarsSnapshot, EnvironmentRepositoryPort, WingetManifest,
    WingetPackage,
};

#[derive(Debug, Default, Clone)]
pub struct WindowsEnvironmentRepository;

impl WindowsEnvironmentRepository {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Deserialize)]
struct WingetExportFile {
    #[serde(rename = "Sources", default)]
    sources: Vec<WingetSourceSection>,
}

#[derive(Debug, Deserialize)]
struct WingetSourceSection {
    #[serde(rename = "SourceDetails")]
    source_details: Option<WingetSourceDetails>,
    #[serde(rename = "Packages", default)]
    packages: Vec<WingetExportPackage>,
}

#[derive(Debug, Deserialize)]
struct WingetSourceDetails {
    #[serde(rename = "Name")]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WingetExportPackage {
    #[serde(rename = "PackageIdentifier")]
    package_identifier: String,
    #[serde(rename = "Version")]
    version: Option<String>,
}

impl EnvironmentRepositoryPort for WindowsEnvironmentRepository {
    fn capture_winget(&self) -> DomainResult<WingetManifest> {
        let temp_path =
            std::env::temp_dir().join(format!("wbak-winget-export-{}.json", std::process::id()));

        let output = Command::new("winget")
            .arg("export")
            .arg("-o")
            .arg(&temp_path)
            .arg("--include-versions")
            .arg("--accept-source-agreements")
            .output();

        let Ok(out) = output else {
            // If winget is not installed on this machine, return an empty manifest gracefully
            return Ok(WingetManifest {
                captured_at: Some(Utc::now()),
                packages: Vec::new(),
                raw_winget_export_json: None,
            });
        };

        if !temp_path.exists() && !out.status.success() {
            return Ok(WingetManifest {
                captured_at: Some(Utc::now()),
                packages: Vec::new(),
                raw_winget_export_json: None,
            });
        }

        let raw_json = std::fs::read_to_string(&temp_path).unwrap_or_default();
        let _ = std::fs::remove_file(&temp_path);

        let packages = parse_winget_export_json(&raw_json);

        Ok(WingetManifest {
            captured_at: Some(Utc::now()),
            packages,
            raw_winget_export_json: if raw_json.is_empty() {
                None
            } else {
                Some(raw_json)
            },
        })
    }

    fn restore_winget(&self, manifest: &WingetManifest, dry_run: bool) -> DomainResult<usize> {
        if manifest.packages.is_empty() {
            return Ok(0);
        }
        if dry_run {
            return Ok(manifest.packages.len());
        }

        if let Some(raw_json) = &manifest.raw_winget_export_json {
            let temp_path = std::env::temp_dir()
                .join(format!("wbak-winget-import-{}.json", std::process::id()));
            std::fs::write(&temp_path, raw_json).map_err(|e| {
                DomainError::EnvironmentError(format!(
                    "Failed writing temporary winget import file: {e}"
                ))
            })?;

            let status = Command::new("winget")
                .arg("import")
                .arg("-i")
                .arg(&temp_path)
                .arg("--accept-package-agreements")
                .arg("--accept-source-agreements")
                .arg("--ignore-unavailable")
                .status();

            let _ = std::fs::remove_file(&temp_path);

            match status {
                Ok(_) => return Ok(manifest.packages.len()),
                Err(e) => {
                    return Err(DomainError::EnvironmentError(format!(
                        "Failed to execute `winget import`: {e}"
                    )));
                }
            }
        }

        let mut installed = 0usize;
        for pkg in &manifest.packages {
            let mut cmd = Command::new("winget");
            cmd.arg("install")
                .arg("--id")
                .arg(&pkg.id)
                .arg("-e")
                .arg("--accept-package-agreements")
                .arg("--accept-source-agreements");
            if let Some(ver) = &pkg.version {
                cmd.arg("--version").arg(ver);
            }
            if cmd.status().is_ok() {
                installed += 1;
            }
        }

        Ok(installed)
    }

    fn capture_env_vars(&self) -> DomainResult<EnvVarsSnapshot> {
        let mut user_vars = BTreeMap::new();
        let mut system_vars = BTreeMap::new();

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(env_key) = hkcu.open_subkey_with_flags("Environment", KEY_READ) {
            for (name, val) in env_key.enum_values().flatten() {
                if let Ok(s) = String::from_utf8(val.bytes.clone()).or_else(|_| {
                    let u16s: Vec<u16> = val
                        .bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&c| c != 0)
                        .collect();
                    Ok::<String, ()>(String::from_utf16_lossy(&u16s))
                }) {
                    user_vars.insert(name, s);
                }
            }
        }

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(sys_env_key) = hklm.open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            KEY_READ,
        ) {
            for (name, val) in sys_env_key.enum_values().flatten() {
                let u16s: Vec<u16> = val
                    .bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                system_vars.insert(name, String::from_utf16_lossy(&u16s));
            }
        }

        Ok(EnvVarsSnapshot {
            user_vars,
            system_vars,
        })
    }

    fn restore_user_env_vars(
        &self,
        snapshot: &EnvVarsSnapshot,
        dry_run: bool,
    ) -> DomainResult<usize> {
        if dry_run {
            return Ok(snapshot.user_vars.len());
        }

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (env_key, _) = hkcu.create_subkey("Environment").map_err(|e| {
            DomainError::EnvironmentError(format!("Failed opening HKCU\\Environment: {e}"))
        })?;

        for (k, v) in &snapshot.user_vars {
            env_key.set_value(k, v).map_err(|e| {
                DomainError::EnvironmentError(format!("Failed setting user env var '{k}': {e}"))
            })?;
        }

        Ok(snapshot.user_vars.len())
    }
}

pub fn parse_winget_export_json(raw_json: &str) -> Vec<WingetPackage> {
    let Ok(parsed) = serde_json::from_str::<WingetExportFile>(raw_json) else {
        return Vec::new();
    };

    let mut packages = Vec::new();
    for source in parsed.sources {
        let source_name = source
            .source_details
            .and_then(|d| d.name)
            .unwrap_or_else(|| "winget".to_string());
        for pkg in source.packages {
            packages.push(WingetPackage {
                id: pkg.package_identifier,
                name: None,
                version: pkg.version,
                source: source_name.clone(),
            });
        }
    }
    packages.sort();
    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_winget_export_json_schema() {
        let sample = r#"{
            "$schema": "https://aka.ms/winget-packages.schema.2.0.json",
            "Sources": [
                {
                    "Packages": [
                        { "PackageIdentifier": "Git.Git", "Version": "2.47.0" },
                        { "PackageIdentifier": "Microsoft.VisualStudioCode", "Version": "1.95.0" }
                    ],
                    "SourceDetails": {
                        "Name": "winget"
                    }
                }
            ]
        }"#;

        let pkgs = parse_winget_export_json(sample);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].id, "Git.Git");
        assert_eq!(pkgs[0].version.as_deref(), Some("2.47.0"));
        assert_eq!(pkgs[1].id, "Microsoft.VisualStudioCode");
    }
}
