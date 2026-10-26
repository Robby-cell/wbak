use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use chrono::{DateTime, Utc};

use wbak_domain::{
    ConflictPolicy, DomainError, DomainResult, FileRestorerPort, WindowsFileAttributes,
};

#[derive(Debug, Default, Clone)]
pub struct WindowsFileRestorer;

impl WindowsFileRestorer {
    pub fn new() -> Self {
        Self
    }

    fn apply_attributes(target_path: &Path, attributes: &WindowsFileAttributes) {
        if let Ok(meta) = fs::metadata(target_path) {
            let mut perms = meta.permissions();
            if perms.readonly() != attributes.readonly {
                perms.set_readonly(attributes.readonly);
                let _ = fs::set_permissions(target_path, perms);
            }
        }

        #[cfg(windows)]
        {
            if attributes.hidden {
                let _ = Command::new("attrib").arg("+H").arg(target_path).output();
            }
        }
    }
}

impl FileRestorerPort for WindowsFileRestorer {
    fn restore_directory(
        &self,
        target_path: &Path,
        attributes: &WindowsFileAttributes,
    ) -> DomainResult<()> {
        fs::create_dir_all(target_path).map_err(|e| {
            DomainError::FilesystemError(format!(
                "Failed to create directory '{}': {e}",
                target_path.display()
            ))
        })?;
        Self::apply_attributes(target_path, attributes);
        Ok(())
    }

    fn restore_regular_file(
        &self,
        target_path: &Path,
        contents: &[u8],
        attributes: &WindowsFileAttributes,
        modified_at: Option<DateTime<Utc>>,
        conflict_policy: ConflictPolicy,
    ) -> DomainResult<bool> {
        if target_path.exists() {
            match conflict_policy {
                ConflictPolicy::SkipExisting => return Ok(false),
                ConflictPolicy::BackupExisting => {
                    let backup_path = target_path.with_extension(
                        target_path
                            .extension()
                            .map(|ext| format!("{}.wbak.bak", ext.to_string_lossy()))
                            .unwrap_or_else(|| "wbak.bak".to_string()),
                    );
                    let _ = fs::rename(target_path, &backup_path);
                }
                ConflictPolicy::Overwrite => {
                    // Clear readonly flag if set so overwrite succeeds
                    if let Ok(meta) = fs::metadata(target_path) {
                        let mut perms = meta.permissions();
                        if perms.readonly() {
                            #[allow(clippy::permissions_set_readonly_false)]
                            perms.set_readonly(false);
                            let _ = fs::set_permissions(target_path, perms);
                        }
                    }
                }
            }
        }

        if let Some(parent) = target_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                DomainError::FilesystemError(format!(
                    "Failed to create parent directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        let mut file = File::create(target_path).map_err(|e| {
            DomainError::FilesystemError(format!(
                "Failed to create file '{}': {e}",
                target_path.display()
            ))
        })?;
        file.write_all(contents).map_err(|e| {
            DomainError::FilesystemError(format!(
                "Failed to write file '{}': {e}",
                target_path.display()
            ))
        })?;

        if let Some(mtime) = modified_at {
            let sys_time: std::time::SystemTime = mtime.into();
            let _ = file.set_modified(sys_time);
        }

        drop(file);
        Self::apply_attributes(target_path, attributes);

        Ok(true)
    }

    fn restore_symlink(
        &self,
        target_path: &Path,
        link_target: &str,
        is_dir: bool,
        conflict_policy: ConflictPolicy,
    ) -> DomainResult<bool> {
        if target_path.symlink_metadata().is_ok() {
            match conflict_policy {
                ConflictPolicy::SkipExisting => return Ok(false),
                ConflictPolicy::BackupExisting | ConflictPolicy::Overwrite => {
                    let _ = fs::remove_file(target_path).or_else(|_| fs::remove_dir(target_path));
                }
            }
        }

        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        #[cfg(windows)]
        {
            let res = if is_dir {
                std::os::windows::fs::symlink_dir(link_target, target_path)
            } else {
                std::os::windows::fs::symlink_file(link_target, target_path)
            };
            // Note: Creating symlinks on Windows may require Developer Mode or Admin privileges;
            // we log/ignore permission errors gracefully if non-elevated.
            if let Err(e) = res {
                return Err(DomainError::FilesystemError(format!(
                    "Failed to create symlink '{}' -> '{}': {e}",
                    target_path.display(),
                    link_target
                )));
            }
        }

        Ok(true)
    }

    fn tighten_secret_file_acl(&self, target_path: &Path) -> DomainResult<()> {
        #[cfg(windows)]
        {
            let username = std::env::var("USERNAME").unwrap_or_default();
            if !username.is_empty() && target_path.exists() {
                // Disable ACL inheritance and grant only current user Full/Read-Write access,
                // satisfying Windows OpenSSH strict private key permission checks.
                let grant_arg = format!("{username}:(F)");
                let _ = Command::new("icacls")
                    .arg(target_path)
                    .arg("/inheritance:r")
                    .arg("/grant:r")
                    .arg(&grant_arg)
                    .output();
            }
        }
        Ok(())
    }
}
