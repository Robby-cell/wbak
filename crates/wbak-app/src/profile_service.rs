use std::fs;
use std::path::Path;

use wbak_domain::{DomainError, DomainResult, ProfileConfig};

pub struct ProfileService;

impl ProfileService {
    pub fn load_from_file(path: &Path) -> DomainResult<ProfileConfig> {
        let content = fs::read_to_string(path).map_err(|e| {
            DomainError::InvalidProfile(format!("Failed to read profile '{}': {e}", path.display()))
        })?;
        toml::from_str(&content).map_err(|e| {
            DomainError::InvalidProfile(format!("TOML syntax error in '{}': {e}", path.display()))
        })
    }

    pub fn save_to_file(profile: &ProfileConfig, path: &Path) -> DomainResult<()> {
        let toml_str = toml::to_string_pretty(profile).map_err(|e| {
            DomainError::InvalidProfile(format!("Failed to serialize profile to TOML: {e}"))
        })?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(path, toml_str).map_err(|e| {
            DomainError::InvalidProfile(format!(
                "Failed to write profile '{}': {e}",
                path.display()
            ))
        })
    }

    pub fn default_wbakignore_content() -> &'static str {
        r#"# .wbakignore — Exclude build artifacts, caches, and temporary files
# Uses standard .gitignore syntax. Prefix a pattern with '!' to exempt it.

# Dependency & Build Directories
/node_modules/
**/node_modules/
/target/
**/target/
/.git/objects/
**/.venv/
**/__pycache__/

# OS & Temporary Caches
*.tmp
*.temp
*.bak
*.log
**/Thumbs.db
**/desktop.ini

# Example Exemptions ('!' overrides previous ignore rules)
#!/target/release/important-tool.exe
#!important-audit.log
"#
    }

    pub fn write_starter_templates(
        profile_path: &Path,
        ignore_path: &Path,
    ) -> DomainResult<ProfileConfig> {
        let mut profile = ProfileConfig::default();
        profile.files.ignore_file = Some(ignore_path.to_path_buf());
        Self::save_to_file(&profile, profile_path)?;

        if !ignore_path.exists() {
            fs::write(ignore_path, Self::default_wbakignore_content()).map_err(|e| {
                DomainError::FilesystemError(format!(
                    "Failed to write ignore file '{}': {e}",
                    ignore_path.display()
                ))
            })?;
        }

        Ok(profile)
    }
}
