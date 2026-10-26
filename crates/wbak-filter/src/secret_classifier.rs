use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use wbak_domain::{
    DomainError, DomainResult, SensitivityClassifierPort, SensitivityLevel,
    classify_builtin_sensitivity, normalize_slashes,
};

/// Glob-based sensitivity classifier that detects `.ssh` keys, `.gnupg`, certificates, and custom secret patterns.
#[derive(Debug, Clone)]
pub struct GlobSensitivityClassifier {
    glob_set: GlobSet,
    enabled: bool,
}

impl GlobSensitivityClassifier {
    pub fn new(patterns: &[String], enabled: bool) -> DomainResult<Self> {
        let mut builder = GlobSetBuilder::new();
        for pat in patterns {
            let clean = pat.replace('\\', "/");
            let glob = GlobBuilder::new(&clean)
                .case_insensitive(true)
                .build()
                .map_err(|e| {
                    DomainError::FilterError(format!("Invalid sensitivity pattern '{pat}': {e}"))
                })?;
            builder.add(glob);
        }
        let glob_set = builder.build().map_err(|e| {
            DomainError::FilterError(format!("Failed to build sensitivity set: {e}"))
        })?;

        Ok(Self { glob_set, enabled })
    }
}

impl SensitivityClassifierPort for GlobSensitivityClassifier {
    fn classify(&self, logical_path: &str, physical_path: &Path) -> SensitivityLevel {
        if !self.enabled {
            return SensitivityLevel::Public;
        }

        let norm_logical = normalize_slashes(logical_path);
        let norm_physical = normalize_slashes(&physical_path.to_string_lossy());

        if classify_builtin_sensitivity(&norm_logical) == SensitivityLevel::Secret
            || classify_builtin_sensitivity(&norm_physical) == SensitivityLevel::Secret
            || self.glob_set.is_match(&norm_logical)
            || self.glob_set.is_match(&norm_physical)
        {
            SensitivityLevel::Secret
        } else {
            SensitivityLevel::Public
        }
    }
}

#[cfg(test)]
mod tests {
    use wbak_domain::default_sensitive_patterns;

    use super::*;

    #[test]
    fn classifies_ssh_and_custom_patterns_as_secret() {
        let mut patterns = default_sensitive_patterns();
        patterns.push("**/corporate-secrets/**".to_string());

        let classifier = GlobSensitivityClassifier::new(&patterns, true).unwrap();

        assert_eq!(
            classifier.classify(
                "${USERPROFILE}/.ssh/id_ed25519",
                Path::new(r"C:\Users\alice\.ssh\id_ed25519")
            ),
            SensitivityLevel::Secret
        );
        assert_eq!(
            classifier.classify(
                "C:/work/corporate-secrets/token.json",
                Path::new(r"C:\work\corporate-secrets\token.json")
            ),
            SensitivityLevel::Secret
        );
        assert_eq!(
            classifier.classify(
                "${USERPROFILE}/.gitconfig",
                Path::new(r"C:\Users\alice\.gitconfig")
            ),
            SensitivityLevel::Public
        );
    }
}
