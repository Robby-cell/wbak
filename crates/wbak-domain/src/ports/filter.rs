use std::path::Path;

use crate::entities::SensitivityLevel;
use crate::error::DomainResult;

/// Detailed result of evaluating a path against `.wbakignore` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterDecision {
    /// Included normally (did not match any ignore pattern).
    Included,
    /// Excluded by a matching ignore pattern (e.g. `/node_modules/` or `/target/`).
    Ignored { matched_pattern: String },
    /// Explicitly exempted by a negation `!` pattern (e.g. `!/target/release/tool.exe`).
    Exempted { matched_pattern: String },
}

impl FilterDecision {
    pub fn is_included(&self) -> bool {
        matches!(self, Self::Included | Self::Exempted { .. })
    }
}

/// Port for evaluating `.wbakignore` rules (including `/node_modules`, `/target`, and `!` exemptions).
pub trait PathFilterPort: Send + Sync {
    /// Evaluates `candidate_path` relative to `scan_root`.
    fn evaluate(&self, scan_root: &Path, candidate_path: &Path, is_dir: bool) -> FilterDecision;

    /// Convenience helper returning true if the path should be included in the backup.
    fn should_include(&self, scan_root: &Path, candidate_path: &Path, is_dir: bool) -> bool {
        self.evaluate(scan_root, candidate_path, is_dir)
            .is_included()
    }
}

/// Factory port for constructing a `PathFilterPort` from profile patterns and `.wbakignore` files.
pub trait PathFilterFactoryPort: Send + Sync {
    fn build_filter(
        &self,
        patterns: &[String],
        ignore_file: Option<&Path>,
    ) -> DomainResult<Box<dyn PathFilterPort>>;
}

/// Port for classifying files as `Public` vs `Secret` (such as `.ssh` keys, `.gnupg`, `*.pem`).
pub trait SensitivityClassifierPort: Send + Sync {
    fn classify(&self, logical_path: &str, physical_path: &Path) -> SensitivityLevel;
}
