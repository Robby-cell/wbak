use std::path::Path;

use globset::{GlobBuilder, GlobMatcher};

use wbak_domain::{
    DomainError, DomainResult, FilterDecision, PathFilterFactoryPort, PathFilterPort,
    normalize_slashes,
};

#[derive(Debug, Clone)]
struct CompiledRule {
    raw: String,
    is_negated: bool,
    dir_only: bool,
    anchored: bool,
    /// Normalized pattern body without leading `!`, leading `/`, or trailing `/`.
    clean_pattern: String,
    direct_matcher: GlobMatcher,
    unanchored_matcher: Option<GlobMatcher>,
}

impl CompiledRule {
    fn compile(raw_line: &str) -> DomainResult<Option<Self>> {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        let (is_negated, rest) = if let Some(stripped) = trimmed.strip_prefix("\\!") {
            (false, stripped)
        } else if let Some(stripped) = trimmed.strip_prefix('!') {
            (true, stripped.trim_start())
        } else {
            (false, trimmed)
        };

        let norm = rest.replace('\\', "/");
        let dir_only = norm.ends_with('/');
        let without_trailing = norm.trim_end_matches('/');

        if without_trailing.is_empty() {
            return Ok(None);
        }

        // A pattern is anchored to the scan root if it starts with `/` or contains a `/` in the middle
        // (unless it starts with `**/`).
        let starts_with_slash = without_trailing.starts_with('/');
        let clean = without_trailing.trim_start_matches('/');
        let starts_with_double_star = clean.starts_with("**/");
        let anchored = starts_with_slash || (clean.contains('/') && !starts_with_double_star);

        let direct_glob = GlobBuilder::new(clean)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
            .map_err(|e| DomainError::FilterError(format!("Invalid pattern '{raw_line}': {e}")))?
            .compile_matcher();

        let unanchored_matcher = if !anchored {
            let pat = if starts_with_double_star {
                clean.to_string()
            } else {
                format!("**/{clean}")
            };
            let m = GlobBuilder::new(&pat)
                .case_insensitive(true)
                .literal_separator(true)
                .build()
                .map_err(|e| {
                    DomainError::FilterError(format!("Invalid pattern '{raw_line}': {e}"))
                })?
                .compile_matcher();
            Some(m)
        } else {
            None
        };

        Ok(Some(Self {
            raw: trimmed.to_string(),
            is_negated,
            dir_only,
            anchored,
            clean_pattern: clean.to_string(),
            direct_matcher: direct_glob,
            unanchored_matcher,
        }))
    }

    fn matches_single_segment(&self, rel_path: &str, is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        if self.direct_matcher.is_match(rel_path) {
            return true;
        }
        if let Some(unanchored) = &self.unanchored_matcher
            && unanchored.is_match(rel_path)
        {
            return true;
        }
        false
    }

    /// Evaluates whether this rule matches `rel_path` directly OR matches any ancestor directory of `rel_path`.
    fn matches_path_or_ancestor(&self, rel_path: &str, is_dir: bool) -> bool {
        if self.matches_single_segment(rel_path, is_dir) {
            return true;
        }

        // Check ancestor directories (all ancestors are directories: `is_dir = true`)
        let mut current = rel_path;
        while let Some((parent, _)) = current.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            if self.matches_single_segment(parent, true) {
                return true;
            }
            current = parent;
        }

        false
    }

    /// Checks whether a negated (`!`) rule could potentially match a descendant inside `rel_dir`.
    fn could_match_descendant_of(&self, rel_dir: &str) -> bool {
        if !self.is_negated {
            return false;
        }
        if !self.anchored || self.clean_pattern.starts_with("**/") {
            return true;
        }
        let dir_lower = rel_dir.to_ascii_lowercase();
        let pat_lower = self.clean_pattern.to_ascii_lowercase();
        pat_lower.starts_with(&format!("{dir_lower}/"))
            || dir_lower.starts_with(&format!("{pat_lower}/"))
    }
}

/// `.wbakignore` pattern matcher supporting `/node_modules`, `/target`, globs, and `!` exemptions.
#[derive(Debug, Clone, Default)]
pub struct GitignoreMatcher {
    rules: Vec<CompiledRule>,
}

impl GitignoreMatcher {
    pub fn from_patterns_and_file(
        patterns: &[String],
        ignore_file: Option<&Path>,
    ) -> DomainResult<Self> {
        let mut rules = Vec::new();

        // Built-in Windows system lock files and .wbak archives that should always be ignored unless exempted
        for sys_pat in [
            "**/pagefile.sys",
            "**/hiberfil.sys",
            "**/swapfile.sys",
            "**/*.wbak",
        ] {
            if let Some(rule) = CompiledRule::compile(sys_pat)? {
                rules.push(rule);
            }
        }

        if let Some(path) = ignore_file
            && path.exists()
        {
            let content = std::fs::read_to_string(path).map_err(|e| {
                DomainError::FilterError(format!(
                    "Failed to read ignore file '{}': {e}",
                    path.display()
                ))
            })?;
            for line in content.lines() {
                if let Some(rule) = CompiledRule::compile(line)? {
                    rules.push(rule);
                }
            }
        }

        for pat in patterns {
            for line in pat.lines() {
                if let Some(rule) = CompiledRule::compile(line)? {
                    rules.push(rule);
                }
            }
        }

        Ok(Self { rules })
    }

    /// Appends rules from a local `.wbakignore` file discovered inside a directory during traversal.
    pub fn with_additional_ignore_file(&self, local_ignore_file: &Path) -> DomainResult<Self> {
        let mut cloned = self.clone();
        if local_ignore_file.exists() {
            let content = std::fs::read_to_string(local_ignore_file).map_err(|e| {
                DomainError::FilterError(format!(
                    "Failed to read local ignore file '{}': {e}",
                    local_ignore_file.display()
                ))
            })?;
            for line in content.lines() {
                if let Some(rule) = CompiledRule::compile(line)? {
                    cloned.rules.push(rule);
                }
            }
        }
        Ok(cloned)
    }

    /// Returns true if an ignored directory has any `!` exemption rule that might match a file inside it.
    /// When false, the filesystem walker can skip descending into the directory entirely (O(1) pruning).
    pub fn has_potential_exemption_in_dir(&self, scan_root: &Path, candidate_dir: &Path) -> bool {
        let rel = Self::relative_normalized(scan_root, candidate_dir);
        if rel.is_empty() {
            return true;
        }
        self.rules.iter().any(|r| r.could_match_descendant_of(&rel))
    }

    fn relative_normalized(scan_root: &Path, candidate_path: &Path) -> String {
        let root_norm = normalize_slashes(&scan_root.to_string_lossy());
        let cand_norm = normalize_slashes(&candidate_path.to_string_lossy());

        let root_lower = root_norm.to_ascii_lowercase();
        let cand_lower = cand_norm.to_ascii_lowercase();

        if cand_lower == root_lower {
            return String::new();
        }
        if cand_lower.starts_with(&root_lower) {
            let rest = &cand_norm[root_norm.len()..];
            return rest.trim_start_matches('/').to_string();
        }
        cand_norm.trim_start_matches('/').to_string()
    }
}

impl PathFilterPort for GitignoreMatcher {
    fn evaluate(&self, scan_root: &Path, candidate_path: &Path, is_dir: bool) -> FilterDecision {
        let rel = Self::relative_normalized(scan_root, candidate_path);
        if rel.is_empty() {
            return FilterDecision::Included;
        }

        let mut decision = FilterDecision::Included;
        for rule in &self.rules {
            if rule.matches_path_or_ancestor(&rel, is_dir) {
                if rule.is_negated {
                    decision = FilterDecision::Exempted {
                        matched_pattern: rule.raw.clone(),
                    };
                } else {
                    decision = FilterDecision::Ignored {
                        matched_pattern: rule.raw.clone(),
                    };
                }
            }
        }
        decision
    }
}

#[derive(Debug, Default, Clone)]
pub struct GitignoreFilterFactory;

impl PathFilterFactoryPort for GitignoreFilterFactory {
    fn build_filter(
        &self,
        patterns: &[String],
        ignore_file: Option<&Path>,
    ) -> DomainResult<Box<dyn PathFilterPort>> {
        let matcher = GitignoreMatcher::from_patterns_and_file(patterns, ignore_file)?;
        Ok(Box::new(matcher))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_node_modules_and_target_and_honors_bang_exemptions() {
        let patterns = vec![
            "/node_modules".to_string(),
            "/target/".to_string(),
            "*.log".to_string(),
            "!/target/release/wbak.exe".to_string(),
            "!important.log".to_string(),
        ];
        let matcher = GitignoreMatcher::from_patterns_and_file(&patterns, None).unwrap();
        let root = Path::new(r"C:\Projects\my_app");

        // 1. /node_modules is ignored
        assert_eq!(
            matcher.evaluate(root, Path::new(r"C:\Projects\my_app\node_modules"), true),
            FilterDecision::Ignored {
                matched_pattern: "/node_modules".to_string()
            }
        );
        assert_eq!(
            matcher.evaluate(
                root,
                Path::new(r"C:\Projects\my_app\node_modules\react\index.js"),
                false
            ),
            FilterDecision::Ignored {
                matched_pattern: "/node_modules".to_string()
            }
        );

        // 2. /target/debug is ignored, but !/target/release/wbak.exe is exempted!
        assert_eq!(
            matcher.evaluate(
                root,
                Path::new(r"C:\Projects\my_app\target\debug\wbak.exe"),
                false
            ),
            FilterDecision::Ignored {
                matched_pattern: "/target/".to_string()
            }
        );
        assert_eq!(
            matcher.evaluate(
                root,
                Path::new(r"C:\Projects\my_app\target\release\wbak.exe"),
                false
            ),
            FilterDecision::Exempted {
                matched_pattern: "!/target/release/wbak.exe".to_string()
            }
        );

        // 3. *.log is ignored, !important.log is exempted
        assert_eq!(
            matcher.evaluate(root, Path::new(r"C:\Projects\my_app\debug.log"), false),
            FilterDecision::Ignored {
                matched_pattern: "*.log".to_string()
            }
        );
        assert_eq!(
            matcher.evaluate(
                root,
                Path::new(r"C:\Projects\my_app\logs\important.log"),
                false
            ),
            FilterDecision::Exempted {
                matched_pattern: "!important.log".to_string()
            }
        );

        // 4. Normal source files are included
        assert_eq!(
            matcher.evaluate(root, Path::new(r"C:\Projects\my_app\src\main.rs"), false),
            FilterDecision::Included
        );
    }
}
