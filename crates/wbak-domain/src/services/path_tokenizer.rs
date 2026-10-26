use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Bidirectional converter between physical Windows paths (`C:\Users\alice\AppData\Roaming\...`)
/// and portable tokenized paths (`${APPDATA}/...`, `${USERPROFILE}/...`) for enterprise reproducibility.
#[derive(Debug, Clone)]
pub struct PortablePathTokenizer {
    /// Ordered list of `(token_name, normalized_physical_prefix)` sorted longest-prefix first.
    mappings: Vec<(String, String)>,
}

impl PortablePathTokenizer {
    /// Creates a tokenizer populated from the current process's Windows environment variables.
    pub fn from_process_env() -> Self {
        let mut vars = BTreeMap::new();
        for key in [
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
            "PROGRAMDATA",
            "PUBLIC",
        ] {
            if let Ok(val) = std::env::var(key)
                && !val.trim().is_empty()
            {
                vars.insert(key.to_string(), val);
            }
        }
        Self::from_map(&vars)
    }

    /// Creates a tokenizer from an explicit variable map (e.g. `USERPROFILE -> C:\Users\alice`).
    pub fn from_map(vars: &BTreeMap<String, String>) -> Self {
        let mut mappings: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (format!("${{{k}}}"), normalize_slashes(v)))
            .collect();

        // Sort longest physical path first so `${APPDATA}` (`C:/Users/alice/AppData/Roaming`)
        // matches before `${USERPROFILE}` (`C:/Users/alice`).
        mappings.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

        Self { mappings }
    }

    /// Converts a physical path into a portable logical path with forward slashes.
    pub fn tokenize(&self, physical_path: &Path) -> String {
        let normalized = normalize_slashes(&physical_path.to_string_lossy());
        let normalized_lower = normalized.to_ascii_lowercase();

        for (token, prefix) in &self.mappings {
            let prefix_lower = prefix.to_ascii_lowercase();
            if normalized_lower == prefix_lower {
                return token.clone();
            }
            if normalized_lower.starts_with(&prefix_lower) {
                let rest = &normalized[prefix.len()..];
                if rest.starts_with('/') {
                    return format!("{token}{rest}");
                }
            }
        }

        normalized
    }

    /// Expands a portable logical path (`${USERPROFILE}/.ssh/id_ed25519`) to a physical `PathBuf`
    /// on the current target Windows machine.
    pub fn detokenize(&self, logical_path: &str) -> PathBuf {
        let mut resolved = normalize_slashes(logical_path);
        for (token, prefix) in &self.mappings {
            if resolved == *token {
                resolved = prefix.clone();
                break;
            } else if let Some(rest) = resolved.strip_prefix(token)
                && rest.starts_with('/')
            {
                resolved = format!("{prefix}{rest}");
                break;
            }
        }

        #[cfg(windows)]
        {
            PathBuf::from(resolved.replace('/', "\\"))
        }
        #[cfg(not(windows))]
        {
            PathBuf::from(resolved)
        }
    }
}

pub fn normalize_slashes(path: &str) -> String {
    let mut s = path.replace('\\', "/");
    // Strip Windows extended-length path prefix if present
    if let Some(stripped) = s.strip_prefix("//?/") {
        s = stripped.to_string();
    }
    while s.ends_with('/') && s.len() > 3 {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tokenizer() -> PortablePathTokenizer {
        let mut vars = BTreeMap::new();
        vars.insert("USERPROFILE".to_string(), r"C:\Users\Alice".to_string());
        vars.insert(
            "APPDATA".to_string(),
            r"C:\Users\Alice\AppData\Roaming".to_string(),
        );
        vars.insert(
            "LOCALAPPDATA".to_string(),
            r"C:\Users\Alice\AppData\Local".to_string(),
        );
        PortablePathTokenizer::from_map(&vars)
    }

    #[test]
    fn longest_prefix_wins_during_tokenization() {
        let tok = sample_tokenizer();
        let p1 = Path::new(r"C:\Users\Alice\AppData\Roaming\Code\User\settings.json");
        assert_eq!(tok.tokenize(p1), "${APPDATA}/Code/User/settings.json");

        let p2 = Path::new(r"C:\Users\Alice\.ssh\id_ed25519");
        assert_eq!(tok.tokenize(p2), "${USERPROFILE}/.ssh/id_ed25519");
    }

    #[test]
    fn case_insensitive_matching_and_cross_user_detokenization() {
        let tok_alice = sample_tokenizer();
        let logical = tok_alice.tokenize(Path::new(r"c:\users\alice\.ssh\config"));
        assert_eq!(logical, "${USERPROFILE}/.ssh/config");

        let mut bob_vars = BTreeMap::new();
        bob_vars.insert("USERPROFILE".to_string(), r"D:\Users\Bob".to_string());
        let tok_bob = PortablePathTokenizer::from_map(&bob_vars);

        let restored = tok_bob.detokenize(&logical);
        assert_eq!(
            normalize_slashes(&restored.to_string_lossy()),
            "D:/Users/Bob/.ssh/config"
        );
    }
}
