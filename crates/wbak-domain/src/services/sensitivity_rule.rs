use crate::entities::SensitivityLevel;
use crate::services::normalize_slashes;

/// Default glob patterns for files that MUST be encrypted by default (e.g. `.ssh` keys, GPG keys, certificates).
pub fn default_sensitive_patterns() -> Vec<String> {
    vec![
        "**/.ssh/**".to_string(),
        "**/.gnupg/**".to_string(),
        "**/.aws/credentials".to_string(),
        "**/.kube/config".to_string(),
        "**/*.pem".to_string(),
        "**/*.key".to_string(),
        "**/*.pfx".to_string(),
        "**/*.p12".to_string(),
        "**/*.kdbx".to_string(),
        "**/id_rsa*".to_string(),
        "**/id_ed25519*".to_string(),
        "**/id_ecdsa*".to_string(),
        "**/id_dsa*".to_string(),
        "**/.npmrc".to_string(),
        "**/.pypirc".to_string(),
    ]
}

/// Pure domain check for whether a path belongs to an `.ssh` directory or private key
/// requiring restricted Windows NTFS ACL permissions upon restoration.
pub fn is_ssh_path(logical_or_physical_path: &str) -> bool {
    let norm = normalize_slashes(logical_or_physical_path).to_ascii_lowercase();
    norm.contains("/.ssh/") || norm.ends_with("/.ssh")
}

/// Built-in fallback classifier in the domain layer.
pub fn classify_builtin_sensitivity(logical_or_physical_path: &str) -> SensitivityLevel {
    let norm = normalize_slashes(logical_or_physical_path).to_ascii_lowercase();
    if is_ssh_path(&norm)
        || norm.contains("/.gnupg/")
        || norm.ends_with("/.aws/credentials")
        || norm.ends_with("/.kube/config")
        || norm.ends_with(".pem")
        || norm.ends_with(".key")
        || norm.ends_with(".pfx")
        || norm.ends_with(".p12")
        || norm.ends_with(".kdbx")
        || norm.ends_with("/.npmrc")
        || norm.ends_with("/.pypirc")
    {
        SensitivityLevel::Secret
    } else {
        SensitivityLevel::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_and_private_keys_are_classified_secret() {
        assert_eq!(
            classify_builtin_sensitivity("${USERPROFILE}/.ssh/id_ed25519"),
            SensitivityLevel::Secret
        );
        assert_eq!(
            classify_builtin_sensitivity(r"C:\Users\alice\.ssh\config"),
            SensitivityLevel::Secret
        );
        assert_eq!(
            classify_builtin_sensitivity(r"C:\certs\corp-client.pfx"),
            SensitivityLevel::Secret
        );
        assert_eq!(
            classify_builtin_sensitivity("${APPDATA}/Code/User/settings.json"),
            SensitivityLevel::Public
        );
        assert!(is_ssh_path("${USERPROFILE}/.ssh/id_rsa"));
    }
}
