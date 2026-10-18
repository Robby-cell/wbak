use std::collections::BTreeMap;
use std::sync::Arc;

use tempfile::tempdir;
use winreg::enums::*;
use winreg::RegKey;

use wbak_app::{CreateBackupRequest, RestoreBackupRequest, WbakApplication};
use wbak_crypto::WbakCryptoProvider;
use wbak_domain::{
    default_sensitive_patterns, ConflictPolicy, DomainError, DriftStatus, EnvironmentBackupConfig,
    FileBackupConfig, NoopProgressSink, PortablePathTokenizer, ProfileConfig, ProfileMetadata,
    RegistryBackupConfig, SecurityPolicy, SensitivityLevel,
};
use wbak_filter::{GitignoreFilterFactory, GlobSensitivityClassifier};
use wbak_storage::{WbakArchiveReader, WbakArchiveWriter};
use wbak_win::{
    WindowsEnvironmentRepository, WindowsFileRestorer, WindowsFileScanner,
    WindowsRegistryRepository,
};

#[test]
fn end_to_end_backup_ignore_bang_exemption_ssh_encryption_diff_and_restore() {
    let temp = tempdir().unwrap();
    let fake_user_profile = temp.path().join("Users").join("Alice");
    let ssh_dir = fake_user_profile.join(".ssh");
    let proj_dir = fake_user_profile.join("dev").join("app");
    let node_modules_dir = proj_dir.join("node_modules").join("left-pad");
    let target_debug_dir = proj_dir.join("target").join("debug");
    let target_release_dir = proj_dir.join("target").join("release");

    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::create_dir_all(proj_dir.join("src")).unwrap();
    std::fs::create_dir_all(&node_modules_dir).unwrap();
    std::fs::create_dir_all(&target_debug_dir).unwrap();
    std::fs::create_dir_all(&target_release_dir).unwrap();

    // 1. Populate files: .ssh key, source code, node_modules, target/debug, and ! exempted target/release binary
    let ssh_private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nALICE_SUPER_SECRET_KEY\n";
    std::fs::write(ssh_dir.join("id_ed25519"), ssh_private_key).unwrap();
    std::fs::write(proj_dir.join("src").join("main.rs"), b"fn main() {}").unwrap();
    std::fs::write(node_modules_dir.join("index.js"), b"module.exports = {};").unwrap();
    std::fs::write(target_debug_dir.join("app.exe"), b"debug-binary").unwrap();
    std::fs::write(target_release_dir.join("keep-tool.exe"), b"release-kept").unwrap();

    // 2. Populate a temporary test Registry key under HKCU
    let reg_subkey = r"Software\wbak_e2e_integration_test";
    let reg_full_key = format!(r"HKCU\{reg_subkey}");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (test_reg, _) = hkcu.create_subkey(reg_subkey).unwrap();
    test_reg
        .set_value("EnvironmentProfile", &"enterprise-prod")
        .unwrap();
    test_reg.set_value("BuildThreads", &8u32).unwrap();

    // 3. Configure application with custom USERPROFILE mapping
    let mut env_map = BTreeMap::new();
    env_map.insert(
        "USERPROFILE".to_string(),
        fake_user_profile.to_string_lossy().to_string(),
    );
    let tokenizer = PortablePathTokenizer::from_map(&env_map);
    let sensitivity_classifier =
        Arc::new(GlobSensitivityClassifier::new(&default_sensitive_patterns(), true).unwrap());
    let crypto = Arc::new(WbakCryptoProvider::fast_for_tests());

    let app = WbakApplication::new(
        Arc::new(GitignoreFilterFactory),
        Arc::new(WindowsFileScanner::new(
            tokenizer.clone(),
            sensitivity_classifier,
        )),
        Arc::new(WindowsFileRestorer::new()),
        Arc::new(WindowsRegistryRepository::new()),
        Arc::new(WindowsEnvironmentRepository::new()),
        Arc::new(WbakArchiveWriter::new(crypto.clone())),
        Arc::new(WbakArchiveReader::new(crypto.clone())),
        crypto,
        tokenizer,
    );

    let profile = ProfileConfig {
        profile: ProfileMetadata {
            name: "e2e-enterprise-profile".to_string(),
            description: "End-to-end test profile".to_string(),
            compression_level: 3,
        },
        security: SecurityPolicy {
            encrypt_full_archive: false,
            encrypt_sensitive_by_default: true,
            sensitive_patterns: default_sensitive_patterns(),
        },
        files: FileBackupConfig {
            include: vec![
                "${USERPROFILE}/.ssh".to_string(),
                "${USERPROFILE}/dev/app".to_string(),
            ],
            ignore_file: None,
            ignore_patterns: vec![
                "**/node_modules/".to_string(),
                "/target/".to_string(),
                "!/target/release/keep-tool.exe".to_string(),
            ],
            respect_local_ignore_files: true,
        },
        registry: RegistryBackupConfig {
            include_keys: vec![reg_full_key.clone()],
            exclude_patterns: vec![],
        },
        environment: EnvironmentBackupConfig {
            capture_winget: false,
            capture_env_vars: false,
        },
    };

    let archive_path = temp.path().join("enterprise.wbak");

    // 4. Because `.ssh/id_ed25519` is included, backup WITHOUT a passphrase must be rejected by default!
    let err = app
        .create_backup(
            CreateBackupRequest {
                profile: profile.clone(),
                output_archive: archive_path.clone(),
                passphrase: None,
                allow_unencrypted_secrets: false,
            },
            &NoopProgressSink,
            None,
        )
        .unwrap_err();
    assert!(matches!(err, DomainError::PassphraseRequired(_)));

    // 5. Run backup WITH a passphrase
    let manifest = app
        .create_backup(
            CreateBackupRequest {
                profile,
                output_archive: archive_path.clone(),
                passphrase: Some("enterprise-pass-999".to_string()),
                allow_unencrypted_secrets: false,
            },
            &NoopProgressSink,
            None,
        )
        .unwrap();

    let logical_paths: Vec<&str> = manifest
        .files
        .iter()
        .map(|f| f.logical_path.as_str())
        .collect();

    // Verify `.ssh/id_ed25519`, `src/main.rs`, and `!`-exempted `target/release/keep-tool.exe` are present
    assert!(logical_paths.contains(&"${USERPROFILE}/.ssh/id_ed25519"));
    assert!(logical_paths.contains(&"${USERPROFILE}/dev/app/src/main.rs"));
    assert!(logical_paths.contains(&"${USERPROFILE}/dev/app/target/release/keep-tool.exe"));

    // Verify `node_modules` and `target/debug/app.exe` were ignored!
    assert!(!logical_paths
        .iter()
        .any(|p| p.contains("node_modules") || p.contains("target/debug")));

    // Verify `.ssh/id_ed25519` is flagged as `SensitivityLevel::Secret`
    let ssh_node = manifest
        .files
        .iter()
        .find(|f| f.logical_path == "${USERPROFILE}/.ssh/id_ed25519")
        .unwrap();
    assert_eq!(ssh_node.sensitivity, SensitivityLevel::Secret);

    // 6. Simulate system drift: delete `keep-tool.exe` and change the Registry value
    std::fs::remove_file(target_release_dir.join("keep-tool.exe")).unwrap();
    test_reg
        .set_value("EnvironmentProfile", &"drifted-value")
        .unwrap();

    let drift = app.diff_system(&archive_path, None).unwrap();
    assert_eq!(drift.changed_files_count(), 1);
    assert_eq!(drift.changed_registry_count(), 1);
    assert!(drift.files.iter().any(|f| {
        f.logical_path.ends_with("keep-tool.exe") && f.status == DriftStatus::MissingOnSystem
    }));

    // 7. Restore the archive and verify both the missing file and the registry value are restored!
    let summary = app
        .restore_backup(
            RestoreBackupRequest {
                archive_path: archive_path.clone(),
                passphrase: Some("enterprise-pass-999".to_string()),
                target_dir_override: None,
                restore_files: true,
                restore_registry: true,
                restore_winget: false,
                restore_env_vars: false,
                dry_run: false,
                conflict_policy: ConflictPolicy::Overwrite,
                path_filter: None,
            },
            &NoopProgressSink,
            None,
        )
        .unwrap();

    assert!(summary.files_restored >= 3);
    assert!(summary.secret_acls_hardened >= 1);
    assert!(summary.rollback_reg_file.as_ref().unwrap().exists());

    // Verify `keep-tool.exe` is back on disk and Registry value is restored to `enterprise-prod`
    assert_eq!(
        std::fs::read(target_release_dir.join("keep-tool.exe")).unwrap(),
        b"release-kept"
    );
    let restored_reg_val: String = test_reg.get_value("EnvironmentProfile").unwrap();
    assert_eq!(restored_reg_val, "enterprise-prod");

    // Clean up test registry key
    let _ = hkcu.delete_subkey_all(reg_subkey);
}
