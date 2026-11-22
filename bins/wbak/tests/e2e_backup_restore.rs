use std::collections::BTreeMap;
use std::sync::Arc;

use tempfile::tempdir;
use winreg::RegKey;
use winreg::enums::*;

use wbak_app::{CreateBackupRequest, RestoreBackupRequest, WbakApplication};
use wbak_crypto::WbakCryptoProvider;
use wbak_domain::{
    ConflictPolicy, DomainError, DriftStatus, EnvironmentBackupConfig, FileBackupConfig,
    NoopProgressSink, PortablePathTokenizer, ProfileConfig, ProfileMetadata, RegistryBackupConfig,
    SecurityPolicy, SensitivityLevel, default_sensitive_patterns,
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
                force_full_rebuild: false,
                keep_deleted: false,
                compact_after_update: false,
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
                profile: profile.clone(),
                output_archive: archive_path.clone(),
                passphrase: Some("enterprise-pass-999".to_string()),
                allow_unencrypted_secrets: false,
                force_full_rebuild: false,
                keep_deleted: false,
                compact_after_update: false,
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
    assert!(
        !logical_paths
            .iter()
            .any(|p| p.contains("node_modules") || p.contains("target/debug"))
    );

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

    // 8. Incremental update + deletion + compaction:
    // Delete `keep-tool.exe` and modify `src/main.rs`, then run incremental backup on the existing archive.
    std::fs::remove_file(target_release_dir.join("keep-tool.exe")).unwrap();
    std::fs::write(
        proj_dir.join("src").join("main.rs"),
        b"fn main() { println!(\"v2\"); }",
    )
    .unwrap();

    let updated_manifest = app
        .create_backup(
            CreateBackupRequest {
                profile,
                output_archive: archive_path.clone(),
                passphrase: Some("enterprise-pass-999".to_string()),
                allow_unencrypted_secrets: false,
                force_full_rebuild: false,
                keep_deleted: false,
                compact_after_update: false,
            },
            &NoopProgressSink,
            None,
        )
        .unwrap();

    // Deleted `keep-tool.exe` must no longer be in the manifest, and dead chunks should be tracked
    assert!(
        !updated_manifest
            .files
            .iter()
            .any(|f| f.logical_path.ends_with("keep-tool.exe"))
    );
    assert!(updated_manifest.stats.reclaimable_chunks >= 2);

    // Compact the archive to garbage-collect dead chunks without re-compressing live chunks
    let size_before_compact = std::fs::metadata(&archive_path).unwrap().len();
    let compacted_manifest = app
        .compact_archive(
            &archive_path,
            Some("enterprise-pass-999"),
            &NoopProgressSink,
        )
        .unwrap();
    let size_after_compact = std::fs::metadata(&archive_path).unwrap().len();
    assert_eq!(compacted_manifest.stats.reclaimable_chunks, 0);
    assert_eq!(compacted_manifest.stats.reclaimable_bytes, 0);
    assert!(size_after_compact < size_before_compact);

    // 9. Create a folder `${USERPROFILE}/Files/MyImages` in the archive and drag-and-drop a new file into it
    let _ = app
        .create_directory_in_archive(
            &archive_path,
            "${USERPROFILE}/Files/MyImages",
            Some("enterprise-pass-999"),
            &NoopProgressSink,
        )
        .unwrap();

    let dropped_photo_path = temp.path().join("dropped-photo.png");
    let fake_png_bytes = b"\x89PNG\r\n\x1a\nFAKE_IN_MEMORY_PHOTO_PAYLOAD";
    std::fs::write(&dropped_photo_path, fake_png_bytes).unwrap();

    let (injected_manifest, new_mem_map) = app
        .inject_paths_into_archive(
            &archive_path,
            "${USERPROFILE}/Files/MyImages",
            std::slice::from_ref(&dropped_photo_path),
            Some("enterprise-pass-999"),
            true,
            &NoopProgressSink,
        )
        .unwrap();

    let expected_logical = "${USERPROFILE}/Files/MyImages/dropped-photo.png";
    assert_eq!(
        new_mem_map.get(expected_logical).map(|b| b.as_ref()),
        Some(fake_png_bytes.as_slice())
    );

    // Because `encrypt_added_files` was true, reading the injected file without passphrase must require passphrase!
    let no_pass_err = app
        .read_archive_file_bytes(&archive_path, &injected_manifest, expected_logical, None)
        .unwrap_err();
    assert!(matches!(no_pass_err, DomainError::PassphraseRequired(_)));

    // Reading into memory with passphrase succeeds without writing anything to disk
    let (node, read_bytes) = app
        .read_archive_file_bytes(
            &archive_path,
            &injected_manifest,
            "dropped-photo.png",
            Some("enterprise-pass-999"),
        )
        .unwrap();
    assert_eq!(node.logical_path, expected_logical);
    assert_eq!(read_bytes, fake_png_bytes);

    let preloaded = app
        .preload_archive_files_in_memory(
            &archive_path,
            &injected_manifest,
            Some("enterprise-pass-999"),
            &NoopProgressSink,
        )
        .unwrap();
    assert_eq!(
        preloaded.get(expected_logical).map(|b| b.as_ref()),
        Some(fake_png_bytes.as_slice())
    );

    // 10. Rotate/change the archive passphrase from "enterprise-pass-999" to "new-rotated-pass-2026"
    let rekeyed_manifest = app
        .change_archive_passphrase(
            &archive_path,
            Some("enterprise-pass-999"),
            "new-rotated-pass-2026",
            &NoopProgressSink,
        )
        .unwrap();

    // Old passphrase must no longer decrypt encrypted files; new passphrase must succeed!
    assert!(
        app.read_archive_file_bytes(
            &archive_path,
            &rekeyed_manifest,
            expected_logical,
            Some("enterprise-pass-999"),
        )
        .is_err()
    );
    let (_, rotated_read) = app
        .read_archive_file_bytes(
            &archive_path,
            &rekeyed_manifest,
            expected_logical,
            Some("new-rotated-pass-2026"),
        )
        .unwrap();
    assert_eq!(rotated_read, fake_png_bytes);

    // Also test changing password on a fully-encrypted archive
    let full_enc_archive = temp.path().join("full-enc.wbak");
    let full_enc_profile = ProfileConfig {
        profile: ProfileMetadata {
            name: "full-enc-test".to_string(),
            description: "Full archive encryption password rotation test".to_string(),
            compression_level: 3,
        },
        security: SecurityPolicy {
            encrypt_full_archive: true,
            encrypt_sensitive_by_default: true,
            sensitive_patterns: default_sensitive_patterns(),
        },
        files: FileBackupConfig {
            include: vec!["${USERPROFILE}/dev/app".to_string()],
            ignore_file: None,
            ignore_patterns: vec!["**/node_modules/".to_string()],
            respect_local_ignore_files: false,
        },
        registry: RegistryBackupConfig::default(),
        environment: EnvironmentBackupConfig::default(),
    };
    let _ = app
        .create_backup(
            CreateBackupRequest {
                profile: full_enc_profile,
                output_archive: full_enc_archive.clone(),
                passphrase: Some("enterprise-pass-999".to_string()),
                allow_unencrypted_secrets: false,
                force_full_rebuild: true,
                keep_deleted: false,
                compact_after_update: false,
            },
            &NoopProgressSink,
            None,
        )
        .unwrap();

    let rotated_full_manifest = app
        .change_archive_passphrase(
            &full_enc_archive,
            Some("enterprise-pass-999"),
            "new-rotated-pass-2026",
            &NoopProgressSink,
        )
        .unwrap();
    assert!(rotated_full_manifest.full_archive_encrypted);
    // Old password cannot read manifest; new password can!
    assert!(
        app.inspect_archive(&full_enc_archive, Some("enterprise-pass-999"))
            .is_err()
    );
    let inspected_new = app
        .inspect_archive(&full_enc_archive, Some("new-rotated-pass-2026"))
        .unwrap();
    assert!(inspected_new.full_archive_encrypted);

    // 11. Remove an entire directory from the archive and verify it is no longer present
    let (after_remove_manifest, removed_count) = app
        .remove_items_from_archive(
            &archive_path,
            &["${USERPROFILE}/Files/MyImages".to_string()],
            Some("new-rotated-pass-2026"),
            true,
            &NoopProgressSink,
        )
        .unwrap();
    assert!(removed_count >= 2); // MyImages directory node + dropped-photo.png
    assert!(
        !after_remove_manifest
            .files
            .iter()
            .any(|f| f.logical_path.contains("MyImages"))
    );
    app.verify_archive(
        &archive_path,
        Some("new-rotated-pass-2026"),
        &NoopProgressSink,
    )
    .unwrap();

    // Clean up test registry key
    let _ = hkcu.delete_subkey_all(reg_subkey);
}
