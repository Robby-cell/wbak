pub mod archive_reader;
pub mod archive_writer;
pub mod wire_format;

pub use archive_reader::*;
pub use archive_writer::*;
pub use wire_format::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::tempdir;

    use wbak_crypto::WbakCryptoProvider;
    use wbak_domain::{
        ArchiveBuildInput, ArchiveReaderPort, ArchiveWriterPort, ChunkId, DomainError, FileNode,
        FileNodeKind, NoopProgressSink, ProfileMetadata, RegistryTree, SensitivityLevel,
        WindowsFileAttributes,
    };

    use super::*;

    #[test]
    fn deduplicates_identical_files_and_encrypts_ssh_keys_by_default() {
        let dir = tempdir().unwrap();
        let file1_path = dir.path().join("config1.toml");
        let file2_path = dir.path().join("config2.toml");
        let ssh_key_path = dir.path().join("id_ed25519");
        let archive_path = dir.path().join("test.wbak");

        let shared_payload = b"enterprise_setting = true\nworkers = 8\n".repeat(100);
        let secret_ssh_payload = b"-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_DATA\n";

        std::fs::write(&file1_path, &shared_payload).unwrap();
        std::fs::write(&file2_path, &shared_payload).unwrap();
        std::fs::write(&ssh_key_path, secret_ssh_payload).unwrap();

        let crypto = Arc::new(WbakCryptoProvider::fast_for_tests());
        let writer = WbakArchiveWriter::new(crypto.clone());
        let reader = WbakArchiveReader::new(crypto);

        let files = vec![
            FileNode {
                logical_path: "${APPDATA}/app/config1.toml".to_string(),
                original_path: file1_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Public,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
            FileNode {
                logical_path: "${APPDATA}/app/config2.toml".to_string(),
                original_path: file2_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Public,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
            FileNode {
                logical_path: "${USERPROFILE}/.ssh/id_ed25519".to_string(),
                original_path: ssh_key_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Secret,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
        ];

        // 1. Attempting to write with a Secret `.ssh` file and NO passphrase must fail by default!
        let missing_pass_input = ArchiveBuildInput {
            profile: ProfileMetadata::default(),
            compression_level: 3,
            encrypt_full_archive: false,
            encrypt_secrets_by_default: true,
            passphrase: None,
            files: files.clone(),
            registry: RegistryTree::default(),
            winget: None,
            env_vars: None,
            previous_manifest: None,
        };
        let err = writer
            .write_archive(&archive_path, missing_pass_input, &NoopProgressSink)
            .unwrap_err();
        assert!(matches!(err, DomainError::PassphraseRequired(_)));

        // 2. Writing with a passphrase encrypts the `.ssh` chunk while deduplicating the two config files
        let valid_input = ArchiveBuildInput {
            profile: ProfileMetadata::default(),
            compression_level: 3,
            encrypt_full_archive: false,
            encrypt_secrets_by_default: true,
            passphrase: Some("vault-secret-123".to_string()),
            files,
            registry: RegistryTree::default(),
            winget: None,
            env_vars: None,
            previous_manifest: None,
        };
        let written_manifest = writer
            .write_archive(&archive_path, valid_input, &NoopProgressSink)
            .unwrap();

        // 3 files total, but only 2 unique chunks because config1.toml and config2.toml are identical!
        assert_eq!(written_manifest.stats.total_files, 3);
        assert_eq!(written_manifest.stats.unique_chunks, 2);
        assert_eq!(written_manifest.stats.secret_files_count, 1);
        assert!(written_manifest.has_encrypted_secrets);

        // 3. Manifest and Public files can be read WITHOUT a passphrase
        let loaded_manifest = reader.read_manifest(&archive_path, None).unwrap();
        let public_bytes = reader
            .extract_file_bytes(
                &archive_path,
                &loaded_manifest,
                &loaded_manifest.files[0],
                None,
            )
            .unwrap();
        assert_eq!(public_bytes, shared_payload);

        // 4. Extracting the `.ssh` private key WITHOUT a passphrase fails
        let ssh_node = &loaded_manifest.files[2];
        assert!(
            reader
                .extract_file_bytes(&archive_path, &loaded_manifest, ssh_node, None)
                .is_err()
        );

        // 5. Extracting the `.ssh` private key WITH the passphrase succeeds and verifies BLAKE3 hash
        let ssh_bytes = reader
            .extract_file_bytes(
                &archive_path,
                &loaded_manifest,
                ssh_node,
                Some("vault-secret-123"),
            )
            .unwrap();
        assert_eq!(ssh_bytes, secret_ssh_payload);
    }

    #[test]
    fn incremental_tail_append_skips_unchanged_files_handles_deletions_and_compacts() {
        let dir = tempdir().unwrap();
        let unchanged_path = dir.path().join("unchanged.bin");
        let modified_path = dir.path().join("modified.bin");
        let deleted_path = dir.path().join("to_delete.bin");
        let archive_path = dir.path().join("inc.wbak");

        std::fs::write(&unchanged_path, b"UNCHANGED_PAYLOAD_1111111111").unwrap();
        std::fs::write(&modified_path, b"MODIFIED_V1_PAYLOAD_22222222").unwrap();
        std::fs::write(&deleted_path, b"DELETED_PAYLOAD_333333333333").unwrap();

        let crypto = Arc::new(WbakCryptoProvider::fast_for_tests());
        let writer = WbakArchiveWriter::new(crypto.clone());
        let reader = WbakArchiveReader::new(crypto);

        let initial_files = vec![
            FileNode {
                logical_path: "unchanged.bin".to_string(),
                original_path: unchanged_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Public,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
            FileNode {
                logical_path: "modified.bin".to_string(),
                original_path: modified_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Public,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
            FileNode {
                logical_path: "to_delete.bin".to_string(),
                original_path: deleted_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Public,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
        ];

        let m1 = writer
            .write_archive(
                &archive_path,
                ArchiveBuildInput {
                    profile: ProfileMetadata::default(),
                    compression_level: 3,
                    encrypt_full_archive: false,
                    encrypt_secrets_by_default: true,
                    passphrase: None,
                    files: initial_files,
                    registry: RegistryTree::default(),
                    winget: None,
                    env_vars: None,
                    previous_manifest: None,
                },
                &NoopProgressSink,
            )
            .unwrap();

        assert_eq!(m1.stats.total_files, 3);
        assert_eq!(m1.stats.unique_chunks, 3);
        assert_eq!(m1.stats.reclaimable_chunks, 0);

        // Prove that unchanged.bin is NOT read from disk during incremental update by deleting it from disk
        // while passing its pre-populated `FileNode` from `m1`!
        std::fs::remove_file(&unchanged_path).unwrap();
        // Modify `modified.bin` to V2
        std::fs::write(&modified_path, b"MODIFIED_V2_NEW_CONTENT_9999").unwrap();
        // `to_delete.bin` is omitted from the incremental file list (simulating file deletion)

        let inc_files = vec![
            m1.files[0].clone(), // unchanged.bin (pre-populated chunks & hash -> 0 disk reads!)
            FileNode {
                logical_path: "modified.bin".to_string(),
                original_path: modified_path.to_string_lossy().to_string(),
                kind: FileNodeKind::RegularFile {
                    size: 0,
                    chunks: vec![],
                    content_hash: ChunkId(String::new()),
                },
                sensitivity: SensitivityLevel::Public,
                attributes: WindowsFileAttributes::default(),
                modified_at: None,
                created_at: None,
            },
        ];

        let m2 = writer
            .write_archive(
                &archive_path,
                ArchiveBuildInput {
                    profile: ProfileMetadata::default(),
                    compression_level: 3,
                    encrypt_full_archive: false,
                    encrypt_secrets_by_default: true,
                    passphrase: None,
                    files: inc_files,
                    registry: RegistryTree::default(),
                    winget: None,
                    env_vars: None,
                    previous_manifest: Some(m1),
                },
                &NoopProgressSink,
            )
            .unwrap();

        // Now only 2 live files (`unchanged.bin` and `modified.bin` V2), and 2 reclaimable dead chunks
        // (from `modified.bin` V1 and deleted `to_delete.bin`)!
        assert_eq!(m2.stats.total_files, 2);
        assert_eq!(m2.stats.unique_chunks, 2);
        assert_eq!(m2.stats.reclaimable_chunks, 2);
        assert!(m2.stats.reclaimable_bytes > 0);

        // Both `unchanged.bin` and `modified.bin` V2 extract cleanly
        let extracted_unchanged = reader
            .extract_file_bytes(&archive_path, &m2, &m2.files[0], None)
            .unwrap();
        assert_eq!(extracted_unchanged, b"UNCHANGED_PAYLOAD_1111111111");

        let extracted_mod = reader
            .extract_file_bytes(&archive_path, &m2, &m2.files[1], None)
            .unwrap();
        assert_eq!(extracted_mod, b"MODIFIED_V2_NEW_CONTENT_9999");

        // Now run `compact_archive` to garbage-collect the 2 dead chunks
        let size_before_compact = std::fs::metadata(&archive_path).unwrap().len();
        let m3 = writer
            .compact_archive(&archive_path, None, &NoopProgressSink)
            .unwrap();
        let size_after_compact = std::fs::metadata(&archive_path).unwrap().len();

        assert_eq!(m3.stats.unique_chunks, 2);
        assert_eq!(m3.stats.reclaimable_chunks, 0);
        assert_eq!(m3.stats.reclaimable_bytes, 0);
        assert!(size_after_compact < size_before_compact);

        // Verify archive integrity after compaction
        reader
            .verify_archive(&archive_path, None, &NoopProgressSink)
            .unwrap();
    }
}
