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
        assert!(reader
            .extract_file_bytes(&archive_path, &loaded_manifest, ssh_node, None)
            .is_err());

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
}
