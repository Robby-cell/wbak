use wbak_domain::{DomainError, DomainResult};

pub const HEADER_MAGIC: &[u8; 8] = b"WBAK\x00\x01\x00\x00";
pub const FOOTER_MAGIC: &[u8; 8] = b"WBAKEND\x01";
pub const FORMAT_VERSION: u16 = 1;

pub const HEADER_SIZE: usize = 32;
pub const FOOTER_SIZE: usize = 36;

pub const FLAG_FULL_ARCHIVE_ENCRYPTED: u16 = 1 << 0;
pub const FLAG_HAS_ENCRYPTED_SECRETS: u16 = 1 << 1;

/// Default maximum uncompressed chunk size (4 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveHeader {
    pub version: u16,
    pub flags: u16,
    pub kdf_salt: [u8; 16],
}

impl ArchiveHeader {
    pub fn is_full_encrypted(&self) -> bool {
        (self.flags & FLAG_FULL_ARCHIVE_ENCRYPTED) != 0
    }

    pub fn has_encrypted_secrets(&self) -> bool {
        (self.flags & FLAG_HAS_ENCRYPTED_SECRETS) != 0
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(HEADER_MAGIC);
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.flags.to_le_bytes());
        buf[12..28].copy_from_slice(&self.kdf_salt);
        buf
    }

    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> DomainResult<Self> {
        if &buf[0..8] != HEADER_MAGIC {
            return Err(DomainError::StorageError(
                "Invalid .wbak archive: header magic mismatch".to_string(),
            ));
        }
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        if version != FORMAT_VERSION {
            return Err(DomainError::StorageError(format!(
                "Unsupported .wbak archive version: {version}"
            )));
        }
        let flags = u16::from_le_bytes([buf[10], buf[11]]);
        let mut kdf_salt = [0u8; 16];
        kdf_salt.copy_from_slice(&buf[12..28]);

        Ok(Self {
            version,
            flags,
            kdf_salt,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveFooter {
    pub manifest_offset: u64,
    pub manifest_stored_size: u64,
    pub manifest_nonce: [u8; 12],
}

impl ArchiveFooter {
    pub fn to_bytes(&self) -> [u8; FOOTER_SIZE] {
        let mut buf = [0u8; FOOTER_SIZE];
        buf[0..8].copy_from_slice(&self.manifest_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.manifest_stored_size.to_le_bytes());
        buf[16..28].copy_from_slice(&self.manifest_nonce);
        buf[28..36].copy_from_slice(FOOTER_MAGIC);
        buf
    }

    pub fn from_bytes(buf: &[u8; FOOTER_SIZE]) -> DomainResult<Self> {
        if &buf[28..36] != FOOTER_MAGIC {
            return Err(DomainError::StorageError(
                "Corrupted or incomplete .wbak archive: footer magic mismatch".to_string(),
            ));
        }
        let mut off = [0u8; 8];
        off.copy_from_slice(&buf[0..8]);
        let mut sz = [0u8; 8];
        sz.copy_from_slice(&buf[8..16]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[16..28]);

        Ok(Self {
            manifest_offset: u64::from_le_bytes(off),
            manifest_stored_size: u64::from_le_bytes(sz),
            manifest_nonce: nonce,
        })
    }
}
