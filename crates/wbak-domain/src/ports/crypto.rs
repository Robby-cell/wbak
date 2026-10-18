use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::entities::ChunkId;
use crate::error::DomainResult;

/// 256-bit derived encryption key that automatically zeroizes its memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

/// Port for content hashing (BLAKE3) and authenticated encryption (`Argon2id` + `ChaCha20-Poly1305`).
pub trait CryptoProviderPort: Send + Sync {
    /// Computes the BLAKE3 hash of `data` as a `ChunkId`.
    fn hash_bytes(&self, data: &[u8]) -> ChunkId;

    /// Generates a cryptographically random 16-byte salt for `Argon2id`.
    fn generate_salt(&self) -> [u8; 16];

    /// Derives a 256-bit key from a passphrase and 16-byte salt using `Argon2id`.
    fn derive_key(&self, passphrase: &str, salt: &[u8; 16]) -> DomainResult<DerivedKey>;

    /// Encrypts plaintext using `ChaCha20-Poly1305` with associated data (`aad`),
    /// returning `(ciphertext_with_tag, 12_byte_nonce)`.
    fn encrypt(
        &self,
        key: &DerivedKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> DomainResult<(Vec<u8>, [u8; 12])>;

    /// Decrypts `ciphertext` using `ChaCha20-Poly1305` with the given 12-byte `nonce` and `aad`.
    fn decrypt(
        &self,
        key: &DerivedKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> DomainResult<Vec<u8>>;
}
