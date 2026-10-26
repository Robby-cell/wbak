use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;

use wbak_domain::{ChunkId, CryptoProviderPort, DerivedKey, DomainError, DomainResult};

/// Production cryptographic adapter implementing `BLAKE3` hashing,
/// `Argon2id` password key derivation, and `ChaCha20-Poly1305` authenticated encryption.
#[derive(Debug, Clone)]
pub struct WbakCryptoProvider {
    /// Memory cost in KiB for Argon2id (default: 19456 KiB ~ 19 MiB, OWASP recommendation).
    argon2_m_cost: u32,
    /// Time cost (iterations) for Argon2id.
    argon2_t_cost: u32,
    /// Parallelism degree for Argon2id.
    argon2_p_cost: u32,
}

impl Default for WbakCryptoProvider {
    fn default() -> Self {
        Self {
            argon2_m_cost: 19_456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
        }
    }
}

impl WbakCryptoProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lightweight KDF parameters for fast unit testing.
    pub fn fast_for_tests() -> Self {
        Self {
            argon2_m_cost: 1024,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
        }
    }
}

impl CryptoProviderPort for WbakCryptoProvider {
    fn hash_bytes(&self, data: &[u8]) -> ChunkId {
        let hash = blake3::hash(data);
        ChunkId(hash.to_hex().to_string())
    }

    fn generate_salt(&self) -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    fn derive_key(&self, passphrase: &str, salt: &[u8; 16]) -> DomainResult<DerivedKey> {
        let params = Params::new(
            self.argon2_m_cost,
            self.argon2_t_cost,
            self.argon2_p_cost,
            Some(32),
        )
        .map_err(|e| DomainError::CryptoError(format!("Invalid Argon2id parameters: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| {
                DomainError::CryptoError(format!("Argon2id key derivation failed: {e}"))
            })?;

        Ok(DerivedKey(out))
    }

    fn encrypt(
        &self,
        key: &DerivedKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> DomainResult<(Vec<u8>, [u8; 12])> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| {
                DomainError::CryptoError(format!("ChaCha20-Poly1305 encrypt failed: {e}"))
            })?;

        Ok((ciphertext, nonce_bytes))
    }

    fn decrypt(
        &self,
        key: &DerivedKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> DomainResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
        let nonce_obj = Nonce::from_slice(nonce);

        cipher
            .decrypt(
                nonce_obj,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                DomainError::CryptoError(
                    "Decryption failed: invalid passphrase or corrupted encrypted chunk"
                        .to_string(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_and_chacha20_poly1305_roundtrip() {
        let provider = WbakCryptoProvider::fast_for_tests();
        let data = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI secret private key payload";
        let aad = b"chunk:id_ed25519";

        let chunk_id = provider.hash_bytes(data);
        assert_eq!(chunk_id.as_str().len(), 64);

        let salt = provider.generate_salt();
        let key = provider
            .derive_key("correct-horse-battery-staple", &salt)
            .unwrap();

        let (ciphertext, nonce) = provider.encrypt(&key, data, aad).unwrap();
        assert_ne!(ciphertext, data);

        let decrypted = provider.decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, data);

        // Wrong AAD or wrong password must fail authentication
        let wrong_key = provider.derive_key("wrong-password", &salt).unwrap();
        assert!(
            provider
                .decrypt(&wrong_key, &nonce, &ciphertext, aad)
                .is_err()
        );
        assert!(
            provider
                .decrypt(&key, &nonce, &ciphertext, b"tampered-aad")
                .is_err()
        );
    }
}
