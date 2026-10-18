use thiserror::Error;

pub type DomainResult<T> = Result<T, DomainError>;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Invalid profile configuration: {0}")]
    InvalidProfile(String),

    #[error("Path resolution error: {0}")]
    PathError(String),

    #[error("Filter pattern error: {0}")]
    FilterError(String),

    #[error("Encryption required for sensitive files ({0}), but no passphrase was provided")]
    PassphraseRequired(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Archive format or storage error: {0}")]
    StorageError(String),

    #[error("Filesystem operation failed: {0}")]
    FilesystemError(String),

    #[error("Registry operation failed: {0}")]
    RegistryError(String),

    #[error("Environment / package manager operation failed: {0}")]
    EnvironmentError(String),

    #[error("Integrity verification failed for '{path}': expected {expected}, actual {actual}")]
    IntegrityMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("Operation cancelled by user")]
    Cancelled,
}
