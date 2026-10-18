use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use wbak_domain::ConflictPolicy;

#[derive(Debug, Parser)]
#[command(
    name = "wbak",
    version,
    about = "Windows Backup & Enterprise Reproducible Environment Tool (CLI + GUI)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize starter `wbak.toml` profile and `.wbakignore` file
    Init {
        /// Output path for the profile configuration
        #[arg(short, long, default_value = "wbak.toml")]
        profile: PathBuf,

        /// Output path for the ignore file
        #[arg(short, long, default_value = ".wbakignore")]
        ignore: PathBuf,
    },

    /// Create or incrementally update a deduplicated, compressed `.wbak` backup archive
    #[command(visible_alias = "update")]
    Backup {
        /// Path to a `wbak.toml` profile file (optional if `--path` or `--reg` is given)
        #[arg(short, long)]
        profile: Option<PathBuf>,

        /// Output `.wbak` archive file path (if it already exists, performs a fast incremental update unless `--full` is set)
        #[arg(short, long, default_value = "backup.wbak")]
        output: PathBuf,

        /// File or directory paths to include (repeatable; supports `.`, `C:\Users\john\Documents`, `${USERPROFILE}`, etc.)
        #[arg(short = 'd', long = "path", visible_alias = "dir")]
        paths: Vec<String>,

        /// Additional Windows Registry keys to include (e.g. `HKCU\Environment`, `HKCU\Console`)
        #[arg(long = "reg")]
        registry_keys: Vec<String>,

        /// Path to a `.wbakignore` file
        #[arg(long)]
        ignore_file: Option<PathBuf>,

        /// Inline ignore patterns (supports `/node_modules`, `/target`, and `!` exemptions)
        #[arg(short = 'x', long = "exclude")]
        exclude_patterns: Vec<String>,

        /// Capture installed `winget` package manifest
        #[arg(long)]
        winget: bool,

        /// Encrypt the entire archive (note: `.ssh` and secret files are encrypted by default)
        #[arg(short, long)]
        encrypt: bool,

        /// Passphrase for encrypting `.ssh`/sensitive files or the full archive
        #[arg(long)]
        password: Option<String>,

        /// Explicitly allow saving `.ssh` keys and secrets without encryption (not recommended)
        #[arg(long)]
        allow_unencrypted_secrets: bool,

        /// Force a full archive rebuild from scratch instead of an incremental tail update
        #[arg(long)]
        full: bool,

        /// Retain files deleted on disk in the archive manifest during an incremental update
        #[arg(long)]
        keep_deleted: bool,

        /// Automatically compact dead/superseded chunks after an incremental update
        #[arg(long)]
        compact: bool,
    },

    /// Reclaim dead space from deleted or modified files without re-compressing live chunks
    Compact {
        /// Path to the `.wbak` archive to compact
        archive: PathBuf,

        /// Passphrase if the full archive manifest is encrypted
        #[arg(long)]
        password: Option<String>,
    },

    /// Restore files, registry settings, and optional `winget` packages from a `.wbak` archive
    Restore {
        /// Path to the `.wbak` archive to restore
        archive: PathBuf,

        /// Extract files into a custom directory instead of their original/tokenized system locations
        #[arg(short, long)]
        target_dir: Option<PathBuf>,

        /// Restore only files (skip registry and winget)
        #[arg(long)]
        files_only: bool,

        /// Restore only Windows Registry settings (skip files and winget)
        #[arg(long)]
        reg_only: bool,

        /// Also reinstall captured `winget` packages
        #[arg(long)]
        winget: bool,

        /// Also restore captured User environment variables
        #[arg(long)]
        env_vars: bool,

        /// Simulate the restore without modifying disk or registry
        #[arg(long)]
        dry_run: bool,

        /// Conflict resolution policy for existing files
        #[arg(long, value_enum, default_value_t = CliConflictPolicy::Overwrite)]
        conflict: CliConflictPolicy,

        /// Only restore paths containing this substring
        #[arg(short, long)]
        filter: Option<String>,

        /// Passphrase for decrypting `.ssh`/secret chunks or encrypted archives
        #[arg(long)]
        password: Option<String>,
    },

    /// Inspect archive contents, deduplication savings, registry keys, and `winget` packages
    Inspect {
        /// Path to the `.wbak` archive
        archive: PathBuf,

        /// Passphrase if the full archive manifest is encrypted
        #[arg(long)]
        password: Option<String>,

        /// Output raw manifest as JSON
        #[arg(long)]
        json: bool,
    },

    /// Compare a `.wbak` archive against the live Windows filesystem, Registry, and `winget` packages
    Diff {
        /// Path to the `.wbak` archive
        archive: PathBuf,

        /// Passphrase if the full archive manifest is encrypted
        #[arg(long)]
        password: Option<String>,
    },

    /// Verify BLAKE3 cryptographic hashes and AEAD tags of all chunks in an archive
    Verify {
        /// Path to the `.wbak` archive
        archive: PathBuf,

        /// Passphrase to also verify encrypted secret chunks
        #[arg(long)]
        password: Option<String>,
    },

    /// Preview `.wbakignore` matching (shows Included, Ignored, `!` Exempted, and 🔒 Secret files)
    Preview {
        /// Optional `wbak.toml` profile to preview
        #[arg(short, long)]
        profile: Option<PathBuf>,

        /// Paths to scan
        #[arg(short = 'd', long = "path", visible_alias = "dir")]
        paths: Vec<String>,

        /// `.wbakignore` file to evaluate
        #[arg(long)]
        ignore_file: Option<PathBuf>,

        /// Additional ignore or `!` exemption patterns
        #[arg(short = 'x', long = "exclude")]
        exclude_patterns: Vec<String>,
    },

    /// Launch the graphical user interface
    Gui,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliConflictPolicy {
    Overwrite,
    Skip,
    Backup,
}

impl From<CliConflictPolicy> for ConflictPolicy {
    fn from(value: CliConflictPolicy) -> Self {
        match value {
            CliConflictPolicy::Overwrite => ConflictPolicy::Overwrite,
            CliConflictPolicy::Skip => ConflictPolicy::SkipExisting,
            CliConflictPolicy::Backup => ConflictPolicy::BackupExisting,
        }
    }
}
