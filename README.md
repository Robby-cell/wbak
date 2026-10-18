# `wbak` — Windows Backup & Reproducible Environment Tool

`wbak` is a fast, single-binary Windows backup and environment provisioning tool written in Rust. It works in both **CLI mode** (for quick directory backups, scripting, and enterprise automation) and **native GUI mode** (for interactive selection, live `.wbakignore` testing, Registry browsing, and system drift analysis).

It can be used at **any scale**:
- **Single-Directory Backup**: Back up a single folder (such as `C:\Users\john\Documents` or `.` in your current working directory) with zero configuration files required.
- **Workstation Reinstall Backup**: Back up multiple user folders, app configs (`%APPDATA%`), `.ssh` keys, and Windows Registry settings into a single deduplicated `.wbak` archive.
- **Enterprise Reproducible Environments**: Stamp out identical developer or corporate workstations across different Windows machines and usernames using declarative `wbak.toml` profiles, portable path tokens (`${USERPROFILE}`, `${APPDATA}`), Registry snapshots, and `winget` package manifests.

---

## Key Features

- **Flexible Scope**: Back up a single folder, multiple directories, specific files, Windows Registry keys (`HKCU`, `HKLM`, `HKCR`, `HKU`, `HKCC`), `winget` package lists, or all of them together.
- **`.wbakignore` with `!` Exemptions**: Uses `.gitignore` syntax to exclude heavy build/cache directories (`/node_modules/`, `/target/`) while allowing `!` negation rules (e.g. `!/target/release/my-tool.exe`) to rescue specific files.
- **Content-Addressed Deduplication & Zstd Compression**: Splits files into content-addressed chunks hashed with **BLAKE3** and compressed with **Zstandard (`zstd`)**. Identical files or chunks are stored only once.
- **`.ssh` Keys & Secrets Encrypted by Default**: Automatically detects sensitive files (`.ssh/**`, `.gnupg/**`, `*.pem`, `*.key`, `*.pfx`, `.aws/credentials`, `.kube/config`) and encrypts their chunks with **`ChaCha20-Poly1305` + `Argon2id`** by default—even when the rest of the archive is unencrypted. On restore, `.ssh` private keys automatically receive strict owner-only Windows NTFS ACL permissions (`icacls`) so Windows OpenSSH accepts them immediately.
- **Safe Registry Restore**: Automatically exports a standard Windows `.reg` rollback file of existing Registry values before applying any Registry changes.
- **Instant Random-Access Inspection & System Diff**: Reads the archive index from the file footer in milliseconds without decompressing file chunks, and compares archives against the live Windows machine (`wbak diff`).

---

## Building

```powershell
cargo build --release
```

The standalone executable is produced at `target\release\wbak.exe`.

---

## Sample Usage

### 1. Backing Up a Single Directory (e.g. `C:\Users\john\Documents`)

You do **not** have to back up the whole system or write a profile file to back up a single folder. When you pass `--path` (or `-d` / `--dir`), `wbak` backs up **only** the path(s) you specify (no Registry keys or `winget` packages are included unless requested).

**Example A — You are currently inside `C:\Users\john\Documents`:**
```powershell
cd C:\Users\john\Documents

# Back up the current directory into my-docs.wbak
wbak backup --path . -o my-docs.wbak
```

**Example B — Backing up `C:\Users\john\Documents` from anywhere, with inline exclusions & `!` exemptions:**
```powershell
wbak backup `
  --path "C:\Users\john\Documents" `
  --exclude "/node_modules/" `
  --exclude "/target/" `
  --exclude "*.tmp" `
  --exclude "!/target/release/important-tool.exe" `
  -o C:\Backups\john-docs.wbak
```

**Example C — Using a local `.wbakignore` file inside `C:\Users\john\Documents`:**
If `C:\Users\john\Documents\.wbakignore` exists, `wbak` automatically respects it during traversal (or you can pass `--ignore-file path\to\.wbakignore` explicitly).

---

### 2. Restoring a Single Directory Backup

**Restore back to its original location (or equivalent `${USERPROFILE}\Documents` on a new Windows install):**
```powershell
wbak restore C:\Backups\john-docs.wbak
```

**Restore into a separate folder (sandbox / extraction mode):**
```powershell
wbak restore C:\Backups\john-docs.wbak --target-dir "C:\Users\john\Desktop\RestoredDocs"
```

**Preview what would be restored without touching disk (`--dry-run`):**
```powershell
wbak restore C:\Backups\john-docs.wbak --dry-run
```

**Restore only specific files matching a filter:**
```powershell
wbak restore C:\Backups\john-docs.wbak --filter "invoices/2026" --conflict skip
```

---

### 3. Backing Up Files + `.ssh` Keys + Registry + `winget` (CLI Ad-Hoc)

```powershell
wbak backup `
  --path "${USERPROFILE}/.ssh" `
  --path "${USERPROFILE}/Documents" `
  --path "${APPDATA}/Code/User" `
  --reg "HKCU\Environment" `
  --reg "HKCU\Console" `
  --winget `
  -o workstation.wbak
```
> **Note on `.ssh` keys**: Because `${USERPROFILE}/.ssh` contains private keys, `wbak` automatically flags those files as `[SECRET 🔒]` and prompts you for an encryption passphrase (or you can pass `--password <pass>`). Public files in the same archive remain inspectable without a password, while `.ssh` chunks are encrypted with `ChaCha20-Poly1305`.
>
> To encrypt the **entire** archive (all files, Registry keys, and file list index), add `--encrypt`.

---

### 4. Reproducible Enterprise Profiles (`wbak.toml`)

For repeatable workstation backups or provisioning an enterprise developer environment across multiple machines:

**Step 1: Generate starter `wbak.toml` and `.wbakignore` files**
```powershell
wbak init
```

**Step 2: Customize `wbak.toml`**
```toml
[profile]
name = "enterprise-dev-workstation"
description = "Standard corporate dev environment & settings"
compression_level = 3

[security]
encrypt_full_archive = false
encrypt_sensitive_by_default = true

[files]
include = [
    "${USERPROFILE}/.ssh",
    "${USERPROFILE}/.gitconfig",
    "${USERPROFILE}/Documents/Projects",
    "${APPDATA}/Code/User",
]
ignore_file = ".wbakignore"
ignore_patterns = [
    "**/node_modules/",
    "**/target/",
    "*.log",
    "!/target/release/company-cli.exe",
    "!important.log",
]

[registry]
include_keys = [
    "HKCU\\Environment",
    "HKCU\\Console",
]
exclude_patterns = [
    "*\\BagMRU*",
]

[environment]
capture_winget = true
capture_env_vars = true
```

**Step 3: Preview `.wbakignore` rules before backing up**
```powershell
wbak preview -p wbak.toml
```
Outputs every discovered path marked as `[INCLUDE]`, `[EXEMPT!] (by '!/target/release/company-cli.exe')`, `[IGNORED] (by '**/node_modules/')`, and `[SECRET 🔒]`.

**Step 4: Run the profile backup**
```powershell
wbak backup -p wbak.toml -o enterprise-env.wbak
```

---

### 5. Inspecting, Auditing Drift (`diff`), and Verifying Archives

```powershell
# Instantly list archive summary, deduplication savings, files, registry keys & winget packages
wbak inspect enterprise-env.wbak

# Export the archive manifest as JSON for scripts/CI
wbak inspect enterprise-env.wbak --json

# Compare the archive against the live Windows machine (files, Registry values & winget packages)
wbak diff enterprise-env.wbak

# Cryptographically verify BLAKE3 hashes and AEAD tags of every chunk in the archive
wbak verify enterprise-env.wbak
```

---

### 6. Native Windows GUI Mode

Launch the desktop GUI either by double-clicking `wbak.exe` in Explorer, running `wbak` with no arguments, or running:

```powershell
wbak gui
```

The GUI provides five workspace tabs:
1. **📦 Backup Composer**: Add folders/files via native Windows dialogs, toggle quick presets (`.ssh`, VS Code, Documents), configure compression & encryption, and run backups.
2. **🚫 Ignore Rules (`.wbakignore`)**: Edit ignore and `!` exemption patterns on the left with a live color-coded preview tree on the right.
3. **🗂 Windows Registry**: Browse live `HKCU`, `HKLM`, `HKCR`, and `HKU` keys interactively and add keys or exclusion globs to your backup.
4. **♻ Restore & System Diff**: Open any `.wbak` archive, browse its files/Registry/`winget` packages, run a live System Drift (`Diff`) check, and restore selectively.
5. **🏢 Enterprise Profile (TOML)**: Load, edit, and save `wbak.toml` profiles.

---

## Workspace Architecture

`wbak` is organized as a Clean / Hexagonal Architecture Cargo workspace:

| Crate | Layer | Responsibility |
| :--- | :--- | :--- |
| `crates/wbak-domain` | **Domain** | Pure entities, portable path tokenizer, sensitivity rules, diff calculator, and Port traits |
| `crates/wbak-app` | **Application** | Use-case orchestration (`create_backup`, `restore_backup`, `diff_system`, `preview_scan`, `verify_archive`) |
| `crates/wbak-filter` | **Driven Adapter** | `.wbakignore` engine (`globset` / `ignore`), `!` exemptions, O(1) directory pruning, secret classifier |
| `crates/wbak-crypto` | **Driven Adapter** | `BLAKE3` hashing, `Argon2id` key derivation, and `ChaCha20-Poly1305` AEAD encryption |
| `crates/wbak-storage` | **Driven Adapter** | `.wbak` binary container writer & random-access reader, chunk deduplication, `zstd` compression |
| `crates/wbak-win` | **Driven Adapter** | Windows NTFS scanner/restorer, `.ssh` ACL hardening (`icacls`), Registry engine (`winreg`), `winget` integration |
| `crates/wbak-cli` | **Driving Adapter** | Command-line interface (`clap`, `indicatif`, `rpassword`) |
| `crates/wbak-gui` | **Driving Adapter** | Native Windows GUI (`eframe` / `egui`, `rfd`) |
| `bins/wbak` | **Composition Root** | Dependency injection wiring and dual-mode (`CLI` / `GUI`) binary entrypoint |

## License

This project is licensed under the [MIT License](LICENSE).
