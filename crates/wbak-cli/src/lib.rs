pub mod commands;
pub mod terminal_ui;

use anyhow::Result;
use console::style;

use wbak_app::{CreateBackupRequest, ProfileService, RestoreBackupRequest, WbakApplication};
use wbak_domain::{
    DriftStatus, FilterDecision, ProfileConfig, SecretPromptPort, SensitivityLevel,
};

pub use commands::*;
pub use terminal_ui::*;

/// Executes a CLI command using `WbakApplication`.
/// Returns `Ok(true)` if the caller should launch the GUI instead.
pub fn run_cli_command(app: &WbakApplication, cli: Cli) -> Result<bool> {
    let Some(cmd) = cli.command else {
        return Ok(true);
    };

    match cmd {
        Commands::Gui => return Ok(true),

        Commands::Init { profile, ignore } => {
            ProfileService::write_starter_templates(&profile, &ignore)?;
            println!(
                "{} Created starter profile at {} and ignore file at {}",
                style("✔").green().bold(),
                style(profile.display()).cyan(),
                style(ignore.display()).cyan()
            );
        }

        Commands::Backup {
            profile,
            output,
            paths,
            registry_keys,
            ignore_file,
            exclude_patterns,
            winget,
            encrypt,
            password,
            allow_unencrypted_secrets,
        } => {
            let mut cfg = if let Some(prof_path) = &profile {
                ProfileService::load_from_file(prof_path)?
            } else if paths.is_empty() && registry_keys.is_empty() && !winget {
                ProfileConfig::default()
            } else {
                let mut empty = ProfileConfig::default();
                empty.files.include.clear();
                empty.registry.include_keys.clear();
                empty.environment.capture_winget = false;
                empty.environment.capture_env_vars = false;
                empty
            };

            if !paths.is_empty() {
                cfg.files.include.extend(paths);
            }
            if !registry_keys.is_empty() {
                cfg.registry.include_keys.extend(registry_keys);
            }
            if let Some(ig) = ignore_file {
                cfg.files.ignore_file = Some(ig);
            }
            if !exclude_patterns.is_empty() {
                cfg.files.ignore_patterns.extend(exclude_patterns);
            }
            if winget {
                cfg.environment.capture_winget = true;
            }
            if encrypt {
                cfg.security.encrypt_full_archive = true;
            }

            let progress = CliProgressSink::new();
            let prompter = CliSecretPrompter;
            let manifest = app.create_backup(
                CreateBackupRequest {
                    profile: cfg,
                    output_archive: output.clone(),
                    passphrase: password,
                    allow_unencrypted_secrets,
                },
                &progress,
                Some(&prompter),
            )?;
            progress.finish();

            println!(
                "\n{} Backup saved to {}",
                style("✔").green().bold(),
                style(output.display()).cyan().bold()
            );
            println!(
                "  Files backed up : {} ({} secret 🔒 encrypted by default)",
                manifest.stats.total_files, manifest.stats.secret_files_count
            );
            println!(
                "  Unique chunks   : {} (Logical: {} B -> Stored: {} B)",
                manifest.stats.unique_chunks,
                manifest.stats.total_logical_bytes,
                manifest.stats.compressed_stored_bytes
            );
            println!(
                "  Registry        : {} keys ({} values)",
                manifest.stats.registry_keys_count, manifest.stats.registry_values_count
            );
            if let Some(wg) = &manifest.winget {
                println!("  Winget packages : {}", wg.packages.len());
            }
        }

        Commands::Restore {
            archive,
            target_dir,
            files_only,
            reg_only,
            winget,
            env_vars,
            dry_run,
            conflict,
            filter,
            password,
        } => {
            let restore_files = !reg_only;
            let restore_registry = !files_only;

            let progress = CliProgressSink::new();
            let prompter = CliSecretPrompter;
            let summary = app.restore_backup(
                RestoreBackupRequest {
                    archive_path: archive.clone(),
                    passphrase: password,
                    target_dir_override: target_dir,
                    restore_files,
                    restore_registry,
                    restore_winget: winget,
                    restore_env_vars: env_vars,
                    dry_run,
                    conflict_policy: conflict.into(),
                    path_filter: filter,
                },
                &progress,
                Some(&prompter),
            )?;
            progress.finish();

            let prefix = if summary.dry_run {
                "[DRY RUN] "
            } else {
                ""
            };
            println!(
                "\n{} {}Restore completed from {}",
                style("✔").green().bold(),
                style(prefix).yellow().bold(),
                style(archive.display()).cyan()
            );
            println!(
                "  Files restored       : {} (skipped: {}, dirs: {})",
                summary.files_restored, summary.files_skipped, summary.dirs_restored
            );
            if summary.secret_acls_hardened > 0 {
                println!(
                    "  .ssh / Secret ACLs   : {} files locked to current user",
                    summary.secret_acls_hardened
                );
            }
            println!(
                "  Registry values      : {}",
                summary.registry_values_restored
            );
            if let Some(rollback) = &summary.rollback_reg_file {
                println!(
                    "  Registry rollback    : {}",
                    style(rollback.display()).yellow()
                );
            }
            if summary.winget_packages_restored > 0 {
                println!(
                    "  Winget packages      : {}",
                    summary.winget_packages_restored
                );
            }
        }

        Commands::Inspect {
            archive,
            password,
            json,
        } => {
            let manifest = app.inspect_archive(&archive, password.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                return Ok(false);
            }

            println!(
                "{} Archive: {}",
                style("📦").bold(),
                style(archive.display()).cyan().bold()
            );
            println!("  Profile      : {} ({})", manifest.profile.name, manifest.profile.description);
            println!("  Created      : {} on {} (user: {})", manifest.created_at, manifest.source_hostname, manifest.source_username);
            println!(
                "  Encryption   : full={}, encrypted_secrets={}",
                manifest.full_archive_encrypted, manifest.has_encrypted_secrets
            );
            println!(
                "  Storage      : {} files, {} unique chunks, {} B logical -> {} B stored",
                manifest.stats.total_files,
                manifest.stats.unique_chunks,
                manifest.stats.total_logical_bytes,
                manifest.stats.compressed_stored_bytes
            );

            if !manifest.files.is_empty() {
                println!("\n{}", style("Files:").bold().underlined());
                for f in &manifest.files {
                    let badge = if f.sensitivity == SensitivityLevel::Secret {
                        style("[SECRET 🔒]").yellow().to_string()
                    } else {
                        String::new()
                    };
                    println!("  {} ({} B) {}", f.logical_path, f.size(), badge);
                }
            }

            if !manifest.registry.keys.is_empty() {
                println!("\n{}", style("Registry Keys:").bold().underlined());
                for (path, key) in &manifest.registry.keys {
                    println!("  {} ({} values)", path, key.values.len());
                }
            }

            if let Some(wg) = &manifest.winget {
                println!(
                    "\n{} ({} packages)",
                    style("Winget Packages:").bold().underlined(),
                    wg.packages.len()
                );
                for pkg in wg.packages.iter().take(25) {
                    println!(
                        "  {} ({})",
                        pkg.id,
                        pkg.version.as_deref().unwrap_or("latest")
                    );
                }
                if wg.packages.len() > 25 {
                    println!("  ... and {} more", wg.packages.len() - 25);
                }
            }
        }

        Commands::Diff { archive, password } => {
            let report = app.diff_system(&archive, password.as_deref())?;
            println!(
                "{} System Drift Report against {}",
                style("🔍").bold(),
                style(archive.display()).cyan().bold()
            );

            for item in &report.files {
                match item.status {
                    DriftStatus::Identical => {}
                    DriftStatus::MissingOnSystem => {
                        println!(
                            "  {} File missing   : {} -> {}",
                            style("[-]").red(),
                            item.logical_path,
                            item.target_path
                        );
                    }
                    DriftStatus::ModifiedOnSystem => {
                        println!(
                            "  {} File modified  : {} ({})",
                            style("[~]").yellow(),
                            item.logical_path,
                            item.detail
                        );
                    }
                    DriftStatus::AddedOnSystem => {}
                }
            }

            for reg in &report.registry {
                if reg.status != DriftStatus::Identical {
                    println!(
                        "  {} Registry drift : {}\\{} (archive={:?}, live={:?})",
                        style("[R]").magenta(),
                        reg.key_path,
                        reg.value_name.as_deref().unwrap_or("(Key)"),
                        reg.archive_value,
                        reg.system_value
                    );
                }
            }

            for pkg in &report.packages {
                if pkg.status == DriftStatus::MissingOnSystem {
                    println!(
                        "  {} Winget missing : {} ({})",
                        style("[P]").cyan(),
                        pkg.package_id,
                        pkg.archive_version.as_deref().unwrap_or("any")
                    );
                }
            }

            if report.is_clean() {
                println!(
                    "  {} Live system matches archive with zero drift!",
                    style("✔").green().bold()
                );
            } else {
                println!(
                    "\nSummary: {} file diffs, {} registry diffs, {} missing winget packages",
                    report.changed_files_count(),
                    report.changed_registry_count(),
                    report.missing_packages_count()
                );
            }
        }

        Commands::Verify { archive, password } => {
            let progress = CliProgressSink::new();
            let prompter = CliSecretPrompter;

            let manifest = match app.verify_archive(&archive, password.as_deref(), &progress) {
                Ok(m) => m,
                Err(wbak_domain::DomainError::PassphraseRequired(reason)) => {
                    progress.finish();
                    let pass = prompter.prompt_passphrase(&reason, false)?;
                    app.verify_archive(&archive, Some(&pass), &progress)?
                }
                Err(e) => return Err(e.into()),
            };
            progress.finish();

            println!(
                "{} Verified {} unique chunks and {} files in {} — all BLAKE3 hashes and AEAD tags valid!",
                style("✔").green().bold(),
                manifest.stats.unique_chunks,
                manifest.stats.total_files,
                style(archive.display()).cyan()
            );
        }

        Commands::Preview {
            profile,
            paths,
            ignore_file,
            exclude_patterns,
        } => {
            let mut cfg = if let Some(p) = profile {
                ProfileService::load_from_file(&p)?
            } else {
                ProfileConfig::default()
            };
            if !paths.is_empty() {
                cfg.files.include = paths;
            }
            if let Some(ig) = ignore_file {
                cfg.files.ignore_file = Some(ig);
            }
            if !exclude_patterns.is_empty() {
                cfg.files.ignore_patterns.extend(exclude_patterns);
            }

            let entries = app.preview_scan(
                &cfg.files.include,
                &cfg.files.ignore_patterns,
                cfg.files.ignore_file.as_deref(),
                cfg.files.respect_local_ignore_files,
            )?;

            for e in &entries {
                let secret_tag = if e.sensitivity == SensitivityLevel::Secret {
                    " [SECRET 🔒]"
                } else {
                    ""
                };
                match &e.filter_decision {
                    FilterDecision::Included => {
                        println!(
                            "  {} {}{}",
                            style("[INCLUDE]").green(),
                            e.logical_path,
                            style(secret_tag).yellow()
                        );
                    }
                    FilterDecision::Exempted { matched_pattern } => {
                        println!(
                            "  {} {} (by '{}'){}",
                            style("[EXEMPT!]").cyan().bold(),
                            e.logical_path,
                            matched_pattern,
                            style(secret_tag).yellow()
                        );
                    }
                    FilterDecision::Ignored { matched_pattern } => {
                        println!(
                            "  {} {} (by '{}')",
                            style("[IGNORED]").red().dim(),
                            style(&e.logical_path).dim(),
                            matched_pattern
                        );
                    }
                }
            }
        }
    }

    Ok(false)
}
