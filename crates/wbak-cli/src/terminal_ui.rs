use std::sync::Mutex;

use console::style;
use indicatif::{ProgressBar, ProgressStyle};

use wbak_domain::{
    DomainError, DomainResult, ProgressEvent, ProgressPhase, ProgressSinkPort, SecretPromptPort,
};

pub struct CliProgressSink {
    bar: Mutex<Option<ProgressBar>>,
}

impl Default for CliProgressSink {
    fn default() -> Self {
        Self::new()
    }
}

impl CliProgressSink {
    pub fn new() -> Self {
        let pb = ProgressBar::new_spinner();
        if let Ok(tpl) =
            ProgressStyle::with_template("{spinner:.cyan} [{bar:30.cyan/blue}] {pos}/{len} {msg}")
        {
            pb.set_style(tpl.progress_chars("=>-"));
        }
        Self {
            bar: Mutex::new(Some(pb)),
        }
    }

    pub fn finish(&self) {
        if let Ok(mut guard) = self.bar.lock() {
            if let Some(pb) = guard.take() {
                pb.finish_and_clear();
            }
        }
    }
}

impl ProgressSinkPort for CliProgressSink {
    fn on_progress(&self, event: ProgressEvent) {
        if let Ok(guard) = self.bar.lock() {
            if let Some(pb) = guard.as_ref() {
                if !matches!(event.phase, ProgressPhase::Completed) {
                    if let Some(total) = event.total {
                        pb.set_length(total);
                        pb.set_position(event.current);
                    }
                    pb.set_message(event.message);
                }
            }
        }
    }
}

pub struct CliSecretPrompter;

impl SecretPromptPort for CliSecretPrompter {
    fn prompt_passphrase(&self, reason: &str, confirm: bool) -> DomainResult<String> {
        eprintln!(
            "\n{} {}",
            style("🔒 Security Policy:").yellow().bold(),
            style(reason).yellow()
        );
        let pass = rpassword::prompt_password("Enter encryption passphrase: ").map_err(|e| {
            DomainError::CryptoError(format!("Failed reading passphrase from terminal: {e}"))
        })?;
        if pass.is_empty() {
            return Err(DomainError::PassphraseRequired(
                "Passphrase cannot be empty".to_string(),
            ));
        }

        if confirm {
            let confirm_pass = rpassword::prompt_password("Confirm encryption passphrase: ")
                .map_err(|e| {
                    DomainError::CryptoError(format!("Failed reading confirmation passphrase: {e}"))
                })?;
            if pass != confirm_pass {
                return Err(DomainError::CryptoError(
                    "Passphrases did not match".to_string(),
                ));
            }
        }

        Ok(pass)
    }
}
