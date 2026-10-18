use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use wbak_app::WbakApplication;
use wbak_cli::{run_cli_command, Cli};
use wbak_crypto::WbakCryptoProvider;
use wbak_domain::{default_sensitive_patterns, PortablePathTokenizer};
use wbak_filter::{GitignoreFilterFactory, GlobSensitivityClassifier};
use wbak_gui::launch_gui;
use wbak_storage::{WbakArchiveReader, WbakArchiveWriter};
use wbak_win::{
    WindowsEnvironmentRepository, WindowsFileRestorer, WindowsFileScanner,
    WindowsRegistryRepository,
};

fn build_application() -> Result<WbakApplication> {
    let tokenizer = PortablePathTokenizer::from_process_env();
    let sensitivity_classifier = Arc::new(GlobSensitivityClassifier::new(
        &default_sensitive_patterns(),
        true,
    )?);

    let filter_factory = Arc::new(GitignoreFilterFactory);
    let scanner = Arc::new(WindowsFileScanner::new(
        tokenizer.clone(),
        sensitivity_classifier,
    ));
    let restorer = Arc::new(WindowsFileRestorer::new());
    let registry = Arc::new(WindowsRegistryRepository::new());
    let environment = Arc::new(WindowsEnvironmentRepository::new());
    let crypto = Arc::new(WbakCryptoProvider::new());
    let archive_writer = Arc::new(WbakArchiveWriter::new(crypto.clone()));
    let archive_reader = Arc::new(WbakArchiveReader::new(crypto.clone()));

    Ok(WbakApplication::new(
        filter_factory,
        scanner,
        restorer,
        registry,
        environment,
        archive_writer,
        archive_reader,
        crypto,
        tokenizer,
    ))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let app = build_application()?;

    let should_open_gui = run_cli_command(&app, cli)?;
    if should_open_gui {
        launch_gui(app)?;
    }

    Ok(())
}
