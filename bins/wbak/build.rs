use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    for rel in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/wbak-domain/src",
        "crates/wbak-app/src",
        "crates/wbak-filter/src",
        "crates/wbak-crypto/src",
        "crates/wbak-storage/src",
        "crates/wbak-win/src",
        "crates/wbak-cli/src",
        "crates/wbak-gui/src",
        "bins/wbak-cli/src",
        "bins/wbak-gui/src",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            workspace_root.join(rel).display()
        );
    }

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let embedded_target_dir = workspace_root.join("target").join("wbak-embedded");

    let mut cmd = Command::new(&cargo);
    cmd.current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", &embedded_target_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .arg("build")
        .arg("--package")
        .arg("wbak-cli-bin")
        .arg("--package")
        .arg("wbak-gui-bin")
        .arg("--target-dir")
        .arg(&embedded_target_dir);

    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("Failed to invoke cargo to build embedded wbak-cli and wbak-gui binaries");
    assert!(
        status.success(),
        "Building embedded wbak-cli and wbak-gui binaries failed"
    );

    let bin_dir = embedded_target_dir.join(&profile);
    let cli_exe_path = bin_dir.join("wbak-cli.exe");
    let gui_exe_path = bin_dir.join("wbak-gui.exe");

    let cli_bytes = fs::read(&cli_exe_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", cli_exe_path.display()));
    let gui_bytes = fs::read(&gui_exe_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", gui_exe_path.display()));

    let mut hasher = blake3::Hasher::new();
    hasher.update(&(cli_bytes.len() as u64).to_le_bytes());
    hasher.update(&cli_bytes);
    hasher.update(&(gui_bytes.len() as u64).to_le_bytes());
    hasher.update(&gui_bytes);
    let bundle_hash = hasher.finalize().to_hex();
    let bundle_id = &bundle_hash[..16];

    let cli_zst =
        zstd::encode_all(cli_bytes.as_slice(), 3).expect("Failed to zstd-compress wbak-cli.exe");
    let gui_zst =
        zstd::encode_all(gui_bytes.as_slice(), 3).expect("Failed to zstd-compress wbak-gui.exe");

    let cli_zst_path = out_dir.join("wbak-cli.exe.zst");
    let gui_zst_path = out_dir.join("wbak-gui.exe.zst");

    fs::write(&cli_zst_path, &cli_zst).expect("Failed to write wbak-cli.exe.zst");
    fs::write(&gui_zst_path, &gui_zst).expect("Failed to write wbak-gui.exe.zst");

    println!("cargo:rustc-env=WBAK_BUNDLE_ID={bundle_id}");
    println!(
        "cargo:rustc-env=WBAK_CLI_ZST_PATH={}",
        cli_zst_path.display()
    );
    println!(
        "cargo:rustc-env=WBAK_GUI_ZST_PATH={}",
        gui_zst_path.display()
    );
    println!("cargo:rustc-env=WBAK_CLI_RAW_LEN={}", cli_bytes.len());
    println!("cargo:rustc-env=WBAK_GUI_RAW_LEN={}", gui_bytes.len());
}
