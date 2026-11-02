#![windows_subsystem = "windows"]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

const BUNDLE_ID: &str = env!("WBAK_BUNDLE_ID");
const EMBEDDED_CLI_ZST: &[u8] = include_bytes!(env!("WBAK_CLI_ZST_PATH"));
const EMBEDDED_GUI_ZST: &[u8] = include_bytes!(env!("WBAK_GUI_ZST_PATH"));

fn cli_expected_len() -> u64 {
    env!("WBAK_CLI_RAW_LEN").parse::<u64>().unwrap_or(0)
}

fn gui_expected_len() -> u64 {
    env!("WBAK_GUI_RAW_LEN").parse::<u64>().unwrap_or(0)
}

fn should_launch_gui(args: &[OsString]) -> bool {
    if args.is_empty() {
        return true;
    }
    args.len() == 1 && args[0].eq_ignore_ascii_case("gui")
}

fn bundle_cache_root() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("wbak").join("bin")
}

fn extract_if_needed(
    cache_dir: &Path,
    file_name: &str,
    compressed_bytes: &[u8],
    expected_len: u64,
) -> Result<PathBuf> {
    let target_path = cache_dir.join(file_name);
    if let Ok(meta) = fs::metadata(&target_path)
        && meta.is_file()
        && meta.len() == expected_len
    {
        return Ok(target_path);
    }

    fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "Failed to create bundle cache directory at {}",
            cache_dir.display()
        )
    })?;

    let decompressed = zstd::decode_all(compressed_bytes)
        .with_context(|| format!("Failed to decompress embedded {file_name}"))?;

    let tmp_path = cache_dir.join(format!("{file_name}.{}.tmp", std::process::id()));
    fs::write(&tmp_path, &decompressed)
        .with_context(|| format!("Failed to write temporary binary {}", tmp_path.display()))?;

    if let Err(rename_err) = fs::rename(&tmp_path, &target_path) {
        let _ = fs::remove_file(&tmp_path);
        let already_ready = fs::metadata(&target_path)
            .map(|m| m.is_file() && m.len() == expected_len)
            .unwrap_or(false);
        if !already_ready {
            return Err(rename_err).with_context(|| {
                format!(
                    "Failed to finalize extracted binary at {}",
                    target_path.display()
                )
            });
        }
    }

    Ok(target_path)
}

fn cleanup_stale_bundles(root: &Path) {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_name() != BUNDLE_ID {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

fn ensure_cli_binary() -> Result<PathBuf> {
    let root = bundle_cache_root();
    let cache_dir = root.join(BUNDLE_ID);
    let cli_path = extract_if_needed(
        &cache_dir,
        "wbak-cli.exe",
        EMBEDDED_CLI_ZST,
        cli_expected_len(),
    )?;
    cleanup_stale_bundles(&root);
    Ok(cli_path)
}

fn ensure_gui_binary() -> Result<PathBuf> {
    let root = bundle_cache_root();
    let cache_dir = root.join(BUNDLE_ID);
    let gui_path = extract_if_needed(
        &cache_dir,
        "wbak-gui.exe",
        EMBEDDED_GUI_ZST,
        gui_expected_len(),
    )?;
    cleanup_stale_bundles(&root);
    Ok(gui_path)
}

#[cfg(windows)]
mod win_console {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    type Handle = *mut c_void;

    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
    const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const FILE_TYPE_UNKNOWN: u32 = 0x0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AttachConsole(dw_process_id: u32) -> i32;
        fn AllocConsole() -> i32;
        fn GetLastError() -> u32;
        fn GetStdHandle(n_std_handle: u32) -> Handle;
        fn SetStdHandle(n_std_handle: u32, h_handle: Handle) -> i32;
        fn GetFileType(h_file: Handle) -> u32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *const SecurityAttributes,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: Handle,
        ) -> Handle;
    }

    unsafe fn valid_redirected_handle(std_handle: u32) -> Option<Handle> {
        let h = unsafe { GetStdHandle(std_handle) };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return None;
        }
        if unsafe { GetFileType(h) } == FILE_TYPE_UNKNOWN {
            return None;
        }
        Some(h)
    }

    pub fn attach_for_cli() {
        unsafe {
            let orig_stdin = valid_redirected_handle(STD_INPUT_HANDLE);
            let orig_stdout = valid_redirected_handle(STD_OUTPUT_HANDLE);
            let orig_stderr = valid_redirected_handle(STD_ERROR_HANDLE);

            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                let err = GetLastError();
                if err != ERROR_ACCESS_DENIED
                    && orig_stdin.is_none()
                    && orig_stdout.is_none()
                    && orig_stderr.is_none()
                {
                    let _ = AllocConsole();
                }
            }

            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: null_mut(),
                b_inherit_handle: 1,
            };

            let conin_name: [u16; 7] = [
                b'C' as u16,
                b'O' as u16,
                b'N' as u16,
                b'I' as u16,
                b'N' as u16,
                b'$' as u16,
                0,
            ];
            let conout_name: [u16; 8] = [
                b'C' as u16,
                b'O' as u16,
                b'N' as u16,
                b'O' as u16,
                b'U' as u16,
                b'T' as u16,
                b'$' as u16,
                0,
            ];

            if let Some(h_in) = orig_stdin {
                let _ = SetStdHandle(STD_INPUT_HANDLE, h_in);
            } else {
                let conin = CreateFileW(
                    conin_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &sa,
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                );
                if conin != INVALID_HANDLE_VALUE && !conin.is_null() {
                    let _ = SetStdHandle(STD_INPUT_HANDLE, conin);
                }
            }

            if orig_stdout.is_none() || orig_stderr.is_none() {
                let conout = CreateFileW(
                    conout_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &sa,
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                );
                if conout != INVALID_HANDLE_VALUE && !conout.is_null() {
                    let _ = SetStdHandle(STD_OUTPUT_HANDLE, orig_stdout.unwrap_or(conout));
                    let _ = SetStdHandle(STD_ERROR_HANDLE, orig_stderr.unwrap_or(conout));
                }
            } else {
                if let Some(h_out) = orig_stdout {
                    let _ = SetStdHandle(STD_OUTPUT_HANDLE, h_out);
                }
                if let Some(h_err) = orig_stderr {
                    let _ = SetStdHandle(STD_ERROR_HANDLE, h_err);
                }
            }
        }
    }
}

fn run() -> Result<i32> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    if should_launch_gui(&args) {
        let gui_exe = ensure_gui_binary()?;
        Command::new(&gui_exe)
            .spawn()
            .with_context(|| format!("Failed to launch GUI binary at {}", gui_exe.display()))?;
        Ok(0)
    } else {
        #[cfg(windows)]
        win_console::attach_for_cli();

        let cli_exe = ensure_cli_binary()?;
        let status = Command::new(&cli_exe)
            .args(&args)
            .status()
            .with_context(|| format!("Failed to execute CLI binary at {}", cli_exe.display()))?;

        Ok(status.code().unwrap_or(1))
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            #[cfg(windows)]
            win_console::attach_for_cli();
            eprintln!("wbak launcher error: {err:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::should_launch_gui;

    #[test]
    fn launcher_chooses_gui_when_no_args_or_gui_subcommand() {
        assert!(should_launch_gui(&[]));
        assert!(should_launch_gui(&[OsString::from("gui")]));
        assert!(should_launch_gui(&[OsString::from("GUI")]));
        assert!(!should_launch_gui(&[OsString::from("backup")]));
        assert!(!should_launch_gui(&[OsString::from("--help")]));
    }
}
