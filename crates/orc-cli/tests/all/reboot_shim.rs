//! The reboot shim, dispatched for real.
//!
//! The Windows shim is the runtime binary itself, materialized in the phase's shim
//! directory as `shutdown.exe` and recognized by the name it was invoked under. That
//! multi-call dispatch is platform-agnostic, so the whole path — a real process,
//! started under the shim's name, with the platform's own arguments — can be exercised
//! here rather than left to a Windows-only branch CI never runs.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// Materializes the built `orc` binary under the shim's name.
///
/// The directory sits beside the binary so the hardlink stays on one filesystem: the
/// suite commonly runs with `TMPDIR` on a tmpfs, where a link into the target directory
/// cannot be made at all. A copy covers whatever is left. `current_exe` resolves
/// symlinks on Linux, so a symlink would report the binary's own name and never
/// dispatch — the shim has to be a second name for the file, not a pointer to it.
fn shim_binary() -> (TempDir, PathBuf) {
    let built = Path::new(env!("CARGO_BIN_EXE_orc"));
    let dir = TempDir::new_in(built.parent().expect("the built binary has a directory"))
        .expect("tempdir beside the built binary");
    let shim = dir.path().join(if cfg!(windows) {
        "shutdown.exe"
    } else {
        "shutdown"
    });
    if std::fs::hard_link(built, &shim).is_err() {
        std::fs::copy(built, &shim).expect("copy the built binary as the shim");
    }
    (dir, shim)
}

/// Runs the shim with `args`, granting a request file only when `with_request`.
fn run_shim(args: &[&str], with_request: bool) -> (Output, Option<String>) {
    let (dir, shim) = shim_binary();
    let request = dir.path().join("reboot-request");
    let mut command = Command::new(&shim);
    command.args(args).env_remove("ORC_REBOOT_REQUEST");
    if with_request {
        command.env("ORC_REBOOT_REQUEST", &request);
    }
    let output = command.output().expect("run the shim");
    let recorded = std::fs::read_to_string(&request).ok();
    (output, recorded)
}

#[test]
fn the_shim_records_a_restart_and_reports_it_to_the_phase() {
    // `shutdown /r /t 0` — the Windows spelling that used to slip past the batch shim
    // whenever a script qualified the extension.
    let (output, recorded) = run_shim(&["/r", "/t", "0"], true);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the restart must be accepted: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("orc: reboot requested; the runtime restarts this node after the phase"),
        "the phase is told the request took: {stdout}"
    );
    assert_eq!(
        recorded.as_deref(),
        Some("/r /t 0\n"),
        "the request records the literal arguments, trailing digit and all"
    );
}

#[test]
fn the_shim_records_the_unix_restart_spelling_too() {
    let (output, recorded) = run_shim(&["-r", "now"], true);
    assert!(output.status.success());
    assert_eq!(recorded.as_deref(), Some("-r now\n"));
}

#[test]
fn the_shim_refuses_a_restart_once_the_budget_is_gone() {
    // At the cap the runtime stops exporting the request variable; the refusal lands
    // in the phase's own log.
    let (output, recorded) = run_shim(&["/r", "/t", "0"], false);
    assert!(!output.status.success(), "the restart must be refused");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("orc: reboot budget exhausted; request refused"),
        "the refusal says why: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(recorded, None, "a refusal records nothing");
}

#[test]
fn the_shim_refuses_to_power_the_node_off() {
    let (output, recorded) = run_shim(&["/s", "/t", "0"], true);
    assert!(!output.status.success(), "the power-off must be refused");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("orc: phase may not power off the node"),
        "the refusal says why: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(recorded, None, "a refusal records nothing");
}

#[test]
fn the_binary_under_its_own_name_is_still_the_cli() {
    // Dispatch keys on the executable's name alone, so the same build invoked as `orc`
    // must parse its arguments as usual — `/r` is not a CLI flag and is rejected.
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["/r", "/t", "0"])
        .env("ORC_REBOOT_REQUEST", "/dev/null")
        .output()
        .expect("run the cli");
    assert!(
        !output.status.success(),
        "the CLI rejects platform switches"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error"),
        "clap explains the rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
