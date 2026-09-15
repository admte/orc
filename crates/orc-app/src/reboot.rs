//! Phase-requested reboots.
//!
//! A lifecycle phase never restarts the machine itself: it *asks*, by calling the
//! platform's ordinary reboot command, and the initiating runtime or standalone
//! CLI — owns what happens next. Three pieces make that work:
//!
//! * a **shim directory** prepended to the phase's `PATH`, holding commands named like
//!   the real ones (`shutdown`, `reboot`). A restart form records the request and
//!   returns success, exactly as the native command would; a power-off form is refused
//!   outright — a phase has no business powering a node down. Outside a runtime-managed
//!   phase the shim is not on `PATH`, so the same script run by hand hits the real
//!   command. On Unix the shims are small `sh` scripts; on Windows the shim is the
//!   runtime binary itself, materialized as `shutdown.exe` — see [`maybe_run_shim`].
//! * a **marker plus counter** persisted in the runtime state dir, so the phase is
//!   re-entered from the top after the restart, and a phase that keeps asking is capped
//!   instead of looping the machine forever.
//! * a **reboot executor**, real in production and file-recording under test, so the
//!   integration suite can observe a reboot without losing the test process.
//!
//! The decisions here are pure and unit-tested; the side effects are one thin
//! platform-specific function.

#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use crate::error::{CliError, Result};

/// Shim directory under the runtime state dir. Rewritten on every phase entry so an
/// upgraded runtime never leaves an older shim behind for a phase to call.
const SHIM_DIR: &str = "reboot-shim";

/// File the shim records a request in; the runtime consumes it when the pass ends.
const REQUEST_FILE: &str = "reboot-request";

/// In-flight marker and reboot counter, one per runtime state dir. A phase execution
/// is keyed by app + version + phase, so a different app's reboots start from a fresh
/// budget.
const MARKER_FILE: &str = "phase-reboot.json";

/// Environment variable naming the request file. The shim writes there when the
/// variable is set and refuses the call when it is not — which is how the cap is
/// enforced where the phase can see it, in its own log.
pub const REQUEST_ENV: &str = "ORC_REBOOT_REQUEST";

/// Environment variable carrying the reason a phase may not restart the node at all,
/// which the shim prints in place of its budget message. Set for the phases that run
/// around a termination — a stop hook restarting the node would take the whole node
/// down to end one app.
pub const DENY_ENV: &str = "ORC_REBOOT_DENY";

/// Environment variable selecting a non-restarting executor, `fake:<path>`.
pub const EXEC_ENV: &str = "ORC_REBOOT_EXEC";

/// Cap on reboots within one phase execution. A phase that never settles (a patch set
/// that keeps re-flagging a restart, a script with a bug) burns its budget and then
/// runs to completion on its own merits: an imperfect result beats a reboot loop.
pub const MAX_PHASE_REBOOTS: u32 = 5;

/// Pure decision: given the reboots already taken by this phase execution, may the
/// phase ask for another? `false` at the cap, so the runtime stops exporting the
/// request variable and the shim starts refusing.
#[must_use]
pub fn may_reboot(count: u32) -> bool {
    count < MAX_PHASE_REBOOTS
}

/// How a lifecycle phase pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum PhaseOutcome {
    /// The pass ran to its own end; nothing is pending.
    Completed,
    /// The phase asked the runtime to restart the machine. Not a failure and not a
    /// finished install: the runtime reboots and re-enters the phase from the top.
    RebootRequested {
        /// Reboots this phase execution has now been charged, this one included.
        reboot_count: u32,
    },
}

/// Persisted in-flight marker: which phase execution owns the machine right now, and
/// how many restarts it has spent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhaseMarker {
    pub app: String,
    pub version: String,
    pub phase: String,
    /// Reboots already charged to this phase execution.
    pub reboot_count: u32,
    /// Set between recording a request and the phase's next entry. It is what
    /// separates "we took the machine down deliberately" from "the phase went down
    /// some other way" — the latter is tolerated, but charged all the same.
    #[serde(default)]
    pub requested: bool,
}

/// Path of the in-flight marker within a runtime state dir.
#[must_use]
pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MARKER_FILE)
}

/// Reads the in-flight marker. A missing or unreadable file means no phase is in
/// flight — the same conclusion, so both collapse to `None`.
#[must_use]
pub fn read_marker(state_dir: &Path) -> Option<PhaseMarker> {
    let body = std::fs::read(marker_path(state_dir)).ok()?;
    serde_json::from_slice(&body).ok()
}

fn write_marker(state_dir: &Path, marker: &PhaseMarker) -> Result<()> {
    let path = marker_path(state_dir);
    let body = serde_json::to_vec(marker)
        .map_err(|err| CliError::Operational(format!("encode reboot marker: {err}")))?;
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))
}

/// Retires the in-flight marker and any request left next to it. Best-effort: the
/// phase execution is over either way, and a stale marker only costs the next
/// execution one charged reboot.
pub fn clear(state_dir: &Path) {
    let _ = std::fs::remove_file(marker_path(state_dir));
    let _ = std::fs::remove_file(state_dir.join(REQUEST_FILE));
}

/// The reboot plumbing one phase pass runs under: the shim directory that goes first
/// on its `PATH`, and — while the phase is under the cap — the file the shim records
/// a request in.
///
/// Built by [`PhaseReboot::enter`] before the phase runs and closed by
/// [`PhaseReboot::finish`] after it exits.
#[derive(Debug)]
pub struct PhaseReboot {
    state_dir: PathBuf,
    shim_dir: PathBuf,
    /// `None` at the cap: with nothing to write to, the shim refuses the call.
    request_file: Option<PathBuf>,
    reboot_count: u32,
    /// Set for a phase that may not restart the node at all; the shim reports it as
    /// the reason for the refusal.
    deny: Option<String>,
}

impl PhaseReboot {
    /// Opens a phase pass: lays down the shim, resumes or opens the in-flight marker,
    /// and reports the reboot budget already spent.
    ///
    /// Entering with a marker for this same phase means the previous pass did not
    /// finish. If it recorded a request, this is the re-entry after the runtime's own
    /// reboot and the counter was charged then. If it did not, the phase went down
    /// behind the shim's back — an absolute-path `shutdown`, an API restart, a power
    /// cut — which is tolerated but charged against the same cap, so a script that
    /// reboots without asking cannot loop the machine either.
    pub fn enter(state_dir: &Path, app: &str, version: &str, phase: &str) -> Result<Self> {
        let shim_dir = install_shim(state_dir)?;
        // A request the runtime never consumed (the phase died between writing it and
        // exiting) must not be read as this pass's request.
        let request_file = state_dir.join(REQUEST_FILE);
        let _ = std::fs::remove_file(&request_file);

        let resumed = read_marker(state_dir).filter(|marker| {
            marker.app == app && marker.version == version && marker.phase == phase
        });
        let marker = match resumed {
            Some(marker) if marker.requested => PhaseMarker {
                requested: false,
                ..marker
            },
            Some(marker) => PhaseMarker {
                reboot_count: marker.reboot_count.saturating_add(1),
                requested: false,
                ..marker
            },
            None => PhaseMarker {
                app: app.to_owned(),
                version: version.to_owned(),
                phase: phase.to_owned(),
                reboot_count: 0,
                requested: false,
            },
        };
        write_marker(state_dir, &marker)?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            shim_dir,
            request_file: may_reboot(marker.reboot_count).then_some(request_file),
            reboot_count: marker.reboot_count,
            deny: None,
        })
    }

    /// Plumbing for a phase that may not restart the node under any circumstances.
    ///
    /// The shim still goes first on the phase's `PATH` — that is the whole point, since
    /// a script left to resolve `shutdown` itself would reach the platform binary and
    /// take the node down — but no request file is granted, so every restart form is
    /// refused with `reason` in the phase's own log and a non-zero exit.
    ///
    /// Opens no phase execution and touches no marker: nothing here is re-entered
    /// after a restart, because no restart can happen.
    pub fn refusing(state_dir: &Path, reason: &str) -> Result<Self> {
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            shim_dir: install_shim(state_dir)?,
            request_file: None,
            reboot_count: 0,
            deny: Some(reason.to_owned()),
        })
    }

    /// Why this phase may not restart the node, when it may not at all.
    #[must_use]
    pub fn deny_reason(&self) -> Option<&str> {
        self.deny.as_deref()
    }

    /// Directory holding the shim commands; goes first on the phase's `PATH`.
    #[must_use]
    pub fn shim_dir(&self) -> &Path {
        &self.shim_dir
    }

    /// File the shim records a request in, or `None` at the cap.
    #[must_use]
    pub fn request_file(&self) -> Option<&Path> {
        self.request_file.as_deref()
    }

    /// Reboots this phase execution has spent so far.
    #[must_use]
    pub fn reboot_count(&self) -> u32 {
        self.reboot_count
    }

    /// Closes a pass that ran to its own end, consuming any request the shim recorded.
    ///
    /// A recorded request charges the counter and marks the marker, so the re-entry
    /// after the restart resumes this phase instead of charging the restart twice. A
    /// pass that asked for nothing retires the marker outright — the phase execution
    /// is over, and the next one starts on a full budget.
    pub fn finish(&self) -> Result<PhaseOutcome> {
        let requested = self
            .request_file
            .as_ref()
            .is_some_and(|path| std::fs::remove_file(path).is_ok());
        if !requested {
            clear(&self.state_dir);
            return Ok(PhaseOutcome::Completed);
        }
        let reboot_count = self.reboot_count.saturating_add(1);
        let marker = read_marker(&self.state_dir).map_or_else(
            || PhaseMarker {
                app: String::new(),
                version: String::new(),
                phase: String::new(),
                reboot_count,
                requested: true,
            },
            |marker| PhaseMarker {
                reboot_count,
                requested: true,
                ..marker
            },
        );
        // Persisted BEFORE the machine goes down: a counter that failed to reach the
        // disk would let the phase reboot forever, so the phase fails loudly instead.
        write_marker(&self.state_dir, &marker)?;
        Ok(PhaseOutcome::RebootRequested { reboot_count })
    }

    /// Closes a pass that failed. The failure is the outcome the runtime reports, so
    /// any request the phase managed to record dies with it; the retry opens a fresh
    /// phase execution.
    pub fn abandon(&self) {
        clear(&self.state_dir);
    }
}

// ─── The shim ────────────────────────────────────────────────────────────────────

/// `shutdown` on Unix. A restart form (`-r`/`--reboot`, wherever it sits in the
/// arguments) records the request; everything else — `-h`, `-P`, `--halt`, no
/// arguments at all — is a power-off and refused.
#[cfg(unix)]
const UNIX_SHUTDOWN_SHIM: &str = r#"#!/bin/sh
# orc lifecycle-phase shim: a phase requests a restart, the runtime performs it.
for arg in "$@"; do
    case "$arg" in
    -r | --reboot)
        if [ -n "${ORC_REBOOT_REQUEST:-}" ]; then
            printf '%s\n' "$*" >"$ORC_REBOOT_REQUEST"
            echo "orc: reboot requested; the runtime restarts this node after the phase"
            exit 0
        fi
        echo "orc: ${ORC_REBOOT_DENY:-reboot budget exhausted}; request refused" >&2
        exit 1
        ;;
    esac
done
echo "orc: phase may not power off the node" >&2
exit 1
"#;

/// `reboot` on Unix. The bare command *is* a restart, so only its power-off flags are
/// refused.
#[cfg(unix)]
const UNIX_REBOOT_SHIM: &str = r#"#!/bin/sh
# orc lifecycle-phase shim: a phase requests a restart, the runtime performs it.
for arg in "$@"; do
    case "$arg" in
    -p | --poweroff | --power-off | -h | --halt)
        echo "orc: phase may not power off the node" >&2
        exit 1
        ;;
    esac
done
if [ -n "${ORC_REBOOT_REQUEST:-}" ]; then
    printf '%s\n' "$*" >"$ORC_REBOOT_REQUEST"
    echo "orc: reboot requested; the runtime restarts this node after the phase"
    exit 0
fi
echo "orc: ${ORC_REBOOT_DENY:-reboot budget exhausted}; request refused" >&2
exit 1
"#;

/// Command name the shim answers to, and the file stem that tells a runtime process it
/// was invoked *as* the shim rather than as itself.
const SHIM_COMMAND: &str = "shutdown";

/// The Windows shim: the runtime binary itself under a second name. `PATHEXT` puts
/// `.EXE` ahead of every scripting extension, and an extension-qualified call
/// (`shutdown.exe /r`, a common spelling) only ever matches an `.exe` — so a real
/// executable is the only shim that catches every way a script can spell the command.
#[cfg_attr(not(windows), allow(dead_code))]
const WINDOWS_SHIM: &str = "shutdown.exe";

/// Batch shim laid down by runtimes before the multi-call binary. Removed on sight:
/// `PATHEXT` would prefer the `.exe` anyway, but a phase that spells the extension
/// explicitly would otherwise still reach it.
#[cfg_attr(not(windows), allow(dead_code))]
const WINDOWS_LEGACY_SHIM: &str = "shutdown.cmd";

/// Writes the shim commands into `<state_dir>/reboot-shim`, returning the directory.
fn install_shim(state_dir: &Path) -> Result<PathBuf> {
    let dir = state_dir.join(SHIM_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", dir.display())))?;
    #[cfg(unix)]
    {
        write_shim(&dir, SHIM_COMMAND, UNIX_SHUTDOWN_SHIM)?;
        write_shim(&dir, "reboot", UNIX_REBOOT_SHIM)?;
    }
    #[cfg(windows)]
    {
        remove_legacy_shim(&dir);
        install_multicall_shim(&dir)?;
    }
    Ok(dir)
}

/// Best-effort removal of the pre-multi-call `shutdown.cmd`. Upgrade hygiene only: a
/// failure leaves a file `PATHEXT` no longer prefers, so it is never worth failing a
/// phase over.
#[cfg_attr(not(windows), allow(dead_code))]
fn remove_legacy_shim(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(WINDOWS_LEGACY_SHIM));
}

/// Materializes the running binary as `<dir>/shutdown.exe`, hardlinked where the
/// filesystem allows it and copied where it does not (a shim directory on another
/// volume than the runtime binary).
///
/// The shim directory is re-laid on every phase entry and the binary can change
/// between entries, so a link left by an earlier runtime is removed before the new one
/// goes in — a link to a replaced binary must not outlive the upgrade.
///
/// **When the removal fails, the existing shim is kept.** Windows refuses to unlink a
/// file that is mapped as a running image, and a hardlink is not a copy: while the shim
/// still points at the *running* binary, every name for it is the running image and the
/// unlink is denied. That case needs no replacement — the link already resolves to the
/// current binary. After a real upgrade the old link names the old file, which is no
/// longer running and unlinks normally. Anything else (a lock the runtime cannot
/// explain, a read-only directory) leaves a shim from an older runtime in place, which
/// is harmless: the shim contract is the request environment variable and three fixed
/// messages, and every runtime that ever wrote a shim honours it.
#[cfg_attr(not(windows), allow(dead_code))]
fn install_multicall_shim(dir: &Path) -> Result<()> {
    let source = std::env::current_exe()
        .map_err(|err| CliError::Operational(format!("locate the running binary: {err}")))?;
    let target = dir.join(WINDOWS_SHIM);
    if target.exists() && std::fs::remove_file(&target).is_err() {
        return Ok(());
    }
    if std::fs::hard_link(&source, &target).is_ok() {
        return Ok(());
    }
    std::fs::copy(&source, &target).map(|_| ()).map_err(|err| {
        CliError::Operational(format!(
            "install {} as {}: {err}",
            source.display(),
            target.display()
        ))
    })
}

// ─── The shim, as the runtime binary runs it ─────────────────────────────────────

/// Runs the current process as the reboot shim when it was invoked under the shim's
/// name, returning the exit code to leave with; `None` when it was invoked as itself.
///
/// This is the multi-call pattern — one binary, several commands, selected by the name
/// it was called under (the house precedent is `orc-vmm`, a re-exec of the plugin
/// binary). The Windows shim needs it because only a real `.exe` catches every spelling
/// a phase script might use: `PATHEXT` resolution prefers `.EXE` over any script
/// extension, and an extension-qualified `shutdown.exe /r` matches nothing else at all.
/// So the runtime hardlinks itself into the shim directory as `shutdown.exe`, and the
/// copy that a phase invokes recognizes itself here.
///
/// Detection is by executable name rather than a flag or a variable because the caller
/// is an arbitrary phase script that knows nothing about orc: it types `shutdown /r`
/// and `PATH` does the rest. Nothing else can trip it — an orc binary is only ever
/// named `shutdown` because the runtime put it there.
///
/// Call it on the **first line of `main`**, before any argument parsing: the shim's
/// arguments are the platform's (`/r`, `/t 0`), which no orc argument parser accepts.
///
/// Deliberately not `cfg`-gated to Windows. The check is one `current_exe` call, and
/// keeping it uniform lets the Unix test suite exercise the real dispatch path end to
/// end instead of a Windows-only branch CI can never run.
#[must_use]
pub fn maybe_run_shim() -> Option<i32> {
    let exe = std::env::current_exe().ok()?;
    let stem = exe.file_stem()?.to_str()?;
    if !stem.eq_ignore_ascii_case(SHIM_COMMAND) {
        return None;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = std::env::var_os(REQUEST_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let deny = std::env::var(DENY_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    Some(run_shim_args(
        &args,
        request.as_deref(),
        deny.as_deref(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    ))
}

/// The shim's whole behaviour, over its arguments and the request file the runtime
/// granted it — `None` once the phase has spent its reboot budget, or for a phase that
/// was never allowed to restart the node, which says so through `deny`.
///
/// Byte-for-byte the same three outcomes as the Unix `sh` shims, because a phase log
/// should read identically on either platform.
pub fn run_shim_args(
    args: &[String],
    request_file: Option<&Path>,
    deny: Option<&str>,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> i32 {
    if !args.iter().any(|arg| is_restart_form(arg)) {
        let _ = writeln!(err, "orc: phase may not power off the node");
        return 1;
    }
    let Some(path) = request_file else {
        let _ = writeln!(
            err,
            "orc: {}; request refused",
            deny.unwrap_or("reboot budget exhausted")
        );
        return 1;
    };
    // Recorded before the success message: a phase told its restart was accepted must
    // never find that nothing was written down.
    if let Err(error) = std::fs::write(path, format!("{}\n", args.join(" "))) {
        let _ = writeln!(
            err,
            "orc: reboot request could not be recorded: {}: {error}",
            path.display()
        );
        return 1;
    }
    let _ = writeln!(
        out,
        "orc: reboot requested; the runtime restarts this node after the phase"
    );
    0
}

/// A restart, in any spelling a phase script might reach for: `-r`/`--reboot` from
/// `shutdown(8)`, `/r` from Windows (whose switches are case-insensitive).
fn is_restart_form(arg: &str) -> bool {
    arg == "-r" || arg == "--reboot" || arg.eq_ignore_ascii_case("/r")
}

#[cfg(unix)]
fn write_shim(dir: &Path, name: &str, body: &str) -> Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|err| CliError::Operational(format!("chmod {}: {err}", path.display())))?;
    }
    Ok(())
}

// ─── The executor ────────────────────────────────────────────────────────────────

/// How the runtime performs a granted reboot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebootExecutor {
    /// Restart the machine.
    Real,
    /// Append a line to a file instead of restarting. The integration suite observes
    /// reboots this way and then drives the re-entry itself, in one process.
    Fake(PathBuf),
}

/// What handing the machine to an executor did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RebootAction {
    /// The restart is enqueued and proceeds independently; the caller must stop now.
    Rebooting,
    /// Recorded by a fake executor. Nothing restarted and control returns.
    Recorded,
    /// The platform would not restart. The caller keeps running and reports it: a
    /// node that cannot reboot is a problem to narrate, not to hide.
    Failed,
}

impl RebootExecutor {
    /// Reads the executor from the environment: `ORC_REBOOT_EXEC=fake:<path>` records
    /// instead of restarting; anything else (including an unset variable) is real.
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var(EXEC_ENV).map_or(Self::Real, |value| Self::parse(&value))
    }

    #[must_use]
    fn parse(value: &str) -> Self {
        value
            .strip_prefix("fake:")
            .map_or(Self::Real, |path| Self::Fake(PathBuf::from(path)))
    }

    /// Performs the reboot. `note` identifies the phase that asked for it and is what
    /// a fake executor records.
    pub fn execute(&self, note: &str) -> RebootAction {
        match self {
            Self::Real => {
                if reboot_machine() {
                    RebootAction::Rebooting
                } else {
                    RebootAction::Failed
                }
            }
            Self::Fake(path) => {
                use std::io::Write as _;
                let appended = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut file| writeln!(file, "{note}"));
                if appended.is_ok() {
                    RebootAction::Recorded
                } else {
                    RebootAction::Failed
                }
            }
        }
    }
}

/// Enqueues the platform's restart, reporting whether it was accepted.
///
/// Resolution goes through the runtime's own `PATH`, never the phase's: the shim only
/// ever sits in front of a phase process, so the command found here is the real one.
#[cfg(target_os = "linux")]
fn reboot_machine() -> bool {
    // systemd's own verb first — it enqueues the transition and returns, letting the
    // manager stop units in order. `reboot(8)` covers systemd-less images.
    run_reboot("systemctl", &["reboot", "--no-wall"]) || run_reboot("reboot", &[])
}

#[cfg(target_os = "macos")]
fn reboot_machine() -> bool {
    run_reboot("shutdown", &["-r", "now"])
}

#[cfg(target_os = "windows")]
fn reboot_machine() -> bool {
    run_reboot("shutdown", &["/r", "/t", "0"])
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn reboot_machine() -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_reboot(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(app: &str, phase: &str, count: u32, requested: bool) -> PhaseMarker {
        PhaseMarker {
            app: app.to_owned(),
            version: "1.0".to_owned(),
            phase: phase.to_owned(),
            reboot_count: count,
            requested,
        }
    }

    #[test]
    fn may_reboot_stops_at_the_cap() {
        assert!(may_reboot(0));
        assert!(may_reboot(MAX_PHASE_REBOOTS - 1));
        // At and beyond the cap the phase must complete without another restart.
        assert!(!may_reboot(MAX_PHASE_REBOOTS));
        assert!(!may_reboot(MAX_PHASE_REBOOTS + 1));
    }

    #[test]
    fn marker_round_trips_and_clears() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            read_marker(dir.path()),
            None,
            "no marker → nothing in flight"
        );

        let in_flight = marker("os-update", "install", 2, true);
        write_marker(dir.path(), &in_flight).expect("write");
        assert_eq!(read_marker(dir.path()), Some(in_flight));

        clear(dir.path());
        assert_eq!(read_marker(dir.path()), None);

        // A garbled marker reads as "nothing in flight" rather than wedging a phase.
        std::fs::write(marker_path(dir.path()), b"{oops").expect("write");
        assert_eq!(read_marker(dir.path()), None);
    }

    #[test]
    fn entering_a_fresh_phase_starts_on_a_full_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        assert_eq!(reboot.reboot_count(), 0);
        assert_eq!(
            reboot.request_file(),
            Some(dir.path().join(REQUEST_FILE).as_path())
        );
        assert_eq!(
            read_marker(dir.path()),
            Some(marker("demo", "install", 0, false))
        );
    }

    #[test]
    fn a_recorded_request_charges_the_counter_and_marks_the_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        std::fs::write(reboot.request_file().expect("under cap"), "-r now\n").expect("request");

        assert_eq!(
            reboot.finish().expect("finish"),
            PhaseOutcome::RebootRequested { reboot_count: 1 }
        );
        assert_eq!(
            read_marker(dir.path()),
            Some(marker("demo", "install", 1, true))
        );
        // The request is consumed, never re-read by the next pass.
        assert!(!dir.path().join(REQUEST_FILE).exists());

        // Re-entry after the restart resumes the same execution at the charged count.
        let resumed = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("re-enter");
        assert_eq!(resumed.reboot_count(), 1);
        assert_eq!(
            read_marker(dir.path()),
            Some(marker("demo", "install", 1, false))
        );
    }

    #[test]
    fn a_pass_that_asks_for_nothing_retires_the_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        assert_eq!(reboot.finish().expect("finish"), PhaseOutcome::Completed);
        assert_eq!(read_marker(dir.path()), None);
    }

    #[test]
    fn a_restart_taken_behind_the_shims_back_is_charged_on_re_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        // In flight with nothing recorded: the phase rebooted by absolute path or the
        // machine simply went away.
        write_marker(dir.path(), &marker("demo", "install", 1, false)).expect("write");

        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        assert_eq!(
            reboot.reboot_count(),
            2,
            "the unannounced restart is charged"
        );
        assert_eq!(
            read_marker(dir.path()),
            Some(marker("demo", "install", 2, false))
        );
    }

    #[test]
    fn another_phase_execution_starts_on_its_own_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_marker(dir.path(), &marker("os-update", "install", 3, true)).expect("write");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        assert_eq!(
            reboot.reboot_count(),
            0,
            "a different app gets a full budget"
        );
    }

    #[test]
    fn at_the_cap_the_phase_gets_no_request_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_marker(
            dir.path(),
            &marker("demo", "install", MAX_PHASE_REBOOTS, true),
        )
        .expect("write");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        assert_eq!(reboot.reboot_count(), MAX_PHASE_REBOOTS);
        assert_eq!(
            reboot.request_file(),
            None,
            "at the cap the shim has nowhere to record a request"
        );
        // And with nothing to consume, the pass ends normally however loudly the shim
        // refused inside it.
        assert_eq!(reboot.finish().expect("finish"), PhaseOutcome::Completed);
    }

    #[test]
    fn a_stale_request_is_not_read_as_this_passs_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(REQUEST_FILE), "-r now\n").expect("stale request");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        assert_eq!(reboot.finish().expect("finish"), PhaseOutcome::Completed);
    }

    #[test]
    fn a_failed_pass_abandons_its_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reboot = PhaseReboot::enter(dir.path(), "demo", "1.0", "install").expect("enter");
        std::fs::write(reboot.request_file().expect("under cap"), "-r now\n").expect("request");
        reboot.abandon();
        assert_eq!(read_marker(dir.path()), None);
        assert!(!dir.path().join(REQUEST_FILE).exists());
    }

    #[test]
    fn executor_reads_the_fake_mode_from_the_environment() {
        assert_eq!(RebootExecutor::parse(""), RebootExecutor::Real);
        assert_eq!(RebootExecutor::parse("real"), RebootExecutor::Real);
        assert_eq!(
            RebootExecutor::parse("fake:/tmp/reboots"),
            RebootExecutor::Fake(PathBuf::from("/tmp/reboots"))
        );
    }

    #[test]
    fn the_fake_executor_records_a_line_per_reboot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("reboots");
        let executor = RebootExecutor::Fake(log.clone());
        assert_eq!(executor.execute("demo install"), RebootAction::Recorded);
        assert_eq!(executor.execute("demo install"), RebootAction::Recorded);
        assert_eq!(
            std::fs::read_to_string(&log).expect("log"),
            "demo install\ndemo install\n"
        );
    }

    #[test]
    fn the_fake_executor_reports_a_path_it_cannot_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let executor = RebootExecutor::Fake(dir.path().join("missing").join("reboots"));
        assert_eq!(executor.execute("demo install"), RebootAction::Failed);
    }

    // ─── The shim scripts, run for real ──────────────────────────────────────────

    #[cfg(unix)]
    struct ShimRun {
        status: std::process::ExitStatus,
        stderr: String,
        request: Option<String>,
    }

    /// Runs a generated shim script with `args`, optionally under a request file.
    #[cfg(unix)]
    fn run_shim(command: &str, args: &[&str], with_request: bool) -> ShimRun {
        let dir = tempfile::tempdir().expect("tempdir");
        let shim_dir = install_shim(dir.path()).expect("shim");
        let request = dir.path().join(REQUEST_FILE);
        let mut process = std::process::Command::new(shim_dir.join(command));
        process.args(args).env_remove(REQUEST_ENV);
        if with_request {
            process.env(REQUEST_ENV, &request);
        }
        let output = process.output().expect("run shim");
        ShimRun {
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            request: std::fs::read_to_string(&request).ok(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_shim_accepts_every_restart_spelling() {
        for args in [
            vec!["-r", "now"],
            vec!["now", "-r"],
            vec!["-r"],
            vec!["--reboot", "+1"],
        ] {
            let run = run_shim("shutdown", &args, true);
            assert!(
                run.status.success(),
                "shutdown {args:?} must be accepted: {}",
                run.stderr
            );
            assert_eq!(
                run.request.as_deref(),
                Some(format!("{}\n", args.join(" ")).as_str()),
                "the request records the literal arguments"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_shim_refuses_every_power_off_spelling() {
        for args in [
            vec!["-h", "now"],
            vec!["-P", "now"],
            vec!["--halt"],
            vec!["-p"],
            vec![],
        ] {
            let run = run_shim("shutdown", &args, true);
            assert!(!run.status.success(), "shutdown {args:?} must be refused");
            assert!(
                run.stderr.contains("orc: phase may not power off the node"),
                "shutdown {args:?} says why: {}",
                run.stderr
            );
            assert_eq!(run.request, None, "a refusal records nothing");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_bare_reboot_command_is_a_restart_request() {
        let run = run_shim("reboot", &[], true);
        assert!(
            run.status.success(),
            "reboot must be accepted: {}",
            run.stderr
        );
        assert!(run.request.is_some(), "reboot records a request");

        // ...but its power-off flags are refused like shutdown's.
        let halt = run_shim("reboot", &["-p"], true);
        assert!(!halt.status.success());
        assert!(
            halt.stderr
                .contains("orc: phase may not power off the node")
        );
        assert_eq!(halt.request, None);
    }

    // ─── The multi-call shim ─────────────────────────────────────────────────────

    struct CoreRun {
        code: i32,
        out: String,
        err: String,
        request: Option<String>,
    }

    /// Runs the shim core over `args`, with or without a granted request file.
    fn run_core(args: &[&str], with_request: bool) -> CoreRun {
        run_core_denied(args, with_request, None)
    }

    /// The same, for a phase the runtime refused outright with its own reason.
    fn run_core_denied(args: &[&str], with_request: bool, deny: Option<&str>) -> CoreRun {
        let dir = tempfile::tempdir().expect("tempdir");
        let request = dir.path().join(REQUEST_FILE);
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_shim_args(
            &args,
            with_request.then_some(request.as_path()),
            deny,
            &mut out,
            &mut err,
        );
        CoreRun {
            code,
            out: String::from_utf8(out).expect("utf-8 stdout"),
            err: String::from_utf8(err).expect("utf-8 stderr"),
            request: std::fs::read_to_string(&request).ok(),
        }
    }

    #[test]
    fn the_shim_core_accepts_every_restart_spelling_anywhere_in_the_arguments() {
        for args in [
            vec!["/r"],
            vec!["/R"],
            vec!["/r", "/t", "0"],
            vec!["/t", "0", "/r"],
            vec!["-r", "now"],
            vec!["now", "-r"],
            vec!["--reboot", "+1"],
        ] {
            let run = run_core(&args, true);
            assert_eq!(
                run.code, 0,
                "shutdown {args:?} must be accepted: {}",
                run.err
            );
            assert_eq!(
                run.out,
                "orc: reboot requested; the runtime restarts this node after the phase\n"
            );
            assert_eq!(
                run.request.as_deref(),
                Some(format!("{}\n", args.join(" ")).as_str()),
                "the request records the literal arguments"
            );
        }
    }

    #[test]
    fn the_shim_core_refuses_every_power_off_spelling() {
        for args in [
            vec!["/s"],
            vec!["/s", "/t", "0"],
            vec!["-h", "now"],
            vec!["-P", "now"],
            vec!["--halt"],
            vec!["-p"],
            vec![],
        ] {
            let run = run_core(&args, true);
            assert_eq!(run.code, 1, "shutdown {args:?} must be refused");
            assert_eq!(run.err, "orc: phase may not power off the node\n");
            assert!(run.out.is_empty(), "a refusal says nothing on stdout");
            assert_eq!(run.request, None, "a refusal records nothing");
        }
    }

    #[test]
    fn the_shim_core_refuses_a_restart_once_the_budget_is_gone() {
        // No request file granted: exactly what the runtime does at the cap, and the
        // refusal lands in the phase's own log.
        let run = run_core(&["/r", "/t", "0"], false);
        assert_eq!(run.code, 1);
        assert_eq!(run.err, "orc: reboot budget exhausted; request refused\n");
        assert!(run.out.is_empty());
    }

    /// A phase that may not restart the node at all is refused with its own reason,
    /// not with the budget message — the phase's log has to say why.
    #[test]
    fn the_shim_core_refuses_a_phase_that_may_not_restart_at_all() {
        let run = run_core_denied(
            &["-r", "now"],
            false,
            Some("a stop hook may not restart the node"),
        );
        assert_eq!(run.code, 1);
        assert_eq!(
            run.err,
            "orc: a stop hook may not restart the node; request refused\n"
        );
        assert!(run.out.is_empty());
        assert_eq!(run.request, None);
    }

    /// The refusing plumbing lays the shim down and grants nothing, so the phase env
    /// built from it puts the shim first on `PATH` with no request file to write.
    #[test]
    fn refusing_plumbing_installs_the_shim_and_grants_no_request() {
        let state = tempfile::tempdir().expect("state dir");
        let reboot = PhaseReboot::refusing(state.path(), "a stop hook may not restart the node")
            .expect("refusing");
        assert!(reboot.shim_dir().exists());
        assert_eq!(reboot.request_file(), None);
        assert_eq!(
            reboot.deny_reason(),
            Some("a stop hook may not restart the node")
        );
        // No phase execution was opened, so nothing is left in flight either.
        assert_eq!(read_marker(state.path()), None);
    }

    #[test]
    fn a_request_that_cannot_be_written_is_not_reported_as_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unwritable = dir.path().join("missing").join(REQUEST_FILE);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_shim_args(
            &["/r".to_owned()],
            Some(unwritable.as_path()),
            None,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        assert!(out.is_empty(), "the phase must not be told the reboot took");
        assert!(
            String::from_utf8_lossy(&err).contains("could not be recorded"),
            "the write failure is narrated: {}",
            String::from_utf8_lossy(&err)
        );
    }

    #[test]
    fn a_runtime_invoked_as_itself_is_not_the_shim() {
        // The test binary is named after its target, never `shutdown`, so dispatch
        // must decline here. The granted path is covered end to end by the CLI suite,
        // which hardlinks the built binary under the shim's name and runs it.
        assert_eq!(maybe_run_shim(), None);
    }

    #[test]
    fn installing_the_multicall_shim_replaces_what_an_earlier_runtime_left() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(WINDOWS_LEGACY_SHIM), "@echo off\r\n").expect("legacy");
        std::fs::write(dir.path().join(WINDOWS_SHIM), b"an older runtime").expect("stale");

        remove_legacy_shim(dir.path());
        install_multicall_shim(dir.path()).expect("install");

        assert!(
            !dir.path().join(WINDOWS_LEGACY_SHIM).exists(),
            "the batch shim of older runtimes is cleared"
        );
        let installed = std::fs::read(dir.path().join(WINDOWS_SHIM)).expect("shim");
        let running = std::fs::read(std::env::current_exe().expect("current exe")).expect("exe");
        assert_eq!(installed, running, "the shim is the running binary");

        // Re-laying it on the next phase entry is idempotent, link or copy.
        install_multicall_shim(dir.path()).expect("re-install");
        assert!(dir.path().join(WINDOWS_SHIM).exists());
    }

    #[test]
    fn clearing_a_legacy_shim_that_is_not_there_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        remove_legacy_shim(dir.path());
        assert!(!dir.path().join(WINDOWS_LEGACY_SHIM).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_shim_refuses_a_restart_once_the_budget_is_gone() {
        // No request variable exported: this is exactly what the runtime does at the
        // cap, and the refusal lands in the phase's own log.
        for command in ["shutdown", "reboot"] {
            let args: &[&str] = if command == "shutdown" {
                &["-r", "now"]
            } else {
                &[]
            };
            let run = run_shim(command, args, false);
            assert!(
                !run.status.success(),
                "{command} must be refused at the cap"
            );
            assert!(
                run.stderr
                    .contains("orc: reboot budget exhausted; request refused"),
                "{command} says why: {}",
                run.stderr
            );
            assert_eq!(run.request, None);
        }
    }
}
