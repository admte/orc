//! The supervisor an `orc start` becomes, and how another shell finds it again.
//!
//! A foreground `orc start` is the app's runtime: it holds the child, it owns the
//! termination sequence, and it is the only process that can run it. `orc stop` in a
//! second terminal therefore does not stop the app itself — it asks that supervisor to,
//! by signal.
//!
//! Which makes the pid the whole problem. A pid on its own is a number the operating
//! system hands out again, so a recorded pid whose supervisor died is a loaded gun
//! pointed at whatever process inherited the number. Everything here exists to make the
//! answer to "is that still our supervisor?" a fact rather than an assumption: the pid
//! is written to a marker inside the app's own work directory, alongside a token that
//! only the process that wrote it can still match, and a signal is sent only when both
//! agree.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

/// Marker file naming the process supervising this app, inside the app's work dir.
const MARKER_FILE: &str = ".orc-supervisor.json";

/// Who is supervising one installed app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    /// The supervising process — the `orc start` that holds the app's child.
    pub pid: u32,
    /// Proof that the pid was not recycled: on Linux the kernel's own start time for
    /// that process, which no later process reusing the number can reproduce. `None`
    /// where the platform does not offer one cheaply, and then liveness is all there is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_token: Option<String>,
}

/// What a stop found when it looked for the supervisor a record named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervision {
    /// The recorded process is alive and is the one that started this app.
    Live(u32),
    /// Nothing is supervising this app: no marker, a pid that has gone, or a pid the
    /// system has since handed to somebody else. Never signalled.
    Gone,
}

#[must_use]
pub fn marker_path(work_dir: &Path) -> PathBuf {
    work_dir.join(MARKER_FILE)
}

/// Records this process as the app's supervisor.
pub fn record(work_dir: &Path) -> Result<Marker> {
    let pid = std::process::id();
    let marker = Marker {
        pid,
        start_token: start_token(pid),
    };
    let path = marker_path(work_dir);
    let body = serde_json::to_vec(&marker)
        .map_err(|err| CliError::Operational(format!("encode the supervisor record: {err}")))?;
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    Ok(marker)
}

/// Reads the marker back, or `None` when there is none to read.
#[must_use]
pub fn read(work_dir: &Path) -> Option<Marker> {
    let body = std::fs::read(marker_path(work_dir)).ok()?;
    serde_json::from_slice(&body).ok()
}

/// Drops the marker. Best-effort: it is cleanup, and the caller is on its way out.
pub fn clear(work_dir: &Path) {
    let _ = std::fs::remove_file(marker_path(work_dir));
}

/// Whether the process a record names is still this app's supervisor.
///
/// Three things have to agree before a signal is sent: a marker exists, it names the pid
/// the install record does, and that pid is both alive and still the same process the
/// marker was written by. Any disagreement reads as [`Supervision::Gone`] — the app is
/// reported as no longer running rather than signalled on a guess.
#[must_use]
pub fn supervision(work_dir: &Path, recorded_pid: Option<u32>) -> Supervision {
    let Some(marker) = read(work_dir) else {
        return Supervision::Gone;
    };
    if recorded_pid.is_some_and(|pid| pid != marker.pid) {
        return Supervision::Gone;
    }
    if !alive(marker.pid) {
        return Supervision::Gone;
    }
    // A token the platform can produce but that does not match is a recycled pid: the
    // number is alive, the process behind it is somebody else's.
    if let Some(recorded) = &marker.start_token
        && start_token(marker.pid).is_some_and(|current| &current != recorded)
    {
        return Supervision::Gone;
    }
    Supervision::Live(marker.pid)
}

/// Asks the supervisor to stop the app: `SIGTERM` for the graceful sequence, `SIGUSR1`
/// for the forced one, which the `orc start` handler reads as "do not wait".
#[cfg(unix)]
pub fn ask_to_stop(pid: u32, force: bool) -> Result<()> {
    let signal = if force { libc::SIGUSR1 } else { libc::SIGTERM };
    let Ok(pid) = i32::try_from(pid) else {
        return Err(CliError::Operational(
            "the recorded supervisor pid is not a valid process id".to_owned(),
        ));
    };
    // SAFETY: `kill` takes two integers by value and has no memory preconditions. The
    // pid was verified as this app's live supervisor immediately above the call site.
    #[allow(unsafe_code)]
    let sent = unsafe { libc::kill(pid, signal) };
    if sent == 0 {
        return Ok(());
    }
    Err(CliError::Operational(format!(
        "signal the supervisor: {}",
        std::io::Error::last_os_error()
    )))
}

/// Whether a process with this id exists.
///
/// `EPERM` counts as alive: the process is there, it simply is not ours to signal, and
/// reporting it as gone would let a stop clear a record for an app that is still running.
#[cfg(unix)]
#[must_use]
pub fn alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 performs the permission and existence checks without delivering
    // anything; both arguments are integers passed by value.
    #[allow(unsafe_code)]
    let probe = unsafe { libc::kill(pid, 0) };
    probe == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Windows has no supervisor signalling, so nothing here asks a process anything; the
/// pid is reported as present and the caller refuses the live stop.
#[cfg(not(unix))]
#[must_use]
pub fn alive(_pid: u32) -> bool {
    true
}

/// A value only the process that wrote it can still produce: the kernel's own record of
/// when that pid started. Field 22 of `/proc/<pid>/stat`, read after the command name,
/// which is the one field that may itself contain spaces and brackets.
#[cfg(target_os = "linux")]
fn start_token(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19).map(str::to_owned)
}

/// No cheap start time on this platform: liveness is the whole check, and the marker
/// says so by carrying no token rather than by carrying an unverifiable one.
#[cfg(not(target_os = "linux"))]
fn start_token(_pid: u32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_supervisor_reads_back_as_this_process() {
        let dir = tempfile::tempdir().expect("work dir");
        let marker = record(dir.path()).expect("record");
        assert_eq!(marker.pid, std::process::id());
        assert_eq!(read(dir.path()), Some(marker.clone()));
        assert_eq!(
            supervision(dir.path(), Some(marker.pid)),
            Supervision::Live(marker.pid)
        );
    }

    #[test]
    fn no_marker_means_nothing_is_supervising() {
        let dir = tempfile::tempdir().expect("work dir");
        assert_eq!(supervision(dir.path(), Some(1)), Supervision::Gone);
    }

    #[test]
    fn a_marker_disagreeing_with_the_record_is_never_signalled() {
        let dir = tempfile::tempdir().expect("work dir");
        let marker = record(dir.path()).expect("record");
        assert_eq!(
            supervision(dir.path(), Some(marker.pid + 1)),
            Supervision::Gone
        );
    }

    /// The recycled-pid case: this process is alive, but the marker was written by a
    /// process that started at a different time, so it is not the app's supervisor.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_recycled_pid_is_gone_even_though_it_is_alive() {
        let dir = tempfile::tempdir().expect("work dir");
        let pid = std::process::id();
        let body = serde_json::to_vec(&Marker {
            pid,
            start_token: Some("0".to_owned()),
        })
        .expect("marker json");
        std::fs::write(marker_path(dir.path()), body).expect("write marker");
        assert!(alive(pid));
        assert_eq!(supervision(dir.path(), Some(pid)), Supervision::Gone);
    }

    #[test]
    fn clearing_removes_the_marker() {
        let dir = tempfile::tempdir().expect("work dir");
        record(dir.path()).expect("record");
        clear(dir.path());
        assert_eq!(read(dir.path()), None);
    }
}
