//! Supervised app child processes.

#![allow(clippy::missing_errors_doc)]

use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Instant;

use futures_util::StreamExt as _;
use futures_util::stream::BoxStream;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

use crate::error::{CliError, Result};
use crate::service::{ServiceBackend, ServiceState, ServiceStatus};

/// The signal an app is asked to end with (`stop.signal`).
///
/// A closed set: these are the signals a well-behaved app installs a handler for. A
/// recipe naming anything else is a configuration error rather than a silent SIGTERM,
/// because "the signal my app listens for" is precisely the thing an author gets
/// wrong once and never notices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopSignal {
    #[default]
    Term,
    Int,
    Hup,
    Usr1,
    Usr2,
}

impl StopSignal {
    /// Reads `stop.signal`. Accepts the `SIG`-prefixed spelling and the bare one, in
    /// any case; rejects everything outside the allowed set.
    pub fn parse(value: &str) -> Result<Self> {
        let name = value.trim();
        let bare = name
            .strip_prefix("SIG")
            .or_else(|| name.strip_prefix("sig"))
            .unwrap_or(name);
        match bare.to_ascii_uppercase().as_str() {
            "TERM" => Ok(Self::Term),
            "INT" => Ok(Self::Int),
            "HUP" => Ok(Self::Hup),
            "USR1" => Ok(Self::Usr1),
            "USR2" => Ok(Self::Usr2),
            _ => Err(CliError::Usage(format!(
                "stop signal {value:?} is not one of SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2"
            ))),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Int => "SIGINT",
            Self::Hup => "SIGHUP",
            Self::Usr1 => "SIGUSR1",
            Self::Usr2 => "SIGUSR2",
        }
    }

    #[cfg(unix)]
    #[must_use]
    fn number(self) -> i32 {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Int => libc::SIGINT,
            Self::Hup => libc::SIGHUP,
            Self::Usr1 => libc::SIGUSR1,
            Self::Usr2 => libc::SIGUSR2,
        }
    }
}

/// How the app was asked to end, for the operator's log.
///
/// The ask differs by platform and run mode — a Unix child gets a signal, a service
/// gets its manager's stop, a Windows child gets nothing at all — and only the log
/// cares which, so the termination sequence reads this instead of branching itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopAsk {
    /// The signal the app declared was delivered to its process group.
    Signal(StopSignal),
    /// The service manager was asked to stop the app; it delivers its own signal.
    Manager,
    /// Nothing could be asked; the wait is the whole of the app's chance.
    None,
}

/// What is running for one app, as the termination sequence sees it.
///
/// Either a child the runtime spawned and supervises, or a service the platform's own
/// manager runs. The sequence is the same over both — the stop command, the ask, the
/// grace, the kill — which is exactly why it talks to this rather than to a [`Child`].
pub enum AppProcess<'a> {
    /// A child process the runtime spawned itself. On Unix it leads its own process
    /// group (see [`spawn_app`]), so signals reach the whole tree it started.
    Subprocess {
        child: &'a mut Child,
        /// When the app started; the stopped hook reports how long it ran.
        started: Instant,
    },
    /// A service the platform's manager runs. The runtime holds a name, not a handle:
    /// what it knows about the app comes from the manager telling it.
    Service {
        backend: Arc<dyn ServiceBackend>,
        /// The platform service name.
        name: String,
        started: Instant,
        /// The manager's own state changes for this service; the wait reads its next
        /// terminal state off here.
        states: BoxStream<'static, ServiceStatus>,
        /// The main pid as last reported, so the stop hooks can be told `APP_PID`.
        pid: Option<u32>,
        /// The last state seen, which decides what a terminal state without an exit
        /// recorded means.
        state: ServiceState,
    },
}

impl<'a> AppProcess<'a> {
    /// A supervised child that started at `started`.
    #[must_use]
    pub fn subprocess(child: &'a mut Child, started: Instant) -> Self {
        Self::Subprocess { child, started }
    }

    /// A service the platform's manager runs, watched from the moment this is built.
    ///
    /// The watch is opened here rather than at the first wait so that a service that
    /// fails between the start and the wait is still seen: the runtime learns what the
    /// manager did, not what it happened to be doing when somebody looked.
    #[must_use]
    pub fn service(
        backend: Arc<dyn ServiceBackend>,
        name: String,
        started: Instant,
        pid: Option<u32>,
    ) -> Self {
        let states = backend.watch(&name);
        Self::Service {
            backend,
            name,
            started,
            states,
            pid,
            state: ServiceState::Unknown,
        }
    }

    /// When the app started.
    #[must_use]
    pub fn started(&self) -> Instant {
        match self {
            Self::Subprocess { started, .. } | Self::Service { started, .. } => *started,
        }
    }

    /// The app's process id while it is still running.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Subprocess { child, .. } => child.id(),
            Self::Service { pid, .. } => *pid,
        }
    }

    /// Waits for the app to end.
    ///
    /// Cancel-safe: the termination sequence races this against the stop command, the
    /// grace deadline and the force token, and resumes the same wait afterwards.
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Subprocess { child, .. } => child.wait().await,
            Self::Service {
                states,
                pid,
                state,
                name,
                ..
            } => {
                while let Some(status) = states.next().await {
                    if status.main_pid.is_some() {
                        *pid = status.main_pid;
                    }
                    *state = status.state;
                    // A manager restarting the app under its own policy passes through
                    // the non-terminal states, which is what keeps that restart
                    // invisible to the runtime rather than reported as a failure.
                    if status.state.is_terminal() {
                        return Ok(service_exit_status(&status));
                    }
                }
                Err(std::io::Error::other(format!(
                    "service {name} is no longer reporting its state"
                )))
            }
        }
    }

    /// Asks the app to end: a Unix child's process group gets `signal`, a service gets
    /// its manager's stop (which delivers the manager's own configured signal), and a
    /// Windows child gets nothing — there the stop command was the whole ask.
    pub async fn signal(&mut self, signal: StopSignal) -> StopAsk {
        match self {
            Self::Subprocess { child, .. } => {
                #[cfg(unix)]
                {
                    signal_tree(child, signal.number());
                    StopAsk::Signal(signal)
                }
                #[cfg(not(unix))]
                {
                    let _ = signal;
                    let _ = child;
                    StopAsk::None
                }
            }
            Self::Service { backend, name, .. } => {
                if let Err(err) = backend.stop(name).await {
                    tracing::warn!(service = %name, error = %err, "service stop could not be requested");
                    return StopAsk::None;
                }
                StopAsk::Manager
            }
        }
    }

    /// Ends the app the hard way: `SIGKILL` to its process group on Unix, `taskkill
    /// /T /F` on Windows. Both take the tree, not just the process the runtime holds.
    #[allow(
        clippy::unused_async,
        reason = "the Windows kill awaits taskkill; the call reads the same on both"
    )]
    pub async fn kill(&mut self) {
        match self {
            Self::Service { backend, name, .. } => {
                if let Err(err) = backend.kill(name).await {
                    tracing::warn!(service = %name, error = %err, "service could not be killed");
                }
            }
            Self::Subprocess { child, .. } => {
                #[cfg(unix)]
                signal_tree(child, libc::SIGKILL);
                #[cfg(not(unix))]
                taskkill_tree(child).await;
                // Always follow up with the runtime's own kill: on Unix it is a no-op
                // for an already-signalled child, and it is what closes the handle
                // where the platform kill did not land.
                let _ = child.start_kill();
            }
        }
    }
}

/// Renders a manager-reported exit as the platform status the termination sequence
/// reads exits off.
///
/// The manager reports an exit code **or** a signal, never both, so the status carries
/// whichever it gave. A terminal state with no exit recorded is read from the state
/// itself: a failed service that ended in a way the manager could not describe is still
/// a failure, and reporting it as a clean exit 0 would hide it.
fn service_exit_status(status: &ServiceStatus) -> ExitStatus {
    let (code, signal) = match (status.exit_code, status.exit_signal) {
        (_, Some(signal)) => (0, signal),
        (Some(code), None) => (code, 0),
        (None, None) if status.state == ServiceState::Failed => (1, 0),
        (None, None) => (0, 0),
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if signal != 0 {
            return ExitStatus::from_raw(signal & 0x7f);
        }
        ExitStatus::from_raw((code & 0xff) << 8)
    }
    #[cfg(not(unix))]
    {
        use std::os::windows::process::ExitStatusExt as _;
        let _ = signal;
        ExitStatus::from_raw(u32::try_from(code).unwrap_or(1))
    }
}

/// Sends `signal` to the process group a child leads, or to the child alone when it
/// leads none.
///
/// Every app and phase command leads its own group (see [`crate::lifecycle`]'s command
/// builders), so this reaches whatever a wrapper started — a login shell's forked child
/// included. `killpg` only ever addresses the group the child itself leads: for a child
/// that leads none it fails with `ESRCH` and never reaches the runtime's own group, and
/// the signal then goes to the child alone. A process that called `setsid` or moved to
/// another group has left on purpose and is not followed.
#[cfg(unix)]
fn signal_tree(child: &Child, signal: i32) {
    let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) else {
        // No pid means the child was already reaped; there is nothing to signal, and
        // the number could by then belong to somebody else.
        return;
    };
    // SAFETY: both calls take a pid by value and have no memory preconditions. The
    // child is still owned here, so neither its pid nor the group it leads can have
    // been recycled.
    #[allow(unsafe_code)]
    let sent = unsafe {
        if libc::killpg(pid, signal) == 0 {
            true
        } else if is_gone() {
            libc::kill(pid, signal) == 0
        } else {
            false
        }
    };
    // A child that has already ended is not a failure to report: there is nothing
    // left to end.
    let errno = last_errno();
    if !sent && errno != libc::ESRCH {
        tracing::warn!(pid, signal, errno, "app could not be signalled");
    }
}

/// Whether the last failed call found no such process or group, which for a signal
/// means there is nothing left to end.
#[cfg(unix)]
fn is_gone() -> bool {
    last_errno() == libc::ESRCH
}

/// The errno the last failed call left.
#[cfg(unix)]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Windows has no process groups a runtime can signal, so the whole tree is ended
/// through `taskkill`, which walks the child list itself.
#[cfg(not(unix))]
async fn taskkill_tree(child: &Child) {
    let Some(pid) = child.id() else {
        return;
    };
    let _ = Command::new("taskkill")
        .arg("/T")
        .arg("/F")
        .arg("/PID")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// An operator's interrupt of a foreground command, handed to the phases it runs.
///
/// A phase that sees it raised sends `SIGINT` to its process group, gives the group
/// [`crate::lifecycle::SHUTDOWN_GRACE`], kills what is left, and fails with
/// [`CliError::Interrupted`]. Once raised it stays raised, so a command the operator
/// interrupted starts no further phase. A runtime with no operator at a terminal, such
/// as the agent or a service, passes none.
#[derive(Debug, Clone, Default)]
pub struct PhaseInterrupt {
    raised: CancellationToken,
    signal: Arc<AtomicI32>,
}

impl PhaseInterrupt {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `signal` interrupted the command. The first signal is the one kept.
    pub fn raise(&self, signal: i32) {
        let _ = self
            .signal
            .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
        self.raised.cancel();
    }

    /// The signal that interrupted the command, once one has.
    #[must_use]
    pub fn signal(&self) -> Option<i32> {
        self.raised
            .is_cancelled()
            .then(|| self.signal.load(Ordering::SeqCst))
    }

    /// Resolves with the interrupting signal once the command is interrupted.
    pub async fn raised(&self) -> i32 {
        self.raised.cancelled().await;
        self.signal.load(Ordering::SeqCst)
    }

    /// Fails with [`CliError::Interrupted`] for `phase` once the command is interrupted.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Interrupted`] when the interrupt has been raised.
    pub fn check(&self, phase: &str) -> Result<()> {
        self.signal().map_or(Ok(()), |signal| {
            Err(CliError::Interrupted {
                phase: phase.to_owned(),
                signal,
            })
        })
    }
}

/// Resolves with the interrupting signal once `interrupt` is raised; never, without one.
pub async fn interrupted(interrupt: Option<&PhaseInterrupt>) -> i32 {
    match interrupt {
        Some(interrupt) => interrupt.raised().await,
        None => std::future::pending().await,
    }
}

/// Child stream that produced a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

impl LogStream {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Shared callback a drained child stream forwards each line to. Hosts label the
/// line with the owning app and map the stream to a log level (stderr→warn,
/// stdout→info); see [`spawn_app`] and the lifecycle phase runners.
pub type LogLine = Arc<dyn Fn(LogStream, &str) + Send + Sync>;

/// Outcome of classifying a supervised child exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExitOutcome {
    /// Process exited zero; report `completed`.
    Completed,
    /// Process failed; report `failed` with [`ChildExit::cause`].
    Failed,
}

/// Classified child exit for status reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildExit {
    pub outcome: ChildExitOutcome,
    /// Free-text reason for the status report / termination narrative.
    pub reason: String,
    /// Exit code when the process exited normally (not by signal); `None` for signals.
    pub exit_code: Option<i32>,
    /// Wire cause token (`""`, `"exit-error"`, `"oom-killed"`, `"signal"`).
    pub cause: &'static str,
}

/// Classifies a supervised child [`ExitStatus`] into a status-report payload.
///
/// On Unix, `SIGKILL` (9) maps to `oom-killed` and other signals to `signal`.
/// A non-zero exit code is `exit-error`. A clean exit is a graceful completion.
#[must_use]
pub fn classify_child_exit(status: ExitStatus) -> ChildExit {
    if status.success() {
        return ChildExit {
            outcome: ChildExitOutcome::Completed,
            reason: "completed".to_owned(),
            exit_code: None,
            cause: "",
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            let cause = if signal == 9 { "oom-killed" } else { "signal" };
            return ChildExit {
                outcome: ChildExitOutcome::Failed,
                reason: format!("killed by signal {signal}"),
                exit_code: None,
                cause,
            };
        }
    }
    let code = status.code();
    ChildExit {
        outcome: ChildExitOutcome::Failed,
        reason: code.map_or_else(
            || "app exited abnormally".to_owned(),
            |c| format!("app exited with code {c}"),
        ),
        exit_code: code,
        cause: "exit-error",
    }
}

/// Spawns an ordinary app and drains stdout and stderr to `log_line`.
///
/// On Unix the app leads its own process group. An app is a tree — a shell that
/// execs a launcher that starts the real process — and the runtime holds only its
/// root; a group is what lets the stop signal, and the kill behind it, reach every
/// process the app started rather than the one the runtime happens to know about.
pub fn spawn_app(
    command: Command,
    log_line: impl Fn(LogStream, &str) + Send + Sync + 'static,
) -> Result<Child> {
    let mut child = spawn_piped_app(command)?;
    let log_line: LogLine = Arc::new(log_line);

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::Operational("app stderr not piped".to_owned()))?;
    drain_lines(
        BufReader::new(stderr),
        LogStream::Stderr,
        Arc::clone(&log_line),
        Vec::new(),
    );

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Operational("app stdout not piped".to_owned()))?;
    drain_lines(
        BufReader::new(stdout),
        LogStream::Stdout,
        log_line,
        Vec::new(),
    );
    Ok(child)
}

/// Spawns an app with piped output streams and the platform's process-tree setup.
///
/// Hosts that own a protocol layered on an app process can take the pipes themselves.
/// Ordinary app callers should use [`spawn_app`], which always drains output as logs.
pub fn spawn_piped_app(mut command: Command) -> Result<Child> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    command
        .spawn()
        .map_err(|err| CliError::Operational(format!("spawn app: {err}")))
}

/// Delivers `signal` to the app's process group, falling back to the process alone
/// when it does not lead one.
#[cfg(unix)]
pub fn terminate(child: &mut Child, signal: StopSignal) {
    signal_tree(child, signal.number());
}

/// Windows cannot ask an arbitrary process to end, so the polite step is the app's own
/// stop command and this closes the handle the runtime holds.
#[cfg(not(unix))]
pub fn terminate(child: &mut Child, _signal: StopSignal) {
    let _ = child.start_kill();
}

/// Spawns a task forwarding lines (continuing any `partial` first line) to `log`.
///
/// The returned handle resolves once the stream reaches EOF and every buffered
/// line has been forwarded; blocking lifecycle phases join it so no trailing
/// output is lost, while long-lived supervised apps just drop it (detaching the
/// task, which keeps draining until the child's pipe closes).
pub fn drain_lines(
    mut reader: impl AsyncBufRead + Unpin + Send + 'static,
    stream: LogStream,
    log: LogLine,
    mut partial: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match reader.read_until(b'\n', &mut partial).await {
                Ok(0) => {
                    // A stream that ended on a line break has nothing left over.
                    if !partial.is_empty()
                        && let Some(line) = output_line(&partial)
                    {
                        log(stream, &line);
                    }
                    break;
                }
                Ok(_) => {
                    if partial.ends_with(b"\n") {
                        if let Some(line) = output_line(&partial) {
                            log(stream, &line);
                        }
                        partial.clear();
                    }
                }
                Err(_) => break,
            }
        }
    })
}

/// One line of an app's output as the log shows it, or `None` when it shows nothing.
///
/// The line breaks are trimmed, carriage returns included. Output that is valid UTF-8
/// is UTF-8. On Windows anything else is text in the console's code page — what a
/// .NET or C program writes there when its output is a pipe, `√` included — and a
/// blank line, which a Windows program prints between paragraphs as a bare `\r\n`, is
/// dropped. Elsewhere invalid bytes read as replacement characters and every line is
/// kept, as before.
fn output_line(raw: &[u8]) -> Option<String> {
    decode_line(raw, cfg!(windows), legacy_text)
}

/// [`output_line`] with the platform's choices passed in: whether blank lines are
/// dropped, and how bytes that are not UTF-8 are read.
fn decode_line(
    raw: &[u8],
    drop_blank: bool,
    legacy: impl FnOnce(&[u8]) -> Option<String>,
) -> Option<String> {
    let line = trim_line(raw);
    let text = match std::str::from_utf8(line) {
        Ok(text) => text.to_owned(),
        Err(_) => legacy(line).unwrap_or_else(|| String::from_utf8_lossy(line).into_owned()),
    };
    if drop_blank && text.trim().is_empty() {
        return None;
    }
    Some(text)
}

/// Reads bytes in the console's output code page, or the system's OEM code page when
/// this process has no console — the one a console program falls back to.
#[cfg(windows)]
#[allow(unsafe_code, reason = "code page conversion has no safe API")]
fn legacy_text(bytes: &[u8]) -> Option<String> {
    use windows_sys::Win32::Globalization::GetOEMCP;
    use windows_sys::Win32::System::Console::GetConsoleOutputCP;

    // SAFETY: no arguments.
    let (console, oem) = unsafe { (GetConsoleOutputCP(), GetOEMCP()) };
    code_page_text(legacy_code_page(console, oem)?, bytes)
}

/// The code page that bytes which are not UTF-8 were written in: the console's, or the
/// OEM one when there is no console (0) or the console is UTF-8 — the bytes are no
/// UTF-8, so whatever wrote them did not use it. `None` when no legacy code page is
/// left to try.
#[cfg_attr(not(windows), allow(dead_code, reason = "only Windows has code pages"))]
fn legacy_code_page(console: u32, oem: u32) -> Option<u32> {
    const UTF8: u32 = 65001;
    [console, oem]
        .into_iter()
        .find(|code_page| *code_page != 0 && *code_page != UTF8)
}

/// Decodes `bytes` from the Windows code page `code_page`.
#[cfg(windows)]
#[allow(unsafe_code, reason = "code page conversion has no safe API")]
fn code_page_text(code_page: u32, bytes: &[u8]) -> Option<String> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;

    let length = i32::try_from(bytes.len()).ok()?;
    if length == 0 {
        return Some(String::new());
    }
    // SAFETY: `bytes` is valid for `length` bytes; a null output asks for the size.
    let wide = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
        )
    };
    let mut buffer = vec![0_u16; usize::try_from(wide).ok().filter(|wide| *wide > 0)?];
    // SAFETY: `buffer` holds exactly the `wide` units the first call asked for.
    let written = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            length,
            buffer.as_mut_ptr(),
            wide,
        )
    };
    buffer.truncate(
        usize::try_from(written)
            .ok()
            .filter(|written| *written > 0)?,
    );
    String::from_utf16(&buffer).ok()
}

#[cfg(not(windows))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Windows reads another code page here; other platforms have none to read"
)]
fn legacy_text(_bytes: &[u8]) -> Option<String> {
    None
}

fn trim_line(line: &[u8]) -> &[u8] {
    let mut line = line;
    while let [rest @ .., last] = line {
        if *last == b'\n' || *last == b'\r' {
            line = rest;
        } else {
            break;
        }
    }
    line
}

#[cfg(test)]
mod output_tests {
    use super::*;

    #[test]
    fn a_utf8_line_reads_as_written_without_its_line_break() {
        let never = |_: &[u8]| -> Option<String> { panic!("UTF-8 needs no other reading") };
        assert_eq!(
            decode_line("tests passed \u{221a}\r\n".as_bytes(), true, never),
            Some("tests passed \u{221a}".to_owned())
        );
        assert_eq!(
            decode_line(b"done\r\r\n", false, never),
            Some("done".to_owned())
        );
    }

    /// A byte UTF-8 cannot read is handed to the platform's code page, not replaced.
    #[test]
    fn bytes_that_are_not_utf8_are_read_in_the_legacy_code_page() {
        let cp437 = |bytes: &[u8]| -> Option<String> {
            Some(
                bytes
                    .iter()
                    .map(|byte| {
                        if *byte == 0xFB {
                            '\u{221a}'
                        } else {
                            char::from(*byte)
                        }
                    })
                    .collect(),
            )
        };
        assert_eq!(
            decode_line(b"ok \xFB\r\n", true, cp437),
            Some("ok \u{221a}".to_owned())
        );
        // With no code page to read them in, they are replaced as before.
        assert_eq!(
            decode_line(b"ok \xFB\n", false, |_| None),
            Some("ok \u{fffd}".to_owned())
        );
    }

    #[test]
    fn the_legacy_code_page_is_never_utf8() {
        assert_eq!(legacy_code_page(437, 437), Some(437));
        assert_eq!(legacy_code_page(0, 850), Some(850));
        assert_eq!(legacy_code_page(65001, 437), Some(437));
        assert_eq!(legacy_code_page(65001, 65001), None);
        assert_eq!(legacy_code_page(0, 0), None);
    }

    #[test]
    fn a_blank_line_is_dropped_only_where_asked() {
        for blank in [&b"\r\n"[..], b"\n", b"   \r\n", b"\t\n", b""] {
            assert_eq!(decode_line(blank, true, |_| None), None, "{blank:?}");
        }
        assert_eq!(decode_line(b"\r\n", false, |_| None), Some(String::new()));
    }

    /// The real conversion: the OEM code pages a .NET program writes `√` in.
    #[cfg(windows)]
    #[test]
    fn a_square_root_in_an_oem_code_page_reads_as_one() {
        assert_eq!(
            code_page_text(437, b"ok \xFB"),
            Some("ok \u{221a}".to_owned())
        );
        assert_eq!(code_page_text(866, b"\xFB"), Some("\u{221a}".to_owned()));
        assert_eq!(code_page_text(437, b""), Some(String::new()));
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        command
    }

    type LogLines = Arc<Mutex<Vec<(LogStream, String)>>>;

    fn collector() -> (LogLines, impl Fn(LogStream, &str) + Send + Sync) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        (lines, move |stream: LogStream, line: &str| {
            sink.lock()
                .expect("log lines")
                .push((stream, line.to_owned()));
        })
    }

    async fn wait_for_log(lines: &LogLines, expected: &str) {
        for _ in 0..50 {
            if lines
                .lock()
                .expect("log lines")
                .iter()
                .any(|(_, line)| line == expected)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "log line {expected:?} never arrived: {:?}",
            lines.lock().expect("log lines")
        );
    }

    #[tokio::test]
    async fn jsonrpc_output_is_logged_by_an_ordinary_app() {
        let (lines, log) = collector();
        let script = r#"echo '{"jsonrpc":"2.0","id":1,"method":"example.echo","params":{}}'; cat"#;
        let mut child = spawn_app(shell(script), log).expect("spawn");
        wait_for_log(
            &lines,
            r#"{"jsonrpc":"2.0","id":1,"method":"example.echo","params":{}}"#,
        )
        .await;
        let _ = child.kill().await;
    }

    #[tokio::test]
    async fn plain_output_is_logged() {
        let (lines, log) = collector();
        let mut child = spawn_app(shell("echo hello; sleep 0.1"), log).expect("spawn");
        wait_for_log(&lines, "hello").await;
        let _ = child.wait().await;
    }

    #[test]
    fn classify_child_exit_maps_status() {
        use std::os::unix::process::ExitStatusExt as _;

        let ok = classify_child_exit(ExitStatus::from_raw(0));
        assert_eq!(ok.outcome, ChildExitOutcome::Completed);
        assert_eq!(ok.cause, "");

        let bad = classify_child_exit(ExitStatus::from_raw(1 << 8));
        assert_eq!(bad.outcome, ChildExitOutcome::Failed);
        assert_eq!(bad.cause, "exit-error");
        assert_eq!(bad.exit_code, Some(1));
        assert_eq!(bad.reason, "app exited with code 1");

        let killed = classify_child_exit(ExitStatus::from_raw(9));
        assert_eq!(killed.outcome, ChildExitOutcome::Failed);
        assert_eq!(killed.cause, "oom-killed");
        assert_eq!(killed.reason, "killed by signal 9");
        assert_eq!(killed.exit_code, None);

        let term = classify_child_exit(ExitStatus::from_raw(15));
        assert_eq!(term.cause, "signal");
        assert_eq!(term.reason, "killed by signal 15");
    }
}

/// Watching a process an app started behind its wrapper — the `sleep` a shell forked —
/// for tests that check a stop or a kill reached it.
#[cfg(all(test, unix))]
pub(crate) mod grandchild {
    use std::path::Path;
    use std::time::Duration;

    /// The file a test command writes its background child's pid to, under the work
    /// directory: `sh -c 'sleep 600 & echo $! > sleeper.pid; wait'`.
    pub(crate) const PID_FILE: &str = "sleeper.pid";

    /// A grandchild by pid. Dropping it kills it, so a failing test leaves nothing
    /// running behind it.
    pub(crate) struct Grandchild(i32);

    impl Grandchild {
        /// Waits for the test command to record its background child.
        pub(crate) async fn recorded_in(dir: &Path) -> Self {
            let file = dir.join(PID_FILE);
            for _ in 0..250 {
                if let Some(pid) = std::fs::read_to_string(&file)
                    .ok()
                    .and_then(|text| text.trim().parse().ok())
                {
                    return Self(pid);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("{} was never written", file.display());
        }

        /// Whether the process has ended within a few seconds. A zombie has ended: it
        /// only waits for whoever inherited it to read its status.
        pub(crate) async fn ends(&self) -> bool {
            for _ in 0..250 {
                if !self.running() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            false
        }

        fn running(&self) -> bool {
            // SAFETY: signal 0 only checks the pid exists; it takes no memory.
            #[allow(unsafe_code)]
            let exists = unsafe { libc::kill(self.0, 0) } == 0;
            exists && !self.is_zombie()
        }

        fn is_zombie(&self) -> bool {
            // The state follows the parenthesised command name in /proc/<pid>/stat.
            std::fs::read_to_string(format!("/proc/{}/stat", self.0))
                .ok()
                .and_then(|stat| {
                    let state = stat.rsplit_once(')')?.1.trim_start().chars().next()?;
                    Some(state == 'Z')
                })
                .unwrap_or(false)
        }
    }

    impl Drop for Grandchild {
        fn drop(&mut self) {
            if self.running() {
                // SAFETY: as above; the pid is still the test's sleep, which is alive.
                #[allow(unsafe_code)]
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
    }
}
