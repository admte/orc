//! How a Windows service host asks the app it hosts to stop.
//!
//! Windows has no signals. What a console program listens for instead is a console
//! control event — Ctrl+C or Ctrl+Break — which .NET raises as `Console.CancelKeyPress`,
//! Python as `KeyboardInterrupt`, Go as `os.Interrupt` and a C runtime as `SIGINT` or
//! `SIGBREAK`. A service has no console, so the host gives itself one before it starts
//! the app, the app inherits it, and the stop is that console's control event: it
//! reaches every process on the console — the app's whole tree, and the host, which
//! ignores it.

use crate::process::StopSignal;

/// A console control event a stop can be delivered as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlEvent {
    /// Ctrl+C: what `SIGINT` means to a console program.
    C,
    /// Ctrl+Break: the console's other stop, standing in for every other signal.
    Break,
}

impl CtrlEvent {
    /// The event that carries `signal`: Ctrl+C for `SIGINT`, Ctrl+Break for the rest.
    #[must_use]
    pub fn for_signal(signal: StopSignal) -> Self {
        match signal {
            StopSignal::Int => Self::C,
            StopSignal::Term | StopSignal::Hup | StopSignal::Usr1 | StopSignal::Usr2 => Self::Break,
        }
    }

    /// How the event reads in a log line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C => "Ctrl+C",
            Self::Break => "Ctrl+Break",
        }
    }
}

/// Gives this process a console its children inherit, and makes this process deaf to
/// that console's stop events, so asking the app to stop never ends its host.
///
/// Call once, before the app is started. A process that already has a console keeps it.
///
/// # Errors
///
/// Returns the platform error when the host cannot be kept alive through the events
/// it sends; the app can then only be ended by the kill.
#[cfg(windows)]
#[allow(unsafe_code, reason = "the console has no safe API")]
pub fn own_console() -> std::io::Result<()> {
    use windows_sys::Win32::System::Console::{AllocConsole, SetConsoleCtrlHandler};

    // SAFETY: plain Win32 calls with no pointers; the handler is a `'static` function.
    unsafe {
        // Fails only when the process is already attached to one, which is as good.
        let _ = AllocConsole();
        // Ignoring Ctrl+C by a null handler would be inherited by the app, which would
        // then ignore the very stop this console exists for. Normal processing is
        // restored for the children, and this process ignores the events in a handler
        // of its own, which is not inherited.
        SetConsoleCtrlHandler(None, 0);
        if SetConsoleCtrlHandler(Some(ignore_stop), 1) == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The host's own handler: the stop events it sends are for the app, never for itself.
#[cfg(windows)]
#[allow(unsafe_code, reason = "a console control handler is a C callback")]
unsafe extern "system" fn ignore_stop(event: u32) -> windows_sys::Win32::Foundation::BOOL {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    i32::from(event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
}

/// Sends `event` to every process on this process's console.
///
/// # Errors
///
/// Returns the platform error when the event could not be sent — no console, most
/// likely — in which case the app was not asked.
#[cfg(windows)]
#[allow(unsafe_code, reason = "the console has no safe API")]
pub fn ask(event: CtrlEvent) -> std::io::Result<()> {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, GenerateConsoleCtrlEvent,
    };

    let code = match event {
        CtrlEvent::C => CTRL_C_EVENT,
        CtrlEvent::Break => CTRL_BREAK_EVENT,
    };
    // SAFETY: no pointers. Group 0 is every process attached to this console; Ctrl+C
    // can be sent to no narrower group.
    if unsafe { GenerateConsoleCtrlEvent(code, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigint_is_ctrl_c_and_every_other_signal_ctrl_break() {
        assert_eq!(CtrlEvent::for_signal(StopSignal::Int), CtrlEvent::C);
        for signal in [
            StopSignal::Term,
            StopSignal::Hup,
            StopSignal::Usr1,
            StopSignal::Usr2,
        ] {
            assert_eq!(CtrlEvent::for_signal(signal), CtrlEvent::Break);
        }
    }

    /// The whole ask, as a service host makes it: a host with no console gives itself
    /// one, starts the app on it, and asks; the app hears the ask and ends on its own,
    /// and the host is still there to see it.
    ///
    /// The test binary plays all three parts, told apart by an environment variable:
    /// this test, the host (started with no console, as the SCM starts a service), and
    /// the app. The host runs detached so its events never reach the test runner.
    #[cfg(windows)]
    #[test]
    fn a_hosted_app_hears_the_stop_and_its_host_survives_it() {
        use std::os::windows::process::CommandExt as _;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        match std::env::var(ROLE).as_deref() {
            Ok("host") => host_role(),
            Ok("app") => app_role(),
            _ => {}
        }
        let dir = tempfile::tempdir().expect("dir");
        let mut host = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args(role_args())
            .env(ROLE, "host")
            .env(DIR, dir.path())
            .creation_flags(DETACHED_PROCESS)
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("host");
        let status = wait_bounded(&mut host, std::time::Duration::from_secs(90));
        assert_eq!(
            status.and_then(|status| status.code()),
            Some(0),
            "host outcome: {:?}",
            std::fs::read_to_string(dir.path().join("host-outcome")).ok()
        );
        assert!(dir.path().join("asked").exists(), "the app heard the ask");
    }

    #[cfg(windows)]
    const ROLE: &str = "ORC_CONSOLE_TEST_ROLE";
    #[cfg(windows)]
    const DIR: &str = "ORC_CONSOLE_TEST_DIR";

    #[cfg(windows)]
    fn role_args() -> [&'static str; 4] {
        [
            "--exact",
            "console::tests::a_hosted_app_hears_the_stop_and_its_host_survives_it",
            "--nocapture",
            "--test-threads=1",
        ]
    }

    #[cfg(windows)]
    fn wait_bounded(
        child: &mut std::process::Child,
        limit: std::time::Duration,
    ) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + limit;
        while std::time::Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                return Some(status);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = child.kill();
        None
    }

    /// Owns a console, starts the app on it, asks it to stop, and exits 0 only when the
    /// app ended by itself after hearing the ask.
    #[cfg(windows)]
    fn host_role() -> ! {
        let dir = std::path::PathBuf::from(std::env::var(DIR).expect("dir"));
        let outcome = |text: &str, code: i32| -> ! {
            let _ = std::fs::write(dir.join("host-outcome"), text);
            std::process::exit(code)
        };
        if let Err(err) = own_console() {
            outcome(&format!("no console: {err}"), 2);
        }
        let mut app = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args(role_args())
            .env(ROLE, "app")
            .env(DIR, &dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("app");
        let ready = std::time::Instant::now();
        while !dir.join("ready").exists() {
            if ready.elapsed() > std::time::Duration::from_secs(60) {
                let _ = app.kill();
                outcome("the app never became ready", 3);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if let Err(err) = ask(CtrlEvent::C) {
            let _ = app.kill();
            outcome(&format!("ask failed: {err}"), 4);
        }
        match wait_bounded(&mut app, std::time::Duration::from_secs(30)) {
            Some(status) if status.code() == Some(0) => outcome("app ended on its own", 0),
            other => outcome(&format!("app did not end on its own: {other:?}"), 5),
        }
    }

    #[cfg(windows)]
    static ASKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    #[cfg(windows)]
    #[allow(unsafe_code, reason = "a console control handler is a C callback")]
    unsafe extern "system" fn on_ctrl(_event: u32) -> windows_sys::Win32::Foundation::BOOL {
        ASKED.store(true, std::sync::atomic::Ordering::SeqCst);
        1
    }

    /// Listens for Ctrl+C the way an app does, and ends with 0 once it hears it.
    #[cfg(windows)]
    #[allow(unsafe_code, reason = "the console has no safe API")]
    fn app_role() -> ! {
        let dir = std::path::PathBuf::from(std::env::var(DIR).expect("dir"));
        // SAFETY: a `'static` handler, no pointers.
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
        std::fs::write(dir.join("ready"), b"").expect("ready");
        let started = std::time::Instant::now();
        while !ASKED.load(std::sync::atomic::Ordering::SeqCst) {
            if started.elapsed() > std::time::Duration::from_secs(30) {
                std::process::exit(6);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::fs::write(dir.join("asked"), b"").expect("asked");
        std::process::exit(0)
    }
}
