//! Platform service managers behind one contract.
//!
//! An app runs either as a child the runtime supervises or as a service the platform's
//! own manager supervises (spec 142 run modes). Service mode exists because some apps
//! must outlive the initiating runtime: a CI runner mid-build can continue across a
//! runtime upgrade. What the runtime keeps in that mode is not a process handle but a
//! name, and everything it can do with the app — define it, start it, ask it to end,
//! kill it, watch what the manager says about it — goes through [`ServiceBackend`].
//!
//! The contract is deliberately thin. It is not a systemd wrapper: nothing outside this
//! module knows what a unit file is, and the Windows SCM and launchd fit the same seven
//! calls. The one thing every backend must do the same way is [`ServiceBackend::watch`]:
//! the runtime learns that an app failed by being told, never by asking in a loop.

#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;

use crate::error::{CliError, Result};
use crate::process::StopSignal;

pub mod launchd;
#[cfg(windows)]
pub mod scm;
#[cfg(target_os = "linux")]
pub mod systemd;

#[cfg(test)]
mod tests;

/// Where a service is in its life, in the only terms every platform agrees on.
///
/// The distinction that matters to the termination sequence is terminal versus not:
/// a manager restarting a service under its own restart policy passes through
/// [`ServiceState::Activating`], which is why a restart the app opted into is invisible
/// to the runtime rather than reported as a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServiceState {
    /// Not running, and the manager is not trying to change that.
    Inactive,
    /// Starting, or restarting under the manager's own restart policy.
    Activating,
    /// Running.
    Active,
    /// Stopped, and the manager calls that a failure.
    Failed,
    /// The manager said something this runtime does not model.
    #[default]
    Unknown,
}

impl ServiceState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the service has come to rest. A terminal state ends the runtime's wait
    /// on the app; every other state is a stage the manager is still moving through.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Inactive | Self::Failed)
    }
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the manager currently says about one service.
///
/// `exit_code` and `exit_signal` are mutually exclusive — only one of them ever
/// describes how a process ended — and both are absent while the service is running or
/// has never run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceStatus {
    pub state: ServiceState,
    /// The pid of the service's main process, while it has one.
    pub main_pid: Option<u32>,
    /// Exit code of the last main process, when it exited on its own terms.
    pub exit_code: Option<i32>,
    /// Signal number, when the last main process was ended by one.
    pub exit_signal: Option<i32>,
    /// How many times the manager has restarted this service under its restart policy.
    pub restarts: u64,
}

/// What a service manager does when the app ends (`start.restart`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    /// The app ending is the app ending. The default.
    #[default]
    Never,
    /// Restart on an unclean exit only.
    OnFailure,
    /// Restart on every exit.
    Always,
}

impl RestartPolicy {
    /// Reads `start.restart`. A closed set, because a policy the runtime silently
    /// mistook for "never" is an app that quietly stops restarting.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "never" | "no" => Ok(Self::Never),
            "on-failure" => Ok(Self::OnFailure),
            "always" => Ok(Self::Always),
            _ => Err(CliError::Usage(format!(
                "start restart policy {value:?} is not one of never, on-failure, always"
            ))),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::OnFailure => "on-failure",
            Self::Always => "always",
        }
    }
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Everything a backend needs to write a definition the runtime owns.
///
/// Only runtime-managed service mode uses this: a bring-your-own service is defined by
/// the app's own install phase and the runtime never sees its shape.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// The platform name — what [`ServiceBackend::platform_name`] derived, not the bare
    /// identifier the package declared.
    pub name: String,
    /// One line an operator reads in the manager's own listing.
    pub description: String,
    /// The command the manager runs. Always the runtime's own shim, which rebuilds the
    /// app's environment and becomes the app; see [`crate::lifecycle::shim_argv`].
    pub exec: Vec<String>,
    pub work_dir: PathBuf,
    pub restart: RestartPolicy,
    /// The signal the manager delivers to ask the app to end (`stop.signal`).
    pub kill_signal: StopSignal,
    /// How long the manager waits for the app to end before killing it (`stop.grace`).
    pub stop_timeout: Duration,
}

/// One platform's service manager.
///
/// Every method is idempotent where it can be: defining a service that already exists
/// rewrites it, undefining one that is gone succeeds. That is what lets the runtime
/// converge to a desired state without first working out where it left off.
#[async_trait]
pub trait ServiceBackend: Send + Sync {
    /// The platform's name for a bare identifier — `<name>.service`, `<name>`,
    /// `com.orc8r.app.<name>`. This is what every phase is given as `APP_SERVICE`.
    fn platform_name(&self, name: &str) -> String;

    /// Writes (or rewrites) a definition the runtime owns, and never enables it for
    /// boot: after a reboot the runtime alone decides what runs.
    async fn define(&self, spec: &ServiceSpec) -> Result<()>;

    /// Removes a definition this runtime wrote. Refuses one it did not.
    async fn undefine(&self, name: &str) -> Result<()>;

    async fn start(&self, name: &str) -> Result<()>;

    /// Asks the manager to stop the service, and returns without waiting for it to
    /// land. The grace period and the kill behind it belong to the termination
    /// sequence, which cannot run them while blocked inside this call.
    async fn stop(&self, name: &str) -> Result<()>;

    /// Ends the service the hard way, whatever it is still running.
    async fn kill(&self, name: &str) -> Result<()>;

    async fn status(&self, name: &str) -> Result<ServiceStatus>;

    /// A status per change the manager reports.
    ///
    /// Event-driven by contract. A backend that cannot subscribe says so loudly and
    /// ends the stream; it never falls back to asking on a timer, because a poll
    /// interval is a lie about how quickly an app failure is noticed.
    fn watch(&self, name: &str) -> BoxStream<'static, ServiceStatus>;

    /// The service's own output, line by line, from now on.
    ///
    /// A subprocess app writes down a pipe the runtime holds; a service writes into
    /// whatever its manager collects, so this is the only way its output reaches the
    /// node log. `None` where the platform keeps no log the runtime can follow — the
    /// caller says so once and carries on, because an app whose output cannot be
    /// collected is still an app that runs.
    ///
    /// `work_dir` is the app instance's own directory. A manager that keeps the output
    /// itself ignores it; one that does not — the SCM discards a service's stdio — is
    /// told where the runtime's shim left its copy. It is passed per call rather than
    /// held by the backend because one backend serves every app on the host.
    fn logs(&self, name: &str, work_dir: &Path) -> Option<BoxStream<'static, String>> {
        let _ = (name, work_dir);
        None
    }
}

/// The platform's service manager, or `None` on a platform with no backend.
///
/// A package that declares `start.service` on a platform that answers `None` here is a
/// package that cannot run there; the caller reports that rather than pretending.
#[must_use]
pub fn backend() -> Option<Box<dyn ServiceBackend>> {
    #[cfg(target_os = "linux")]
    {
        systemd::Systemd::detect().map(|backend| Box::new(backend) as Box<dyn ServiceBackend>)
    }
    #[cfg(windows)]
    {
        Some(Box::new(scm::Scm::new()) as Box<dyn ServiceBackend>)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

/// The platform's name for a bare service identifier, without needing a backend.
///
/// The lifecycle phases need `APP_SERVICE` whether or not a manager is reachable — a
/// stop hook on a host whose D-Bus is down still deserves to be told what the app is
/// called — so the derivation is a plain function of the identifier and the platform.
#[must_use]
pub fn platform_name(name: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        format!("{name}.service")
    }
    #[cfg(target_os = "macos")]
    {
        format!("{}{name}", launchd::LABEL_PREFIX)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        name.to_owned()
    }
}

/// Suffixes a package author reaches for out of habit, and which the runtime adds
/// itself. Naming a service `foo.service` would yield `foo.service.service`.
const PLATFORM_SUFFIXES: [&str; 5] = [".service", ".plist", ".socket", ".timer", ".target"];

/// Checks that `start.service` is the OS-agnostic bare identifier the contract asks
/// for, after `${VAR}` expansion.
///
/// The two rejections that matter are a platform suffix — the runtime derives that, and
/// a package that spells it itself gets it twice — and a path separator, which would let
/// a service name reach outside the manager's own namespace and, on Linux, name a file.
pub fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(CliError::Usage(
            "start service name is empty; it must be a bare identifier such as \"jenkins-agent\""
                .to_owned(),
        ));
    }
    if let Some(suffix) = PLATFORM_SUFFIXES
        .iter()
        .find(|suffix| name.to_ascii_lowercase().ends_with(**suffix))
    {
        return Err(CliError::Usage(format!(
            "start service name {name:?} carries the platform suffix {suffix:?}; \
             name the service {:?} and the runtime derives the platform name for each OS",
            &name[..name.len() - suffix.len()]
        )));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(CliError::Usage(format!(
            "start service name {name:?} contains a path separator; it must be a bare identifier"
        )));
    }
    if !name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
    {
        return Err(CliError::Usage(format!(
            "start service name {name:?} must begin with a letter or a digit"
        )));
    }
    if let Some(bad) = name
        .chars()
        .find(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@')))
    {
        return Err(CliError::Usage(format!(
            "start service name {name:?} contains {bad:?}; \
             a service identifier holds letters, digits, and - _ . @ only"
        )));
    }
    Ok(())
}

/// Splits a `si_code` / status pair — the shape both systemd and `waitid` report an
/// exit in — into the exit code **or** the signal that describes it.
///
/// `si_code` says which of the two the status is: `CLD_EXITED` (1) makes it an exit
/// code, `CLD_KILLED` (2) and `CLD_DUMPED` (3) make it a signal number. Reading the
/// status without the code is how a service killed by signal 9 gets reported as having
/// exited 9 — a clean-looking failure that never happened.
#[must_use]
pub const fn exit_from_si_code(si_code: i32, status: i32) -> (Option<i32>, Option<i32>) {
    match si_code {
        1 => (Some(status), None),
        2 | 3 => (None, Some(status)),
        _ => (None, None),
    }
}
