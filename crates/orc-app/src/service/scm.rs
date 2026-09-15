//! The Windows Service Control Manager backend.
//!
//! The SCM is a registry, not a directory of files, so a runtime-managed definition is
//! created with `CreateService` and removed with `DeleteService`. Everything the
//! systemd unit says in text is said here through the API: a Manual start type is how a
//! definition is "never enabled for boot", and the restart policy becomes the service's
//! recovery actions.
//!
//! What the SCM cannot do is run an arbitrary command as a service: a service binary
//! must talk the SCM protocol. So the registered binary is always the runtime's own
//! shim, which is an SCM service main, hosts the app as its child, and translates the
//! stop control into the app's own termination.

use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState as ScmState, ServiceStatus as ScmStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use super::{RestartPolicy, ServiceBackend, ServiceSpec, ServiceState, ServiceStatus};
use crate::error::{CliError, Result};

/// Delay before the SCM restarts a service under its recovery actions. The same five
/// seconds systemd's `RestartSec=` gets, so a flapping app behaves alike on both.
const RESTART_DELAY: Duration = Duration::from_secs(5);

/// Window over which failures are counted before the count resets.
const FAILURE_RESET: Duration = Duration::from_secs(60 * 60);

/// How many status changes may queue up before the runtime's reader is considered
/// hopeless.
const WATCH_BUFFER: usize = 64;

/// How many output lines may queue up before the runtime's reader is considered
/// hopeless.
const LOG_BUFFER: usize = 256;

/// How often the log tailer looks for new output. The file is appended to by another
/// process a handful of lines at a time, and Windows offers no file-change
/// notification worth its machinery for that.
const LOG_POLL: Duration = Duration::from_millis(250);

/// How many idle polls pass before the tailer asks whether the service still exists.
/// Only ever asked when there is nothing to read, so a busy app never pays for it.
const LOG_IDLE_CHECKS: u32 = 8;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// The Windows service control manager.
pub struct Scm;

impl Scm {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for Scm {
    fn default() -> Self {
        Self::new()
    }
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&OsStr>, access)
        .map_err(|err| operational("reach the service manager", err))
}

fn open(name: &str, access: ServiceAccess) -> Result<Service> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(name, access)
        .map_err(|err| operational("open the service", err))
}

/// Whether a service the runtime is asked to remove is one it created.
///
/// A generated definition runs the runtime's own shim, so its command line carries the
/// shim subcommand. A service registered by somebody else does not, and is left alone.
fn is_generated(service: &Service) -> bool {
    service.query_config().is_ok_and(|config| {
        config
            .executable_path
            .to_string_lossy()
            .contains(crate::lifecycle::SHIM_SUBCOMMAND)
    })
}

fn service_info(spec: &ServiceSpec) -> Result<ServiceInfo> {
    let Some((program, arguments)) = spec.exec.split_first() else {
        return Err(CliError::Operational(
            "service definition has no command to run".to_owned(),
        ));
    };
    Ok(ServiceInfo {
        name: OsString::from(&spec.name),
        display_name: OsString::from(&spec.description),
        service_type: SERVICE_TYPE,
        // Manual, always: after a reboot the runtime alone decides what runs.
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(program),
        launch_arguments: arguments.iter().map(OsString::from).collect(),
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    })
}

fn failure_actions(restart: RestartPolicy) -> ServiceFailureActions {
    let actions = match restart {
        RestartPolicy::Never => Vec::new(),
        RestartPolicy::OnFailure | RestartPolicy::Always => (0..3)
            .map(|_| ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: RESTART_DELAY,
            })
            .collect(),
    };
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    }
}

#[async_trait]
impl ServiceBackend for Scm {
    fn platform_name(&self, name: &str) -> String {
        name.to_owned()
    }

    async fn define(&self, spec: &ServiceSpec) -> Result<()> {
        let info = service_info(spec)?;
        let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP;
        let manager =
            manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        // Idempotent: a definition that already exists is rewritten rather than
        // refused, so a version change or a re-converge lands without an uninstall.
        let service = if let Ok(service) = manager.create_service(&info, access) {
            service
        } else {
            let service = manager
                .open_service(&spec.name, access)
                .map_err(|err| operational("open the service", err))?;
            service
                .change_config(&info)
                .map_err(|err| operational("update the service definition", err))?;
            service
        };
        service
            .set_description(&spec.description)
            .map_err(|err| operational("describe the service", err))?;
        service
            .update_failure_actions(failure_actions(spec.restart))
            .map_err(|err| operational("set the service restart policy", err))?;
        // A clean exit the app's own policy calls a failure counts too, which is what
        // `always` means and what `on-failure` must not do.
        service
            .set_failure_actions_on_non_crash_failures(spec.restart == RestartPolicy::Always)
            .map_err(|err| operational("set the service restart policy", err))?;
        tracing::info!(service = %spec.name, "service definition written");
        Ok(())
    }

    async fn undefine(&self, name: &str) -> Result<()> {
        let Ok(service) = manager(ServiceManagerAccess::CONNECT)?
            .open_service(name, ServiceAccess::QUERY_CONFIG | ServiceAccess::DELETE)
        else {
            // Nothing to remove is the state this call is for.
            return Ok(());
        };
        if !is_generated(&service) {
            return Err(CliError::Conflict(format!(
                "service {name} was not defined by this runtime and will not be removed"
            )));
        }
        service
            .delete()
            .map_err(|err| operational("remove the service definition", err))?;
        tracing::info!(service = %name, "service definition removed");
        Ok(())
    }

    async fn start(&self, name: &str) -> Result<()> {
        let service = open(name, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        match service.start::<&OsStr>(&[]) {
            Ok(()) => {}
            // Already running is the state this call is for.
            Err(err) if is_running(&service) => {
                tracing::debug!(service = %name, error = %err, "service was already running");
            }
            Err(err) => return Err(operational("start the service", err)),
        }
        tracing::info!(service = %name, "service start requested");
        Ok(())
    }

    async fn stop(&self, name: &str) -> Result<()> {
        let service = open(name, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        // `ControlService` posts the stop and returns; the grace period and the kill
        // behind it belong to the termination sequence.
        match service.stop() {
            Ok(_) => {}
            Err(err) if !is_running(&service) => {
                tracing::debug!(service = %name, error = %err, "service was already stopped");
            }
            Err(err) => return Err(operational("stop the service", err)),
        }
        tracing::info!(service = %name, "service stop requested");
        Ok(())
    }

    async fn kill(&self, name: &str) -> Result<()> {
        // Ask the manager to stop before ending the tree. A service killed without a
        // pending stop reads as a crash, and the recovery actions a package's
        // `restart` policy configured then start it again — the app the operator just
        // forced down comes back while the node is still terminating. Best effort: the
        // kill below is what actually ends it.
        if let Ok(control) = open(name, ServiceAccess::STOP) {
            let _ = control.stop();
        }
        let service = open(name, ServiceAccess::QUERY_STATUS)?;
        let pid = service
            .query_status()
            .ok()
            .and_then(|status| status.process_id)
            .filter(|pid| *pid > 0);
        let Some(pid) = pid else {
            return Ok(());
        };
        // Windows has no process group to signal, so the tree is ended through
        // taskkill, which walks the child list itself.
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
        tracing::warn!(service = %name, "service killed");
        Ok(())
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let service = open(name, ServiceAccess::QUERY_STATUS)?;
        let status = service
            .query_status()
            .map_err(|err| operational("ask the service manager for the app's state", err))?;
        Ok(from_scm(&status))
    }

    fn watch(&self, name: &str) -> BoxStream<'static, ServiceStatus> {
        let name = name.to_owned();
        let (sender, receiver) = tokio::sync::mpsc::channel(WATCH_BUFFER);
        // A dedicated OS thread, because the SCM delivers status changes as an APC and
        // only to a thread that is waiting alertably — which a tokio worker never is.
        std::thread::spawn(move || {
            if let Err(err) = notify::pump(&name, &sender) {
                // A watch ends whenever its service goes away, and removing the
                // definition is how an app is uninstalled — so "gone" is the ordinary
                // end of a watch, not a fault. Saying the manager is unavailable there
                // sends an operator looking for a broken host that is working fine.
                if open(&name, ServiceAccess::QUERY_STATUS).is_err() {
                    tracing::debug!(service = %name, "service watch ended; it is no longer registered");
                    return;
                }
                tracing::error!(
                    service = %name,
                    error = %err,
                    "service manager unavailable"
                );
            }
        });
        Box::pin(futures_util::stream::unfold(
            receiver,
            |mut receiver| async move { receiver.recv().await.map(|status| (status, receiver)) },
        ))
    }

    fn logs(&self, name: &str, work_dir: &Path) -> Option<BoxStream<'static, String>> {
        let path = log_path(work_dir);
        let name = name.to_owned();
        let (sender, receiver) = tokio::sync::mpsc::channel(LOG_BUFFER);
        // A dedicated OS thread, because following the file is a blocking read on a
        // timer and the runtime's workers have apps to supervise.
        std::thread::spawn(move || tail(&path, &name, &sender));
        Some(Box::pin(futures_util::stream::unfold(
            receiver,
            |mut receiver| async move { receiver.recv().await.map(|line| (line, receiver)) },
        )))
    }
}

fn is_running(service: &Service) -> bool {
    service
        .query_status()
        .is_ok_and(|status| status.current_state == ScmState::Running)
}

/// Maps an SCM status onto the states the runtime models.
///
/// A stopped service is a failure exactly when the SCM recorded a non-zero exit for it;
/// a service the runtime stopped reports zero and is simply inactive.
fn from_scm(status: &ScmStatus) -> ServiceStatus {
    let exit_code = match status.exit_code {
        ServiceExitCode::Win32(0) => None,
        ServiceExitCode::Win32(code) | ServiceExitCode::ServiceSpecific(code) => {
            i32::try_from(code).ok()
        }
    };
    let state = match status.current_state {
        ScmState::Running | ScmState::StopPending | ScmState::PausePending | ScmState::Paused => {
            ServiceState::Active
        }
        ScmState::StartPending | ScmState::ContinuePending => ServiceState::Activating,
        ScmState::Stopped => {
            if exit_code.is_some() {
                ServiceState::Failed
            } else {
                ServiceState::Inactive
            }
        }
    };
    ServiceStatus {
        state,
        main_pid: status.process_id.filter(|pid| *pid > 0),
        exit_code,
        exit_signal: None,
        // The SCM keeps a failure count, not a restart count, and does not report it.
        restarts: 0,
    }
}

fn operational(what: &str, err: impl std::fmt::Display) -> CliError {
    CliError::Operational(format!("{what}: {err}"))
}

// ─── The app's output ────────────────────────────────────────────────────────────
//
// The SCM discards a service's stdio: it is closed before the service main runs, and
// there is no journal to ask afterwards. So the shim writes the app's output down
// beside the app's own state, and the backend follows that file — which is what puts a
// hosted app's diagnostics into the node log the way journald does on Linux.

/// The shim's copy of a hosted app's output, inside the app instance's work directory.
const LOG_FILE: &str = ".orc-service.log";

/// The one path [`ServiceLog`] writes and [`Scm::logs`] follows, for one app instance.
fn log_path(work_dir: &Path) -> PathBuf {
    work_dir.join(LOG_FILE)
}

/// The shim's copy of the hosted app's output.
///
/// Best effort throughout: an app whose output cannot be written down is still an app
/// that runs, so a host that refuses the file costs one warning and nothing else.
pub(crate) struct ServiceLog(Option<Mutex<std::fs::File>>);

impl ServiceLog {
    /// Opens the file for one service start, discarding what the previous start left.
    /// A restart re-runs the shim, and an operator reading the node log is watching the
    /// run that is happening now.
    pub(crate) fn create(work_dir: &Path, app: &str, instance: &str) -> Self {
        let path = log_path(work_dir);
        match std::fs::File::create(&path) {
            Ok(file) => Self(Some(Mutex::new(file))),
            Err(err) => {
                tracing::warn!(
                    app = %app,
                    instance = %instance,
                    path = %path.display(),
                    error = %err,
                    "app output cannot be collected"
                );
                Self(None)
            }
        }
    }

    /// Appends one line, raw and unbuffered — the lines worth having are the ones
    /// written in the seconds before an app dies, which a buffer would eat.
    pub(crate) fn line(&self, line: &str) {
        let Some(file) = self.0.as_ref() else {
            return;
        };
        if let Ok(mut file) = file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.write_all(b"\n");
        }
    }
}

/// Follows one app's log file and forwards a line per line, from the top of the file
/// the running service is writing.
///
/// Ends when the runtime stops reading, or when the service is gone and its output has
/// been drained.
fn tail(path: &Path, name: &str, sender: &tokio::sync::mpsc::Sender<String>) {
    let mut file: Option<std::fs::File> = None;
    let mut read: u64 = 0;
    let mut partial: Vec<u8> = Vec::new();
    let mut idle: u32 = 0;
    let mut buffer = [0_u8; 8192];
    loop {
        if sender.is_closed() {
            return;
        }
        // A file shorter than what has been read is the shim starting the app again:
        // follow the new run from its first line rather than waiting for the old
        // length to come back.
        if file.is_some() && std::fs::metadata(path).is_ok_and(|meta| meta.len() < read) {
            file = None;
        }
        if file.is_none() {
            file = std::fs::File::open(path).ok();
            read = 0;
            partial.clear();
        }
        let mut moved = false;
        if let Some(handle) = file.as_mut() {
            while let Ok(count) = handle.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                moved = true;
                read += count as u64;
                partial.extend_from_slice(&buffer[..count]);
                while let Some(end) = partial.iter().position(|byte| *byte == b'\n') {
                    let line = String::from_utf8_lossy(trim_end(&partial[..end])).into_owned();
                    partial.drain(..=end);
                    if sender.blocking_send(line).is_err() {
                        return;
                    }
                }
            }
        }
        if moved {
            idle = 0;
        } else {
            idle += 1;
            // Everything readable has been read, so a service that no longer exists has
            // nothing further to say.
            if idle.is_multiple_of(LOG_IDLE_CHECKS)
                && open(name, ServiceAccess::QUERY_STATUS).is_err()
            {
                return;
            }
        }
        std::thread::sleep(LOG_POLL);
    }
}

/// Drops the carriage return a Windows app leaves on every line.
fn trim_end(line: &[u8]) -> &[u8] {
    match line {
        [rest @ .., b'\r'] => rest,
        _ => line,
    }
}

// ─── The shim as an SCM service main ─────────────────────────────────────────────
//
// A runtime-managed service's registered binary invokes the runtime's app-exec shim.
// Under the SCM that process must be a service main: register a control handler, report
// running, and report stopped when it is done. It hosts the app as its child — Windows
// has no exec — and translates the stop control into the app's own termination.

/// What the app the shim hosts is, stashed before the SCM dispatcher starts.
///
/// The SCM invokes the service main through a C ABI callback with no user data, so
/// there is no other way to pass it through.
pub struct HostContext {
    pub work_dir: PathBuf,
    pub app: String,
    pub instance: String,
    pub version: String,
    pub service_name: String,
    /// The app's own grace period: how long it has to end after the stop control
    /// before the shim ends it.
    pub grace: Duration,
}

/// Set once by [`host`], read once by the service main.
static HOST_CONTEXT: OnceLock<HostContext> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hosts the app under the SCM. Blocks until the service stops.
pub fn host(context: HostContext) -> Result<()> {
    let name = context.service_name.clone();
    let _ = HOST_CONTEXT.set(context);
    service_dispatcher::start(&name, ffi_service_main)
        .map_err(|err| operational("run as a service", err))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_hosted() {
        tracing::error!(error = %err, "app service exited with error");
    }
}

fn run_hosted() -> Result<()> {
    let Some(context) = HOST_CONTEXT.get() else {
        return Err(CliError::Operational(
            "app service started without an app to run".to_owned(),
        ));
    };
    let stop = CancellationToken::new();
    let handler_token = stop.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_token.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(&context.service_name, handler)
        .map_err(|err| operational("register the service control handler", err))?;

    let report = |state: ScmState, controls: ServiceControlAccept, wait: Duration, code: u32| {
        let _ = handle.set_service_status(ScmStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        });
    };
    report(
        ScmState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
        0,
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| operational("start the app runtime", err))?;
    let exit = runtime.block_on(crate::lifecycle::run_hosted_app(context, &stop));

    report(
        ScmState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
        exit,
    );
    Ok(())
}

/// `NotifyServiceStatusChangeW`, which is how the SCM tells a program that a service
/// changed rather than making it ask.
mod notify {
    use std::cell::Cell;
    use std::ffi::c_void;

    use windows_service::service::ServiceAccess;
    use windows_sys::Win32::Foundation::WAIT_IO_COMPLETION;
    use windows_sys::Win32::System::Services::{
        NotifyServiceStatusChangeW, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_CONTINUE_PENDING,
        SERVICE_NOTIFY_DELETE_PENDING, SERVICE_NOTIFY_PAUSE_PENDING, SERVICE_NOTIFY_PAUSED,
        SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE,
        SERVICE_NOTIFY_STOP_PENDING, SERVICE_NOTIFY_STOPPED, SERVICE_STATUS_PROCESS,
    };
    use windows_sys::Win32::System::Threading::SleepEx;

    use super::{ServiceStatus, from_scm_process, open, operational};
    use crate::error::Result;

    /// Every transition worth waking for. Registration fires immediately when the
    /// service is already in one of these states, which is what gives the runtime the
    /// state as it stands before any change happens.
    const MASK: u32 = SERVICE_NOTIFY_STOPPED
        | SERVICE_NOTIFY_START_PENDING
        | SERVICE_NOTIFY_STOP_PENDING
        | SERVICE_NOTIFY_RUNNING
        | SERVICE_NOTIFY_CONTINUE_PENDING
        | SERVICE_NOTIFY_PAUSE_PENDING
        | SERVICE_NOTIFY_PAUSED
        | SERVICE_NOTIFY_DELETE_PENDING;

    /// A status with nothing in it, spelled out rather than zeroed, so the notification
    /// plumbing needs no `unsafe` to construct its buffers.
    const EMPTY_STATUS: SERVICE_STATUS_PROCESS = SERVICE_STATUS_PROCESS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
        dwProcessId: 0,
        dwServiceFlags: 0,
    };

    /// What the callback hands back to the waiting thread.
    ///
    /// `Cell`, not `&mut`: the callback runs as an APC on this very thread, so the two
    /// never run at once, and shared references keep the aliasing rules satisfied
    /// without a lock that could not be contended anyway.
    struct Notified {
        status: Cell<SERVICE_STATUS_PROCESS>,
        notification: Cell<u32>,
        fired: Cell<bool>,
    }

    /// Called by the SCM on this thread while it waits alertably.
    ///
    /// # Safety
    ///
    /// `parameter` is the `SERVICE_NOTIFY_2W` handed to `NotifyServiceStatusChangeW`,
    /// whose `pContext` is the [`Notified`] the waiting thread owns; both outlive the
    /// call by construction.
    #[allow(unsafe_code, reason = "the SCM reports changes through a C callback")]
    unsafe extern "system" fn on_change(parameter: *const c_void) {
        let notify = parameter.cast::<SERVICE_NOTIFY_2W>();
        if notify.is_null() {
            return;
        }
        let context = unsafe { (*notify).pContext }.cast::<Notified>();
        if context.is_null() {
            return;
        }
        let context = unsafe { &*context };
        context.status.set(unsafe { (*notify).ServiceStatus });
        context
            .notification
            .set(unsafe { (*notify).dwNotificationStatus });
        context.fired.set(true);
    }

    /// Registers for changes and forwards a status per change until the service is
    /// gone or the runtime stops reading.
    pub(super) fn pump(
        name: &str,
        sender: &tokio::sync::mpsc::Sender<ServiceStatus>,
    ) -> Result<()> {
        let service = open(name, ServiceAccess::QUERY_STATUS)?;
        let handle = service.raw_handle();
        let context = Box::new(Notified {
            status: Cell::new(EMPTY_STATUS),
            notification: Cell::new(0),
            fired: Cell::new(false),
        });
        loop {
            context.fired.set(false);
            let notify = SERVICE_NOTIFY_2W {
                dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
                pfnNotifyCallback: Some(on_change),
                pContext: std::ptr::from_ref(&*context).cast_mut().cast::<c_void>(),
                dwNotificationStatus: 0,
                ServiceStatus: EMPTY_STATUS,
                dwNotificationTriggered: 0,
                pszServiceNames: std::ptr::null_mut(),
            };
            // SAFETY: `handle` is an open service handle, and `notify` outlives the
            // alertable wait below, which is the only place the callback can run.
            #[allow(unsafe_code, reason = "the SCM has no safe notification API")]
            let registered =
                unsafe { NotifyServiceStatusChangeW(handle, MASK, std::ptr::from_ref(&notify)) };
            if registered != 0 {
                return Err(operational(
                    "subscribe to the service's state",
                    std::io::Error::from_raw_os_error(
                        i32::try_from(registered).unwrap_or(i32::MAX),
                    ),
                ));
            }
            // The callback is delivered as an APC, so the wait must be alertable and
            // this thread must do nothing else while it waits.
            #[allow(unsafe_code, reason = "an APC is only delivered to an alertable wait")]
            let woken = unsafe { SleepEx(u32::MAX, 1) };
            if !context.fired.get() {
                if woken == WAIT_IO_COMPLETION {
                    continue;
                }
                return Ok(());
            }
            // A non-zero notification status means the service is going away; there is
            // nothing further to hear about it.
            if context.notification.get() != 0 {
                return Ok(());
            }
            if sender
                .blocking_send(from_scm_process(&context.status.get()))
                .is_err()
            {
                return Ok(());
            }
        }
    }
}

/// The same mapping as [`from_scm`], over the raw status the SCM reports to a
/// notification callback.
#[allow(
    unsafe_code,
    reason = "the notification reports a plain C status struct"
)]
fn from_scm_process(
    status: &windows_sys::Win32::System::Services::SERVICE_STATUS_PROCESS,
) -> ServiceStatus {
    use windows_sys::Win32::System::Services::{
        SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };
    let code = if status.dwWin32ExitCode == 0 {
        None
    } else {
        i32::try_from(status.dwWin32ExitCode).ok()
    };
    let state = match status.dwCurrentState {
        SERVICE_RUNNING | SERVICE_STOP_PENDING | SERVICE_PAUSE_PENDING | SERVICE_PAUSED => {
            ServiceState::Active
        }
        SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => ServiceState::Activating,
        SERVICE_STOPPED => {
            if code.is_some() {
                ServiceState::Failed
            } else {
                ServiceState::Inactive
            }
        }
        _ => ServiceState::Unknown,
    };
    ServiceStatus {
        state,
        main_pid: (status.dwProcessId > 0).then_some(status.dwProcessId),
        exit_code: code,
        exit_signal: None,
        restarts: 0,
    }
}
