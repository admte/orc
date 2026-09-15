//! The systemd backend.
//!
//! Definitions are ordinary unit files under `/etc/systemd/system`, generated from the
//! app's own config and carrying a marker line that says the runtime wrote them — so
//! `undefine` can tell a unit it owns from one an operator hand-wrote under the same
//! name and refuse to delete somebody else's work.
//!
//! No unit is ever enabled. After a reboot the runtime decides what runs, which it
//! cannot do if systemd has already started the app on its own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use futures_util::stream::BoxStream;
use tokio::io::AsyncBufReadExt as _;
use tokio::process::Command;

use super::{RestartPolicy, ServiceBackend, ServiceSpec, ServiceState, ServiceStatus};
use crate::error::{CliError, Result};

/// Where generated units live. Not `/run`: a runtime-managed app must survive a reboot
/// as a definition, even though it is never started by one.
const UNIT_DIR: &str = "/etc/systemd/system";

/// The line that says this runtime wrote the unit. First line of the file, so a partial
/// read still finds it, and checked before every removal.
pub(crate) const GENERATED_MARKER: &str = "# orc8r-runtime-managed";

/// systemd is the init system on this host.
const SYSTEMD_RUN_DIR: &str = "/run/systemd/system";

const DBUS_DESTINATION: &str = "org.freedesktop.systemd1";
const DBUS_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const DBUS_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const DBUS_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const DBUS_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const DBUS_PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

/// How many status changes may queue up before the runtime's reader is considered
/// hopeless. Generous: a service flapping under a restart policy produces a burst per
/// restart, and dropping the terminal state of a burst would strand the wait.
const WATCH_BUFFER: usize = 64;

/// The systemd service manager.
pub struct Systemd {
    unit_dir: PathBuf,
}

impl Systemd {
    /// The backend for this host, or `None` where systemd is not the init system.
    #[must_use]
    pub fn detect() -> Option<Self> {
        Path::new(SYSTEMD_RUN_DIR)
            .is_dir()
            .then(|| Self::in_dir(PathBuf::from(UNIT_DIR)))
    }

    /// A backend writing units into `unit_dir`. Tests point this at a temp directory;
    /// nothing else should.
    #[must_use]
    pub fn in_dir(unit_dir: PathBuf) -> Self {
        Self { unit_dir }
    }

    fn unit_path(&self, name: &str) -> PathBuf {
        self.unit_dir.join(name)
    }
}

/// Renders the unit file for a runtime-managed app.
///
/// There is no `[Install]` section, deliberately: a unit with nothing to install into
/// cannot be enabled for boot even by hand, which is the property the contract asks for
/// stated in the file itself rather than in a comment.
#[must_use]
pub(crate) fn render_unit(spec: &ServiceSpec) -> String {
    let restart = match spec.restart {
        RestartPolicy::Never => "no",
        RestartPolicy::OnFailure => "on-failure",
        RestartPolicy::Always => "always",
    };
    let exec = spec
        .exec
        .iter()
        .map(|argument| quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{GENERATED_MARKER}\n\
         # Written by the ORC runtime; it is rewritten on every start and removed on\n\
         # uninstall. Never enabled for boot: the runtime decides what runs after a reboot.\n\
         [Unit]\n\
         Description={description}\n\
         StartLimitIntervalSec={limit_window}\n\
         StartLimitBurst={limit_burst}\n\
         \n\
         [Service]\n\
         Type=simple\n\
         WorkingDirectory={work_dir}\n\
         ExecStart={exec}\n\
         Restart={restart}\n\
         RestartSec=5\n\
         KillMode=control-group\n\
         KillSignal={signal}\n\
         TimeoutStopSec={stop_timeout}\n",
        description = escape_specifiers(&one_line(&spec.description)),
        limit_window = RESTART_LIMIT_WINDOW.as_secs(),
        limit_burst = RESTART_LIMIT_BURST,
        work_dir = escape_specifiers(&spec.work_dir.display().to_string()),
        signal = spec.kill_signal.as_str(),
        stop_timeout = spec.stop_timeout.as_secs(),
    )
}

/// Whether a unit file at hand is one this runtime generated.
#[must_use]
pub(crate) fn is_generated(unit: &str) -> bool {
    unit.lines()
        .next()
        .is_some_and(|line| line == GENERATED_MARKER)
}

/// Quotes one `ExecStart` argument the way systemd reads it: double-quoted, with
/// backslashes, quotes, and control characters escaped, and `%` doubled so systemd does
/// not read a specifier out of the app's own arguments.
fn quote(argument: &str) -> String {
    let mut out = String::with_capacity(argument.len() + 2);
    out.push('"');
    for ch in argument.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Doubles `%` in an unquoted unit value, where systemd would otherwise expand a
/// specifier (`%i`, `%n`, `%%`).
fn escape_specifiers(value: &str) -> String {
    value.replace('%', "%%")
}

/// Flattens a value into the single line a unit setting can hold.
fn one_line(value: &str) -> String {
    value.replace(['\n', '\r'], " ").trim().to_owned()
}

#[async_trait]
impl ServiceBackend for Systemd {
    fn platform_name(&self, name: &str) -> String {
        format!("{name}.service")
    }

    async fn define(&self, spec: &ServiceSpec) -> Result<()> {
        let path = self.unit_path(&spec.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| operational("create the service directory", err))?;
        }
        // Written through a temp file in the same directory: systemd reads units at
        // daemon-reload, and a half-written file it happened to read would fail the app
        // with a parse error rather than start it.
        let temporary = path.with_extension("service.orc-new");
        std::fs::write(&temporary, render_unit(spec))
            .map_err(|err| operational("write the service definition", err))?;
        std::fs::rename(&temporary, &path).map_err(|err| {
            let _ = std::fs::remove_file(&temporary);
            operational("install the service definition", err)
        })?;
        daemon_reload().await?;
        tracing::info!(service = %spec.name, "service definition written");
        Ok(())
    }

    async fn undefine(&self, name: &str) -> Result<()> {
        let path = self.unit_path(name);
        let unit = match std::fs::read_to_string(&path) {
            Ok(unit) => unit,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(operational("read the service definition", err)),
        };
        if !is_generated(&unit) {
            return Err(CliError::Conflict(format!(
                "service {name} was not defined by this runtime and will not be removed"
            )));
        }
        std::fs::remove_file(&path)
            .map_err(|err| operational("remove the service definition", err))?;
        daemon_reload().await?;
        tracing::info!(service = %name, "service definition removed");
        Ok(())
    }

    async fn start(&self, name: &str) -> Result<()> {
        systemctl(&["start", name]).await?;
        tracing::info!(service = %name, "service start requested");
        Ok(())
    }

    async fn stop(&self, name: &str) -> Result<()> {
        // `--no-block`: the grace period and the kill behind it belong to the
        // termination sequence, and it cannot run them while parked inside systemctl.
        systemctl(&["stop", "--no-block", name]).await?;
        tracing::info!(service = %name, "service stop requested");
        Ok(())
    }

    async fn kill(&self, name: &str) -> Result<()> {
        // Queue the stop job first, even when one is already running. Killing a unit
        // that the manager was not asked to stop reads as an unexpected death, and a
        // unit carrying `Restart=always` is started again seconds later — the app the
        // operator just forced down comes back while the node is still terminating.
        // With a stop job in flight the kill is part of that stop, and nothing
        // restarts. `--no-block` because this must not wait out `TimeoutStopSec`.
        for arguments in kill_argv(name) {
            systemctl(&arguments.iter().map(String::as_str).collect::<Vec<_>>()).await?;
        }
        tracing::warn!(service = %name, "service killed");
        Ok(())
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let output = Command::new("systemctl")
            .arg("show")
            .arg(name)
            .arg("--property=ActiveState,SubState,Result,NRestarts,ExecMainPID,ExecMainStatus,ExecMainCode")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await
            .map_err(|err| operational("ask the service manager for the app's state", err))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let properties: HashMap<&str, &str> = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        Ok(status_from(
            properties.get("ActiveState").copied().unwrap_or_default(),
            properties.get("SubState").copied().unwrap_or_default(),
            &|name| properties.get(name).map(|value| (*value).to_owned()),
        ))
    }

    /// Follows the unit's journal from now on, one line per record.
    ///
    /// `--lines 0` starts at the present: the runtime is adopting or starting the app
    /// here, and replaying the last boot's output into the node log would date-stamp
    /// old failures as if they had just happened.
    fn logs(&self, name: &str, _work_dir: &Path) -> Option<BoxStream<'static, String>> {
        // The journal already holds the unit's output; where the app's files sit is
        // beside the point.
        let mut child = Command::new("journalctl")
            .args([
                "--unit", name, "--follow", "--lines", "0", "--output", "cat",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| {
                tracing::info!(
                    service = %name,
                    error = %err,
                    "service output cannot be collected on this host"
                );
            })
            .ok()?;
        let stdout = child.stdout.take()?;
        let lines = tokio::io::BufReader::new(stdout).lines();
        Some(Box::pin(futures_util::stream::unfold(
            (lines, child),
            |(mut lines, child)| async move {
                match lines.next_line().await {
                    Ok(Some(line)) => Some((line, (lines, child))),
                    _ => None,
                }
            },
        )))
    }

    fn watch(&self, name: &str) -> BoxStream<'static, ServiceStatus> {
        let name = name.to_owned();
        let (sender, receiver) = tokio::sync::mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            if let Err(err) = pump(&name, &sender).await {
                // A watch ends whenever its unit goes away, and removing the definition
                // is how an app is uninstalled — so "gone" is the ordinary end of a
                // watch, not a fault. Saying the manager is unavailable there sends an
                // operator looking for a broken host that is working fine.
                if !unit_is_loaded(&name).await {
                    tracing::debug!(service = %name, "service watch ended; it is no longer registered");
                    return;
                }
                // Loud, and then done: this runtime does not fall back to asking on a
                // timer, so an operator who sees this knows app state has stopped
                // updating rather than quietly gone stale.
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
}

/// Subscribes to one unit's property changes and forwards a status per change.
///
/// systemd only emits unit signals while some client has called `Subscribe`, and it
/// tells subscribers *that* properties changed rather than what they became, so each
/// signal is followed by a read of the properties the runtime cares about.
async fn pump(unit: &str, sender: &tokio::sync::mpsc::Sender<ServiceStatus>) -> Result<()> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|err| operational("connect to the service manager", err))?;
    let manager = zbus::Proxy::new(
        &connection,
        DBUS_DESTINATION,
        DBUS_MANAGER_PATH,
        DBUS_MANAGER_INTERFACE,
    )
    .await
    .map_err(|err| operational("reach the service manager", err))?;
    manager
        .call::<_, _, ()>("Subscribe", &())
        .await
        .map_err(|err| operational("subscribe to service manager events", err))?;
    let path: zbus::zvariant::OwnedObjectPath = manager
        .call("LoadUnit", &(unit))
        .await
        .map_err(|err| operational("look up the service", err))?;
    let properties = zbus::Proxy::new(
        &connection,
        DBUS_DESTINATION,
        path.clone(),
        DBUS_PROPERTIES_INTERFACE,
    )
    .await
    .map_err(|err| operational("read the service's state", err))?;
    let mut changes = properties
        .receive_signal("PropertiesChanged")
        .await
        .map_err(|err| operational("subscribe to the service's state", err))?;

    // The first status is the state as it stands, not a change: a runtime that only
    // ever heard about changes would never learn about a service that had already
    // failed by the time it started watching.
    if sender.send(read_status(&properties).await).await.is_err() {
        return Ok(());
    }
    while changes.next().await.is_some() {
        if sender.send(read_status(&properties).await).await.is_err() {
            break;
        }
    }
    Ok(())
}

/// Reads the properties one status is made of, over the `Properties` interface so no
/// cached value can answer for a service that has since moved on.
async fn read_status(properties: &zbus::Proxy<'_>) -> ServiceStatus {
    let unit = get_all(properties, DBUS_UNIT_INTERFACE).await;
    let service = get_all(properties, DBUS_SERVICE_INTERFACE).await;
    let lookup = |name: &str| {
        service
            .get(name)
            .or_else(|| unit.get(name))
            .map(ToOwned::to_owned)
    };
    status_from(
        unit.get("ActiveState")
            .map(String::as_str)
            .unwrap_or_default(),
        unit.get("SubState").map(String::as_str).unwrap_or_default(),
        &lookup,
    )
}

/// Every property of one interface, rendered as the strings the shared status reader
/// expects, so a D-Bus read and a `systemctl show` read parse identically.
async fn get_all(properties: &zbus::Proxy<'_>, interface: &str) -> HashMap<String, String> {
    let reply: zbus::Result<HashMap<String, zbus::zvariant::OwnedValue>> =
        properties.call("GetAll", &(interface)).await;
    reply
        .map(|values| {
            values
                .into_iter()
                .filter_map(|(name, value)| scalar(&value).map(|value| (name, value)))
                .collect()
        })
        .unwrap_or_default()
}

/// Renders the scalar D-Bus values a status is built from. Anything else — arrays,
/// structs, the bulk of a unit's properties — is not part of a status and is dropped.
fn scalar(value: &zbus::zvariant::OwnedValue) -> Option<String> {
    use zbus::zvariant::Value;
    match &**value {
        Value::Str(text) => Some(text.to_string()),
        Value::U32(number) => Some(number.to_string()),
        Value::I32(number) => Some(number.to_string()),
        Value::U64(number) => Some(number.to_string()),
        Value::I64(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Builds a status from the property values systemd reports, however they were read.
///
/// `ExecMainCode` is a `si_code` and `ExecMainStatus` is read through it: the same
/// number means an exit code under `CLD_EXITED` and a signal number under `CLD_KILLED`.
pub(crate) fn status_from(
    active_state: &str,
    sub_state: &str,
    property: &dyn Fn(&str) -> Option<String>,
) -> ServiceStatus {
    let number = |name: &str| property(name).and_then(|value| value.parse::<i64>().ok());
    let main_pid = number("ExecMainPID")
        .filter(|pid| *pid > 0)
        .and_then(|pid| u32::try_from(pid).ok());
    let si_code = number("ExecMainCode").unwrap_or_default();
    let status = number("ExecMainStatus").unwrap_or_default();
    let (exit_code, exit_signal) = super::exit_from_si_code(
        i32::try_from(si_code).unwrap_or_default(),
        i32::try_from(status).unwrap_or_default(),
    );
    ServiceStatus {
        state: state_from(active_state, sub_state),
        main_pid,
        exit_code,
        exit_signal,
        restarts: number("NRestarts")
            .and_then(|restarts| u64::try_from(restarts).ok())
            .unwrap_or_default(),
    }
}

/// Maps systemd's `ActiveState` onto the states the runtime models.
///
/// `activating` covers the auto-restart window (`SubState=auto-restart`), which is
/// exactly why a manager-driven restart never reaches the runtime as an app failure.
/// `deactivating` is reported as active because the app is still there — the runtime is
/// waiting for it to be gone, and only `inactive` or `failed` says it is.
fn state_from(active_state: &str, sub_state: &str) -> ServiceState {
    match active_state {
        "active" | "deactivating" => ServiceState::Active,
        "activating" | "reloading" => ServiceState::Activating,
        "failed" => ServiceState::Failed,
        "inactive" => {
            if sub_state == "auto-restart" {
                ServiceState::Activating
            } else {
                ServiceState::Inactive
            }
        }
        _ => ServiceState::Unknown,
    }
}

async fn daemon_reload() -> Result<()> {
    systemctl(&["daemon-reload"]).await
}

/// Whether the manager still knows this unit. A unit whose definition has been
/// removed reports `LoadState=not-found`, which is how an ended watch is told apart
/// from a manager that cannot be reached.
async fn unit_is_loaded(name: &str) -> bool {
    let Ok(output) = Command::new("systemctl")
        .args(["show", name, "--property=LoadState"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    !text.contains("LoadState=not-found") && text.contains("LoadState=")
}

/// How many times the manager may restart an app before it gives up and reports the
/// unit failed, and the window that count decays over.
///
/// Without a limit an app that fails at *every* start is restarted forever, and a
/// manager-driven restart is deliberately invisible to the runtime — so the node
/// stays online and healthy-looking while the app has never once come up. That is
/// right for an app that crashed after running and wrong for one that never ran.
///
/// The numbers match what the Windows service manager already enforces (three
/// recovery actions, an hour before the count resets), because spec 142 requires the
/// same behaviour from both runtimes and only systemd was blind to this.
const RESTART_LIMIT_BURST: u32 = 3;
const RESTART_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// The manager calls that end a unit now, in the order they have to be made.
///
/// The stop job comes first even when one is already in flight: a unit killed while
/// the manager was not asked to stop it reads as an unexpected death, and one
/// carrying `Restart=always` is started again seconds later. That is not academic —
/// it resurrected a force-terminated app mid-termination. With a stop job queued the
/// kill is part of that stop and nothing restarts it. `--no-block` because a forced
/// stop must not wait out the unit's own `TimeoutStopSec`.
fn kill_argv(name: &str) -> Vec<Vec<String>> {
    vec![
        vec!["stop".to_owned(), "--no-block".to_owned(), name.to_owned()],
        vec![
            "kill".to_owned(),
            "-s".to_owned(),
            "KILL".to_owned(),
            name.to_owned(),
        ],
    ]
}

async fn systemctl(arguments: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|err| operational("run the service manager", err))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.lines().next().unwrap_or("").trim();
    Err(CliError::Operational(format!(
        "service manager rejected {}: {detail}",
        arguments.join(" ")
    )))
}

fn operational(what: &str, err: impl std::fmt::Display) -> CliError {
    CliError::Operational(format!("{what}: {err}"))
}

#[cfg(test)]
mod kill_order_tests {
    use super::kill_argv;

    /// A forced stop jumps straight to the kill, so the kill has to be safe on its
    /// own. Without the stop job in front of it the manager reads the death as a
    /// crash and `Restart=always` starts the app again while the node is still
    /// terminating — which is exactly what happened before this order was pinned.
    #[test]
    fn killing_a_unit_asks_the_manager_to_stop_it_first() {
        let argv = kill_argv("demo.service");
        assert_eq!(
            argv,
            vec![
                vec![
                    "stop".to_owned(),
                    "--no-block".to_owned(),
                    "demo.service".to_owned()
                ],
                vec![
                    "kill".to_owned(),
                    "-s".to_owned(),
                    "KILL".to_owned(),
                    "demo.service".to_owned()
                ],
            ],
            "the stop job must be queued before the kill"
        );
    }
}
