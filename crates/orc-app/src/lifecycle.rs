#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::BufReader;
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

use crate::app::{AppConfig, CommandPhase, CommandValue, ParamLifetime};
use crate::error::{CliError, Result};
use crate::params::{ParsedParam, ParsedParamValue};
use crate::process::{AppProcess, LogLine, LogStream, StopAsk, StopSignal, drain_lines};
use crate::reboot::{PhaseOutcome, PhaseReboot};
use crate::service::{self, RestartPolicy, ServiceSpec};

/// Per-instance directory under the app work dir for start-phase file-backed params.
const PARAM_DIR: &str = ".orc-params";

/// How long the stop command may run while the app is still alive, unless the recipe
/// says otherwise.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the app has to end after the stop signal, unless the recipe says otherwise.
/// Granted in full after the stop command, however long that took.
/// Grace given to a subprocess app when the runtime itself is exiting (shutdown,
/// upgrade, host reboot). Deliberately short and not configurable: the app's own
/// budget is for orchestrated stops, not for holding up a restart of the runtime.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(10);

/// How long the stopped hook may run, unless the recipe says otherwise.
pub const DEFAULT_STOPPED_TIMEOUT: Duration = Duration::from_secs(60);

/// The cap a caller in a hurry puts on the stopped hook — a forced stop or runtime
/// shutdown. Nothing is failed by it; the hook simply does not get to hold the
/// runtime up.
pub const FORCED_STOPPED_TIMEOUT: Duration = Duration::from_secs(15);

/// What the shim tells a stop-side hook that tries to restart the node.
const STOP_REBOOT_DENIAL: &str = "a stop hook may not restart the node";

/// The subcommand a runtime binary is re-invoked under to become one app's start shim.
///
/// A service manager's definition names this, not the app's own command: the app's
/// environment — params, secret files, the login environment — has to be rebuilt at
/// every start, including restarts the manager performs independently of the initiating
/// runtime. Recognising it is also how a Windows service definition is known to
/// be one this runtime wrote.
pub const SHIM_SUBCOMMAND: &str = "app-exec";

/// Where an app's resolved params are persisted for the start shim to rebuild the
/// app's environment from, inside the app's own work directory. Owner-only.
pub const APP_ENV_FILE: &str = ".orc-app-env.json";

/// Resolves a secret reference (a `sec:` token) to its plaintext bytes.
///
/// Object-safe with a hand-rolled boxed-future signature so hosts can thread
/// `Option<&dyn SecretResolver>` through the lifecycle phases without an
/// `async_trait` dependency. Implementations must never log or embed the
/// resolved value in errors; error messages reference the token only.
pub trait SecretResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        reference: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
}

/// What the runtime calls each copy of an assigned app: the value every phase reads
/// as `APP_INSTANCE`, the work-dir component, and the key every status report and
/// endpoint status is filed under.
///
/// Identity is what the app *is* — its name and the version asked for — never where it
/// sits in the assignment list. A positional label renames the survivors whenever an
/// earlier entry is removed, and a runtime whose labels shift under an edit stops the
/// app the operator kept and starts the one they dropped.
///
/// - one entry of a name → the bare `name`;
/// - several entries of a name at different versions → `name:<version>`;
/// - entries alike in name *and* version → `name`, `name-2`, `name-3` — the one place
///   a position is used at all, because nothing else tells them apart.
///
/// `version` is the resolved version string, `"default"` where the assignment names
/// none. A list whose names are unique, or whose repeats all sit at one version, gets
/// exactly the labels the positional scheme gave it, so nothing an existing node
/// already reports under changes name.
#[must_use]
pub fn instance_labels<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    use std::collections::{BTreeSet, HashMap};

    let entries: Vec<(&str, &str)> = entries.into_iter().collect();
    let mut versions: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    let mut occurrences: HashMap<&str, usize> = HashMap::new();
    for (name, version) in &entries {
        versions.entry(name).or_default().insert(version);
        *occurrences.entry(name).or_default() += 1;
    }
    let mut used: HashMap<String, usize> = HashMap::new();
    entries
        .iter()
        .map(|(name, version)| {
            let alone = occurrences.get(name).copied().unwrap_or(1) == 1;
            let one_version = versions.get(name).map_or(1, BTreeSet::len) == 1;
            let base = if alone || one_version {
                (*name).to_owned()
            } else {
                format!("{name}:{version}")
            };
            let seen = used.entry(base.clone()).or_default();
            *seen += 1;
            if *seen == 1 {
                base
            } else {
                format!("{base}-{seen}")
            }
        })
        .collect()
}

/// Path of the start-phase param-file directory for an app instance.
#[must_use]
pub fn param_files_dir(work_dir: &Path) -> PathBuf {
    work_dir.join(PARAM_DIR)
}

/// Removes the start-phase param-file directory for an app instance.
///
/// Hosts call this when the supervised child exits or is stopped. Best-effort:
/// missing directories and individual file errors are ignored.
pub fn remove_param_files(work_dir: &Path) {
    let _ = std::fs::remove_dir_all(param_files_dir(work_dir));
}

/// Ends a phase pass: a request the shim recorded becomes
/// [`PhaseOutcome::RebootRequested`], a failed pass drops any request it made, and a
/// runtime that wired no reboot plumbing always sees [`PhaseOutcome::Completed`].
fn phase_outcome(reboot: Option<&PhaseReboot>, result: &Result<()>) -> Result<PhaseOutcome> {
    match (reboot, result) {
        (Some(reboot), Ok(())) => reboot.finish(),
        (Some(reboot), Err(_)) => {
            reboot.abandon();
            Ok(PhaseOutcome::Completed)
        }
        (None, _) => Ok(PhaseOutcome::Completed),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "phase identity, params, and runtime wiring are each required"
)]
pub async fn run_install_phase(
    app: &str,
    instance: &str,
    version: &str,
    config: &AppConfig,
    params: &BTreeMap<String, ParsedParam>,
    work_dir: &Path,
    secrets: Option<&dyn SecretResolver>,
    log_line: LogLine,
    reboot: Option<&PhaseReboot>,
    persist_state: Option<PersistState>,
) -> Result<PhaseOutcome> {
    let Some(command) = lifecycle_command("install", app, config.install.as_ref(), work_dir)?
    else {
        // An app with no install phase still retires the marker its runtime opened.
        return phase_outcome(reboot, &Ok(()));
    };
    // Blocking phase: temp files live only for the phase duration.
    let env = phase_env(
        version,
        instance,
        params,
        secrets,
        None,
        reboot,
        declared_service(config),
        persist_state,
    )
    .await?;
    let result = run_command("install", command, work_dir, &env.vars, log_line, reboot).await;
    for path in env.startup_files.into_iter().chain(env.param_files) {
        let _ = std::fs::remove_file(path);
    }
    let outcome = phase_outcome(reboot, &result)?;
    result?;
    Ok(outcome)
}

/// Runs one of an app's capture hooks — `persist.hook_pre` before a snapshot is taken,
/// `persist.hook_post` after it is released.
///
/// Same shape as the install phase, deliberately: a hook is written by the same author,
/// against the same environment, with the same params and secrets in scope, and its output
/// reaches the node log the same way. What differs is that a hook is *declared inline* —
/// there is no packaged `capture-<app>` script fallback — so an app with no hook block runs
/// nothing at all, and the capture engine treats that as success.
///
/// `phase` is `"hook_pre"` or `"hook_post"`, which is what the node log labels the output
/// with. A `hook_pre` failure skips that app's capture for the cycle; a `hook_post` failure
/// is warned about and nothing more, because by then the snapshot is already released.
///
/// # Errors
///
/// Returns [`CliError::Operational`] if the hook exits non-zero or times out, and whatever
/// resolving the app's params and secrets failed with.
#[allow(
    clippy::too_many_arguments,
    reason = "phase identity, params, and runtime wiring are each required"
)]
pub async fn run_capture_hook_phase(
    phase: &str,
    instance: &str,
    version: &str,
    config: &AppConfig,
    hook: Option<&CommandPhase>,
    params: &BTreeMap<String, ParsedParam>,
    work_dir: &Path,
    secrets: Option<&dyn SecretResolver>,
    log_line: LogLine,
) -> Result<()> {
    let Some(mut command) = hook.map(command_phase).transpose()?.flatten() else {
        return Ok(());
    };
    command.timeout = Some(capture_hook_timeout(command.timeout));
    // Blocking phase: temp files live only for the hook's duration. A hook never requests
    // a reboot — a capture is not an install — so no reboot plumbing is offered to it.
    let env = phase_env(
        version,
        instance,
        params,
        secrets,
        None,
        None,
        declared_service(config),
        None,
    )
    .await?;
    let result = run_command(phase, command, work_dir, &env.vars, log_line, None).await;
    for path in env.startup_files.into_iter().chain(env.param_files) {
        let _ = std::fs::remove_file(path);
    }
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "phase identity, params, and runtime wiring are each required"
)]
pub async fn run_uninstall_phase(
    app: &str,
    instance: &str,
    version: &str,
    config: &AppConfig,
    params: &BTreeMap<String, String>,
    work_dir: &Path,
    log_line: LogLine,
    reboot: Option<&PhaseReboot>,
) -> Result<PhaseOutcome> {
    let Some(command) = lifecycle_command("uninstall", app, config.uninstall.as_ref(), work_dir)?
    else {
        return phase_outcome(reboot, &Ok(()));
    };
    let env = durable_phase_env(version, instance, params, reboot, declared_service(config))?;
    let result = run_command("uninstall", command, work_dir, &env, log_line, reboot).await;
    let outcome = phase_outcome(reboot, &result)?;
    result?;
    Ok(outcome)
}

#[allow(
    clippy::too_many_arguments,
    reason = "phase identity, params, and runtime wiring are each required"
)]
pub async fn run_start_phase(
    app: &str,
    instance: &str,
    version: &str,
    config: &AppConfig,
    params: &BTreeMap<String, ParsedParam>,
    work_dir: &Path,
    secrets: Option<&dyn SecretResolver>,
    log_line: LogLine,
    reboot: Option<&PhaseReboot>,
    persist_state: Option<PersistState>,
) -> Result<PhaseOutcome> {
    let command = required_start_command(app, config, work_dir)?;
    // Blocking phase: temp files live only for the phase duration.
    let env = phase_env(
        version,
        instance,
        params,
        secrets,
        None,
        reboot,
        declared_service(config),
        persist_state,
    )
    .await?;
    let result = run_command(
        "start",
        PhaseCommand {
            value: command,
            timeout: None,
        },
        work_dir,
        &env.vars,
        log_line,
        reboot,
    )
    .await;
    for path in env.startup_files.into_iter().chain(env.param_files) {
        let _ = std::fs::remove_file(path);
    }
    let outcome = phase_outcome(reboot, &result)?;
    result?;
    Ok(outcome)
}

/// Unspawned start-phase command plus the file-backed param files its environment
/// references, split by lifetime. Both sets live under `{work_dir}/.orc-params/`:
/// the caller must remove each `startup_files` entry once the child's startup
/// completes (right after spawning), keep `param_files` until the child exits,
/// and then call [`remove_param_files`].
pub struct StartCommand {
    pub command: Command,
    pub param_files: Vec<PathBuf>,
    pub startup_files: Vec<PathBuf>,
    /// The resolved-params environment the app started with. Endpoint probes reuse
    /// it (see [`probe_command`]) so a probe command runs in exactly the context the
    /// lifecycle commands ran in. Startup-lifetime param files are withdrawn right
    /// after the child starts, so a probe command must not depend on their `*_FILE`
    /// entries — the variable still names a path that no longer exists.
    pub env: BTreeMap<String, String>,
}

/// Builds the (unspawned) start-phase command with the param environment and
/// working directory applied. Hosts that supervise the child themselves or implement
/// caller-specific protocols spawn it instead of waiting for exit.
#[allow(
    clippy::too_many_arguments,
    reason = "phase identity, params, and runtime wiring are each required"
)]
pub async fn start_command(
    app: &str,
    instance: &str,
    config: &AppConfig,
    version: &str,
    params: &BTreeMap<String, ParsedParam>,
    work_dir: &Path,
    secrets: Option<&dyn SecretResolver>,
    reboot: Option<&PhaseReboot>,
    persist_state: Option<PersistState>,
) -> Result<StartCommand> {
    let command = required_start_command(app, config, work_dir)?;
    let param_dir = prepare_param_dir(work_dir)?;
    let env = phase_env(
        version,
        instance,
        params,
        secrets,
        Some(&param_dir),
        reboot,
        declared_service(config),
        persist_state,
    )
    .await?;
    let mut process = match &command {
        CommandValue::String(command) => shell_command(&shim_first(command, reboot)),
        CommandValue::Argv(argv) => argv_command(argv, &env.vars)?,
    };
    apply_login_env(&mut process);
    process.current_dir(work_dir).envs(&env.vars);
    Ok(StartCommand {
        command: process,
        param_files: env.param_files,
        startup_files: env.startup_files,
        env: env.vars,
    })
}

/// Builds an unspawned probe command in the lifecycle-command context: the app's work
/// directory plus the resolved-params environment captured at start (spec 180 requires
/// probe commands to run exactly where lifecycle commands run).
pub fn probe_command(
    command: &CommandValue,
    work_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Result<Command> {
    let mut process = match command {
        CommandValue::String(command) => shell_command(command),
        CommandValue::Argv(argv) => argv_command(argv, env)?,
    };
    apply_login_env(&mut process);
    process.current_dir(work_dir).envs(env);
    Ok(process)
}

/// Command the start phase resolves to, or `None` when the app defines no start
/// at all — an install-only app whose install *is* the whole job.
///
/// Resolution matches the other phases: an explicit `start.command` wins, and the
/// packaged `start-{app}` script is the fallback, so a recipe can leave `start:` empty
/// and rely on the file-naming convention alone. The config wins because it is the
/// specific statement — a package can carry a script for every phase and still have one
/// phase overridden, and an author who wrote a command means it.
#[must_use]
pub fn resolve_start_command(
    app: &str,
    config: &AppConfig,
    work_dir: &Path,
) -> Option<CommandValue> {
    if let Some(command) = config
        .start
        .as_ref()
        .and_then(|start| start.command.clone())
    {
        return Some(command);
    }
    lifecycle_script("start", app, work_dir).map(|script| script_command(&script))
}

fn required_start_command(app: &str, config: &AppConfig, work_dir: &Path) -> Result<CommandValue> {
    resolve_start_command(app, config, work_dir).ok_or_else(|| {
        CliError::Operational("app config does not define a start command".to_owned())
    })
}

/// How an app runs: the three shapes `start` can take (spec 142 run modes).
///
/// The distinction is which side owns what. In [`StartMode::Subprocess`] the runtime
/// owns the process. In [`StartMode::ManagedService`] it owns the definition and the
/// manager owns the process. In [`StartMode::Service`] the app's own install phase owns
/// the definition and the runtime only starts, stops, and watches it — so a runtime
/// that wrote a definition there would be overwriting the app's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartMode {
    /// `command` alone: a foreground child of the runtime.
    Subprocess(CommandValue),
    /// `command` + `service`: the runtime generates the definition and removes it on
    /// uninstall. `command` is what the app is, and what the start shim runs; the
    /// definition itself always names the shim.
    ManagedService { name: String, command: CommandValue },
    /// `service` alone: the definition belongs to the app's install phase.
    Service { name: String },
}

impl StartMode {
    /// The platform service name, in the two modes that have one.
    #[must_use]
    pub fn service_name(&self) -> Option<&str> {
        match self {
            Self::Subprocess(_) => None,
            Self::ManagedService { name, .. } | Self::Service { name } => Some(name),
        }
    }
}

/// Resolves how this app runs, or `None` when it declares no start at all — an
/// install-only app whose install *is* the whole job.
///
/// `env` is the phase environment the start will run with; the service identifier is
/// expanded against it, so `${APP_VERSION}`, `${APP_INSTANCE}`, and params all reach a
/// service name and two versions of one app can carry distinct ones.
///
/// The name in the returned mode is the **platform** name — `<name>.service`,
/// `com.orc8r.app.<name>`, the bare name on Windows — which is what every
/// [`crate::service::ServiceBackend`] call and `APP_SERVICE` speak in.
///
/// A packaged `start-{app}` script counts as the command, exactly as it does for every
/// other phase: a package that ships one alongside `service` is asking the runtime to
/// own the definition and run the script inside it.
pub fn resolve_start_mode(
    app: &str,
    config: &AppConfig,
    work_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Result<Option<StartMode>> {
    let command = resolve_start_command(app, config, work_dir);
    let Some(raw) = declared_service(config) else {
        return Ok(command.map(StartMode::Subprocess));
    };
    let expanded = substitute_vars(raw, env)?;
    service::validate_identifier(&expanded)?;
    let name = service::platform_name(&expanded);
    Ok(Some(match command {
        Some(command) => StartMode::ManagedService { name, command },
        None => StartMode::Service { name },
    }))
}

// ─── Service mode ────────────────────────────────────────────────────────────────
//
// A service-mode app is started by the platform's service manager, not by the runtime,
// and the manager may restart it while the runtime is down or being upgraded. So the
// definition never names the app's own command: it names this runtime, re-invoked as a
// start shim, which rebuilds the app's environment from what was persisted at install
// and only then becomes the app.

/// The app's resolved params, persisted so the start shim can rebuild the environment.
///
/// Written when a managed service is defined and removed on uninstall. Owner-only, and
/// never logged: it holds the same secret material the app's `*_FILE` params carry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppEnv {
    pub app: String,
    pub instance: String,
    pub version: String,
    pub params: BTreeMap<String, ParsedParam>,
    /// What the app's persisted data looked like when the runtime installed it. The
    /// service manager restarts a service-mode app on its own schedule, long after the
    /// runtime has stopped looking, and each of those starts must be handed the same
    /// environment the first one got. `None` for every app that does not persist.
    pub persist_state: Option<PersistState>,
}

/// Path of an app instance's persisted params.
#[must_use]
pub fn app_env_path(work_dir: &Path) -> PathBuf {
    work_dir.join(APP_ENV_FILE)
}

/// Persists an app's resolved params for the start shim.
///
/// Written to a temp file in the same directory and renamed over the previous one, so a
/// restart that races a reconfigure reads one whole set of params or the other, never
/// half of each.
pub fn write_app_env(work_dir: &Path, env: &AppEnv) -> Result<()> {
    let path = app_env_path(work_dir);
    let temporary = path.with_extension("json.new");
    let body = serde_json::to_vec(env)
        .map_err(|err| CliError::Operational(format!("encode the app environment: {err}")))?;
    write_private_file(&temporary, &body)?;
    std::fs::rename(&temporary, &path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        CliError::Operational(format!("write {}: {err}", path.display()))
    })
}

/// Reads back what [`write_app_env`] persisted.
pub fn read_app_env(work_dir: &Path) -> Result<AppEnv> {
    let path = app_env_path(work_dir);
    let body = std::fs::read(&path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
    serde_json::from_slice(&body)
        .map_err(|err| CliError::Operational(format!("parse {}: {err}", path.display())))
}

/// Removes an app instance's persisted params. Best-effort: it is cleanup, and the
/// caller is on its way out.
pub fn remove_app_env(work_dir: &Path) {
    let path = app_env_path(work_dir);
    let _ = std::fs::remove_file(path.with_extension("json.new"));
    let _ = std::fs::remove_file(path);
}

/// Creates (or replaces) an owner-only file holding `body`.
fn write_private_file(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", path.display())))?;
    file.write_all(body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    file.sync_all()
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    drop(file);
    // A file left behind by an interrupted write is reused rather than recreated, so
    // the mode is asserted rather than assumed.
    set_private_file(path)
}

/// Resolves every secret reference in `params` to the value it names.
///
/// The persisted set has to be resolver-free because the shim may run without the
/// original host or secret resolver. The resolved value takes the file-backed form the
/// param already had, so the rebuilt environment is byte-identical.
pub async fn resolved_params(
    params: &BTreeMap<String, ParsedParam>,
    secrets: Option<&dyn SecretResolver>,
) -> Result<BTreeMap<String, ParsedParam>> {
    let mut resolved = BTreeMap::new();
    for (key, param) in params {
        let value = match &param.value {
            ParsedParamValue::SecretRef(reference) => {
                let Some(secrets) = secrets else {
                    return Err(CliError::Operational(format!(
                        "secret URI resolution for --{} is not implemented yet",
                        param.name.replace('_', "-")
                    )));
                };
                let bytes = secrets.resolve(reference).await.map_err(|err| {
                    CliError::Operational(format!("resolve secret {reference}: {err}"))
                })?;
                ParsedParamValue::File {
                    path: PathBuf::new(),
                    bytes,
                }
            }
            other => other.clone(),
        };
        resolved.insert(
            key.clone(),
            ParsedParam {
                name: param.name.clone(),
                value,
                file_backed: param.file_backed,
                lifetime: param.lifetime,
            },
        );
    }
    Ok(resolved)
}

/// The command a service definition runs: this runtime, re-invoked as one app's shim.
#[must_use]
pub fn shim_argv(
    runtime_exe: &Path,
    work_dir: &Path,
    app: &str,
    instance: &str,
    version: &str,
) -> Vec<String> {
    vec![
        runtime_exe.display().to_string(),
        SHIM_SUBCOMMAND.to_owned(),
        "--work-dir".to_owned(),
        work_dir.display().to_string(),
        "--app".to_owned(),
        app.to_owned(),
        "--instance".to_owned(),
        instance.to_owned(),
        "--version".to_owned(),
        version.to_owned(),
    ]
}

/// The definition the runtime writes for a runtime-managed service.
///
/// Generated from the app's config alone — restart policy from `start.restart`, kill
/// signal from `stop.signal`, the manager's own stop timeout from `stop.grace` — which
/// is what lets app packages ship no unit files, plists, or registration code.
#[must_use]
pub fn managed_service_spec(
    app: &str,
    instance: &str,
    version: &str,
    config: &AppConfig,
    work_dir: &Path,
    service_name: &str,
    runtime_exe: &Path,
) -> ServiceSpec {
    let stop = config.stop.as_ref();
    let restart = config
        .start
        .as_ref()
        .and_then(|start| start.restart.as_deref())
        .map_or(RestartPolicy::default(), |value| {
            RestartPolicy::parse(value).unwrap_or_else(|_| {
                tracing::warn!(
                    app = %app,
                    instance = %instance,
                    restart = %value,
                    "restart policy not recognized, the app will not be restarted"
                );
                RestartPolicy::default()
            })
        });
    let kill_signal =
        stop.and_then(|stop| stop.signal.as_deref())
            .map_or(StopSignal::default(), |value| {
                StopSignal::parse(value).unwrap_or_else(|_| {
                    tracing::warn!(
                        app = %app,
                        instance = %instance,
                        signal = %value,
                        "stop signal not recognized, using SIGTERM"
                    );
                    StopSignal::default()
                })
            });
    ServiceSpec {
        name: service_name.to_owned(),
        description: if instance.is_empty() {
            format!("ORC app {app}")
        } else {
            format!("ORC app {instance}")
        },
        exec: shim_argv(runtime_exe, work_dir, app, instance, version),
        work_dir: work_dir.to_path_buf(),
        restart,
        kill_signal,
        stop_timeout: configured_duration(
            stop.and_then(|stop| stop.grace.as_deref()),
            DEFAULT_STOP_GRACE,
        ),
    }
}

/// The variables a service identifier may be written in terms of.
///
/// The reserved ones, and the params that reach a phase as values. A file-backed param
/// reaches it as a path under a directory that only exists while the app runs, which is
/// not something a service name can be built from — and leaving it out here means the
/// name resolves identically whether or not the param files have been materialized.
fn name_vars(
    version: &str,
    instance: &str,
    params: &BTreeMap<String, ParsedParam>,
) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    if version != "default" {
        vars.insert("APP_VERSION".to_owned(), version.to_owned());
    }
    insert_instance(&mut vars, instance);
    for param in params.values() {
        if param.file_backed {
            continue;
        }
        match &param.value {
            ParsedParamValue::String(value) | ParsedParamValue::Number(value) => {
                vars.insert(env_name(&param.name), value.clone());
            }
            ParsedParamValue::Boolean(value) => {
                vars.insert(env_name(&param.name), value.to_string());
            }
            _ => {}
        }
    }
    vars
}

/// The platform service name for one app instance, without materializing anything.
///
/// `None` when the app declares no service. Hosts use it to define, start, stop, and
/// watch the app's service; it is the same name every phase is told as `APP_SERVICE`.
pub fn instance_service_name(
    config: &AppConfig,
    instance: &str,
    version: &str,
    params: &BTreeMap<String, ParsedParam>,
) -> Result<Option<String>> {
    let Some(raw) = declared_service(config) else {
        return Ok(None);
    };
    let expanded = substitute_vars(raw, &name_vars(version, instance, params))?;
    service::validate_identifier(&expanded)?;
    Ok(Some(service::platform_name(&expanded)))
}

/// Becomes the app: the shim's whole job.
///
/// A service manager starts this, not the app, because the app's environment has to be
/// rebuilt at every start, including restarts the manager performs independently of the
/// initiating runtime. On Unix the start command is `exec`ed, so the unit's main
/// pid is the app itself and nothing sits between it and the manager's signals.
#[allow(
    clippy::unused_async,
    reason = "the Windows path hands off to the SCM dispatcher and awaits nothing"
)]
pub async fn exec_app(work_dir: &Path, app: &str, instance: &str, version: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let start = shim_start_command(work_dir, app, instance, version).await?;
        tracing::info!(app = %app, instance = %instance, "app start handed over");
        let error = {
            use std::os::unix::process::CommandExt as _;
            let mut command = start.command;
            command.as_std_mut().exec()
        };
        Err(CliError::Operational(format!("start the app: {error}")))
    }
    #[cfg(windows)]
    {
        let config = crate::app::read_config(work_dir)?;
        let stored = read_app_env(work_dir)?;
        let Some(service_name) = instance_service_name(&config, instance, version, &stored.params)?
        else {
            return Err(CliError::Operational(
                "app config does not define a service to run as".to_owned(),
            ));
        };
        let grace = configured_duration(
            config.stop.as_ref().and_then(|stop| stop.grace.as_deref()),
            DEFAULT_STOP_GRACE,
        );
        crate::service::scm::host(crate::service::scm::HostContext {
            work_dir: work_dir.to_path_buf(),
            app: app.to_owned(),
            instance: instance.to_owned(),
            version: version.to_owned(),
            service_name,
            grace,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (work_dir, app, instance, version);
        Err(CliError::Operational(
            "this platform has no service manager to run an app under".to_owned(),
        ))
    }
}

/// Rebuilds the app's start command from what was persisted at install.
///
/// The same code path a supervised start takes, with no resolver of its own. Every
/// secret the app needs is already in the persisted set before the shim runs.
#[cfg(any(unix, windows))]
async fn shim_start_command(
    work_dir: &Path,
    app: &str,
    instance: &str,
    version: &str,
) -> Result<StartCommand> {
    let config = crate::app::read_config(work_dir)?;
    let stored = read_app_env(work_dir)?;
    start_command(
        app,
        instance,
        &config,
        version,
        &stored.params,
        work_dir,
        None,
        // The shim is not a phase pass: there is nobody to hand a reboot request back
        // to, so it carries no shim directory of its own.
        None,
        stored.persist_state,
    )
    .await
}

/// Runs the app under the Windows service control manager and translates the stop
/// control into the app's own termination.
///
/// Windows cannot replace the shim with the app — there is no `exec`, and the SCM needs
/// a process that speaks its protocol — so the app runs as the shim's child and the
/// shim ends it: no signal, the app's grace period, then the tree.
#[cfg(windows)]
pub(crate) async fn run_hosted_app(
    context: &crate::service::scm::HostContext,
    stop: &CancellationToken,
) -> u32 {
    let app = context.app.clone();
    let instance = context.instance.clone();
    let log_app = app.clone();
    let log_instance = instance.clone();
    // The shim's own tracing reaches nobody: the SCM closes a service's stdio before
    // the service main runs and keeps no log of it. So every line the app writes is
    // also written down where the runtime's service backend follows it, which is what
    // puts a hosted app's own diagnostics into the node log. Truncated here, so each
    // start — including one the manager's restart policy made — begins fresh.
    let out = std::sync::Arc::new(crate::service::scm::ServiceLog::create(
        &context.work_dir,
        &app,
        &instance,
    ));
    let start = match shim_start_command(
        &context.work_dir,
        &context.app,
        &context.instance,
        &context.version,
    )
    .await
    {
        Ok(start) => start,
        Err(err) => {
            tracing::error!(app = %app, instance = %instance, error = %err, "app could not be started");
            out.line(&format!("app could not be started: {err}"));
            return 1;
        }
    };
    let log_out = std::sync::Arc::clone(&out);
    let child = crate::process::spawn_app(start.command, move |stream, line| {
        log_out.line(line);
        match stream {
            LogStream::Stderr => {
                tracing::warn!(app = %log_app, instance = %log_instance, "{line}");
            }
            LogStream::Stdout => {
                tracing::info!(app = %log_app, instance = %log_instance, "{line}");
            }
        }
    });
    let mut child = match child {
        Ok(child) => child,
        Err(err) => {
            tracing::error!(app = %app, instance = %instance, error = %err, "app could not be started");
            out.line(&format!("app could not be started: {err}"));
            return 1;
        }
    };
    let status = tokio::select! {
        status = child.wait() => status,
        () = stop.cancelled() => {
            tracing::info!(app = %app, instance = %instance, grace_s = context.grace.as_secs(), "app given time to stop");
            let mut process = AppProcess::subprocess(&mut child, std::time::Instant::now());
            if let Ok(status) = tokio::time::timeout(context.grace, process.wait()).await {
                status
            } else {
                tracing::warn!(app = %app, instance = %instance, "app killed after the grace period");
                process.kill().await;
                process.wait().await
            }
        }
    };
    // Withdrawn now the app has exited, not the moment it was spawned. The shim keeps
    // running while the app does, so an early withdrawal is a race the app loses: it
    // deletes the operator's secret out from under a start command that has not read it
    // yet — an interpreter that takes seconds to reach its first line finds nothing
    // there. Nothing is lost by waiting, because a restart re-runs the shim and rebuilds
    // the whole set from the persisted params. Unix withdraws at no point at all: it
    // `exec`s the app, so the shim is gone and the app owns the files for its run.
    remove_param_files(&context.work_dir);
    match status {
        Ok(status) if status.success() => 0,
        Ok(status) => u32::try_from(status.code().unwrap_or(1)).unwrap_or(1),
        Err(err) => {
            tracing::warn!(app = %app, instance = %instance, error = %err, "app exit could not be read");
            1
        }
    }
}

struct PhaseCommand {
    value: CommandValue,
    timeout: Option<Duration>,
}

#[derive(Debug)]
struct PhaseEnv {
    vars: BTreeMap<String, String>,
    /// File-backed params the app may read for its whole run.
    param_files: Vec<PathBuf>,
    /// File-backed params consumed during startup only (operator secrets by
    /// default); the host withdraws them once the start phase completes.
    startup_files: Vec<PathBuf>,
}

/// How long a capture hook may run when its manifest declares no `timeout`. Long
/// enough for a database to flush and check-point itself, short enough that a hook
/// which has wedged costs one cycle rather than every cycle after it.
const DEFAULT_CAPTURE_HOOK_TIMEOUT: Duration = Duration::from_secs(120);

/// The bound a capture hook runs under: what the manifest declared, or
/// [`DEFAULT_CAPTURE_HOOK_TIMEOUT`] when it declared none.
///
/// A hook runs between a capture cycle deciding to freeze the volume and the freeze
/// itself, so one that never returns is a node that never captures again. The install
/// and start phases are deliberately left unbounded — an install may legitimately take
/// an hour — but a hook is a quiesce, and a quiesce that has not finished in two
/// minutes is not going to.
fn capture_hook_timeout(declared: Option<Duration>) -> Duration {
    declared.unwrap_or(DEFAULT_CAPTURE_HOOK_TIMEOUT)
}

/// Resolves a phase to the command that runs it: the configured `command` first, the
/// packaged `{phase}-{app}` script as the fallback. The configured timeout applies to
/// whichever of the two ran.
fn lifecycle_command(
    phase: &str,
    app: &str,
    config: Option<&CommandPhase>,
    work_dir: &Path,
) -> Result<Option<PhaseCommand>> {
    if let Some(command) = config.map(command_phase).transpose()?.flatten() {
        return Ok(Some(command));
    }
    let Some(script) = lifecycle_script(phase, app, work_dir) else {
        return Ok(None);
    };
    Ok(Some(PhaseCommand {
        value: script_command(&script),
        timeout: config
            .and_then(|phase| phase.timeout.as_deref())
            .map(parse_duration)
            .transpose()?,
    }))
}

fn command_phase(phase: &CommandPhase) -> Result<Option<PhaseCommand>> {
    phase
        .command
        .as_ref()
        .map(|command| {
            Ok(PhaseCommand {
                value: command.clone(),
                timeout: phase.timeout.as_deref().map(parse_duration).transpose()?,
            })
        })
        .transpose()
}

#[cfg(unix)]
fn lifecycle_script(phase: &str, app: &str, work_dir: &Path) -> Option<PathBuf> {
    let path = work_dir.join(format!("{phase}-{app}.sh"));
    path.exists().then_some(path)
}

#[cfg(windows)]
fn lifecycle_script(phase: &str, app: &str, work_dir: &Path) -> Option<PathBuf> {
    for extension in ["ps1", "cmd"] {
        let path = work_dir.join(format!("{phase}-{app}.{extension}"));
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(unix)]
fn script_command(path: &Path) -> CommandValue {
    CommandValue::Argv(vec!["sh".to_owned(), path.display().to_string()])
}

#[cfg(windows)]
fn script_command(path: &Path) -> CommandValue {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("cmd") => CommandValue::Argv(vec![
            "cmd".to_owned(),
            "/C".to_owned(),
            path.display().to_string(),
        ]),
        _ => CommandValue::Argv(vec![
            "powershell".to_owned(),
            "-File".to_owned(),
            path.display().to_string(),
        ]),
    }
}

/// Builds the phase environment. When `param_dir` is `Some`, file-backed params
/// are written there with deterministic names (start-phase / supervised apps).
/// When `None`, they go to process-private temp files (blocking install/start).
///
/// `instance` is what the runtime calls this particular copy of the app — the plain
/// name, `name:<version>`, or `name-N` for a scaled member — and every phase is told
/// it, so a hook can label what it writes without guessing.
///
/// `persist_state` is carried only by the phases that run before the app is serving —
/// install and start — and only for an app the runtime keeps data for; every other
/// phase passes `None`.
#[allow(
    clippy::too_many_arguments,
    reason = "the phase environment is assembled from independent sources"
)]
async fn phase_env(
    version: &str,
    instance: &str,
    params: &BTreeMap<String, ParsedParam>,
    secrets: Option<&dyn SecretResolver>,
    param_dir: Option<&Path>,
    reboot: Option<&PhaseReboot>,
    service: Option<&str>,
    persist_state: Option<PersistState>,
) -> Result<PhaseEnv> {
    let mut vars = BTreeMap::new();
    let mut param_files = Vec::new();
    let mut startup_files = Vec::new();
    if version != "default" {
        vars.insert("APP_VERSION".to_owned(), version.to_owned());
    }
    insert_instance(&mut vars, instance);
    for param in params.values() {
        let name = env_name(&param.name);
        let files = match param.lifetime {
            ParamLifetime::Startup => &mut startup_files,
            ParamLifetime::Runtime => &mut param_files,
        };
        match &param.value {
            ParsedParamValue::String(value) | ParsedParamValue::Number(value)
                if !param.file_backed =>
            {
                vars.insert(name, value.clone());
            }
            ParsedParamValue::Boolean(value) if !param.file_backed => {
                vars.insert(name, value.to_string());
            }
            ParsedParamValue::File { bytes, .. } => {
                let path = write_param_file(param_dir, &param.name, bytes)?;
                vars.insert(format!("{name}_FILE"), path.display().to_string());
                files.push(path);
            }
            // Resolved values are delivered file-backed only (`<VAR>_FILE`), never
            // exported as environment variable values.
            ParsedParamValue::SecretRef(reference) => {
                let Some(secrets) = secrets else {
                    return Err(CliError::Operational(format!(
                        "secret URI resolution for --{} is not implemented yet",
                        param.name.replace('_', "-")
                    )));
                };
                let value = secrets.resolve(reference).await.map_err(|err| {
                    CliError::Operational(format!("resolve secret {reference}: {err}"))
                })?;
                let path = write_param_file(param_dir, &param.name, &value)?;
                vars.insert(format!("{name}_FILE"), path.display().to_string());
                files.push(path);
            }
            _ => {
                let path =
                    write_param_file(param_dir, &param.name, durable_param_bytes(&param.value))?;
                vars.insert(format!("{name}_FILE"), path.display().to_string());
                files.push(path);
            }
        }
    }
    // After the params, because the service identifier may be written in terms of
    // them, and before the reboot variables, which are last for the same reason every
    // runtime-set name wins over a colliding param.
    insert_service(&mut vars, service)?;
    // After the params for that same reason: what the runtime knows about the app's
    // data beats anything a package happened to name the same way.
    insert_persist_state(&mut vars, persist_state);
    // Applied last: the reserved reboot variables win over a colliding param, as every
    // runtime-set name does.
    apply_reboot_env(&mut vars, reboot);
    Ok(PhaseEnv {
        vars,
        param_files,
        startup_files,
    })
}

/// Puts the reboot shim in front of the phase's `PATH` and — while the phase is under
/// its reboot cap — names the file the shim records a request in.
///
/// First position on `PATH` is the whole mechanism: a phase asks for a restart by
/// calling `shutdown -r now` exactly as it would anywhere else, and resolution finds
/// the shim rather than the platform's binary. At the cap the request variable is
/// simply absent, so the shim refuses the call in the phase's own log instead of the
/// runtime silently swallowing it.
fn apply_reboot_env(vars: &mut BTreeMap<String, String>, reboot: Option<&PhaseReboot>) {
    let Some(reboot) = reboot else {
        return;
    };
    vars.insert("PATH".to_owned(), phase_path(reboot.shim_dir()));
    if let Some(request) = reboot.request_file() {
        vars.insert(
            crate::reboot::REQUEST_ENV.to_owned(),
            request.display().to_string(),
        );
    }
    if let Some(reason) = reboot.deny_reason() {
        vars.insert(crate::reboot::DENY_ENV.to_owned(), reason.to_owned());
    }
}

/// Names the instance for every phase. An empty label is left out rather than exported
/// blank: a hook testing `$APP_INSTANCE` should see it either set to something usable
/// or absent.
fn insert_instance(vars: &mut BTreeMap<String, String>, instance: &str) {
    if !instance.is_empty() {
        vars.insert("APP_INSTANCE".to_owned(), instance.to_owned());
    }
}

/// What the app's persisted data looked like when this boot reached its install and
/// start phases.
///
/// An app that persists cannot tell an empty slot from a restored one by looking at
/// its own directory — both hold whatever the app itself put there — and the two call
/// for opposite work: initialize a fresh database, or leave the restored one alone.
/// So the runtime, which does know, says which of the three it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PersistState {
    /// The app's subtree on the App-data volume held no entries at the check.
    Empty,
    /// This boot populated the subtree from a restore point.
    Restored,
    /// Data is there that was not restored this boot — an earlier run's.
    Present,
}

impl PersistState {
    /// The word the phase environment carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Restored => "restored",
            Self::Present => "present",
        }
    }
}

/// Tells the install and start phases what state the app's persisted data is in.
///
/// Absent for an app that declares no `persist` block, and absent rather than blank:
/// a phase testing `$APP_PERSIST_STATE` learns from the variable's presence alone that
/// the runtime is keeping data for it at all.
fn insert_persist_state(vars: &mut BTreeMap<String, String>, state: Option<PersistState>) {
    if let Some(state) = state {
        vars.insert("APP_PERSIST_STATE".to_owned(), state.as_str().to_owned());
    }
}

/// The phase `PATH`: the shim directory, then everything the runtime itself has.
fn phase_path(shim_dir: &Path) -> String {
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let entries = std::iter::once(shim_dir.to_path_buf()).chain(std::env::split_paths(&inherited));
    std::env::join_paths(entries).map_or_else(
        |_| shim_dir.display().to_string(),
        |joined| joined.to_string_lossy().into_owned(),
    )
}

/// Re-prepends the shim directory inside a string command's own text.
///
/// String commands run through a LOGIN shell, and a login profile is free to rewrite
/// `PATH` wholesale (Debian's `/etc/profile` does exactly that for root), which would
/// drop the shim the runtime put in front. An assignment inside the command text runs
/// after the profile, so the phase's `shutdown` reaches the shim however the profile
/// rewrote the variable. Argv commands run no profile and need none of this.
#[cfg(unix)]
fn shim_first(command: &str, reboot: Option<&PhaseReboot>) -> String {
    reboot.map_or_else(
        || command.to_owned(),
        |reboot| {
            format!(
                "PATH={}:$PATH\nexport PATH\n{command}",
                sh_quote(reboot.shim_dir())
            )
        },
    )
}

/// Windows commands run through `powershell -Command`, which derives no `PATH` of its
/// own, so the environment the runtime set already holds.
#[cfg(windows)]
fn shim_first(command: &str, _reboot: Option<&PhaseReboot>) -> String {
    command.to_owned()
}

/// Single-quotes a path for `sh`, the one form in which no character is special.
#[cfg(unix)]
fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

fn durable_param_bytes(value: &ParsedParamValue) -> &[u8] {
    match value {
        ParsedParamValue::String(value) | ParsedParamValue::Number(value) => value.as_bytes(),
        ParsedParamValue::Boolean(true) => b"true",
        ParsedParamValue::Boolean(false) => b"false",
        ParsedParamValue::File { bytes, .. } => bytes,
        ParsedParamValue::SecretRef(_) => b"",
    }
}

fn durable_phase_env(
    version: &str,
    instance: &str,
    params: &BTreeMap<String, String>,
    reboot: Option<&PhaseReboot>,
    service: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut vars = BTreeMap::new();
    if version != "default" {
        vars.insert("APP_VERSION".to_owned(), version.to_owned());
    }
    insert_instance(&mut vars, instance);
    for (name, value) in params {
        vars.insert(env_name(name), value.clone());
    }
    insert_service(&mut vars, service)?;
    apply_reboot_env(&mut vars, reboot);
    Ok(vars)
}

/// Names the app's service for every phase.
///
/// The identifier a package declares is OS-agnostic and may be written in terms of the
/// version, the instance, or a param — that is how two versions of one app carry
/// distinct service names — so it is expanded against the environment built so far and
/// then checked to be the bare identifier the contract asks for. The platform's own
/// spelling is derived from it, and that is what the phase is told.
fn insert_service(vars: &mut BTreeMap<String, String>, service: Option<&str>) -> Result<()> {
    let Some(raw) = service else {
        return Ok(());
    };
    let expanded = substitute_vars(raw, vars)?;
    crate::service::validate_identifier(&expanded)?;
    vars.insert("APP_SERVICE".to_owned(), service::platform_name(&expanded));
    Ok(())
}

/// The `start.service` identifier a config declares, before expansion.
#[must_use]
fn declared_service(config: &AppConfig) -> Option<&str> {
    config
        .start
        .as_ref()
        .and_then(|start| start.service.as_deref())
}

/// Recreates `{work_dir}/.orc-params` (0700) for a fresh start.
fn prepare_param_dir(work_dir: &Path) -> Result<PathBuf> {
    let dir = param_files_dir(work_dir);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", dir.display())))?;
    set_private_dir(&dir)?;
    Ok(dir)
}

fn write_param_file(param_dir: Option<&Path>, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = if let Some(dir) = param_dir {
        dir.join(name)
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| CliError::Operational(format!("system clock before epoch: {err}")))?;
        std::env::temp_dir().join(format!(
            "orc-param-{}-{name}-{}",
            std::process::id(),
            now.as_nanos()
        ))
    };
    std::fs::write(&path, bytes)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    set_private_file(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(path)
        .map_err(|err| CliError::Operational(format!("stat {}: {err}", path.display())))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|err| CliError::Operational(format!("chmod {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(path)
        .map_err(|err| CliError::Operational(format!("stat {}: {err}", path.display())))?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)
        .map_err(|err| CliError::Operational(format!("chmod {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// Whether a phase command leads its own process group.
///
/// Phases the runtime may have to cut short — the stop command while the app is still
/// alive, the stopped hook under a cap — lead one, so ending them ends whatever they
/// started rather than orphaning it. The phases that simply run to completion stay in
/// the runtime's group, where an operator's Ctrl-C still reaches them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseGroup {
    Inherited,
    Own,
}

/// A running phase command with its output drains.
struct PhaseProcess {
    child: Child,
    stdout_drain: tokio::task::JoinHandle<()>,
    stderr_drain: tokio::task::JoinHandle<()>,
}

impl PhaseProcess {
    /// Waits for the command to exit.
    ///
    /// Cancel-safe, so the termination sequence can race it against the app's own exit
    /// and against the force token and still come back to it.
    async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait().await
    }

    /// Ends the command and everything it started, then reaps it.
    async fn kill(&mut self) {
        crate::process::AppProcess::subprocess(&mut self.child, std::time::Instant::now())
            .kill()
            .await;
        let _ = self.child.wait().await;
    }

    /// Lets both drains flush what the closed pipes still hold.
    async fn flush(self) {
        let _ = self.stdout_drain.await;
        let _ = self.stderr_drain.await;
    }
}

/// Spawns a phase command with the phase environment applied and both pipes draining
/// to the log.
fn spawn_phase(
    phase: &str,
    command: &CommandValue,
    work_dir: &Path,
    env: &BTreeMap<String, String>,
    log_line: LogLine,
    reboot: Option<&PhaseReboot>,
    group: PhaseGroup,
) -> Result<PhaseProcess> {
    let mut process = match command {
        CommandValue::String(command) => shell_command(&shim_first(command, reboot)),
        CommandValue::Argv(argv) => argv_command(argv, env)?,
    };
    apply_login_env(&mut process);
    process
        .current_dir(work_dir)
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    if group == PhaseGroup::Own {
        process.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = group;
    let mut child = process
        .spawn()
        .map_err(|err| CliError::Operational(format!("run {phase} phase: {err}")))?;
    // Drain both pipes concurrently with the wait: a blocked, unread pipe would
    // otherwise deadlock a chatty child against `child.wait()`.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Operational(format!("{phase} phase stdout not piped")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::Operational(format!("{phase} phase stderr not piped")))?;
    let stdout_drain = drain_lines(
        BufReader::new(stdout),
        LogStream::Stdout,
        Arc::clone(&log_line),
        Vec::new(),
    );
    let stderr_drain = drain_lines(
        BufReader::new(stderr),
        LogStream::Stderr,
        log_line,
        Vec::new(),
    );
    Ok(PhaseProcess {
        child,
        stdout_drain,
        stderr_drain,
    })
}

async fn run_command(
    phase: &str,
    command: PhaseCommand,
    work_dir: &Path,
    env: &BTreeMap<String, String>,
    log_line: LogLine,
    reboot: Option<&PhaseReboot>,
) -> Result<()> {
    let mut process = spawn_phase(
        phase,
        &command.value,
        work_dir,
        env,
        log_line,
        reboot,
        PhaseGroup::Inherited,
    )?;
    let status = if let Some(timeout) = command.timeout {
        if let Ok(status) = tokio::time::timeout(timeout, process.wait()).await {
            status
        } else {
            process.kill().await;
            // Killing closes the pipes; let the drains flush what was buffered.
            process.flush().await;
            return Err(CliError::Operational(format!("{phase} phase timed out")));
        }
    } else {
        process.wait().await
    }
    .map_err(|err| CliError::Operational(format!("run {phase} phase: {err}")))?;
    // Ensure every buffered line reaches the log before the phase returns.
    process.flush().await;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Operational(format!(
            "{phase} phase exited with {status}"
        )))
    }
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut process = Command::new(login_shell());
    process.arg("-l").arg("-c").arg(command);
    process
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut process = Command::new("powershell");
    process.arg("-Command").arg(command);
    process
}

/// The passwd identity of the runtime user, used to give lifecycle
/// phases a normal login environment.
///
/// Service managers start runtimes without one — no `HOME`, no profile-derived
/// `PATH` — while recipes are written against what a human gets in a shell
/// (installers that lay out under `$HOME`, tools that cache under
/// `~/.cache`). On Windows the service control manager already provides
/// `USERPROFILE`/`USERNAME` for the service account, so this is Unix-only.
#[cfg(unix)]
struct LoginIdentity {
    name: String,
    home: String,
    shell: String,
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn login_identity() -> Option<LoginIdentity> {
    // SAFETY: `passwd` is a plain-old-data libc struct for which zeroed is a
    // valid (if meaningless) value; `getpwuid_r` only writes it on success.
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 4096];
    loop {
        // SAFETY: all pointers reference live locals; the buffer length passed
        // matches the allocation getpwuid_r may fill.
        let code = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &raw mut passwd,
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
                &raw mut result,
            )
        };
        if code == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        break;
    }
    let field = |ptr: *const libc::c_char| {
        // SAFETY: on success the passwd string fields point into `buffer`,
        // which outlives this borrow; null is checked before dereferencing.
        (!ptr.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy())
    };
    Some(LoginIdentity {
        name: field(passwd.pw_name)?.into_owned(),
        home: field(passwd.pw_dir)?.into_owned(),
        shell: field(passwd.pw_shell)?.into_owned(),
    })
}

/// The login shell string commands run through: the user's passwd shell, or
/// `/bin/sh` when the account has none worth invoking.
#[cfg(unix)]
fn login_shell() -> String {
    login_identity().map_or_else(
        || "/bin/sh".to_owned(),
        |identity| usable_shell(identity.shell),
    )
}

/// Keeps a passwd shell that can actually run a command; shell-less accounts
/// (`nologin`, `false`, an empty field) fall back to `/bin/sh`.
#[cfg(unix)]
fn usable_shell(shell: String) -> String {
    let program = shell.rsplit('/').next().unwrap_or("");
    if program.is_empty() || program == "nologin" || program == "false" {
        "/bin/sh".to_owned()
    } else {
        shell
    }
}

/// Seeds the passwd-derived identity variables on a phase command, before the
/// phase's own env is applied (recipe-declared variables win).
#[cfg(unix)]
fn apply_login_env(process: &mut Command) {
    let Some(identity) = login_identity() else {
        return;
    };
    process
        .env("HOME", &identity.home)
        .env("USER", &identity.name)
        .env("LOGNAME", &identity.name)
        .env("SHELL", login_shell());
}

#[cfg(windows)]
fn apply_login_env(_process: &mut Command) {}

fn argv_command(argv: &[String], env: &BTreeMap<String, String>) -> Result<Command> {
    let Some(program) = argv.first() else {
        return Err(CliError::Operational(
            "lifecycle command argv cannot be empty".to_owned(),
        ));
    };
    let mut process = Command::new(substitute_vars(program, env)?);
    for arg in &argv[1..] {
        process.arg(substitute_vars(arg, env)?);
    }
    Ok(process)
}

fn substitute_vars(value: &str, env: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end_idx) = after_start.find('}') else {
            return Err(CliError::Operational(format!(
                "unterminated variable reference in {value:?}"
            )));
        };
        let name = &after_start[..end_idx];
        let replacement = env.get(name).ok_or_else(|| {
            CliError::Operational(format!(
                "lifecycle command references unset variable {name}"
            ))
        })?;
        out.push_str(replacement);
        rest = &after_start[end_idx + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn env_name(name: &str) -> String {
    name.to_ascii_uppercase()
}

/// Parses the manifest duration grammar — `<integer>` followed by `s`, `m`, or `h`.
///
/// Shared with the endpoint probes ([`crate::probe`]), whose `interval`/`timeout`
/// overrides use the same grammar as phase timeouts.
pub(crate) fn parse_duration(value: &str) -> Result<Duration> {
    let digits = value
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_digit())
        .map(|(index, ch)| index + ch.len_utf8())
        .last()
        .unwrap_or(0);
    if digits == 0 || digits == value.len() {
        return Err(CliError::Usage(format!("invalid timeout {value:?}")));
    }
    let amount = value[..digits]
        .parse::<u64>()
        .map_err(|_| CliError::Usage(format!("invalid timeout {value:?}")))?;
    let seconds = match &value[digits..] {
        "s" => amount,
        "m" => amount
            .checked_mul(60)
            .ok_or_else(|| CliError::Usage(format!("timeout {value:?} is too large")))?,
        "h" => amount
            .checked_mul(60 * 60)
            .ok_or_else(|| CliError::Usage(format!("timeout {value:?} is too large")))?,
        _ => return Err(CliError::Usage(format!("invalid timeout {value:?}"))),
    };
    Ok(Duration::from_secs(seconds))
}

// ─── The termination contract ────────────────────────────────────────────────────
//
// Ending an app is a sequence, not a signal: the app's own stop command runs first,
// while the app is still alive and can still do something about it; then the signal
// the app listens for; then, after a grace period nothing shortens, the kill. Whatever
// the app ends by — this sequence, a crash, or its own last line — the stopped hook
// runs afterwards and is told what happened.

/// Why an app is being stopped, as the stop and stopped hooks are told it.
///
/// The distinctions are the ones a hook can act on: a `restart` is coming back, a
/// `terminate` is not, a `shutdown` is the node going away underneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The same app is starting again — a new version, a config change, a restart.
    Restart,
    /// The app was stopped and stays installed.
    Stop,
    /// The app is being removed from this node.
    Terminate,
    /// The node itself is going down.
    Shutdown,
}

impl StopReason {
    /// The value the hooks see in `APP_STOP_REASON`.
    #[must_use]
    pub fn as_env(&self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Stop => "stop",
            Self::Terminate => "terminate",
            Self::Shutdown => "shutdown",
        }
    }
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_env())
    }
}

/// Why the stopped hook is running: because the runtime stopped the app, or because
/// the app ended on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoppedReason {
    /// The runtime asked the app to end, for this reason.
    Stopped(StopReason),
    /// Nobody asked: the app exited, cleanly or not, by itself.
    Exit,
}

impl StoppedReason {
    /// The value the hook sees in `APP_STOP_REASON`.
    #[must_use]
    pub fn as_env(&self) -> &'static str {
        match self {
            Self::Stopped(reason) => reason.as_env(),
            Self::Exit => "exit",
        }
    }
}

impl std::fmt::Display for StoppedReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_env())
    }
}

/// How the app's own stop command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopStatus {
    /// It ran and exited zero: the app said it is safe to signal.
    Ok,
    /// It ran and exited non-zero, or could not be started at all. The sequence
    /// carries on regardless — a stop command that cannot say "wait" does not get to
    /// keep the app alive.
    Failed,
    /// It was still running when `stop.timeout` elapsed.
    Timeout,
    /// It never decided anything: the app declares no stop command, or the app had
    /// already ended by the time the command would have mattered.
    Skipped,
}

impl StopStatus {
    /// The value the stopped hook sees in `APP_STOP_STATUS`.
    #[must_use]
    pub fn as_env(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Skipped => "skipped",
        }
    }
}

impl std::fmt::Display for StopStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_env())
    }
}

/// How the app actually ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopHow {
    /// It ended by itself, within the grace period.
    Graceful,
    /// The grace period ran out and the runtime killed it.
    Killed,
    /// The runtime was told to stop waiting and killed it straight away.
    Forced,
}

impl StopHow {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Killed => "killed",
            Self::Forced => "forced",
        }
    }
}

impl std::fmt::Display for StopHow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How an app run ended, in the terms the stopped hook is given: an exit code **or** a
/// signal — never both, because only one of them ever describes an exit — plus how long
/// the app ran and the pid it ran as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    /// The pid the app ran as, while the runtime still knew it.
    pub pid: Option<u32>,
    /// Exit code, when the app exited on its own terms.
    pub code: Option<i32>,
    /// Signal number, when the app was ended by one.
    pub signal: Option<i32>,
    /// How long the app ran, from start to exit.
    pub run_duration: Duration,
}

impl ExitInfo {
    /// Reads an exit off the platform status.
    #[must_use]
    pub fn from_status(status: ExitStatus, pid: Option<u32>, run_duration: Duration) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            if let Some(signal) = status.signal() {
                return Self {
                    pid,
                    code: None,
                    signal: Some(signal),
                    run_duration,
                };
            }
        }
        Self {
            pid,
            code: status.code(),
            signal: None,
            run_duration,
        }
    }

    /// An exit the runtime could not read — the wait itself failed. Rare, and never a
    /// reason to skip the stopped hook.
    #[must_use]
    pub fn unknown(pid: Option<u32>, run_duration: Duration) -> Self {
        Self {
            pid,
            code: None,
            signal: None,
            run_duration,
        }
    }
}

/// What the termination sequence did and what it ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopOutcome {
    pub how: StopHow,
    pub stop_status: StopStatus,
    pub exit: ExitInfo,
}

/// Everything the stop-side phases need to know about the app they are ending.
///
/// The params are the source the phase environment is rebuilt **from**, not a
/// snapshot taken at start: sensitive params are withdrawn once the app is running, and
/// a stop hook that has to deregister a runner needs its token back.
pub struct AppContext<'a> {
    /// The app's package name — what its packaged scripts are named after.
    pub app: &'a str,
    /// What the runtime calls this copy of the app (`name`, `name:<version>`,
    /// `name-N`); every phase gets it as `APP_INSTANCE`.
    pub instance: &'a str,
    pub version: &'a str,
    pub config: &'a AppConfig,
    pub params: &'a BTreeMap<String, ParsedParam>,
    pub work_dir: &'a Path,
    /// Runtime state directory. The stop-side hooks materialize a *refusing* reboot
    /// shim here: they get the shim on their `PATH` like every other phase, but every
    /// restart they ask for is refused.
    pub state_dir: &'a Path,
    pub secrets: Option<&'a dyn SecretResolver>,
    pub log_line: LogLine,
}

/// Longest a termination of this app can take: the stop command, the grace period, and
/// the stopped hook. Callers can sum this across supervised apps to budget a runtime
/// shutdown.
///
/// A phase the app does not declare costs nothing — except the grace period, which is
/// granted to every app that has to be signalled, declared or not. Capped at a day, so
/// one recipe asking for an hour of grace cannot make the whole figure meaningless.
#[must_use]
pub fn stop_budget(app: &str, config: &AppConfig, work_dir: &Path) -> Duration {
    let stop = config.stop.as_ref();
    // A stop command may be declared in the config or shipped as a `stop-<app>` script;
    // both hold the stop up for `stop.timeout`, so both are charged. Resolving it the
    // same way the sequence does is what keeps the budget an honest upper bound — a
    // script-only stop that reported no timeout would understate the required budget.
    let has_command = stop.is_some_and(|stop| stop.command.is_some())
        || lifecycle_script("stop", app, work_dir).is_some();
    let command = if has_command {
        stop.map_or(DEFAULT_STOP_TIMEOUT, |stop| {
            configured_duration(stop.timeout.as_deref(), DEFAULT_STOP_TIMEOUT)
        })
    } else {
        Duration::ZERO
    };
    let grace = stop.map_or(DEFAULT_STOP_GRACE, |stop| {
        configured_duration(stop.grace.as_deref(), DEFAULT_STOP_GRACE)
    });
    let stopped = config.stopped.as_ref().map_or(Duration::ZERO, |stopped| {
        configured_duration(stopped.timeout.as_deref(), DEFAULT_STOPPED_TIMEOUT)
    });
    command
        .saturating_add(grace)
        .saturating_add(stopped)
        .min(Duration::from_secs(24 * 60 * 60))
}

/// A configured duration, or the default when it is absent or unreadable. Unreadable
/// values are reported where they are used, not here.
fn configured_duration(value: Option<&str>, default: Duration) -> Duration {
    value.map_or(default, |value| parse_duration(value).unwrap_or(default))
}

/// The same, with the complaint: a phase timing the runtime cannot read falls back to
/// the default and says so once, where the operator sees it.
fn phase_duration(
    ctx: &AppContext<'_>,
    setting: &str,
    value: Option<&str>,
    default: Duration,
) -> Duration {
    let Some(value) = value else {
        return default;
    };
    parse_duration(value).unwrap_or_else(|_| {
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            setting = %setting,
            value = %value,
            "stop timing not understood, using the default"
        );
        default
    })
}

/// The signal `stop.signal` names, or `SIGTERM` when it names nothing the runtime
/// knows. A signal an app does not listen for is worse than the default, so an
/// unreadable one is reported and the default used.
fn stop_signal(ctx: &AppContext<'_>) -> StopSignal {
    let Some(value) = ctx
        .config
        .stop
        .as_ref()
        .and_then(|stop| stop.signal.as_deref())
    else {
        return StopSignal::default();
    };
    StopSignal::parse(value).unwrap_or_else(|_| {
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            signal = %value,
            "stop signal not recognized, using SIGTERM"
        );
        StopSignal::default()
    })
}

/// Reboot plumbing for a stop-side hook: the shim first on `PATH`, and every restart it
/// asks for refused in its own log. Never `None` by choice — with no shim the hook's
/// `shutdown -r now` would reach the platform's own command and take the node down to
/// end one app.
fn refusing_reboot(ctx: &AppContext<'_>) -> Option<PhaseReboot> {
    PhaseReboot::refusing(ctx.state_dir, STOP_REBOOT_DENIAL).map_or_else(
        |_| {
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                "stop hook restart guard could not be installed"
            );
            None
        },
        Some,
    )
}

/// Removes the process-private param files a stop-side hook was handed.
///
/// Deliberately not [`remove_param_files`]: the stop hook runs while the app is still
/// alive, and the app's own runtime param files live in that directory.
fn discard_phase_files(env: PhaseEnv) {
    for path in env.startup_files.into_iter().chain(env.param_files) {
        let _ = std::fs::remove_file(path);
    }
}

/// Which of the four things the sequence was waiting on happened first.
enum StopCommandEnd {
    /// The stop command exited.
    Command(std::io::Result<ExitStatus>),
    /// The app exited while its stop command was still running.
    App(std::io::Result<ExitStatus>),
    /// `stop.timeout` elapsed.
    Timeout,
    /// The caller stopped waiting.
    Forced,
}

/// Runs the app's stop command while the app is still alive, and reports what it
/// decided — plus the app's exit status if the app ended on its own meanwhile, in
/// which case there is nothing left to signal.
async fn run_stop_command(
    ctx: &AppContext<'_>,
    process: &mut AppProcess<'_>,
    command: &CommandValue,
    reason: StopReason,
    timeout: Duration,
    force: &CancellationToken,
) -> (StopStatus, Option<std::io::Result<ExitStatus>>) {
    let reboot = refusing_reboot(ctx);
    let pid = process.pid();
    let Ok(env) = stop_phase_env(ctx, reboot.as_ref(), pid, reason.as_env(), &[]).await else {
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            "stop command environment could not be prepared"
        );
        return (StopStatus::Failed, None);
    };
    let spawned = spawn_phase(
        "stop",
        command,
        ctx.work_dir,
        &env.vars,
        Arc::clone(&ctx.log_line),
        reboot.as_ref(),
        PhaseGroup::Own,
    );
    let Ok(mut phase) = spawned else {
        discard_phase_files(env);
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            "stop command could not be started"
        );
        return (StopStatus::Failed, None);
    };

    let end = tokio::select! {
        result = phase.wait() => StopCommandEnd::Command(result),
        result = process.wait() => StopCommandEnd::App(result),
        () = tokio::time::sleep(timeout) => StopCommandEnd::Timeout,
        () = force.cancelled() => StopCommandEnd::Forced,
    };
    let outcome = match end {
        StopCommandEnd::Command(Ok(status)) if status.success() => (StopStatus::Ok, None),
        StopCommandEnd::Command(Ok(status)) => {
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                exit_code = status.code().unwrap_or(-1),
                "stop command failed"
            );
            (StopStatus::Failed, None)
        }
        StopCommandEnd::Command(Err(_)) => {
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                "stop command could not be waited for"
            );
            (StopStatus::Failed, None)
        }
        StopCommandEnd::App(result) => {
            // Nothing left to quiesce: the app is already gone, so its stop command is
            // ended with it rather than left running against a dead app.
            phase.kill().await;
            tracing::info!(
                app = %ctx.app,
                instance = %ctx.instance,
                "app ended during its stop command"
            );
            (StopStatus::Skipped, Some(result))
        }
        StopCommandEnd::Timeout => {
            phase.kill().await;
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                timeout_s = timeout.as_secs(),
                "stop command timed out"
            );
            (StopStatus::Timeout, None)
        }
        StopCommandEnd::Forced => {
            phase.kill().await;
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                "stop command ended early to stop the app now"
            );
            (StopStatus::Failed, None)
        }
    };
    phase.flush().await;
    discard_phase_files(env);
    outcome
}

/// Ends one app: its stop command, then the signal, then the kill.
///
/// Steps 1 and 2 are the ask; step 3 is not optional. The grace period is granted in
/// full once the app has been asked — a stop command that ran long does not eat into
/// the time the app itself gets — and `force` collapses the whole sequence to the kill.
///
/// The stopped hook is **not** run here: it runs after every exit, including the ones
/// this sequence never saw, so it belongs to the caller that owns the app's lifetime.
/// See [`run_stopped_phase`].
pub async fn stop_sequence(
    ctx: &AppContext<'_>,
    process: &mut AppProcess<'_>,
    reason: StopReason,
    force: &CancellationToken,
) -> StopOutcome {
    let started = process.started();
    let pid = process.pid();
    let stop = ctx.config.stop.as_ref();
    let timeout = phase_duration(
        ctx,
        "stop.timeout",
        stop.and_then(|stop| stop.timeout.as_deref()),
        DEFAULT_STOP_TIMEOUT,
    );
    let grace = phase_duration(
        ctx,
        "stop.grace",
        stop.and_then(|stop| stop.grace.as_deref()),
        DEFAULT_STOP_GRACE,
    );
    // The runtime is going away itself: an upgrade or a host reboot must not wait out a
    // CI drain, so the app gets the signal and a short fixed grace, and its stop command
    // never runs. An app whose work must outlive the runtime declares service mode.
    let (grace, quiesce_first) = match reason {
        StopReason::Shutdown => (SHUTDOWN_GRACE.min(grace), false),
        _ => (grace, true),
    };
    let signal = stop_signal(ctx);
    tracing::info!(
        app = %ctx.app,
        instance = %ctx.instance,
        reason = %reason,
        timeout_s = timeout.as_secs(),
        grace_s = grace.as_secs(),
        "app stop requested"
    );

    // ── 1. the app's own stop command, while the app is still alive ──
    let command = stop_phase_command(ctx).unwrap_or_else(|_| {
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            "stop command could not be resolved"
        );
        None
    });
    let mut stop_status = StopStatus::Skipped;
    let mut early_exit = None;
    if force.is_cancelled() || !quiesce_first {
        // Already out of time, or the runtime itself is exiting: nothing polite is
        // attempted at all.
    } else if let Some(command) = command {
        let (status, exit) = run_stop_command(ctx, process, &command, reason, timeout, force).await;
        stop_status = status;
        early_exit = exit;
    }

    // ── 2/3. the signal, the grace period, and the kill ──
    let (how, status) = match early_exit {
        Some(result) => (StopHow::Graceful, result.ok()),
        None => end_the_app(ctx, process, signal, grace, force).await,
    };

    let run_duration = started.elapsed();
    let exit = status.map_or_else(
        || ExitInfo::unknown(pid, run_duration),
        |status| ExitInfo::from_status(status, pid, run_duration),
    );
    log_stopped(ctx, how, &exit);
    StopOutcome {
        how,
        stop_status,
        exit,
    }
}

/// Signals the app, grants it the grace period, and kills it if that runs out — or
/// kills it straight away when the caller has stopped waiting.
async fn end_the_app(
    ctx: &AppContext<'_>,
    process: &mut AppProcess<'_>,
    signal: StopSignal,
    grace: Duration,
    force: &CancellationToken,
) -> (StopHow, Option<ExitStatus>) {
    if force.is_cancelled() {
        process.kill().await;
        return (StopHow::Forced, process.wait().await.ok());
    }
    // A Unix child gets the signal it declared; a service gets its manager's stop. On
    // Windows a child gets nothing to act on — there the stop command was the whole
    // ask, and the grace period is the app's chance to finish acting on it.
    match process.signal(signal).await {
        StopAsk::Signal(signal) => tracing::info!(
            app = %ctx.app,
            instance = %ctx.instance,
            signal = %signal.as_str(),
            grace_s = grace.as_secs(),
            "app asked to stop"
        ),
        StopAsk::Manager => tracing::info!(
            app = %ctx.app,
            instance = %ctx.instance,
            grace_s = grace.as_secs(),
            "service asked to stop"
        ),
        StopAsk::None => tracing::info!(
            app = %ctx.app,
            instance = %ctx.instance,
            grace_s = grace.as_secs(),
            "app given time to stop"
        ),
    }
    let how = tokio::select! {
        result = process.wait() => return (StopHow::Graceful, result.ok()),
        () = tokio::time::sleep(grace) => {
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                grace_s = grace.as_secs(),
                "app killed after the grace period"
            );
            StopHow::Killed
        }
        () = force.cancelled() => {
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                "app killed to stop it now"
            );
            StopHow::Forced
        }
    };
    process.kill().await;
    (how, process.wait().await.ok())
}

/// The one line an operator reads when an app is gone.
fn log_stopped(ctx: &AppContext<'_>, how: StopHow, exit: &ExitInfo) {
    match (exit.code, exit.signal) {
        (_, Some(signal)) => tracing::info!(
            app = %ctx.app,
            instance = %ctx.instance,
            how = %how,
            signal = signal,
            duration_s = exit.run_duration.as_secs(),
            "app stopped"
        ),
        (code, None) => tracing::info!(
            app = %ctx.app,
            instance = %ctx.instance,
            how = %how,
            exit_code = code.unwrap_or(-1),
            duration_s = exit.run_duration.as_secs(),
            "app stopped"
        ),
    }
}

/// The stop phase's command: the configured one first, the packaged `stop-{app}`
/// script as the fallback — the same order every phase resolves in.
fn stop_phase_command(ctx: &AppContext<'_>) -> Result<Option<CommandValue>> {
    let configured = CommandPhase {
        command: ctx
            .config
            .stop
            .as_ref()
            .and_then(|stop| stop.command.clone()),
        timeout: None,
    };
    Ok(
        lifecycle_command("stop", ctx.app, Some(&configured), ctx.work_dir)?
            .map(|command| command.value),
    )
}

/// The environment a stop-side hook runs in: the ordinary phase environment, rebuilt
/// from the params (so withdrawn secrets are materialized afresh), plus what this hook
/// is being told about the run that is ending.
async fn stop_phase_env(
    ctx: &AppContext<'_>,
    reboot: Option<&PhaseReboot>,
    pid: Option<u32>,
    reason: &str,
    extra: &[(&str, String)],
) -> Result<PhaseEnv> {
    let mut env = phase_env(
        ctx.version,
        ctx.instance,
        ctx.params,
        ctx.secrets,
        None,
        reboot,
        declared_service(ctx.config),
        None,
    )
    .await?;
    if let Some(pid) = pid {
        env.vars.insert("APP_PID".to_owned(), pid.to_string());
    }
    env.vars
        .insert("APP_STOP_REASON".to_owned(), reason.to_owned());
    for (name, value) in extra {
        env.vars.insert((*name).to_owned(), value.clone());
    }
    Ok(env)
}

/// Runs the app's `stopped` hook, after every way an app can end.
///
/// Never fails the caller: the app is already gone, and a hook that cannot run is a
/// line in the log, not a failed stop. `cap` shortens the hook's own timeout for a
/// caller that has somewhere to be — a forced stop or runtime shutdown; it
/// never lengthens it.
pub async fn run_stopped_phase(
    ctx: &AppContext<'_>,
    reason: StoppedReason,
    stop_status: StopStatus,
    exit: &ExitInfo,
    cap: Option<Duration>,
) {
    let configured = ctx.config.stopped.as_ref();
    let command = match lifecycle_command("stopped", ctx.app, configured, ctx.work_dir) {
        Ok(Some(command)) => command,
        Ok(None) => return,
        Err(_) => {
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                "stop hook could not be resolved"
            );
            return;
        }
    };
    let timeout = phase_duration(
        ctx,
        "stopped.timeout",
        configured.and_then(|phase| phase.timeout.as_deref()),
        DEFAULT_STOPPED_TIMEOUT,
    );
    let timeout = cap.map_or(timeout, |cap| timeout.min(cap));

    let mut extra = vec![
        ("APP_STOP_STATUS", stop_status.as_env().to_owned()),
        ("APP_RUN_DURATION", exit.run_duration.as_secs().to_string()),
    ];
    // Exactly one of the two: an exit is a code or a signal, never both.
    match (exit.signal, exit.code) {
        (Some(signal), _) => extra.push(("APP_EXIT_SIGNAL", signal.to_string())),
        (None, Some(code)) => extra.push(("APP_EXIT_CODE", code.to_string())),
        (None, None) => {}
    }

    let reboot = refusing_reboot(ctx);
    let Ok(env) = stop_phase_env(ctx, reboot.as_ref(), exit.pid, reason.as_env(), &extra).await
    else {
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            "stop hook environment could not be prepared"
        );
        return;
    };
    let spawned = spawn_phase(
        "stopped",
        &command.value,
        ctx.work_dir,
        &env.vars,
        Arc::clone(&ctx.log_line),
        reboot.as_ref(),
        PhaseGroup::Own,
    );
    let Ok(mut phase) = spawned else {
        discard_phase_files(env);
        tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            "stop hook could not be started"
        );
        return;
    };
    let ended = tokio::select! {
        result = phase.wait() => Some(result),
        () = tokio::time::sleep(timeout) => None,
    };
    match ended {
        Some(Ok(status)) if status.success() => {}
        Some(Ok(status)) => tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            reason = %reason,
            exit_code = status.code().unwrap_or(-1),
            "stop hook failed"
        ),
        Some(Err(_)) => tracing::warn!(
            app = %ctx.app,
            instance = %ctx.instance,
            reason = %reason,
            "stop hook failed"
        ),
        None => {
            phase.kill().await;
            tracing::warn!(
                app = %ctx.app,
                instance = %ctx.instance,
                reason = %reason,
                timeout_s = timeout.as_secs(),
                "stop hook timed out"
            );
        }
    }
    phase.flush().await;
    discard_phase_files(env);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::StartPhase;

    /// Discards drained phase output; for tests that assert non-log behavior.
    fn no_log() -> LogLine {
        Arc::new(|_, _| {})
    }

    // ── service mode ─────────────────────────────────────────────────────────────

    fn config_of(value: serde_json::Value) -> AppConfig {
        serde_json::from_value(value).expect("app config")
    }

    #[test]
    fn a_command_alone_runs_as_a_subprocess() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({ "start": { "command": "run.sh" } }));
        let mode = resolve_start_mode("demo", &config, work.path(), &BTreeMap::new())
            .expect("resolve")
            .expect("a start");
        assert_eq!(
            mode,
            StartMode::Subprocess(CommandValue::String("run.sh".to_owned()))
        );
        assert_eq!(mode.service_name(), None);
    }

    #[test]
    fn a_command_and_a_service_make_the_runtime_own_the_definition() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({
            "start": { "command": "run.sh", "service": "jenkins-agent" }
        }));
        let mode = resolve_start_mode("demo", &config, work.path(), &BTreeMap::new())
            .expect("resolve")
            .expect("a start");
        assert_eq!(
            mode,
            StartMode::ManagedService {
                name: crate::service::platform_name("jenkins-agent"),
                command: CommandValue::String("run.sh".to_owned()),
            }
        );
    }

    #[test]
    fn a_service_alone_is_the_apps_own_definition() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({ "start": { "service": "jenkins-agent" } }));
        let mode = resolve_start_mode("demo", &config, work.path(), &BTreeMap::new())
            .expect("resolve")
            .expect("a start");
        assert_eq!(
            mode,
            StartMode::Service {
                name: crate::service::platform_name("jenkins-agent"),
            }
        );
    }

    #[test]
    fn an_app_with_no_start_at_all_has_no_mode() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({}));
        assert!(
            resolve_start_mode("demo", &config, work.path(), &BTreeMap::new())
                .expect("resolve")
                .is_none()
        );
    }

    /// Two versions of one app run side by side, so their service names must differ —
    /// which is what `${APP_VERSION}` in the identifier is for.
    #[test]
    fn a_service_name_is_written_in_terms_of_the_version() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({
            "start": { "command": "run.sh", "service": "python-${APP_VERSION}" }
        }));
        let env = BTreeMap::from([("APP_VERSION".to_owned(), "3.12".to_owned())]);
        let mode = resolve_start_mode("demo", &config, work.path(), &env)
            .expect("resolve")
            .expect("a start");
        assert_eq!(
            mode.service_name(),
            Some(crate::service::platform_name("python-3.12").as_str())
        );
    }

    #[test]
    fn a_service_name_carrying_a_platform_suffix_is_a_config_error() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({
            "start": { "command": "run.sh", "service": "jenkins-agent.service" }
        }));
        let err = resolve_start_mode("demo", &config, work.path(), &BTreeMap::new())
            .expect_err("a suffixed name is rejected");
        assert!(err.to_string().contains("jenkins-agent"), "{err}");
    }

    #[tokio::test]
    async fn every_phase_is_told_the_derived_service_name() {
        let config = config_of(serde_json::json!({
            "start": { "command": "run.sh", "service": "runner-${APP_VERSION}" }
        }));
        let env = phase_env(
            "2.1",
            "demo",
            &BTreeMap::new(),
            None,
            None,
            None,
            declared_service(&config),
            None,
        )
        .await
        .expect("env");
        assert_eq!(
            env.vars["APP_SERVICE"],
            crate::service::platform_name("runner-2.1")
        );
    }

    // ── persisted-data state ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_persisting_app_is_told_what_state_its_data_is_in() {
        for (state, word) in [
            (PersistState::Empty, "empty"),
            (PersistState::Restored, "restored"),
            (PersistState::Present, "present"),
        ] {
            let env = phase_env(
                "1.0",
                "demo",
                &BTreeMap::new(),
                None,
                None,
                None,
                None,
                Some(state),
            )
            .await
            .expect("env");
            assert_eq!(env.vars["APP_PERSIST_STATE"], word);
        }
    }

    /// An app the runtime keeps no data for must not be able to test the variable at
    /// all: absent is how it tells the two kinds of app apart.
    #[tokio::test]
    async fn an_app_that_does_not_persist_is_told_nothing_about_persisted_data() {
        let env = phase_env(
            "1.0",
            "demo",
            &BTreeMap::new(),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("env");
        assert!(!env.vars.contains_key("APP_PERSIST_STATE"));
    }

    /// The reserved name is the runtime's, exactly as the reboot and service names are:
    /// a package that declares a param spelling the same variable does not get to lie
    /// to its own install phase about what is on the volume.
    #[tokio::test]
    async fn a_param_cannot_shadow_the_persisted_data_state() {
        let params = BTreeMap::from([(
            "app_persist_state".to_owned(),
            ParsedParam {
                name: "app_persist_state".to_owned(),
                value: ParsedParamValue::String("restored".to_owned()),
                file_backed: false,
                lifetime: ParamLifetime::Runtime,
            },
        )]);
        let env = phase_env(
            "1.0",
            "demo",
            &params,
            None,
            None,
            None,
            None,
            Some(PersistState::Empty),
        )
        .await
        .expect("env");
        assert_eq!(env.vars["APP_PERSIST_STATE"], "empty");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_install_phase_reads_the_persisted_data_state() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            install: Some(CommandPhase {
                command: Some(CommandValue::String(
                    r#"printf %s "$APP_PERSIST_STATE" > state"#.to_owned(),
                )),
                timeout: None,
            }),
            ..AppConfig::default()
        };
        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &config,
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            None,
            Some(PersistState::Present),
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::Completed);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("state")).expect("state"),
            "present"
        );
    }

    #[tokio::test]
    async fn the_start_command_carries_the_persisted_data_state() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            start: Some(StartPhase {
                command: Some(CommandValue::String("true".to_owned())),
                service: None,
                restart: None,
                gui: false,
            }),
            ..AppConfig::default()
        };
        let start = start_command(
            "demo",
            "demo",
            &config,
            "1.0",
            &BTreeMap::new(),
            dir.path(),
            None,
            None,
            Some(PersistState::Empty),
        )
        .await
        .expect("start command");
        assert_eq!(start.env["APP_PERSIST_STATE"], "empty");
        remove_param_files(dir.path());
    }

    #[test]
    fn the_service_name_is_derived_without_materializing_anything() {
        let config = config_of(serde_json::json!({
            "start": { "command": "run.sh", "service": "runner-${APP_VERSION}" }
        }));
        assert_eq!(
            instance_service_name(&config, "demo", "2.1", &BTreeMap::new()).expect("name"),
            Some(crate::service::platform_name("runner-2.1"))
        );
        let plain = config_of(serde_json::json!({ "start": { "command": "run.sh" } }));
        assert_eq!(
            instance_service_name(&plain, "demo", "2.1", &BTreeMap::new()).expect("name"),
            None
        );
    }

    #[test]
    fn a_service_definition_runs_the_shim_and_never_the_app_command() {
        let work = tempfile::tempdir().expect("work dir");
        let config = config_of(serde_json::json!({
            "start": { "command": "run.sh", "service": "demo", "restart": "always" },
            "stop": { "signal": "SIGINT", "grace": "45s" }
        }));
        let spec = managed_service_spec(
            "demo",
            "demo:1.0",
            "1.0",
            &config,
            work.path(),
            "demo-service",
            Path::new("/usr/bin/demo-app"),
        );
        assert_eq!(spec.name, "demo-service");
        assert_eq!(spec.restart, RestartPolicy::Always);
        assert_eq!(spec.kill_signal, StopSignal::Int);
        assert_eq!(spec.stop_timeout, Duration::from_secs(45));
        assert_eq!(spec.exec[0], "/usr/bin/demo-app");
        assert_eq!(spec.exec[1], SHIM_SUBCOMMAND);
        assert!(
            !spec.exec.iter().any(|argument| argument == "run.sh"),
            "the definition names the shim, not the app command: {:?}",
            spec.exec
        );
        assert!(spec.exec.contains(&"demo:1.0".to_owned()));
    }

    fn stored_params() -> BTreeMap<String, ParsedParam> {
        BTreeMap::from([
            (
                "jenkins_url".to_owned(),
                ParsedParam {
                    name: "jenkins_url".to_owned(),
                    value: ParsedParamValue::String("https://ci.example.com".to_owned()),
                    file_backed: false,
                    lifetime: ParamLifetime::Runtime,
                },
            ),
            (
                "token".to_owned(),
                ParsedParam {
                    name: "token".to_owned(),
                    value: ParsedParamValue::File {
                        path: PathBuf::new(),
                        bytes: b"hunter2".to_vec(),
                    },
                    file_backed: true,
                    lifetime: ParamLifetime::Startup,
                },
            ),
        ])
    }

    #[test]
    fn the_persisted_params_round_trip_and_stay_owner_only() {
        let work = tempfile::tempdir().expect("work dir");
        let env = AppEnv {
            app: "jenkins-agent".to_owned(),
            instance: "jenkins-agent".to_owned(),
            version: "3.46".to_owned(),
            params: stored_params(),
            persist_state: Some(PersistState::Restored),
        };
        write_app_env(work.path(), &env).expect("write");

        let read = read_app_env(work.path()).expect("read");
        assert_eq!(read.app, "jenkins-agent");
        assert_eq!(read.version, "3.46");
        assert_eq!(read.params, env.params);
        assert_eq!(read.params["token"].lifetime, ParamLifetime::Startup);
        assert_eq!(read.params["jenkins_url"].lifetime, ParamLifetime::Runtime);
        assert_eq!(read.persist_state, Some(PersistState::Restored));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(app_env_path(work.path()))
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the params file holds secret material");
        }
        assert!(
            !app_env_path(work.path())
                .with_extension("json.new")
                .exists(),
            "the temp file is renamed away, not left behind"
        );
    }

    #[test]
    fn rewriting_the_persisted_params_replaces_them_whole() {
        let work = tempfile::tempdir().expect("work dir");
        let mut env = AppEnv {
            app: "demo".to_owned(),
            instance: "demo".to_owned(),
            version: "1.0".to_owned(),
            params: stored_params(),
            persist_state: None,
        };
        write_app_env(work.path(), &env).expect("first write");
        env.version = "2.0".to_owned();
        env.params.remove("token");
        write_app_env(work.path(), &env).expect("second write");

        let read = read_app_env(work.path()).expect("read");
        assert_eq!(read.version, "2.0");
        assert!(!read.params.contains_key("token"));

        remove_app_env(work.path());
        assert!(!app_env_path(work.path()).exists());
        assert!(read_app_env(work.path()).is_err());
    }

    #[tokio::test]
    async fn persisted_params_carry_resolved_secrets_so_the_shim_needs_no_resolver() {
        let resolver = StubResolver(b"hunter2".to_vec());
        let params = BTreeMap::from([(
            "token".to_owned(),
            ParsedParam {
                name: "token".to_owned(),
                value: ParsedParamValue::SecretRef("sec:token".to_owned()),
                file_backed: true,
                lifetime: ParamLifetime::Startup,
            },
        )]);
        let resolved = resolved_params(&params, Some(&resolver))
            .await
            .expect("resolve");
        assert_eq!(
            resolved["token"].value,
            ParsedParamValue::File {
                path: PathBuf::new(),
                bytes: b"hunter2".to_vec(),
            }
        );
        assert_eq!(resolved["token"].lifetime, ParamLifetime::Startup);
        assert!(resolved["token"].file_backed);

        // Rebuilt without a resolver, the environment is the one the host would have
        // built: file-backed, never an env value.
        let env = phase_env("1.0", "demo", &resolved, None, None, None, None, None)
            .await
            .expect("env");
        assert!(!env.vars.contains_key("TOKEN"));
        let path = PathBuf::from(&env.vars["TOKEN_FILE"]);
        assert_eq!(std::fs::read(&path).expect("read"), b"hunter2");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn shell_less_accounts_fall_back_to_sh() {
        assert_eq!(usable_shell("/usr/sbin/nologin".to_owned()), "/bin/sh");
        assert_eq!(usable_shell("/bin/false".to_owned()), "/bin/sh");
        assert_eq!(usable_shell(String::new()), "/bin/sh");
        assert_eq!(usable_shell("/bin/bash".to_owned()), "/bin/bash");
    }

    #[cfg(unix)]
    #[test]
    fn phase_commands_carry_a_login_environment() {
        let mut process = shell_command("true");
        apply_login_env(&mut process);
        let std_command = process.as_std();
        let args: Vec<_> = std_command.get_args().collect();
        assert_eq!(&args[..2], ["-l", "-c"]);
        let envs: BTreeMap<_, _> = std_command.get_envs().collect();
        for key in ["HOME", "USER", "LOGNAME", "SHELL"] {
            let value = envs
                .get(std::ffi::OsStr::new(key))
                .copied()
                .flatten()
                .unwrap_or_default();
            assert!(!value.is_empty(), "{key} must be seeded from passwd");
        }
    }

    #[test]
    fn substitutes_argv_variables_and_rejects_unset_refs() {
        let env = BTreeMap::from([("URL".to_owned(), "https://example.com".to_owned())]);
        assert_eq!(
            substitute_vars("--url=${URL}", &env).expect("substitute"),
            "--url=https://example.com"
        );
        assert!(substitute_vars("${MISSING}", &env).is_err());
    }

    #[test]
    fn timeout_values_parse_units() {
        assert_eq!(
            parse_duration("5s").expect("seconds"),
            Duration::from_secs(5)
        );
        assert_eq!(
            parse_duration("2m").expect("minutes"),
            Duration::from_secs(120)
        );
        assert!(parse_duration("10").is_err());
    }

    fn uninstall_script_name() -> &'static str {
        #[cfg(unix)]
        {
            "uninstall-demo.sh"
        }
        #[cfg(windows)]
        {
            "uninstall-demo.ps1"
        }
    }

    /// The configured command is the specific statement, so it wins over a script the
    /// package happens to carry for the same phase.
    #[test]
    fn uninstall_phase_prefers_the_config_command_over_the_packaged_script() {
        let dir = tempfile::tempdir().expect("work dir");
        std::fs::write(dir.path().join(uninstall_script_name()), b"").expect("script");
        let config = AppConfig {
            uninstall: Some(CommandPhase {
                command: Some(CommandValue::String("echo config".to_owned())),
                timeout: Some("5s".to_owned()),
            }),
            ..AppConfig::default()
        };
        let command = lifecycle_command("uninstall", "demo", config.uninstall.as_ref(), dir.path())
            .expect("phase")
            .expect("command");
        assert_eq!(command.timeout, Some(Duration::from_secs(5)));
        match command.value {
            CommandValue::String(command) => assert_eq!(command, "echo config"),
            CommandValue::Argv(argv) => panic!("expected the configured command, got {argv:?}"),
        }
    }

    /// With no command configured the packaged script runs, under the phase's own
    /// configured timeout.
    #[test]
    fn uninstall_phase_falls_back_to_the_packaged_script() {
        let dir = tempfile::tempdir().expect("work dir");
        std::fs::write(dir.path().join(uninstall_script_name()), b"").expect("script");
        let config = AppConfig {
            uninstall: Some(CommandPhase {
                command: None,
                timeout: Some("5s".to_owned()),
            }),
            ..AppConfig::default()
        };
        let command = lifecycle_command("uninstall", "demo", config.uninstall.as_ref(), dir.path())
            .expect("phase")
            .expect("command");
        assert_eq!(command.timeout, Some(Duration::from_secs(5)));
        match command.value {
            CommandValue::Argv(argv) => {
                assert!(
                    argv.last()
                        .is_some_and(|arg| arg.ends_with("uninstall-demo.sh")
                            || arg.ends_with("uninstall-demo.ps1")),
                    "expected the packaged script, got {argv:?}"
                );
            }
            CommandValue::String(command) => panic!("expected script argv, got {command:?}"),
        }
        // A phase with no command and no script resolves to nothing at all.
        let empty = tempfile::tempdir().expect("empty work dir");
        assert!(
            lifecycle_command("uninstall", "demo", config.uninstall.as_ref(), empty.path())
                .expect("phase")
                .is_none()
        );
    }

    fn start_script_name() -> &'static str {
        #[cfg(unix)]
        {
            "start-demo.sh"
        }
        #[cfg(windows)]
        {
            "start-demo.ps1"
        }
    }

    fn assert_is_start_script(command: &CommandValue) {
        match command {
            CommandValue::Argv(argv) => assert!(
                argv.last().is_some_and(
                    |arg| arg.ends_with("start-demo.sh") || arg.ends_with("start-demo.ps1")
                ),
                "expected the packaged start script, got {argv:?}"
            ),
            CommandValue::String(command) => panic!("expected script argv, got {command:?}"),
        }
    }

    #[test]
    fn empty_start_phase_falls_back_to_the_packaged_start_script() {
        let dir = tempfile::tempdir().expect("work dir");
        std::fs::write(dir.path().join(start_script_name()), b"").expect("script");
        // `start: {}` in the recipe: the phase is present but carries no command.
        let config = AppConfig {
            start: Some(StartPhase::default()),
            ..AppConfig::default()
        };
        let command = resolve_start_command("demo", &config, dir.path()).expect("start command");
        assert_is_start_script(&command);
    }

    #[test]
    fn absent_start_phase_still_falls_back_to_the_packaged_start_script() {
        let dir = tempfile::tempdir().expect("work dir");
        std::fs::write(dir.path().join(start_script_name()), b"").expect("script");
        let command =
            resolve_start_command("demo", &AppConfig::default(), dir.path()).expect("command");
        assert_is_start_script(&command);
    }

    #[test]
    fn the_configured_start_command_wins_over_the_packaged_script() {
        let dir = tempfile::tempdir().expect("work dir");
        std::fs::write(dir.path().join(start_script_name()), b"").expect("script");
        let config = AppConfig {
            start: Some(StartPhase {
                command: Some(CommandValue::String("echo config".to_owned())),
                ..StartPhase::default()
            }),
            ..AppConfig::default()
        };
        match resolve_start_command("demo", &config, dir.path()).expect("start command") {
            CommandValue::String(command) => assert_eq!(command, "echo config"),
            CommandValue::Argv(argv) => panic!("expected the configured command, got {argv:?}"),
        }
    }

    #[test]
    fn install_only_app_resolves_to_no_start_command() {
        let dir = tempfile::tempdir().expect("work dir");
        // No packaged script and an empty `start: {}`: still install-only, so the
        // runtime must keep reporting completed instead of failing to start.
        assert!(resolve_start_command("demo", &AppConfig::default(), dir.path()).is_none());
        let empty = AppConfig {
            start: Some(StartPhase::default()),
            ..AppConfig::default()
        };
        assert!(resolve_start_command("demo", &empty, dir.path()).is_none());
    }

    #[test]
    fn configured_command_is_used_when_no_script_is_packaged() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            start: Some(StartPhase {
                command: Some(CommandValue::String("echo config".to_owned())),
                ..StartPhase::default()
            }),
            ..AppConfig::default()
        };
        match resolve_start_command("demo", &config, dir.path()).expect("start command") {
            CommandValue::String(command) => assert_eq!(command, "echo config"),
            CommandValue::Argv(argv) => panic!("expected configured string, got {argv:?}"),
        }
    }

    #[test]
    fn start_script_lookup_is_scoped_to_the_app_name() {
        let dir = tempfile::tempdir().expect("work dir");
        std::fs::write(dir.path().join(start_script_name()), b"").expect("script");
        // `start-demo.sh` must not satisfy a different app's start phase.
        assert!(resolve_start_command("other", &AppConfig::default(), dir.path()).is_none());
    }

    #[test]
    fn durable_phase_env_sets_app_version_and_params() {
        let env = durable_phase_env(
            "1.0",
            "demo-2",
            &BTreeMap::from([("github_url".to_owned(), "https://example.com".to_owned())]),
            None,
            None,
        )
        .expect("env");
        assert_eq!(env["APP_VERSION"], "1.0");
        assert_eq!(env["APP_INSTANCE"], "demo-2");
        assert_eq!(env["GITHUB_URL"], "https://example.com");
    }

    struct StubResolver(Vec<u8>);

    impl SecretResolver for StubResolver {
        fn resolve<'a>(
            &'a self,
            _reference: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>>
        {
            let value = self.0.clone();
            Box::pin(async move { Ok(value) })
        }
    }

    struct DenyingResolver;

    impl SecretResolver for DenyingResolver {
        fn resolve<'a>(
            &'a self,
            _reference: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>>
        {
            Box::pin(async { Err(CliError::Auth("secret resolution denied".to_owned())) })
        }
    }

    fn secret_param() -> BTreeMap<String, ParsedParam> {
        secret_param_with_lifetime(ParamLifetime::Startup)
    }

    fn secret_param_with_lifetime(lifetime: ParamLifetime) -> BTreeMap<String, ParsedParam> {
        BTreeMap::from([(
            "token".to_owned(),
            ParsedParam {
                name: "token".to_owned(),
                value: ParsedParamValue::SecretRef(
                    "sec:pool:p_d000000000000:1:s_d000000000000".to_owned(),
                ),
                file_backed: true,
                lifetime,
            },
        )])
    }

    #[tokio::test]
    async fn resolved_secrets_are_file_backed_and_never_env_values() {
        let resolver = StubResolver(b"hunter2".to_vec());
        let env = phase_env(
            "1.0",
            "demo",
            &secret_param(),
            Some(&resolver),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("env");

        // The value travels only via a private temp file exposed as <VAR>_FILE.
        assert!(!env.vars.contains_key("TOKEN"));
        let path = PathBuf::from(&env.vars["TOKEN_FILE"]);
        assert_eq!(std::fs::read(&path).expect("file"), b"hunter2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(env.startup_files, vec![path]);
        assert!(env.param_files.is_empty());
        for path in env.startup_files {
            let _ = std::fs::remove_file(path);
        }
    }

    // ── capture hooks ────────────────────────────────────────────────────────────

    #[test]
    fn a_capture_hook_that_declares_no_timeout_gets_the_default_one() {
        // What a manifest asked for is what it gets, however long.
        assert_eq!(
            capture_hook_timeout(Some(Duration::from_secs(900))),
            Duration::from_secs(900)
        );
        // And a manifest that asked for nothing does not get forever: a hook runs
        // between a cycle deciding to freeze the volume and the freeze itself.
        assert_eq!(capture_hook_timeout(None), DEFAULT_CAPTURE_HOOK_TIMEOUT);
    }

    /// A hook that never returns would leave the node never capturing again, so the
    /// undeclared timeout has to be a real one: the hook is killed and the phase
    /// reports the failure that leaves this app out of the cycle.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_capture_hook_that_never_returns_is_cut_off_without_a_declared_timeout() {
        let dir = tempfile::tempdir().expect("work dir");
        let hook = CommandPhase {
            command: Some(CommandValue::String("sleep 86400".to_owned())),
            timeout: None,
        };
        let err = run_capture_hook_phase(
            "capture-pre",
            "demo",
            "1.0",
            &AppConfig::default(),
            Some(&hook),
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
        )
        .await
        .expect_err("a hook that never returns must not hold the cycle");
        assert!(
            err.to_string().contains("timed out"),
            "{err}: the hook is cut off, not waited out"
        );
    }

    /// And a hook that finishes inside its bound is simply a hook that ran.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_capture_hook_that_finishes_in_time_succeeds() {
        let dir = tempfile::tempdir().expect("work dir");
        let hook = CommandPhase {
            command: Some(CommandValue::String(
                "printf %s quiesced > flushed".to_owned(),
            )),
            timeout: Some("30s".to_owned()),
        };
        run_capture_hook_phase(
            "capture-pre",
            "demo",
            "1.0",
            &AppConfig::default(),
            Some(&hook),
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
        )
        .await
        .expect("hook");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("flushed")).expect("hook output"),
            "quiesced"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_phase_delivers_secret_file_and_removes_it_afterwards() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            install: Some(CommandPhase {
                command: Some(CommandValue::String(
                    r#"cat "$TOKEN_FILE" > out && printf %s "$TOKEN_FILE" > path"#.to_owned(),
                )),
                timeout: None,
            }),
            ..AppConfig::default()
        };
        let resolver = StubResolver(b"hunter2".to_vec());
        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &config,
            &secret_param(),
            dir.path(),
            Some(&resolver),
            no_log(),
            None,
            None,
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::Completed);

        assert_eq!(
            std::fs::read(dir.path().join("out")).expect("out"),
            b"hunter2"
        );
        let temp_path = std::fs::read_to_string(dir.path().join("path")).expect("path");
        assert!(
            !PathBuf::from(temp_path).exists(),
            "secret file must be removed after the phase"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_phase_streams_stdout_and_stderr_to_the_log_callback() {
        use std::sync::Mutex;

        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            install: Some(CommandPhase {
                command: Some(CommandValue::String("echo out; echo err >&2".to_owned())),
                timeout: None,
            }),
            ..AppConfig::default()
        };
        let captured: Arc<Mutex<Vec<(LogStream, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);
        let log: LogLine = Arc::new(move |stream: LogStream, line: &str| {
            sink.lock()
                .expect("captured")
                .push((stream, line.to_owned()));
        });
        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &config,
            &BTreeMap::new(),
            dir.path(),
            None,
            log,
            None,
            None,
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::Completed);

        let lines = captured.lock().expect("captured").clone();
        assert!(
            lines.contains(&(LogStream::Stdout, "out".to_owned())),
            "stdout line must reach the callback: {lines:?}"
        );
        assert!(
            lines.contains(&(LogStream::Stderr, "err".to_owned())),
            "stderr line must reach the callback: {lines:?}"
        );
    }

    #[tokio::test]
    async fn start_command_writes_params_under_work_dir() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            start: Some(StartPhase {
                command: Some(CommandValue::String("true".to_owned())),
                service: None,
                restart: None,
                gui: false,
            }),
            ..AppConfig::default()
        };
        let resolver = StubResolver(b"hunter2".to_vec());
        let start = start_command(
            "demo",
            "demo",
            &config,
            "1.0",
            &secret_param(),
            dir.path(),
            Some(&resolver),
            None,
            None,
        )
        .await
        .expect("start command");

        let expected = param_files_dir(dir.path()).join("token");
        assert_eq!(start.startup_files, vec![expected.clone()]);
        assert!(start.param_files.is_empty());
        assert_eq!(std::fs::read(&expected).expect("file"), b"hunter2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir_mode = std::fs::metadata(param_files_dir(dir.path()))
                .expect("stat dir")
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
            let file_mode = std::fs::metadata(&expected)
                .expect("stat file")
                .permissions()
                .mode();
            assert_eq!(file_mode & 0o777, 0o600);
        }
        remove_param_files(dir.path());
        assert!(!param_files_dir(dir.path()).exists());
    }

    /// Regression: runtime-lifetime file-backed params must still be readable
    /// after a delayed read (some apps open TLS material lazily after the
    /// detect window).
    #[cfg(unix)]
    #[tokio::test]
    async fn start_param_files_survive_until_child_exits() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            start: Some(StartPhase {
                command: Some(CommandValue::String(
                    r#"sleep 0.2 && cat "$TOKEN_FILE" > out"#.to_owned(),
                )),
                service: None,
                restart: None,
                gui: false,
            }),
            ..AppConfig::default()
        };
        let resolver = StubResolver(b"hunter2".to_vec());
        let mut start = start_command(
            "demo",
            "demo",
            &config,
            "1.0",
            &secret_param_with_lifetime(ParamLifetime::Runtime),
            dir.path(),
            Some(&resolver),
            None,
            None,
        )
        .await
        .expect("start command");
        assert_eq!(
            start.param_files,
            vec![param_files_dir(dir.path()).join("token")]
        );
        assert!(start.startup_files.is_empty());
        let status = start.command.status().await.expect("spawn delayed reader");
        assert!(status.success(), "child must read TOKEN_FILE after delay");
        assert_eq!(
            std::fs::read(dir.path().join("out")).expect("out"),
            b"hunter2"
        );
        assert!(
            param_files_dir(dir.path()).join("token").exists(),
            "param file must outlive spawn; host removes it after exit"
        );
        remove_param_files(dir.path());
        assert!(!param_files_dir(dir.path()).exists());
    }

    // ─── Phase-requested reboots ─────────────────────────────────────────────

    /// Spends the whole reboot budget of `demo`'s install phase and returns the pass
    /// that follows it — the one the runtime runs with no request file to offer.
    fn reboot_at_the_cap(state_dir: &Path) -> PhaseReboot {
        for _ in 0..crate::reboot::MAX_PHASE_REBOOTS {
            let reboot = PhaseReboot::enter(state_dir, "demo", "1.0", "install").expect("enter");
            std::fs::write(reboot.request_file().expect("under cap"), "-r now\n").expect("request");
            let _ = reboot.finish().expect("finish");
        }
        PhaseReboot::enter(state_dir, "demo", "1.0", "install").expect("enter")
    }

    #[tokio::test]
    async fn phase_env_leads_with_the_shim_and_names_the_request_file() {
        let state = tempfile::tempdir().expect("state dir");
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");
        let env = phase_env(
            "1.0",
            "demo",
            &BTreeMap::new(),
            None,
            None,
            Some(&reboot),
            None,
            None,
        )
        .await
        .expect("env");

        let path = &env.vars["PATH"];
        let first = std::env::split_paths(path).next().expect("a PATH entry");
        assert_eq!(
            first,
            reboot.shim_dir(),
            "the shim must resolve first: {path}"
        );
        assert_eq!(
            env.vars[crate::reboot::REQUEST_ENV],
            reboot
                .request_file()
                .expect("under cap")
                .display()
                .to_string()
        );
    }

    #[tokio::test]
    async fn phase_env_withholds_the_request_file_at_the_cap() {
        let state = tempfile::tempdir().expect("state dir");
        let reboot = reboot_at_the_cap(state.path());
        let env = phase_env(
            "1.0",
            "demo",
            &BTreeMap::new(),
            None,
            None,
            Some(&reboot),
            None,
            None,
        )
        .await
        .expect("env");

        // The shim stays on PATH — it is what refuses the call, loudly, in the phase's
        // own log — but there is nowhere for it to record a request.
        assert!(env.vars.contains_key("PATH"));
        assert!(
            !env.vars.contains_key(crate::reboot::REQUEST_ENV),
            "at the cap the phase must not be handed a request file"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_install_script_asking_for_a_restart_ends_in_reboot_requested() {
        let dir = tempfile::tempdir().expect("work dir");
        let state = tempfile::tempdir().expect("state dir");
        std::fs::write(
            dir.path().join("install-demo.sh"),
            "shutdown -r now\necho asked\n",
        )
        .expect("script");
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");

        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &AppConfig::default(),
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            Some(&reboot),
            None,
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::RebootRequested { reboot_count: 1 });
    }

    /// The shim assignment has to sit inside the command text, because a login
    /// profile runs before it and is free to rewrite `PATH` wholesale.
    #[cfg(unix)]
    #[test]
    fn a_string_command_re_prepends_the_shim_after_the_profile() {
        let state = tempfile::tempdir().expect("state dir");
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");
        let command = shim_first("shutdown -r now", Some(&reboot));
        let (assignment, rest) = command.split_once('\n').expect("prefixed command");
        assert_eq!(
            assignment,
            format!("PATH={}:$PATH", sh_quote(reboot.shim_dir()))
        );
        assert_eq!(rest, "export PATH\nshutdown -r now");
        // Without reboot plumbing the command is passed through untouched.
        assert_eq!(shim_first("shutdown -r now", None), "shutdown -r now");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_string_command_reaches_the_shim_through_the_login_shell() {
        let dir = tempfile::tempdir().expect("work dir");
        let state = tempfile::tempdir().expect("state dir");
        let config = AppConfig {
            install: Some(CommandPhase {
                command: Some(CommandValue::String("shutdown -r now".to_owned())),
                timeout: None,
            }),
            ..AppConfig::default()
        };
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");

        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &config,
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            Some(&reboot),
            None,
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::RebootRequested { reboot_count: 1 });
    }

    #[tokio::test]
    async fn an_app_with_no_install_phase_leaves_nothing_in_flight() {
        let dir = tempfile::tempdir().expect("work dir");
        let state = tempfile::tempdir().expect("state dir");
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");

        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &AppConfig::default(),
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            Some(&reboot),
            None,
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::Completed);
        assert_eq!(crate::reboot::read_marker(state.path()), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_phase_that_powers_nothing_off_completes_normally() {
        let dir = tempfile::tempdir().expect("work dir");
        let state = tempfile::tempdir().expect("state dir");
        // The shim refuses the halt with a non-zero exit; a script without `set -e`
        // carries on, and the pass is an ordinary success with no reboot recorded.
        std::fs::write(
            dir.path().join("install-demo.sh"),
            "shutdown -h now\nexit 0\n",
        )
        .expect("script");
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");

        let outcome = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &AppConfig::default(),
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            Some(&reboot),
            None,
        )
        .await
        .expect("install phase");
        assert_eq!(outcome, PhaseOutcome::Completed);
        assert_eq!(crate::reboot::read_marker(state.path()), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_pass_reports_the_failure_and_drops_its_request() {
        let dir = tempfile::tempdir().expect("work dir");
        let state = tempfile::tempdir().expect("state dir");
        std::fs::write(
            dir.path().join("install-demo.sh"),
            "shutdown -r now\nexit 3\n",
        )
        .expect("script");
        let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");

        let err = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &AppConfig::default(),
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            Some(&reboot),
            None,
        )
        .await
        .expect_err("install phase failed");
        assert!(err.to_string().contains("install phase exited"), "{err}");
        assert_eq!(
            crate::reboot::read_marker(state.path()),
            None,
            "a failed pass leaves no phase in flight"
        );
    }

    #[tokio::test]
    async fn secret_resolution_errors_name_the_token_and_require_a_resolver() {
        let denied = phase_env(
            "1.0",
            "demo",
            &secret_param(),
            Some(&DenyingResolver),
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("denied");
        assert!(
            denied
                .to_string()
                .contains("sec:pool:p_d000000000000:1:s_d000000000000"),
            "error names the token: {denied}"
        );

        let unresolved = phase_env("1.0", "demo", &secret_param(), None, None, None, None, None)
            .await
            .expect_err("no resolver");
        assert!(unresolved.to_string().contains("--token"), "{unresolved}");
    }

    // ─── The termination contract ────────────────────────────────────────────────

    #[test]
    fn the_stop_vocabulary_matches_the_hook_contract() {
        assert_eq!(StopReason::Restart.as_env(), "restart");
        assert_eq!(StopReason::Stop.as_env(), "stop");
        assert_eq!(StopReason::Terminate.as_env(), "terminate");
        assert_eq!(StopReason::Shutdown.as_env(), "shutdown");
        // The stopped hook has one value the stop side cannot produce: nobody asked.
        assert_eq!(StoppedReason::Stopped(StopReason::Stop).as_env(), "stop");
        assert_eq!(StoppedReason::Exit.as_env(), "exit");
        assert_eq!(StopStatus::Ok.as_env(), "ok");
        assert_eq!(StopStatus::Failed.as_env(), "failed");
        assert_eq!(StopStatus::Timeout.as_env(), "timeout");
        assert_eq!(StopStatus::Skipped.as_env(), "skipped");
        assert_eq!(StopHow::Graceful.as_str(), "graceful");
        assert_eq!(StopHow::Killed.as_str(), "killed");
        assert_eq!(StopHow::Forced.as_str(), "forced");
    }

    #[test]
    fn stop_signals_are_limited_to_the_ones_apps_listen_for() {
        for (spelling, signal) in [
            ("SIGTERM", StopSignal::Term),
            ("sigint", StopSignal::Int),
            ("HUP", StopSignal::Hup),
            ("SIGUSR1", StopSignal::Usr1),
            ("sigusr2", StopSignal::Usr2),
        ] {
            assert_eq!(StopSignal::parse(spelling).expect("known signal"), signal);
        }
        assert_eq!(StopSignal::Term.as_str(), "SIGTERM");
        assert_eq!(StopSignal::default(), StopSignal::Term);
        // A signal an app does not listen for is a configuration error, not a silent
        // fallback at the moment the app has to end.
        for rejected in ["SIGKILL", "SIGSTOP", "9", "", "TERMINATE"] {
            assert!(
                StopSignal::parse(rejected).is_err(),
                "{rejected:?} must be rejected"
            );
        }
    }

    /// The maximum duration a caller should budget for stopping this app.
    #[test]
    fn the_stop_budget_sums_the_phases_that_can_hold_a_stop_up() {
        let empty = tempfile::tempdir().expect("dir");
        // Nothing declared: the app is still signalled and still gets its grace.
        assert_eq!(
            stop_budget("demo", &AppConfig::default(), empty.path()),
            DEFAULT_STOP_GRACE
        );

        let full: AppConfig = serde_json::from_value(serde_json::json!({
            "stop": {"command": "./drain.sh", "timeout": "45s", "grace": "20s"},
            "stopped": {"command": "./report.sh", "timeout": "90s"}
        }))
        .expect("config");
        assert_eq!(
            stop_budget("demo", &full, empty.path()),
            Duration::from_secs(45 + 20 + 90)
        );

        // A stop phase with no command costs nothing but its grace; the defaults apply
        // wherever the recipe stays silent.
        let bare: AppConfig =
            serde_json::from_value(serde_json::json!({"stop": {}, "stopped": {}})).expect("config");
        assert_eq!(
            stop_budget("demo", &bare, empty.path()),
            DEFAULT_STOP_GRACE + DEFAULT_STOPPED_TIMEOUT
        );
    }

    /// A packaged `stop-{app}` script holds the stop up for exactly as long as a
    /// configured command does, and the budget has to say so: a script-only stop that
    /// reporting only its grace would understate the time allowed for draining.
    #[cfg(unix)]
    #[test]
    fn the_stop_budget_charges_a_packaged_stop_script() {
        let work = tempfile::tempdir().expect("dir");
        // The shape both real CI apps ship: timings in the config, the command in a script.
        let config: AppConfig =
            serde_json::from_value(serde_json::json!({"stop": {"timeout": "30m", "grace": "30s"}}))
                .expect("config");
        assert_eq!(
            stop_budget("demo", &config, work.path()),
            DEFAULT_STOP_GRACE.max(Duration::from_secs(30)),
            "with no script packaged only the grace is charged"
        );

        std::fs::write(work.path().join("stop-demo.sh"), b"exit 0").expect("script");
        assert_eq!(
            stop_budget("demo", &config, work.path()),
            Duration::from_secs(30 * 60 + 30),
            "the packaged script is charged its configured timeout"
        );
    }

    /// The stop command resolves like every other phase: the configured command first,
    /// the packaged `stop-{app}` script as the fallback.
    #[cfg(unix)]
    #[test]
    fn the_stop_command_prefers_the_config_and_falls_back_to_the_script() {
        let env = StopEnv::new(serde_json::json!({"stop": {"command": "echo config"}}));
        std::fs::write(env.work.path().join("stop-demo.sh"), b"").expect("script");
        match stop_phase_command(&env.context())
            .expect("resolved")
            .expect("command")
        {
            CommandValue::String(command) => assert_eq!(command, "echo config"),
            CommandValue::Argv(argv) => panic!("expected the configured command, got {argv:?}"),
        }

        let scripted = StopEnv::new(serde_json::json!({"stop": {}}));
        assert!(
            stop_phase_command(&scripted.context())
                .expect("resolved")
                .is_none()
        );
        std::fs::write(scripted.work.path().join("stop-demo.sh"), b"").expect("script");
        match stop_phase_command(&scripted.context())
            .expect("resolved")
            .expect("command")
        {
            CommandValue::Argv(argv) => assert!(
                argv.last().is_some_and(|arg| arg.ends_with("stop-demo.sh")),
                "expected the packaged script, got {argv:?}"
            ),
            CommandValue::String(command) => panic!("expected script argv, got {command:?}"),
        }
    }

    /// The ordinary path: the app's stop command runs while it is still alive, and the
    /// signal follows once the command says it is safe.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_stop_command_runs_and_then_the_app_is_signalled() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "touch stop-ran", "timeout": "5s", "grace": "5s"}
        }));
        let mut app = env.spawn("trap 'exit 0' TERM\nsleep 30 &\nwait\n");
        let outcome = env
            .stop(&mut app, StopReason::Stop, &CancellationToken::new())
            .await;

        assert!(
            env.work.path().join("stop-ran").exists(),
            "the stop command ran"
        );
        assert_eq!(outcome.stop_status, StopStatus::Ok);
        assert_eq!(outcome.how, StopHow::Graceful);
        assert_eq!(outcome.exit.code, Some(0));
        assert_eq!(outcome.exit.signal, None);
    }

    /// The app ended by itself while its stop command was draining: there is nothing
    /// left to signal, and the command is ended with the app rather than left running
    /// against a process that is already gone.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_app_that_ends_during_its_stop_command_needs_no_signal() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "sleep 30; touch stop-finished", "timeout": "30s"}
        }));
        let mut app = env.spawn("sleep 0.2\n");
        let outcome = env
            .stop(&mut app, StopReason::Stop, &CancellationToken::new())
            .await;

        assert_eq!(outcome.how, StopHow::Graceful);
        assert_eq!(outcome.exit.code, Some(0));
        // Nothing decided the stop: the command never got to finish.
        assert_eq!(outcome.stop_status, StopStatus::Skipped);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !env.work.path().join("stop-finished").exists(),
            "the stop command must not outlive the app it was draining"
        );
    }

    /// A stop command that never returns does not keep the app alive: the timeout ends
    /// it, the signal goes out anyway, and the kill follows the grace period.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_command_that_hangs_still_ends_in_a_kill() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "sleep 30", "timeout": "1s", "grace": "1s"}
        }));
        let mut app = env.spawn("trap '' TERM\nsleep 30 &\nwait\n");
        let outcome = env
            .stop(&mut app, StopReason::Terminate, &CancellationToken::new())
            .await;

        assert_eq!(outcome.stop_status, StopStatus::Timeout);
        assert_eq!(outcome.how, StopHow::Killed);
        assert_eq!(outcome.exit.signal, Some(9));
        assert_eq!(outcome.exit.code, None);
    }

    /// A stop command that fails has said nothing that keeps the app running.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failing_stop_command_does_not_stop_the_signal() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "exit 3", "timeout": "5s", "grace": "5s"}
        }));
        let mut app = env.spawn("trap 'exit 0' TERM\nsleep 30 &\nwait\n");
        let outcome = env
            .stop(&mut app, StopReason::Stop, &CancellationToken::new())
            .await;

        assert_eq!(outcome.stop_status, StopStatus::Failed);
        assert_eq!(outcome.how, StopHow::Graceful);
        assert_eq!(outcome.exit.code, Some(0));
    }

    /// Force collapses the sequence: the stop command is cut off and the app is killed
    /// without waiting out either window.
    #[cfg(unix)]
    #[tokio::test]
    async fn force_during_the_stop_command_kills_the_app_now() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "sleep 30", "timeout": "30s", "grace": "30s"}
        }));
        let mut app = env.spawn("trap '' TERM\nsleep 30 &\nwait\n");
        let force = CancellationToken::new();
        let trigger = force.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            trigger.cancel();
        });

        let began = std::time::Instant::now();
        let outcome = env.stop(&mut app, StopReason::Terminate, &force).await;
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "force must not wait out the stop timeout or the grace period"
        );
        assert_eq!(outcome.how, StopHow::Forced);
        assert_eq!(outcome.exit.signal, Some(9));
    }

    /// The runtime going away is not an orchestrated stop: a runtime upgrade or a host
    /// reboot must not wait out a CI drain, so the app's stop command never runs and the
    /// grace is the short fixed one, whatever the package asked for.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_runtime_shutdown_skips_the_stop_command_and_uses_the_short_grace() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "touch ran-the-stop-command; sleep 300",
                     "timeout": "30m", "grace": "10m"}
        }));
        let mut app = env.spawn("trap '' TERM\ntouch app-ready\nsleep 300 &\nwait\n");
        env.wait_for_file("app-ready").await;

        let began = std::time::Instant::now();
        let outcome = env
            .stop(&mut app, StopReason::Shutdown, &CancellationToken::new())
            .await;

        assert!(
            !env.work.path().join("ran-the-stop-command").exists(),
            "a shutdown must not run the app's stop command"
        );
        assert!(
            began.elapsed() < Duration::from_secs(30),
            "the shutdown grace is the short fixed one, not the configured 10m"
        );
        assert_eq!(outcome.how, StopHow::Killed);
        assert_eq!(outcome.stop_status, StopStatus::Skipped);
        assert_eq!(outcome.exit.signal, Some(9));
    }

    /// The grace period belongs to the app, not to what is left of the stop timeout: an
    /// app that takes a moment to shut down after a slow stop command still gets to.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_grace_period_is_granted_in_full_after_a_slow_stop_command() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "sleep 30", "timeout": "1s", "grace": "5s"}
        }));
        // Two seconds of shutdown work after the signal — longer than the whole stop
        // timeout that preceded it.
        let mut app = env.spawn("trap 'sleep 2; exit 7' TERM\nsleep 30 &\nwait\n");
        let outcome = env
            .stop(&mut app, StopReason::Restart, &CancellationToken::new())
            .await;

        assert_eq!(outcome.stop_status, StopStatus::Timeout);
        assert_eq!(outcome.how, StopHow::Graceful, "the app must not be killed");
        assert_eq!(outcome.exit.code, Some(7));
    }

    /// The regression that matters: an app is a tree, and the kill has to take the
    /// whole tree. A grandchild that outlived its parent would keep the port bound and
    /// the next start would fail for reasons nothing in the log explains.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_kill_reaches_a_grandchild() {
        let env = StopEnv::new(serde_json::json!({"stop": {"grace": "1s"}}));
        let mut app = env.spawn("trap '' TERM\nsleep 300 &\necho $! > grandchild.pid\nwait\n");
        let grandchild = env.wait_for_pid("grandchild.pid").await;
        assert!(pid_alive(grandchild), "the grandchild is running");

        let outcome = env
            .stop(&mut app, StopReason::Terminate, &CancellationToken::new())
            .await;
        assert_eq!(outcome.how, StopHow::Killed);
        assert_eq!(outcome.exit.signal, Some(9));

        for _ in 0..100 {
            if !pid_alive(grandchild) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Best effort tidy-up so a failure does not leave the process behind.
        kill_pid(grandchild);
        panic!("the grandchild survived the kill");
    }

    /// The hook that runs after every exit, told what happened: an app that ended by
    /// itself reports its own code and nobody's stop reason.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_stopped_hook_describes_a_natural_exit() {
        let env = StopEnv::new(serde_json::json!({
            "stopped": {"command": STOPPED_REPORT, "timeout": "10s"}
        }));
        let mut app = env.spawn("exit 0\n");
        let pid = app.id();
        let status = app.wait().await.expect("exit");
        let exit = ExitInfo::from_status(status, pid, Duration::from_secs(12));

        run_stopped_phase(
            &env.context(),
            StoppedReason::Exit,
            StopStatus::Skipped,
            &exit,
            None,
        )
        .await;

        let report = env.report();
        assert_eq!(report["reason"], "exit");
        assert_eq!(report["status"], "skipped");
        assert_eq!(report["code"], "0");
        assert_eq!(report["signal"], "unset");
        assert_eq!(report["duration"], "12");
        assert_eq!(report["instance"], "demo-1");
        assert_eq!(report["version"], "1.0");
        assert_eq!(report["pid"], pid.expect("pid").to_string());
    }

    /// After a graceful stop the hook is told which reason ended the app and that the
    /// stop command approved it.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_stopped_hook_describes_a_graceful_stop() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"command": "true", "timeout": "5s", "grace": "5s"},
            "stopped": {"command": STOPPED_REPORT, "timeout": "10s"}
        }));
        let mut app = env.spawn("trap 'exit 0' TERM\nsleep 30 &\nwait\n");
        let outcome = env
            .stop(&mut app, StopReason::Restart, &CancellationToken::new())
            .await;
        env.stopped(&outcome, StopReason::Restart, None).await;

        let report = env.report();
        assert_eq!(report["reason"], "restart");
        assert_eq!(report["status"], "ok");
        assert_eq!(report["code"], "0");
        assert_eq!(report["signal"], "unset");
    }

    /// A killed app reports the signal and no exit code — exactly one of the two is
    /// ever set, because only one of them describes what happened.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_stopped_hook_describes_a_killed_app() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {"grace": "1s"},
            "stopped": {"command": STOPPED_REPORT, "timeout": "10s"}
        }));
        let mut app = env.spawn("trap '' TERM\ntouch app-ready\nsleep 30 &\nwait\n");
        env.wait_for_file("app-ready").await;
        let outcome = env
            .stop(&mut app, StopReason::Terminate, &CancellationToken::new())
            .await;
        assert_eq!(outcome.how, StopHow::Killed);
        env.stopped(&outcome, StopReason::Terminate, None).await;

        let report = env.report();
        assert_eq!(report["reason"], "terminate");
        assert_eq!(report["status"], "skipped");
        assert_eq!(report["signal"], "9");
        assert_eq!(report["code"], "unset");
    }

    /// The whole reason the stop side rebuilds its environment from the params: the
    /// app's secrets were withdrawn when it started, and a stop hook that has to
    /// deregister a runner needs them back.
    #[cfg(unix)]
    #[tokio::test]
    async fn both_stop_hooks_get_freshly_materialized_secrets() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {
                "command": "cat \"$TOKEN_FILE\" > stop-token; printf %s \"$TOKEN_FILE\" > stop-token-path",
                "timeout": "10s",
                "grace": "5s"
            },
            "stopped": {
                "command": "cat \"$TOKEN_FILE\" > stopped-token; printf %s \"$TOKEN_FILE\" > stopped-token-path",
                "timeout": "10s"
            }
        }))
        .with_params(secret_param());
        let mut app = env.spawn("trap 'exit 0' TERM\nsleep 30 &\nwait\n");
        let outcome = env
            .stop(&mut app, StopReason::Stop, &CancellationToken::new())
            .await;
        assert_eq!(outcome.stop_status, StopStatus::Ok);
        env.stopped(&outcome, StopReason::Stop, None).await;

        for hook in ["stop", "stopped"] {
            assert_eq!(
                env.read(&format!("{hook}-token")).as_deref(),
                Some("hunter2"),
                "the {hook} hook must be able to read the secret"
            );
            let path = env.read(&format!("{hook}-token-path")).expect("path");
            assert!(
                !PathBuf::from(&path).exists(),
                "the {hook} hook's secret file must be removed afterwards: {path}"
            );
        }
        // The running app's own param directory is untouched by either hook.
        assert!(!param_files_dir(env.work.path()).exists());
    }

    /// A stop hook may not restart the node: taking the whole machine down to end one
    /// app is never the answer, so the shim refuses and says so in the app's own log.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_hook_may_not_restart_the_node() {
        let env = StopEnv::new(serde_json::json!({
            "stop": {
                "command": "if shutdown -r now; then echo taken > verdict; else echo refused > verdict; fi",
                "timeout": "10s",
                "grace": "5s"
            }
        }));
        let mut app = env.spawn("trap 'exit 0' TERM\nsleep 30 &\nwait\n");
        let _ = env
            .stop(&mut app, StopReason::Stop, &CancellationToken::new())
            .await;

        assert_eq!(env.read("verdict").as_deref(), Some("refused"));
        assert!(
            env.logged("may not restart the node"),
            "the refusal reaches the app's log: {:?}",
            env.lines.lock().expect("lines")
        );
        // Nothing was recorded, so no runtime is going to act on it either.
        assert_eq!(crate::reboot::read_marker(env.state.path()), None);
    }

    /// A caller with somewhere to be caps the hook; the hook does not get to hold the
    /// stop up, and its failure is never the caller's problem.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_capped_stopped_hook_is_cut_short_without_failing_the_stop() {
        let env = StopEnv::new(serde_json::json!({
            "stopped": {"command": "sleep 30", "timeout": "600s"}
        }));
        let began = std::time::Instant::now();
        run_stopped_phase(
            &env.context(),
            StoppedReason::Stopped(StopReason::Shutdown),
            StopStatus::Ok,
            &ExitInfo::unknown(None, Duration::from_secs(1)),
            Some(Duration::from_secs(1)),
        )
        .await;
        assert!(
            began.elapsed() < Duration::from_secs(20),
            "the cap must beat the configured timeout"
        );
    }

    /// An app that declares no stopped hook is not a phase that failed.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_app_without_a_stopped_hook_runs_nothing() {
        let env = StopEnv::new(serde_json::json!({}));
        run_stopped_phase(
            &env.context(),
            StoppedReason::Exit,
            StopStatus::Skipped,
            &ExitInfo::unknown(None, Duration::ZERO),
            None,
        )
        .await;
        assert!(env.report_missing());
    }

    /// A phase that will not end is not allowed to hold the runtime forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_phase_command_that_overruns_its_timeout_is_ended() {
        let dir = tempfile::tempdir().expect("work dir");
        let config = AppConfig {
            install: Some(CommandPhase {
                command: Some(CommandValue::String("sleep 30".to_owned())),
                timeout: Some("1s".to_owned()),
            }),
            ..AppConfig::default()
        };
        let began = std::time::Instant::now();
        let err = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &config,
            &BTreeMap::new(),
            dir.path(),
            None,
            no_log(),
            None,
            None,
        )
        .await
        .expect_err("the phase must time out");
        assert!(err.to_string().contains("install phase timed out"), "{err}");
        assert!(began.elapsed() < Duration::from_secs(20));
    }

    // ─── Stop-side test rig ──────────────────────────────────────────────────────

    /// A stopped hook that writes down everything it was told.
    #[cfg(unix)]
    const STOPPED_REPORT: &str = concat!(
        "{ echo \"reason=$APP_STOP_REASON\"; echo \"status=$APP_STOP_STATUS\"; ",
        "echo \"code=${APP_EXIT_CODE-unset}\"; echo \"signal=${APP_EXIT_SIGNAL-unset}\"; ",
        "echo \"duration=$APP_RUN_DURATION\"; echo \"pid=$APP_PID\"; ",
        "echo \"instance=$APP_INSTANCE\"; echo \"version=$APP_VERSION\"; } > stopped-report"
    );

    #[cfg(unix)]
    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 performs the permission and existence check only; `kill`
        // takes a pid by value and has no memory preconditions.
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(pid, 0) == 0
        }
    }

    #[cfg(unix)]
    fn kill_pid(pid: i32) {
        // SAFETY: as above.
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }

    /// A service manager that does exactly what a test tells it to.
    ///
    /// It records what it was asked to do and pushes the states a real manager would
    /// report, so the termination sequence can be driven through the service path
    /// without a systemd on the machine running the tests.
    #[cfg(unix)]
    struct FakeManager {
        events: std::sync::Mutex<Vec<&'static str>>,
        states: tokio::sync::mpsc::UnboundedSender<crate::service::ServiceStatus>,
        watcher: std::sync::Mutex<
            Option<tokio::sync::mpsc::UnboundedReceiver<crate::service::ServiceStatus>>,
        >,
        /// Whether asking the manager to stop actually ends the service. A manager
        /// whose stop never lands is the case the grace period and the kill exist for.
        stop_lands: bool,
    }

    #[cfg(unix)]
    impl FakeManager {
        fn new(stop_lands: bool) -> Arc<Self> {
            let (states, watcher) = tokio::sync::mpsc::unbounded_channel();
            let manager = Arc::new(Self {
                events: std::sync::Mutex::new(Vec::new()),
                states,
                watcher: std::sync::Mutex::new(Some(watcher)),
                stop_lands,
            });
            manager.report(crate::service::ServiceStatus {
                state: crate::service::ServiceState::Active,
                main_pid: Some(4242),
                ..crate::service::ServiceStatus::default()
            });
            manager
        }

        fn report(&self, status: crate::service::ServiceStatus) {
            let _ = self.states.send(status);
        }

        fn record(&self, event: &'static str) {
            self.events.lock().expect("events").push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().expect("events").clone()
        }
    }

    #[cfg(unix)]
    #[async_trait::async_trait]
    impl crate::service::ServiceBackend for FakeManager {
        fn platform_name(&self, name: &str) -> String {
            name.to_owned()
        }

        async fn define(&self, _spec: &crate::service::ServiceSpec) -> Result<()> {
            self.record("define");
            Ok(())
        }

        async fn undefine(&self, _name: &str) -> Result<()> {
            self.record("undefine");
            Ok(())
        }

        async fn start(&self, _name: &str) -> Result<()> {
            self.record("start");
            Ok(())
        }

        async fn stop(&self, _name: &str) -> Result<()> {
            self.record("stop");
            if self.stop_lands {
                self.report(crate::service::ServiceStatus {
                    state: crate::service::ServiceState::Inactive,
                    exit_code: Some(0),
                    ..crate::service::ServiceStatus::default()
                });
            }
            Ok(())
        }

        async fn kill(&self, _name: &str) -> Result<()> {
            self.record("kill");
            self.report(crate::service::ServiceStatus {
                state: crate::service::ServiceState::Failed,
                exit_signal: Some(9),
                ..crate::service::ServiceStatus::default()
            });
            Ok(())
        }

        async fn status(&self, _name: &str) -> Result<crate::service::ServiceStatus> {
            Ok(crate::service::ServiceStatus::default())
        }

        fn watch(
            &self,
            _name: &str,
        ) -> futures_util::stream::BoxStream<'static, crate::service::ServiceStatus> {
            let receiver = self
                .watcher
                .lock()
                .expect("watcher")
                .take()
                .expect("one watcher per fake manager");
            Box::pin(futures_util::stream::unfold(
                receiver,
                |mut receiver| async move { receiver.recv().await.map(|status| (status, receiver)) },
            ))
        }
    }

    /// The whole sequence over a service: the app's stop command runs while the service
    /// is still up, then the manager is asked to stop it, and the manager landing that
    /// stop is what ends the app — no signal from the runtime, and no kill.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_service_ends_when_its_manager_lands_the_stop() {
        let env = StopEnv::new(serde_json::json!({
            "start": { "command": "run.sh", "service": "demo" },
            "stop": { "command": "printf quiesced > quiesced", "grace": "30s" }
        }));
        let manager = FakeManager::new(true);
        let outcome = env
            .stop_service(
                Arc::clone(&manager),
                StopReason::Stop,
                &CancellationToken::new(),
            )
            .await;

        assert_eq!(outcome.stop_status, StopStatus::Ok);
        assert_eq!(outcome.how, StopHow::Graceful);
        assert_eq!(outcome.exit.code, Some(0));
        assert_eq!(outcome.exit.signal, None);
        assert_eq!(outcome.exit.pid, Some(4242));
        assert_eq!(env.read("quiesced").as_deref(), Some("quiesced"));
        assert_eq!(manager.events(), vec!["stop"]);
    }

    /// A stop the manager never lands is exactly what the grace period is for: the
    /// service is killed when it runs out, and the app is reported killed rather than
    /// left running behind a stop that quietly did nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_service_whose_stop_never_lands_is_killed_after_the_grace() {
        let env = StopEnv::new(serde_json::json!({
            "start": { "command": "run.sh", "service": "demo" },
            "stop": { "grace": "1s" }
        }));
        let manager = FakeManager::new(false);
        let outcome = env
            .stop_service(
                Arc::clone(&manager),
                StopReason::Stop,
                &CancellationToken::new(),
            )
            .await;

        assert_eq!(outcome.how, StopHow::Killed);
        assert_eq!(outcome.exit.signal, Some(9));
        assert_eq!(outcome.exit.code, None);
        assert_eq!(manager.events(), vec!["stop", "kill"]);
    }

    /// One app's worth of stop-side wiring: a work dir, a state dir, the config under
    /// test, and a log the assertions can read back.
    #[cfg(unix)]
    struct StopEnv {
        work: tempfile::TempDir,
        state: tempfile::TempDir,
        config: AppConfig,
        params: BTreeMap<String, ParsedParam>,
        resolver: StubResolver,
        lines: Arc<std::sync::Mutex<Vec<String>>>,
        log: LogLine,
    }

    #[cfg(unix)]
    impl StopEnv {
        fn new(config: serde_json::Value) -> Self {
            let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = Arc::clone(&lines);
            Self {
                work: tempfile::tempdir().expect("work dir"),
                state: tempfile::tempdir().expect("state dir"),
                config: serde_json::from_value(config).expect("app config"),
                params: BTreeMap::new(),
                resolver: StubResolver(b"hunter2".to_vec()),
                lines,
                log: Arc::new(move |_stream, line: &str| {
                    sink.lock().expect("lines").push(line.to_owned());
                }),
            }
        }

        fn with_params(mut self, params: BTreeMap<String, ParsedParam>) -> Self {
            self.params = params;
            self
        }

        fn context(&self) -> AppContext<'_> {
            AppContext {
                app: "demo",
                instance: "demo-1",
                version: "1.0",
                config: &self.config,
                params: &self.params,
                work_dir: self.work.path(),
                state_dir: self.state.path(),
                secrets: Some(&self.resolver),
                log_line: Arc::clone(&self.log),
            }
        }

        /// Starts a supervised app the way the runtime does, so it leads its own
        /// process group.
        fn spawn(&self, script: &str) -> Child {
            let mut command = Command::new("sh");
            command.arg("-c").arg(script).current_dir(self.work.path());
            let sink = Arc::clone(&self.log);
            crate::process::spawn_app(command, move |stream, line| {
                sink(stream, line);
            })
            .expect("spawn app")
        }

        async fn stop(
            &self,
            child: &mut Child,
            reason: StopReason,
            force: &CancellationToken,
        ) -> StopOutcome {
            let mut process = AppProcess::subprocess(child, std::time::Instant::now());
            stop_sequence(&self.context(), &mut process, reason, force).await
        }

        /// The same sequence over a service the platform's manager runs.
        async fn stop_service(
            &self,
            manager: Arc<FakeManager>,
            reason: StopReason,
            force: &CancellationToken,
        ) -> StopOutcome {
            let mut process = AppProcess::service(
                manager,
                "demo.service".to_owned(),
                std::time::Instant::now(),
                Some(4242),
            );
            stop_sequence(&self.context(), &mut process, reason, force).await
        }

        async fn stopped(&self, outcome: &StopOutcome, reason: StopReason, cap: Option<Duration>) {
            run_stopped_phase(
                &self.context(),
                StoppedReason::Stopped(reason),
                outcome.stop_status,
                &outcome.exit,
                cap,
            )
            .await;
        }

        fn read(&self, name: &str) -> Option<String> {
            std::fs::read_to_string(self.work.path().join(name))
                .ok()
                .map(|body| body.trim_end().to_owned())
        }

        fn report(&self) -> BTreeMap<String, String> {
            self.read("stopped-report")
                .expect("the stopped hook wrote its report")
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect()
        }

        fn report_missing(&self) -> bool {
            !self.work.path().join("stopped-report").exists()
        }

        fn logged(&self, needle: &str) -> bool {
            self.lines
                .lock()
                .expect("lines")
                .iter()
                .any(|line| line.contains(needle))
        }

        /// Waits for a script to write a pid down, then reads it.
        async fn wait_for_pid(&self, name: &str) -> i32 {
            for _ in 0..100 {
                if let Some(pid) = self.read(name).and_then(|body| body.trim().parse().ok()) {
                    return pid;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("{name} was never written");
        }

        /// Waits until a script has completed its startup setup.
        async fn wait_for_file(&self, name: &str) {
            for _ in 0..100 {
                if self.work.path().join(name).exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("{name} was never written");
        }
    }
}
