//! App format v2 (spec 214): params as the argv tokens a manifest writes out.
//!
//! - [`token`] — the one `${name}` syntax, shared by build and run time.
//! - [`build`] — what `orc build` does to a v2 recipe's `config:` per platform: resolves
//!   values by platform and build-time tokens, and passes run-time tokens through.
//! - [`check`] — the publish checks `orc build`, `orc push` and the server run on a
//!   built config, reading the manifest alone.
//! - [`command`] — what the runtime does to a command before it spawns it: substitutes
//!   run-time tokens and resolves the program.
//!
//! The vocabulary below is the contract both sides read, so the checker refuses exactly
//! what the runtime could not fill.

pub mod build;
pub mod check;
pub mod command;
pub mod token;

/// The keys a per-OS value may use (spec 214 *Values by platform*).
pub const OS_KEYS: [&str; 5] = ["linux", "darwin", "windows", "unix", "default"];

/// Names `orc build` fills on every platform, beside the platform's own `vars`.
pub const BUILTIN_BUILD_VARS: [&str; 2] = ["os", "arch"];

/// A context token the runtime fills (spec 214 *Context*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Context {
    Version,
    Instance,
    Service,
    PersistState,
    Pid,
    StopReason,
    StopStatus,
    ExitCode,
    ExitSignal,
    RunDuration,
}

impl Context {
    pub const ALL: [Self; 10] = [
        Self::Version,
        Self::Instance,
        Self::Service,
        Self::PersistState,
        Self::Pid,
        Self::StopReason,
        Self::StopStatus,
        Self::ExitCode,
        Self::ExitSignal,
        Self::RunDuration,
    ];

    /// The token name: `${version}`, `${stop_reason}`, …
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Instance => "instance",
            Self::Service => "service",
            Self::PersistState => "persist_state",
            Self::Pid => "pid",
            Self::StopReason => "stop_reason",
            Self::StopStatus => "stop_status",
            Self::ExitCode => "exit_code",
            Self::ExitSignal => "exit_signal",
            Self::RunDuration => "run_duration",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|context| context.name() == name)
    }
}

/// Where a run-time token is resolved: a lifecycle phase, or one of the other places a
/// command or name is filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Install,
    Start,
    Stop,
    Stopped,
    Uninstall,
    /// `persist.hook_pre`.
    HookPre,
    /// `persist.hook_post`.
    HookPost,
    /// An endpoint's `probe.command`. Takes the tokens of `start`.
    Probe,
    /// The `start.service` identifier.
    Service,
}

impl Phase {
    /// The five lifecycle phases a manifest declares at its top level.
    pub const LIFECYCLE: [Self; 5] = [
        Self::Install,
        Self::Start,
        Self::Stop,
        Self::Stopped,
        Self::Uninstall,
    ];

    /// How the manifest and every refusal name the phase.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Stopped => "stopped",
            Self::Uninstall => "uninstall",
            Self::HookPre => "persist.hook_pre",
            Self::HookPost => "persist.hook_post",
            Self::Probe => "probe",
            Self::Service => "start.service",
        }
    }

    /// The context tokens a phase can read (spec 214's *Context* table). `service` is
    /// further limited to service-mode apps and `persist_state` to `persist` apps; see
    /// [`Phase::context_available`].
    #[must_use]
    pub fn context(self) -> &'static [Context] {
        use Context::{
            ExitCode, ExitSignal, Instance, PersistState, Pid, RunDuration, Service, StopReason,
            StopStatus, Version,
        };
        match self {
            Self::Install | Self::Start | Self::Probe => {
                &[Version, Instance, Service, PersistState]
            }
            Self::Stop => &[Version, Instance, Service, Pid, StopReason],
            Self::Stopped => &[
                Version,
                Instance,
                Service,
                Pid,
                StopReason,
                StopStatus,
                ExitCode,
                ExitSignal,
                RunDuration,
            ],
            Self::Uninstall => &[Version, Instance, Service],
            Self::HookPre | Self::HookPost | Self::Service => &[Version, Instance],
        }
    }

    /// Whether `context` can be read here, for an app that does or does not run as a
    /// service and does or does not persist.
    #[must_use]
    pub fn context_available(self, context: Context, service_mode: bool, persists: bool) -> bool {
        self.context().contains(&context)
            && (context != Context::Service || service_mode)
            && (context != Context::PersistState || persists)
    }

    /// Whether a file-backed param's `_file` path can be read here. Everywhere but a
    /// service name: a path names a file that exists only while a phase runs, and a
    /// service name has to come out the same at every start.
    #[must_use]
    pub const fn takes_files(self) -> bool {
        !matches!(self, Self::Service)
    }
}

/// What a field of the config holds, for telling a per-OS value from a map that merely
/// has OS-named keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldKind {
    /// An object with fixed field names (a phase, a param, a probe): never a per-OS value.
    Fields,
    /// An object keyed by the author's own names (params, endpoints, `x-source` params),
    /// whose keys may well be `linux` or `default`.
    Names,
    /// A string, a list, or any other value: may be given per OS.
    Value,
}

/// The kind of the field at `path` (object keys from the config root; list indices
/// are not part of it).
#[allow(
    clippy::unnested_or_patterns,
    reason = "one path per line reads as the schema it is"
)]
pub(crate) fn field_kind(path: &[&str]) -> FieldKind {
    match path {
        ["params", "properties"]
        | ["params", "properties", _, "x-source", "params"]
        | ["endpoints"] => FieldKind::Names,
        []
        | ["params"]
        | ["params", "properties", _]
        | ["params", "properties", _, "x-source"]
        | ["endpoints", _]
        | ["endpoints", _, "probe"]
        | ["install" | "start" | "stop" | "stopped" | "uninstall"]
        | ["persist"]
        | ["persist", "hook_pre" | "hook_post"]
        | ["versions"]
        | ["versions", "filter"] => FieldKind::Fields,
        _ => FieldKind::Value,
    }
}

/// The phase whose run-time tokens a string at `path` takes, or `None` for a field the
/// runtime never resolves (where only build-time tokens may appear).
pub(crate) fn runtime_field(path: &[&str]) -> Option<Phase> {
    match path {
        ["install", "command"] => Some(Phase::Install),
        ["start", "command"] => Some(Phase::Start),
        ["stop", "command"] => Some(Phase::Stop),
        ["stopped", "command"] => Some(Phase::Stopped),
        ["uninstall", "command"] => Some(Phase::Uninstall),
        ["persist", "hook_pre", "command"] => Some(Phase::HookPre),
        ["persist", "hook_post", "command"] => Some(Phase::HookPost),
        ["endpoints", _, "probe", "command"] => Some(Phase::Probe),
        ["start", "service"] => Some(Phase::Service),
        _ => None,
    }
}

/// Whether the field at `path` is a command (as opposed to the service name).
pub(crate) fn is_command_field(path: &[&str]) -> bool {
    runtime_field(path).is_some_and(|phase| phase != Phase::Service)
}

/// The key a per-OS value picks for `os`: the most specific one present.
#[must_use]
pub fn os_key_for<'a>(os: &str, keys: &[&'a str]) -> Option<&'a str> {
    let family = matches!(os, "linux" | "darwin").then_some("unix");
    [Some(os), family, Some("default")]
        .into_iter()
        .flatten()
        .find_map(|wanted| keys.iter().copied().find(|key| *key == wanted))
}

/// Whether an object's keys make it a per-OS value: at least one key, all of them OS keys.
pub(crate) fn is_os_keyed<'a>(mut keys: impl Iterator<Item = &'a str>) -> bool {
    let mut any = false;
    keys.all(|key| {
        any = true;
        OS_KEYS.contains(&key)
    }) && any
}

/// Renders a config path for a refusal: `install.command[2]`.
pub(crate) fn render_path(path: &[&str], index: Option<usize>) -> String {
    let mut out = path.join(".");
    if let Some(index) = index {
        use std::fmt::Write as _;
        let _ = write!(out, "[{index}]");
    }
    if out.is_empty() {
        "config".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_most_specific_os_key_wins() {
        let all = ["linux", "darwin", "windows", "unix", "default"];
        assert_eq!(os_key_for("linux", &all), Some("linux"));
        assert_eq!(os_key_for("linux", &["unix", "default"]), Some("unix"));
        assert_eq!(os_key_for("darwin", &["unix", "windows"]), Some("unix"));
        assert_eq!(os_key_for("windows", &["unix", "default"]), Some("default"));
        assert_eq!(os_key_for("windows", &["unix"]), None);
        assert_eq!(os_key_for("freebsd", &["unix", "linux"]), None);
    }

    #[test]
    fn only_a_map_of_os_keys_alone_is_per_os() {
        assert!(is_os_keyed(["unix", "windows"].into_iter()));
        assert!(is_os_keyed(["default"].into_iter()));
        assert!(!is_os_keyed(["unix", "command"].into_iter()));
        assert!(!is_os_keyed(std::iter::empty()));
    }

    #[test]
    fn the_context_table_matches_the_spec() {
        assert!(Phase::Stopped.context_available(Context::ExitCode, false, false));
        assert!(!Phase::Stop.context_available(Context::ExitCode, false, false));
        assert!(!Phase::Install.context_available(Context::Pid, false, false));
        assert!(Phase::Probe.context_available(Context::PersistState, false, true));
        assert!(!Phase::Probe.context_available(Context::PersistState, false, false));
        assert!(!Phase::Install.context_available(Context::Service, false, false));
        assert!(Phase::Uninstall.context_available(Context::Service, true, false));
        assert!(!Phase::HookPre.context_available(Context::Service, true, false));
        assert!(!Phase::Service.context_available(Context::Service, true, false));
        assert!(Phase::Service.context_available(Context::Instance, true, false));
    }
}
