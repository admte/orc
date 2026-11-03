//! The format v2 publish checks (spec 214 *Publish checks*).
//!
//! `orc build`, `orc push` and the server run these on every push. They read the built
//! config and the package's file list and run nothing:
//!
//! - every token names a build var, a declared param, a file-backed param's `_file` form,
//!   or a context name available where it is used, and every `${` is closed;
//! - no two of those share a name, and no param's `_file` form collides with another;
//! - a file-backed param is never referenced by its value token;
//! - a per-OS map uses only the OS keys, and only on string or list fields — and none is
//!   left in a built config;
//! - every command is an argv list;
//! - on Unix, a `./name` first element names a packaged file marked executable.
//!
//! That every platform resolves each declared phase's command is checked where the
//! platforms are still known, by [`super::build`]. Each refusal names the platform, the
//! place (phase and element), and the token.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::token::{self, Token};
use super::{
    BUILTIN_BUILD_VARS, Context, FieldKind, Phase, field_kind, is_command_field, is_os_keyed,
    render_path,
};
use crate::app::{AppConfig, CommandValue, ParamProperty, Platform};
use crate::error::CliError;

/// One file a package carries, as its layer annotations record it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagedFile {
    /// `org.opencontainers.image.title`: the `/`-separated path in the package.
    pub title: String,
    /// `vnd.orc8r.file.executable: "true"`.
    pub executable: bool,
}

/// What a config is checked against.
#[derive(Debug, Clone, Default)]
pub struct CheckTarget<'a> {
    /// The platform the config was built for; `None` for a platformless manifest, which
    /// is held to the Unix rules as well, since it may run there.
    pub platform: Option<&'a Platform>,
    /// Names `orc build` filled in, beyond `os` and `arch`: the platforms' `vars`. A
    /// caller that no longer has the recipe (a registry) passes none; the builtins are
    /// always reserved.
    pub build_vars: BTreeSet<String>,
    /// The package's files. `None` skips the `./name` check, for a caller that has no
    /// file list; every publishing caller has one.
    pub files: Option<&'a [PackagedFile]>,
}

impl CheckTarget<'_> {
    fn label(&self) -> String {
        self.platform
            .map_or_else(|| "any platform".to_owned(), Platform::label)
    }

    /// Whether the config may run on a Unix host.
    fn unix(&self) -> bool {
        self.platform
            .is_none_or(|platform| platform.os != "windows")
    }

    fn build_vars(&self) -> BTreeSet<String> {
        BUILTIN_BUILD_VARS
            .iter()
            .map(|name| (*name).to_owned())
            .chain(self.build_vars.iter().cloned())
            .collect()
    }
}

/// One thing a publish check refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The platform label (`linux/amd64`), or `any platform`.
    pub platform: String,
    /// Where in the config: `install.command[2]`, `start.service`, `params.properties.os`.
    pub place: String,
    /// The element as written, for a command element or a string field.
    pub element: Option<String>,
    /// The token as written, `${pool}`, when one is at fault.
    pub token: Option<String>,
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.platform, self.place)?;
        if let Some(element) = &self.element {
            write!(formatter, " {element:?}")?;
        }
        formatter.write_str(": ")?;
        if let Some(token) = &self.token {
            write!(formatter, "{token} ")?;
        }
        formatter.write_str(&self.reason)
    }
}

/// Every refusal one check produced. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusals(pub Vec<Refusal>);

impl std::fmt::Display for Refusals {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("app format v2 config refused:")?;
        for refusal in &self.0 {
            write!(formatter, "\n  {refusal}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refusals {}

impl From<Refusals> for CliError {
    fn from(refusals: Refusals) -> Self {
        Self::Usage(refusals.to_string())
    }
}

/// Runs every publish check on a built v2 config blob.
///
/// # Errors
///
/// Every refusal found, when there is at least one.
pub fn check_config_bytes(body: &[u8], target: &CheckTarget<'_>) -> Result<(), Refusals> {
    match serde_json::from_slice::<Value>(body) {
        Ok(value) => check_config(&value, target),
        Err(err) => Err(Refusals(vec![Refusal {
            platform: target.label(),
            place: "config".to_owned(),
            element: None,
            token: None,
            reason: format!("is not JSON: {err}"),
        }])),
    }
}

/// Runs every publish check on a built v2 config.
///
/// # Errors
///
/// Every refusal found, when there is at least one.
pub fn check_config(config: &Value, target: &CheckTarget<'_>) -> Result<(), Refusals> {
    let mut checker = Checker {
        target,
        label: target.label(),
        refusals: Vec::new(),
    };
    checker.structure(config, &mut Vec::new());
    if !checker.refusals.is_empty() {
        // A per-OS map left in the blob would read as nonsense below; say only that.
        return Err(Refusals(checker.refusals));
    }
    match serde_json::from_value::<AppConfig>(config.clone()) {
        Ok(parsed) => checker.config(&parsed),
        Err(err) => checker.refuse("config", None, None, format!("is not an app config: {err}")),
    }
    if checker.refusals.is_empty() {
        Ok(())
    } else {
        Err(Refusals(checker.refusals))
    }
}

struct Checker<'a> {
    target: &'a CheckTarget<'a>,
    label: String,
    refusals: Vec<Refusal>,
}

/// What the checker knows about the config's names.
struct Names {
    build_vars: BTreeSet<String>,
    params: BTreeMap<String, ParamProperty>,
    service_mode: bool,
    persists: bool,
}

impl Names {
    fn file_backed(&self, name: &str) -> Option<bool> {
        self.params
            .get(name)
            .map(crate::params::is_file_backed_property)
    }
}

impl Checker<'_> {
    fn refuse(
        &mut self,
        place: impl Into<String>,
        element: Option<&str>,
        token: Option<&str>,
        reason: impl Into<String>,
    ) {
        self.refusals.push(Refusal {
            platform: self.label.clone(),
            place: place.into(),
            element: element.map(str::to_owned),
            token: token.map(str::to_owned),
            reason: reason.into(),
        });
    }

    /// Per-OS maps: none may be left in a built config, and none may sit where an object
    /// is expected.
    fn structure(&mut self, value: &Value, path: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                let keys: Vec<&str> = path.iter().map(String::as_str).collect();
                let kind = field_kind(&keys);
                if kind != FieldKind::Names && is_os_keyed(object.keys().map(String::as_str)) {
                    let reason = if kind == FieldKind::Fields {
                        "is an object, so it cannot be given per OS: a per-OS value only \
                         replaces a string or a list"
                    } else {
                        "is a per-OS value, and a published config holds plain values only: \
                         `orc build` resolves them for each platform"
                    };
                    self.refuse(render_path(&keys, None), None, None, reason);
                    return;
                }
                for (key, child) in object {
                    path.push(key.clone());
                    self.structure(child, path);
                    path.pop();
                }
            }
            Value::Array(items) => {
                let keys: Vec<&str> = path.iter().map(String::as_str).collect();
                let mut per_os = false;
                for (index, item) in items.iter().enumerate() {
                    if let Value::Object(object) = item
                        && is_os_keyed(object.keys().map(String::as_str))
                    {
                        per_os = true;
                        self.refuse(
                            render_path(&keys, Some(index)),
                            None,
                            None,
                            "is a per-OS value inside a list: a per-OS value replaces a whole \
                             field, not one element of it",
                        );
                    }
                }
                if !per_os && is_command_field(&keys) && !items.iter().all(Value::is_string) {
                    self.refuse(
                        render_path(&keys, None),
                        None,
                        None,
                        "must be a list of strings",
                    );
                }
            }
            _ => {}
        }
    }

    fn config(&mut self, config: &AppConfig) {
        let names = Names {
            build_vars: self.target.build_vars(),
            params: config
                .params
                .as_ref()
                .map(|params| params.properties.clone())
                .unwrap_or_default(),
            service_mode: config
                .start
                .as_ref()
                .is_some_and(|start| start.service.is_some()),
            persists: config.persist.is_some(),
        };
        self.collisions(&names);
        let phases = [
            (
                Phase::Install,
                config.install.as_ref().and_then(|p| p.command.as_ref()),
            ),
            (
                Phase::Start,
                config.start.as_ref().and_then(|p| p.command.as_ref()),
            ),
            (
                Phase::Stop,
                config.stop.as_ref().and_then(|p| p.command.as_ref()),
            ),
            (
                Phase::Stopped,
                config.stopped.as_ref().and_then(|p| p.command.as_ref()),
            ),
            (
                Phase::Uninstall,
                config.uninstall.as_ref().and_then(|p| p.command.as_ref()),
            ),
        ];
        for (phase, command) in phases {
            if let Some(command) = command {
                self.command(&names, phase, &format!("{}.command", phase.name()), command);
            }
        }
        if let Some(persist) = &config.persist {
            for (phase, hook) in [
                (Phase::HookPre, persist.hook_pre.as_ref()),
                (Phase::HookPost, persist.hook_post.as_ref()),
            ] {
                if let Some(command) = hook.and_then(|hook| hook.command.as_ref()) {
                    self.command(&names, phase, &format!("{}.command", phase.name()), command);
                }
            }
        }
        for (endpoint, declared) in &config.endpoints {
            if let Some(command) = declared
                .probe
                .as_ref()
                .and_then(|probe| probe.command.as_ref())
            {
                let place = format!("endpoints.{endpoint}.probe.command");
                self.command(&names, Phase::Probe, &place, command);
            }
        }
        if let Some(service) = config
            .start
            .as_ref()
            .and_then(|start| start.service.as_ref())
        {
            self.element(&names, Phase::Service, "start.service".to_owned(), service);
        }
    }

    fn collisions(&mut self, names: &Names) {
        let contexts: BTreeSet<&str> = Context::ALL.iter().map(|context| context.name()).collect();
        for var in &names.build_vars {
            if contexts.contains(var.as_str()) {
                self.refuse(
                    "platforms.vars",
                    None,
                    Some(&format!("${{{var}}}")),
                    "is both a build var and a context name",
                );
            }
        }
        for name in names.params.keys() {
            let place = format!("params.properties.{name}");
            let token = format!("${{{name}}}");
            if names.build_vars.contains(name) {
                self.refuse(
                    &place,
                    None,
                    Some(&token),
                    "is both a param and a build var",
                );
            }
            if contexts.contains(name.as_str()) {
                self.refuse(
                    &place,
                    None,
                    Some(&token),
                    "is both a param and a context name",
                );
            }
            let file = format!("{name}_file");
            let file_token = format!("${{{file}}}");
            if names.params.contains_key(&file) {
                self.refuse(
                    &place,
                    None,
                    Some(&file_token),
                    format!("is both param `{name}`'s file path and a param"),
                );
            }
            if names.build_vars.contains(&file) {
                self.refuse(
                    &place,
                    None,
                    Some(&file_token),
                    format!("is both param `{name}`'s file path and a build var"),
                );
            }
            if contexts.contains(file.as_str()) {
                self.refuse(
                    &place,
                    None,
                    Some(&file_token),
                    format!("is both param `{name}`'s file path and a context name"),
                );
            }
        }
    }

    fn command(&mut self, names: &Names, phase: Phase, place: &str, command: &CommandValue) {
        let argv = match command {
            CommandValue::String(_) => {
                self.refuse(
                    place,
                    None,
                    None,
                    "is a string; a v2 command is an argv list, run with no shell",
                );
                return;
            }
            CommandValue::Argv(argv) => argv,
        };
        // `[]` skips the phase on purpose.
        let Some(first) = argv.first() else {
            return;
        };
        if first.is_empty() {
            self.refuse(
                format!("{place}[0]"),
                Some(first),
                None,
                "is empty: the first element names the program",
            );
        }
        for (index, element) in argv.iter().enumerate() {
            self.element(names, phase, format!("{place}[{index}]"), element);
        }
        if self.target.unix() {
            self.packaged_program(&format!("{place}[0]"), first);
        }
    }

    /// The tokens of one run-time string.
    fn element(&mut self, names: &Names, phase: Phase, place: String, element: &str) {
        let tokens = match token::tokens(element) {
            Ok(tokens) => tokens,
            Err(err) => {
                self.refuse(place, Some(element), None, err.to_string());
                return;
            }
        };
        for token in tokens {
            if let Some(reason) = token_refusal(names, phase, &token) {
                self.refuse(place.clone(), Some(element), Some(token.raw), reason);
            }
        }
    }

    /// A Unix `./name` program is a file the package carries, marked executable.
    fn packaged_program(&mut self, place: &str, first: &str) {
        let Some(files) = self.target.files else {
            return;
        };
        let Some(relative) = first.strip_prefix("./") else {
            return;
        };
        // A program assembled at run time cannot be looked up here.
        if first.contains("${") {
            return;
        }
        let title = relative.trim_start_matches("./");
        match files.iter().find(|file| file.title == title) {
            None => self.refuse(
                place,
                Some(first),
                None,
                format!("names `{title}`, which the package does not carry"),
            ),
            Some(file) if !file.executable => self.refuse(
                place,
                Some(first),
                None,
                format!(
                    "names `{title}`, which the package carries without its executable bit \
                     (vnd.orc8r.file.executable); mark it executable and build on a system \
                     that records the bit"
                ),
            ),
            Some(_) => {}
        }
    }
}

/// Why `token` cannot be used in `phase`, or `None` when it can.
fn token_refusal(names: &Names, phase: Phase, token: &Token<'_>) -> Option<String> {
    let name = token.name;
    if let Some(file_backed) = names.file_backed(name) {
        return file_backed.then(|| {
            format!(
                "is the value of file-backed param `{name}`, which never appears in argv; \
                 use its path, ${{{name}_file}}"
            )
        });
    }
    if let Some(base) = name.strip_suffix("_file")
        && let Some(file_backed) = names.file_backed(base)
    {
        if !file_backed {
            return Some(format!(
                "names the file of param `{base}`, which is not file-backed; use ${{{base}}}"
            ));
        }
        if !phase.takes_files() {
            return Some(
                "is a file path, which changes at every start; a service name cannot carry one"
                    .to_owned(),
            );
        }
        return None;
    }
    if let Some(context) = Context::from_name(name) {
        if phase.context_available(context, names.service_mode, names.persists) {
            return None;
        }
        if context == Context::Service && phase.context().contains(&context) {
            return Some(
                "is set only for an app that runs as a service (start.service)".to_owned(),
            );
        }
        if context == Context::PersistState && phase.context().contains(&context) {
            return Some("is set only for an app that declares persist".to_owned());
        }
        return Some(format!("is not available in {}", phase.name()));
    }
    if names.build_vars.contains(name) {
        return Some(
            "is a build-time token, which `orc build` resolves; a built config holds none"
                .to_owned(),
        );
    }
    Some("names no build var, param, file path or context".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(os: &str) -> Platform {
        Platform {
            os: os.to_owned(),
            architecture: "amd64".to_owned(),
            variant: String::new(),
        }
    }

    fn files(entries: &[(&str, bool)]) -> Vec<PackagedFile> {
        entries
            .iter()
            .map(|(title, executable)| PackagedFile {
                title: (*title).to_owned(),
                executable: *executable,
            })
            .collect()
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline"
    )]
    fn refusals(config: Value, os: &str, packaged: &[(&str, bool)]) -> Vec<String> {
        let platform = platform(os);
        let packaged = files(packaged);
        let target = CheckTarget {
            platform: Some(&platform),
            build_vars: BTreeSet::new(),
            files: Some(&packaged),
        };
        match check_config(&config, &target) {
            Ok(()) => Vec::new(),
            Err(refusals) => refusals.0.iter().map(ToString::to_string).collect(),
        }
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline"
    )]
    fn one(config: Value) -> String {
        let found = refusals(config, "linux", &[("run.sh", true)]);
        assert_eq!(found.len(), 1, "{found:#?}");
        found.into_iter().next().expect("one refusal")
    }

    fn runner() -> Value {
        serde_json::json!({
            "params": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "token": {"type": "string", "sensitive": true},
                    "pool": {"type": "string"}
                }
            },
            "start": {
                "service": "runner-${instance}",
                "command": ["./run.sh", "--url=${url}", "--token-file=${token_file}", "--pool=${pool:-x}"]
            },
            "stopped": {"command": ["./run.sh", "--reason=${stop_reason}", "--code=${exit_code}"]}
        })
    }

    #[test]
    fn a_well_formed_config_passes() {
        assert_eq!(
            refusals(runner(), "linux", &[("run.sh", true)]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_unknown_token_is_refused_naming_platform_phase_element_and_token() {
        let found = one(serde_json::json!({"install": {"command": ["./run.sh", "--a=${nope}"]}}));
        assert_eq!(
            found,
            "linux/amd64: install.command[1] \"--a=${nope}\": ${nope} names no build var, \
             param, file path or context"
        );
    }

    #[test]
    fn an_unclosed_token_is_refused() {
        let found = one(serde_json::json!({"install": {"command": ["./run.sh", "--a=${a"]}}));
        assert!(found.contains("never closed"), "{found}");
    }

    #[test]
    fn a_context_token_outside_its_phases_is_refused() {
        let found = one(serde_json::json!({"install": {"command": ["./run.sh", "${pid}"]}}));
        assert!(
            found.contains("${pid} is not available in install"),
            "{found}"
        );
        let found = one(serde_json::json!({"stop": {"command": ["./run.sh", "${exit_code}"]}}));
        assert!(found.contains("not available in stop"), "{found}");
        let found = one(serde_json::json!({"install": {"command": ["./run.sh", "${service}"]}}));
        assert!(found.contains("runs as a service"), "{found}");
        let found =
            one(serde_json::json!({"start": {"command": ["./run.sh", "${persist_state}"]}}));
        assert!(found.contains("declares persist"), "{found}");
        let found = one(serde_json::json!({
            "persist": {"paths": ["/srv/x"], "hook_pre": {"command": ["./run.sh", "${persist_state}"]}}
        }));
        assert!(
            found.contains("not available in persist.hook_pre"),
            "{found}"
        );
        let found = one(serde_json::json!({
            "start": {"service": "a-${version}-${pid}", "command": ["./run.sh"]}
        }));
        assert!(found.contains("start.service"), "{found}");
    }

    #[test]
    fn probes_take_the_tokens_of_start() {
        let config = serde_json::json!({
            "persist": {"paths": ["/srv/x"]},
            "endpoints": {"web": {"port": 80, "probe": {"command": ["./run.sh", "${persist_state}", "${pid}"]}}}
        });
        let found = refusals(config, "linux", &[("run.sh", true)]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].contains("endpoints.web.probe.command[2]"),
            "{found:?}"
        );
        assert!(
            found[0].contains("${pid} is not available in probe"),
            "{found:?}"
        );
    }

    #[test]
    fn a_file_backed_param_has_no_value_token() {
        let mut config = runner();
        config["start"]["command"][2] = "--token=${token}".into();
        let found = one(config);
        assert!(
            found.contains("${token} is the value of file-backed param"),
            "{found}"
        );
        // Source kinds delivered as files are file-backed too.
        for kind in ["peers.all", "tls.key"] {
            let found = one(serde_json::json!({
                "params": {"properties": {"peers": {"type": "string", "x-source": {"kind": kind}}}},
                "install": {"command": ["./run.sh", "${peers}"]}
            }));
            assert!(found.contains("file-backed"), "{kind}: {found}");
        }
        let found = one(serde_json::json!({
            "params": {"properties": {"doc": {"type": "string", "contentMediaType": "application/json"}}},
            "install": {"command": ["./run.sh", "${doc}"]}
        }));
        assert!(found.contains("file-backed"), "{found}");
    }

    #[test]
    fn a_file_token_for_a_plain_param_or_a_service_name_is_refused() {
        let mut config = runner();
        config["start"]["command"][1] = "--url=${url_file}".into();
        assert!(one(config).contains("is not file-backed; use ${url}"));
        let mut config = runner();
        config["start"]["service"] = "runner-${token_file}".into();
        assert!(one(config).contains("a service name cannot carry one"));
    }

    #[test]
    fn names_shared_by_two_kinds_of_value_are_refused() {
        let found = one(serde_json::json!({"params": {"properties": {"os": {"type": "string"}}}}));
        assert!(
            found.contains("${os} is both a param and a build var"),
            "{found}"
        );
        let found = one(serde_json::json!({"params": {"properties": {"pid": {"type": "string"}}}}));
        assert!(
            found.contains("is both a param and a context name"),
            "{found}"
        );
        let found = one(serde_json::json!({
            "params": {"properties": {"cert": {"type": "string"}, "cert_file": {"type": "string"}}}
        }));
        assert!(
            found.contains("${cert_file} is both param `cert`'s file path and a param"),
            "{found}"
        );
        let platform = platform("linux");
        let target = CheckTarget {
            platform: Some(&platform),
            build_vars: BTreeSet::from(["url".to_owned(), "version".to_owned()]),
            files: None,
        };
        let found = check_config(&runner(), &target)
            .expect_err("collisions")
            .to_string();
        assert!(
            found.contains("${url} is both a param and a build var"),
            "{found}"
        );
        assert!(
            found.contains("${version} is both a build var and a context name"),
            "{found}"
        );
    }

    #[test]
    fn a_build_token_left_in_a_built_config_is_refused() {
        let found =
            one(serde_json::json!({"install": {"command": ["./run.sh", "--arch=${arch}"]}}));
        assert!(found.contains("${arch} is a build-time token"), "{found}");
    }

    #[test]
    fn a_string_command_is_refused() {
        let found = one(serde_json::json!({"install": {"command": "./run.sh"}}));
        assert!(found.contains("install.command: is a string"), "{found}");
    }

    #[test]
    fn an_empty_command_skips_and_an_empty_program_is_refused() {
        assert!(
            refusals(
                serde_json::json!({"install": {"command": []}}),
                "linux",
                &[]
            )
            .is_empty()
        );
        let found = one(serde_json::json!({"install": {"command": ["", "x"]}}));
        assert!(found.contains("install.command[0]"), "{found}");
    }

    #[test]
    fn a_per_os_map_left_in_a_published_config_is_refused() {
        let found = one(serde_json::json!({
            "install": {"command": {"unix": ["./run.sh"], "windows": ["run.ps1"]}}
        }));
        assert!(
            found.contains("install.command: is a per-OS value"),
            "{found}"
        );
        let found = one(serde_json::json!({
            "install": {"command": ["./run.sh", {"unix": "-a"}]}
        }));
        assert!(found.contains("inside a list"), "{found}");
        let found = one(serde_json::json!({"start": {"unix": {"command": ["./run.sh"]}}}));
        assert!(found.contains("start: is an object"), "{found}");
        // Params and endpoints are keyed by the author's own names, which may be OS names.
        assert!(
            refusals(
                serde_json::json!({"params": {"properties": {"linux": {"type": "string"}, "default": {"type": "string"}}}}),
                "linux",
                &[]
            )
            .is_empty()
        );
    }

    #[test]
    fn a_unix_program_must_be_a_packaged_executable() {
        let config = serde_json::json!({"install": {"command": ["./install.sh"]}});
        let found = refusals(config.clone(), "linux", &[("install.sh", false)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("without its executable bit"), "{found:?}");
        let found = refusals(config.clone(), "darwin", &[]);
        assert!(found[0].contains("does not carry"), "{found:?}");
        assert!(refusals(config.clone(), "linux", &[("install.sh", true)]).is_empty());
        // Windows records no executable bit and resolves programs its own way.
        assert!(refusals(config, "windows", &[("install.sh", false)]).is_empty());
        // A bare name is looked up in PATH and never checked against the package.
        assert!(
            refusals(
                serde_json::json!({"install": {"command": ["sh", "x"]}}),
                "linux",
                &[]
            )
            .is_empty()
        );
    }

    #[test]
    fn a_platformless_config_is_held_to_the_unix_rules() {
        let packaged = files(&[("run.sh", false)]);
        let target = CheckTarget {
            platform: None,
            build_vars: BTreeSet::new(),
            files: Some(&packaged),
        };
        let found = check_config(
            &serde_json::json!({"start": {"command": ["./run.sh"]}}),
            &target,
        )
        .expect_err("not executable")
        .to_string();
        assert!(found.contains("any platform: start.command[0]"), "{found}");
    }
}
