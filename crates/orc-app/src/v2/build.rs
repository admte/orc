//! What `orc build` does to a format v2 recipe, per platform (spec 214 *Values by
//! platform*, *Tokens*).
//!
//! - A per-OS value — an object whose keys are all OS keys, standing where a string or a
//!   list goes — becomes the value of the most specific key for the platform. A key
//!   missing for the platform leaves the field absent; for a command that is a refusal,
//!   since a phase skips a platform only on purpose, with an empty list.
//! - A command resolved to an empty list is left out of the config: the phase does not
//!   run on that platform.
//! - Build-time tokens (`${os}`, `${arch}`, the platform's `vars`) are resolved in every
//!   string. In the fields the runtime resolves again — commands, probe commands,
//!   persist hook commands and `start.service` — run-time tokens and escapes are kept as
//!   written and a build value is escaped, so the runtime reads it back unchanged.
//!   Everywhere else an escape is resolved and a run-time token is refused.
//!
//! Only `config:` takes per-OS values; `files:` entries take build-time tokens, as a v1
//! recipe's do.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use super::check::Refusal;
use super::token::{self, Piece};
use super::{
    BUILTIN_BUILD_VARS, Context, FieldKind, field_kind, is_command_field, is_os_keyed, os_key_for,
    render_path, runtime_field,
};

/// The platform a config is being built for.
#[derive(Debug, Clone, Copy)]
pub struct BuildPlatform<'a> {
    pub os: &'a str,
    pub arch: &'a str,
    /// The label refusals name it by, `linux/amd64`.
    pub label: &'a str,
    pub vars: &'a BTreeMap<String, String>,
}

impl<'a> BuildPlatform<'a> {
    fn lookup(self, name: &str) -> Option<&'a str> {
        match name {
            "os" => Some(self.os),
            "arch" => Some(self.arch),
            name => self.vars.get(name).map(String::as_str),
        }
    }
}

/// Every build-time name a recipe has: `os`, `arch`, and the keys of every platform's
/// `vars`. A token naming one is a build token on every platform, set or not.
#[must_use]
pub fn build_var_names<'a>(
    vars: impl IntoIterator<Item = &'a BTreeMap<String, String>>,
) -> BTreeSet<String> {
    BUILTIN_BUILD_VARS
        .iter()
        .map(|name| (*name).to_owned())
        .chain(vars.into_iter().flat_map(|vars| vars.keys().cloned()))
        .collect()
}

/// Resolves a v2 recipe's `config:` for one platform (`None` for a recipe that declares
/// no platforms) into the JSON its config blob holds.
///
/// # Errors
///
/// Every refusal found: a per-OS value misused or left unresolved, a command a platform
/// does not resolve, a build var a platform does not set, a run-time token outside a
/// run-time field, an unknown name, or invalid token syntax.
pub fn resolve_config(
    config: &YamlValue,
    platform: Option<BuildPlatform<'_>>,
    build_vars: &BTreeSet<String>,
) -> Result<JsonValue, Vec<Refusal>> {
    let mut builder = Builder {
        platform,
        label: platform.map_or("any platform", |platform| platform.label),
        build_vars,
        runtime_names: runtime_names(config),
        refusals: Vec::new(),
    };
    let resolved = builder.walk(config, &mut Vec::new(), None);
    if builder.refusals.is_empty() {
        Ok(resolved.unwrap_or(JsonValue::Null))
    } else {
        Err(builder.refusals)
    }
}

/// Resolves the build-time tokens of a string outside the config — a `files:` path, a
/// `url`, a `sha256` — where no run-time token may appear.
///
/// # Errors
///
/// The refusal, naming `place`.
pub fn resolve_build_string(
    input: &str,
    place: &str,
    platform: Option<BuildPlatform<'_>>,
    build_vars: &BTreeSet<String>,
) -> Result<String, Refusal> {
    let mut builder = Builder {
        platform,
        label: platform.map_or("any platform", |platform| platform.label),
        build_vars,
        runtime_names: BTreeSet::new(),
        refusals: Vec::new(),
    };
    match builder.string(input, place, None) {
        Some(out) if builder.refusals.is_empty() => Ok(out),
        _ => Err(builder.refusals.remove(0)),
    }
}

/// [`resolve_config`] for a recipe builder: the refusals as one usage error.
///
/// # Errors
///
/// [`crate::error::CliError::Usage`] listing every refusal.
pub fn platform_config(
    config: &YamlValue,
    platform: Option<BuildPlatform<'_>>,
    build_vars: &BTreeSet<String>,
) -> crate::error::Result<JsonValue> {
    resolve_config(config, platform, build_vars)
        .map_err(|refusals| super::check::Refusals(refusals).into())
}

/// [`resolve_build_string`] for a recipe builder.
///
/// # Errors
///
/// [`crate::error::CliError::Usage`] naming the refusal.
pub fn build_string(
    input: &str,
    place: &str,
    platform: Option<BuildPlatform<'_>>,
    build_vars: &BTreeSet<String>,
) -> crate::error::Result<String> {
    resolve_build_string(input, place, platform, build_vars)
        .map_err(|refusal| super::check::Refusals(vec![refusal]).into())
}

/// Runs the publish checks on one platform's built config blob, for a recipe builder.
///
/// # Errors
///
/// [`crate::error::CliError::Usage`] listing every refusal.
pub fn check_built(
    config_bytes: &[u8],
    platform: Option<&crate::app::Platform>,
    build_vars: &BTreeSet<String>,
    files: &[super::check::PackagedFile],
) -> crate::error::Result<()> {
    let target = super::check::CheckTarget {
        platform,
        build_vars: build_vars.clone(),
        files: Some(files),
    };
    super::check::check_config_bytes(config_bytes, &target).map_err(Into::into)
}

/// The run-time names a config declares — params, their `_file` forms, and the context
/// names — used only to say which kind of name was misplaced.
fn runtime_names(config: &YamlValue) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = Context::ALL
        .iter()
        .map(|context| context.name().to_owned())
        .collect();
    if let Some(YamlValue::Mapping(properties)) = config
        .get("params")
        .and_then(|params| params.get("properties"))
    {
        for key in properties.keys().filter_map(YamlValue::as_str) {
            names.insert(key.to_owned());
            names.insert(format!("{key}_file"));
        }
    }
    names
}

struct Builder<'a> {
    platform: Option<BuildPlatform<'a>>,
    label: &'a str,
    build_vars: &'a BTreeSet<String>,
    runtime_names: BTreeSet<String>,
    refusals: Vec<Refusal>,
}

impl Builder<'_> {
    fn refuse(
        &mut self,
        place: String,
        element: Option<&str>,
        token: Option<&str>,
        reason: impl Into<String>,
    ) {
        self.refusals.push(Refusal {
            platform: self.label.to_owned(),
            place,
            element: element.map(str::to_owned),
            token: token.map(str::to_owned),
            reason: reason.into(),
        });
    }

    /// Resolves one value; `None` when it is absent for this platform.
    fn walk(
        &mut self,
        value: &YamlValue,
        path: &mut Vec<String>,
        index: Option<usize>,
    ) -> Option<JsonValue> {
        let owned = path.clone();
        let keys: Vec<&str> = owned.iter().map(String::as_str).collect();
        let place = render_path(&keys, index);
        match value {
            YamlValue::Null => Some(JsonValue::Null),
            YamlValue::Bool(value) => Some(JsonValue::Bool(*value)),
            YamlValue::Number(number) => match serde_json::to_value(number) {
                Ok(number) => Some(number),
                Err(err) => {
                    self.refuse(place, None, None, format!("is not a JSON number: {err}"));
                    None
                }
            },
            YamlValue::String(text) => self
                .string(text, &place, runtime_field(&keys).map(|_| ()))
                .map(JsonValue::String),
            YamlValue::Sequence(items) => {
                let is_command = is_command_field(&keys);
                if is_command && items.is_empty() {
                    // Skipped on purpose.
                    return None;
                }
                let mut out = Vec::with_capacity(items.len());
                for (position, item) in items.iter().enumerate() {
                    if let YamlValue::Mapping(mapping) = item
                        && is_os_keyed(mapping.keys().filter_map(YamlValue::as_str))
                        && mapping.keys().all(YamlValue::is_string)
                    {
                        self.refuse(
                            render_path(&keys, Some(position)),
                            None,
                            None,
                            "is a per-OS value inside a list: a per-OS value replaces a whole \
                             field, not one element of it",
                        );
                        continue;
                    }
                    if let Some(item) = self.walk(item, path, Some(position)) {
                        out.push(item);
                    }
                }
                Some(JsonValue::Array(out))
            }
            YamlValue::Mapping(mapping) => self.mapping(mapping, path, &keys, place),
            YamlValue::Tagged(tagged) => self.walk(&tagged.value, path, index),
        }
    }

    fn mapping(
        &mut self,
        mapping: &serde_yaml::Mapping,
        path: &mut Vec<String>,
        keys: &[&str],
        place: String,
    ) -> Option<JsonValue> {
        let mut names = Vec::with_capacity(mapping.len());
        for key in mapping.keys() {
            let Some(key) = key.as_str() else {
                self.refuse(place, None, None, "has a key that is not a string");
                return None;
            };
            names.push(key);
        }
        let kind = field_kind(keys);
        if kind != FieldKind::Names && is_os_keyed(names.iter().copied()) {
            if kind == FieldKind::Fields {
                self.refuse(
                    place,
                    None,
                    None,
                    "is an object, so it cannot be given per OS: a per-OS value only replaces \
                     a string or a list",
                );
                return None;
            }
            return self.per_os(mapping, &names, path, keys, place);
        }
        let mut object = serde_json::Map::new();
        for (key, value) in mapping {
            let Some(key) = key.as_str() else { continue };
            path.push(key.to_owned());
            if let Some(value) = self.walk(value, path, None) {
                object.insert(key.to_owned(), value);
            }
            path.pop();
        }
        Some(JsonValue::Object(object))
    }

    /// A per-OS value: the most specific key's value, resolved in its turn.
    fn per_os(
        &mut self,
        mapping: &serde_yaml::Mapping,
        names: &[&str],
        path: &mut Vec<String>,
        keys: &[&str],
        place: String,
    ) -> Option<JsonValue> {
        let Some(platform) = self.platform else {
            self.refuse(
                place,
                None,
                None,
                "is a per-OS value, which needs the recipe to declare its platforms",
            );
            return None;
        };
        let Some(key) = os_key_for(platform.os, names) else {
            if is_command_field(keys) {
                let os = platform.os;
                self.refuse(
                    place,
                    None,
                    None,
                    format!(
                        "resolves no command for {os}: give it a `{os}` or `default` value, or \
                         `{os}: []` to skip the phase there"
                    ),
                );
            }
            return None;
        };
        let selected = &mapping[key];
        if !matches!(selected, YamlValue::String(_) | YamlValue::Sequence(_)) {
            self.refuse(
                format!("{place}.{key}"),
                None,
                None,
                "must be a string or a list: a per-OS value only replaces a string or a list",
            );
            return None;
        }
        self.walk(selected, path, None)
    }

    /// Resolves the build-time tokens of one string. `runtime` is `Some` in a field the
    /// runtime resolves again.
    fn string(&mut self, input: &str, place: &str, runtime: Option<()>) -> Option<String> {
        let pieces = match token::parse(input) {
            Ok(pieces) => pieces,
            Err(err) => {
                self.refuse(place.to_owned(), Some(input), None, err.to_string());
                return None;
            }
        };
        let mut out = String::with_capacity(input.len());
        let mut ok = true;
        for piece in pieces {
            match piece {
                Piece::Text { raw, text } => {
                    out.push_str(if runtime.is_some() { raw } else { text });
                }
                Piece::Token(found) if self.build_vars.contains(found.name) => {
                    let value = self
                        .platform
                        .and_then(|platform| platform.lookup(found.name))
                        .or(found.default);
                    match value {
                        Some(value) if runtime.is_some() => out.push_str(&token::escape(value)),
                        Some(value) => out.push_str(value),
                        None => {
                            let reason = if self.platform.is_some() {
                                "is a build var this platform does not set".to_owned()
                            } else {
                                "is a build var, which needs the recipe to declare its platforms"
                                    .to_owned()
                            };
                            self.refuse(place.to_owned(), Some(input), Some(found.raw), reason);
                            ok = false;
                        }
                    }
                }
                Piece::Token(found) if runtime.is_some() => out.push_str(found.raw),
                Piece::Token(found) => {
                    let reason = if self.runtime_names.contains(found.name) {
                        "is a run-time token; it may appear only in a command, a probe command \
                         or start.service"
                    } else {
                        "names no build var"
                    };
                    self.refuse(place.to_owned(), Some(input), Some(found.raw), reason);
                    ok = false;
                }
            }
        }
        ok.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> YamlValue {
        serde_yaml::from_str(text).expect("yaml")
    }

    fn build(config: &str, os: &str, vars: &[(&str, &str)]) -> Result<JsonValue, Vec<String>> {
        let vars: BTreeMap<String, String> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let label = format!("{os}/amd64");
        let platform = BuildPlatform {
            os,
            arch: "amd64",
            label: &label,
            vars: &vars,
        };
        let names = build_var_names([&vars]);
        resolve_config(&yaml(config), Some(platform), &names)
            .map_err(|refusals| refusals.iter().map(ToString::to_string).collect())
    }

    const RUNNER: &str = r#"
params:
  properties:
    url: {type: string, description: {unix: "POSIX", windows: "Windows"}}
    token: {type: string, sensitive: true}
    linux: {type: string}
install:
  command:
    unix: ["./install.sh", "--arch=${arch}", "--os=${os}"]
    windows: ["install.ps1", "-Arch:${arch}"]
start:
  service: runner-${instance}
  command:
    unix: ["./start.sh", "--url=${url}", "--token-file=${token_file}", "$${literal}", "--v=${v}"]
    windows: ["start.ps1", "-Url:${url}"]
uninstall:
  command: {unix: ["./uninstall.sh"], windows: []}
"#;

    #[test]
    fn per_os_values_resolve_to_the_most_specific_key() {
        let linux = build(RUNNER, "linux", &[("v", "1")]).expect("linux");
        assert_eq!(
            linux["install"]["command"],
            serde_json::json!(["./install.sh", "--arch=amd64", "--os=linux"])
        );
        assert_eq!(linux["params"]["properties"]["url"]["description"], "POSIX");
        // A param named after an OS is a param, not a per-OS value.
        assert_eq!(linux["params"]["properties"]["linux"]["type"], "string");
        let windows = build(RUNNER, "windows", &[("v", "1")]).expect("windows");
        assert_eq!(
            windows["install"]["command"],
            serde_json::json!(["install.ps1", "-Arch:amd64"])
        );
        assert_eq!(
            windows["params"]["properties"]["url"]["description"],
            "Windows"
        );
    }

    #[test]
    fn run_time_tokens_and_escapes_pass_through_build_untouched() {
        let linux = build(RUNNER, "linux", &[("v", "1")]).expect("linux");
        assert_eq!(
            linux["start"]["command"],
            serde_json::json!([
                "./start.sh",
                "--url=${url}",
                "--token-file=${token_file}",
                "$${literal}",
                "--v=1"
            ])
        );
        assert_eq!(linux["start"]["service"], "runner-${instance}");
    }

    #[test]
    fn a_build_value_in_a_run_time_field_is_escaped_for_the_second_pass() {
        let built = build(
            "start: {command: ['./run', '--v=${v}']}\nparams: {properties: {}}",
            "linux",
            &[("v", "a$b${c}")],
        )
        .expect("built");
        assert_eq!(built["start"]["command"][1], "--v=a$$b$${c}");
        let values: BTreeMap<String, String> = BTreeMap::new();
        let element = built["start"]["command"][1].as_str().expect("string");
        assert_eq!(
            token::substitute(element, |name| values.get(name).map(String::as_str))
                .expect("syntax")
                .as_deref(),
            Some("--v=a$b${c}")
        );
    }

    #[test]
    fn outside_a_run_time_field_escapes_resolve_and_run_time_tokens_are_refused() {
        let built = build(
            "params: {properties: {url: {type: string, description: 'costs $$5, see $${url}'}}}",
            "linux",
            &[],
        )
        .expect("built");
        assert_eq!(
            built["params"]["properties"]["url"]["description"],
            "costs $5, see ${url}"
        );
        let refused = build(
            "params: {properties: {url: {type: string, description: 'see ${url}'}}}",
            "linux",
            &[],
        )
        .expect_err("run-time token in a description");
        assert_eq!(refused.len(), 1);
        assert!(
            refused[0].starts_with("linux/amd64: params.properties.url.description \"see ${url}\": ${url} is a run-time token"),
            "{refused:?}"
        );
        let refused = build("default_version: '${nope}'", "linux", &[]).expect_err("unknown");
        assert!(
            refused[0].contains("${nope} names no build var"),
            "{refused:?}"
        );
    }

    #[test]
    fn an_empty_list_skips_a_phase_on_that_platform() {
        let windows = build(RUNNER, "windows", &[("v", "1")]).expect("windows");
        assert_eq!(windows["uninstall"], serde_json::json!({}));
        let linux = build(RUNNER, "linux", &[("v", "1")]).expect("linux");
        assert_eq!(
            linux["uninstall"]["command"],
            serde_json::json!(["./uninstall.sh"])
        );
    }

    #[test]
    fn a_platform_that_resolves_no_command_is_refused() {
        let refused = build(
            "install: {command: {unix: ['./install.sh']}}",
            "windows",
            &[],
        )
        .expect_err("no windows command");
        assert_eq!(refused.len(), 1);
        assert!(
            refused[0].contains("windows/amd64: install.command: resolves no command for windows"),
            "{refused:?}"
        );
        // A non-command field without the key is just absent.
        let built = build(
            "params: {properties: {cmd: {type: string, contentMediaType: {unix: text/x-sh}}}}",
            "windows",
            &[],
        )
        .expect("absent");
        assert!(
            built["params"]["properties"]["cmd"]
                .get("contentMediaType")
                .is_none()
        );
    }

    #[test]
    fn per_os_misuse_is_refused() {
        let refused = build("start: {unix: {command: ['./a']}}", "linux", &[]).expect_err("object");
        assert!(refused[0].contains("start: is an object"), "{refused:?}");
        let refused = build("stop: {timeout: {unix: 5}}", "linux", &[]).expect_err("number");
        assert!(
            refused[0].contains("stop.timeout.unix: must be a string or a list"),
            "{refused:?}"
        );
        let refused =
            build("install: {command: ['./a', {unix: '-x'}]}", "linux", &[]).expect_err("element");
        assert!(
            refused[0].contains("install.command[1]: is a per-OS value inside a list"),
            "{refused:?}"
        );
    }

    #[test]
    fn a_build_var_a_platform_does_not_set_is_refused_unless_defaulted() {
        let vars: BTreeMap<String, String> = BTreeMap::new();
        let other = BTreeMap::from([("only_linux".to_owned(), "1".to_owned())]);
        let names = build_var_names([&vars, &other]);
        let platform = BuildPlatform {
            os: "windows",
            arch: "amd64",
            label: "windows/amd64",
            vars: &vars,
        };
        let refused = resolve_config(
            &yaml("install: {command: ['a.ps1', '-X:${only_linux}']}"),
            Some(platform),
            &names,
        )
        .expect_err("unset on windows");
        assert!(
            refused[0]
                .to_string()
                .contains("is a build var this platform does not set")
        );
        let built = resolve_config(
            &yaml("install: {command: ['a.ps1', '-X:${only_linux:-none}']}"),
            Some(platform),
            &names,
        )
        .expect("defaulted");
        assert_eq!(built["install"]["command"][1], "-X:none");
    }

    #[test]
    fn a_platformless_recipe_takes_no_per_os_values_or_build_tokens() {
        let names = build_var_names(std::iter::empty());
        let refused = resolve_config(&yaml("install: {command: {unix: ['./a']}}"), None, &names)
            .expect_err("per-os");
        assert!(
            refused[0]
                .to_string()
                .contains("needs the recipe to declare its platforms")
        );
        let refused = resolve_config(&yaml("install: {command: ['./a', '${os}']}"), None, &names)
            .expect_err("os");
        assert!(
            refused[0]
                .to_string()
                .contains("needs the recipe to declare its platforms")
        );
    }

    #[test]
    fn file_strings_take_build_tokens_only() {
        let names = build_var_names(std::iter::empty());
        let vars = BTreeMap::new();
        let platform = BuildPlatform {
            os: "linux",
            arch: "arm64",
            label: "linux/arm64",
            vars: &vars,
        };
        assert_eq!(
            resolve_build_string("bin/${os}-${arch}/run", "files[0]", Some(platform), &names)
                .expect("path"),
            "bin/linux-arm64/run"
        );
        // v1's `{os}` is plain text in v2.
        assert_eq!(
            resolve_build_string("{os}", "files[0]", Some(platform), &names).expect("text"),
            "{os}"
        );
        assert!(resolve_build_string("${url}", "files[0]", Some(platform), &names).is_err());
    }
}
