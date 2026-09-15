use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::app::{ParamLifetime, ParamProperty, ParamSchema};
use crate::error::{CliError, Result};

fn is_implicitly_sensitive(property: &ParamProperty) -> bool {
    property
        .x_source
        .as_ref()
        .is_some_and(|source| source.kind == "tls.key")
}

fn is_file_backed(property: &ParamProperty) -> bool {
    property.sensitive
        || property.content_media_type.is_some()
        || property
            .x_source
            .as_ref()
            .is_some_and(|source| matches!(source.kind.as_str(), "tls.key" | "peers.all"))
}

fn is_sensitive(property: &ParamProperty) -> bool {
    property.sensitive || is_implicitly_sensitive(property)
}

/// Resolves a param's value lifetime: the schema declaration wins; otherwise
/// operator secrets (`sec:` references) default to startup-only availability and
/// everything else (sourced TLS material, `@file` content, plain values) to the
/// whole app run.
fn param_lifetime(property: Option<&ParamProperty>, value: &ParsedParamValue) -> ParamLifetime {
    property
        .and_then(|property| property.lifetime)
        .unwrap_or(match value {
            ParsedParamValue::SecretRef(_) => ParamLifetime::Startup,
            _ => ParamLifetime::Runtime,
        })
}

/// Serializable so a runtime can persist the params an app started with and rebuild
/// its environment later — a service manager restarting independently has no other
/// source for them. See [`crate::lifecycle::write_app_env`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ParsedParam {
    pub name: String,
    pub value: ParsedParamValue,
    pub file_backed: bool,
    pub lifetime: ParamLifetime,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ParsedParamValue {
    String(String),
    Number(String),
    Boolean(bool),
    File { path: PathBuf, bytes: Vec<u8> },
    SecretRef(String),
}

/// Assignment params for lifecycle phases in host runtimes.
///
/// Schema-`sensitive` params hold `sec:` tokens by configure-time tokenization, so
/// they travel as secret references with file-backed delivery; params whose schema
/// marks them file-backed (`contentMediaType`, `x-source`, etc.) are delivered via
/// `<VAR>_FILE` env vars.
#[must_use]
pub fn parsed_assignment_params(
    params: &BTreeMap<String, String>,
    schema: Option<&ParamSchema>,
) -> BTreeMap<String, ParsedParam> {
    params
        .iter()
        .map(|(name, value)| {
            let property = schema.and_then(|schema| schema.properties.get(name));
            let tls_key_source = property
                .and_then(|property| property.x_source.as_ref())
                .is_some_and(|source| source.kind == "tls.key");
            let sensitive = property.is_some_and(|property| property.sensitive) || tls_key_source;
            let file_backed = property.is_some_and(is_file_backed) || sensitive;
            let value = if sensitive && !tls_key_source {
                ParsedParamValue::SecretRef(value.clone())
            } else {
                ParsedParamValue::String(value.clone())
            };
            let lifetime = param_lifetime(property, &value);
            (
                name.clone(),
                ParsedParam {
                    name: name.clone(),
                    value,
                    file_backed,
                    lifetime,
                },
            )
        })
        .collect()
}

/// Parses app parameter flags against an app config `params` schema.
///
/// # Errors
///
/// Returns a usage error for unknown, duplicate, missing, mistyped, or disallowed sensitive
/// parameters. Returns an operational error when an `@file` value cannot be read.
pub fn parse_app_params(
    schema: Option<&ParamSchema>,
    args: &[String],
    base_dir: &Path,
) -> Result<BTreeMap<String, ParsedParam>> {
    let Some(schema) = schema else {
        if args.is_empty() {
            return Ok(BTreeMap::new());
        }
        return Err(CliError::Usage(
            "app does not accept parameters; valid params: none".to_owned(),
        ));
    };
    let mut parsed = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let raw = &args[index];
        let flag = raw
            .strip_prefix("--")
            .ok_or_else(|| CliError::Usage(format!("app param {raw:?} must be a --flag")))?;
        let (flag, inline_value) = flag
            .split_once('=')
            .map_or((flag, None), |(name, value)| (name, Some(value.to_owned())));
        if flag.is_empty() {
            return Err(CliError::Usage("app param flag cannot be empty".to_owned()));
        }
        let name = flag.replace('-', "_");
        let property = schema.properties.get(&name).ok_or_else(|| {
            CliError::Usage(format!(
                "unknown app param --{flag}; valid params: {}",
                valid_params(schema)
            ))
        })?;
        if parsed.contains_key(&name) {
            return Err(CliError::Usage(format!("duplicate app param --{flag}")));
        }
        let (value, consumed) = match inline_value {
            Some(value) => (value, 1),
            None if property.kind == "boolean" => {
                if args
                    .get(index + 1)
                    .is_some_and(|next| !next.starts_with("--"))
                {
                    (args[index + 1].clone(), 2)
                } else {
                    ("true".to_owned(), 1)
                }
            }
            None => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliError::Usage(format!(
                        "app param --{flag} requires a value"
                    )));
                };
                if value.starts_with("--") {
                    return Err(CliError::Usage(format!(
                        "app param --{flag} requires a value"
                    )));
                }
                (value.clone(), 2)
            }
        };
        let parsed_value = parse_value(&name, property, &value, base_dir)?;
        let lifetime = param_lifetime(Some(property), &parsed_value);
        parsed.insert(
            name.clone(),
            ParsedParam {
                name,
                value: parsed_value,
                file_backed: is_file_backed(property),
                lifetime,
            },
        );
        index += consumed;
    }

    let present = parsed.keys().cloned().collect::<BTreeSet<_>>();
    for required in &schema.required {
        if !present.contains(required) {
            return Err(CliError::Usage(format!(
                "missing required app param --{}",
                required.replace('_', "-")
            )));
        }
    }
    Ok(parsed)
}

#[must_use]
pub fn durable_param_values(params: &BTreeMap<String, ParsedParam>) -> BTreeMap<String, String> {
    params
        .iter()
        .map(|(name, param)| (name.clone(), durable_value(&param.value)))
        .collect()
}

fn durable_value(value: &ParsedParamValue) -> String {
    match value {
        ParsedParamValue::String(value)
        | ParsedParamValue::Number(value)
        | ParsedParamValue::SecretRef(value) => value.clone(),
        ParsedParamValue::Boolean(value) => value.to_string(),
        ParsedParamValue::File { path, .. } => format!("@{}", path.display()),
    }
}

fn parse_value(
    name: &str,
    property: &ParamProperty,
    value: &str,
    base_dir: &Path,
) -> Result<ParsedParamValue> {
    if let Some(path) = value.strip_prefix('@') {
        if path.is_empty() {
            return Err(CliError::Usage(format!(
                "app param --{} has an empty @file path",
                name.replace('_', "-")
            )));
        }
        let path = resolve_file_path(base_dir, path);
        let bytes = std::fs::read(&path)
            .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
        return Ok(ParsedParamValue::File { path, bytes });
    }
    if is_sensitive(property) {
        if is_secret_ref(value) {
            return Ok(ParsedParamValue::SecretRef(value.to_owned()));
        }
        return Err(CliError::Usage(format!(
            "sensitive app param --{} must use @file or a secret URI",
            name.replace('_', "-")
        )));
    }

    validate_type(name, property, value)?;
    validate_choices(name, property, value)?;
    match property.kind.as_str() {
        "boolean" => Ok(ParsedParamValue::Boolean(
            parse_bool(value).expect("validated bool"),
        )),
        "number" | "integer" => Ok(ParsedParamValue::Number(value.to_owned())),
        _ => Ok(ParsedParamValue::String(value.to_owned())),
    }
}

fn validate_type(name: &str, property: &ParamProperty, value: &str) -> Result<()> {
    let valid = match property.kind.as_str() {
        "" | "string" => true,
        "boolean" => parse_bool(value).is_some(),
        "integer" => value.parse::<i64>().is_ok(),
        "number" => value.parse::<f64>().is_ok_and(f64::is_finite),
        other => {
            return Err(CliError::Usage(format!(
                "app param --{} has unsupported type {other:?}",
                name.replace('_', "-")
            )));
        }
    };
    if valid {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "app param --{} must be {}",
            name.replace('_', "-"),
            property.kind
        )))
    }
}

fn validate_choices(name: &str, property: &ParamProperty, value: &str) -> Result<()> {
    if property.choices.is_empty() {
        return Ok(());
    }
    if property
        .choices
        .iter()
        .any(|choice| choice_matches(choice, property, value))
    {
        return Ok(());
    }
    Err(CliError::Usage(format!(
        "app param --{} must be one of {}",
        name.replace('_', "-"),
        property
            .choices
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn choice_matches(choice: &Value, property: &ParamProperty, value: &str) -> bool {
    match property.kind.as_str() {
        "boolean" => choice
            .as_bool()
            .is_some_and(|choice| parse_bool(value).is_some_and(|value| value == choice)),
        "integer" => choice
            .as_i64()
            .is_some_and(|choice| value.parse::<i64>().is_ok_and(|value| value == choice)),
        "number" => choice.as_f64().is_some_and(|choice| {
            value
                .parse::<f64>()
                .is_ok_and(|value| (value - choice).abs() < f64::EPSILON)
        }),
        _ => choice.as_str() == Some(value),
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn resolve_file_path(base_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

/// Returns `true` when `value` is a secret reference that must be delivered through
/// a side channel (temp file) rather than an environment variable. Recognises the
/// `sec:` token grammar (spec 052) and previous vault/bitwarden/1password forms.
#[must_use]
pub fn is_secret_ref(value: &str) -> bool {
    value.starts_with("vault://")
        || value.starts_with("bw://")
        || value.starts_with("op://")
        || value.starts_with("sec:")
}

fn valid_params(schema: &ParamSchema) -> String {
    if schema.properties.is_empty() {
        return "none".to_owned();
    }
    schema
        .properties
        .keys()
        .map(|name| format!("--{}", name.replace('_', "-")))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_boolean_and_file_params() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("token.txt"), b"secret").expect("token");
        let schema = schema(
            r#"{
            "required": ["github_url", "token"],
            "properties": {
                "github_url": {"type": "string"},
                "privileged": {"type": "boolean"},
                "token": {"type": "string", "contentMediaType": "text/plain"}
            }
        }"#,
        );
        let args = vec![
            "--github-url".to_owned(),
            "https://github.com/acme".to_owned(),
            "--privileged".to_owned(),
            "--token".to_owned(),
            "@token.txt".to_owned(),
        ];

        let parsed = parse_app_params(Some(&schema), &args, dir.path()).expect("params");
        assert_eq!(
            parsed["github_url"].value,
            ParsedParamValue::String("https://github.com/acme".to_owned())
        );
        assert_eq!(parsed["privileged"].value, ParsedParamValue::Boolean(true));
        assert!(parsed["token"].file_backed);
        assert_eq!(
            parsed["token"].value,
            ParsedParamValue::File {
                path: dir.path().join("token.txt"),
                bytes: b"secret".to_vec(),
            }
        );
    }

    #[test]
    fn validates_unknown_missing_duplicate_and_type_errors() {
        let schema = schema(
            r#"{
            "required": ["count"],
            "properties": {
                "count": {"type": "integer"},
                "mode": {"type": "string", "enum": ["fast", "safe"]}
            }
        }"#,
        );
        assert!(parse_app_params(Some(&schema), &["--bogus".to_owned()], Path::new(".")).is_err());
        assert!(
            parse_app_params(
                Some(&schema),
                &["--mode".to_owned(), "fast".to_owned()],
                Path::new(".")
            )
            .is_err()
        );
        assert!(
            parse_app_params(
                Some(&schema),
                &["--count".to_owned(), "NaN".to_owned()],
                Path::new(".")
            )
            .is_err()
        );
        assert!(
            parse_app_params(
                Some(&schema),
                &[
                    "--count".to_owned(),
                    "1".to_owned(),
                    "--count".to_owned(),
                    "2".to_owned()
                ],
                Path::new(".")
            )
            .is_err()
        );
        assert!(
            parse_app_params(
                Some(&schema),
                &[
                    "--count".to_owned(),
                    "1".to_owned(),
                    "--mode".to_owned(),
                    "slow".to_owned()
                ],
                Path::new(".")
            )
            .is_err()
        );
    }

    #[test]
    fn sensitive_params_reject_literals_but_accept_secret_refs_and_files() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("token.txt"), b"secret").expect("token");
        let schema = schema(
            r#"{
            "required": ["github_token"],
            "properties": {
                "github_token": {"type": "string", "sensitive": true}
            }
        }"#,
        );
        assert!(
            parse_app_params(
                Some(&schema),
                &["--github-token".to_owned(), "hunter2".to_owned()],
                dir.path(),
            )
            .is_err()
        );
        let secret_ref = parse_app_params(
            Some(&schema),
            &["--github-token".to_owned(), "vault://kv/token".to_owned()],
            dir.path(),
        )
        .expect("secret ref");
        assert_eq!(
            secret_ref["github_token"].value,
            ParsedParamValue::SecretRef("vault://kv/token".to_owned())
        );
        let file = parse_app_params(
            Some(&schema),
            &["--github-token".to_owned(), "@token.txt".to_owned()],
            dir.path(),
        )
        .expect("file");
        assert!(matches!(
            file["github_token"].value,
            ParsedParamValue::File { .. }
        ));
        assert_eq!(
            durable_param_values(&file)["github_token"],
            format!("@{}", dir.path().join("token.txt").display())
        );
    }

    #[test]
    fn schema_without_params_rejects_any_arg() {
        assert!(
            parse_app_params(None, &[], Path::new("."))
                .expect("empty")
                .is_empty()
        );
        assert!(parse_app_params(None, &["--url".to_owned()], Path::new(".")).is_err());
    }

    #[test]
    fn x_source_peers_all_and_tls_key_are_file_backed() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("peers.txt"), b"10.0.0.1\n").expect("peers");
        std::fs::write(dir.path().join("key.pem"), b"PRIVATE KEY").expect("key");
        let schema = schema(
            r#"{
            "properties": {
                "peer_set": {"type": "string", "x-source": {"kind": "peers.all"}},
                "tls_key": {"type": "string", "x-source": {"kind": "tls.key", "params": {"pair": "tls_cert"}}},
                "ca_bundle": {"type": "string", "contentMediaType": "application/x-pem-file", "x-source": {"kind": "ca.bundle"}}
            }
        }"#,
        );
        let parsed = parse_app_params(
            Some(&schema),
            &[
                "--peer-set".to_owned(),
                "@peers.txt".to_owned(),
                "--tls-key".to_owned(),
                "@key.pem".to_owned(),
                "--ca-bundle".to_owned(),
                "PEM material".to_owned(),
            ],
            dir.path(),
        )
        .expect("params");
        assert!(parsed["peer_set"].file_backed);
        assert!(parsed["tls_key"].file_backed);
        assert!(parsed["ca_bundle"].file_backed);
    }

    #[test]
    fn x_source_tls_key_rejects_literals_but_accepts_files() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("key.pem"), b"PRIVATE KEY").expect("key");
        let schema = schema(
            r#"{
            "properties": {
                "tls_key": {"type": "string", "x-source": {"kind": "tls.key", "params": {"pair": "tls_cert"}}}
            }
        }"#,
        );
        assert!(
            parse_app_params(
                Some(&schema),
                &["--tls-key".to_owned(), "secret-key".to_owned()],
                dir.path(),
            )
            .is_err()
        );
        let parsed = parse_app_params(
            Some(&schema),
            &["--tls-key".to_owned(), "@key.pem".to_owned()],
            dir.path(),
        )
        .expect("file");
        assert!(parsed["tls_key"].file_backed);
        assert!(matches!(
            parsed["tls_key"].value,
            ParsedParamValue::File { .. }
        ));
    }

    #[test]
    fn lifetime_defaults_to_startup_for_secrets_and_runtime_otherwise() {
        let schema = schema(
            r#"{
            "properties": {
                "token": {"type": "string", "sensitive": true},
                "lazy_token": {"type": "string", "sensitive": true, "lifetime": "runtime"},
                "tls_key": {"type": "string", "x-source": {"kind": "tls.key", "params": {"pair": "tls_cert"}}},
                "greeting": {"type": "string"},
                "eager_note": {"type": "string", "contentMediaType": "text/plain", "lifetime": "startup"}
            }
        }"#,
        );
        let params = BTreeMap::from([
            ("token".to_owned(), "sec:pool:p_1:1:s_1".to_owned()),
            ("lazy_token".to_owned(), "sec:pool:p_1:1:s_2".to_owned()),
            ("tls_key".to_owned(), "PRIVATE KEY".to_owned()),
            ("greeting".to_owned(), "hello".to_owned()),
            ("eager_note".to_owned(), "note".to_owned()),
        ]);
        let parsed = parsed_assignment_params(&params, Some(&schema));

        // Operator secrets are startup-only unless the schema opts them out.
        assert_eq!(parsed["token"].lifetime, ParamLifetime::Startup);
        assert_eq!(parsed["lazy_token"].lifetime, ParamLifetime::Runtime);
        // Sourced TLS material is read lazily by host runtimes: runtime by default,
        // even though it is implicitly sensitive.
        assert_eq!(parsed["tls_key"].lifetime, ParamLifetime::Runtime);
        assert_eq!(parsed["greeting"].lifetime, ParamLifetime::Runtime);
        // And the schema can shorten a non-secret file param's availability.
        assert_eq!(parsed["eager_note"].lifetime, ParamLifetime::Startup);
    }

    fn schema(body: &str) -> ParamSchema {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            params: ParamSchema,
        }
        serde_json::from_str::<Wrapper>(&format!(r#"{{"params":{body}}}"#))
            .expect("schema")
            .params
    }
}
