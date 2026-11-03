use std::fmt::Write as _;

use serde::Serialize;

use crate::app::{AppConfig, AppFormat, CommandValue};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InfoDocument {
    pub reference: String,
    pub digest: String,
    pub description: String,
    pub platforms: Vec<String>,
    /// The app format, `v1` or `v2` (spec 214).
    pub format: String,
    /// Whose config the mode and phases describe: a platform label, or `any` for a
    /// single-manifest package. A v2 app's commands are resolved per platform, so they
    /// read as that platform's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_platform: Option<String>,
    pub mode: String,
    pub phases: Vec<String>,
    pub params: Vec<ParamInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParamInfo {
    pub flag: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub required: bool,
    pub sensitive: bool,
    pub description: String,
}

pub fn build_info_document(
    reference: String,
    digest: String,
    description: String,
    platforms: Vec<String>,
    config: Option<&AppConfig>,
) -> InfoDocument {
    let (mode, phases, params) = config.map_or_else(
        || ("process".to_owned(), Vec::new(), Vec::new()),
        |config| (mode(config), phases(config), app_params(config)),
    );
    InfoDocument {
        reference,
        digest,
        description,
        platforms,
        format: config
            .map_or(AppFormat::V1, |config| config.format)
            .label()
            .to_owned(),
        config_platform: None,
        mode,
        phases,
        params,
    }
}

/// Extracts the CLI parameter descriptors from an app config's `params` JSON schema.
pub fn app_params(config: &AppConfig) -> Vec<ParamInfo> {
    let Some(schema) = &config.params else {
        return Vec::new();
    };
    schema
        .properties
        .iter()
        .map(|(name, property)| ParamInfo {
            flag: param_flag(name),
            name: name.clone(),
            kind: property.kind.clone(),
            required: schema.required.iter().any(|required| required == name),
            sensitive: property.sensitive,
            description: property.description.clone(),
        })
        .collect()
}

/// How the app runs, in the three shapes `start` can take (spec 142 run modes).
///
/// A service app is named by the platform name the runtime derives — what an operator
/// types at their own service manager — and by who owns that definition: the runtime
/// writes and removes one it generated, while a bring-your-own definition is the app's
/// install phase's to register and its uninstall phase's to remove.
fn mode(config: &AppConfig) -> String {
    let Some(start) = &config.start else {
        return "none".to_owned();
    };
    if let Some(service) = &start.service {
        let has_command = match (config.format, &start.command) {
            (AppFormat::V2, Some(CommandValue::Argv(argv))) => !argv.is_empty(),
            (_, command) => command.is_some(),
        };
        let owner = if has_command {
            "runtime-managed"
        } else {
            "bring-your-own"
        };
        return format!(
            "service {} ({owner})",
            crate::service::platform_name(service)
        );
    }
    if start.gui {
        return "process (gui)".to_owned();
    }
    "process".to_owned()
}

fn phases(config: &AppConfig) -> Vec<String> {
    let format = config.format;
    let mut phases = Vec::new();
    if let Some(phase) = &config.install {
        phases.push(command_phase(
            format,
            "install",
            phase.timeout.as_deref(),
            phase.command.as_ref(),
        ));
    }
    if let Some(start) = &config.start {
        let mut label = command_phase(format, "start", None, start.command.as_ref());
        if let Some(restart) = &start.restart {
            let _ = write!(label, " restart={restart}");
        }
        phases.push(label);
    }
    if let Some(stop) = &config.stop {
        // The stop phase reads as the sequence it is: the signal, the window the stop
        // command runs in, and the grace the app gets after it — defaults included,
        // since they are what decides how long a stop of this app takes.
        let mut label = format!(
            "stop ({}, {}, grace {})",
            stop.signal.as_deref().unwrap_or("SIGTERM"),
            stop.timeout.as_deref().unwrap_or("30s"),
            stop.grace.as_deref().unwrap_or("10s")
        );
        append_command(format, &mut label, stop.command.as_ref());
        phases.push(label);
    }
    if let Some(phase) = &config.stopped {
        phases.push(command_phase(
            format,
            "stopped",
            phase.timeout.as_deref(),
            phase.command.as_ref(),
        ));
    }
    if let Some(phase) = &config.uninstall {
        phases.push(command_phase(
            format,
            "uninstall",
            phase.timeout.as_deref(),
            phase.command.as_ref(),
        ));
    }
    phases
}

fn command_phase(
    format: AppFormat,
    name: &str,
    timeout: Option<&str>,
    command: Option<&CommandValue>,
) -> String {
    let mut label = name.to_owned();
    if let Some(timeout) = timeout {
        let _ = write!(label, " ({timeout})");
    }
    append_command(format, &mut label, command);
    label
}

/// Notes how a phase's command is written. A v1 command is not quoted — a string runs a
/// shell and may carry anything. A v2 command is shown as resolved for its platform: it
/// is an argv list whose secrets are only ever `${name_file}` paths, so what runs can be
/// read straight off it.
fn append_command(format: AppFormat, label: &mut String, command: Option<&CommandValue>) {
    if format == AppFormat::V2 {
        match command {
            Some(CommandValue::Argv(argv)) if argv.is_empty() => label.push_str(" [skipped]"),
            Some(CommandValue::Argv(argv)) => {
                let _ = write!(
                    label,
                    " {}",
                    serde_json::to_string(argv).unwrap_or_default()
                );
            }
            Some(CommandValue::String(_)) => label.push_str(" [string: not run by v2]"),
            None => {}
        }
        return;
    }
    match command {
        Some(CommandValue::String(command)) => {
            if !command.is_empty() {
                label.push_str(" [shell]");
            }
        }
        Some(CommandValue::Argv(argv)) => {
            let _ = write!(label, " [argv:{}]", argv.len());
        }
        None => {}
    }
}

fn param_flag(name: &str) -> String {
    format!("--{}", name.replace('_', "-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_document_marks_required_sensitive_params_and_service_mode() {
        let config: AppConfig = serde_json::from_value(serde_json::json!({
            "params": {
                "type": "object",
                "required": ["github_url", "github_token"],
                "properties": {
                    "github_url": {"type": "string", "description": "Repository URL"},
                    "github_token": {"type": "string", "sensitive": true}
                }
            },
            "start": {"service": "github-runner", "restart": "on-failure"},
            "stop": {"command": "./drain.sh", "signal": "SIGINT", "timeout": "30s", "grace": "20s"},
            "stopped": {"command": "./report.sh", "timeout": "60s"}
        }))
        .expect("config");

        let info = build_info_document(
            "ghcr.io/acme/github-runner:default".to_owned(),
            "sha256:abc".to_owned(),
            "runner".to_owned(),
            vec!["linux/amd64".to_owned()],
            Some(&config),
        );

        assert_eq!(
            info.mode,
            format!(
                "service {} (bring-your-own)",
                crate::service::platform_name("github-runner")
            )
        );
        assert_eq!(
            info.phases,
            vec![
                "start restart=on-failure",
                "stop (SIGINT, 30s, grace 20s) [shell]",
                "stopped (60s) [shell]",
            ]
        );
        assert_eq!(info.params[0].flag, "--github-token");
        assert!(info.params[0].required);
        assert!(info.params[0].sensitive);
        assert_eq!(info.params[1].flag, "--github-url");
    }

    /// A bare `stop:` still tells the operator the two things that decide how long a
    /// termination takes, defaults included.
    #[test]
    fn a_bare_stop_phase_lists_the_defaults() {
        let config: AppConfig = serde_json::from_value(serde_json::json!({
            "install": {"command": "./setup.sh", "timeout": "600s"},
            "start": {"command": "./run.sh"},
            "stop": {},
            "uninstall": {"command": "./purge.sh"}
        }))
        .expect("config");
        assert_eq!(
            phases(&config),
            vec![
                "install (600s) [shell]",
                "start [shell]",
                "stop (SIGTERM, 30s, grace 10s)",
                "uninstall [shell]",
            ]
        );
    }

    /// A v2 app reads as its format, with each phase's argv as resolved for the platform
    /// whose config it is — tokens and all, since secrets only ever appear as paths.
    #[test]
    fn a_v2_app_shows_its_format_and_resolved_commands() {
        let config = AppConfig::parse(
            AppFormat::V2,
            br#"{
                "install": {"command": ["./install.sh", "--arch=amd64"], "timeout": "600s"},
                "start": {"service": "runner", "command": ["./run.sh", "--token-file=${token_file}"]},
                "uninstall": {"command": []}
            }"#,
        )
        .expect("config");
        let info = build_info_document(
            "ghcr.io/acme/runner:2".to_owned(),
            "sha256:abc".to_owned(),
            String::new(),
            vec!["linux/amd64".to_owned()],
            Some(&config),
        );
        assert_eq!(info.format, "v2");
        assert_eq!(
            info.mode,
            format!(
                "service {} (runtime-managed)",
                crate::service::platform_name("runner")
            )
        );
        assert_eq!(
            info.phases,
            vec![
                r#"install (600s) ["./install.sh","--arch=amd64"]"#,
                r#"start ["./run.sh","--token-file=${token_file}"]"#,
                "uninstall [skipped]",
            ]
        );
    }
}
