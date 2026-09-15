use std::fmt::Write as _;

use serde::Serialize;

use crate::app::{AppConfig, CommandValue};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InfoDocument {
    pub reference: String,
    pub digest: String,
    pub description: String,
    pub platforms: Vec<String>,
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
        let owner = if start.command.is_some() {
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
    let mut phases = Vec::new();
    if let Some(phase) = &config.install {
        phases.push(command_phase(
            "install",
            phase.timeout.as_deref(),
            phase.command.as_ref(),
        ));
    }
    if let Some(start) = &config.start {
        let mut label = command_phase("start", None, start.command.as_ref());
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
        append_command(&mut label, stop.command.as_ref());
        phases.push(label);
    }
    if let Some(phase) = &config.stopped {
        phases.push(command_phase(
            "stopped",
            phase.timeout.as_deref(),
            phase.command.as_ref(),
        ));
    }
    if let Some(phase) = &config.uninstall {
        phases.push(command_phase(
            "uninstall",
            phase.timeout.as_deref(),
            phase.command.as_ref(),
        ));
    }
    phases
}

fn command_phase(name: &str, timeout: Option<&str>, command: Option<&CommandValue>) -> String {
    let mut label = name.to_owned();
    if let Some(timeout) = timeout {
        let _ = write!(label, " ({timeout})");
    }
    append_command(&mut label, command);
    label
}

/// Notes how a phase's command is written, without quoting the command itself.
fn append_command(label: &mut String, command: Option<&CommandValue>) {
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
}
