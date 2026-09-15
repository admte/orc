use serde::Serialize;

use crate::error::{CliError, Result};
use crate::info::{InfoDocument, ParamInfo};
use crate::local_artifact_store::CachedRefSummary;
use crate::state::InstallRecord;
use crate::versions::VersionRow;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListRow {
    pub name: String,
    #[serde(rename = "default")]
    pub default_version: String,
    pub description: String,
    pub reference: String,
}

pub fn print_list(rows: &[ListRow], format: OutputFormat, quiet: bool) -> Result<()> {
    if quiet {
        for row in rows {
            println!("{}", row.name);
        }
        return Ok(());
    }
    match format {
        OutputFormat::Json => print_json(rows),
        OutputFormat::Text => {
            println!("{:<24} {:<10} DESCRIPTION", "NAME", "DEFAULT");
            for row in rows {
                println!(
                    "{:<24} {:<10} {}",
                    row.name, row.default_version, row.description
                );
            }
            Ok(())
        }
    }
}

pub fn print_cached_refs(
    rows: &[CachedRefSummary],
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    if quiet {
        for row in rows {
            println!("{}", row.reference);
        }
        return Ok(());
    }
    match format {
        OutputFormat::Json => print_json(rows),
        OutputFormat::Text => {
            println!("{:<42} {:<20} DESCRIPTION", "REFERENCE", "PLATFORMS");
            for row in rows {
                let platforms = if row.platforms.is_empty() {
                    "-".to_owned()
                } else {
                    row.platforms.join(", ")
                };
                let description = row.error.as_ref().map_or_else(
                    || row.description.clone(),
                    |error| format!("ERROR: {error}"),
                );
                println!("{:<42} {:<20} {}", row.reference, platforms, description);
            }
            Ok(())
        }
    }
}

pub fn print_versions(rows: &[VersionRow], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => print_json(rows),
        OutputFormat::Text => {
            println!("{:<16} {:<8} PLATFORMS", "VERSION", "DEFAULT");
            for row in rows {
                let default = if row.default { "*" } else { "" };
                println!(
                    "{:<16} {:<8} {}",
                    row.version,
                    default,
                    row.platforms.join(", ")
                );
            }
            Ok(())
        }
    }
}

/// Prints per-app `--help` for `start`/`install`: usage plus the app's parameter flags
/// derived from its config schema.
pub fn print_app_help(command: &str, app: &str, params: &[ParamInfo]) {
    println!("Usage: orc {command} {app} [PARAMS]...");
    println!();
    if params.is_empty() {
        println!("This app takes no parameters.");
        return;
    }
    println!("Parameters:");
    for param in params {
        let required = if param.required {
            "required"
        } else {
            "optional"
        };
        let sensitive = if param.sensitive { "*" } else { "" };
        println!(
            "  {:<18} {:<8} {}{}  {}",
            param.flag, param.kind, required, sensitive, param.description
        );
    }
    println!();
    println!("Pass values as flags, e.g. `orc {command} {app} --name value`.");
    println!("(*) sensitive: pass via @file or a secret URI.");
}

pub fn print_info(info: &InfoDocument, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => print_json(info),
        OutputFormat::Text => {
            println!("{} ({})", info.reference, info.digest);
            if !info.description.is_empty() {
                println!("{}", info.description);
            }
            println!("Platforms: {}", info.platforms.join(", "));
            println!("Mode:      {}", info.mode);
            println!("Phases:    {}", info.phases.join(", "));
            if !info.params.is_empty() {
                println!("Params:");
                for param in &info.params {
                    let required = if param.required {
                        "required"
                    } else {
                        "optional"
                    };
                    let sensitive = if param.sensitive { "*" } else { "" };
                    println!(
                        "  {:<18} {:<8} {}{}  {}",
                        param.flag, param.kind, required, sensitive, param.description
                    );
                }
            }
            Ok(())
        }
    }
}

pub fn print_status(rows: &[InstallRecord], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => print_json(rows),
        OutputFormat::Text => {
            println!(
                "{:<24} {:<12} {:<8} {:<10} PID/SERVICE",
                "APP", "VERSION", "MODE", "STATE"
            );
            for row in rows {
                println!(
                    "{:<24} {:<12} {:<8} {:<10} {}",
                    row.app,
                    row.version,
                    row.mode,
                    row.state,
                    row.pid_service.as_deref().unwrap_or("-")
                );
            }
            Ok(())
        }
    }
}

fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|err| CliError::Operational(format!("encode json output: {err}")))?;
    println!("{body}");
    Ok(())
}
