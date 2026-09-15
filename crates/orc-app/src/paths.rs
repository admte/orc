//! Shared per-user directories for the CLI and app runtime.

use std::path::PathBuf;

use crate::{CliError, Result};

/// Resolve configuration storage, honoring `ORC_CONFIG_DIR`.
///
/// # Errors
/// Returns an error if the user directory cannot be located.
pub fn config_dir() -> Result<PathBuf> {
    directory("ORC_CONFIG_DIR", ".config/orc", "config")
}

/// Resolve the shared blob cache, honoring `ORC_CACHE_DIR`.
///
/// # Errors
/// Returns an error if the user directory cannot be located.
pub fn cache_dir() -> Result<PathBuf> {
    directory("ORC_CACHE_DIR", ".cache/orc", "cache")
}

/// Resolve runtime state, honoring `ORC_STATE_DIR`.
///
/// # Errors
/// Returns an error if the user directory cannot be located.
pub fn state_dir() -> Result<PathBuf> {
    directory("ORC_STATE_DIR", ".local/state/orc", "state")
}

fn directory(override_name: &str, unix_suffix: &str, windows_suffix: &str) -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(override_name) {
        return Ok(PathBuf::from(dir));
    }
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|home| PathBuf::from(home).join("AppData/Local"))
            });
        return base
            .map(|base| base.join("orc").join(windows_suffix))
            .ok_or_else(|| {
                CliError::Operational(format!(
                    "LOCALAPPDATA and USERPROFILE are not set; set {override_name}"
                ))
            });
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(unix_suffix))
        .ok_or_else(|| CliError::Operational(format!("HOME is not set; set {override_name}")))
}
