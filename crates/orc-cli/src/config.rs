use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use orc_app::error::{CliError, Result};
use orc_app::reference::BUILTIN_DEFAULT_PREFIX;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StoredConfig {
    #[serde(default)]
    pub default_registry: Option<String>,
    /// Organization `orc forward` acts in when `--org` says nothing. Set at
    /// login, or with `orc config set default-org`.
    #[serde(default)]
    pub default_org: Option<String>,
    #[serde(default)]
    pub credentials: BTreeMap<String, StoredCredential>,
}

pub use orc_app::credential::StoredCredential;

impl StoredConfig {
    /// Reads the stored configuration, or the defaults when there is no file yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or does not parse.
    pub fn load() -> Result<Self> {
        let path = config_file()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(&path)
            .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
        serde_json::from_str(&body)
            .map_err(|err| CliError::Operational(format!("parse {}: {err}", path.display())))
    }

    /// Writes it back, creating the configuration directory when it is missing.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory or the file cannot be written.
    pub fn save(&self) -> Result<()> {
        let path = config_file()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                CliError::Operational(format!("create {}: {err}", parent.display()))
            })?;
        }
        let body = serde_json::to_vec_pretty(self)
            .map_err(|err| CliError::Operational(format!("encode config: {err}")))?;
        std::fs::write(&path, body)
            .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
        Ok(())
    }

    #[must_use]
    pub fn default_prefix(&self) -> &str {
        self.default_registry
            .as_deref()
            .unwrap_or(BUILTIN_DEFAULT_PREFIX)
    }

    #[must_use]
    pub fn credential_for(&self, registry: &str) -> Option<&StoredCredential> {
        self.credentials.get(registry)
    }

    /// One configuration value by the name `orc config get` takes.
    #[must_use]
    pub fn config_value(&self, key: &str) -> Option<String> {
        match key {
            "default-registry" => Some(self.default_prefix().to_owned()),
            "default-org" => self.default_org.clone(),
            _ => None,
        }
    }

    /// Sets one, by the same names.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is not one of them.
    pub fn set_config_value(&mut self, key: &str, value: String) -> Result<()> {
        match key {
            "default-registry" => {
                self.default_registry = Some(value);
                Ok(())
            }
            "default-org" => {
                self.default_org = Some(value);
                Ok(())
            }
            _ => Err(CliError::Usage(format!("unknown config key {key:?}"))),
        }
    }
}

/// Where the stored configuration lives: `ORC_CONFIG_DIR` when it is set, else
/// the user's own configuration directory.
///
/// # Errors
///
/// Returns an error when neither is known.
pub fn config_file() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("ORC_CONFIG_DIR") {
        return Ok(PathBuf::from(dir).join("config.json"));
    }
    let home = std::env::var("HOME").map_err(|_| {
        CliError::Operational("HOME is not set; cannot locate ConfigDir".to_owned())
    })?;
    Ok(PathBuf::from(home).join(".config/orc/config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_round_trips_and_unknown_keys_are_rejected() {
        let mut config = StoredConfig::default();
        assert_eq!(
            config.config_value("default-registry").as_deref(),
            Some(BUILTIN_DEFAULT_PREFIX)
        );
        config
            .set_config_value("default-registry", "registry.example.com".to_owned())
            .expect("set");
        assert_eq!(
            config.config_value("default-registry").as_deref(),
            Some("registry.example.com")
        );
        assert!(
            config
                .set_config_value("chunker.fixed.size", "4KiB".to_owned())
                .is_err()
        );
        assert!(config.config_value("chunker.fastcdc.min").is_none());
    }

    #[test]
    fn the_default_org_round_trips() {
        let mut config = StoredConfig::default();
        assert!(config.config_value("default-org").is_none());
        config
            .set_config_value("default-org", "acme".to_owned())
            .expect("set");
        assert_eq!(config.config_value("default-org").as_deref(), Some("acme"));
    }
}
