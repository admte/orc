#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstallRecord {
    pub app: String,
    pub version: String,
    pub reference: String,
    pub digest: String,
    pub platform: String,
    pub mode: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_service: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub materialized_dir: String,
}

pub fn list_install_records(app_filter: Option<&str>) -> Result<Vec<InstallRecord>> {
    list_install_records_in(&installs_dir()?, app_filter)
}

fn list_install_records_in(root: &Path, app_filter: Option<&str>) -> Result<Vec<InstallRecord>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for app_entry in std::fs::read_dir(root)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", root.display())))?
    {
        let app_entry =
            app_entry.map_err(|err| CliError::Operational(format!("read install app: {err}")))?;
        let metadata = app_entry.metadata().map_err(|err| {
            CliError::Operational(format!("stat {}: {err}", app_entry.path().display()))
        })?;
        if !metadata.is_dir() {
            continue;
        }
        for version_entry in std::fs::read_dir(app_entry.path()).map_err(|err| {
            CliError::Operational(format!("read {}: {err}", app_entry.path().display()))
        })? {
            let version_entry = version_entry
                .map_err(|err| CliError::Operational(format!("read install record: {err}")))?;
            if version_entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                != Some("json")
            {
                continue;
            }
            let body = std::fs::read_to_string(version_entry.path()).map_err(|err| {
                CliError::Operational(format!("read {}: {err}", version_entry.path().display()))
            })?;
            let record = serde_json::from_str::<InstallRecord>(&body).map_err(|err| {
                CliError::Operational(format!("parse {}: {err}", version_entry.path().display()))
            })?;
            if app_filter.is_none_or(|filter| filter == record.app) {
                records.push(record);
            }
        }
    }
    records.sort_by(|left, right| {
        left.app
            .cmp(&right.app)
            .then_with(|| left.version.cmp(&right.version))
    });
    Ok(records)
}

pub fn read_install_record(app: &str, version: &str) -> Result<Option<InstallRecord>> {
    let path = install_record_path(app, version)?;
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
    serde_json::from_str(&body)
        .map(Some)
        .map_err(|err| CliError::Operational(format!("parse {}: {err}", path.display())))
}

pub fn write_install_record(record: &InstallRecord) -> Result<()> {
    let path = install_record_path(&record.app, &record.version)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Operational(format!("create {}: {err}", parent.display())))?;
    }
    let body = serde_json::to_vec_pretty(record)
        .map_err(|err| CliError::Operational(format!("encode install record: {err}")))?;
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))
}

pub fn remove_install_record(app: &str, version: &str) -> Result<()> {
    remove_install_record_in(&installs_dir()?, app, version)
}

fn remove_install_record_in(root: &Path, app: &str, version: &str) -> Result<()> {
    let path = install_record_path_in(root, app, version)?;
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&path)
        .map_err(|err| CliError::Operational(format!("remove {}: {err}", path.display())))?;
    if let Some(parent) = path.parent()
        && parent
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_none())
    {
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}

pub fn materialized_app_dir(app: &str, version: &str) -> Result<PathBuf> {
    if app.is_empty() || version.is_empty() {
        return Err(CliError::Usage(
            "app and version must be non-empty for install state".to_owned(),
        ));
    }
    Ok(state_dir()?
        .join("apps")
        .join(encode_component(app))
        .join(encode_component(version)))
}

fn install_record_path(app: &str, version: &str) -> Result<PathBuf> {
    install_record_path_in(&installs_dir()?, app, version)
}

fn install_record_path_in(root: &Path, app: &str, version: &str) -> Result<PathBuf> {
    if app.is_empty() || version.is_empty() {
        return Err(CliError::Usage(
            "app and version must be non-empty for install state".to_owned(),
        ));
    }
    Ok(root
        .join(encode_component(app))
        .join(format!("{}.json", encode_component(version))))
}

fn installs_dir() -> Result<PathBuf> {
    Ok(state_dir()?.join("installs"))
}

/// Root of the runtime state: install records, materialized app dirs, and the markers a
/// runtime keeps between passes.
pub fn state_dir() -> Result<PathBuf> {
    crate::paths::state_dir()
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                encoded.push(char::from(byte));
            }
            _ => write!(&mut encoded, "%{byte:02X}").expect("write to string"),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_paths_escape_path_separators() {
        let dir = tempfile::tempdir().expect("state dir");
        let path = install_record_path_in(&dir.path().join("installs"), "acme/runner", "1.0/linux")
            .expect("path");
        assert!(path.ends_with("installs/acme%2Frunner/1.0%2Flinux.json"));
    }

    #[test]
    fn records_are_sorted_and_filterable() {
        let dir = tempfile::tempdir().expect("state dir");
        let root = dir.path().join("installs");
        write_record(
            &InstallRecord {
                app: "runner".to_owned(),
                version: "2".to_owned(),
                reference: "ghcr.io/acme/runner:2".to_owned(),
                digest: "sha256:2".to_owned(),
                platform: "linux/arm64".to_owned(),
                mode: "process".to_owned(),
                state: "stopped".to_owned(),
                pid_service: None,
                params: BTreeMap::new(),
                blob_digests: Vec::new(),
                materialized_dir: String::new(),
            },
            &root,
        );
        write_record(
            &InstallRecord {
                app: "agent".to_owned(),
                version: "1".to_owned(),
                reference: "ghcr.io/acme/agent:1".to_owned(),
                digest: "sha256:1".to_owned(),
                platform: "linux/amd64".to_owned(),
                mode: "service".to_owned(),
                state: "running".to_owned(),
                pid_service: Some("agent".to_owned()),
                params: BTreeMap::new(),
                blob_digests: Vec::new(),
                materialized_dir: String::new(),
            },
            &root,
        );

        let all = list_install_records_in(&root, None).expect("records");
        assert_eq!(
            all.iter()
                .map(|record| record.app.as_str())
                .collect::<Vec<_>>(),
            ["agent", "runner"]
        );
        let runner = list_install_records_in(&root, Some("runner")).expect("filtered");
        assert_eq!(runner.len(), 1);
        assert_eq!(runner[0].version, "2");
    }

    #[test]
    fn remove_record_deletes_record_file_only() {
        let dir = tempfile::tempdir().expect("state dir");
        let root = dir.path().join("installs");
        let record = InstallRecord {
            app: "agent".to_owned(),
            version: "1".to_owned(),
            reference: "ghcr.io/acme/agent:1".to_owned(),
            digest: "sha256:1".to_owned(),
            platform: "linux/amd64".to_owned(),
            mode: "process".to_owned(),
            state: "stopped".to_owned(),
            pid_service: None,
            params: BTreeMap::new(),
            blob_digests: Vec::new(),
            materialized_dir: String::new(),
        };
        write_record(&record, &root);
        let path = install_record_path_in(&root, "agent", "1").expect("path");

        remove_install_record_in(&root, "agent", "1").expect("remove record");
        assert!(!path.exists());
    }

    fn write_record(record: &InstallRecord, root: &Path) {
        let path = install_record_path_in(root, &record.app, &record.version).expect("path");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(record).expect("record json"),
        )
        .expect("write record");
    }
}
