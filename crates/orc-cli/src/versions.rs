use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use orc_app::discovery::{self, DiscoveryLimits, VersionScope};
use serde::Serialize;

use crate::app::{AppConfig, ManifestDocument};
use crate::config::StoredConfig;
use crate::error::{CliError, Result};
use crate::registry::RegistryClient;

/// The stored credential a discovery run authenticates GitHub sources with.
///
/// Version sources are read from GitHub, never from the app's own registry, so
/// `ghcr.io` is the only stored credential that belongs on those requests. Handing a
/// target registry's key to `api.github.com` earns a 401, and a 401 reads as an
/// unreachable source — which is how a discoverable version turns into a tag-miss.
/// Every discovery call site takes its token from here so none of them can pick a
/// different one.
#[must_use]
pub fn github_token(config: &StoredConfig) -> Option<&str> {
    config
        .credential_for("ghcr.io")
        .map(|credential| credential.token.as_str())
}

/// The evaluation budget every CLI-side discovery run uses.
///
/// A stored `ghcr.io` credential rides along so an author previewing a private
/// release feed sees the same list as other discovery consumers.
pub fn discovery_limits(github_token: Option<&str>) -> DiscoveryLimits {
    DiscoveryLimits {
        github_token: github_token.map(str::to_owned),
        ..DiscoveryLimits::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionRow {
    pub version: String,
    pub default: bool,
    pub platforms: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ManifestSummary {
    pub digest: String,
    pub config: Option<AppConfig>,
    pub description: String,
    pub platforms: Vec<String>,
}

pub async fn read_manifest_summary(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
) -> Result<Option<ManifestSummary>> {
    let response = match registry.get_manifest(repository, reference).await {
        Ok(r) => r,
        Err(CliError::NotFound(_)) => return Ok(None),
        Err(err) => return Err(err),
    };
    let doc = ManifestDocument::parse(&response.body, &response.content_type)
        .map_err(|err| CliError::Operational(format!("decode manifest: {err}")))?;
    if !doc.is_orc_app() {
        return Ok(None);
    }
    let config = registry.app_config_for_manifest(repository, &doc).await?;
    let platforms = doc.platforms();
    Ok(Some(ManifestSummary {
        digest: response.digest,
        config,
        description: doc.description(),
        platforms,
    }))
}

pub async fn discover_versions(
    registry: &RegistryClient,
    github_token: Option<&str>,
    repository: &str,
    scope: VersionScope,
) -> Result<Vec<VersionRow>> {
    let Some(default_summary) = read_manifest_summary(registry, repository, "default").await?
    else {
        return Err(CliError::NotFound(format!(
            "{repository}:default is not an ORC app artifact"
        )));
    };
    let default_config = default_summary.config.clone().unwrap_or_default();
    let default_platforms = default_summary.platforms.clone();

    let mut rows = BTreeMap::<String, VersionSeed>::new();
    for tag in registry.list_tags(repository).await? {
        if tag == "default" {
            continue;
        }
        let Some(summary) = read_manifest_summary(registry, repository, &tag).await? else {
            continue;
        };
        rows.insert(
            tag,
            VersionSeed {
                digest: Some(summary.digest),
                platforms: summary.platforms,
                source_order: rows.len(),
            },
        );
    }

    if let Some(discovery) = &default_config.versions {
        // This listing is the author's preview of the complete discoverable set, so it
        // reads a paginated source to its end before it
        // decides anything. Reading one page here would preview a different app.
        let outcome = discovery::evaluate_scoped(
            discovery,
            repository,
            &discovery_limits(github_token),
            scope,
            discovery::Reach::WholeListing,
        )
        .await;
        // A live source failure is fatal for the author-facing preview: surface
        // it rather than silently returning a shorter list.
        if let Some(error) = outcome.source_error {
            return Err(CliError::Operational(error));
        }
        for version in outcome.versions {
            let next_order = rows.len();
            rows.entry(version).or_insert_with(|| VersionSeed {
                digest: None,
                platforms: default_platforms.clone(),
                source_order: next_order,
            });
        }
    }

    let default_version = resolve_default_version(
        &rows,
        &default_summary.digest,
        default_config.default_version.as_deref(),
    );
    let mut output = rows
        .into_iter()
        .map(|(version, seed)| VersionRow {
            default: Some(version.as_str()) == default_version.as_deref(),
            version,
            platforms: seed.platforms,
        })
        .collect::<Vec<_>>();
    output.sort_by(version_row_order);
    if !output.iter().any(|row| row.default)
        && let Some(first) = output.first_mut()
    {
        first.default = true;
    }
    Ok(output)
}

#[derive(Debug, Clone)]
struct VersionSeed {
    digest: Option<String>,
    platforms: Vec<String>,
    source_order: usize,
}

fn resolve_default_version(
    rows: &BTreeMap<String, VersionSeed>,
    default_digest: &str,
    configured: Option<&str>,
) -> Option<String> {
    if let Some((version, _)) = rows
        .iter()
        .find(|(_, seed)| seed.digest.as_deref() == Some(default_digest))
    {
        return Some(version.clone());
    }
    if let Some(configured) = configured
        && rows.contains_key(configured)
    {
        return Some(configured.to_owned());
    }
    rows.iter()
        .min_by(|(left_version, left), (right_version, right)| {
            version_seed_order(left_version, left, right_version, right)
        })
        .map(|(version, _)| version.clone())
}

fn version_row_order(left: &VersionRow, right: &VersionRow) -> Ordering {
    discovery::compare_semver_desc(&left.version, &right.version)
}

fn version_seed_order(
    left_version: &str,
    left: &VersionSeed,
    right_version: &str,
    right: &VersionSeed,
) -> Ordering {
    discovery::compare_semver_desc(left_version, right_version)
        .then(left.source_order.cmp(&right.source_order))
}

pub fn unique_platforms(platforms: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    platforms
        .into_iter()
        .filter(|platform| seen.insert(platform.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_digest_match_then_configured_version() {
        let mut rows = BTreeMap::new();
        rows.insert(
            "1.0.0".to_owned(),
            VersionSeed {
                digest: Some("sha256:old".to_owned()),
                platforms: vec!["any".to_owned()],
                source_order: 0,
            },
        );
        rows.insert(
            "1.1.0".to_owned(),
            VersionSeed {
                digest: Some("sha256:new".to_owned()),
                platforms: vec!["any".to_owned()],
                source_order: 1,
            },
        );
        assert_eq!(
            resolve_default_version(&rows, "sha256:new", Some("1.0.0")).as_deref(),
            Some("1.1.0")
        );
        assert_eq!(
            resolve_default_version(&rows, "sha256:missing", Some("1.0.0")).as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn version_sort_defaults_to_semver_descending() {
        let mut rows = [
            VersionRow {
                version: "2.9.0".to_owned(),
                default: false,
                platforms: vec![],
            },
            VersionRow {
                version: "2.10.0".to_owned(),
                default: false,
                platforms: vec![],
            },
            VersionRow {
                version: "2.10.0-beta.1".to_owned(),
                default: false,
                platforms: vec![],
            },
        ];
        rows.sort_by(version_row_order);
        assert_eq!(rows[0].version, "2.10.0");
        assert_eq!(rows[1].version, "2.10.0-beta.1");
    }
}
