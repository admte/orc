#![allow(clippy::missing_errors_doc)]

use crate::error::{CliError, Result};

/// Registry a bare app reference resolves against. The prefix carries no
/// namespace, so `uv` becomes the single-segment repository `uv` — zone scope
/// in an ORC registry, visible to every org and project.
pub const BUILTIN_DEFAULT_PREFIX: &str = "orc8r.com";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrefix {
    pub registry: String,
    pub namespace: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReference {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub full: String,
}

pub fn resolve_prefix(
    input: Option<&str>,
    override_prefix: Option<&str>,
) -> Result<ResolvedPrefix> {
    let raw = input
        .or(override_prefix)
        .unwrap_or(BUILTIN_DEFAULT_PREFIX)
        .trim();
    if raw.is_empty() {
        return Err(CliError::Usage(
            "registry prefix cannot be empty".to_owned(),
        ));
    }
    let (registry, namespace) = split_prefix(raw)?;
    Ok(ResolvedPrefix {
        registry: registry.to_owned(),
        namespace: namespace.to_owned(),
        value: raw.trim_end_matches('/').to_owned(),
    })
}

pub fn resolve_app_reference(
    input: &str,
    default_prefix: &str,
    override_prefix: Option<&str>,
) -> Result<ResolvedReference> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CliError::Usage("app reference cannot be empty".to_owned()));
    }
    let (path, tag) = split_tag(input);
    let tag = tag.unwrap_or("default");
    if path.is_empty() || tag.is_empty() {
        return Err(CliError::Usage(format!("invalid app reference {input:?}")));
    }

    let (registry, repository) = if has_explicit_registry(path) {
        let (registry, repository) = path.split_once('/').ok_or_else(|| {
            CliError::Usage(format!("reference {input:?} is missing an app name"))
        })?;
        (registry.to_owned(), repository.to_owned())
    } else {
        let prefix = override_prefix.unwrap_or(default_prefix);
        let (registry, namespace) = split_prefix(prefix)?;
        let repository = if namespace.is_empty() {
            path.to_owned()
        } else {
            format!("{namespace}/{path}")
        };
        (registry.to_owned(), repository)
    };

    validate_path(&registry, "registry")?;
    validate_path(&repository, "repository")?;
    let full = format_reference(&registry, &repository, tag);
    Ok(ResolvedReference {
        registry,
        repository,
        tag: tag.to_owned(),
        full,
    })
}

impl ResolvedReference {
    /// This reference with `tag` in place of its own — how a reference whose tag
    /// was only a version line is respelled once the line resolves to a concrete
    /// version.
    #[must_use]
    pub fn with_tag(&self, tag: &str) -> String {
        format_reference(&self.registry, &self.repository, tag)
    }
}

/// The one place the `registry/repository:tag` form is spelled out, so a
/// reference built here and one respelled later can never drift apart.
fn format_reference(registry: &str, repository: &str, tag: &str) -> String {
    format!("{registry}/{repository}:{tag}")
}

/// Whether `tag` is a legal OCI tag: an initial alphanumeric or `_`, then up to
/// 127 more of alphanumeric, `_`, `.`, or `-` (`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`).
///
/// This is the single charset rule shared by clients and services that
/// discovered-version validation, so a discovered version is always usable as a
/// `name:version` tag reference.
#[must_use]
pub fn is_valid_tag(tag: &str) -> bool {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() && first != '_' {
        return false;
    }
    tag.len() <= 128 && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

fn split_prefix(prefix: &str) -> Result<(&str, &str)> {
    let prefix = prefix.trim().trim_end_matches('/');
    let (registry, namespace) = prefix.split_once('/').unwrap_or((prefix, ""));
    validate_path(registry, "registry")?;
    if !namespace.is_empty() {
        validate_path(namespace, "namespace")?;
    }
    Ok((registry, namespace))
}

fn split_tag(input: &str) -> (&str, Option<&str>) {
    let last_slash = input.rfind('/');
    let last_colon = input.rfind(':');
    match (last_slash, last_colon) {
        (_, Some(colon)) if last_slash.is_none_or(|slash| colon > slash) => {
            (&input[..colon], Some(&input[colon + 1..]))
        }
        _ => (input, None),
    }
}

fn has_explicit_registry(path: &str) -> bool {
    let Some((first, _)) = path.split_once('/') else {
        return false;
    };
    first == "localhost" || first.contains('.') || first.contains(':')
}

fn validate_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.contains("//") || value.starts_with('/') || value.ends_with('/') {
        return Err(CliError::Usage(format!("invalid {label} {value:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_bare_ref_to_builtin_default() {
        let resolved =
            resolve_app_reference("jenkins-agent", BUILTIN_DEFAULT_PREFIX, None).expect("resolved");
        assert_eq!(resolved.registry, "orc8r.com");
        assert_eq!(resolved.repository, "jenkins-agent");
        assert_eq!(resolved.tag, "default");
        assert_eq!(resolved.full, "orc8r.com/jenkins-agent:default");
    }

    #[test]
    fn explicit_registry_bypasses_default_prefix() {
        let resolved = resolve_app_reference(
            "acme.example.com/ci/runner:3.46",
            BUILTIN_DEFAULT_PREFIX,
            None,
        )
        .expect("resolved");
        assert_eq!(resolved.registry, "acme.example.com");
        assert_eq!(resolved.repository, "ci/runner");
        assert_eq!(resolved.tag, "3.46");
    }

    #[test]
    fn registry_override_applies_to_relative_refs() {
        let resolved = resolve_app_reference(
            "ci/runner",
            BUILTIN_DEFAULT_PREFIX,
            Some("localhost:5000/dev"),
        )
        .expect("resolved");
        assert_eq!(resolved.full, "localhost:5000/dev/ci/runner:default");
    }

    #[test]
    fn with_tag_respells_the_reference_at_another_version() {
        let resolved =
            resolve_app_reference("uv:1.5", BUILTIN_DEFAULT_PREFIX, None).expect("resolved");
        assert_eq!(resolved.full, "orc8r.com/uv:1.5");
        assert_eq!(resolved.with_tag("1.5.7"), "orc8r.com/uv:1.5.7");
    }

    #[test]
    fn prefix_defaults_to_builtin() {
        let prefix = resolve_prefix(None, None).expect("prefix");
        assert_eq!(prefix.registry, "orc8r.com");
        assert!(prefix.namespace.is_empty());
    }
}
