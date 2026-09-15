#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::app::{
    APP_ARTIFACT_TYPE, APP_CONFIG_MEDIA_TYPE, Descriptor, ImageManifest, ManifestDocument,
    has_chunked_suffix,
};
use crate::cache::{read_blob, write_blob};
use crate::chunked::read_chunked_blob;
use crate::error::{CliError, Result};
use crate::progress::{ProgressEvent, ProgressKind, ProgressPhase};
use crate::registry::{RegistryClient, verify_digest};

const ANNOTATIONS_FILE: &str = "annotations.json";
/// Reserved namespace for ORC-internal encoded payload layers. A layer media type
/// in this namespace that the reader does not understand (e.g. the deleted legacy
/// `chunk.v1[+zstd]` format) is refused rather than written as undecoded bytes.
const ORC_PAYLOAD_NAMESPACE: &str = "application/vnd.orc8r.";
const CONFIG_PREFIX: &str = "application/vnd.orc8r.";
const CONFIG_MARKER: &str = ".config.v";
const CONFIG_SUFFIX: &str = "+json";

/// One reference's manifest, fetched once.
///
/// `orc pull` has to read the manifest to know what it was pointed at — an app package or
/// an App-data restore point — and both paths then need the very same document. Carrying
/// the registry's answer verbatim alongside the parsed form is what lets the app path
/// resolve children, and the cache path write the manifest blob, without asking for it
/// again.
pub struct FetchedManifest {
    /// The registry's answer, verbatim: the bytes a cache writes and the digest it files
    /// them under.
    pub response: crate::registry::RegistryResponse,
    pub document: ManifestDocument,
}

/// Names the manifest rather than dumping it: the verbatim body is what a cache writes,
/// not something worth printing into a log line or a panic message.
impl std::fmt::Debug for FetchedManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedManifest")
            .field("digest", &self.response.digest)
            .field("media_type", &self.response.content_type)
            .field("document", &self.document)
            .finish()
    }
}

/// What a reference turned out to name.
#[derive(Debug)]
pub enum PullTarget {
    /// An app package (or an index of them): the manifest, ready for the app path.
    App(Box<FetchedManifest>),
    /// An App-data restore point, resolved from the same manifest.
    RestorePoint(Box<crate::persist::point::ResolvedPoint>),
}

/// Fetches and parses the manifest for `reference`.
///
/// This is the single fetch both pull paths share. It reports no progress of its own: the
/// app path has always opened its `Manifest` progress item inside
/// [`resolve_package`]/[`resolve_package_from`], and the cache path has never opened one.
pub async fn fetch_manifest(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
) -> Result<FetchedManifest> {
    let response = registry.get_manifest(repository, reference).await?;
    let document = ManifestDocument::parse(&response.body, &response.content_type)
        .map_err(|err| CliError::Operational(format!("decode manifest: {err}")))?;
    Ok(FetchedManifest { response, document })
}

/// Decides what `reference` names, from one manifest fetch.
///
/// Routing on `artifactType` rather than on how a tag is spelled is what keeps the two
/// kinds of pull from having to guess about each other — and doing it from a manifest the
/// app path then reuses is what keeps the decision free. A reference that cannot be
/// fetched or parsed fails here with the error the app path has always reported for it;
/// nothing is swallowed and retried.
pub async fn resolve_pull_target(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
) -> Result<PullTarget> {
    let fetched = fetch_manifest(registry, repository, reference).await?;
    if let ManifestDocument::Manifest(manifest) = &fetched.document
        && manifest.artifact_type == crate::persist::point::RESTORE_POINT_ARTIFACT_TYPE
    {
        let point =
            crate::persist::point::parse(manifest, fetched.response.digest.clone(), reference)?;
        return Ok(PullTarget::RestorePoint(Box::new(point)));
    }
    Ok(PullTarget::App(Box::new(fetched)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedPackage {
    pub digest: String,
    pub files: usize,
    pub platform: String,
    pub config_media_type: String,
    pub config_bytes: Vec<u8>,
    pub blob_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMetadata {
    pub digest: String,
    pub config_bytes: Vec<u8>,
}

pub async fn materialize_package(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    platform: Option<&str>,
    dest: &Path,
    force: bool,
) -> Result<MaterializedPackage> {
    let resolved = resolve_package(registry, repository, reference, platform).await?;
    materialize_resolved(registry, repository, resolved, dest, force).await
}

/// [`materialize_package`] for a caller that already holds the reference's manifest.
pub async fn materialize_package_from(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    platform: Option<&str>,
    dest: &Path,
    force: bool,
    fetched: FetchedManifest,
) -> Result<MaterializedPackage> {
    let resolved = resolve_package_from(registry, repository, reference, platform, fetched).await?;
    materialize_resolved(registry, repository, resolved, dest, force).await
}

async fn materialize_resolved(
    registry: &RegistryClient,
    repository: &str,
    resolved: ResolvedPackage,
    dest: &Path,
    force: bool,
) -> Result<MaterializedPackage> {
    let mut outputs = Vec::new();
    outputs.push(OutputFile {
        title: config_filename(&resolved.config_media_type)?,
        body: resolved.config_bytes.clone(),
        executable: false,
        blob_digests: vec![resolved.config_digest.clone()],
    });

    let public_annotations = public_annotations(&resolved.annotations);
    if !public_annotations.is_empty() {
        outputs.push(OutputFile {
            title: ANNOTATIONS_FILE.to_owned(),
            body: serde_json::to_vec_pretty(&public_annotations)
                .map_err(|err| CliError::Operational(format!("encode annotations.json: {err}")))?,
            executable: false,
            blob_digests: Vec::new(),
        });
    }

    outputs.extend(fetch_payloads(registry, repository, &resolved.manifest.layers).await?);

    for output in &outputs {
        let file_event =
            |phase| ProgressEvent::new(output.title.clone(), ProgressKind::File, phase);
        report(registry, file_event(ProgressPhase::Writing));
        write_output(dest, output, force).inspect_err(|err| {
            report(
                registry,
                file_event(ProgressPhase::Failed {
                    message: err.to_string(),
                }),
            );
        })?;
        report(registry, file_event(ProgressPhase::Done));
    }

    Ok(MaterializedPackage {
        digest: resolved.digest,
        files: outputs.len(),
        platform: resolved.platform,
        config_media_type: resolved.config_media_type,
        config_bytes: resolved.config_bytes,
        blob_digests: outputs
            .iter()
            .flat_map(|output| output.blob_digests.iter().cloned())
            .collect(),
    })
}

pub async fn inspect_package(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    platform: Option<&str>,
) -> Result<PackageMetadata> {
    let resolved = resolve_package(registry, repository, reference, platform).await?;
    Ok(PackageMetadata {
        digest: resolved.digest,
        config_bytes: resolved.config_bytes,
    })
}

/// The result of an author-round-trip clone: the resolved top digest, the
/// number of payload files written, and the platforms covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClonedPackage {
    pub digest: String,
    pub files: usize,
    pub platforms: Vec<String>,
}

/// Fetches the verbatim `artifact.yaml` recipe attached to a package as an
/// `application/vnd.orc8r.recipe.v1` referrer of `subject_digest`. Returns
/// `None` when no recipe is attached. Discovery uses the referrers API with the
/// tag-schema fallback ([`RegistryClient::get_referrers`]).
pub async fn fetch_recipe(
    registry: &RegistryClient,
    repository: &str,
    subject_digest: &str,
) -> Result<Option<Vec<u8>>> {
    let referrers = registry
        .get_referrers(
            repository,
            subject_digest,
            Some(crate::app::RECIPE_ARTIFACT_TYPE),
        )
        .await?;
    let Some(referrer) = referrers.into_iter().next() else {
        return Ok(None);
    };
    let response = registry.get_manifest(repository, &referrer.digest).await?;
    let document = ManifestDocument::parse(&response.body, &response.content_type)
        .map_err(|err| CliError::Operational(format!("decode recipe manifest: {err}")))?;
    let ManifestDocument::Manifest(manifest) = document else {
        return Err(CliError::Operational(
            "recipe referrer is not an image manifest".to_owned(),
        ));
    };
    let layer = manifest
        .layers
        .iter()
        .find(|layer| layer.media_type == crate::app::RECIPE_MEDIA_TYPE)
        .or_else(|| manifest.layers.first())
        .ok_or_else(|| CliError::Operational("recipe manifest carries no layer".to_owned()))?;
    Ok(Some(fetch_blob(registry, repository, &layer.digest).await?))
}

/// Materializes the payload files for **every** platform of a package into
/// `dest`, deduplicating layers shared across platforms. Unlike
/// [`materialize_package`] it writes no config or `annotations.json` sidecar —
/// `orc clone` recovers those from the `artifact.yaml` recipe instead.
pub async fn materialize_all_platforms(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    dest: &Path,
    force: bool,
) -> Result<ClonedPackage> {
    let response = registry.get_manifest(repository, reference).await?;
    let document = ManifestDocument::parse(&response.body, &response.content_type)
        .map_err(|err| CliError::Operational(format!("decode manifest: {err}")))?;
    let top_digest = response.digest;

    let mut platforms = Vec::new();
    let mut layers: Vec<Descriptor> = Vec::new();
    match document {
        ManifestDocument::Manifest(manifest) => {
            platforms.push("any".to_owned());
            layers.extend(manifest.layers);
        }
        ManifestDocument::Index(index) => {
            let mut seen_manifests = BTreeSet::new();
            for child in &index.manifests {
                if let Some(platform) = child.platform.as_ref() {
                    platforms.push(platform.label());
                }
                if !seen_manifests.insert(child.digest.clone()) {
                    continue;
                }
                let child_response = registry.get_manifest(repository, &child.digest).await?;
                if child_response.digest != child.digest {
                    return Err(CliError::Operational(format!(
                        "manifest digest mismatch: expected {}, got {}",
                        child.digest, child_response.digest
                    )));
                }
                let child_doc =
                    ManifestDocument::parse(&child_response.body, &child_response.content_type)
                        .map_err(|err| {
                            CliError::Operational(format!("decode child manifest: {err}"))
                        })?;
                let ManifestDocument::Manifest(manifest) = child_doc else {
                    return Err(CliError::Operational(
                        "image index child resolved to another index".to_owned(),
                    ));
                };
                layers.extend(manifest.layers);
            }
        }
    }

    // Platforms that reuse one manifest (identical interpolated content) share
    // layer blobs; dedup by digest so each file is fetched and written once.
    let mut seen_layers = BTreeSet::new();
    layers.retain(|layer| seen_layers.insert(layer.digest.clone()));

    let outputs = fetch_payloads(registry, repository, &layers).await?;
    for output in &outputs {
        let file_event =
            |phase| ProgressEvent::new(output.title.clone(), ProgressKind::File, phase);
        report(registry, file_event(ProgressPhase::Writing));
        write_output(dest, output, force).inspect_err(|err| {
            report(
                registry,
                file_event(ProgressPhase::Failed {
                    message: err.to_string(),
                }),
            );
        })?;
        report(registry, file_event(ProgressPhase::Done));
    }

    platforms.sort();
    platforms.dedup();
    Ok(ClonedPackage {
        digest: top_digest,
        files: outputs.len(),
        platforms,
    })
}

#[derive(Debug)]
struct ResolvedManifest {
    manifest: ImageManifest,
    annotations: BTreeMap<String, String>,
    digest: String,
    platform: String,
}

#[derive(Debug)]
struct ResolvedPackage {
    manifest: ImageManifest,
    annotations: BTreeMap<String, String>,
    digest: String,
    platform: String,
    config_media_type: String,
    config_digest: String,
    config_bytes: Vec<u8>,
}

async fn resolve_package(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    platform: Option<&str>,
) -> Result<ResolvedPackage> {
    report(registry, manifest_event(reference, downloading()));
    let fetched = fetch_manifest(registry, repository, reference)
        .await
        .inspect_err(|err| report(registry, manifest_event(reference, failed(err))))?;
    finish_resolve(registry, repository, reference, platform, fetched).await
}

/// [`resolve_package`] for a caller that already holds the reference's manifest — the one
/// `orc pull` fetched to decide which kind of artifact it was pointed at.
///
/// The saving is one request, not a shortcut: the document resolves exactly as a freshly
/// fetched one does, children and platform selection included, and reports the same
/// progress.
async fn resolve_package_from(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    platform: Option<&str>,
    fetched: FetchedManifest,
) -> Result<ResolvedPackage> {
    report(registry, manifest_event(reference, downloading()));
    finish_resolve(registry, repository, reference, platform, fetched).await
}

/// Everything after the top-level manifest is in hand: pick the platform's manifest, close
/// the progress item, and read the config blob.
async fn finish_resolve(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    platform: Option<&str>,
    fetched: FetchedManifest,
) -> Result<ResolvedPackage> {
    let resolved = resolve_manifest(
        registry,
        repository,
        fetched.document,
        fetched.response.digest,
        platform,
    )
    .await
    .inspect_err(|err| report(registry, manifest_event(reference, failed(err))))?;
    report(registry, manifest_event(reference, ProgressPhase::Done));
    if resolved.manifest.schema_version != 2
        || resolved.manifest.artifact_type != APP_ARTIFACT_TYPE
        || resolved.manifest.config.media_type != APP_CONFIG_MEDIA_TYPE
    {
        return Err(CliError::NotFound(format!(
            "{repository}:{reference} is not an ORC app artifact"
        )));
    }
    let config_media_type = resolved.manifest.config.media_type.clone();
    let config_digest = resolved.manifest.config.digest.clone();
    let config_bytes = fetch_blob(registry, repository, &resolved.manifest.config.digest).await?;
    Ok(ResolvedPackage {
        manifest: resolved.manifest,
        annotations: resolved.annotations,
        digest: resolved.digest,
        platform: resolved.platform,
        config_media_type,
        config_digest,
        config_bytes,
    })
}

async fn resolve_manifest(
    registry: &RegistryClient,
    repository: &str,
    document: ManifestDocument,
    digest: String,
    platform: Option<&str>,
) -> Result<ResolvedManifest> {
    match document {
        ManifestDocument::Manifest(manifest) => {
            let annotations = manifest.annotations.clone();
            Ok(ResolvedManifest {
                manifest,
                annotations,
                digest,
                platform: "any".to_owned(),
            })
        }
        ManifestDocument::Index(index) => {
            let Some(child) = select_child(&index.manifests, platform) else {
                let available = index
                    .manifests
                    .iter()
                    .filter_map(|descriptor| descriptor.platform.as_ref())
                    .map(crate::app::Platform::label)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(CliError::NotFound(format!(
                    "no matching platform; available: {available}"
                )));
            };
            let response = registry.get_manifest(repository, &child.digest).await?;
            if response.digest != child.digest {
                return Err(CliError::Operational(format!(
                    "manifest digest mismatch: expected {}, got {}",
                    child.digest, response.digest
                )));
            }
            let child_doc = ManifestDocument::parse(&response.body, &response.content_type)
                .map_err(|err| CliError::Operational(format!("decode child manifest: {err}")))?;
            let ManifestDocument::Manifest(manifest) = child_doc else {
                return Err(CliError::Operational(
                    "image index child resolved to another index".to_owned(),
                ));
            };
            let platform = child
                .platform
                .as_ref()
                .map_or_else(|| "any".to_owned(), crate::app::Platform::label);
            Ok(ResolvedManifest {
                manifest,
                annotations: index.annotations,
                digest: child.digest.clone(),
                platform,
            })
        }
    }
}

fn select_child<'a>(children: &'a [Descriptor], platform: Option<&str>) -> Option<&'a Descriptor> {
    if let Some(platform) = platform {
        return children.iter().find(|child| {
            child
                .platform
                .as_ref()
                .is_some_and(|item| item.label() == platform)
        });
    }
    if children.len() == 1 {
        return children.first();
    }
    let host = host_platform();
    children.iter().find(|child| {
        child
            .platform
            .as_ref()
            .is_some_and(|item| item.label() == host)
    })
}

fn host_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}/{arch}")
}

async fn fetch_payloads(
    registry: &RegistryClient,
    repository: &str,
    layers: &[Descriptor],
) -> Result<Vec<OutputFile>> {
    let mut grouped: BTreeMap<String, Vec<&Descriptor>> = BTreeMap::new();
    for layer in layers {
        let title = layer_title(layer)?;
        grouped.entry(title).or_default().push(layer);
    }

    let mut outputs = Vec::with_capacity(grouped.len());
    for (title, layers) in grouped {
        let [layer] = layers.as_slice() else {
            return Err(CliError::Operational(format!(
                "duplicate payload title {title:?}"
            )));
        };
        outputs.push(fetch_file(registry, repository, &title, layer).await?);
    }
    Ok(outputs)
}

async fn fetch_file(
    registry: &RegistryClient,
    repository: &str,
    title: &str,
    layer: &Descriptor,
) -> Result<OutputFile> {
    if has_chunked_suffix(&layer.media_type) {
        // Single-blob chunked-zstd layer (spec 146): fetch the whole blob, then
        // stream-decompress it (multi-frame decoder, TOC frame skipped) with the
        // shared reader, which verifies the layer digest and TOC before decoding.
        let blob = fetch_blob(registry, repository, &layer.digest).await?;
        let body = read_chunked_blob(&blob, &layer.annotations, &layer.digest)?;
        return Ok(OutputFile {
            title: title.to_owned(),
            body,
            executable: executable(layer),
            blob_digests: vec![layer.digest.clone()],
        });
    }
    // An ORC-internal payload media type the reader does not understand (e.g. the
    // deleted legacy `chunk.v1[+zstd]` format) must fail loudly — never install
    // undecoded bytes.
    if layer.media_type.starts_with(ORC_PAYLOAD_NAMESPACE) {
        return Err(CliError::Operational(format!(
            "payload {title:?} uses unsupported media type {:?}; \
             this client cannot decode it (re-push the artifact in the current format)",
            layer.media_type
        )));
    }
    // Plain whole-blob payload of a logical file type: written verbatim.
    let body = fetch_blob(registry, repository, &layer.digest).await?;
    Ok(OutputFile {
        title: title.to_owned(),
        body,
        executable: executable(layer),
        blob_digests: vec![layer.digest.clone()],
    })
}

fn layer_title(layer: &Descriptor) -> Result<String> {
    let title = layer
        .annotations
        .get("org.opencontainers.image.title")
        .ok_or_else(|| CliError::Operational("payload layer is missing title".to_owned()))?
        .to_owned();
    validate_title(&title)?;
    Ok(title)
}

fn executable(layer: &Descriptor) -> bool {
    layer
        .annotations
        .get("vnd.orc8r.file.executable")
        .is_some_and(|value| value == "true")
}

fn config_filename(media_type: &str) -> Result<String> {
    let rest = media_type
        .strip_prefix(CONFIG_PREFIX)
        .and_then(|value| value.strip_suffix(CONFIG_SUFFIX))
        .ok_or_else(|| {
            CliError::Operational(format!("unsupported config media type {media_type}"))
        })?;
    let (name, version) = rest.split_once(CONFIG_MARKER).ok_or_else(|| {
        CliError::Operational(format!("unsupported config media type {media_type}"))
    })?;
    if name.is_empty() || version.is_empty() {
        return Err(CliError::Operational(format!(
            "unsupported config media type {media_type}"
        )));
    }
    Ok(format!("{name}.config.v{version}.json"))
}

fn public_annotations(annotations: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    annotations
        .iter()
        .filter(|(key, _)| !key.starts_with("vnd.orc8r."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

async fn fetch_blob(registry: &RegistryClient, repository: &str, digest: &str) -> Result<Vec<u8>> {
    if let Some(body) = read_blob(digest)? {
        report(registry, blob_event(digest, ProgressPhase::Verifying));
        verify_digest(&body, digest).inspect_err(|err| report_failed(registry, digest, err))?;
        // `Cached` is the terminal phase here so the line settles on "Cached"
        // (not "Done") and the user can tell nothing was downloaded.
        report(registry, blob_event(digest, ProgressPhase::Cached));
        return Ok(body);
    }
    // `get_blob` emits the byte-level `Downloading` events for the cache miss.
    let body = registry
        .get_blob(repository, digest)
        .await
        .inspect_err(|err| report_failed(registry, digest, err))?;
    report(registry, blob_event(digest, ProgressPhase::Verifying));
    verify_digest(&body, digest).inspect_err(|err| report_failed(registry, digest, err))?;
    report(registry, blob_event(digest, ProgressPhase::Writing));
    write_blob(digest, &body).inspect_err(|err| report_failed(registry, digest, err))?;
    report(registry, blob_event(digest, ProgressPhase::Done));
    Ok(body)
}

fn manifest_event(reference: &str, phase: ProgressPhase) -> ProgressEvent {
    ProgressEvent::new(reference.to_owned(), ProgressKind::Manifest, phase)
}

const fn downloading() -> ProgressPhase {
    ProgressPhase::Downloading {
        done: 0,
        total: None,
    }
}

fn failed(err: &CliError) -> ProgressPhase {
    ProgressPhase::Failed {
        message: err.to_string(),
    }
}

/// Emits one event if the client has a reporter attached; a no-op otherwise.
fn report(registry: &RegistryClient, event: ProgressEvent) {
    if let Some(reporter) = registry.progress() {
        reporter.report(event);
    }
}

fn blob_event(digest: &str, phase: ProgressPhase) -> ProgressEvent {
    ProgressEvent::new(digest, ProgressKind::Blob, phase)
}

fn report_failed(registry: &RegistryClient, digest: &str, err: &CliError) {
    report(
        registry,
        blob_event(
            digest,
            ProgressPhase::Failed {
                message: err.to_string(),
            },
        ),
    );
}

#[derive(Debug)]
struct OutputFile {
    title: String,
    body: Vec<u8>,
    executable: bool,
    blob_digests: Vec<String>,
}

fn write_output(dest: &Path, output: &OutputFile, force: bool) -> Result<()> {
    let relative = safe_relative_path(&output.title)?;
    let path = dest.join(relative);
    if path.exists() && !force {
        return Err(CliError::Conflict(format!(
            "{} already exists; use --force to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Operational(format!("create {}: {err}", parent.display())))?;
    }
    std::fs::write(&path, &output.body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    set_executable(&path, output.executable)?;
    Ok(())
}

fn safe_relative_path(title: &str) -> Result<PathBuf> {
    validate_title(title)?;
    let path = Path::new(title);
    if path.is_absolute() {
        return Err(CliError::Operational(format!(
            "invalid payload title {title:?}"
        )));
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => out.push(value),
            _ => {
                return Err(CliError::Operational(format!(
                    "invalid payload title {title:?}"
                )));
            }
        }
    }
    Ok(out)
}

fn validate_title(title: &str) -> Result<()> {
    if title.is_empty()
        || title.starts_with('/')
        || title.split('/').any(|part| part.is_empty() || part == "..")
    {
        return Err(CliError::Operational(format!(
            "invalid payload title {title:?}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if !executable {
        return Ok(());
    }
    let metadata = std::fs::metadata(path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o100);
    std::fs::set_permissions(path, permissions)
        .map_err(|err| CliError::Operational(format!("chmod {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::digest_bytes;

    #[test]
    fn config_filename_derives_from_media_type() {
        assert_eq!(
            config_filename("application/vnd.orc8r.kvm.image.config.v1+json").expect("filename"),
            "kvm.image.config.v1.json"
        );
        assert!(config_filename("application/json").is_err());
    }

    #[test]
    fn public_annotations_drop_reserved_keys() {
        let annotations = BTreeMap::from([
            (
                "org.opencontainers.image.description".to_owned(),
                "demo".to_owned(),
            ),
            ("vnd.orc8r.chunker".to_owned(), "none".to_owned()),
        ]);
        assert_eq!(
            public_annotations(&annotations),
            BTreeMap::from([(
                "org.opencontainers.image.description".to_owned(),
                "demo".to_owned()
            )])
        );
    }

    #[tokio::test]
    async fn manifest_resolution_reports_universal_platform() {
        let manifest = ImageManifest {
            schema_version: 2,
            artifact_type: APP_ARTIFACT_TYPE.to_owned(),
            config: Descriptor {
                media_type: "application/vnd.orc8r.app.config.v1+json".to_owned(),
                digest: digest_bytes(b"config"),
                size: 6,
                platform: None,
                annotations: BTreeMap::new(),
            },
            layers: Vec::new(),
            annotations: BTreeMap::from([(
                "org.opencontainers.image.description".to_owned(),
                "demo".to_owned(),
            )]),
        };
        let registry = RegistryClient::new("example.com", None, false).expect("registry");
        let resolved = resolve_manifest(
            &registry,
            "acme/demo",
            ManifestDocument::Manifest(manifest),
            "sha256:manifest".to_owned(),
            None,
        )
        .await
        .expect("resolved");

        assert_eq!(resolved.digest, "sha256:manifest");
        assert_eq!(resolved.platform, "any");
        assert_eq!(
            resolved
                .annotations
                .get("org.opencontainers.image.description")
                .map(String::as_str),
            Some("demo")
        );
    }

    #[test]
    fn safe_relative_path_rejects_traversal() {
        assert!(safe_relative_path("bin/run.sh").is_ok());
        assert!(safe_relative_path("../secret").is_err());
        assert!(safe_relative_path("bin//run.sh").is_err());
        assert!(safe_relative_path("/abs").is_err());
    }

    #[test]
    fn write_output_refuses_conflict_without_force() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("file.txt"), b"old").expect("old");
        let output = OutputFile {
            title: "file.txt".to_owned(),
            body: b"new".to_vec(),
            executable: false,
            blob_digests: Vec::new(),
        };
        assert!(matches!(
            write_output(dir.path(), &output, false),
            Err(CliError::Conflict(_))
        ));
        write_output(dir.path(), &output, true).expect("force");
        assert_eq!(
            std::fs::read(dir.path().join("file.txt")).expect("body"),
            b"new"
        );
    }

    /// Serializes tests that mutate the process-global `ORC_CACHE_DIR`.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[allow(unsafe_code)]
    fn set_cache_dir(path: &Path) {
        // SAFETY: cache-touching tests hold `env_lock`, so no other thread reads
        // or writes the environment concurrently.
        unsafe { std::env::set_var("ORC_CACHE_DIR", path) };
    }

    // The env guard must stay held across the await so the cache dir cannot be
    // swapped mid-test by a sibling; that is the point of serializing.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_blob_cache_hit_skips_network_and_reports_cached() {
        use crate::progress::test_support::RecordingReporter;

        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("dir");
        set_cache_dir(dir.path());

        let payload = b"already cached bytes";
        let digest = digest_bytes(payload);
        write_blob(&digest, payload).expect("seed cache");

        let recorder = RecordingReporter::shared();
        // An unroutable port: a cache hit must never open a connection.
        let client = RegistryClient::new("127.0.0.1:1", None, true)
            .expect("client")
            .with_progress(recorder.clone());
        let body = fetch_blob(&client, "acme/app", &digest)
            .await
            .expect("cache hit");

        assert_eq!(body, payload);
        assert_eq!(
            recorder.phases(),
            vec![ProgressPhase::Verifying, ProgressPhase::Cached]
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_blob_cache_miss_downloads_verifies_and_writes() {
        use std::io::{Read as _, Write as _};

        use crate::progress::test_support::RecordingReporter;

        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("dir");
        set_cache_dir(dir.path());

        let payload = b"freshly downloaded bytes".to_vec();
        let digest = digest_bytes(&payload);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = payload.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                served.len()
            );
            stream.write_all(header.as_bytes()).expect("write header");
            stream.write_all(&served).expect("write body");
        });

        let recorder = RecordingReporter::shared();
        let client = RegistryClient::new(&addr.to_string(), None, true)
            .expect("client")
            .with_progress(recorder.clone());
        let body = fetch_blob(&client, "acme/app", &digest)
            .await
            .expect("cache miss");
        server.join().expect("server thread");

        assert_eq!(body, payload);
        assert!(
            read_blob(&digest).expect("read cache").is_some(),
            "miss populates the cache"
        );

        let phases = recorder.phases();
        assert!(
            phases
                .iter()
                .any(|phase| matches!(phase, ProgressPhase::Downloading { .. })),
            "miss streams download events: {phases:?}"
        );
        let tail = &phases[phases.len() - 3..];
        assert_eq!(
            tail,
            [
                ProgressPhase::Verifying,
                ProgressPhase::Writing,
                ProgressPhase::Done,
            ],
            "miss ends with verify, cache write, done: {phases:?}"
        );
    }
}
