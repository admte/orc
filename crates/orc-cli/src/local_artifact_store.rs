use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::app::{
    APP_ARTIFACT_TYPE, APP_CONFIG_MEDIA_TYPE, Descriptor, ImageManifest, ManifestDocument,
    has_chunked_suffix,
};
use crate::cache::{human_size, read_blob};
use crate::error::{CliError, Result};
use crate::registry::digest_bytes;
use orc_app::chunked::read_chunked_blob;
use orc_app::progress::{ProgressEvent, ProgressKind, ProgressPhase, ProgressReporter};

pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const ANNOTATIONS_FILE: &str = "annotations.json";
/// Reserved namespace for ORC-internal encoded payload layers (see `pull.rs`).
const ORC_PAYLOAD_NAMESPACE: &str = "application/vnd.orc8r.";
const CONFIG_PREFIX: &str = "application/vnd.orc8r.";
const CONFIG_MARKER: &str = ".config.v";
const CONFIG_SUFFIX: &str = "+json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalRef {
    pub reference: String,
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub target: CachedDescriptor,
    /// Referrer manifests attached to `target` (e.g. the recipe), pushed after
    /// the main graph and registered in the referrers index/fallback tag.
    #[serde(default)]
    pub referrers: Vec<CachedDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCacheStats {
    pub blobs: u64,
    pub manifests: u64,
    pub refs: u64,
    pub bytes: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CachedRefSummary {
    pub reference: String,
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    pub platforms: Vec<String>,
    pub description: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedMaterializedPackage {
    pub digest: String,
    pub files: usize,
    pub platform: String,
    pub config_media_type: String,
    pub config_bytes: Vec<u8>,
    pub blob_digests: Vec<String>,
}

pub fn cache_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("ORC_CACHE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME")
        .map_err(|_| CliError::Operational("HOME is not set; cannot locate CacheDir".to_owned()))?;
    Ok(PathBuf::from(home).join(".cache/orc"))
}

pub fn descriptor_for(media_type: &str, body: &[u8]) -> Result<CachedDescriptor> {
    Ok(CachedDescriptor {
        media_type: media_type.to_owned(),
        digest: digest_bytes(body),
        size: body
            .len()
            .try_into()
            .map_err(|_| CliError::Operational("artifact body is too large".to_owned()))?,
    })
}

pub fn write_manifest(media_type: &str, body: &[u8]) -> Result<CachedDescriptor> {
    let descriptor = descriptor_for(media_type, body)?;
    write_digest_file(&manifest_path(&descriptor.digest)?, body)?;
    Ok(descriptor)
}

pub fn read_manifest(digest: &str) -> Result<Vec<u8>> {
    let path = manifest_path(digest)?;
    if !path.exists() {
        return Err(CliError::NotFound(format!(
            "cached manifest {digest} is missing"
        )));
    }
    let body = std::fs::read(&path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
    verify_digest(&body, digest)?;
    Ok(body)
}

pub fn write_ref(
    reference: &str,
    registry: &str,
    repository: &str,
    tag: &str,
    target: CachedDescriptor,
    referrers: Vec<CachedDescriptor>,
) -> Result<()> {
    let local_ref = LocalRef {
        reference: reference.to_owned(),
        registry: registry.to_owned(),
        repository: repository.to_owned(),
        tag: tag.to_owned(),
        target,
        referrers,
    };
    let body = serde_json::to_vec_pretty(&local_ref)
        .map_err(|err| CliError::Operational(format!("encode local ref: {err}")))?;
    // Refs are last-write-wins: overwrite so re-build/pull updates the target
    // digest and referrers (digest-file dedup would keep a stale ref).
    write_file_atomic(&ref_path(reference)?, &body)
}

pub fn read_ref(reference: &str) -> Result<LocalRef> {
    let path = ref_path(reference)?;
    if !path.exists() {
        return Err(CliError::NotFound(format!(
            "cached reference {reference} is missing; run `orc build` or `orc pull` first"
        )));
    }
    let body = std::fs::read(&path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
    serde_json::from_slice(&body)
        .map_err(|err| CliError::Operational(format!("decode {}: {err}", path.display())))
}

fn report_blob(reporter: Option<&dyn ProgressReporter>, digest: &str, phase: &ProgressPhase) {
    if let Some(reporter) = reporter {
        reporter.report(ProgressEvent::new(
            digest,
            ProgressKind::Blob,
            phase.clone(),
        ));
    }
}

fn report_file(reporter: Option<&dyn ProgressReporter>, title: &str, phase: &ProgressPhase) {
    if let Some(reporter) = reporter {
        reporter.report(ProgressEvent::new(title, ProgressKind::File, phase.clone()));
    }
}

pub fn materialize_cached_package(
    reference: &str,
    platform: Option<&str>,
    dest: &Path,
    force: bool,
    reporter: Option<&dyn ProgressReporter>,
) -> Result<Option<CachedMaterializedPackage>> {
    let Some(resolved) = resolve_cached_package_ref(reference, platform)? else {
        return Ok(None);
    };
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
    outputs.extend(cached_payloads(&resolved.manifest.layers)?);

    // Payload bytes came from the local cache; signal that nothing was fetched.
    for digest in outputs.iter().flat_map(|output| &output.blob_digests) {
        report_blob(reporter, digest, &ProgressPhase::Cached);
    }
    for output in &outputs {
        report_file(reporter, &output.title, &ProgressPhase::Writing);
        write_output(dest, output, force).inspect_err(|err| {
            report_file(
                reporter,
                &output.title,
                &ProgressPhase::Failed {
                    message: err.to_string(),
                },
            );
        })?;
        report_file(reporter, &output.title, &ProgressPhase::Done);
    }

    Ok(Some(CachedMaterializedPackage {
        digest: resolved.digest,
        files: outputs.len(),
        platform: resolved.platform,
        config_media_type: resolved.config_media_type,
        config_bytes: resolved.config_bytes,
        blob_digests: outputs
            .iter()
            .flat_map(|output| output.blob_digests.iter().cloned())
            .collect(),
    }))
}

pub fn list_refs() -> Result<Vec<CachedRefSummary>> {
    let mut refs = read_all_refs()?
        .into_iter()
        .map(summarize_ref)
        .collect::<Vec<_>>();
    refs.sort_by(|left, right| left.reference.cmp(&right.reference));
    Ok(refs)
}

pub fn stats() -> Result<LocalCacheStats> {
    let root = cache_dir()?;
    let (blobs, blob_bytes) = count_digest_files(&root.join("blobs/sha256"))?;
    let (manifests, manifest_bytes) = count_digest_files(&root.join("manifests/sha256"))?;
    let (refs, ref_bytes) = count_regular_files(&root.join("refs"))?;
    Ok(LocalCacheStats {
        blobs,
        manifests,
        refs,
        bytes: blob_bytes + manifest_bytes + ref_bytes,
        path: root,
    })
}

pub fn clean_all() -> Result<LocalCacheStats> {
    let before = stats()?;
    if before.path.exists() {
        std::fs::remove_dir_all(&before.path).map_err(|err| {
            CliError::Operational(format!("remove {}: {err}", before.path.display()))
        })?;
    }
    Ok(before)
}

pub fn clean_unused(installed_blobs: &BTreeSet<String>) -> Result<LocalCacheStats> {
    let before = stats()?;
    let root = cache_dir()?;
    let refs = read_all_refs()?;
    let mut protected_manifests = BTreeSet::new();
    let mut protected_blobs = installed_blobs.clone();
    for local_ref in refs {
        protect_descriptor(
            &local_ref.target,
            &mut protected_manifests,
            &mut protected_blobs,
        )?;
    }
    clean_digest_dir(&root.join("manifests/sha256"), &protected_manifests)?;
    clean_digest_dir(&root.join("blobs/sha256"), &protected_blobs)?;
    let after = stats()?;
    Ok(LocalCacheStats {
        blobs: before.blobs.saturating_sub(after.blobs),
        manifests: before.manifests.saturating_sub(after.manifests),
        refs: 0,
        bytes: before.bytes.saturating_sub(after.bytes),
        path: before.path,
    })
}

pub fn print_stats(stats: &LocalCacheStats) {
    println!(
        "{} in {} blobs, {} manifests, {} refs ({})",
        human_size(stats.bytes),
        stats.blobs,
        stats.manifests,
        stats.refs,
        stats.path.display()
    );
}

pub fn print_cleaned(stats: &LocalCacheStats) {
    println!("freed {}", human_size(stats.bytes));
}

fn summarize_ref(local_ref: LocalRef) -> CachedRefSummary {
    let mut summary = CachedRefSummary {
        reference: local_ref.reference,
        registry: local_ref.registry,
        repository: local_ref.repository,
        tag: local_ref.tag,
        digest: local_ref.target.digest,
        media_type: local_ref.target.media_type,
        size: local_ref.target.size,
        platforms: Vec::new(),
        description: String::new(),
        error: None,
    };
    match read_manifest(&summary.digest).and_then(|body| {
        ManifestDocument::parse(&body, &summary.media_type)
            .map_err(|err| CliError::Operational(format!("decode cached manifest: {err}")))
    }) {
        Ok(document) => {
            summary.platforms = document.platforms();
            summary.description = document.description();
        }
        Err(err) => {
            summary.error = Some(err.to_string());
        }
    }
    summary
}

fn protect_descriptor(
    descriptor: &CachedDescriptor,
    manifests: &mut BTreeSet<String>,
    blobs: &mut BTreeSet<String>,
) -> Result<()> {
    if !manifests.insert(descriptor.digest.clone()) {
        return Ok(());
    }
    let body = match read_manifest(&descriptor.digest) {
        Ok(body) => body,
        Err(CliError::NotFound(_)) => return Ok(()),
        Err(err) => return Err(err),
    };
    let document = ManifestDocument::parse(&body, &descriptor.media_type)
        .map_err(|err| CliError::Operational(format!("decode cached manifest: {err}")))?;
    match document {
        ManifestDocument::Manifest(manifest) => {
            blobs.insert(manifest.config.digest);
            blobs.extend(manifest.layers.into_iter().map(|layer| layer.digest));
        }
        ManifestDocument::Index(index) => {
            for child in index.manifests {
                let child_descriptor = CachedDescriptor {
                    media_type: child.media_type,
                    digest: child.digest,
                    size: child.size.try_into().unwrap_or_default(),
                };
                protect_descriptor(&child_descriptor, manifests, blobs)?;
            }
        }
    }
    Ok(())
}

fn read_all_refs() -> Result<Vec<LocalRef>> {
    let dir = cache_dir()?.join("refs");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut refs = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", dir.display())))?
    {
        let entry = entry.map_err(|err| CliError::Operational(format!("read cache ref: {err}")))?;
        if entry.metadata().is_ok_and(|metadata| metadata.is_file()) {
            let body = std::fs::read(entry.path()).map_err(|err| {
                CliError::Operational(format!("read {}: {err}", entry.path().display()))
            })?;
            refs.push(serde_json::from_slice(&body).map_err(|err| {
                CliError::Operational(format!("decode {}: {err}", entry.path().display()))
            })?);
        }
    }
    Ok(refs)
}

fn clean_digest_dir(dir: &Path, protected: &BTreeSet<String>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", dir.display())))?
    {
        let entry =
            entry.map_err(|err| CliError::Operational(format!("read cache entry: {err}")))?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        if entry.metadata().is_ok_and(|metadata| metadata.is_file())
            && is_sha256_hex(&filename)
            && !protected.contains(&format!("sha256:{filename}"))
        {
            std::fs::remove_file(entry.path()).map_err(|err| {
                CliError::Operational(format!("remove {}: {err}", entry.path().display()))
            })?;
        }
    }
    Ok(())
}

fn manifest_path(digest: &str) -> Result<PathBuf> {
    Ok(cache_dir()?
        .join("manifests/sha256")
        .join(digest_hex(digest)?))
}

fn ref_path(reference: &str) -> Result<PathBuf> {
    Ok(cache_dir()?.join("refs").join(ref_key(reference)))
}

/// Writes a content-addressed file once: an identical digest means identical
/// bytes, so an existing file is left untouched.
fn write_digest_file(path: &Path, body: &[u8]) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    write_file_atomic(path, body)
}

/// Atomically writes `body` to `path` (temp + rename), overwriting any existing
/// file. Used for refs, whose path is stable but whose content is mutable
/// (target digest, referrers) — re-build and `orc pull` refresh must update them.
fn write_file_atomic(path: &Path, body: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Operational(format!("create {}: {err}", parent.display())))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", temporary.display())))?;
    std::fs::rename(&temporary, path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        CliError::Operational(format!("rename {}: {err}", path.display()))
    })
}

fn count_digest_files(dir: &Path) -> Result<(u64, u64)> {
    if !dir.exists() {
        return Ok((0, 0));
    }
    let mut count = 0;
    let mut bytes = 0;
    for entry in std::fs::read_dir(dir)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", dir.display())))?
    {
        let entry =
            entry.map_err(|err| CliError::Operational(format!("read cache entry: {err}")))?;
        let metadata = entry.metadata().map_err(|err| {
            CliError::Operational(format!("stat {}: {err}", entry.path().display()))
        })?;
        if metadata.is_file() && is_sha256_hex(&entry.file_name().to_string_lossy()) {
            count += 1;
            bytes += metadata.len();
        }
    }
    Ok((count, bytes))
}

fn count_regular_files(dir: &Path) -> Result<(u64, u64)> {
    if !dir.exists() {
        return Ok((0, 0));
    }
    let mut count = 0;
    let mut bytes = 0;
    for entry in std::fs::read_dir(dir)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", dir.display())))?
    {
        let entry =
            entry.map_err(|err| CliError::Operational(format!("read cache entry: {err}")))?;
        let metadata = entry.metadata().map_err(|err| {
            CliError::Operational(format!("stat {}: {err}", entry.path().display()))
        })?;
        if metadata.is_file() {
            count += 1;
            bytes += metadata.len();
        }
    }
    Ok((count, bytes))
}

fn digest_hex(digest: &str) -> Result<&str> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(CliError::Operational(format!(
            "unsupported digest {digest:?}"
        )));
    };
    if !is_sha256_hex(hex) {
        return Err(CliError::Operational(format!("invalid digest {digest:?}")));
    }
    Ok(hex)
}

fn verify_digest(body: &[u8], digest: &str) -> Result<()> {
    let actual = digest_bytes(body);
    if actual == digest {
        Ok(())
    } else {
        Err(CliError::Operational(format!(
            "digest mismatch: expected {digest}, got {actual}"
        )))
    }
}

pub fn verify_cached_blob(digest: &str) -> Result<Vec<u8>> {
    let Some(body) = read_blob(digest)? else {
        return Err(CliError::NotFound(format!(
            "cached blob {digest} is missing"
        )));
    };
    verify_digest(&body, digest)?;
    Ok(body)
}

struct ResolvedCachedPackage {
    manifest: ImageManifest,
    annotations: std::collections::BTreeMap<String, String>,
    digest: String,
    platform: String,
    config_media_type: String,
    config_digest: String,
    config_bytes: Vec<u8>,
}

fn resolve_cached_package_ref(
    reference: &str,
    platform: Option<&str>,
) -> Result<Option<ResolvedCachedPackage>> {
    let local_ref = match read_ref(reference) {
        Ok(local_ref) => local_ref,
        Err(CliError::NotFound(_)) => return Ok(None),
        Err(err) => return Err(err),
    };
    resolve_cached_package(&local_ref.target, platform).map(Some)
}

fn resolve_cached_package(
    descriptor: &CachedDescriptor,
    platform: Option<&str>,
) -> Result<ResolvedCachedPackage> {
    let body = read_manifest(&descriptor.digest)?;
    let document = ManifestDocument::parse(&body, &descriptor.media_type)
        .map_err(|err| CliError::Operational(format!("decode cached manifest: {err}")))?;
    let (manifest, annotations, digest, platform) = match document {
        ManifestDocument::Manifest(manifest) => {
            let annotations = manifest.annotations.clone();
            (
                manifest,
                annotations,
                descriptor.digest.clone(),
                "any".to_owned(),
            )
        }
        ManifestDocument::Index(index) => {
            let child = select_child_descriptor(&index.manifests, platform)?;
            let child_body = read_manifest(&child.digest)?;
            let child_doc =
                ManifestDocument::parse(&child_body, &child.media_type).map_err(|err| {
                    CliError::Operational(format!("decode cached child manifest: {err}"))
                })?;
            let ManifestDocument::Manifest(manifest) = child_doc else {
                return Err(CliError::Operational(
                    "cached image index child resolved to another index".to_owned(),
                ));
            };
            let platform = child
                .platform
                .as_ref()
                .map_or_else(|| "any".to_owned(), crate::app::Platform::label);
            (manifest, index.annotations, child.digest.clone(), platform)
        }
    };
    validate_app_manifest(&manifest)?;
    let config_media_type = manifest.config.media_type.clone();
    let config_digest = manifest.config.digest.clone();
    let config_bytes = verify_cached_blob(&config_digest)?;
    Ok(ResolvedCachedPackage {
        manifest,
        annotations,
        digest,
        platform,
        config_media_type,
        config_digest,
        config_bytes,
    })
}

fn validate_app_manifest(manifest: &ImageManifest) -> Result<()> {
    if manifest.schema_version != 2
        || manifest.artifact_type != APP_ARTIFACT_TYPE
        || manifest.config.media_type != APP_CONFIG_MEDIA_TYPE
    {
        return Err(CliError::NotFound(
            "cached manifest is not an ORC app artifact".to_owned(),
        ));
    }
    Ok(())
}

fn select_child_descriptor<'a>(
    children: &'a [Descriptor],
    platform: Option<&str>,
) -> Result<&'a Descriptor> {
    if let Some(platform) = platform {
        return children
            .iter()
            .find(|child| {
                child
                    .platform
                    .as_ref()
                    .is_some_and(|item| item.label() == platform)
            })
            .ok_or_else(|| no_matching_platform(children));
    }
    if children.len() == 1 {
        return children
            .first()
            .ok_or_else(|| no_matching_platform(children));
    }
    let host = host_platform_label();
    children
        .iter()
        .find(|child| {
            child
                .platform
                .as_ref()
                .is_some_and(|item| item.label() == host)
        })
        .ok_or_else(|| no_matching_platform(children))
}

fn no_matching_platform(children: &[Descriptor]) -> CliError {
    let available = children
        .iter()
        .filter_map(|descriptor| descriptor.platform.as_ref())
        .map(crate::app::Platform::label)
        .collect::<Vec<_>>()
        .join(", ");
    CliError::NotFound(format!("no matching platform; available: {available}"))
}

fn host_platform_label() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}/{architecture}")
}

fn cached_payloads(layers: &[Descriptor]) -> Result<Vec<OutputFile>> {
    let mut grouped: std::collections::BTreeMap<String, Vec<&Descriptor>> =
        std::collections::BTreeMap::new();
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
        outputs.push(cached_file(&title, layer)?);
    }
    Ok(outputs)
}

fn cached_file(title: &str, layer: &Descriptor) -> Result<OutputFile> {
    let blob = verify_cached_blob(&layer.digest)?;
    let body = if has_chunked_suffix(&layer.media_type) {
        // Single-blob chunked-zstd layer (spec 146): decode via the shared reader.
        read_chunked_blob(&blob, &layer.annotations, &layer.digest)?
    } else if layer.media_type.starts_with(ORC_PAYLOAD_NAMESPACE) {
        // An ORC-internal payload encoding this client cannot decode (e.g. the
        // deleted legacy `chunk.v1[+zstd]` format) fails loudly.
        return Err(CliError::Operational(format!(
            "payload {title:?} uses unsupported media type {:?}; \
             this client cannot decode it (re-push the artifact in the current format)",
            layer.media_type
        )));
    } else {
        blob
    };
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

fn public_annotations(
    annotations: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    annotations
        .iter()
        .filter(|(key, _)| !key.starts_with("vnd.orc8r."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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

fn ref_key(reference: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    format!("{:x}.json", hasher.finalize())
}

fn is_sha256_hex(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}
