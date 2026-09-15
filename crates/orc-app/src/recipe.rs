use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::app::{
    APP_ARTIFACT_TYPE, APP_CONFIG_MEDIA_TYPE, OCI_EMPTY_BLOB, OCI_EMPTY_MEDIA_TYPE,
    OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST, OS_RECIPE_ARTIFACT_TYPE, OS_RECIPE_CONFIG_MEDIA_TYPE,
    Platform, RECIPE_ARTIFACT_TYPE, RECIPE_MEDIA_TYPE,
};
use crate::error::{CliError, Result};
use crate::progress::{ProgressEvent, ProgressKind, ProgressPhase, ProgressReporter};
use crate::registry::digest_bytes;

const OCI_MANIFEST_MEDIA_TYPE: &str = OCI_IMAGE_MANIFEST;

const KVM_ARTIFACT_TYPE: &str = "application/vnd.orc8r.kvm.image.v1";
const KVM_CONFIG_MEDIA_TYPE: &str = "application/vnd.orc8r.kvm.image.config.v1+json";

/// Options controlling recipe builds (e.g. boot-time seeding vs CLI builds).
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildOptions {
    /// When set, rejects `files:` entries with remote `url:` and never downloads.
    pub offline: bool,
    /// When set, declared platforms whose local `files:` are missing are skipped
    /// instead of failing the build; `url:`-sourced files count as present.
    /// Errors when no declared platform has all files present.
    pub skip_missing_platforms: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

fn descriptor_for(media_type: &str, body: &[u8]) -> Result<CachedDescriptor> {
    Ok(CachedDescriptor {
        media_type: media_type.to_owned(),
        digest: digest_bytes(body),
        size: body
            .len()
            .try_into()
            .map_err(|_| CliError::Operational("artifact body is too large".to_owned()))?,
    })
}

#[derive(Debug, Clone)]
pub struct BuildArtifact {
    pub root: CachedDescriptor,
    pub manifests: Vec<ManifestBlob>,
    pub blobs: Vec<Blob>,
    /// Reference (`repository:tag`) derived from the recipe's OCI annotations
    /// (`org.opencontainers.image.title` / `.version`). `None` when no title is set.
    pub default_reference: Option<String>,
    /// The verbatim `artifact.yaml` attached as an OCI recipe referrer of `root`.
    pub recipe: Option<RecipeReferrer>,
}

/// The source recipe attached to a package as an `application/vnd.orc8r.recipe.v1`
/// referrer: the referrer manifest, its blobs (recipe + empty config), and the
/// subject (package manifest/index) it points at.
#[derive(Debug, Clone)]
pub struct RecipeReferrer {
    pub manifest: ManifestBlob,
    pub blobs: Vec<Blob>,
}

const ANNOTATION_TITLE: &str = "org.opencontainers.image.title";
const ANNOTATION_VERSION: &str = "org.opencontainers.image.version";

/// Derives a default `repository:tag` reference from recipe annotations.
/// Title is required; version defaults to `default` when absent.
fn default_reference(annotations: &BTreeMap<String, String>) -> Option<String> {
    let title = annotations.get(ANNOTATION_TITLE)?;
    let version = annotations
        .get(ANNOTATION_VERSION)
        .map_or("default", String::as_str);
    Some(format!("{title}:{version}"))
}

#[derive(Debug, Clone)]
pub struct ManifestBlob {
    pub descriptor: CachedDescriptor,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Blob {
    pub digest: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipe {
    artifact_type: String,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    config: YamlValue,
    #[serde(default)]
    files: Vec<FileEntry>,
    #[serde(default)]
    platforms: Vec<RecipePlatform>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FileEntry {
    Path(String),
    Object {
        path: String,
        #[serde(default)]
        url: Option<String>,
        #[serde(default)]
        sha256: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct RecipePlatform {
    os: String,
    #[serde(rename = "arch")]
    architecture: String,
    #[serde(default)]
    variant: String,
    /// Build-time template substitution values for this platform, spliced into the
    /// recipe's `config`, `path`, `url`, and `sha256` scalars while the package is
    /// built. Distinct from an app assignment's `params`, which are the run-time
    /// values an operator hands the installed app: `vars` never leave the recipe.
    #[serde(default)]
    vars: BTreeMap<String, String>,
}

impl RecipePlatform {
    fn platform(&self) -> Platform {
        Platform {
            os: self.os.clone(),
            architecture: self.architecture.clone(),
            variant: self.variant.clone(),
        }
    }
}

#[derive(Debug)]
struct BuildContext {
    platform: Option<RecipePlatform>,
}

#[derive(Debug)]
struct FileMaterial {
    title: String,
    body: Vec<u8>,
    executable: bool,
}

/// Builds an OCI artifact from an `artifact.yaml` directory.
///
/// # Errors
///
/// Returns an error when the recipe cannot be read or parsed, a referenced
/// material is missing, or assembling the artifact layers fails.
pub async fn build_artifact(
    root: &Path,
    platforms: &[Platform],
    reporter: Option<&dyn ProgressReporter>,
    options: BuildOptions,
    extra_annotations: &BTreeMap<String, String>,
) -> Result<BuildArtifact> {
    let recipe_path = root.join("artifact.yaml");
    let body = std::fs::read(&recipe_path)
        .map_err(|err| CliError::Usage(format!("read {}: {err}", recipe_path.display())))?;
    let mut recipe: Recipe = serde_yaml::from_slice(&body)
        .map_err(|err| CliError::Usage(format!("parse {}: {err}", recipe_path.display())))?;
    // Caller-supplied annotations (e.g. a build-version stamp) override recipe
    // values and are baked into the produced manifest/index bytes, so a later
    // reader can recover them from the tagged manifest.
    for (key, value) in extra_annotations {
        recipe.annotations.insert(key.clone(), value.clone());
    }
    let config_media_type = config_media_type(&recipe.artifact_type)?;
    // An os.recipe payload must ingest as a single plain un-chunked blob (this twin already
    // caches every layer as a whole blob); enforce its single-layer/no-templating contract.
    if recipe.artifact_type == OS_RECIPE_ARTIFACT_TYPE {
        validate_os_recipe(&recipe)?;
    }
    let default_reference = default_reference(&recipe.annotations);
    let mut contexts = build_contexts(&recipe, platforms)?;
    if options.skip_missing_platforms {
        let mut present = Vec::new();
        for context in contexts {
            // Platformless recipes stay strict: only declared platforms are skipped.
            if context.platform.is_none() || local_files_present(root, &recipe, &context)? {
                present.push(context);
            }
        }
        if present.is_empty() {
            return Err(CliError::NotFound(
                "no declared platform has all local files present".to_owned(),
            ));
        }
        contexts = present;
    }
    let mut manifests = Vec::new();
    let mut blobs = Vec::new();
    let mut index_entries = Vec::new();
    for context in contexts {
        let built = build_manifest(
            root,
            &recipe,
            config_media_type,
            &context,
            reporter,
            options,
        )
        .await?;
        blobs.extend(built.blobs);
        if let Some(platform) = context.platform.as_ref() {
            index_entries.push(IndexEntry {
                media_type: OCI_MANIFEST_MEDIA_TYPE.to_owned(),
                digest: built.manifest.descriptor.digest.clone(),
                size: built.manifest.descriptor.size,
                platform: platform.platform(),
            });
        }
        manifests.push(built.manifest);
    }
    blobs.sort_by(|left, right| left.digest.cmp(&right.digest));
    blobs.dedup_by(|left, right| left.digest == right.digest);
    let root = if index_entries.is_empty() {
        manifests
            .first()
            .ok_or_else(|| CliError::Operational("build produced no manifest".to_owned()))?
            .descriptor
            .clone()
    } else {
        index_entries.sort_by_key(|entry| entry.platform.label());
        let index = ImageIndex {
            schema_version: 2,
            media_type: OCI_IMAGE_INDEX,
            artifact_type: recipe.artifact_type.clone(),
            manifests: index_entries,
            annotations: recipe.annotations.clone(),
        };
        let index_body = serde_json::to_vec(&index)
            .map_err(|err| CliError::Operational(format!("encode image index: {err}")))?;
        let descriptor = descriptor_for(OCI_IMAGE_INDEX, &index_body)?;
        manifests.push(ManifestBlob {
            descriptor: descriptor.clone(),
            body: index_body,
        });
        descriptor
    };
    // Embed the verbatim artifact.yaml as a recipe referrer of the package so
    // `orc clone` can recover the author source byte-for-byte.
    let recipe_referrer = build_recipe_referrer(&body, &root, &recipe.annotations)?;
    Ok(BuildArtifact {
        root,
        manifests,
        blobs,
        default_reference,
        recipe: Some(recipe_referrer),
    })
}

/// Builds the recipe referrer manifest: the verbatim `artifact.yaml` as an
/// `application/vnd.orc8r.recipe.v1` referrer whose `subject` is the package.
fn build_recipe_referrer(
    recipe_bytes: &[u8],
    subject: &CachedDescriptor,
    annotations: &BTreeMap<String, String>,
) -> Result<RecipeReferrer> {
    let recipe_digest = digest_bytes(recipe_bytes);
    let recipe_size: u64 = recipe_bytes
        .len()
        .try_into()
        .map_err(|_| CliError::Operational("recipe is too large".to_owned()))?;
    let empty_blob = OCI_EMPTY_BLOB.to_vec();
    let empty_digest = digest_bytes(&empty_blob);
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE,
        artifact_type: RECIPE_ARTIFACT_TYPE.to_owned(),
        config: Descriptor {
            media_type: OCI_EMPTY_MEDIA_TYPE.to_owned(),
            digest: empty_digest.clone(),
            size: empty_blob.len().try_into().unwrap_or(2),
            annotations: BTreeMap::new(),
        },
        layers: vec![Descriptor {
            media_type: RECIPE_MEDIA_TYPE.to_owned(),
            digest: recipe_digest.clone(),
            size: recipe_size,
            annotations: BTreeMap::from([(
                "org.opencontainers.image.title".to_owned(),
                "artifact.yaml".to_owned(),
            )]),
        }],
        annotations: annotations.clone(),
        subject: Some(Descriptor {
            media_type: subject.media_type.clone(),
            digest: subject.digest.clone(),
            size: subject.size,
            annotations: BTreeMap::new(),
        }),
    };
    let body = serde_json::to_vec(&manifest)
        .map_err(|err| CliError::Operational(format!("encode recipe manifest: {err}")))?;
    Ok(RecipeReferrer {
        manifest: ManifestBlob {
            descriptor: descriptor_for(OCI_MANIFEST_MEDIA_TYPE, &body)?,
            body,
        },
        blobs: vec![
            Blob {
                digest: recipe_digest,
                body: recipe_bytes.to_vec(),
            },
            Blob {
                digest: empty_digest,
                body: empty_blob,
            },
        ],
    })
}

struct BuiltManifest {
    manifest: ManifestBlob,
    blobs: Vec<Blob>,
}

async fn build_manifest(
    root: &Path,
    recipe: &Recipe,
    config_media_type: &str,
    context: &BuildContext,
    reporter: Option<&dyn ProgressReporter>,
    options: BuildOptions,
) -> Result<BuiltManifest> {
    let config = interpolate_yaml(&recipe.config, context)?;
    let config_bytes = serde_json::to_vec(&config)
        .map_err(|err| CliError::Operational(format!("encode config JSON: {err}")))?;
    validate_config(&recipe.artifact_type, &config_bytes)?;
    let config_digest = digest_bytes(&config_bytes);
    let mut blobs = vec![Blob {
        digest: config_digest.clone(),
        body: config_bytes.clone(),
    }];
    let mut layers = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in &recipe.files {
        let file = materialize_file(root, entry, context, reporter, options).await?;
        if !seen.insert(file.title.clone()) {
            return Err(CliError::Usage(format!(
                "duplicate file path {:?}",
                file.title
            )));
        }
        let digest = digest_bytes(&file.body);
        let mut annotations =
            BTreeMap::from([("org.opencontainers.image.title".to_owned(), file.title)]);
        if file.executable {
            annotations.insert("vnd.orc8r.file.executable".to_owned(), "true".to_owned());
        }
        layers.push(Descriptor {
            media_type: media_type_for_bytes(&file.body),
            digest: digest.clone(),
            size: file
                .body
                .len()
                .try_into()
                .map_err(|_| CliError::Operational("payload is too large".to_owned()))?,
            annotations,
        });
        blobs.push(Blob {
            digest,
            body: file.body,
        });
    }
    layers.sort_by(|left, right| {
        layer_title(left)
            .unwrap_or_default()
            .cmp(layer_title(right).unwrap_or_default())
    });
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE,
        artifact_type: recipe.artifact_type.clone(),
        config: Descriptor {
            media_type: config_media_type.to_owned(),
            digest: config_digest,
            size: config_bytes
                .len()
                .try_into()
                .map_err(|_| CliError::Operational("config is too large".to_owned()))?,
            annotations: BTreeMap::new(),
        },
        layers,
        annotations: recipe.annotations.clone(),
        subject: None,
    };
    let body = serde_json::to_vec(&manifest)
        .map_err(|err| CliError::Operational(format!("encode manifest: {err}")))?;
    Ok(BuiltManifest {
        manifest: ManifestBlob {
            descriptor: descriptor_for(OCI_MANIFEST_MEDIA_TYPE, &body)?,
            body,
        },
        blobs,
    })
}

async fn materialize_file(
    root: &Path,
    entry: &FileEntry,
    context: &BuildContext,
    reporter: Option<&dyn ProgressReporter>,
    options: BuildOptions,
) -> Result<FileMaterial> {
    let (path, url, sha256) = match entry {
        FileEntry::Path(path) => (path.as_str(), None, None),
        FileEntry::Object { path, url, sha256 } => {
            if options.offline && url.is_some() {
                return Err(CliError::Usage(format!(
                    "offline build rejects remote file {path:?}"
                )));
            }
            (path.as_str(), url.as_deref(), sha256.as_deref())
        }
    };
    let interpolated_path = interpolate_string(path, context)?;
    let relative = safe_relative_path(&interpolated_path)?;
    let title = relative
        .iter()
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    let local = root.join(&relative);
    let expected = sha256
        .map(|value| interpolate_string(value, context))
        .transpose()?;
    let body = file_bytes(&local, url, expected.as_deref(), reporter, &title, options).await?;
    let executable = is_executable(&local);
    Ok(FileMaterial {
        title,
        body,
        executable,
    })
}

/// Reports whether every `files:` entry without a remote `url:` resolves to an
/// existing local file for this context; `url:`-sourced entries count as present.
fn local_files_present(root: &Path, recipe: &Recipe, context: &BuildContext) -> Result<bool> {
    for entry in &recipe.files {
        let path = match entry {
            FileEntry::Object { url: Some(_), .. } => continue,
            FileEntry::Path(path) | FileEntry::Object { path, .. } => path.as_str(),
        };
        let interpolated_path = interpolate_string(path, context)?;
        let relative = safe_relative_path(&interpolated_path)?;
        if !root.join(relative).exists() {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn file_bytes(
    path: &Path,
    url: Option<&str>,
    expected: Option<&str>,
    reporter: Option<&dyn ProgressReporter>,
    title: &str,
    options: BuildOptions,
) -> Result<Vec<u8>> {
    if options.offline && url.is_some() {
        return Err(CliError::Usage(format!(
            "offline build rejects remote file {}",
            path.display()
        )));
    }
    if path.exists() {
        let body = std::fs::read(path)
            .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
        if expected.is_none_or(|sha| sha256_matches(&body, sha).is_ok_and(|matches| matches)) {
            return Ok(body);
        }
    }
    let Some(url) = url else {
        let body = std::fs::read(path)
            .map_err(|err| CliError::Usage(format!("read {}: {err}", path.display())))?;
        verify_sha256(&body, expected)?;
        return Ok(body);
    };
    let body = download_file(url, reporter, title).await?;
    verify_sha256(&body, expected)?;
    report_file(reporter, title, &ProgressPhase::Writing);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Operational(format!("create {}: {err}", parent.display())))?;
    }
    std::fs::write(path, &body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))?;
    report_file(reporter, title, &ProgressPhase::Done);
    Ok(body)
}

/// Streams a URL into memory, emitting byte-level download progress keyed by the
/// destination file title.
async fn download_file(
    url: &str,
    reporter: Option<&dyn ProgressReporter>,
    title: &str,
) -> Result<Vec<u8>> {
    use futures_util::StreamExt as _;

    let response = reqwest::get(url)
        .await
        .map_err(|err| CliError::Operational(format!("download {url}: {err}")))?
        .error_for_status()
        .map_err(|err| CliError::Operational(format!("download {url}: {err}")))?;
    let total = response.content_length();
    report_file(
        reporter,
        title,
        &ProgressPhase::Downloading { done: 0, total },
    );
    let mut body = Vec::with_capacity(usize::try_from(total.unwrap_or(0)).unwrap_or(0));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|err| CliError::Operational(format!("read download {url}: {err}")))?;
        body.extend_from_slice(&chunk);
        report_file(
            reporter,
            title,
            &ProgressPhase::Downloading {
                done: u64::try_from(body.len()).unwrap_or(u64::MAX),
                total,
            },
        );
    }
    Ok(body)
}

fn report_file(reporter: Option<&dyn ProgressReporter>, title: &str, phase: &ProgressPhase) {
    if let Some(reporter) = reporter {
        reporter.report(ProgressEvent::new(title, ProgressKind::File, phase.clone()));
    }
}

fn build_contexts(recipe: &Recipe, selected: &[Platform]) -> Result<Vec<BuildContext>> {
    if recipe.platforms.is_empty() {
        if !selected.is_empty() {
            return Ok(vec![BuildContext { platform: None }]);
        }
        return Ok(vec![BuildContext { platform: None }]);
    }
    let mut contexts = Vec::new();
    for platform in &recipe.platforms {
        if selected.is_empty()
            || selected
                .iter()
                .any(|selected| selected.label() == platform.platform().label())
        {
            contexts.push(BuildContext {
                platform: Some(platform.clone()),
            });
        }
    }
    if contexts.is_empty() {
        let available = recipe
            .platforms
            .iter()
            .map(|platform| platform.platform().label())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CliError::NotFound(format!(
            "no matching platform; available: {available}"
        )));
    }
    Ok(contexts)
}

fn interpolate_yaml(value: &YamlValue, context: &BuildContext) -> Result<JsonValue> {
    match value {
        YamlValue::Null => Ok(JsonValue::Null),
        YamlValue::Bool(value) => Ok(JsonValue::Bool(*value)),
        YamlValue::Number(value) => serde_json::to_value(value)
            .map_err(|err| CliError::Operational(format!("convert YAML number: {err}"))),
        YamlValue::String(value) => interpolate_string(value, context).map(JsonValue::String),
        YamlValue::Sequence(values) => values
            .iter()
            .map(|value| interpolate_yaml(value, context))
            .collect::<Result<Vec<_>>>()
            .map(JsonValue::Array),
        YamlValue::Mapping(values) => {
            let mut object = serde_json::Map::new();
            for (key, value) in values {
                let YamlValue::String(key) = key else {
                    return Err(CliError::Usage("config keys must be strings".to_owned()));
                };
                object.insert(key.clone(), interpolate_yaml(value, context)?);
            }
            Ok(JsonValue::Object(object))
        }
        YamlValue::Tagged(value) => interpolate_yaml(&value.value, context),
    }
}

fn interpolate_string(input: &str, context: &BuildContext) -> Result<String> {
    let mut output = String::new();
    let mut rest = input;
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('}') else {
            return Err(CliError::Usage(format!(
                "unclosed interpolation in {input:?}"
            )));
        };
        let key = &after_start[..end];
        output.push_str(&interpolation_value(key, context).ok_or_else(|| {
            CliError::Usage(format!("unresolved interpolation {{{key}}} in {input:?}"))
        })?);
        rest = &after_start[end + 1..];
    }
    if rest.contains('}') {
        return Err(CliError::Usage(format!(
            "unmatched interpolation in {input:?}"
        )));
    }
    output.push_str(rest);
    Ok(output)
}

fn interpolation_value(key: &str, context: &BuildContext) -> Option<String> {
    let platform = context.platform.as_ref()?;
    match key {
        "os" => Some(platform.os.clone()),
        "arch" => Some(platform.architecture.clone()),
        key => platform.vars.get(key).cloned(),
    }
}

fn safe_relative_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(CliError::Usage(format!(
            "file path {} must be relative",
            path.display()
        )));
    }
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => output.push(value),
            _ => {
                return Err(CliError::Usage(format!(
                    "file path {} must be a normalized relative path",
                    path.display()
                )));
            }
        }
    }
    if output.as_os_str().is_empty() {
        return Err(CliError::Usage("file path cannot be empty".to_owned()));
    }
    Ok(output)
}

fn config_media_type(artifact_type: &str) -> Result<&'static str> {
    match artifact_type {
        APP_ARTIFACT_TYPE => Ok(APP_CONFIG_MEDIA_TYPE),
        KVM_ARTIFACT_TYPE => Ok(KVM_CONFIG_MEDIA_TYPE),
        OS_RECIPE_ARTIFACT_TYPE => Ok(OS_RECIPE_CONFIG_MEDIA_TYPE),
        _ => Err(CliError::Usage(format!(
            "unsupported artifactType {artifact_type:?}"
        ))),
    }
}

fn validate_config(artifact_type: &str, body: &[u8]) -> Result<()> {
    if artifact_type == APP_ARTIFACT_TYPE {
        serde_json::from_slice::<crate::app::AppConfig>(body)
            .map_err(|err| CliError::Usage(format!("invalid app config: {err}")))?;
        // The recipe `config:` map becomes the config blob verbatim, so it answers to the
        // same authoring contract a directory push is held to (params vocabulary, endpoint
        // rules) — the author hears about a violation at build time, not at ingest.
        crate::package::validate_app_config(body)?;
    }
    if artifact_type == OS_RECIPE_ARTIFACT_TYPE {
        validate_os_recipe_config(body)?;
    }
    Ok(())
}

/// The os.recipe config blob is the artifact.yaml `config:` map serialized verbatim; it must
/// match the public OS recipe config shape (`{osinfo{id,name,…}, arch, disk_gb}`). It is
/// validated structurally here so malformed recipes fail at build time.
///
/// There is no `os` selector to check: a recipe's selector is derived from the
/// repository and tag it is published under (spec 134), so the config cannot state one.
fn validate_os_recipe_config(body: &[u8]) -> Result<()> {
    let value: JsonValue = serde_json::from_slice(body)
        .map_err(|err| CliError::Usage(format!("os.recipe config is not JSON: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Usage("os.recipe config must be a JSON object".to_owned()))?;
    for (key, ok) in [
        ("arch", object.get("arch").is_some_and(JsonValue::is_string)),
        (
            "disk_gb",
            object.get("disk_gb").is_some_and(JsonValue::is_u64),
        ),
        (
            "osinfo",
            object.get("osinfo").is_some_and(JsonValue::is_object),
        ),
    ] {
        if !ok {
            return Err(CliError::Usage(format!(
                "os.recipe config is missing or malformed required field {key:?}"
            )));
        }
    }
    Ok(())
}

/// Enforces the os.recipe artifact contract: exactly one payload layer as a single plain
/// un-chunked blob, and no `platforms:` templating (the
/// payload is a single disk image, not a per-`{os}-{arch}` matrix). This twin never chunks
/// layers, so the plain-format half of the contract holds for free.
fn validate_os_recipe(recipe: &Recipe) -> Result<()> {
    if recipe.files.len() != 1 {
        return Err(CliError::Usage(format!(
            "os.recipe artifact must declare exactly one payload file, found {}",
            recipe.files.len()
        )));
    }
    if !recipe.platforms.is_empty() {
        return Err(CliError::Usage(
            "os.recipe artifact does not support platforms: templating (single payload layer)"
                .to_owned(),
        ));
    }
    Ok(())
}

fn verify_sha256(body: &[u8], expected: Option<&str>) -> Result<()> {
    if let Some(expected) = expected
        && !sha256_matches(body, expected)?
    {
        return Err(CliError::Operational(format!(
            "sha256 mismatch: expected {expected}, got {}",
            digest_bytes(body)
        )));
    }
    Ok(())
}

fn sha256_matches(body: &[u8], expected: &str) -> Result<bool> {
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::Usage(format!("invalid sha256 {expected:?}")));
    }
    Ok(digest_bytes(body) == format!("sha256:{expected}"))
}

fn media_type_for_bytes(bytes: &[u8]) -> String {
    if let Some(kind) = infer::get(bytes) {
        return kind.mime_type().to_owned();
    }
    if bytes.starts_with(b"#!") {
        return "text/x-shellscript".to_owned();
    }
    if serde_json::from_slice::<JsonValue>(bytes).is_ok() {
        return "application/json".to_owned();
    }
    if std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
    }) {
        return "text/plain".to_owned();
    }
    "application/octet-stream".to_owned()
}

fn layer_title(descriptor: &Descriptor) -> Option<&str> {
    descriptor
        .annotations
        .get("org.opencontainers.image.title")
        .map(String::as_str)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o100 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    false
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageManifest {
    schema_version: u8,
    media_type: &'static str,
    artifact_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Descriptor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageIndex {
    schema_version: u8,
    media_type: &'static str,
    artifact_type: String,
    manifests: Vec<IndexEntry>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexEntry {
    media_type: String,
    digest: String,
    size: u64,
    platform: Platform,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anns(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn default_reference_uses_title_and_version() {
        let annotations = anns(&[(ANNOTATION_TITLE, "shell"), (ANNOTATION_VERSION, "1.0.1")]);
        assert_eq!(
            default_reference(&annotations),
            Some("shell:1.0.1".to_owned())
        );
    }

    #[test]
    fn default_reference_defaults_version_to_default() {
        let annotations = anns(&[(ANNOTATION_TITLE, "apt")]);
        assert_eq!(
            default_reference(&annotations),
            Some("apt:default".to_owned())
        );
    }

    #[test]
    fn default_reference_none_without_title() {
        let annotations = anns(&[(ANNOTATION_VERSION, "1.0.1")]);
        assert_eq!(default_reference(&annotations), None);
        assert_eq!(default_reference(&BTreeMap::new()), None);
    }

    #[tokio::test]
    async fn offline_build_rejects_remote_file_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("artifact.yaml"),
            "artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: demo
config:
  start:
    command: sh run.sh
files:
  - path: run.sh
    url: https://example.com/run.sh
",
        )
        .expect("write recipe");
        let err = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions {
                offline: true,
                ..BuildOptions::default()
            },
            &BTreeMap::new(),
        )
        .await
        .expect_err("remote url");
        assert!(matches!(err, CliError::Usage(_)));
    }

    fn write_two_platform_recipe(dir: &Path) {
        std::fs::write(
            dir.join("artifact.yaml"),
            "artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: demo
config:
  start:
    command: ./bin-{os}-{arch}
platforms:
  - os: linux
    arch: amd64
  - os: darwin
    arch: arm64
files:
  - bin-{os}-{arch}
",
        )
        .expect("write recipe");
    }

    #[tokio::test]
    async fn skip_missing_platforms_builds_only_present_platforms() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_two_platform_recipe(dir.path());
        std::fs::write(dir.path().join("bin-linux-amd64"), b"#!/bin/sh\n").expect("write binary");
        let artifact = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions {
                offline: true,
                skip_missing_platforms: true,
            },
            &BTreeMap::new(),
        )
        .await
        .expect("build");
        assert_eq!(artifact.root.media_type, OCI_IMAGE_INDEX);
        let index = artifact
            .manifests
            .iter()
            .find(|manifest| manifest.descriptor.digest == artifact.root.digest)
            .expect("index manifest");
        let index: JsonValue = serde_json::from_slice(&index.body).expect("parse index");
        let entries = index["manifests"].as_array().expect("manifests array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["platform"]["os"], "linux");
        assert_eq!(entries[0]["platform"]["architecture"], "amd64");
    }

    #[tokio::test]
    async fn strict_build_fails_on_missing_platform_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_two_platform_recipe(dir.path());
        std::fs::write(dir.path().join("bin-linux-amd64"), b"#!/bin/sh\n").expect("write binary");
        let err = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions::default(),
            &BTreeMap::new(),
        )
        .await
        .expect_err("missing darwin binary");
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[tokio::test]
    async fn skip_missing_platforms_errors_when_no_platform_files_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_two_platform_recipe(dir.path());
        let err = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions {
                offline: true,
                skip_missing_platforms: true,
            },
            &BTreeMap::new(),
        )
        .await
        .expect_err("no binaries");
        assert!(matches!(err, CliError::NotFound(_)));
    }

    /// The recipe `config:` map is the config blob: endpoints authored in
    /// `artifact.yaml` must arrive in the published blob unchanged.
    #[tokio::test]
    async fn recipe_config_round_trips_endpoints_into_the_config_blob() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("artifact.yaml"),
            "artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: demo
config:
  endpoints:
    pg:
      port: 5432
    metrics:
      port: 9187
      protocol: http
      probe:
        http: /metrics
        interval: 5s
  start:
    command: run
",
        )
        .expect("write recipe");
        let artifact = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions::default(),
            &BTreeMap::new(),
        )
        .await
        .expect("build");

        let manifest: JsonValue =
            serde_json::from_slice(&artifact.manifests[0].body).expect("parse manifest");
        let config_digest = manifest["config"]["digest"]
            .as_str()
            .expect("config digest");
        let config = artifact
            .blobs
            .iter()
            .find(|blob| blob.digest == config_digest)
            .expect("config blob");
        let config: crate::app::AppConfig =
            serde_json::from_slice(&config.body).expect("parse config blob");
        assert_eq!(config.endpoints["pg"].port, 5432);
        assert_eq!(
            config.endpoints["pg"].protocol,
            crate::app::EndpointProtocol::Tcp
        );
        let metrics = &config.endpoints["metrics"];
        assert_eq!(metrics.port, 9187);
        assert_eq!(metrics.protocol, crate::app::EndpointProtocol::Http);
        let probe = metrics.probe.as_ref().expect("probe");
        assert_eq!(probe.http.as_deref(), Some("/metrics"));
        assert_eq!(probe.interval.as_deref(), Some("5s"));
    }

    /// A recipe answers to the same authoring contract as a directory push, so an
    /// endpoint violation fails the build rather than reaching a registry.
    #[tokio::test]
    async fn recipe_build_rejects_invalid_endpoints() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("artifact.yaml"),
            "artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: demo
config:
  endpoints:
    Metrics:
      port: 9187
",
        )
        .expect("write recipe");
        let err = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions::default(),
            &BTreeMap::new(),
        )
        .await
        .expect_err("non-label endpoint name");
        assert!(
            matches!(&err, CliError::Usage(message) if message.contains("is not a DNS label")),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn skip_missing_platforms_keeps_url_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("artifact.yaml"),
            "artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: demo
config:
  start:
    command: ./bin-{os}-{arch}
platforms:
  - os: linux
    arch: amd64
  - os: darwin
    arch: arm64
files:
  - path: bin-{os}-{arch}
    url: https://example.com/bin-{os}-{arch}
",
        )
        .expect("write recipe");
        let err = build_artifact(
            dir.path(),
            &[],
            None,
            BuildOptions {
                offline: true,
                skip_missing_platforms: true,
            },
            &BTreeMap::new(),
        )
        .await
        .expect_err("offline url");
        // Url entries count as present, so the platforms survive filtering and
        // the build fails on the offline url rejection rather than NotFound.
        assert!(
            matches!(&err, CliError::Usage(message) if message.contains("offline build rejects")),
            "unexpected error: {err:?}"
        );
    }
}
