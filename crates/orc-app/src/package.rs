use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::app::{DOWNLOAD_ARTIFACT_TYPE, PersistBlock, ZSTD_CHUNKED_MEDIA_SUFFIX};
use crate::chunked::{
    CHUNK_SIZE_FLOOR, ChunkedEncodeOptions, DEFAULT_ZSTD_LEVEL, encode_chunked_layer,
};
use crate::error::{CliError, Result};
use crate::persist::PersistSpec;
use crate::registry::digest_bytes;

/// Payload layer framing chosen for a package (spec 146 §CLI Surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFormat {
    /// One whole-blob OCI layer per file. The only format used against registries that do
    /// not advertise the ORC chunked-upload extension.
    Plain,
    /// Single-blob chunked-zstd layer per file at/above the size floor (spec 146). Requires
    /// an `_orc`-capable registry to negotiate and dedup; readable only by orc consumers.
    ChunkedZstd,
}

/// Packaging knobs resolved from the CLI (`--format`, `--zstd-level`, `--no-compress`).
#[derive(Debug, Clone, Copy)]
pub struct PackageOptions {
    pub format: PackageFormat,
    /// `false` when `format` is only a default the caller computed without seeing the
    /// package: the packager may then override it once the artifact type is known. An
    /// operator who named `--format` gets exactly what they asked for.
    pub explicit_format: bool,
    pub zstd_level: i32,
    pub no_compress: bool,
}

impl Default for PackageOptions {
    fn default() -> Self {
        Self {
            format: PackageFormat::Plain,
            explicit_format: false,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            no_compress: false,
        }
    }
}

impl PackageOptions {
    fn encode(self) -> ChunkedEncodeOptions {
        ChunkedEncodeOptions {
            zstd_level: self.zstd_level,
            no_compress: self.no_compress,
        }
    }

    /// The framing for `artifact_type`. Download layers are served back as the published
    /// files, so their stored bytes must equal the source byte for byte — a merely defaulted
    /// chunked format drops to plain rather than re-framing them.
    fn resolve_format(self, artifact_type: &str) -> PackageFormat {
        if !self.explicit_format && artifact_type == DOWNLOAD_ARTIFACT_TYPE {
            PackageFormat::Plain
        } else {
            self.format
        }
    }
}

const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const ANNOTATIONS_FILE: &str = "annotations.json";
const VALID_X_SOURCE_KINDS: &[&str] = &[
    "peers.gossip",
    "peers.all",
    "peers.first",
    "peers.any",
    "pool.slot",
    "pool.name",
    "ca.bundle",
    "tls.cert",
    "tls.key",
];
const ENDPOINT_PROTOCOLS: &[&str] = &["tcp", "udp", "http", "https"];
/// Serve modes an endpoint may declare (spec 180). `role` is reserved for a later
/// field and is not accepted: refusing it now keeps its meaning open, where accepting
/// and ignoring it would ship a manifest key that silently does nothing.
const ENDPOINT_SERVE_MODES: &[&str] = &["primary", "spread"];
const ENDPOINT_PROBE_KINDS: &[&str] = &["tcp", "http", "command"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePlan {
    pub artifact_type: String,
    /// The framing the payloads were actually built with, after the artifact type had its
    /// say (see [`PackageOptions::explicit_format`]).
    pub format: PackageFormat,
    pub config_media_type: String,
    pub config_title: String,
    pub config_bytes: Vec<u8>,
    pub annotations: BTreeMap<String, String>,
    pub payloads: Vec<PayloadPlan>,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPlan {
    pub title: String,
    pub source: PathBuf,
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    pub executable: bool,
    pub body: Vec<u8>,
    /// `true` when `body` is an assembled chunked-zstd stream (spec 146) and `media_type`
    /// carries the `+zstd-chunked` suffix — the signal to upload via the negotiated `_orc`
    /// path rather than a whole-blob `PUT`.
    pub chunked: bool,
    annotations: BTreeMap<String, String>,
}

impl PayloadPlan {
    /// The descriptor annotations for this payload (the chunked-format TOC annotations for
    /// a chunked layer; empty for a whole blob).
    #[must_use]
    pub fn descriptor_annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InputEntry {
    title: String,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigIdentity {
    title: String,
    artifact_type: String,
    config_media_type: String,
}

/// Builds a deterministic OCI manifest plan for all non-hidden entries under `root`.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for invalid inputs, unsupported config schemas, reserved
/// annotations, missing configs, or duplicate layer titles. Returns [`CliError::Operational`]
/// when filesystem reads or manifest encoding fail.
pub fn plan_directory_push(root: &Path) -> Result<PackagePlan> {
    plan_push(root, &[], PackageOptions::default())
}

/// Builds a deterministic OCI manifest plan for the selected package inputs.
///
/// With [`PackageFormat::Plain`] each file becomes one whole-blob OCI layer (registry-side
/// content-defined chunking can still deduplicate it). With [`PackageFormat::ChunkedZstd`] each file at or above the
/// [`CHUNK_SIZE_FLOOR`] becomes a single-blob chunked-zstd layer (spec 146); smaller files
/// stay whole blobs. The assembled chunked stream is content-addressed like any other blob,
/// so the build cache and the push path both carry it verbatim. A chunked format the caller
/// only defaulted to ([`PackageOptions::explicit_format`]) drops to [`PackageFormat::Plain`]
/// for download artifacts, whose layers are the published files themselves.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for invalid inputs, unsupported config schemas, reserved
/// annotations, missing configs, or duplicate layer titles. Returns [`CliError::Operational`]
/// when filesystem reads, chunk encoding, or manifest encoding fail.
pub fn plan_push(root: &Path, paths: &[PathBuf], options: PackageOptions) -> Result<PackagePlan> {
    let entries = collect_entries(root, paths)?;
    build_plan(&entries, options)
}

fn collect_entries(root: &Path, paths: &[PathBuf]) -> Result<Vec<InputEntry>> {
    let mut entries = Vec::new();
    if paths.is_empty() {
        for entry in std::fs::read_dir(root)
            .map_err(|err| CliError::Operational(format!("read {}: {err}", root.display())))?
        {
            let entry =
                entry.map_err(|err| CliError::Operational(format!("read input entry: {err}")))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            collect_path(&entry.path(), Path::new(&name), &mut entries)?;
        }
    } else {
        for path in paths {
            let source = if path.is_absolute() {
                path.clone()
            } else {
                root.join(path)
            };
            let name = source
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| CliError::Usage(format!("invalid input path {}", path.display())))?;
            collect_path(&source, Path::new(name), &mut entries)?;
        }
    }
    entries.sort_by(|left, right| left.title.cmp(&right.title));
    Ok(entries)
}

fn collect_path(path: &Path, title: &Path, entries: &mut Vec<InputEntry>) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .map_err(|err| CliError::Usage(format!("read input {}: {err}", path.display())))?;
    if metadata.is_dir() {
        let mut children = std::fs::read_dir(path)
            .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| CliError::Operational(format!("read input entry: {err}")))?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let name = child.file_name();
            let child_title = title.join(name);
            collect_path(&child.path(), &child_title, entries)?;
        }
    } else if metadata.is_file() {
        entries.push(InputEntry {
            title: canonical_title(title)?,
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn build_plan(entries: &[InputEntry], options: PackageOptions) -> Result<PackagePlan> {
    let config_entries = entries
        .iter()
        .filter_map(|entry| config_identity(&entry.title).map(|identity| (entry, identity)))
        .collect::<Vec<_>>();
    let [(config_entry, config_identity)] = config_entries.as_slice() else {
        return Err(CliError::Usage(format!(
            "expected exactly one <artifact>.config.v<version>.json, found {}",
            config_entries.len()
        )));
    };

    // The framing default resolves only here: the artifact type decides whether chunked
    // re-framing is allowed at all.
    let options = PackageOptions {
        format: options.resolve_format(&config_identity.artifact_type),
        ..options
    };

    let config_bytes = std::fs::read(&config_entry.path).map_err(|err| {
        CliError::Operational(format!("read {}: {err}", config_entry.path.display()))
    })?;
    validate_app_config(&config_bytes)?;

    let annotations = read_annotations(entries)?;
    let mut seen_titles = BTreeSet::new();
    let mut payloads = Vec::new();
    for entry in entries {
        if entry.title == config_identity.title || entry.title == ANNOTATIONS_FILE {
            continue;
        }
        if !seen_titles.insert(entry.title.clone()) {
            return Err(CliError::Usage(format!(
                "duplicate payload title {:?}",
                entry.title
            )));
        }
        payloads.push(payload_plan(entry, options)?);
    }

    let manifest_bytes = manifest_bytes(
        &config_identity.artifact_type,
        &config_identity.config_media_type,
        &config_bytes,
        &annotations,
        &payloads,
    )?;
    let manifest_digest = digest_bytes(&manifest_bytes);
    Ok(PackagePlan {
        artifact_type: config_identity.artifact_type.clone(),
        format: options.format,
        config_media_type: config_identity.config_media_type.clone(),
        config_title: config_identity.title.clone(),
        config_bytes,
        annotations,
        payloads,
        manifest_bytes,
        manifest_digest,
    })
}

fn payload_plan(entry: &InputEntry, options: PackageOptions) -> Result<PayloadPlan> {
    let body = std::fs::read(&entry.path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", entry.path.display())))?;
    let base_media_type = media_type_for_title(&entry.title);
    // Chunk file entries at/above the size floor when the format is chunked-zstd; smaller
    // files (and every file under Plain) stay whole blobs.
    if options.format == PackageFormat::ChunkedZstd && body.len() >= CHUNK_SIZE_FLOOR {
        let layer = encode_chunked_layer(&body, &options.encode())?;
        let size = layer
            .blob
            .len()
            .try_into()
            .map_err(|_| CliError::Operational("chunked payload is too large".to_owned()))?;
        let annotations = layer.annotations();
        return Ok(PayloadPlan {
            title: entry.title.clone(),
            source: entry.path.clone(),
            media_type: format!("{base_media_type}{ZSTD_CHUNKED_MEDIA_SUFFIX}"),
            digest: layer.layer_digest,
            size,
            executable: is_executable(&entry.path),
            body: layer.blob,
            chunked: true,
            annotations,
        });
    }
    Ok(PayloadPlan {
        title: entry.title.clone(),
        source: entry.path.clone(),
        media_type: base_media_type,
        digest: digest_bytes(&body),
        size: body
            .len()
            .try_into()
            .map_err(|_| CliError::Operational("payload is too large".to_owned()))?,
        executable: is_executable(&entry.path),
        body,
        chunked: false,
        annotations: BTreeMap::new(),
    })
}

fn manifest_bytes(
    artifact_type: &str,
    config_media_type: &str,
    config_bytes: &[u8],
    annotations: &BTreeMap<String, String>,
    payloads: &[PayloadPlan],
) -> Result<Vec<u8>> {
    let mut manifest_annotations = annotations.clone();
    // Record the packager framing for the 142 contract. Per-layer media types are the
    // authoritative signal (whole blob vs `+zstd-chunked`); this manifest-level hint is
    // "zstd-chunked" when any layer is chunked, else "none".
    let chunker = if payloads.iter().any(|payload| payload.chunked) {
        "zstd-chunked"
    } else {
        "none"
    };
    manifest_annotations.insert("vnd.orc8r.chunker".to_owned(), chunker.to_owned());
    let manifest = Manifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE,
        artifact_type,
        config: Descriptor {
            media_type: config_media_type,
            digest: digest_bytes(config_bytes),
            size: config_bytes
                .len()
                .try_into()
                .map_err(|_| CliError::Operational("config is too large".to_owned()))?,
            annotations: BTreeMap::new(),
        },
        layers: payloads.iter().map(layer_descriptor).collect(),
        annotations: manifest_annotations,
    };
    serde_json::to_vec(&manifest)
        .map_err(|err| CliError::Operational(format!("encode manifest: {err}")))
}

fn layer_descriptor(payload: &PayloadPlan) -> Descriptor<'_> {
    let mut annotations = BTreeMap::from([(
        "org.opencontainers.image.title".to_owned(),
        payload.title.clone(),
    )]);
    annotations.extend(payload.annotations.clone());
    if payload.executable {
        annotations.insert("vnd.orc8r.file.executable".to_owned(), "true".to_owned());
    }
    Descriptor {
        media_type: &payload.media_type,
        digest: payload.digest.clone(),
        size: payload.size,
        annotations,
    }
}

fn config_identity(title: &str) -> Option<ConfigIdentity> {
    let basename = Path::new(title).file_name()?.to_str()?;
    let stem = basename.strip_suffix(".json")?;
    let (artifact_name, version) = stem.split_once(".config.v")?;
    if artifact_name.is_empty() || version.is_empty() || title != basename {
        return None;
    }
    Some(ConfigIdentity {
        title: title.to_owned(),
        artifact_type: format!("application/vnd.orc8r.{artifact_name}.v{version}"),
        config_media_type: format!("application/vnd.orc8r.{artifact_name}.config.v{version}+json"),
    })
}

fn read_annotations(entries: &[InputEntry]) -> Result<BTreeMap<String, String>> {
    let Some(entry) = entries.iter().find(|entry| entry.title == ANNOTATIONS_FILE) else {
        return Ok(BTreeMap::new());
    };
    let body = std::fs::read(&entry.path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", entry.path.display())))?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|err| CliError::Usage(format!("parse annotations.json: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Usage("annotations.json must be a JSON object".to_owned()))?;
    let mut annotations = BTreeMap::new();
    for (key, value) in object {
        if key.starts_with("vnd.orc8r.") {
            return Err(CliError::Usage(format!(
                "annotation key {key:?} uses reserved vnd.orc8r.* namespace"
            )));
        }
        let Some(value) = value.as_str() else {
            return Err(CliError::Usage(format!(
                "annotation value for {key:?} must be a string"
            )));
        };
        annotations.insert(key.clone(), value.to_owned());
    }
    Ok(annotations)
}

/// Validates an app config blob against the authoring contract: the closed params
/// vocabulary, the endpoint declarations, and the persistence contract.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the blob is not JSON or violates a contract rule.
pub fn validate_app_config(body: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|err| CliError::Usage(format!("parse config JSON: {err}")))?;
    validate_endpoints(&value)?;
    validate_params(&value)?;
    validate_persist_contract(&value)
}

/// The part of the contract a registry enforces on ingest: the config is a JSON
/// object, its `persist` block is well formed, and `footprint_gb` is an integer.
///
/// Deliberately narrower than [`validate_app_config`] — the authoring rules are the
/// packaging tool's to enforce, so a config published under an older vocabulary still
/// republishes unchanged.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the value is not an object or the persistence
/// declarations are malformed.
pub fn validate_persist_contract(value: &Value) -> Result<()> {
    if !value.is_object() {
        return Err(CliError::Usage("config must be a JSON object".to_owned()));
    }
    validate_persist(value)?;
    validate_footprint(value)
}

/// The `persist` block: the paths to keep and the hooks that bracket a capture.
fn validate_persist(value: &Value) -> Result<()> {
    let Some(persist) = value.get("persist") else {
        return Ok(());
    };
    let persist = persist
        .as_object()
        .ok_or_else(|| CliError::Usage("persist must be an object".to_owned()))?;
    let allowed = BTreeSet::from(["paths", "hook_pre", "hook_post"]);
    for key in persist.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(CliError::Usage(format!(
                "persist keyword {key:?} is not supported"
            )));
        }
    }
    let paths = persist
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::Usage("persist.paths must be an array".to_owned()))?;
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path
            .as_str()
            .ok_or_else(|| CliError::Usage("persist.paths entries must be strings".to_owned()))?;
        entries.push(path.to_owned());
    }
    PersistSpec::parse(&PersistBlock {
        paths: entries,
        hook_pre: None,
        hook_post: None,
    })
    .map_err(|err| CliError::Usage(err.to_string()))?;
    for name in ["hook_pre", "hook_post"] {
        validate_persist_hook(name, persist.get(name))?;
    }
    Ok(())
}

/// A capture hook is a lifecycle command phase: a command and a bound on it.
fn validate_persist_hook(name: &str, hook: Option<&Value>) -> Result<()> {
    let Some(hook) = hook else {
        return Ok(());
    };
    let hook = hook
        .as_object()
        .ok_or_else(|| CliError::Usage(format!("persist.{name} must be an object")))?;
    let allowed = BTreeSet::from(["command", "timeout"]);
    for key in hook.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(CliError::Usage(format!(
                "persist.{name} keyword {key:?} is not supported"
            )));
        }
    }
    if let Some(command) = hook.get("command") {
        let argv_ok = command
            .as_array()
            .is_some_and(|argv| !argv.is_empty() && argv.iter().all(Value::is_string));
        let string_ok = command
            .as_str()
            .is_some_and(|value| !value.trim().is_empty());
        if !argv_ok && !string_ok {
            return Err(CliError::Usage(format!(
                "persist.{name} command must be a non-empty string or argv array"
            )));
        }
    }
    if let Some(timeout) = hook.get("timeout")
        && !timeout.as_str().is_some_and(is_duration)
    {
        return Err(CliError::Usage(format!(
            "persist.{name} timeout must be a duration like \"10s\", \"1m\", or \"1h\""
        )));
    }
    Ok(())
}

/// `footprint_gb` is a planning figure, so only its type is a contract: an
/// over-declaration is clamped when the platform charges it, never refused here.
fn validate_footprint(value: &Value) -> Result<()> {
    let Some(footprint) = value.get("footprint_gb") else {
        return Ok(());
    };
    if footprint.as_u64().is_none() {
        return Err(CliError::Usage(
            "footprint_gb must be a non-negative integer".to_owned(),
        ));
    }
    Ok(())
}

/// Endpoint declarations: name, port, protocol, and probe rules.
fn validate_endpoints(value: &Value) -> Result<()> {
    let Some(endpoints) = value.get("endpoints") else {
        return Ok(());
    };
    let endpoints = endpoints
        .as_object()
        .ok_or_else(|| CliError::Usage("endpoints must be an object".to_owned()))?;
    let allowed = BTreeSet::from(["port", "protocol", "probe", "serve"]);
    // `(protocol, port)` keeps the protocol deliberately: tcp and udp on one number
    // legally coexist on a node (QUIC beside TCP on 443, DNS on 53).
    let mut listens: BTreeMap<(&str, u64), &String> = BTreeMap::new();
    for (name, endpoint) in endpoints {
        if !is_dns_label(name) {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} is not a DNS label (lowercase alphanumeric and '-', 1-63 characters, no leading or trailing '-')"
            )));
        }
        // An access name flattens `{project}--{pool}[--{endpoint}]` into one DNS
        // label (spec 187), so the separator is reserved in every component.
        if name.contains("--") {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} must not contain \"--\", which is reserved as the access-name separator"
            )));
        }
        let endpoint = endpoint
            .as_object()
            .ok_or_else(|| CliError::Usage(format!("endpoint {name:?} must be an object")))?;
        for key in endpoint.keys() {
            if !allowed.contains(key.as_str()) {
                return Err(CliError::Usage(format!(
                    "endpoint {name:?} keyword {key:?} is not supported"
                )));
            }
        }
        let port = endpoint
            .get("port")
            .ok_or_else(|| CliError::Usage(format!("endpoint {name:?} must declare port")))?;
        let port = port
            .as_u64()
            .filter(|port| (1..=65535).contains(port))
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "endpoint {name:?} port must be an integer in 1..=65535"
                ))
            })?;
        let protocol = match endpoint.get("protocol") {
            None => "tcp",
            Some(protocol) => protocol
                .as_str()
                .filter(|protocol| ENDPOINT_PROTOCOLS.contains(protocol))
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "endpoint {name:?} protocol must be one of tcp, udp, http, https"
                    ))
                })?,
        };
        // An unknown mode is refused rather than defaulted: a misspelled `spread`
        // that silently pins the pool to its slot-1 member is exactly the failure an
        // author would not see until production, so it fails the build instead.
        if let Some(serve) = endpoint.get("serve")
            && !serve
                .as_str()
                .is_some_and(|serve| ENDPOINT_SERVE_MODES.contains(&serve))
        {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} serve must be one of {}",
                ENDPOINT_SERVE_MODES.join(", ")
            )));
        }
        // Collisions compare transports: `http`/`https` are TCP listeners, so
        // tcp:443, http:443, and https:443 all fight over the same socket.
        let transport = if matches!(protocol, "http" | "https") {
            "tcp"
        } else {
            protocol
        };
        if let Some(other) = listens.insert((transport, port), name) {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} port {port} duplicates endpoint {other:?} on transport {transport:?}"
            )));
        }
        validate_endpoint_probe(name, protocol, endpoint.get("probe"))?;
    }
    Ok(())
}

fn validate_endpoint_probe(name: &String, protocol: &str, probe: Option<&Value>) -> Result<()> {
    let Some(probe) = probe else {
        return Ok(());
    };
    let probe = probe
        .as_object()
        .ok_or_else(|| CliError::Usage(format!("endpoint {name:?} probe must be an object")))?;
    let allowed = BTreeSet::from(["tcp", "http", "command", "interval", "timeout"]);
    for key in probe.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe keyword {key:?} is not supported"
            )));
        }
    }
    let kinds = ENDPOINT_PROBE_KINDS
        .iter()
        .filter(|kind| probe.contains_key(**kind))
        .count();
    if kinds != 1 {
        return Err(CliError::Usage(format!(
            "endpoint {name:?} probe must declare exactly one of tcp, http, command"
        )));
    }
    if let Some(tcp) = probe.get("tcp") {
        if tcp.as_bool() != Some(true) {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe.tcp must be true"
            )));
        }
        if protocol == "udp" {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe.tcp is not valid on a udp endpoint"
            )));
        }
    }
    if let Some(path) = probe.get("http") {
        if !matches!(protocol, "http" | "https") {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe.http requires protocol \"http\" or \"https\", not {protocol:?}"
            )));
        }
        if !path.as_str().is_some_and(|path| path.starts_with('/')) {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe.http must be a path starting with \"/\""
            )));
        }
    }
    if let Some(command) = probe.get("command") {
        let argv_ok = command
            .as_array()
            .is_some_and(|argv| !argv.is_empty() && argv.iter().all(Value::is_string));
        let string_ok = command
            .as_str()
            .is_some_and(|value| !value.trim().is_empty());
        if !argv_ok && !string_ok {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe.command must be a non-empty string or argv array"
            )));
        }
    }
    for field in ["interval", "timeout"] {
        let Some(value) = probe.get(field) else {
            continue;
        };
        if !value.as_str().is_some_and(is_duration) {
            return Err(CliError::Usage(format!(
                "endpoint {name:?} probe.{field} must be a duration like \"10s\", \"1m\", or \"1h\""
            )));
        }
    }
    Ok(())
}

/// RFC 1123 label: lowercase alphanumeric and `-`, 1–63 characters, no leading or
/// trailing `-`. Endpoint names must be embeddable in a hostname without a rename.
fn is_dns_label(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return false;
    }
    name.bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The `<integer>(s|m|h)` duration grammar the config blob uses everywhere.
fn is_duration(value: &str) -> bool {
    let digits = value.len()
        - value
            .trim_start_matches(|ch: char| ch.is_ascii_digit())
            .len();
    digits > 0
        && matches!(&value[digits..], "s" | "m" | "h")
        && value[..digits].parse::<u64>().is_ok()
}

#[allow(clippy::too_many_lines)]
fn validate_params(value: &Value) -> Result<()> {
    let Some(params) = value.get("params") else {
        return Ok(());
    };
    let object = params
        .as_object()
        .ok_or_else(|| CliError::Usage("params must be an object".to_owned()))?;
    let allowed_top = BTreeSet::from(["type", "properties", "required"]);
    for key in object.keys() {
        if !allowed_top.contains(key.as_str()) {
            return Err(CliError::Usage(format!(
                "params keyword {key:?} is not supported"
            )));
        }
    }
    if params.get("type").and_then(Value::as_str) != Some("object") {
        return Err(CliError::Usage("params.type must be \"object\"".to_owned()));
    }
    let properties = params
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Usage("params.properties must be an object".to_owned()))?;
    if let Some(required) = params.get("required") {
        let required = required
            .as_array()
            .ok_or_else(|| CliError::Usage("params.required must be an array".to_owned()))?;
        for name in required {
            let Some(name) = name.as_str() else {
                return Err(CliError::Usage(
                    "params.required entries must be strings".to_owned(),
                ));
            };
            if !properties.contains_key(name) {
                return Err(CliError::Usage(format!(
                    "params.required entry {name:?} has no property"
                )));
            }
        }
    }
    let allowed_property = BTreeSet::from([
        "type",
        "title",
        "description",
        "default",
        "enum",
        "contentMediaType",
        "sensitive",
        "placeholder",
        "x-source",
    ]);
    for (name, property) in properties {
        let property = property.as_object().ok_or_else(|| {
            CliError::Usage(format!("params property {name:?} must be an object"))
        })?;
        for key in property.keys() {
            if !allowed_property.contains(key.as_str()) {
                return Err(CliError::Usage(format!(
                    "params property {name:?} keyword {key:?} is not supported"
                )));
            }
        }
        let Some(kind) = property.get("type").and_then(Value::as_str) else {
            return Err(CliError::Usage(format!(
                "params property {name:?} must declare a type"
            )));
        };
        if !matches!(kind, "string" | "boolean" | "integer" | "number") {
            return Err(CliError::Usage(format!(
                "params property {name:?} has unsupported type {kind:?}"
            )));
        }
        if let Some(x_source) = property.get("x-source") {
            let x_source = x_source.as_object().ok_or_else(|| {
                CliError::Usage(format!(
                    "params property {name:?} x-source must be an object"
                ))
            })?;
            let allowed_x_source = BTreeSet::from(["kind", "params"]);
            for key in x_source.keys() {
                if !allowed_x_source.contains(key.as_str()) {
                    return Err(CliError::Usage(format!(
                        "params property {name:?} x-source keyword {key:?} is not supported"
                    )));
                }
            }
            let Some(kind) = x_source.get("kind").and_then(Value::as_str) else {
                return Err(CliError::Usage(format!(
                    "params property {name:?} x-source must declare kind"
                )));
            };
            if !VALID_X_SOURCE_KINDS.contains(&kind) {
                return Err(CliError::Usage(format!(
                    "params property {name:?} x-source kind {kind:?} is not supported"
                )));
            }
            if let Some(params) = x_source.get("params") {
                let params = params.as_object().ok_or_else(|| {
                    CliError::Usage(format!(
                        "params property {name:?} x-source.params must be an object"
                    ))
                })?;
                for (param_key, value) in params {
                    if !value.is_string() {
                        return Err(CliError::Usage(format!(
                            "params property {name:?} x-source.params.{param_key:?} must be a string"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn canonical_title(path: &Path) -> Result<String> {
    let components = path
        .iter()
        .map(|component| {
            component
                .to_str()
                .ok_or_else(|| CliError::Usage("input path is not UTF-8".to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() || components.iter().any(|component| component.is_empty()) {
        let title = path.display();
        return Err(CliError::Usage(format!("invalid layer title {title}")));
    }
    Ok(components.join("/"))
}

fn media_type_for_title(title: &str) -> String {
    match Path::new(title)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("json") => "application/json",
        Some("sh") => "text/x-shellscript",
        Some("txt") => "text/plain",
        Some("html") => "text/html",
        Some("wasm") => "application/wasm",
        Some("zip") => "application/zip",
        Some("tar") => "application/x-tar",
        Some("gz") => "application/gzip",
        Some("qcow2") => "application/x-qcow2",
        _ => "application/octet-stream",
    }
    .to_owned()
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
struct Manifest<'a> {
    schema_version: u8,
    media_type: &'a str,
    artifact_type: &'a str,
    config: Descriptor<'a>,
    layers: Vec<Descriptor<'a>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor<'a> {
    media_type: &'a str,
    digest: String,
    size: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{APP_ARTIFACT_TYPE, APP_CONFIG_MEDIA_TYPE};

    #[test]
    fn directory_plan_derives_media_types_and_excludes_sidecars() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("app.config.v1.json"),
            r#"{"params":{"type":"object","properties":{"url":{"type":"string"}}}}"#,
        )
        .expect("config");
        std::fs::write(
            dir.path().join("annotations.json"),
            r#"{"org.opencontainers.image.description":"demo"}"#,
        )
        .expect("annotations");
        std::fs::write(dir.path().join(".hidden"), b"ignored").expect("hidden");
        std::fs::write(dir.path().join("run.sh"), b"echo hi").expect("payload");

        let plan = plan_directory_push(dir.path()).expect("plan");
        assert_eq!(plan.artifact_type, APP_ARTIFACT_TYPE);
        assert_eq!(plan.config_media_type, APP_CONFIG_MEDIA_TYPE);
        assert_eq!(plan.payloads.len(), 1);
        assert_eq!(plan.payloads[0].title, "run.sh");
        assert_eq!(plan.payloads[0].media_type, "text/x-shellscript");
        assert_eq!(
            plan.annotations["org.opencontainers.image.description"],
            "demo"
        );
        let manifest: Value = serde_json::from_slice(&plan.manifest_bytes).expect("manifest");
        assert_eq!(manifest["schemaVersion"], 2);
        assert_eq!(manifest["artifactType"], APP_ARTIFACT_TYPE);
        assert_eq!(
            manifest["layers"][0]["annotations"]["org.opencontainers.image.title"],
            "run.sh"
        );
    }

    #[test]
    fn explicit_directory_titles_are_rooted_at_directory_basename() {
        let dir = tempfile::tempdir().expect("dir");
        let payload = dir.path().join("payload");
        std::fs::create_dir(&payload).expect("payload dir");
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        std::fs::write(payload.join("file.txt"), b"hello").expect("file");

        let plan = plan_push(
            dir.path(),
            &[
                PathBuf::from("app.config.v1.json"),
                PathBuf::from("payload"),
            ],
            PackageOptions::default(),
        )
        .expect("plan");
        assert_eq!(plan.payloads[0].title, "payload/file.txt");
    }

    #[test]
    fn small_files_stay_whole_blobs_under_both_formats() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        std::fs::write(dir.path().join("payload.bin"), vec![7u8; 4096]).expect("payload");

        // Even under the chunked format, a file below the size floor is a plain whole blob.
        for format in [PackageFormat::Plain, PackageFormat::ChunkedZstd] {
            let options = PackageOptions {
                format,
                ..PackageOptions::default()
            };
            let plan = plan_push(dir.path(), &[], options).expect("plan");
            assert_eq!(plan.payloads.len(), 1);
            let payload = &plan.payloads[0];
            assert_eq!(payload.title, "payload.bin");
            assert_eq!(payload.media_type, "application/octet-stream");
            assert_eq!(payload.body, vec![7u8; 4096]);
            assert!(!payload.chunked);
            assert!(payload.annotations.is_empty());
            let manifest: Value = serde_json::from_slice(&plan.manifest_bytes).expect("manifest");
            assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "none");
            assert_eq!(manifest["layers"].as_array().expect("layers").len(), 1);
        }
    }

    #[test]
    fn large_files_become_chunked_layers_under_the_chunked_format() {
        use crate::app::has_chunked_suffix;
        use crate::chunked::{locate_and_verify_toc, read_chunked_blob};

        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        // A compressible payload above the 8 MiB floor.
        let raw: Vec<u8> = (0..CHUNK_SIZE_FLOOR + 5_000_000)
            .map(|i| u8::try_from(i % 251).expect("< 251"))
            .collect();
        std::fs::write(dir.path().join("payload.bin"), &raw).expect("payload");

        let options = PackageOptions {
            format: PackageFormat::ChunkedZstd,
            ..PackageOptions::default()
        };
        let plan = plan_push(dir.path(), &[], options).expect("plan");
        let payload = &plan.payloads[0];
        assert!(payload.chunked, "large file is chunked");
        assert!(has_chunked_suffix(&payload.media_type));
        assert_eq!(payload.digest, digest_bytes(&payload.body));
        // The layer round-trips: TOC verifies and the reader reconstructs the raw bytes.
        locate_and_verify_toc(&payload.body, &payload.annotations).expect("toc verifies");
        let decoded = read_chunked_blob(&payload.body, &payload.annotations, &payload.digest)
            .expect("decode");
        assert_eq!(decoded, raw, "chunked layer decodes to the original file");
        let manifest: Value = serde_json::from_slice(&plan.manifest_bytes).expect("manifest");
        assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "zstd-chunked");
    }

    /// A download package: the marker config plus one archive above the chunking floor.
    fn write_download_package(dir: &Path, body: &[u8]) {
        std::fs::write(dir.join("download.config.v1.json"), "{}").expect("config");
        std::fs::write(dir.join("orc_linux_amd64.tar.gz"), body).expect("payload");
    }

    fn archive_bytes() -> Vec<u8> {
        (0..CHUNK_SIZE_FLOOR + 4096)
            .map(|i| u8::try_from(i % 251).expect("< 251"))
            .collect()
    }

    #[test]
    fn download_packages_default_to_byte_identical_plain_layers() {
        use sha2::{Digest as _, Sha256};

        let dir = tempfile::tempdir().expect("dir");
        let raw = archive_bytes();
        write_download_package(dir.path(), &raw);

        // Whatever compression knobs came along, an unforced chunked default stores the
        // file verbatim so the layer digest is the file's sha256.
        for (zstd_level, no_compress) in [(DEFAULT_ZSTD_LEVEL, false), (19, true)] {
            let options = PackageOptions {
                format: PackageFormat::ChunkedZstd,
                explicit_format: false,
                zstd_level,
                no_compress,
            };
            let plan = plan_push(dir.path(), &[], options).expect("plan");
            assert_eq!(plan.artifact_type, DOWNLOAD_ARTIFACT_TYPE);
            assert_eq!(plan.format, PackageFormat::Plain);
            assert_eq!(plan.payloads.len(), 1);
            let payload = &plan.payloads[0];
            assert_eq!(payload.title, "orc_linux_amd64.tar.gz");
            assert!(!payload.chunked);
            assert_eq!(payload.body, raw, "layer bytes are the file bytes");
            assert_eq!(payload.size, u64::try_from(raw.len()).expect("size"));
            assert_eq!(
                payload.digest,
                format!("sha256:{:x}", Sha256::digest(&raw)),
                "layer digest is the file's sha256"
            );
            assert_eq!(payload.media_type, "application/gzip");
            assert!(!crate::app::has_chunked_suffix(&payload.media_type));
            assert!(payload.annotations.is_empty());
            let manifest: Value = serde_json::from_slice(&plan.manifest_bytes).expect("manifest");
            assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "none");
        }
    }

    /// The display strings a download's pages and JSON surface are the publisher's:
    /// the OCI title/description keys travel from `annotations.json` onto the
    /// manifest verbatim, alongside the packager's own reserved annotation.
    #[test]
    fn download_annotations_carry_the_oci_display_keys_into_the_manifest() {
        let dir = tempfile::tempdir().expect("dir");
        write_download_package(dir.path(), b"orc linux binary");
        std::fs::write(
            dir.path().join("annotations.json"),
            r#"{"org.opencontainers.image.title":"orc CLI",
                "org.opencontainers.image.description":"The command line for ORC8R."}"#,
        )
        .expect("annotations");

        let plan = plan_push(dir.path(), &[], PackageOptions::default()).expect("plan");
        assert_eq!(plan.artifact_type, DOWNLOAD_ARTIFACT_TYPE);
        assert_eq!(
            plan.payloads.len(),
            1,
            "annotations.json is a sidecar, never a layer"
        );

        let manifest: Value = serde_json::from_slice(&plan.manifest_bytes).expect("manifest");
        let annotations = &manifest["annotations"];
        assert_eq!(annotations["org.opencontainers.image.title"], "orc CLI");
        assert_eq!(
            annotations["org.opencontainers.image.description"],
            "The command line for ORC8R."
        );
        assert_eq!(annotations["vnd.orc8r.chunker"], "none");
        assert_eq!(
            manifest["layers"][0]["annotations"]["org.opencontainers.image.title"],
            "orc_linux_amd64.tar.gz",
            "the layer keeps its own title: the file name it is served under"
        );
    }

    #[test]
    fn non_download_packages_keep_the_chunked_default() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        std::fs::write(dir.path().join("payload.bin"), archive_bytes()).expect("payload");

        let options = PackageOptions {
            format: PackageFormat::ChunkedZstd,
            explicit_format: false,
            ..PackageOptions::default()
        };
        let plan = plan_push(dir.path(), &[], options).expect("plan");
        assert_eq!(plan.format, PackageFormat::ChunkedZstd);
        assert!(plan.payloads[0].chunked);
    }

    #[test]
    fn explicit_chunked_format_is_honored_for_download_packages() {
        let dir = tempfile::tempdir().expect("dir");
        write_download_package(dir.path(), &archive_bytes());

        let options = PackageOptions {
            format: PackageFormat::ChunkedZstd,
            explicit_format: true,
            ..PackageOptions::default()
        };
        let plan = plan_push(dir.path(), &[], options).expect("plan");
        assert_eq!(plan.artifact_type, DOWNLOAD_ARTIFACT_TYPE);
        assert_eq!(plan.format, PackageFormat::ChunkedZstd);
        let payload = &plan.payloads[0];
        assert!(payload.chunked, "the operator's choice is sent as-is");
        assert!(crate::app::has_chunked_suffix(&payload.media_type));
    }

    #[test]
    fn empty_files_are_whole_layers() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        std::fs::write(dir.path().join("empty.txt"), []).expect("payload");

        let plan = plan_push(dir.path(), &[], PackageOptions::default()).expect("plan");
        assert_eq!(plan.payloads.len(), 1);
        assert_eq!(plan.payloads[0].media_type, "text/plain");
        assert!(plan.payloads[0].annotations.is_empty());
        assert!(plan.payloads[0].body.is_empty());
    }

    #[test]
    fn duplicate_or_missing_config_is_usage_error() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("a.txt"), b"x").expect("file");
        assert!(plan_directory_push(dir.path()).is_err());
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        std::fs::write(dir.path().join("kvm.image.config.v1.json"), "{}").expect("config2");
        assert!(plan_directory_push(dir.path()).is_err());
    }

    #[test]
    fn reserved_annotations_are_rejected() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("app.config.v1.json"), "{}").expect("config");
        std::fs::write(
            dir.path().join("annotations.json"),
            r#"{"vnd.orc8r.test":"x"}"#,
        )
        .expect("annotations");
        let err = plan_directory_push(dir.path()).expect_err("reserved");
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn params_schema_rejects_unsupported_keywords_and_types() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("app.config.v1.json"),
            r#"{"params":{"type":"object","properties":{"nested":{"type":"array"}}}}"#,
        )
        .expect("config");
        let err = plan_directory_push(dir.path()).expect_err("bad type");
        assert!(err.to_string().contains("unsupported type"));

        std::fs::write(
            dir.path().join("app.config.v1.json"),
            r#"{"params":{"type":"object","patternProperties":{},"properties":{}}}"#,
        )
        .expect("config");
        let err = plan_directory_push(dir.path()).expect_err("bad keyword");
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn params_schema_accepts_valid_x_source() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("app.config.v1.json"),
            r#"{"params":{"type":"object","properties":{"peers":{"type":"string","x-source":{"kind":"peers.all"}},"ca":{"type":"string","x-source":{"kind":"ca.bundle"}}}}}"#,
        )
        .expect("config");
        plan_directory_push(dir.path()).expect("valid x-source");
    }

    #[test]
    fn endpoints_packaging_round_trips_the_config_blob() {
        let dir = tempfile::tempdir().expect("dir");
        let config = r#"{"endpoints":{"pg":{"port":5432},"pg-udp":{"port":5432,"protocol":"udp","probe":{"command":["pg_isready"]}},"metrics":{"port":9187,"protocol":"http","serve":"spread","probe":{"http":"/metrics","interval":"5s","timeout":"2s"}}}}"#;
        std::fs::write(dir.path().join("app.config.v1.json"), config).expect("config");

        let plan = plan_directory_push(dir.path()).expect("valid endpoints");
        // The config blob is the authored bytes verbatim, so the endpoints survive packaging.
        assert_eq!(plan.config_bytes, config.as_bytes());
        let parsed = serde_json::from_slice::<crate::app::AppConfig>(&plan.config_bytes)
            .expect("config blob parses");
        assert_eq!(parsed.endpoints["pg"].port, 5432);
        assert_eq!(
            parsed.endpoints["metrics"].protocol,
            crate::app::EndpointProtocol::Http
        );
        assert_eq!(
            parsed.endpoints["metrics"].serve,
            crate::app::ServeMode::Spread
        );
        assert_eq!(parsed.endpoints["pg"].serve, crate::app::ServeMode::Primary);
    }

    /// Asserts each `(case, config blob, expected error fragment)` row is rejected with
    /// an error naming the endpoint and the offending field.
    fn assert_endpoints_rejected(cases: &[(&str, &str, &str)]) {
        for (case, config, expected) in cases {
            let err = validate_app_config(config.as_bytes()).expect_err(case);
            let message = err.to_string();
            assert!(
                message.contains(expected),
                "{case}: expected {expected:?} in {message:?}"
            );
        }
    }

    #[test]
    fn endpoint_validation_rejects_bad_declarations() {
        assert_endpoints_rejected(&[
            (
                "uppercase name",
                r#"{"endpoints":{"Metrics":{"port":9187}}}"#,
                "\"Metrics\" is not a DNS label",
            ),
            (
                "name with an underscore",
                r#"{"endpoints":{"pg_wire":{"port":5432}}}"#,
                "\"pg_wire\" is not a DNS label",
            ),
            (
                "name with a trailing dash",
                r#"{"endpoints":{"pg-":{"port":5432}}}"#,
                "\"pg-\" is not a DNS label",
            ),
            (
                "over-long name",
                r#"{"endpoints":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"port":1}}}"#,
                "is not a DNS label",
            ),
            (
                "name carrying the reserved access-name separator",
                r#"{"endpoints":{"pg--wire":{"port":5432}}}"#,
                "\"pg--wire\" must not contain \"--\"",
            ),
            (
                "duplicate (protocol, port)",
                r#"{"endpoints":{"pg":{"port":5432},"wire":{"port":5432,"protocol":"tcp"}}}"#,
                "\"wire\" port 5432 duplicates endpoint \"pg\" on transport \"tcp\"",
            ),
            (
                "http collides with tcp on the same port (both are TCP listeners)",
                r#"{"endpoints":{"api":{"port":443,"protocol":"http"},"raw":{"port":443,"protocol":"tcp"}}}"#,
                "\"raw\" port 443 duplicates endpoint \"api\" on transport \"tcp\"",
            ),
            (
                "missing port",
                r#"{"endpoints":{"pg":{"protocol":"tcp"}}}"#,
                "\"pg\" must declare port",
            ),
            (
                "port zero",
                r#"{"endpoints":{"pg":{"port":0}}}"#,
                "\"pg\" port must be an integer in 1..=65535",
            ),
            (
                "port above the range",
                r#"{"endpoints":{"pg":{"port":65536}}}"#,
                "\"pg\" port must be an integer in 1..=65535",
            ),
            (
                "unknown protocol",
                r#"{"endpoints":{"pg":{"port":5432,"protocol":"sctp"}}}"#,
                "\"pg\" protocol must be one of tcp, udp, http",
            ),
            (
                "unknown serve mode",
                r#"{"endpoints":{"pg":{"port":5432,"serve":"anycast"}}}"#,
                "\"pg\" serve must be one of primary, spread",
            ),
            (
                "serve is not a string",
                r#"{"endpoints":{"pg":{"port":5432,"serve":true}}}"#,
                "\"pg\" serve must be one of primary, spread",
            ),
            (
                "unknown endpoint keyword",
                r#"{"endpoints":{"pg":{"port":5432,"expose":"public"}}}"#,
                "\"pg\" keyword \"expose\" is not supported",
            ),
            // `role` is reserved rather than accepted: refusing it keeps the name
            // free for the field it is being held for.
            (
                "the reserved role keyword",
                r#"{"endpoints":{"pg":{"port":5432,"role":"writer"}}}"#,
                "\"pg\" keyword \"role\" is not supported",
            ),
            (
                "endpoint is not an object",
                r#"{"endpoints":{"pg":5432}}"#,
                "\"pg\" must be an object",
            ),
            (
                "endpoints is not an object",
                r#"{"endpoints":[{"port":5432}]}"#,
                "endpoints must be an object",
            ),
        ]);
    }

    #[test]
    fn endpoint_validation_rejects_bad_probes() {
        assert_endpoints_rejected(&[
            (
                "unknown probe keyword",
                r#"{"endpoints":{"pg":{"port":5432,"probe":{"tcp":true,"retries":3}}}}"#,
                "\"pg\" probe keyword \"retries\" is not supported",
            ),
            (
                "http probe on a tcp endpoint",
                r#"{"endpoints":{"pg":{"port":5432,"probe":{"http":"/health"}}}}"#,
                "\"pg\" probe.http requires protocol \"http\" or \"https\", not \"tcp\"",
            ),
            (
                "http probe on a udp endpoint",
                r#"{"endpoints":{"dns":{"port":53,"protocol":"udp","probe":{"http":"/health"}}}}"#,
                "\"dns\" probe.http requires protocol \"http\" or \"https\", not \"udp\"",
            ),
            (
                "tcp probe on a udp endpoint",
                r#"{"endpoints":{"dns":{"port":53,"protocol":"udp","probe":{"tcp":true}}}}"#,
                "\"dns\" probe.tcp is not valid on a udp endpoint",
            ),
            (
                "probe.tcp false",
                r#"{"endpoints":{"pg":{"port":5432,"probe":{"tcp":false}}}}"#,
                "\"pg\" probe.tcp must be true",
            ),
            (
                "two probe kinds",
                r#"{"endpoints":{"api":{"port":8080,"protocol":"http","probe":{"tcp":true,"http":"/healthz"}}}}"#,
                "\"api\" probe must declare exactly one of tcp, http, command",
            ),
            (
                "no probe kind",
                r#"{"endpoints":{"api":{"port":8080,"protocol":"http","probe":{"interval":"5s"}}}}"#,
                "\"api\" probe must declare exactly one of tcp, http, command",
            ),
            (
                "relative http probe path",
                r#"{"endpoints":{"api":{"port":8080,"protocol":"http","probe":{"http":"healthz"}}}}"#,
                "\"api\" probe.http must be a path starting with \"/\"",
            ),
            (
                "empty command probe",
                r#"{"endpoints":{"dns":{"port":53,"protocol":"udp","probe":{"command":[]}}}}"#,
                "\"dns\" probe.command must be a non-empty string or argv array",
            ),
            (
                "unitless probe interval",
                r#"{"endpoints":{"pg":{"port":5432,"probe":{"tcp":true,"interval":"10"}}}}"#,
                "\"pg\" probe.interval must be a duration",
            ),
            (
                "unitless probe timeout",
                r#"{"endpoints":{"pg":{"port":5432,"probe":{"tcp":true,"timeout":"2000ms"}}}}"#,
                "\"pg\" probe.timeout must be a duration",
            ),
            (
                "probe is not an object",
                r#"{"endpoints":{"pg":{"port":5432,"probe":"tcp"}}}"#,
                "\"pg\" probe must be an object",
            ),
        ]);
    }

    #[test]
    fn endpoint_validation_accepts_the_contract_surface() {
        let cases: &[(&str, &str)] = &[
            ("bare tcp endpoint", r#"{"endpoints":{"pg":{"port":5432}}}"#),
            (
                "tcp and udp may share a port",
                r#"{"endpoints":{"dns":{"port":53},"dns-udp":{"port":53,"protocol":"udp"}}}"#,
            ),
            (
                "http endpoint with an http probe and timings",
                r#"{"endpoints":{"metrics":{"port":9187,"protocol":"http","probe":{"http":"/metrics","interval":"10s","timeout":"5s"}}}}"#,
            ),
            (
                "http endpoint may keep the tcp probe",
                r#"{"endpoints":{"api":{"port":8080,"protocol":"http","probe":{"tcp":true}}}}"#,
            ),
            (
                "https endpoint with an http probe",
                r#"{"endpoints":{"api":{"port":8443,"protocol":"https","probe":{"http":"/healthz"}}}}"#,
            ),
            (
                "bare https endpoint",
                r#"{"endpoints":{"api":{"port":8443,"protocol":"https"}}}"#,
            ),
            (
                "udp endpoint with a command probe",
                r#"{"endpoints":{"dns":{"port":53,"protocol":"udp","probe":{"command":"dig @localhost"}}}}"#,
            ),
            (
                "single-character and digit-bearing labels",
                r#"{"endpoints":{"a":{"port":1},"h2-9":{"port":65535}}}"#,
            ),
            ("no endpoints at all", r#"{"start":{"command":"run"}}"#),
        ];
        for (case, config) in cases {
            validate_app_config(config.as_bytes()).unwrap_or_else(|err| panic!("{case}: {err}"));
        }
    }

    /// Asserts each `(case, config blob, expected error fragment)` row is rejected by
    /// the contract the registry gates on, not merely by the authoring rules.
    fn assert_persist_contract_rejected(cases: &[(&str, &str, &str)]) {
        for (case, config, expected) in cases {
            let value: Value = serde_json::from_str(config).expect("test config is JSON");
            let err = validate_persist_contract(&value).expect_err(case);
            let message = err.to_string();
            assert!(
                message.contains(expected),
                "{case}: expected {expected:?} in {message:?}"
            );
            validate_app_config(config.as_bytes()).expect_err(case);
        }
    }

    #[test]
    fn persist_validation_rejects_bad_declarations() {
        assert_persist_contract_rejected(&[
            (
                "config is not an object",
                r#"[{"persist":{"paths":["/srv/app"]}}]"#,
                "config must be a JSON object",
            ),
            (
                "persist is not an object",
                r#"{"persist":["/srv/app"]}"#,
                "persist must be an object",
            ),
            (
                "unknown persist keyword",
                r#"{"persist":{"paths":["/srv/app"],"hooks":{}}}"#,
                "persist keyword \"hooks\" is not supported",
            ),
            (
                "paths missing",
                r#"{"persist":{"hook_pre":{"command":"freeze"}}}"#,
                "persist.paths must be an array",
            ),
            (
                "paths is not an array",
                r#"{"persist":{"paths":"/srv/app"}}"#,
                "persist.paths must be an array",
            ),
            (
                "paths entry is not a string",
                r#"{"persist":{"paths":[7]}}"#,
                "persist.paths entries must be strings",
            ),
            (
                "no path to persist",
                r#"{"persist":{"paths":[]}}"#,
                "declares no path to persist",
            ),
            (
                "system root",
                r#"{"persist":{"paths":["/var"]}}"#,
                "is a system location",
            ),
            (
                "relative root",
                r#"{"persist":{"paths":["srv/app"]}}"#,
                "must be absolute",
            ),
            (
                "hole outside every root",
                r#"{"persist":{"paths":["/srv/app","!/srv/other"]}}"#,
                "is not inside any persisted path",
            ),
            (
                "pattern with a backslash",
                r#"{"persist":{"paths":["c:\\jenkins-agent","!**\\*.bkp"]}}"#,
                "must use \"/\" as its separator",
            ),
            (
                "hook is not an object",
                r#"{"persist":{"paths":["/srv/app"],"hook_pre":"freeze"}}"#,
                "persist.hook_pre must be an object",
            ),
            (
                "unknown hook keyword",
                r#"{"persist":{"paths":["/srv/app"],"hook_post":{"command":"thaw","retries":2}}}"#,
                "persist.hook_post keyword \"retries\" is not supported",
            ),
            (
                "empty hook command",
                r#"{"persist":{"paths":["/srv/app"],"hook_pre":{"command":"  "}}}"#,
                "persist.hook_pre command must be a non-empty string or argv array",
            ),
            (
                "hook timeout is not a duration",
                r#"{"persist":{"paths":["/srv/app"],"hook_pre":{"command":"freeze","timeout":"60"}}}"#,
                "persist.hook_pre timeout must be a duration",
            ),
            (
                "footprint is not an integer",
                r#"{"footprint_gb":"35"}"#,
                "footprint_gb must be a non-negative integer",
            ),
            (
                "footprint is negative",
                r#"{"footprint_gb":-1}"#,
                "footprint_gb must be a non-negative integer",
            ),
        ]);
    }

    #[test]
    fn persist_validation_accepts_the_contract_surface() {
        let cases: &[(&str, &str)] = &[
            ("no persist block at all", r#"{"start":{"command":"run"}}"#),
            (
                "a windows root with a hole and a capture filter",
                r#"{"persist":{"paths":["c:\\jenkins-agent","!c:/jenkins-agent/workspace","!**/*.bkp"]}}"#,
            ),
            (
                "hooks bracketing the capture",
                r#"{"persist":{"paths":["/var/lib/postgresql/data"],"hook_pre":{"command":"pg_backup_start","timeout":"60s"},"hook_post":{"command":["pg_backup_stop"]}}}"#,
            ),
            // A footprint is a planning figure: an over-declaration is clamped where it
            // is charged, so publishing it is never refused.
            ("a footprint above the clamp", r#"{"footprint_gb":500}"#),
            ("a zero footprint", r#"{"footprint_gb":0}"#),
        ];
        for (case, config) in cases {
            let value: Value = serde_json::from_str(config).expect("test config is JSON");
            validate_persist_contract(&value).unwrap_or_else(|err| panic!("{case}: {err}"));
            validate_app_config(config.as_bytes()).unwrap_or_else(|err| panic!("{case}: {err}"));
        }
    }

    #[test]
    fn persist_declarations_round_trip_the_config_blob() {
        let dir = tempfile::tempdir().expect("dir");
        let config = r#"{"persist":{"paths":["c:\\jenkins-agent","!c:/jenkins-agent/workspace"],"hook_pre":{"command":"freeze","timeout":"60s"}},"footprint_gb":35}"#;
        std::fs::write(dir.path().join("app.config.v1.json"), config).expect("config");

        let plan = plan_directory_push(dir.path()).expect("valid persist block");
        let parsed = serde_json::from_slice::<crate::app::AppConfig>(&plan.config_bytes)
            .expect("config blob parses");
        let persist = parsed.persist.as_ref().expect("persist block");
        assert_eq!(
            persist.paths,
            ["c:\\jenkins-agent", "!c:/jenkins-agent/workspace"]
        );
        assert!(persist.hook_post.is_none());
        assert_eq!(parsed.footprint_gb, Some(35));
        assert_eq!(
            crate::persist::effective_footprint_gb(&parsed),
            crate::persist::FOOTPRINT_MAX_GB.min(35)
        );
    }

    #[test]
    fn params_schema_rejects_invalid_x_source_kind() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("app.config.v1.json"),
            r#"{"params":{"type":"object","properties":{"peers":{"type":"string","x-source":{"kind":"peers.invalid"}}}}}"#,
        )
        .expect("config");
        let err = plan_directory_push(dir.path()).expect_err("bad x-source kind");
        assert!(err.to_string().contains("x-source kind"));
    }
}
