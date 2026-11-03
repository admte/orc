use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const APP_ARTIFACT_TYPE: &str = "application/vnd.orc8r.app.v1";
pub const APP_CONFIG_MEDIA_TYPE: &str = "application/vnd.orc8r.app.config.v1+json";

/// Format v2 (spec 214): params reach a phase only as the tokens its argv names.
pub const APP_V2_ARTIFACT_TYPE: &str = "application/vnd.orc8r.app.v2";
pub const APP_V2_CONFIG_MEDIA_TYPE: &str = "application/vnd.orc8r.app.config.v2+json";

/// The app's config blob as it is materialized into the app's work directory.
///
/// Every runtime that starts an app reads it from here — including the runtime
/// re-invoked as a start shim by a service manager, which has nothing else to go on.
pub const CONFIG_FILE: &str = "app.config.v1.json";

/// A format v2 app's config blob in its work directory. The file name is the format
/// marker: everything that later reads an installed app (the start shim, uninstall, a
/// rollback check) knows from it which contract the app was written against.
pub const CONFIG_FILE_V2: &str = "app.config.v2.json";

const APP_ARTIFACT_PREFIX: &str = "application/vnd.orc8r.app.v";
const APP_CONFIG_PREFIX: &str = "application/vnd.orc8r.app.config.v";

/// Which app package contract a config was written against.
///
/// The config blob does not say: its media type, the manifest's `artifactType` and the
/// config file's name in a work directory do. So every place that turns bytes into an
/// [`AppConfig`] is handed the format by whoever knew it ([`AppConfig::parse`],
/// [`read_config`]); a config decoded any other way is v1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppFormat {
    /// Spec 142: params as environment variables, string or argv commands, packaged
    /// lifecycle scripts discovered by name.
    #[default]
    V1,
    /// Spec 214: params as the argv tokens a command names, argv commands only, no
    /// script discovery.
    V2,
}

impl AppFormat {
    /// Every format this runtime runs, oldest first.
    pub const ALL: [Self; 2] = [Self::V1, Self::V2];

    #[must_use]
    pub const fn artifact_type(self) -> &'static str {
        match self {
            Self::V1 => APP_ARTIFACT_TYPE,
            Self::V2 => APP_V2_ARTIFACT_TYPE,
        }
    }

    #[must_use]
    pub const fn config_media_type(self) -> &'static str {
        match self {
            Self::V1 => APP_CONFIG_MEDIA_TYPE,
            Self::V2 => APP_V2_CONFIG_MEDIA_TYPE,
        }
    }

    /// The name the config blob is materialized under in a work directory.
    #[must_use]
    pub const fn config_file(self) -> &'static str {
        match self {
            Self::V1 => CONFIG_FILE,
            Self::V2 => CONFIG_FILE_V2,
        }
    }

    /// `v1` or `v2`, the way the spec and an operator name it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }

    /// The format an app `artifactType` names, or `None` when it names no app at all.
    ///
    /// # Errors
    ///
    /// An app artifact of a format this runtime does not run is refused by name, so an
    /// operator reads which format the app needs rather than "not an app".
    pub fn from_artifact_type(artifact_type: &str) -> crate::error::Result<Option<Self>> {
        Self::named(artifact_type, APP_ARTIFACT_PREFIX, "", artifact_type)
    }

    /// The format an app config media type names, or `None` when it names no app config.
    ///
    /// # Errors
    ///
    /// Refuses an app config of a format this runtime does not run, naming it.
    pub fn from_config_media_type(media_type: &str) -> crate::error::Result<Option<Self>> {
        Self::named(media_type, APP_CONFIG_PREFIX, "+json", media_type)
    }

    /// The format of an app manifest: its `artifactType` and config media type must name
    /// the same known format.
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::NotFound`] when the manifest is not an ORC app at all or
    /// its two types disagree; [`crate::error::CliError::Usage`] naming the format when
    /// it is an app of a format this runtime does not run.
    pub fn of_manifest(artifact_type: &str, config_media_type: &str) -> crate::error::Result<Self> {
        let artifact = Self::from_artifact_type(artifact_type)?;
        let config = Self::from_config_media_type(config_media_type)?;
        match (artifact, config) {
            (Some(artifact), Some(config)) if artifact == config => Ok(artifact),
            _ => Err(crate::error::CliError::NotFound(
                "not an ORC app artifact".to_owned(),
            )),
        }
    }

    fn named(
        value: &str,
        prefix: &str,
        suffix: &str,
        shown: &str,
    ) -> crate::error::Result<Option<Self>> {
        let Some(version) = value
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
        else {
            return Ok(None);
        };
        match version {
            "1" => Ok(Some(Self::V1)),
            "2" => Ok(Some(Self::V2)),
            other if !other.is_empty() && other.bytes().all(|byte| byte.is_ascii_digit()) => {
                Err(unknown_format(other, shown))
            }
            _ => Ok(None),
        }
    }
}

impl std::fmt::Display for AppFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The refusal a runtime gives an app of a format it does not run (spec 214 *Format
/// version*): before install, naming the format.
fn unknown_format(version: &str, shown: &str) -> crate::error::CliError {
    let known = AppFormat::ALL
        .iter()
        .map(|format| format.label())
        .collect::<Vec<_>>()
        .join(" and ");
    crate::error::CliError::Usage(format!(
        "this app needs app format v{version} ({shown}); this orc runs app formats {known}; \
         upgrade orc to run it"
    ))
}

/// Reads the app config a work directory carries, in the format its file name says.
///
/// # Errors
///
/// Fails when the file is unreadable, is not a config this runtime understands, or the
/// directory holds configs of two formats at once.
pub fn read_config(work_dir: &std::path::Path) -> crate::error::Result<AppConfig> {
    let format = installed_format(work_dir)?;
    let path = work_dir.join(format.config_file());
    let bytes = std::fs::read(&path).map_err(|err| {
        crate::error::CliError::Operational(format!("read {}: {err}", path.display()))
    })?;
    AppConfig::parse(format, &bytes).map_err(|err| {
        crate::error::CliError::Operational(format!("parse {}: {err}", path.display()))
    })
}

/// The format of the app installed in a work directory: whichever config file it holds.
/// A directory with neither reads as v1, so the error names the file a v1 runtime looks
/// for.
///
/// # Errors
///
/// Refuses a directory holding both formats' configs: which one the app is cannot be
/// known, and running the wrong contract is worse than not running.
pub fn installed_format(work_dir: &std::path::Path) -> crate::error::Result<AppFormat> {
    let v1 = work_dir.join(CONFIG_FILE).exists();
    let v2 = work_dir.join(CONFIG_FILE_V2).exists();
    match (v1, v2) {
        (true, true) => Err(crate::error::CliError::Operational(format!(
            "{} holds both {CONFIG_FILE} and {CONFIG_FILE_V2}; reinstall the app",
            work_dir.display()
        ))),
        (false, true) => Ok(AppFormat::V2),
        _ => Ok(AppFormat::V1),
    }
}

/// Removes the config file of every app format other than `format` from a work
/// directory, so a directory reused across a re-push that changed the format holds
/// exactly one config. Best-effort: a missing file is the usual case.
pub fn remove_other_configs(work_dir: &std::path::Path, format: AppFormat) {
    for other in AppFormat::ALL {
        if other != format {
            let _ = std::fs::remove_file(work_dir.join(other.config_file()));
        }
    }
}

/// OS recipe artifact (spec 134/137): a data-only recipe whose config blob is an
/// `OsRecipeConfig` JSON (the verbatim `config:` map) and whose single payload layer is the
/// disk image as one plain, un-chunked blob. These public media types let producers and
/// consumers agree on the artifact contract without depending on a provider implementation.
pub const OS_RECIPE_ARTIFACT_TYPE: &str = "application/vnd.orc8r.os.recipe.v1";
pub const OS_RECIPE_CONFIG_MEDIA_TYPE: &str = "application/vnd.orc8r.os.recipe.config.v1+json";

/// Download artifact: every layer is a published file served verbatim, so the stored bytes
/// must equal the source file and the layer digest is that file's sha256.
pub const DOWNLOAD_ARTIFACT_TYPE: &str = "application/vnd.orc8r.download.v1";
pub const OCI_IMAGE_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// Source-recipe referrer: the verbatim `artifact.yaml` attached to a package
/// via the OCI `subject` field for the author round-trip (`orc clone`).
pub const RECIPE_ARTIFACT_TYPE: &str = "application/vnd.orc8r.recipe.v1";
pub const RECIPE_MEDIA_TYPE: &str = "application/vnd.orc8r.recipe.v1+yaml";

/// Media-type suffix (spec 146) marking a single-blob chunked-zstd payload layer:
/// a concatenation of per-chunk zstd frames followed by one skippable frame that
/// carries the table of contents. A layer descriptor whose `mediaType` ends with
/// this suffix is decoded by [`crate::chunked`]; every other layer media type is a
/// plain whole-blob payload. The suffix follows spec 142's `+<encoding>` convention.
pub const ZSTD_CHUNKED_MEDIA_SUFFIX: &str = "+zstd-chunked";

/// Annotation carrying the byte offset of the skippable TOC frame within the blob.
pub const CHUNKED_TOC_OFFSET_ANNOTATION: &str = "org.orc8r.chunked.toc-offset";
/// Annotation carrying the sha256 digest of the TOC bytes (the read-time integrity
/// gate — the TOC is verified against this before any of its fields are trusted).
pub const CHUNKED_TOC_DIGEST_ANNOTATION: &str = "org.orc8r.chunked.toc-digest";
/// Annotation carrying the chunked-format version.
pub const CHUNKED_VERSION_ANNOTATION: &str = "org.orc8r.chunked.version";

/// Returns whether `media_type` names a single-blob chunked-zstd layer (spec 146).
#[must_use]
pub fn has_chunked_suffix(media_type: &str) -> bool {
    media_type.ends_with(ZSTD_CHUNKED_MEDIA_SUFFIX)
}

/// The well-known OCI empty descriptor used as the config of artifact manifests
/// that carry no config blob (e.g. the recipe referrer).
pub const OCI_EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
pub const OCI_EMPTY_BLOB: &[u8] = b"{}";
pub const OCI_EMPTY_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Derives the OCI referrers fallback tag from a subject digest, per the OCI
/// distribution spec: `<algorithm≤32>-<encoded≤64>` with any tag-illegal
/// character replaced by `-`. Registries lacking the referrers API (e.g.
/// `ghcr.io`) store the referrers index under this tag.
#[must_use]
pub fn referrers_tag(digest: &str) -> String {
    let (algorithm, encoded) = digest.split_once(':').unwrap_or(("sha256", digest));
    let sanitize = |value: &str, limit: usize| -> String {
        value
            .chars()
            .take(limit)
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
                    ch
                } else {
                    '-'
                }
            })
            .collect()
    };
    format!("{}-{}", sanitize(algorithm, 32), sanitize(encoded, 64))
}

/// Accepts an explicit JSON `null` where a container field was omitted: some
/// publishers encode omitted slices and maps as `null` (e.g. `"layers":null`),
/// which plain `#[serde(default)]` rejects.
fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AppConfig {
    /// The contract the config was written against. Not part of the blob: set by
    /// [`AppConfig::parse`] and [`read_config`] from the media type or file name that
    /// carried it, and v1 for a config decoded any other way.
    #[serde(skip)]
    pub format: AppFormat,
    #[serde(default)]
    pub params: Option<ParamSchema>,
    #[serde(default, deserialize_with = "null_default")]
    pub endpoints: BTreeMap<String, AppEndpoint>,
    #[serde(default)]
    pub versions: Option<VersionDiscovery>,
    #[serde(default)]
    pub default_version: Option<String>,
    #[serde(default)]
    pub install: Option<CommandPhase>,
    #[serde(default)]
    pub start: Option<StartPhase>,
    #[serde(default)]
    pub stop: Option<StopPhase>,
    /// Hook run after every exit of the app — graceful, killed, forced, crashed, or a
    /// natural exit of its own.
    #[serde(default)]
    pub stopped: Option<CommandPhase>,
    #[serde(default)]
    pub uninstall: Option<CommandPhase>,
    /// What the app keeps across the life of a node, and nothing about how: the
    /// storage behind it is the platform's business.
    #[serde(default)]
    pub persist: Option<PersistBlock>,
    /// OS-disk space the app takes once installed, in GB, working data outside the
    /// persisted paths included. A planning figure the allocator charges against a
    /// host, never a limit; absent means [`crate::persist::FOOTPRINT_DEFAULT_GB`].
    #[serde(default)]
    pub footprint_gb: Option<u64>,
}

impl AppConfig {
    /// Decodes a config blob of a known format.
    ///
    /// # Errors
    ///
    /// The JSON error when the blob does not decode as an app config.
    pub fn parse(format: AppFormat, bytes: &[u8]) -> std::result::Result<Self, serde_json::Error> {
        let mut config: Self = serde_json::from_slice(bytes)?;
        config.format = format;
        Ok(config)
    }

    /// Decodes a config blob carried under `media_type`.
    ///
    /// # Errors
    ///
    /// Refuses a media type naming no app config (or an app format this runtime does not
    /// run, by name), and a blob that does not decode.
    pub fn parse_media_type(media_type: &str, bytes: &[u8]) -> crate::error::Result<Self> {
        let format = AppFormat::from_config_media_type(media_type)?.ok_or_else(|| {
            crate::error::CliError::Operational(format!(
                "unsupported app config media type {media_type}"
            ))
        })?;
        Self::parse(format, bytes)
            .map_err(|err| crate::error::CliError::Operational(format!("decode app config: {err}")))
    }
}

/// The paths an app persists, plus the optional hooks that bracket a capture.
///
/// Entries are absolute paths in native form; an entry prefixed with `!` excludes
/// something under them. Parsed by [`crate::persist::PersistSpec`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PersistBlock {
    #[serde(default, deserialize_with = "null_default")]
    pub paths: Vec<String>,
    /// Run before a capture is taken; a failure skips that capture.
    #[serde(default)]
    pub hook_pre: Option<CommandPhase>,
    /// Run after a capture attempt, whether or not it succeeded.
    #[serde(default)]
    pub hook_post: Option<CommandPhase>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ParamSchema {
    #[serde(default, deserialize_with = "null_default")]
    pub required: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub properties: BTreeMap<String, ParamProperty>,
}

/// A named listen point an app declares: the port it serves on, the protocol spoken
/// there, an optional readiness probe, and how a scaled pool serves it.
///
/// Host-agnostic — an endpoint never names a deployment or an address. It does say
/// *how many* of a pool's members may answer for it ([`ServeMode`]), because only the
/// app knows that; everything else about routing is the consumer's selector.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AppEndpoint {
    /// Listen port, `1..=65535` (package validation rejects anything else).
    pub port: u16,
    #[serde(default)]
    pub protocol: EndpointProtocol,
    #[serde(default)]
    pub probe: Option<EndpointProbe>,
    /// How the endpoint is served across a scaled pool; [`ServeMode::Primary`] when
    /// the manifest says nothing. `#[serde(default)]` rather than a required field:
    /// a config blob written before the mode existed decodes as the default, which is
    /// the same answer the author would have got by omitting it today.
    #[serde(default)]
    pub serve: ServeMode,
}

/// How an endpoint is served across a pool with more than one member (spec 180).
///
/// Declared by the package author and by nobody else: whether a second member may
/// answer a request of this endpoint is a fact about the app, not about the
/// deployment, so there is no request decoration and no operator knob for it.
///
/// The mode is read in two places that must agree — the serving set behind an exposed
/// port and the members a canonical name answers with — and both read it from here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServeMode {
    /// The slot-1 member alone, **fenced**: while it is unfit the name answers empty
    /// and the port refuses rather than falling through to a stand-in.
    ///
    /// The default, and deliberately the conservative one: an author who has said
    /// nothing has not said that a replica may answer, and a pool that scales up
    /// under a silent manifest must not start spreading writes.
    #[default]
    Primary,
    /// Every endpoint-healthy member. The author's statement that any member can
    /// serve any request of this endpoint.
    Spread,
}

impl ServeMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Spread => "spread",
        }
    }

    /// Reads a mode back from its wire/projection spelling; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "primary" => Some(Self::Primary),
            "spread" => Some(Self::Spread),
            _ => None,
        }
    }

    /// Whether this mode answers with the slot-1 member alone.
    #[must_use]
    pub fn is_primary(self) -> bool {
        matches!(self, Self::Primary)
    }
}

/// Protocol spoken on an endpoint. `Http` is TCP carrying plaintext HTTP/1.1+;
/// `Https` is the same wire protocol with the app terminating TLS on the port
/// itself (it consumes a cert/key and serves HTTP-over-TLS). Both are http-family:
/// they are the only protocols eligible for an `http` probe (which dials over TLS
/// for `Https`), and selectors and SRV semantics treat them alike.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointProtocol {
    #[default]
    Tcp,
    Udp,
    Http,
    Https,
}

impl EndpointProtocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Readiness probe for an endpoint: exactly one of `tcp` (connect to the port),
/// `http` (a path that must answer 2xx/3xx), or `command` (exit 0 passes) — the
/// "exactly one" rule is enforced by package validation — plus optional timing
/// overrides for the host-runtime defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EndpointProbe {
    #[serde(default)]
    pub tcp: Option<bool>,
    #[serde(default)]
    pub http: Option<String>,
    #[serde(default)]
    pub command: Option<CommandValue>,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct XSource {
    pub kind: String,
    #[serde(default, deserialize_with = "null_default")]
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ParamProperty {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(rename = "contentMediaType", default)]
    pub content_media_type: Option<String>,
    #[serde(rename = "enum", default, deserialize_with = "null_default")]
    pub choices: Vec<serde_json::Value>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub lifetime: Option<ParamLifetime>,
    #[serde(rename = "x-source", default)]
    pub x_source: Option<XSource>,
}

/// How long a param value stays available to the app.
///
/// `Startup` values are consumed while the app starts and are withdrawn once the
/// start phase completes; `Runtime` values stay available for the whole app run.
/// When the schema does not declare a lifetime, operator secrets default to
/// `Startup` and everything else to `Runtime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamLifetime {
    Startup,
    Runtime,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandPhase {
    #[serde(default)]
    pub command: Option<CommandValue>,
    #[serde(default)]
    pub timeout: Option<String>,
}

/// A lifecycle command as a recipe gives it.
///
/// On Unix every command leads its own process group, and a stop signal, a
/// grace-expiry kill or a phase timeout goes to the whole group, so it reaches the app
/// whatever sits between it and the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CommandValue {
    /// Runs under the user's login shell (PowerShell on Windows).
    String(String),
    /// Runs its program directly, with `${VAR}` substitution and no shell in between —
    /// the better form for a long-running command, e.g. `["sh", "run.sh"]`.
    Argv(Vec<String>),
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct StartPhase {
    #[serde(default)]
    pub command: Option<CommandValue>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub restart: Option<String>,
    #[serde(default)]
    pub gui: bool,
}

/// How an app is asked to end, and how long the runtime waits before it stops asking.
///
/// The `command` runs while the app is still alive — it is the app's own chance to
/// quiesce (drain a queue, deregister a runner) — and its exit code only says whether
/// the runtime may go on to signal. `timeout` bounds that command; `grace` is the
/// separate window the app gets after the signal, and is never shortened by a slow
/// stop command.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StopPhase {
    #[serde(default)]
    pub command: Option<CommandValue>,
    #[serde(default)]
    pub signal: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub grace: Option<String>,
}

/// A recipe's `versions:` declaration.
///
/// Serializable as well as deserializable: deployments fingerprint a declaration to
/// notice that a push changed it, and serializing the parsed form is what makes that
/// fingerprint depend on every field the evaluator actually reads — a field added
/// here joins the fingerprint by construction. The shape holds no maps, so the
/// serialization is canonical without further work.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct VersionDiscovery {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub url: String,
    /// JSON pointer (RFC 6901) to the node holding the versions in a `json`
    /// source; the document root when omitted. Unused by other sources.
    #[serde(default)]
    pub select: Option<String>,
    /// Property name carrying the version string when a `json` source selects an
    /// array of objects.
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub list: Vec<String>,
    #[serde(default)]
    pub filter: VersionFilter,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct VersionFilter {
    #[serde(default)]
    pub prerelease: Option<bool>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub exclude: Vec<String>,
    /// `major` | `minor` | `none` (the default): keep only the newest version of
    /// each line.
    #[serde(default)]
    pub latest_per: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub sort: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    #[serde(rename = "size")]
    pub size: i64,
    #[serde(default)]
    pub platform: Option<Platform>,
    #[serde(default, deserialize_with = "null_default")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, serde::Serialize)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub variant: String,
}

impl Platform {
    #[must_use]
    pub fn label(&self) -> String {
        if self.variant.is_empty() {
            format!("{}/{}", self.os, self.architecture)
        } else {
            format!("{}/{}/{}", self.os, self.architecture, self.variant)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Some publishers marshal nil slices and maps as explicit `null`
    /// (`"layers":null`); parsing must treat that as empty, not fail.
    #[test]
    fn manifest_and_index_tolerate_null_container_fields() {
        let manifest = ManifestDocument::parse(
            br#"{"schemaVersion":2,"artifactType":"application/vnd.orc8r.app.v1","config":{"mediaType":"application/vnd.orc8r.app.config.v1+json","digest":"sha256:d","size":1},"layers":null,"annotations":null}"#,
            "application/vnd.oci.image.manifest.v1+json",
        )
        .expect("manifest with null layers");
        match manifest {
            ManifestDocument::Manifest(manifest) => {
                assert!(manifest.layers.is_empty());
                assert!(manifest.annotations.is_empty());
            }
            ManifestDocument::Index(_) => panic!("expected manifest"),
        }

        let index = ManifestDocument::parse(
            br#"{"schemaVersion":2,"manifests":null,"annotations":null}"#,
            "application/vnd.oci.image.index.v1+json",
        )
        .expect("index with null manifests");
        match index {
            ManifestDocument::Index(index) => assert!(index.manifests.is_empty()),
            ManifestDocument::Manifest(_) => panic!("expected index"),
        }
    }

    #[test]
    fn app_config_tolerates_null_container_fields() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"params":{"required":null,"properties":null},"versions":{"list":null,"filter":{"exclude":null}}}"#,
        )
        .expect("config with null containers");
        let params = config.params.expect("params");
        assert!(params.required.is_empty());
        assert!(params.properties.is_empty());
        let versions = config.versions.expect("versions");
        assert!(versions.list.is_empty());
        assert!(versions.filter.exclude.is_empty());
    }

    #[test]
    fn version_discovery_accepts_static_list_without_source() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"versions":{"list":["3.46","3.45"]},"default_version":"3.45"}"#,
        )
        .expect("config");
        let versions = config.versions.expect("versions");
        assert_eq!(versions.source, "");
        assert_eq!(versions.url, "");
        assert_eq!(versions.list, ["3.46", "3.45"]);
    }

    #[test]
    fn param_property_deserializes_x_source() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"params":{"type":"object","properties":{"peers":{"type":"string","x-source":{"kind":"peers.gossip"}},"tls_key":{"type":"string","x-source":{"kind":"tls.key","params":{"pair":"tls_cert"}}}}}}"#,
        )
        .expect("config");
        let properties = config.params.expect("params").properties;
        let peers = properties.get("peers").expect("peers");
        let x_source = peers.x_source.as_ref().expect("x-source");
        assert_eq!(x_source.kind, "peers.gossip");
        assert!(x_source.params.is_empty());
        let tls_key = properties.get("tls_key").expect("tls_key");
        let x_source = tls_key.x_source.as_ref().expect("x-source");
        assert_eq!(x_source.kind, "tls.key");
        assert_eq!(x_source.params["pair"], "tls_cert");
    }

    #[test]
    fn endpoints_deserialize_with_protocol_and_probe_defaults() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"endpoints":{"pg":{"port":5432},"metrics":{"port":9187,"protocol":"http","probe":{"http":"/metrics","interval":"5s","timeout":"2s"}},"gossip":{"port":7946,"protocol":"udp","probe":{"command":["check","gossip"]}},"secure":{"port":8443,"protocol":"https","probe":{"http":"/healthz"}}}}"#,
        )
        .expect("config with endpoints");
        let pg = &config.endpoints["pg"];
        assert_eq!(pg.port, 5432);
        // Protocol defaults to tcp and the probe stays absent (the runtime applies the
        // default tcp-connect probe).
        assert_eq!(pg.protocol, EndpointProtocol::Tcp);
        assert!(pg.probe.is_none());
        // An unstated mode is `primary`: a silent manifest has not said a replica may
        // answer.
        assert_eq!(pg.serve, ServeMode::Primary);

        let metrics = &config.endpoints["metrics"];
        assert_eq!(metrics.protocol, EndpointProtocol::Http);
        let probe = metrics.probe.as_ref().expect("probe");
        assert_eq!(probe.http.as_deref(), Some("/metrics"));
        assert_eq!(probe.interval.as_deref(), Some("5s"));
        assert_eq!(probe.timeout.as_deref(), Some("2s"));

        let gossip = &config.endpoints["gossip"];
        assert_eq!(gossip.protocol, EndpointProtocol::Udp);
        let command = gossip
            .probe
            .as_ref()
            .and_then(|probe| probe.command.clone())
            .expect("command probe");
        match command {
            CommandValue::Argv(argv) => assert_eq!(argv, ["check", "gossip"]),
            CommandValue::String(value) => panic!("expected argv, got {value:?}"),
        }

        let secure = &config.endpoints["secure"];
        assert_eq!(secure.protocol, EndpointProtocol::Https);
        assert_eq!(secure.protocol.as_str(), "https");
        assert_eq!(
            secure
                .probe
                .as_ref()
                .and_then(|probe| probe.http.as_deref()),
            Some("/healthz")
        );
    }

    #[test]
    fn serve_mode_defaults_to_primary_and_reads_back_spread() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"endpoints":{"pg":{"port":5432},"web":{"port":8080,"serve":"spread"},"writer":{"port":5433,"serve":"primary"}}}"#,
        )
        .expect("config with serve modes");
        assert_eq!(config.endpoints["pg"].serve, ServeMode::Primary);
        assert_eq!(config.endpoints["web"].serve, ServeMode::Spread);
        assert_eq!(config.endpoints["writer"].serve, ServeMode::Primary);
        assert!(config.endpoints["pg"].serve.is_primary());
        assert!(!config.endpoints["web"].serve.is_primary());
    }

    #[test]
    fn serve_mode_parses_and_renders_both_spellings() {
        for (spelling, mode) in [
            ("primary", ServeMode::Primary),
            ("spread", ServeMode::Spread),
        ] {
            assert_eq!(ServeMode::parse(spelling), Some(mode));
            assert_eq!(mode.as_str(), spelling);
            assert_eq!(
                serde_json::from_str::<ServeMode>(&format!("\"{spelling}\"")).expect("parse"),
                mode
            );
            assert_eq!(
                serde_json::to_value(mode).expect("encode"),
                serde_json::json!(spelling)
            );
        }
        assert_eq!(ServeMode::parse("anycast"), None);
        assert_eq!(ServeMode::parse(""), None);
    }

    /// The typed decode refuses a mode it does not know rather than falling back to
    /// the default: a misspelled `spread` that quietly pins the pool to slot 1 is the
    /// one failure an author would never see.
    #[test]
    fn an_unknown_serve_mode_fails_the_decode() {
        serde_json::from_str::<AppConfig>(
            r#"{"endpoints":{"pg":{"port":5432,"serve":"anycast"}}}"#,
        )
        .expect_err("unknown serve mode");
    }

    #[test]
    fn endpoint_protocol_parses_and_renders_https() {
        assert_eq!(
            serde_json::from_str::<EndpointProtocol>("\"https\"").expect("parse"),
            EndpointProtocol::Https
        );
        assert_eq!(EndpointProtocol::Https.as_str(), "https");
        assert_eq!(
            serde_json::to_value(EndpointProtocol::Https).expect("encode"),
            serde_json::json!("https")
        );
    }

    #[test]
    fn endpoints_round_trip_through_the_config_blob() {
        let blob = r#"{"endpoints":{"metrics":{"port":9187,"protocol":"http","probe":{"http":"/metrics"}}}}"#;
        let config = serde_json::from_str::<AppConfig>(blob).expect("config");
        let encoded = serde_json::to_value(&config.endpoints).expect("encode endpoints");
        let original: serde_json::Value = serde_json::from_str(blob).expect("original");
        assert_eq!(
            encoded["metrics"]["port"],
            original["endpoints"]["metrics"]["port"]
        );
        assert_eq!(
            encoded["metrics"]["protocol"],
            original["endpoints"]["metrics"]["protocol"]
        );
        assert_eq!(
            encoded["metrics"]["probe"]["http"],
            original["endpoints"]["metrics"]["probe"]["http"]
        );
        // The mode the blob left out re-encodes as the default it decoded to, so a
        // round trip states what the endpoint actually does rather than staying silent.
        assert_eq!(encoded["metrics"]["serve"], serde_json::json!("primary"));
    }

    /// A config blob written before `serve` existed still decodes, and every endpoint
    /// in it comes back as `primary` — the event-sourced safety net, since these blobs
    /// live in committed app configs.
    #[test]
    fn a_serve_less_endpoints_blob_still_decodes() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"endpoints":{"pg":{"port":5432},"metrics":{"port":9187,"protocol":"http"}}}"#,
        )
        .expect("blob from before the field existed");
        assert!(
            config
                .endpoints
                .values()
                .all(|endpoint| endpoint.serve == ServeMode::Primary)
        );
    }

    #[test]
    fn app_config_without_endpoints_is_empty() {
        let config = serde_json::from_str::<AppConfig>(r#"{"endpoints":null}"#).expect("config");
        assert!(config.endpoints.is_empty());
        let config = serde_json::from_str::<AppConfig>("{}").expect("config");
        assert!(config.endpoints.is_empty());
    }

    /// The termination contract's own shape: `stop` carries a command, a signal, a
    /// timeout and a grace, and `stopped` is the hook that follows every exit.
    #[test]
    fn stop_and_stopped_phases_deserialize() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"stop":{"command":"drain.sh","signal":"SIGINT","timeout":"45s","grace":"20s"},"stopped":{"command":"report.sh","timeout":"90s"}}"#,
        )
        .expect("config");
        let stop = config.stop.expect("stop");
        assert_eq!(
            stop.command,
            Some(CommandValue::String("drain.sh".to_owned()))
        );
        assert_eq!(stop.signal.as_deref(), Some("SIGINT"));
        assert_eq!(stop.timeout.as_deref(), Some("45s"));
        assert_eq!(stop.grace.as_deref(), Some("20s"));
        let stopped = config.stopped.expect("stopped");
        assert_eq!(stopped.timeout.as_deref(), Some("90s"));
    }

    /// `finish` and `drain` are both retired spellings. A blob still carrying one
    /// decodes cleanly and its phase simply never runs, so a package that has not been
    /// republished cannot half-run an obsolete hook.
    #[test]
    fn the_retired_phase_spellings_are_not_read() {
        let config = serde_json::from_str::<AppConfig>(
            r#"{"finish":{"command":"report.sh","timeout":"5s"}}"#,
        )
        .expect("config with a retired phase");
        assert!(config.stopped.is_none());
    }

    /// `drain` is gone from the contract; a blob that still declares one decodes
    /// cleanly and the phase simply never runs.
    #[test]
    fn a_drain_phase_is_ignored() {
        let config = serde_json::from_str::<AppConfig>(r#"{"drain":{"command":"drain.sh"}}"#)
            .expect("config with a retired phase");
        assert!(config.stop.is_none());
        assert!(config.stopped.is_none());
    }

    #[test]
    fn the_format_is_read_off_the_media_types() {
        assert_eq!(
            AppFormat::of_manifest(APP_ARTIFACT_TYPE, APP_CONFIG_MEDIA_TYPE).expect("v1"),
            AppFormat::V1
        );
        assert_eq!(
            AppFormat::of_manifest(APP_V2_ARTIFACT_TYPE, APP_V2_CONFIG_MEDIA_TYPE).expect("v2"),
            AppFormat::V2
        );
        // Mismatched halves, and other artifacts, are not apps.
        assert!(matches!(
            AppFormat::of_manifest(APP_V2_ARTIFACT_TYPE, APP_CONFIG_MEDIA_TYPE),
            Err(crate::error::CliError::NotFound(_))
        ));
        assert_eq!(
            AppFormat::from_artifact_type(OS_RECIPE_ARTIFACT_TYPE).expect("not an app"),
            None
        );
        assert_eq!(AppFormat::V2.config_file(), "app.config.v2.json");
    }

    /// A runtime refuses an app of a format it does not run, naming the format.
    #[test]
    fn an_unknown_app_format_is_refused_by_name() {
        let err = AppFormat::of_manifest(
            "application/vnd.orc8r.app.v3",
            "application/vnd.orc8r.app.config.v3+json",
        )
        .expect_err("v3");
        let message = err.to_string();
        assert!(matches!(err, crate::error::CliError::Usage(_)), "{message}");
        assert!(message.contains("app format v3"), "{message}");
        assert!(
            message.contains("application/vnd.orc8r.app.v3"),
            "{message}"
        );
        let doc = ManifestDocument::parse(
            br#"{"schemaVersion":2,"artifactType":"application/vnd.orc8r.app.v3","manifests":[]}"#,
            OCI_IMAGE_INDEX,
        )
        .expect("index");
        assert!(!doc.is_orc_app());
        assert!(doc.app_format().is_err());
    }

    #[test]
    fn a_v2_manifest_and_index_are_orc_apps() {
        let manifest = ManifestDocument::parse(
            br#"{"schemaVersion":2,"artifactType":"application/vnd.orc8r.app.v2","config":{"mediaType":"application/vnd.orc8r.app.config.v2+json","digest":"sha256:d","size":1}}"#,
            OCI_IMAGE_MANIFEST,
        )
        .expect("manifest");
        assert_eq!(manifest.app_format().expect("format"), Some(AppFormat::V2));
        let index = ManifestDocument::parse(
            br#"{"schemaVersion":2,"artifactType":"application/vnd.orc8r.app.v2","manifests":[]}"#,
            OCI_IMAGE_INDEX,
        )
        .expect("index");
        assert!(index.is_orc_app());
    }

    #[test]
    fn a_work_dir_says_which_format_its_app_is() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join(CONFIG_FILE_V2),
            br#"{"install":{"command":["./x"]}}"#,
        )
        .expect("v2 config");
        let config = read_config(dir.path()).expect("read");
        assert_eq!(config.format, AppFormat::V2);
        // Both at once cannot be told apart, so neither is run.
        std::fs::write(dir.path().join(CONFIG_FILE), b"{}").expect("v1 config");
        let err = read_config(dir.path()).expect_err("ambiguous");
        assert!(err.to_string().contains("both"), "{err}");
        remove_other_configs(dir.path(), AppFormat::V2);
        assert_eq!(read_config(dir.path()).expect("read").format, AppFormat::V2);
        // A config decoded without its media type is v1, as every existing caller expects.
        let plain: AppConfig = serde_json::from_str("{}").expect("config");
        assert_eq!(plain.format, AppFormat::V1);
    }

    #[test]
    fn referrers_tag_replaces_colon_and_truncates() {
        let hex = "a".repeat(64);
        assert_eq!(
            referrers_tag(&format!("sha256:{hex}")),
            format!("sha256-{hex}")
        );
        // Over-long algorithm/encoded sections are truncated to 32/64 chars.
        let long_alg = "x".repeat(40);
        let long_enc = "b".repeat(80);
        let tag = referrers_tag(&format!("{long_alg}:{long_enc}"));
        let (alg, enc) = tag.split_once('-').expect("hyphen");
        assert_eq!(alg.len(), 32);
        assert_eq!(enc.len(), 64);
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i64,
    #[serde(rename = "artifactType", default)]
    pub artifact_type: String,
    pub config: Descriptor,
    #[serde(default, deserialize_with = "null_default")]
    pub layers: Vec<Descriptor>,
    #[serde(default, deserialize_with = "null_default")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i64,
    #[serde(rename = "artifactType", default)]
    pub artifact_type: String,
    #[serde(default, deserialize_with = "null_default")]
    pub manifests: Vec<Descriptor>,
    #[serde(default, deserialize_with = "null_default")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum ManifestDocument {
    Manifest(ImageManifest),
    Index(ImageIndex),
}

impl ManifestDocument {
    /// Parses an OCI manifest or image index from registry bytes and content type.
    ///
    /// # Errors
    ///
    /// Returns a serde JSON error when the body cannot be decoded as the inferred document type.
    pub fn parse(body: &[u8], content_type: &str) -> std::result::Result<Self, serde_json::Error> {
        if content_type.starts_with(OCI_IMAGE_INDEX) || looks_like_index(body) {
            serde_json::from_slice(body).map(Self::Index)
        } else {
            serde_json::from_slice(body).map(Self::Manifest)
        }
    }

    /// Whether this is an ORC app of a format this runtime runs.
    #[must_use]
    pub fn is_orc_app(&self) -> bool {
        self.app_format().is_ok_and(|format| format.is_some())
    }

    /// The app format this document carries: `None` when it is no ORC app at all.
    ///
    /// An index states its format in `artifactType` only when its publisher set one; an
    /// index without one reads as an app whose children say which format they are.
    ///
    /// # Errors
    ///
    /// An app of a format this runtime does not run is refused by name.
    pub fn app_format(&self) -> crate::error::Result<Option<AppFormat>> {
        match self {
            Self::Manifest(manifest) => {
                if manifest.schema_version != 2 {
                    return Ok(None);
                }
                let artifact = AppFormat::from_artifact_type(&manifest.artifact_type)?;
                let config = AppFormat::from_config_media_type(&manifest.config.media_type)?;
                Ok(match (artifact, config) {
                    (Some(artifact), Some(config)) if artifact == config => Some(artifact),
                    _ => None,
                })
            }
            Self::Index(index) => {
                if index.schema_version != 2 {
                    return Ok(None);
                }
                if index.artifact_type.is_empty() {
                    return Ok(Some(AppFormat::V1));
                }
                AppFormat::from_artifact_type(&index.artifact_type)
            }
        }
    }

    #[must_use]
    pub fn description(&self) -> String {
        let annotations = match self {
            Self::Manifest(manifest) => &manifest.annotations,
            Self::Index(index) => &index.annotations,
        };
        annotations
            .get("org.opencontainers.image.description")
            .cloned()
            .unwrap_or_default()
    }

    #[must_use]
    pub fn platforms(&self) -> Vec<String> {
        match self {
            Self::Manifest(_) => vec!["any".to_owned()],
            Self::Index(index) => index
                .manifests
                .iter()
                .filter_map(|descriptor| descriptor.platform.as_ref())
                .map(Platform::label)
                .collect(),
        }
    }
}

fn looks_like_index(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .is_ok_and(|value| value.get("manifests").is_some())
}
