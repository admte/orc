use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const APP_ARTIFACT_TYPE: &str = "application/vnd.orc8r.app.v1";
pub const APP_CONFIG_MEDIA_TYPE: &str = "application/vnd.orc8r.app.config.v1+json";

/// The app's config blob as it is materialized into the app's work directory.
///
/// Every runtime that starts an app reads it from here — including the runtime
/// re-invoked as a start shim by a service manager, which has nothing else to go on.
pub const CONFIG_FILE: &str = "app.config.v1.json";

/// Reads the app config a work directory carries.
///
/// # Errors
///
/// Fails when the file is unreadable or is not a config this runtime understands.
pub fn read_config(work_dir: &std::path::Path) -> crate::error::Result<AppConfig> {
    let path = work_dir.join(CONFIG_FILE);
    let bytes = std::fs::read(&path).map_err(|err| {
        crate::error::CliError::Operational(format!("read {}: {err}", path.display()))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        crate::error::CliError::Operational(format!("parse {}: {err}", path.display()))
    })
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CommandValue {
    String(String),
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

    #[must_use]
    pub fn is_orc_app(&self) -> bool {
        match self {
            Self::Manifest(manifest) => {
                manifest.schema_version == 2
                    && manifest.artifact_type == APP_ARTIFACT_TYPE
                    && manifest.config.media_type == APP_CONFIG_MEDIA_TYPE
            }
            Self::Index(index) => {
                index.schema_version == 2
                    && (index.artifact_type.is_empty() || index.artifact_type == APP_ARTIFACT_TYPE)
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
        .ok()
        .is_some_and(|value| value.get("manifests").is_some())
}
