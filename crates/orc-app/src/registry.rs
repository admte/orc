#![allow(clippy::missing_errors_doc)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Method;
use sha2::{Digest as _, Sha256};

use crate::app::{AppConfig, Descriptor, ManifestDocument};
use crate::credential::{RegistryCredential, StoredCredential};
use crate::error::{CliError, Result};
use crate::progress::{
    ProgressEvent, ProgressKind, ProgressPhase, ProgressReporter, SharedProgress,
};

#[derive(Clone)]
pub struct RegistryClient {
    http: reqwest::Client,
    base: String,
    auth: Option<RegistryCredential>,
    // Scoped bearer tokens from the Docker registry token flow, keyed by a
    // single-action scope ("repository:acme/app:push"), or "" for scope-less
    // tokens. A token granted several actions is filed under each one, so a
    // lookup only has to name the action the request needs and never has to
    // guess how the registry groups actions into a scope. Shared across clones;
    // never held across .await.
    tokens: Arc<Mutex<HashMap<String, CachedToken>>>,
    // Optional sink for transfer/materialization progress. None = silent (the
    // default), so attaching a reporter never changes observable behavior.
    progress: Option<SharedProgress>,
    // In-process cache of the `_orc` chunked-upload capability probe (spec 146):
    // `None` = not probed yet, `Some(None)` = plain-OCI (no extension), `Some(Some(_))`
    // = capable. Shared across clones; the GET is auth'd and idempotent so a rare
    // double-probe is harmless. Never held across an `.await`. The nested option is
    // deliberate: outer = probed yet?, inner = capability present?.
    #[allow(clippy::option_option)]
    chunked_capability: Arc<Mutex<Option<Option<ChunkedCapabilities>>>>,
}

/// The static protocol facts served by `GET /v2/_orc/` (spec 146 §Negotiation scoping).
/// Its mere presence marks the registry chunked-upload capable; the fields bound the
/// client's framing.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChunkedCapabilities {
    #[serde(default)]
    pub chunked_upload_version: u32,
    #[serde(default)]
    pub max_toc_entries: usize,
    #[serde(default)]
    pub max_frame_bytes: u64,
}

/// The result of [`RegistryClient::push_chunked_layer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkedPushOutcome {
    /// `true` when the negotiated `_orc` path committed the layer; `false` on the monolithic
    /// fallback.
    pub negotiated: bool,
    /// Frames actually uploaded on the converged attempt (0 when every frame was already
    /// present — a full cross-version dedup hit; `frames_total` on the monolithic fallback).
    pub frames_uploaded: usize,
    /// Total frames in the layer recipe (payload frames + the trailing TOC frame).
    pub frames_total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthChallenge {
    Bearer(BearerChallenge),
    Basic,
}

enum RequestAuth {
    Anonymous,
    Basic,
    Bearer(String),
}

struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct RegistryResponse {
    pub body: Vec<u8>,
    pub content_type: String,
    pub digest: String,
}

/// Outcome of a manifest PUT. `oci_subject` carries the value of the
/// `OCI-Subject` response header when the registry natively indexed a
/// `subject`-bearing manifest; its absence tells a producer to maintain the
/// referrers tag-schema fallback itself.
pub struct PutManifestResponse {
    pub digest: String,
    pub oci_subject: Option<String>,
}

/// A descriptor as it appears in a referrers image index — an OCI descriptor
/// plus `artifactType`, so consumers can filter referrers without fetching each
/// one. Used for both the native referrers API response and the tag-schema
/// fallback index.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReferrerDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(
        rename = "artifactType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
struct ReferrersIndex {
    #[serde(default)]
    manifests: Option<Vec<ReferrerDescriptor>>,
}

impl RegistryClient {
    pub fn new(
        registry: &str,
        credential: Option<&StoredCredential>,
        insecure: bool,
    ) -> Result<Self> {
        Self::with_auth(registry, credential.map(RegistryCredential::from), insecure)
    }

    /// A client that authenticates with a pre-minted registry bearer token
    /// (an internally minted registry JWT), sent as-is on every request.
    pub fn with_bearer(registry: &str, token: String, insecure: bool) -> Result<Self> {
        Self::with_auth(
            registry,
            Some(RegistryCredential::Bearer { token }),
            insecure,
        )
    }

    /// A client that authenticates with a username/secret pair, driven through
    /// the challenge flow (exchanged at a Bearer realm, or sent as HTTP Basic
    /// against a Basic-realm registry).
    pub fn with_basic(
        registry: &str,
        username: String,
        password: String,
        insecure: bool,
    ) -> Result<Self> {
        Self::with_auth(
            registry,
            Some(RegistryCredential::Basic {
                username,
                secret: password,
            }),
            insecure,
        )
    }

    /// A client that presents no credentials (public / anonymous pulls).
    pub fn with_anonymous(registry: &str, insecure: bool) -> Result<Self> {
        Self::with_auth(registry, None, insecure)
    }

    /// Builds a client from a brokered login result in its wire form: a `scheme`
    /// (`""`/`"bearer"`/`"basic"`), a `token` (bearer token or Basic password),
    /// and a `username` (Basic only). This is the single credential→client
    /// mapping shared by the in-process core node and remote nodes/plugins.
    pub fn from_login(
        registry: &str,
        scheme: &str,
        token: String,
        username: String,
        insecure: bool,
    ) -> Result<Self> {
        match scheme {
            "bearer" => Self::with_bearer(registry, token, insecure),
            "basic" => Self::with_basic(registry, username, token, insecure),
            _ => Self::with_anonymous(registry, insecure),
        }
    }

    fn with_auth(registry: &str, auth: Option<RegistryCredential>, insecure: bool) -> Result<Self> {
        let base = registry_base_url(registry, insecure);
        let http = reqwest::Client::builder()
            .build()
            .map_err(|err| CliError::Operational(format!("build registry client: {err}")))?;
        Ok(Self {
            http,
            base,
            auth,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            progress: None,
            chunked_capability: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns a client that reports transfer and materialization progress to
    /// `reporter`. The reporter is shared (cheap to clone); all clones of the
    /// returned client emit to the same sink.
    #[must_use]
    pub fn with_progress(mut self, reporter: SharedProgress) -> Self {
        self.progress = Some(reporter);
        self
    }

    /// The attached progress reporter, if any. Used by `pull` to emit
    /// orchestration events (verify, write) alongside transport events.
    pub(crate) fn progress(&self) -> Option<&dyn ProgressReporter> {
        self.progress.as_deref()
    }

    /// Emits one event if a reporter is attached; a no-op otherwise.
    fn emit(&self, event: ProgressEvent) {
        if let Some(reporter) = &self.progress {
            reporter.report(event);
        }
    }

    /// Verifies connectivity and credentials with a `GET /v2/` ping through
    /// the token-exchange flow.
    pub async fn ping(&self) -> Result<()> {
        let response = self
            .execute(Method::GET, &self.url_for_path("/v2/"), &[], None)
            .await?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(CliError::Operational(format!(
                "registry ping /v2/ returned {status}"
            )))
        }
    }

    pub async fn list_catalog(&self, namespace: &str) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct Catalog {
            #[serde(default)]
            repositories: Vec<String>,
        }

        let mut repos = Vec::new();
        let mut last = String::new();
        loop {
            let suffix = if last.is_empty() {
                String::new()
            } else {
                format!("&last={last}")
            };
            let response = self
                .get(&format!("/v2/_catalog?n=100{suffix}"), &[])
                .await?;
            let page: Catalog = serde_json::from_slice(&response.body)
                .map_err(|err| CliError::Operational(format!("decode registry catalog: {err}")))?;
            if page.repositories.is_empty() {
                break;
            }
            let page_last = page.repositories.last().cloned();
            repos.extend(page.repositories);
            if repos.len() % 100 != 0 || page_last.as_deref() == Some(&last) {
                break;
            }
            last = page_last.unwrap_or_default();
        }

        let prefix = if namespace.is_empty() {
            String::new()
        } else {
            format!("{namespace}/")
        };
        Ok(repos
            .into_iter()
            .filter_map(|repo| {
                if prefix.is_empty() {
                    Some(repo)
                } else {
                    repo.strip_prefix(&prefix).map(str::to_owned)
                }
            })
            .collect())
    }

    pub async fn list_tags(&self, repository: &str) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct Tags {
            #[serde(default)]
            tags: Option<Vec<String>>,
        }

        let response = self
            .get(&format!("/v2/{repository}/tags/list"), &[])
            .await?;
        let tags: Tags = serde_json::from_slice(&response.body)
            .map_err(|err| CliError::Operational(format!("decode tag list: {err}")))?;
        Ok(tags.tags.unwrap_or_default())
    }

    pub async fn get_manifest(
        &self,
        repository: &str,
        reference: &str,
    ) -> Result<RegistryResponse> {
        self.get(
            &format!("/v2/{repository}/manifests/{reference}"),
            &[(
                "accept",
                "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json",
            )],
        )
        .await
    }

    /// Downloads a blob, streaming the body so a progress reporter (if attached)
    /// sees byte-level `Downloading` events keyed by `digest`. The full body is
    /// still returned for the caller to verify against the digest.
    pub async fn get_blob(&self, repository: &str, digest: &str) -> Result<Vec<u8>> {
        use futures_util::StreamExt as _;

        let path = format!("/v2/{repository}/blobs/{digest}");
        let response = self
            .execute(Method::GET, &self.url_for_path(&path), &[], None)
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(format!(
                "registry resource not found: {path}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "registry GET {path} returned {status}"
            )));
        }
        let total = response.content_length();
        let mut body = Vec::with_capacity(usize::try_from(total.unwrap_or(0)).unwrap_or(0));
        self.emit(ProgressEvent::new(
            digest,
            ProgressKind::Blob,
            ProgressPhase::Downloading { done: 0, total },
        ));
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                CliError::Operational(format!("read registry blob {path}: {err}"))
            })?;
            body.extend_from_slice(&chunk);
            self.emit(ProgressEvent::new(
                digest,
                ProgressKind::Blob,
                ProgressPhase::Downloading {
                    done: u64::try_from(body.len()).unwrap_or(u64::MAX),
                    total,
                },
            ));
        }
        Ok(body)
    }

    /// Opens a blob as a blocking [`std::io::Read`] fed by the async download.
    ///
    /// The restore path decodes a sealed layer frame by frame; it must not hold the layer
    /// in memory and it must not be rewritten around an async reader, because the decoder
    /// (`FastCDC` framing, AEAD, zstd) is synchronous by nature. So the download runs as a
    /// task pushing byte batches through a bounded channel and the returned reader pulls
    /// from it — backpressure caps the in-flight bytes at [`BLOB_READER_QUEUE`] batches.
    ///
    /// The stream is sha256-verified: the reader reports the mismatch **at EOF**, once the
    /// last byte has been read, so a caller must materialize into a temporary area and
    /// abort on the error rather than trust bytes it has already consumed.
    ///
    /// The returned reader blocks. Call it from [`tokio::task::spawn_blocking`] — reading
    /// it on a runtime worker thread panics, exactly as any other blocking receive does.
    pub async fn get_blob_reader(&self, repository: &str, digest: &str) -> Result<BlobReader> {
        use futures_util::StreamExt as _;

        let path = format!("/v2/{repository}/blobs/{digest}");
        let response = self
            .execute(Method::GET, &self.url_for_path(&path), &[], None)
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(format!(
                "registry resource not found: {path}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "registry GET {path} returned {status}"
            )));
        }
        let expected = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| CliError::Usage(format!("unsupported digest algorithm in {digest:?}")))?
            .to_owned();

        let (sender, receiver) = tokio::sync::mpsc::channel(BLOB_READER_QUEUE);
        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let message = match chunk {
                    Ok(bytes) => Ok(bytes.to_vec()),
                    Err(err) => Err(format!("read registry blob {path}: {err}")),
                };
                let fatal = message.is_err();
                if sender.send(message).await.is_err() || fatal {
                    return;
                }
            }
        });
        Ok(BlobReader {
            receiver,
            current: Vec::new(),
            offset: 0,
            hasher: Some(Sha256::new()),
            expected,
        })
    }

    /// Downloads a blob straight to `dest`, streaming chunks to disk so memory use
    /// stays constant regardless of blob size (multi-GB recipe disks). The content
    /// is sha256-verified against `digest` while streaming; on mismatch the partial
    /// file is removed and an error returned. Progress reporters see the same
    /// byte-level `Downloading` events as [`get_blob`](Self::get_blob). Returns the
    /// byte count written.
    pub async fn get_blob_to_file(
        &self,
        repository: &str,
        digest: &str,
        dest: &std::path::Path,
    ) -> Result<u64> {
        self.get_blob_to_file_with_stall(repository, digest, dest, BLOB_STALL_TIMEOUT)
            .await
    }

    /// [`get_blob_to_file`](Self::get_blob_to_file) with an explicit stall timeout,
    /// so tests can exercise the stalled-stream failure without waiting out the
    /// production [`BLOB_STALL_TIMEOUT`].
    async fn get_blob_to_file_with_stall(
        &self,
        repository: &str,
        digest: &str,
        dest: &std::path::Path,
        stall: std::time::Duration,
    ) -> Result<u64> {
        use futures_util::StreamExt as _;
        use tokio::io::AsyncWriteExt as _;

        let path = format!("/v2/{repository}/blobs/{digest}");
        let response = self
            .execute(Method::GET, &self.url_for_path(&path), &[], None)
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(format!(
                "registry resource not found: {path}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "registry GET {path} returned {status}"
            )));
        }
        let expected_hex = digest.strip_prefix("sha256:").ok_or_else(|| {
            CliError::Usage(format!("unsupported digest algorithm in {digest:?}"))
        })?;
        let total = response.content_length();
        self.emit(ProgressEvent::new(
            digest,
            ProgressKind::Blob,
            ProgressPhase::Downloading { done: 0, total },
        ));
        // Stream into a `.partial` sibling and rename on success so an interrupted
        // or corrupt download never leaves a plausible-looking file at `dest`.
        let partial = dest.with_extension("partial");
        let mut file = tokio::fs::File::create(&partial)
            .await
            .map_err(|err| CliError::Operational(format!("create {}: {err}", partial.display())))?;
        let mut hasher = Sha256::new();
        let mut done: u64 = 0;
        let mut stream = response.bytes_stream();
        let write_result: Result<()> = async {
            loop {
                // A dead TCP stream (an edge proxy dropping the connection without
                // a FIN) otherwise hangs this read forever. Any
                // inter-chunk gap over the stall timeout fails the download so the
                // caller can retry with a fresh connection.
                let next = tokio::time::timeout(stall, stream.next())
                    .await
                    .map_err(|_| {
                        CliError::Operational(format!(
                            "read registry blob {path}: stalled for {}s at byte {done}",
                            stall.as_secs()
                        ))
                    })?;
                let Some(chunk) = next else { break };
                let chunk = chunk.map_err(|err| {
                    CliError::Operational(format!("read registry blob {path}: {err}"))
                })?;
                hasher.update(&chunk);
                file.write_all(&chunk).await.map_err(|err| {
                    CliError::Operational(format!("write {}: {err}", partial.display()))
                })?;
                done += chunk.len() as u64;
                self.emit(ProgressEvent::new(
                    digest,
                    ProgressKind::Blob,
                    ProgressPhase::Downloading { done, total },
                ));
            }
            file.flush().await.map_err(|err| {
                CliError::Operational(format!("flush {}: {err}", partial.display()))
            })?;
            Ok(())
        }
        .await;
        if let Err(err) = write_result {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(err);
        }
        drop(file);
        let actual_hex = format!("{:x}", hasher.finalize());
        if actual_hex != expected_hex {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(CliError::Operational(format!(
                "registry blob {path} hashed to sha256:{actual_hex}, want {digest}"
            )));
        }
        tokio::fs::rename(&partial, dest)
            .await
            .map_err(|err| CliError::Operational(format!("rename to {}: {err}", dest.display())))?;
        Ok(done)
    }

    /// Uploads `body` as a blob under `digest` if it is not already present, transfer-chunking
    /// the upload into ≤ [`upload_chunk_size`]-byte `PATCH`es when the body exceeds that size.
    /// Small blobs take the single-shot `POST → PUT` path unchanged.
    pub async fn ensure_blob(&self, repository: &str, digest: &str, body: Vec<u8>) -> Result<bool> {
        self.ensure_blob_chunked(repository, digest, body, upload_chunk_size())
            .await
    }

    /// [`ensure_blob`](Self::ensure_blob) with an explicit transfer-chunk size, so a body
    /// longer than `chunk_size` is uploaded as `POST → N × PATCH → empty-body PUT` and a
    /// shorter one as a single-shot `POST → PUT`. `ensure_blob` calls this with the configured
    /// [`upload_chunk_size`]; tests pass a small `chunk_size` to exercise the chunked path
    /// deterministically without touching the process environment.
    pub async fn ensure_blob_chunked(
        &self,
        repository: &str,
        digest: &str,
        body: Vec<u8>,
        chunk_size: usize,
    ) -> Result<bool> {
        if self.blob_exists(repository, digest).await? {
            self.emit(ProgressEvent::new(
                digest,
                ProgressKind::Blob,
                ProgressPhase::Exists,
            ));
            self.emit(ProgressEvent::new(
                digest,
                ProgressKind::Blob,
                ProgressPhase::Done,
            ));
            return Ok(false);
        }
        // Report the size up front and completion after; the chunked path also emits
        // per-chunk progress in between. True byte-level progress on the single-shot path
        // would require a streamed request body.
        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        self.emit(ProgressEvent::new(
            digest,
            ProgressKind::Blob,
            ProgressPhase::Uploading {
                done: 0,
                total: Some(size),
            },
        ));
        self.upload_blob(repository, digest, &body, chunk_size)
            .await?;
        self.emit(ProgressEvent::new(
            digest,
            ProgressKind::Blob,
            ProgressPhase::Uploading {
                done: size,
                total: Some(size),
            },
        ));
        self.emit(ProgressEvent::new(
            digest,
            ProgressKind::Blob,
            ProgressPhase::Done,
        ));
        Ok(true)
    }

    /// Runs the OCI blob upload wire sequence: `POST` a session, then either a single-shot
    /// `PUT ?digest=` with the whole body (`body.len() <= chunk_size`), or `chunk_size`-byte
    /// `PATCH`es followed by an empty-body `PUT ?digest=` that the server verifies against the
    /// declared digest. Chunking keeps every request body under the edge's request-size cap.
    async fn upload_blob(
        &self,
        repository: &str,
        digest: &str,
        body: &[u8],
        chunk_size: usize,
    ) -> Result<()> {
        let start_path = format!("/v2/{repository}/blobs/uploads/");
        let start = self
            .execute(Method::POST, &self.url_for_path(&start_path), &[], None)
            .await?;
        if start.status() != reqwest::StatusCode::ACCEPTED {
            return Err(Self::status_error(
                "registry upload start",
                &start_path,
                start.status(),
            ));
        }
        let mut location = location_header(&start)?;
        if body.len() <= chunk_size {
            // Single-shot: the whole body rides the finalizing PUT.
            let complete_url = self.finalize_url(&location, digest);
            let complete = self
                .execute(Method::PUT, &complete_url, &[], Some(body))
                .await?;
            if complete.status() != reqwest::StatusCode::CREATED {
                return Err(Self::status_error(
                    "registry upload complete",
                    &complete_url,
                    complete.status(),
                ));
            }
            return Ok(());
        }
        // Transfer-chunked: PATCH each ≤ chunk_size slice, tracking the offset locally and
        // (as an OCI-compliant sanity check) confirming the server's echoed Range end.
        let total = u64::try_from(body.len()).unwrap_or(u64::MAX);
        for (start_off, end_off) in chunk_boundaries(body.len(), chunk_size) {
            let chunk = &body[start_off..end_off];
            let patch_url = self.url_for_location(&location);
            let response = self
                .execute(
                    Method::PATCH,
                    &patch_url,
                    &[
                        ("content-range", &content_range(start_off, end_off)),
                        ("content-type", "application/octet-stream"),
                    ],
                    Some(chunk),
                )
                .await?;
            if response.status() != reqwest::StatusCode::ACCEPTED {
                return Err(Self::status_error(
                    "registry upload chunk",
                    &patch_url,
                    response.status(),
                ));
            }
            // Follow the session Location the 202 returns (the server hands back the same
            // upload path); fall back to the current one if the header is absent.
            if let Ok(next) = location_header(&response) {
                location = next;
            }
            self.emit(ProgressEvent::new(
                digest,
                ProgressKind::Blob,
                ProgressPhase::Uploading {
                    done: u64::try_from(end_off).unwrap_or(u64::MAX),
                    total: Some(total),
                },
            ));
        }
        // Finalize with an empty body: the server appends 0 bytes then verifies the staged
        // content against `digest` (a mismatch fails the upload and discards the staging).
        let complete_url = self.finalize_url(&location, digest);
        let complete = self
            .execute(Method::PUT, &complete_url, &[], Some(&[]))
            .await?;
        if complete.status() != reqwest::StatusCode::CREATED {
            return Err(Self::status_error(
                "registry upload complete",
                &complete_url,
                complete.status(),
            ));
        }
        Ok(())
    }

    /// Builds the finalizing `PUT` URL: the upload session location with `?digest=<digest>`
    /// appended (using `&` when the location already carries a query).
    fn finalize_url(&self, location: &str, digest: &str) -> String {
        let separator = if location.contains('?') { '&' } else { '?' };
        self.url_for_location(&format!("{location}{separator}digest={digest}"))
    }

    // ── Negotiated chunked upload (spec 146 §Upload Protocol, client side) ────────────

    /// Probes and caches the `_orc` chunked-upload capability once per registry
    /// (`GET /v2/_orc/`, authenticated through the normal flow). An absent/`404` endpoint
    /// means the registry is plain-OCI: the caller must upload whole blobs. The result is
    /// memoized in-process and shared across clones.
    ///
    /// # Panics
    ///
    /// Panics only if the in-process capability-cache mutex is poisoned.
    pub async fn chunked_capability(&self) -> Result<Option<ChunkedCapabilities>> {
        if let Some(cached) = self
            .chunked_capability
            .lock()
            .expect("capability cache lock")
            .clone()
        {
            return Ok(cached);
        }
        let path = "/v2/_orc/";
        // The probe is best-effort: any non-2xx status, auth challenge, or transport error
        // means "treat the registry as plain-OCI". The always-correct monolithic path still
        // applies and a genuine auth failure resurfaces on the real upload — the probe never
        // turns a capable push into a hard error.
        let capability = match self
            .execute(Method::GET, &self.url_for_path(path), &[], None)
            .await
        {
            Ok(response) if response.status().is_success() => response
                .bytes()
                .await
                .ok()
                .and_then(|body| serde_json::from_slice::<ChunkedCapabilities>(&body).ok()),
            _ => None,
        };
        *self
            .chunked_capability
            .lock()
            .expect("capability cache lock") = Some(capability.clone());
        Ok(capability)
    }

    /// Uploads an already-assembled chunked-zstd layer blob via the negotiated `_orc`
    /// extension: POST the recipe derived from `toc`, PATCH the frames the registry reports
    /// missing, and PUT-finalize under the layer digest. An unknown-session response is
    /// resolved by re-POSTing (resume). On **any** extension failure it falls back to a
    /// standard monolithic PUT of the *same stream bytes* — a capable orc registry still
    /// reads the `+zstd-chunked` blob, just without wire dedup.
    ///
    /// Returns a [`ChunkedPushOutcome`] describing whether the negotiated path was used and
    /// how many frames actually uploaded (0 on a full cross-version dedup hit).
    pub async fn push_chunked_layer(
        &self,
        repository: &str,
        media_type: &str,
        blob: &[u8],
        toc: &crate::chunked::Toc,
    ) -> Result<ChunkedPushOutcome> {
        let layer_digest = digest_bytes(blob);
        let total_length: u64 = toc.chunks.iter().map(|c| u64::from(c.raw_length)).sum();
        // The recipe must tile the WHOLE blob: every payload frame (from the TOC) plus the
        // trailing skippable TOC frame, so the server reassembles the exact wire stream.
        let wire = wire_frames(blob, toc);
        let frames_total = wire.len();
        if let Ok(frames_uploaded) = self
            .negotiated_chunked_upload(
                repository,
                media_type,
                blob,
                &wire,
                &layer_digest,
                total_length,
            )
            .await
        {
            return Ok(ChunkedPushOutcome {
                negotiated: true,
                frames_uploaded,
                frames_total,
            });
        }
        // Fallback: the same stream bytes as one monolithic blob (registry-side CDC).
        self.ensure_blob(repository, &layer_digest, blob.to_vec())
            .await?;
        Ok(ChunkedPushOutcome {
            negotiated: false,
            frames_uploaded: frames_total,
            frames_total,
        })
    }

    /// The negotiated upload proper (POST → PATCH → PUT) with resume. Returns the number of
    /// frames uploaded on the converged attempt, or `Err` to signal the caller should fall
    /// back to the monolithic path.
    async fn negotiated_chunked_upload(
        &self,
        repository: &str,
        media_type: &str,
        blob: &[u8],
        wire: &[WireFrame],
        layer_digest: &str,
        total_length: u64,
    ) -> Result<usize> {
        const MAX_RESUME: usize = 3;
        let recipe = chunked_recipe_body(layer_digest, total_length, media_type, wire);
        let recipe_bytes = serde_json::to_vec(&recipe)
            .map_err(|err| CliError::Operational(format!("encode chunked recipe: {err}")))?;

        // The session the last attempt opened, until it is finalized. Whatever ends this
        // ladder short of success releases it: the registry only lets a principal hold a
        // handful of un-finalized sessions at once, and a push that falls back to the
        // monolithic path has no further use for the one it left open.
        let mut open: Option<String> = None;
        let mut outcome = Err(CliError::Operational(
            "chunked upload did not converge after resume attempts".to_owned(),
        ));
        for _ in 0..MAX_RESUME {
            let (session, missing) = match self.chunked_negotiate(repository, &recipe_bytes).await {
                Ok(negotiated) => negotiated,
                Err(err) => {
                    outcome = Err(err);
                    break;
                }
            };
            open = Some(session.clone());
            match self
                .chunked_upload_missing(repository, &session, blob, wire, &missing, layer_digest)
                .await
            {
                Ok(()) => {
                    open = None;
                    outcome = Ok(missing.len());
                    break;
                }
                // A retryable unknown-session (the session was lost / expired) is resolved
                // by re-POSTing the recipe for a fresh, smaller missing set — which the
                // registry answers with this very session when it is still holding it.
                Err(ChunkedResume::Retry) => {}
                Err(ChunkedResume::Fatal(err)) => {
                    outcome = Err(err);
                    break;
                }
            }
        }
        if let Some(session) = open {
            self.chunked_abandon(repository, &session).await;
        }
        outcome
    }

    /// PATCH every missing frame (in bounded batches), then PUT-finalize. Classifies an
    /// unknown-session `404` as retryable so the caller re-POSTs.
    async fn chunked_upload_missing(
        &self,
        repository: &str,
        session: &str,
        blob: &[u8],
        wire: &[WireFrame],
        missing: &[u32],
        layer_digest: &str,
    ) -> std::result::Result<(), ChunkedResume> {
        const MAX_BATCH_BYTES: usize = 32 * 1024 * 1024;
        let mut batch: Vec<u8> = Vec::new();
        for &index in missing {
            let Some(entry) = wire.get(index as usize) else {
                return Err(ChunkedResume::Fatal(CliError::Operational(format!(
                    "chunked recipe missing index {index} out of range"
                ))));
            };
            let start = usize::try_from(entry.offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(entry.length).unwrap_or(usize::MAX));
            let frame = blob.get(start..end).ok_or_else(|| {
                ChunkedResume::Fatal(CliError::Operational(
                    "chunked frame slice out of bounds of the assembled blob".to_owned(),
                ))
            })?;
            batch.extend_from_slice(&index.to_le_bytes());
            batch.extend_from_slice(&u32::try_from(frame.len()).unwrap_or(u32::MAX).to_le_bytes());
            batch.extend_from_slice(frame);
            if batch.len() >= MAX_BATCH_BYTES {
                self.chunked_patch(repository, session, std::mem::take(&mut batch))
                    .await?;
            }
        }
        if !batch.is_empty() {
            self.chunked_patch(repository, session, batch).await?;
        }
        self.chunked_finalize(repository, session, layer_digest)
            .await
    }

    /// POST the recipe; returns `(session_id, missing indices)`.
    pub(crate) async fn chunked_negotiate(
        &self,
        repository: &str,
        recipe_bytes: &[u8],
    ) -> Result<(String, Vec<u32>)> {
        #[derive(serde::Deserialize)]
        struct OpenSession {
            session_id: String,
            #[serde(default)]
            missing: Vec<u32>,
        }
        let path = format!("/v2/{repository}/_orc/chunked-uploads/");
        let response = self
            .execute(
                Method::POST,
                &self.url_for_path(&path),
                &[("content-type", "application/json")],
                Some(recipe_bytes),
            )
            .await?;
        // The per-principal session cap. Worth its own sentence: it means earlier uploads
        // of this same client were cut off without being closed out, not that anything
        // about this layer is wrong, and it clears itself.
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(sessions_held(response).await);
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(CliError::Operational(format!(
                "chunked negotiate POST returned {}",
                response.status()
            )));
        }
        let body: OpenSession = response
            .json()
            .await
            .map_err(|err| CliError::Operational(format!("decode chunked session: {err}")))?;
        Ok((body.session_id, body.missing))
    }

    /// PATCH one batch of `(index u32 LE, len u32 LE, frame bytes)` records.
    pub(crate) async fn chunked_patch(
        &self,
        repository: &str,
        session: &str,
        body: Vec<u8>,
    ) -> std::result::Result<(), ChunkedResume> {
        let path = format!("/v2/{repository}/_orc/chunked-uploads/{session}");
        let response = self
            .execute(
                Method::PATCH,
                &self.url_for_path(&path),
                &[("content-type", "application/octet-stream")],
                Some(&body),
            )
            .await
            .map_err(ChunkedResume::Fatal)?;
        match response.status() {
            reqwest::StatusCode::ACCEPTED | reqwest::StatusCode::NO_CONTENT => Ok(()),
            reqwest::StatusCode::NOT_FOUND => Err(ChunkedResume::Retry),
            other => Err(ChunkedResume::Fatal(CliError::Operational(format!(
                "chunked PATCH returned {other}"
            )))),
        }
    }

    /// PUT `?digest=` to finalize the recipe into the content store.
    pub(crate) async fn chunked_finalize(
        &self,
        repository: &str,
        session: &str,
        layer_digest: &str,
    ) -> std::result::Result<(), ChunkedResume> {
        let path = format!("/v2/{repository}/_orc/chunked-uploads/{session}?digest={layer_digest}");
        let response = self
            .execute(Method::PUT, &self.url_for_path(&path), &[], None)
            .await
            .map_err(ChunkedResume::Fatal)?;
        match response.status() {
            reqwest::StatusCode::CREATED | reqwest::StatusCode::OK => Ok(()),
            // Unknown session (expired/lost) → re-POST. Still-missing frames also map to
            // 404-class and are resolved the same way (re-negotiate, re-upload).
            reqwest::StatusCode::NOT_FOUND => Err(ChunkedResume::Retry),
            other => Err(ChunkedResume::Fatal(CliError::Operational(format!(
                "chunked finalize PUT returned {other}"
            )))),
        }
    }

    /// `DELETE` a negotiated session this client will not finalize, so the registry can
    /// release its staged frames and free one of the few session slots the principal has.
    ///
    /// Best effort by design: it runs on paths that are already giving up (a cancelled
    /// capture, a fatal upload error), and none of them become worse because the registry
    /// did not hear about it — the session then expires on its own idle TTL. It is also
    /// bounded, because the caller may be a cancelled capture holding a frozen volume open
    /// and waiting on this call to return.
    pub(crate) async fn chunked_abandon(&self, repository: &str, session: &str) {
        const ABANDON_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let path = format!("/v2/{repository}/_orc/chunked-uploads/{session}");
        let url = self.url_for_path(&path);
        let request = self.execute(Method::DELETE, &url, &[], None);
        match tokio::time::timeout(ABANDON_TIMEOUT, request).await {
            Ok(Ok(response)) if response.status().is_success() => {}
            Ok(Ok(response)) => {
                tracing::debug!(
                    "chunked session {session} was not released: DELETE returned {}",
                    response.status()
                );
            }
            Ok(Err(err)) => tracing::debug!("chunked session {session} was not released: {err}"),
            Err(_) => tracing::debug!("chunked session {session} release timed out"),
        }
    }

    /// POSTs a JSON body to an `_orc` extension endpoint and hands back the raw status and
    /// body, so a caller can act on the endpoint's own error vocabulary rather than a
    /// flattened error string. Authentication follows the normal challenge flow, which
    /// means a 401 or 403 still surfaces as [`CliError::Auth`] before this returns.
    pub(crate) async fn post_extension_json(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let response = self
            .execute(
                Method::POST,
                &self.url_for_path(path),
                &[("content-type", "application/json")],
                Some(body),
            )
            .await?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|err| CliError::Operational(format!("read {path} response: {err}")))?;
        Ok((status, body.to_vec()))
    }

    pub async fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        body: Vec<u8>,
    ) -> Result<String> {
        Ok(self
            .put_manifest_with_response(repository, reference, media_type, body)
            .await?
            .digest)
    }

    /// Like [`put_manifest`](Self::put_manifest) but also surfaces the
    /// `OCI-Subject` response header so a producer can tell whether the registry
    /// natively indexed a `subject`-bearing manifest.
    pub async fn put_manifest_with_response(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        body: Vec<u8>,
    ) -> Result<PutManifestResponse> {
        let path = format!("/v2/{repository}/manifests/{reference}");
        let response = self
            .execute(
                Method::PUT,
                &self.url_for_path(&path),
                &[("content-type", media_type)],
                Some(&body),
            )
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(format!(
                "registry resource not found: {path}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "registry PUT {path} returned {status}"
            )));
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let digest = header("Docker-Content-Digest").unwrap_or_else(|| digest_bytes(&body));
        let oci_subject = header("OCI-Subject");
        Ok(PutManifestResponse {
            digest,
            oci_subject,
        })
    }

    /// Lists referrers of `subject_digest`, filtered to `artifact_type` when
    /// given. Tries the OCI 1.1 Referrers API first; on `404` (the registry
    /// does not serve the endpoint, e.g. `ghcr.io`) it falls back to the
    /// referrers tag schema. An empty result is not an error.
    pub async fn get_referrers(
        &self,
        repository: &str,
        subject_digest: &str,
        artifact_type: Option<&str>,
    ) -> Result<Vec<ReferrerDescriptor>> {
        let path = format!("/v2/{repository}/referrers/{subject_digest}");
        let response = self
            .execute(
                Method::GET,
                &self.url_for_path(&path),
                &[("accept", crate::app::OCI_IMAGE_INDEX)],
                None,
            )
            .await?;
        let status = response.status();
        let body = if status.is_success() {
            response
                .bytes()
                .await
                .map_err(|err| CliError::Operational(format!("read referrers index: {err}")))?
                .to_vec()
        } else if status == reqwest::StatusCode::NOT_FOUND {
            match self
                .referrers_fallback_index(repository, subject_digest)
                .await?
            {
                Some(body) => body,
                None => return Ok(Vec::new()),
            }
        } else {
            return Err(CliError::Operational(format!(
                "registry GET {path} returned {status}"
            )));
        };
        let index: ReferrersIndex = serde_json::from_slice(&body)
            .map_err(|err| CliError::Operational(format!("decode referrers index: {err}")))?;
        let mut manifests = index.manifests.unwrap_or_default();
        if let Some(filter) = artifact_type {
            manifests.retain(|descriptor| descriptor.artifact_type.as_deref() == Some(filter));
        }
        Ok(manifests)
    }

    /// Adds `referrer` to the referrers tag-schema fallback index for
    /// `subject_digest`, creating the index when absent. Used by producers
    /// (`orc push`) against registries whose manifest PUT omits `OCI-Subject`.
    /// Idempotent: a referrer already present is left untouched.
    pub async fn update_referrers_fallback(
        &self,
        repository: &str,
        subject_digest: &str,
        referrer: &ReferrerDescriptor,
    ) -> Result<()> {
        let tag = crate::app::referrers_tag(subject_digest);
        let mut manifests = match self
            .referrers_fallback_index(repository, subject_digest)
            .await?
        {
            Some(body) => serde_json::from_slice::<ReferrersIndex>(&body)
                .map(|index| index.manifests.unwrap_or_default())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        if manifests
            .iter()
            .any(|existing| existing.digest == referrer.digest)
        {
            return Ok(());
        }
        manifests.push(referrer.clone());
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": crate::app::OCI_IMAGE_INDEX,
            "manifests": manifests,
        });
        let body = serde_json::to_vec(&index)
            .map_err(|err| CliError::Operational(format!("encode referrers index: {err}")))?;
        self.put_manifest(repository, &tag, crate::app::OCI_IMAGE_INDEX, body)
            .await?;
        Ok(())
    }

    /// Fetches the referrers tag-schema fallback index body, or `None` when the
    /// fallback tag does not exist.
    async fn referrers_fallback_index(
        &self,
        repository: &str,
        subject_digest: &str,
    ) -> Result<Option<Vec<u8>>> {
        let tag = crate::app::referrers_tag(subject_digest);
        match self
            .get(
                &format!("/v2/{repository}/manifests/{tag}"),
                &[("accept", crate::app::OCI_IMAGE_INDEX)],
            )
            .await
        {
            Ok(response) => Ok(Some(response.body)),
            Err(CliError::NotFound(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn app_config_for_manifest(
        &self,
        repository: &str,
        doc: &ManifestDocument,
    ) -> Result<Option<AppConfig>> {
        let Some(config) = self.config_descriptor(repository, doc).await? else {
            return Ok(None);
        };
        let blob = self.cached_blob(repository, &config.digest).await?;
        serde_json::from_slice(&blob)
            .map(Some)
            .map_err(|err| CliError::Operational(format!("decode app config: {err}")))
    }

    /// Reads a blob through the on-disk content-addressed cache.
    ///
    /// An install reads a repository's config to resolve which version to install
    /// and then materializes that package, which pulls the very same config blob
    /// again; without the cache that is two round trips for identical bytes. Cached
    /// bytes are re-hashed before they are trusted, exactly as the pull path does —
    /// the cache is an ordinary directory, and a blob that no longer matches its
    /// own digest is a fault worth surfacing rather than papering over.
    async fn cached_blob(&self, repository: &str, digest: &str) -> Result<Vec<u8>> {
        if let Some(body) = crate::cache::read_blob(digest)? {
            verify_digest(&body, digest)?;
            return Ok(body);
        }
        let body = self.get_blob(repository, digest).await?;
        crate::cache::write_blob(digest, &body)?;
        Ok(body)
    }

    async fn config_descriptor(
        &self,
        repository: &str,
        doc: &ManifestDocument,
    ) -> Result<Option<Descriptor>> {
        match doc {
            ManifestDocument::Manifest(manifest) => Ok(Some(manifest.config.clone())),
            ManifestDocument::Index(index) => {
                let Some(child) = index.manifests.first() else {
                    return Ok(None);
                };
                let response = self.get_manifest(repository, &child.digest).await?;
                let child_doc = ManifestDocument::parse(&response.body, &response.content_type)
                    .map_err(|err| {
                        CliError::Operational(format!("decode child manifest: {err}"))
                    })?;
                match child_doc {
                    ManifestDocument::Manifest(manifest) => Ok(Some(manifest.config)),
                    ManifestDocument::Index(_) => Ok(None),
                }
            }
        }
    }

    async fn blob_exists(&self, repository: &str, digest: &str) -> Result<bool> {
        let path = format!("/v2/{repository}/blobs/{digest}");
        let response = self
            .execute(Method::HEAD, &self.url_for_path(&path), &[], None)
            .await?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(false),
            status if status.is_success() => Ok(true),
            status => Err(CliError::Operational(format!(
                "registry HEAD {path} returned {status}"
            ))),
        }
    }

    /// Runs one registry request through the Docker registry token flow: the
    /// first attempt uses a cached scoped token (or goes anonymous), a 401 with
    /// a Bearer challenge triggers a token exchange at the named realm, a Basic
    /// challenge falls back to direct Basic with the stored credential. A
    /// pre-minted bearer credential is the exception: it is sent as-is up
    /// front, and a 401 against it is terminal. One retry total; 403 and a
    /// second 401 are terminal.
    ///
    /// Taking the 401 on the request itself is only affordable without a body;
    /// a request that carries one authenticates up front via
    /// [`preflight_auth`](Self::preflight_auth).
    async fn execute(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<reqwest::Response> {
        let path = request_path(url);
        let mut auth = match self.cached_token(&method, path) {
            Some(token) => RequestAuth::Bearer(token),
            None => match &self.auth {
                Some(RegistryCredential::Bearer { token }) => RequestAuth::Bearer(token.clone()),
                // A Basic credential is never pre-sent to the registry host;
                // the 401 challenge decides where it goes (token-endpoint
                // exchange or direct Basic). Sending it up front breaks
                // registries that reject foreign Authorization forms with a
                // terminal 403 (ghcr.io does for raw PATs).
                _ => RequestAuth::Anonymous,
            },
        };
        // A request carrying a body must never leave unauthenticated. The
        // registry answers 401 before draining the body, so a large upload dies
        // with the connection instead of surfacing a 401 the challenge flow
        // could act on. Settle credentials on a bodyless probe first.
        if body.is_some() && matches!(auth, RequestAuth::Anonymous) {
            auth = self.preflight_auth(&method, path).await?;
        }
        let mut retried = false;
        loop {
            let mut request = self.http.request(method.clone(), url);
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            if let Some(body) = body {
                request = request.body(body.to_vec());
            }
            request = match (&auth, &self.auth) {
                (RequestAuth::Basic, Some(RegistryCredential::Basic { username, secret })) => {
                    request.basic_auth(username, Some(secret))
                }
                (RequestAuth::Bearer(token), _) => request.bearer_auth(token),
                _ => request,
            };
            let response = request
                .send()
                .await
                .map_err(|err| CliError::Operational(format!("registry {method} {path}: {err}")))?;
            let status = response.status();
            if status == reqwest::StatusCode::FORBIDDEN {
                return Err(CliError::Auth(self.access_denied_message(path)));
            }
            if status != reqwest::StatusCode::UNAUTHORIZED {
                return Ok(response);
            }
            if retried {
                return Err(CliError::Auth(format!("registry access denied for {path}")));
            }
            retried = true;
            let bearer_credential = matches!(&self.auth, Some(RegistryCredential::Bearer { .. }));
            match select_challenge(response.headers()) {
                // A pre-minted bearer credential was already sent and
                // rejected; there is nothing to exchange.
                Some(AuthChallenge::Bearer(challenge)) if !bearer_credential => {
                    auth = RequestAuth::Bearer(self.exchange_token(&challenge).await?);
                }
                // No token service: the stored docker-login credential goes
                // direct Basic (the builtin registry's `apikey` user).
                Some(AuthChallenge::Basic) | None
                    if matches!(&self.auth, Some(RegistryCredential::Basic { .. })) =>
                {
                    auth = RequestAuth::Basic;
                }
                _ if self.auth.is_some() => {
                    return Err(CliError::Auth(format!(
                        "registry rejected stored credentials for {path}; re-run orc login"
                    )));
                }
                _ => {
                    return Err(CliError::Auth(format!(
                        "authentication required for {path}; run orc login"
                    )));
                }
            }
        }
    }

    /// Settles the credentials for a request that carries a body, before a byte
    /// of it goes out. Learns the challenge from a bodyless `GET /v2/` and
    /// exchanges for the scope the upload needs, rather than letting the
    /// body-carrying request take the 401 itself.
    ///
    /// The exchange asks for [`scope_hint`]'s scope, not the probe's: `/v2/`
    /// challenges without one, and a scope-less token carries no repository
    /// access, so the upload would be refused all the same.
    ///
    /// A registry that challenges the probe will refuse an uploaded body just
    /// the same, so a client with no credential to answer it fails here rather
    /// than at a dropped connection. A registry that challenges nothing takes
    /// the body anonymously, credential or not.
    async fn preflight_auth(&self, method: &Method, path: &str) -> Result<RequestAuth> {
        let probe = self
            .http
            .get(self.url_for_path("/v2/"))
            .send()
            .await
            .map_err(|err| CliError::Operational(format!("registry GET /v2/: {err}")))?;
        if probe.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(RequestAuth::Anonymous);
        }
        let bearer_credential = matches!(&self.auth, Some(RegistryCredential::Bearer { .. }));
        match select_challenge(probe.headers()) {
            Some(AuthChallenge::Bearer(challenge)) if !bearer_credential && self.auth.is_some() => {
                let scope = scope_hint(method, path).or(challenge.scope);
                let challenge = BearerChallenge { scope, ..challenge };
                Ok(RequestAuth::Bearer(self.exchange_token(&challenge).await?))
            }
            Some(AuthChallenge::Basic) | None
                if matches!(&self.auth, Some(RegistryCredential::Basic { .. })) =>
            {
                Ok(RequestAuth::Basic)
            }
            _ if self.auth.is_some() => Err(CliError::Auth(format!(
                "registry rejected stored credentials for {path}; re-run orc login"
            ))),
            _ => Err(CliError::Auth(format!(
                "authentication required for {path}; run orc login"
            ))),
        }
    }

    /// A 403 means the registry authenticated the request but refused the
    /// action — almost always missing token scopes, so say so.
    fn access_denied_message(&self, path: &str) -> String {
        let mut message =
            format!("registry access denied for {path}: the credential may lack required scopes");
        if self.base.ends_with("ghcr.io") {
            message.push_str(" (ghcr.io PATs need read:packages or write:packages)");
        }
        message
    }

    fn cached_token(&self, method: &Method, path: &str) -> Option<String> {
        let scope = scope_hint(method, path)?;
        let tokens = self.tokens.lock().expect("token cache lock");
        let cached = tokens.get(&scope).or_else(|| tokens.get(""))?;
        (cached.expires_at > Instant::now()).then(|| cached.token.clone())
    }

    /// Exchanges the stored credential (or nothing, for public repos) for a
    /// scoped bearer token at the challenge's realm and caches it by scope.
    async fn exchange_token(&self, challenge: &BearerChallenge) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
            #[serde(default)]
            expires_in: Option<u64>,
        }

        let realm = &challenge.realm;
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(service) = &challenge.service {
            query.push(("service", service));
        }
        if let Some(scope) = &challenge.scope {
            query.push(("scope", scope));
        }
        let mut request = self.http.get(realm);
        if !query.is_empty() {
            request = request.query(&query);
        }
        if let Some(RegistryCredential::Basic { username, secret }) = &self.auth {
            request = request.basic_auth(username, Some(secret));
        }
        let response = request.send().await.map_err(|err| {
            CliError::Operational(format!("registry token endpoint {realm}: {err}"))
        })?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CliError::Auth(if self.auth.is_some() {
                format!("registry rejected the credentials at {realm}")
            } else {
                format!("authentication required for {realm}; run orc login")
            }));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "registry token endpoint {realm} returned {status}"
            )));
        }
        let body: TokenResponse = response.json().await.map_err(|err| {
            CliError::Operational(format!("decode token response from {realm}: {err}"))
        })?;
        let token = body
            .token
            .filter(|token| !token.is_empty())
            .or(body.access_token.filter(|token| !token.is_empty()))
            .ok_or_else(|| {
                CliError::Operational(format!("token endpoint {realm} returned no token"))
            })?;
        // 10s slack under the advertised TTL; the Docker token spec minimum is 60s.
        let ttl = Duration::from_secs(body.expires_in.unwrap_or(60).max(60))
            .saturating_sub(Duration::from_secs(10));
        let expires_at = Instant::now() + ttl;
        let mut tokens = self.tokens.lock().expect("token cache lock");
        for key in token_cache_keys(challenge.scope.as_deref()) {
            tokens.insert(
                key,
                CachedToken {
                    token: token.clone(),
                    expires_at,
                },
            );
        }
        drop(tokens);
        Ok(token)
    }

    fn status_error(operation: &str, path: &str, status: reqwest::StatusCode) -> CliError {
        if status == reqwest::StatusCode::NOT_FOUND {
            CliError::NotFound(format!("registry resource not found: {path}"))
        } else {
            CliError::Operational(format!("{operation} returned {status}"))
        }
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Result<RegistryResponse> {
        let response = self
            .execute(Method::GET, &self.url_for_path(path), headers, None)
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(format!(
                "registry resource not found: {path}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "registry GET {path} returned {status}"
            )));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = response
            .bytes()
            .await
            .map_err(|err| CliError::Operational(format!("read registry response: {err}")))?
            .to_vec();
        let digest = digest_bytes(&body);
        Ok(RegistryResponse {
            body,
            content_type,
            digest,
        })
    }

    fn url_for_path(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn url_for_location(&self, location: &str) -> String {
        if location.starts_with("http://") || location.starts_with("https://") {
            location.to_owned()
        } else if location.starts_with('/') {
            format!("{}{}", self.base, location)
        } else {
            format!("{}/{}", self.base, location)
        }
    }
}

/// Picks the challenge to act on from a 401 response: the first Bearer
/// challenge across all `WWW-Authenticate` headers, else the first Basic.
fn select_challenge(headers: &reqwest::header::HeaderMap) -> Option<AuthChallenge> {
    let challenges = headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(parse_www_authenticate)
        .collect::<Vec<_>>();
    challenges
        .iter()
        .find(|challenge| matches!(challenge, AuthChallenge::Bearer(_)))
        .cloned()
        .or_else(|| {
            challenges
                .into_iter()
                .find(|challenge| matches!(challenge, AuthChallenge::Basic))
        })
}

/// Parses an RFC 7235 `WWW-Authenticate` header value into the challenges we
/// understand. Bearer challenges without a realm and unknown schemes are
/// dropped; garbage yields an empty list.
fn parse_www_authenticate(value: &str) -> Vec<AuthChallenge> {
    let mut raw: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for segment in split_challenge_segments(value) {
        if let Some((scheme, rest)) = split_scheme_prefix(&segment) {
            let mut params = Vec::new();
            if let Some(param) = parse_auth_param(rest) {
                params.push(param);
            }
            raw.push((scheme, params));
        } else if let Some(param) = parse_auth_param(&segment)
            && let Some((_, params)) = raw.last_mut()
        {
            params.push(param);
        }
    }
    raw.into_iter()
        .filter_map(
            |(scheme, params)| match scheme.to_ascii_lowercase().as_str() {
                "bearer" => {
                    let mut realm = None;
                    let mut service = None;
                    let mut scope = None;
                    for (key, value) in params {
                        match key.as_str() {
                            "realm" => realm = Some(value),
                            "service" => service = Some(value),
                            "scope" => scope = Some(value),
                            _ => {}
                        }
                    }
                    realm.map(|realm| {
                        AuthChallenge::Bearer(BearerChallenge {
                            realm,
                            service,
                            scope,
                        })
                    })
                }
                "basic" => Some(AuthChallenge::Basic),
                _ => None,
            },
        )
        .collect()
}

/// Splits a header value at commas that are outside double-quoted strings
/// (quoted parameter values like `scope="repository:x:pull,push"` contain
/// literal commas).
fn split_challenge_segments(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                current.push(ch);
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => segments.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    segments.push(current);
    segments
        .into_iter()
        .map(|segment| segment.trim().to_owned())
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Returns `(scheme, remainder)` when the segment starts a new challenge:
/// either a bare scheme token, or a scheme followed by its first parameter.
fn split_scheme_prefix(segment: &str) -> Option<(String, &str)> {
    let is_scheme_token = |word: &str| {
        !word.is_empty()
            && word
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            && !word.contains('=')
    };
    match segment.split_once(char::is_whitespace) {
        Some((word, rest)) if is_scheme_token(word) => Some((word.to_owned(), rest)),
        None if is_scheme_token(segment) => Some((segment.to_owned(), "")),
        _ => None,
    }
}

fn parse_auth_param(segment: &str) -> Option<(String, String)> {
    let (key, value) = segment.split_once('=')?;
    let key = key.trim().to_ascii_lowercase();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return None;
    }
    let value = value.trim();
    let value = if let Some(inner) = value.strip_prefix('"') {
        unescape_quoted(inner.strip_suffix('"').unwrap_or(inner))
    } else {
        value.to_owned()
    };
    Some((key, value))
}

fn unescape_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// The single-action scope a request needs, used as the token cache-lookup key.
/// Naming one action rather than a set is what keeps the key registry-agnostic:
/// registries disagree on how they group actions into a challenge scope (this
/// registry challenges a blob PUT with `push`, ghcr.io with `pull,push`), and
/// [`token_cache_keys`] files a granted token under each action it covers, so
/// either shape satisfies this lookup.
///
/// A miss only costs a round trip on a bodyless request. On a request carrying
/// a body it costs the upload: the registry answers 401 without draining the
/// body, and a large body still in flight dies with the connection.
fn scope_hint(method: &Method, path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix("/v2/")?;
    if rest == "_catalog" || rest.starts_with("_catalog?") {
        return Some("registry:catalog:*".to_owned());
    }
    let keyword_start = ["/manifests/", "/blobs/", "/tags/"]
        .iter()
        .filter_map(|keyword| rest.rfind(keyword))
        .max()?;
    let repository = &rest[..keyword_start];
    if repository.is_empty() {
        return None;
    }
    let action = if matches!(*method, Method::GET | Method::HEAD) {
        "pull"
    } else {
        "push"
    };
    Some(format!("repository:{repository}:{action}"))
}

/// Explodes a granted challenge scope into one cache key per action, so a
/// `repository:acme/app:pull,push` grant answers both a `pull` and a `push`
/// lookup. A scope-less token is filed under `""`, the wildcard fallback.
/// Anything that is not a `repository:` scope (`registry:catalog:*`) is its own
/// key and needs no splitting.
fn token_cache_keys(scope: Option<&str>) -> Vec<String> {
    let Some(scope) = scope else {
        return vec![String::new()];
    };
    let Some((repository, actions)) = scope
        .strip_prefix("repository:")
        .and_then(|rest| rest.rsplit_once(':'))
    else {
        return vec![scope.to_owned()];
    };
    let keys: Vec<String> = actions
        .split(',')
        .map(str::trim)
        .filter(|action| !action.is_empty())
        .map(|action| format!("repository:{repository}:{action}"))
        .collect();
    if keys.is_empty() {
        vec![scope.to_owned()]
    } else {
        keys
    }
}

/// Extracts the path portion of an absolute URL for error messages and scope
/// hints.
fn request_path(url: &str) -> &str {
    url.find("://")
        .and_then(|scheme| {
            let host_start = scheme + 3;
            url[host_start..]
                .find('/')
                .map(|slash| &url[host_start + slash..])
        })
        .unwrap_or(url)
}

/// Byte batches held in flight between the download task and a blocking reader. Eight
/// batches of whatever the transport hands over (~16-64 KiB each) is enough to keep a
/// decoder fed without letting the download run away from it.
const BLOB_READER_QUEUE: usize = 8;

/// A blob being downloaded, presented as a blocking reader.
///
/// See [`RegistryClient::get_blob_reader`]: read it from a blocking thread, and treat the
/// error at EOF as "these bytes were not what the digest promised".
pub struct BlobReader {
    receiver: tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    current: Vec<u8>,
    offset: usize,
    /// Taken at EOF to finalize the digest check; `None` afterwards, so a second read
    /// after EOF returns a clean 0 rather than re-verifying.
    hasher: Option<Sha256>,
    expected: String,
}

impl std::io::Read for BlobReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.offset < self.current.len() {
                let take = (self.current.len() - self.offset).min(buf.len());
                buf[..take].copy_from_slice(&self.current[self.offset..self.offset + take]);
                self.offset += take;
                return Ok(take);
            }
            match self.receiver.blocking_recv() {
                Some(Ok(bytes)) => {
                    if let Some(hasher) = self.hasher.as_mut() {
                        hasher.update(&bytes);
                    }
                    self.current = bytes;
                    self.offset = 0;
                }
                Some(Err(err)) => return Err(std::io::Error::other(err)),
                None => {
                    let Some(hasher) = self.hasher.take() else {
                        return Ok(0);
                    };
                    let actual = hex32(&hasher.finalize().into());
                    if actual != self.expected {
                        return Err(std::io::Error::other(format!(
                            "registry blob digest mismatch: expected sha256:{}, read sha256:{actual}",
                            self.expected
                        )));
                    }
                    return Ok(0);
                }
            }
        }
    }
}

/// Builds the `POST` recipe body for a **sealed** app-data layer, whose frames the caller
/// framed itself rather than reading out of an assembled blob. Same schema as
/// [`chunked_recipe_body`]; the entries already carry their offsets and lengths.
pub(crate) fn sealed_recipe_body(
    layer_digest: &str,
    total_length: u64,
    media_type: &str,
    entries: &[crate::persist::stream::SealedRecipeEntry],
) -> serde_json::Value {
    let chunks: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "frame_cid": format!("blake3:{}", entry.frame_cid),
                "frame_offset": entry.frame_offset,
                "frame_length": entry.frame_length,
                "raw_length": entry.raw_length,
                "compressed": entry.compressed,
            })
        })
        .collect();
    serde_json::json!({
        "digest": layer_digest,
        "total_length": total_length,
        "media_type": media_type,
        "chunks": chunks,
    })
}

/// Reads a negotiate `429` — the per-principal session cap — into a sentence that says
/// what is actually wrong.
///
/// The registry answers with the OCI error envelope and puts the number of sessions it is
/// holding in the machine-readable `detail`, so the count is read rather than scraped out
/// of the prose. Without the count the message still names the cause.
async fn sessions_held(response: reqwest::Response) -> CliError {
    #[derive(serde::Deserialize, Default)]
    struct Envelope {
        #[serde(default)]
        errors: Vec<OciError>,
    }
    #[derive(serde::Deserialize, Default)]
    struct OciError {
        #[serde(default)]
        detail: String,
        #[serde(default)]
        message: String,
    }
    let first = response
        .bytes()
        .await
        .ok()
        .and_then(|body| serde_json::from_slice::<Envelope>(&body).ok())
        .and_then(|envelope| envelope.errors.into_iter().next())
        .unwrap_or_default();
    match first.detail.trim().parse::<usize>() {
        Ok(held) => CliError::Operational(format!(
            "the registry is holding {held} earlier upload sessions of this node and will \
             not open another; retrying once one of them is finalized, abandoned, or times out"
        )),
        Err(_) => CliError::Operational(format!(
            "the registry is holding earlier upload sessions of this node and will not open \
             another; retrying ({})",
            first.message
        )),
    }
}

/// Control flow for the negotiated upload: `Retry` re-POSTs the recipe (resume), `Fatal`
/// bails to the monolithic fallback.
pub(crate) enum ChunkedResume {
    Retry,
    Fatal(CliError),
}

/// One blob chunk on the wire (a payload frame or the trailing skippable TOC frame).
struct WireFrame {
    cid: [u8; 32],
    offset: u64,
    length: u64,
    raw_length: u32,
    compressed: bool,
}

/// Enumerates every chunk of the assembled blob: the payload frames recorded in the
/// [`Toc`](crate::chunked::Toc), followed by the trailing skippable TOC frame (raw length 0)
/// that occupies `[frame_region_len, blob.len())`. The concatenation of these frames *is*
/// the blob, so the server's reassembly is byte-exact.
fn wire_frames(blob: &[u8], toc: &crate::chunked::Toc) -> Vec<WireFrame> {
    let mut frames: Vec<WireFrame> = toc
        .chunks
        .iter()
        .map(|chunk| WireFrame {
            cid: chunk.frame_cid,
            offset: chunk.frame_offset,
            length: chunk.frame_length,
            raw_length: chunk.raw_length,
            compressed: chunk.compressed,
        })
        .collect();
    let frame_region_len = toc
        .chunks
        .last()
        .map_or(0, |chunk| chunk.frame_offset + chunk.frame_length);
    let region = usize::try_from(frame_region_len).unwrap_or(usize::MAX);
    let toc_frame = &blob[region.min(blob.len())..];
    frames.push(WireFrame {
        cid: crate::chunked::frame_cid(toc_frame),
        offset: frame_region_len,
        length: toc_frame.len() as u64,
        raw_length: 0,
        compressed: false,
    });
    frames
}

/// Builds the `POST` recipe body from the wire frames: the declared layer digest, the
/// decompressed total, the layer media type, and one entry per blob chunk (payload frames
/// plus the trailing TOC skippable frame), matching the server's `RecipeRequest` schema.
/// Frame cids are emitted as `blake3:<hex>`.
fn chunked_recipe_body(
    layer_digest: &str,
    total_length: u64,
    media_type: &str,
    wire: &[WireFrame],
) -> serde_json::Value {
    let chunks: Vec<serde_json::Value> = wire
        .iter()
        .map(|frame| {
            serde_json::json!({
                "frame_cid": format!("blake3:{}", hex32(&frame.cid)),
                "frame_offset": frame.offset,
                "frame_length": frame.length,
                "raw_length": frame.raw_length,
                "compressed": frame.compressed,
            })
        })
        .collect();
    serde_json::json!({
        "digest": layer_digest,
        "total_length": total_length,
        "media_type": media_type,
        "chunks": chunks,
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Default transfer-chunk size for blob uploads: 64 MiB, safely under the ~100 MB request-body
/// cap the fleet's edge imposes on a single PUT. A blob larger than the chunk size is uploaded
/// as several `PATCH`es of at most this many bytes.
const UPLOAD_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Longest tolerated gap between download chunks in [`RegistryClient::get_blob_to_file`]
/// before the stream is declared stalled. Generous for slow links (any liveness resets
/// it), but bounded so a silently dropped connection fails instead of hanging a
/// transfer forever.
const BLOB_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The transfer-chunk size for this call, from `ORC_UPLOAD_CHUNK_BYTES` when set (parsed as a
/// `usize`, floored at 1 MiB) or [`UPLOAD_CHUNK_SIZE`] otherwise. Read lazily per upload rather
/// than cached, so a test or operator can retune it without a restart.
fn upload_chunk_size() -> usize {
    parse_chunk_size(std::env::var("ORC_UPLOAD_CHUNK_BYTES").ok())
}

/// Resolves an `ORC_UPLOAD_CHUNK_BYTES` value to a chunk size: a valid positive `usize` floored
/// at 1 MiB, or [`UPLOAD_CHUNK_SIZE`] for an absent/empty/unparseable value. Pure so the env
/// policy is unit-testable without mutating the process environment.
fn parse_chunk_size(raw: Option<String>) -> usize {
    const MIN_CHUNK_SIZE: usize = 1024 * 1024;
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .map_or(UPLOAD_CHUNK_SIZE, |value| value.max(MIN_CHUNK_SIZE))
}

/// Splits a body of `len` bytes into `[start, end)` slices of at most `chunk_size` bytes each.
/// Empty for a zero-length body; a final short slice carries the remainder. `chunk_size` is
/// floored at 1 to keep the walk finite.
fn chunk_boundaries(len: usize, chunk_size: usize) -> Vec<(usize, usize)> {
    let chunk_size = chunk_size.max(1);
    let mut ranges = Vec::new();
    let mut offset = 0;
    while offset < len {
        let end = offset.saturating_add(chunk_size).min(len);
        ranges.push((offset, end));
        offset = end;
    }
    ranges
}

/// Formats a `Content-Range` value for a `[start, end)` slice as `<start>-<end-1>` (end
/// inclusive), matching the server's parse of the range start.
fn content_range(start: usize, end_exclusive: usize) -> String {
    format!("{start}-{}", end_exclusive.saturating_sub(1))
}

/// Reads the `Location` header of a registry upload response.
fn location_header(response: &reqwest::Response) -> Result<String> {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| CliError::Operational("registry upload omitted Location".to_owned()))
}

#[must_use]
pub fn digest_bytes(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Refuses bytes that do not hash to the digest they were asked for.
pub(crate) fn verify_digest(body: &[u8], expected: &str) -> Result<()> {
    let actual = digest_bytes(body);
    if actual == expected {
        Ok(())
    } else {
        Err(CliError::Operational(format!(
            "blob digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn registry_base_url(registry: &str, insecure: bool) -> String {
    if registry == "ghcr.io"
        && let Ok(base) = std::env::var("ORC_GHCR_REGISTRY_BASE_URL")
    {
        return base.trim_end_matches('/').to_owned();
    }
    let scheme = if insecure || is_loopback(registry) {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{registry}")
}

fn is_loopback(registry: &str) -> bool {
    let host = registry.split_once(':').map_or(registry, |(host, _)| host);
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer(realm: &str, service: Option<&str>, scope: Option<&str>) -> AuthChallenge {
        AuthChallenge::Bearer(BearerChallenge {
            realm: realm.to_owned(),
            service: service.map(str::to_owned),
            scope: scope.map(str::to_owned),
        })
    }

    #[test]
    fn parses_ghcr_bearer_challenge() {
        let parsed = parse_www_authenticate(
            "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:acme/runner:pull\"",
        );
        assert_eq!(
            parsed,
            [bearer(
                "https://ghcr.io/token",
                Some("ghcr.io"),
                Some("repository:acme/runner:pull")
            )]
        );
    }

    #[test]
    fn parses_bearer_challenge_without_scope() {
        let parsed = parse_www_authenticate(
            "Bearer realm=\"http://localhost:8080/api/auth/registry/token\",service=\"orc-registry\"",
        );
        assert_eq!(
            parsed,
            [bearer(
                "http://localhost:8080/api/auth/registry/token",
                Some("orc-registry"),
                None
            )]
        );
    }

    #[test]
    fn quoted_scope_with_comma_is_one_param() {
        let parsed = parse_www_authenticate(
            "Bearer realm=\"https://t/token\",scope=\"repository:a:pull,push\"",
        );
        assert_eq!(
            parsed,
            [bearer(
                "https://t/token",
                None,
                Some("repository:a:pull,push")
            )]
        );
    }

    #[test]
    fn parses_unquoted_param_values() {
        let parsed = parse_www_authenticate("Bearer realm=https://t/token,service=reg");
        assert_eq!(parsed, [bearer("https://t/token", Some("reg"), None)]);
    }

    #[test]
    fn parses_escaped_quotes_in_quoted_string() {
        let parsed = parse_www_authenticate(r#"Bearer realm="https://t/\"quoted\"""#);
        assert_eq!(parsed, [bearer(r#"https://t/"quoted""#, None, None)]);
    }

    #[test]
    fn recognizes_basic_challenge() {
        assert_eq!(
            parse_www_authenticate("Basic realm=\"orc-registry-token\""),
            [AuthChallenge::Basic]
        );
        assert_eq!(parse_www_authenticate("Basic"), [AuthChallenge::Basic]);
    }

    #[test]
    fn mixed_challenges_parse_in_order() {
        let parsed =
            parse_www_authenticate("Basic realm=\"r\", Bearer realm=\"https://t\",service=\"s\"");
        assert_eq!(
            parsed,
            [AuthChallenge::Basic, bearer("https://t", Some("s"), None)]
        );
    }

    #[test]
    fn select_challenge_prefers_bearer_over_basic() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::WWW_AUTHENTICATE,
            "Basic realm=\"r\", Bearer realm=\"https://t\""
                .parse()
                .expect("header"),
        );
        assert_eq!(
            select_challenge(&headers),
            Some(bearer("https://t", None, None))
        );
    }

    #[test]
    fn garbage_header_yields_nothing() {
        assert_eq!(parse_www_authenticate("???,,,==="), []);
        assert_eq!(parse_www_authenticate(""), []);
    }

    #[test]
    fn bearer_without_realm_is_dropped() {
        assert_eq!(parse_www_authenticate("Bearer service=\"s\""), []);
    }

    #[test]
    fn scope_hints_cover_catalog_manifests_blobs_and_tags() {
        let cases = [
            (
                Method::GET,
                "/v2/_catalog?n=100",
                Some("registry:catalog:*"),
            ),
            (
                Method::GET,
                "/v2/acme/runner/manifests/default",
                Some("repository:acme/runner:pull"),
            ),
            (
                Method::HEAD,
                "/v2/app/blobs/sha256:abc",
                Some("repository:app:pull"),
            ),
            (
                Method::PUT,
                "/v2/acme/runner/manifests/1.0",
                Some("repository:acme/runner:push"),
            ),
            (
                Method::POST,
                "/v2/a/b/c/blobs/uploads/",
                Some("repository:a/b/c:push"),
            ),
            (
                Method::PUT,
                "/v2/acme/runner/blobs/uploads/abc-123?digest=sha256:ff",
                Some("repository:acme/runner:push"),
            ),
            (
                Method::GET,
                "/v2/acme/app/tags/list",
                Some("repository:acme/app:pull"),
            ),
            (Method::GET, "/api/other", None),
            (Method::GET, "/v2/", None),
        ];
        for (method, path, expected) in cases {
            assert_eq!(
                scope_hint(&method, path).as_deref(),
                expected,
                "{method} {path}"
            );
        }
    }

    /// A granted scope is filed under every action it covers, so that a `push`
    /// lookup hits whether the registry challenged with `push` (this registry)
    /// or `pull,push` (ghcr.io). A miss here sends the next blob PUT anonymous.
    #[test]
    fn granted_scope_is_cached_under_each_action() {
        assert_eq!(
            token_cache_keys(Some("repository:acme/app:push")),
            ["repository:acme/app:push"]
        );
        assert_eq!(
            token_cache_keys(Some("repository:acme/app:pull,push")),
            ["repository:acme/app:pull", "repository:acme/app:push"]
        );
        assert_eq!(token_cache_keys(None), [""]);
        assert_eq!(
            token_cache_keys(Some("registry:catalog:*")),
            ["registry:catalog:*"]
        );
    }

    /// The cache key a blob PUT looks up must be one the token exchange filed,
    /// for both the challenge shapes we see in the wild. This pairing is the
    /// whole contract; when it broke, every large blob push died mid-body.
    #[test]
    fn blob_put_scope_hint_hits_tokens_cached_from_either_challenge() {
        let hint = scope_hint(
            &Method::PUT,
            "/v2/acme/app/blobs/uploads/s1?digest=sha256:ab",
        )
        .expect("hint");
        for challenge in ["repository:acme/app:push", "repository:acme/app:pull,push"] {
            assert!(
                token_cache_keys(Some(challenge)).contains(&hint),
                "{challenge} must satisfy {hint}"
            );
        }
    }

    #[test]
    fn chunk_boundaries_cover_edges_multiples_and_remainder() {
        assert!(
            chunk_boundaries(0, 4).is_empty(),
            "a zero-length body has no chunks"
        );
        assert_eq!(chunk_boundaries(8, 4), [(0, 4), (4, 8)], "exact multiple");
        assert_eq!(
            chunk_boundaries(10, 4),
            [(0, 4), (4, 8), (8, 10)],
            "trailing remainder"
        );
        assert_eq!(
            chunk_boundaries(3, 4),
            [(0, 3)],
            "body smaller than a chunk"
        );
        assert_eq!(chunk_boundaries(4, 4), [(0, 4)], "body exactly one chunk");
        assert_eq!(
            chunk_boundaries(2, 0),
            [(0, 1), (1, 2)],
            "a zero chunk size is floored to 1 so the walk terminates"
        );
    }

    #[test]
    fn content_range_is_end_inclusive() {
        assert_eq!(content_range(0, 4), "0-3");
        assert_eq!(content_range(8, 10), "8-9");
        assert_eq!(content_range(5, 6), "5-5", "a single-byte slice");
    }

    #[test]
    fn parse_chunk_size_defaults_and_floors() {
        assert_eq!(parse_chunk_size(None), UPLOAD_CHUNK_SIZE);
        assert_eq!(parse_chunk_size(Some(String::new())), UPLOAD_CHUNK_SIZE);
        assert_eq!(
            parse_chunk_size(Some("not-a-number".to_owned())),
            UPLOAD_CHUNK_SIZE
        );
        assert_eq!(
            parse_chunk_size(Some("1024".to_owned())),
            1024 * 1024,
            "sub-1-MiB values floor at 1 MiB"
        );
        assert_eq!(
            parse_chunk_size(Some((8 * 1024 * 1024).to_string())),
            8 * 1024 * 1024
        );
        assert_eq!(
            parse_chunk_size(Some("  4194304  ".to_owned())),
            4 * 1024 * 1024,
            "surrounding whitespace is trimmed"
        );
    }

    #[test]
    fn request_path_strips_scheme_and_host() {
        assert_eq!(
            request_path("https://ghcr.io/v2/acme/app/manifests/default"),
            "/v2/acme/app/manifests/default"
        );
        assert_eq!(
            request_path("http://127.0.0.1:5000/v2/_catalog"),
            "/v2/_catalog"
        );
        assert_eq!(request_path("/already/a/path"), "/already/a/path");
    }

    /// Reads one request off a fresh connection, asserts on it, and answers
    /// with `connection: close` so the client cannot reuse the socket.
    fn serve_one(
        listener: &std::net::TcpListener,
        check: impl FnOnce(&str),
        status_line: &str,
        extra_headers: &str,
        body: &str,
    ) {
        use std::io::{Read as _, Write as _};

        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let read = stream.read(&mut buf).expect("read request");
        let request = String::from_utf8_lossy(&buf[..read]).to_ascii_lowercase();
        check(&request);
        let response = format!(
            "HTTP/1.1 {status_line}\r\n{extra_headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    /// The docker-login credential must never be pre-sent to the registry
    /// host (ghcr.io answers a raw PAT bearer with a terminal 403). The first
    /// attempt goes anonymous, the Bearer challenge drives a Basic exchange
    /// at the token endpoint, and the retry carries the issued token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn basic_credential_is_exchanged_via_challenge_not_pre_sent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            serve_one(
                &listener,
                |request| assert!(!request.contains("authorization:"), "{request}"),
                "401 Unauthorized",
                &format!(
                    "www-authenticate: Bearer realm=\"http://{addr}/token\",service=\"test\"\r\n"
                ),
                "",
            );
            serve_one(
                &listener,
                |request| {
                    assert!(request.starts_with("get /token"), "{request}");
                    // base64("user:s3cret")
                    assert!(
                        request.contains("authorization: basic dxnlcjpzm2nyzxq="),
                        "{request}"
                    );
                },
                "200 OK",
                "content-type: application/json\r\n",
                r#"{"token":"issued-token","expires_in":300}"#,
            );
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.contains("authorization: bearer issued-token"),
                        "{request}"
                    );
                },
                "200 OK",
                "",
                "",
            );
        });

        let credential = StoredCredential {
            username: "user".to_owned(),
            token: "s3cret".to_owned(),
        };
        let client =
            RegistryClient::new(&addr.to_string(), Some(&credential), true).expect("client");
        client.ping().await.expect("ping through token exchange");
        server.join().expect("server thread");
    }

    /// A pre-minted registry JWT is the one credential sent as-is up front.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bearer_credential_is_sent_as_is_up_front() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.contains("authorization: bearer minted-jwt"),
                        "{request}"
                    );
                },
                "200 OK",
                "",
                "",
            );
        });

        let client = RegistryClient::with_bearer(&addr.to_string(), "minted-jwt".to_owned(), true)
            .expect("client");
        client.ping().await.expect("ping with pre-minted bearer");
        server.join().expect("server thread");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_blob_streams_body_and_reports_download_progress() {
        use crate::progress::test_support::RecordingReporter;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = "a streamed blob payload";
        let total = u64::try_from(payload.len()).expect("len");
        let server = std::thread::spawn(move || {
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.starts_with("get /v2/acme/app/blobs/sha256:"),
                        "{request}"
                    );
                },
                "200 OK",
                "",
                payload,
            );
        });

        let recorder = RecordingReporter::shared();
        let client = RegistryClient::new(&addr.to_string(), None, true)
            .expect("client")
            .with_progress(recorder.clone());
        let digest = digest_bytes(payload.as_bytes());
        let body = client.get_blob("acme/app", &digest).await.expect("blob");
        server.join().expect("server thread");

        assert_eq!(body, payload.as_bytes());
        let events = recorder.events();
        assert!(!events.is_empty(), "expected download events");
        assert!(
            events
                .iter()
                .all(|event| event.key == digest && event.kind == ProgressKind::Blob),
            "all events key the blob digest"
        );
        assert_eq!(
            events.first().expect("first").phase,
            ProgressPhase::Downloading {
                done: 0,
                total: Some(total)
            },
            "first event starts at zero with the known total"
        );
        assert_eq!(
            events.last().expect("last").phase,
            ProgressPhase::Downloading {
                done: total,
                total: Some(total)
            },
            "final event reaches the total"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_blob_without_reporter_still_returns_body() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = "no reporter attached";
        let server = std::thread::spawn(move || {
            serve_one(&listener, |_| {}, "200 OK", "", payload);
        });

        let client = RegistryClient::new(&addr.to_string(), None, true).expect("client");
        let body = client
            .get_blob("acme/app", &digest_bytes(payload.as_bytes()))
            .await
            .expect("blob");
        server.join().expect("server thread");
        assert_eq!(body, payload.as_bytes());
    }

    /// A registry that challenges will refuse an anonymous write, so a client
    /// with no credential must fail before the body rather than stream one at a
    /// request that is already doomed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upload_without_a_credential_fails_before_sending_the_body() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            // HEAD: blob absent, so the upload starts.
            serve_one(&listener, |_| {}, "404 Not Found", "", "");
            // POST upload start: bodyless, so it may take the 401 itself.
            serve_one(
                &listener,
                |request| assert!(request.starts_with("post "), "{request}"),
                "202 Accepted",
                "location: /v2/acme/app/blobs/uploads/sess\r\n",
                "",
            );
            // The PUT's preflight probe: challenged, and there is no credential
            // to answer it. No PUT may follow.
            serve_one(
                &listener,
                |request| assert!(request.starts_with("get /v2/"), "{request}"),
                "401 Unauthorized",
                "www-authenticate: Basic realm=\"orc-registry-token\"\r\n",
                "",
            );
        });

        let client = RegistryClient::with_anonymous(&addr.to_string(), true).expect("client");
        let body = b"never leaves the client".to_vec();
        let err = client
            .ensure_blob("acme/app", &digest_bytes(&body), body)
            .await
            .expect_err("an anonymous upload is refused");
        assert!(
            matches!(err, CliError::Auth(_)),
            "expected an auth error, got {err:?}"
        );
        server.join().expect("server thread");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ensure_blob_reports_exists_when_present() {
        use crate::progress::test_support::RecordingReporter;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            // HEAD finds the blob already present.
            serve_one(
                &listener,
                |request| assert!(request.starts_with("head /v2/acme/app/blobs/"), "{request}"),
                "200 OK",
                "",
                "",
            );
        });

        let recorder = RecordingReporter::shared();
        let client = RegistryClient::new(&addr.to_string(), None, true)
            .expect("client")
            .with_progress(recorder.clone());
        let uploaded = client
            .ensure_blob("acme/app", &digest_bytes(b"x"), b"x".to_vec())
            .await
            .expect("ensure");
        server.join().expect("server thread");

        assert!(!uploaded, "blob already present so nothing is uploaded");
        assert_eq!(
            recorder.phases(),
            vec![ProgressPhase::Exists, ProgressPhase::Done]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ensure_blob_reports_upload_when_absent() {
        use crate::progress::test_support::RecordingReporter;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let body = b"upload me".to_vec();
        let total = u64::try_from(body.len()).expect("len");
        let server = std::thread::spawn(move || {
            // HEAD: not found -> upload starts.
            serve_one(
                &listener,
                |request| assert!(request.starts_with("head "), "{request}"),
                "404 Not Found",
                "",
                "",
            );
            // POST: upload session accepted, hand back a Location.
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.starts_with("post /v2/acme/app/blobs/uploads/"),
                        "{request}"
                    );
                },
                "202 Accepted",
                "location: /v2/acme/app/blobs/uploads/session-1\r\n",
                "",
            );
            // The PUT's preflight probe: this registry challenges nothing, so
            // the body goes out anonymously.
            serve_one(
                &listener,
                |request| assert!(request.starts_with("get /v2/"), "{request}"),
                "200 OK",
                "",
                "",
            );
            // PUT: upload completes.
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.starts_with("put /v2/acme/app/blobs/uploads/session-1"),
                        "{request}"
                    );
                },
                "201 Created",
                "",
                "",
            );
        });

        let recorder = RecordingReporter::shared();
        let client = RegistryClient::new(&addr.to_string(), None, true)
            .expect("client")
            .with_progress(recorder.clone());
        let uploaded = client
            .ensure_blob("acme/app", &digest_bytes(&body), body)
            .await
            .expect("ensure");
        server.join().expect("server thread");

        assert!(uploaded, "absent blob is uploaded");
        assert_eq!(
            recorder.phases(),
            vec![
                ProgressPhase::Uploading {
                    done: 0,
                    total: Some(total)
                },
                ProgressPhase::Uploading {
                    done: total,
                    total: Some(total)
                },
                ProgressPhase::Done,
            ]
        );
    }

    /// A body larger than the chunk size uploads as `POST → N × PATCH → empty-body PUT`, each
    /// PATCH carrying an end-inclusive `Content-Range` and the finalize PUT carrying `?digest=`
    /// with no body. A pre-minted bearer credential is sent up front, so no preflight `GET /v2/`
    /// interleaves the sequence. Per-chunk progress is reported keyed by the blob digest.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ensure_blob_chunked_uploads_body_in_patches() {
        use crate::progress::test_support::RecordingReporter;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let body = b"abcdefghij".to_vec(); // 10 bytes, chunk size 4 -> ranges 0-3, 4-7, 8-9.
        let server = std::thread::spawn(move || {
            // HEAD: blob absent, so the upload starts.
            serve_one(
                &listener,
                |request| assert!(request.starts_with("head /v2/acme/app/blobs/"), "{request}"),
                "404 Not Found",
                "",
                "",
            );
            // POST: open the upload session.
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.starts_with("post /v2/acme/app/blobs/uploads/"),
                        "{request}"
                    );
                },
                "202 Accepted",
                "location: /v2/acme/app/blobs/uploads/sess\r\n",
                "",
            );
            // Three PATCHes, each with an end-inclusive Content-Range against the session URL.
            for (range, echoed) in [("0-3", "0-3"), ("4-7", "0-7"), ("8-9", "0-9")] {
                serve_one(
                    &listener,
                    move |request| {
                        assert!(
                            request.starts_with("patch /v2/acme/app/blobs/uploads/sess"),
                            "{request}"
                        );
                        assert!(
                            request.contains(&format!("content-range: {range}")),
                            "want content-range {range} in {request}"
                        );
                    },
                    "202 Accepted",
                    &format!("location: /v2/acme/app/blobs/uploads/sess\r\nrange: {echoed}\r\n"),
                    "",
                );
            }
            // PUT: finalize with ?digest= and an empty body.
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.starts_with("put /v2/acme/app/blobs/uploads/sess"),
                        "{request}"
                    );
                    assert!(request.contains("digest=sha256:"), "{request}");
                },
                "201 Created",
                "",
                "",
            );
        });

        let recorder = RecordingReporter::shared();
        let client = RegistryClient::with_bearer(&addr.to_string(), "tok".to_owned(), true)
            .expect("client")
            .with_progress(recorder.clone());
        let digest = digest_bytes(&body);
        let uploaded = client
            .ensure_blob_chunked("acme/app", &digest, body, 4)
            .await
            .expect("chunked ensure");
        server.join().expect("server thread");

        assert!(uploaded, "absent blob is uploaded via the chunked path");
        let phases = recorder.phases();
        // Per-chunk progress lands on each boundary, then the completion bracket.
        for done in [0u64, 4, 8, 10] {
            assert!(
                phases.contains(&ProgressPhase::Uploading {
                    done,
                    total: Some(10)
                }),
                "expected an Uploading event at {done}, got {phases:?}"
            );
        }
        assert!(phases.contains(&ProgressPhase::Done), "{phases:?}");
    }

    #[tokio::test]
    async fn get_blob_to_file_streams_and_verifies() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let body = b"streamed straight to disk".to_vec();
        let digest = digest_bytes(&body);
        let served = body.clone();
        let server = std::thread::spawn(move || {
            serve_one(
                &listener,
                |request| {
                    assert!(
                        request.starts_with("get /v2/acme/app/blobs/sha256:"),
                        "{request}"
                    );
                },
                "200 OK",
                "",
                std::str::from_utf8(&served).expect("utf8 fixture"),
            );
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("payload.raw");
        let client =
            RegistryClient::with_bearer(&addr.to_string(), "tok".to_owned(), true).expect("client");
        let written = client
            .get_blob_to_file("acme/app", &digest, &dest)
            .await
            .expect("streamed get");
        server.join().expect("server thread");

        assert_eq!(written, body.len() as u64);
        assert_eq!(std::fs::read(&dest).expect("read dest"), body);
        assert!(
            !dest.with_extension("partial").exists(),
            "partial must be renamed away on success"
        );
    }

    #[tokio::test]
    async fn get_blob_to_file_fails_a_stalled_stream() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Serve headers + a partial body, then hang without closing — the shape of
        // an edge proxy silently dropping a long download (observed live: a
        // transfer wedged forever mid-stream).
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000000\r\n\r\npartial")
                .expect("write partial");
            stream.flush().expect("flush");
            // Hold the socket open, sending nothing, until the client gives up.
            std::thread::sleep(std::time::Duration::from_secs(3));
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("payload.raw");
        let client =
            RegistryClient::with_bearer(&addr.to_string(), "tok".to_owned(), true).expect("client");
        let err = client
            .get_blob_to_file_with_stall(
                "acme/app",
                &digest_bytes(b"whatever"),
                &dest,
                std::time::Duration::from_millis(300),
            )
            .await
            .expect_err("stalled stream must fail");
        assert!(format!("{err}").contains("stalled"), "{err}");
        assert!(!dest.exists());
        assert!(!dest.with_extension("partial").exists());
        server.join().expect("server thread");
    }

    #[tokio::test]
    async fn get_blob_to_file_rejects_digest_mismatch_and_removes_partial() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Serve different bytes than the digest the client asked for.
        let requested_digest = digest_bytes(b"what the caller expects");
        let server = std::thread::spawn(move || {
            serve_one(&listener, |_| {}, "200 OK", "", "corrupted body");
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("payload.raw");
        let client =
            RegistryClient::with_bearer(&addr.to_string(), "tok".to_owned(), true).expect("client");
        let err = client
            .get_blob_to_file("acme/app", &requested_digest, &dest)
            .await
            .expect_err("mismatch must fail");
        server.join().expect("server thread");

        assert!(format!("{err}").contains("hashed to sha256:"), "{err}");
        assert!(!dest.exists(), "no file may land at dest on mismatch");
        assert!(
            !dest.with_extension("partial").exists(),
            "partial must be cleaned up on mismatch"
        );
    }
}
