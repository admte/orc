//! Uploading a capture: sealed layers onto the registry's chunked-upload extension, then
//! the restore point itself.
//!
//! # One repository per app
//!
//! An uploader is bound to *one* repository, and for App data that repository belongs to
//! one app of one pool: [`app_repository`] puts every app under a leaf of the pool's base
//! (`…/appdata-workers/postgres`), and the layers, the index and the
//! `POST …/_orc/restore-points` commit all address it. A capture cycle covering three
//! apps therefore drives three uploaders, one per app, each with its own client, its own
//! cancellation and its own progress counter.
//!
//! # Why the ladder is not the ordinary one
//!
//! [`crate::registry::RegistryClient::push_chunked_layer`] takes an assembled blob and,
//! if negotiation fails for any reason, falls back to a monolithic `PUT` of the same
//! bytes. That fallback is right for an app image — pushed once — and wrong here. A
//! capture runs every few minutes forever; silently degrading to "upload the whole layer
//! again" would turn a 200 KiB delta into a 60 MiB one and nobody would notice until the
//! bill arrived. So this module drives negotiate → `PATCH` → finalize itself, over the
//! same crate-internal ladder, and **a negotiation failure is an error**.
//!
//! # Two passes for a big file
//!
//! A pack layer is small enough to seal into memory (~68 MiB worst case), so its frames
//! are built once and served from the buffer. A file that owns its layer can be any size,
//! and spooling a sealed copy to disk would double the write load of every capture on the
//! very node whose disk is the constraint. Instead it is encoded **twice**: pass 1 to
//! learn the frame boundaries and the layer digest, pass 2 to emit only the frames the
//! registry said it was missing. The codec is convergent — content-defined boundaries, a
//! one-shot zstd per chunk, a payload-derived nonce — so the two passes are byte-identical
//! by construction, and the layer digest is compared across them to prove it.
//!
//! One consequence worth recording: the *cid* of a compressible chunk depends on libzstd's
//! output. A libzstd version bump therefore changes those cids, and the first cycle after
//! a runtime upgrade re-uploads content already held by the registry.
//!
//! # Tokens
//!
//! The bearer for an app-data repository can be short-lived, and one credential can cover
//! every app repository under a caller-supplied base. The uploader holds a *provider*
//! rather than a fixed client, so an expiry in the middle of a
//! multi-gigabyte layer re-mints and resumes at negotiation — the frame cids are
//! content-addressed, so nothing already uploaded is re-sent.
//!
//! # Abandoning an upload
//!
//! Every byte this module sends is read off a *frozen view* of a volume, and that view
//! cannot be given back while a reader still holds it open. Dropping the future is
//! therefore not enough: the encoders are blocking threads, and a dropped future leaves
//! them reading a mount whose owner is trying to unmount it. So an upload is abandoned in
//! two steps — [`Uploader::cancel`], then *await the call* — and both the encoders and the
//! network ladder watch the token, so the second step comes back promptly.
//!
//! What the ladder does with the session it negotiated on its way out is the other half
//! of that. A cut cycle **keeps** it: the registry resumes a session on a `POST` of the
//! same recipe, so the next cycle's identical layer carries on from the frames this one
//! already got through instead of starting again from zero — which, on a node whose big
//! layer is cut every cycle, is the difference between a restore point eventually and
//! never. The same goes for an expired token: the attempt that re-mints one offers the
//! same recipe and lands back in the same session.
//!
//! A session is handed back (`DELETE`) only when nothing will resume it: the layer was
//! finalized (the registry closes the session itself, so there is nothing to hand back),
//! or the ladder failed in a way that re-offering the same recipe cannot get past — a
//! rejected `PATCH`, a re-encode that did not converge, a negotiation that would not
//! settle within its budget. Sessions the client keeps are bounded on the registry's own
//! side: at the per-principal cap it abandons a principal's least recently active session
//! to open the next one.
//!
//! # Telling slow from stuck
//!
//! What decides whether to abandon an upload is not how long it has been running — no
//! fixed throughput figure is right for both a same-datacentre push and a node on a
//! megabit uplink — but whether it is still *moving*. So the uploader carries a
//! monotonic counter of the bytes it has got through ([`Uploader::progress`]): a
//! `PATCH` the registry acknowledged, a frame negotiation said the registry already
//! holds and this capture therefore need not send, and the sealing pass a whole-file
//! layer does before it can negotiate anything at all. A caller can poll that counter
//! and cancel only an upload that has stopped advancing.
//!
//! The counter is a progress signal and not an accounting of wire bytes: a
//! re-negotiation credits the frames the registry holds a second time, and a whole-file
//! layer's sealing pass is counted alongside the frames it later sends. Both only ever
//! move it forward, which is the one property the watchdog reads.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{CliError, Result};
use crate::persist::pack::{LayerKind, LayerPlan, PlannedFile};
use crate::persist::seal::Sealer;
use crate::persist::stream::{SealedLayer, encode_sealed_stream};
use crate::persist::tree::LayerRef;
use crate::registry::{ChunkedResume, RegistryClient, sealed_recipe_body};
use tokio_util::sync::CancellationToken;

/// Media type declared for every App-data layer, index included.
///
/// This distinguishes the sealed stream from ordinary OCI layers and is part of the
/// restore-point wire contract.
pub const APPDATA_LAYER_MEDIA_TYPE: &str = "application/vnd.orc.appdata.layer.v1+zstd";

/// The repository one app's restore points live in: a caller-supplied base repository
/// plus the app's own leaf.
///
/// A pool's App data is not one pile. Every app that persists gets a repository of its
/// own under the pool's base — `acme/prod/appdata-workers/postgres` beside
/// `acme/prod/appdata-workers/redis` — so an app's blobs, points and tags are addressed
/// by the app they belong to instead of sharing one namespace with every other app on
/// the pool. The leaf keeps each app's blobs, points, and tags in its own namespace.
/// `base` is accepted verbatim and is never derived from deployment state.
#[must_use]
pub fn app_repository(base: &str, app: &str) -> String {
    let base = base.trim_end_matches('/');
    let leaf = app_leaf(app);
    if leaf.is_empty() {
        return base.to_owned();
    }
    format!("{base}/{leaf}")
}

/// The leaf of an app id: its last `/`-separated segment, so `sys/sys/postgres` is
/// `postgres` and a bare `postgres` is itself.
///
/// One function rather than an `rsplit` at every call site keeps repository construction
/// and commit payloads consistent for every app id.
#[must_use]
pub fn app_leaf(app: &str) -> &str {
    app.rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(app)
}

/// Bytes held in one `PATCH` before it is flushed.
///
/// Also the coarsest step the progress counter takes, since a batch is credited only
/// once the registry has acknowledged it. Eight mebibytes is a round trip's worth of
/// overhead nobody notices on a fast link and, at the watchdog's five-minute stall
/// limit, still one acknowledged step for a node sending under thirty kilobytes a
/// second — a link an upload should survive rather than be called stuck on.
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Re-negotiations before an upload is declared stuck. Matches the image path's budget.
const MAX_RESUME: usize = 3;

/// Supplies bearer credentials for an App-data repository.
///
/// `refresh` means the previous credential was rejected or is about to expire; an
/// implementation may cache credentials otherwise.
#[async_trait::async_trait]
pub trait TokenProvider: Send + Sync {
    /// A bearer authorized to push and pull the App-data repository.
    ///
    /// # Errors
    ///
    /// Returns whatever the login path failed with; the uploader surfaces it unchanged.
    async fn bearer(&self, refresh: bool) -> Result<String>;
}

/// What a commit asked the server to record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommitRequest {
    pub app: String,
    pub key_id: String,
    pub created_at: i64,
    pub index: LayerRef,
    pub layers: Vec<LayerRef>,
    /// Entries the index carries — narration only; the server does not verify it.
    pub files: u64,
    /// Plaintext bytes the point represents — narration only.
    pub bytes: u64,
    /// Why the point was taken. A final point is the one a node offers on its way out,
    /// and the server treats it as the end of this node's lineage rather than one more
    /// beat of the loop.
    pub kind: CommitKind,
}

/// Whether a restore point is one of the capture loop's or the last one a node takes
/// before it goes away.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitKind {
    #[default]
    Periodic,
    Final,
}

impl CommitKind {
    /// Whether this point closes the committing node's lineage.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Final)
    }
}

/// The server's answer to a commit, in its own vocabulary rather than a status code.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// This node is no longer the slot's occupant. Terminal: another node owns the
    /// lineage now, and this one must stop capturing.
    #[error("app data: this node no longer occupies its pool slot; capture stops here")]
    Fenced,
    /// The token's repository does not match the pool's. A configuration fault, not a race.
    #[error("app data: the push token does not authorize {0}")]
    Scope(String),
    #[error("app data: the pool has stored {stored} bytes of its {limit}-byte allowance")]
    Quota { stored: u64, limit: u64 },
    #[error("app data: the server does not hold layer {0} — it must be uploaded first")]
    UnknownBlob(String),
    #[error("app data: layer {0} is stored at a different size than the commit declares")]
    SizeMismatch(String),
    #[error("app data: {0:?} is not a persisting app of this pool")]
    UnknownApp(String),
    #[error(
        "app data: a restore point for this app was committed moments ago; \
         the server asks for {retry_after_secs}s"
    )]
    RateLimited {
        /// Seconds the server says are left on the lineage's commit interval. Zero
        /// when it did not say.
        retry_after_secs: i64,
    },
    #[error("app data: the registry could not verify the layers' sizes")]
    Store,
    #[error(transparent)]
    Transport(#[from] CliError),
    #[error("app data: commit returned {status}: {body}")]
    Unexpected { status: u16, body: String },
}

/// A committed restore point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutcome {
    pub id: String,
    /// `false` when the server matched an existing point with the same index digest — the
    /// idempotent landing of a retry after a lost response.
    pub created: bool,
}

/// Uploads sealed layers and commits restore points for one app's App-data repository
/// ([`app_repository`]).
pub struct Uploader {
    registry: String,
    insecure: bool,
    repository: String,
    sealer: Arc<Sealer>,
    provider: Arc<dyn TokenProvider>,
    client: tokio::sync::Mutex<Option<RegistryClient>>,
    /// Cut by [`Uploader::cancel`]. One uploader serves one app of one capture cycle, so
    /// the token is scoped to that too: nothing re-arms it, and a cancelled uploader is
    /// spent — as is the cycle, which never goes on to another app after a cut.
    cancel: CancellationToken,
    /// Bytes this uploader has got through, only ever going up. See the module docs:
    /// callers read it to tell a slow upload from a stopped one.
    progress: Arc<AtomicU64>,
}

impl std::fmt::Debug for Uploader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Uploader")
            .field("registry", &self.registry)
            .field("repository", &self.repository)
            .field("progress", &self.progress_bytes())
            .finish_non_exhaustive()
    }
}

impl Uploader {
    /// Binds an uploader to one repository, sealing under `sealer`.
    ///
    /// `registry` is the host the [`RegistryClient`] constructors take; `repository` is
    /// one app's repository, which the capture path builds with [`app_repository`].
    #[must_use]
    pub fn new(
        registry: String,
        insecure: bool,
        repository: String,
        sealer: Arc<Sealer>,
        provider: Arc<dyn TokenProvider>,
    ) -> Self {
        Self {
            registry,
            insecure,
            repository,
            sealer,
            provider,
            client: tokio::sync::Mutex::new(None),
            cancel: CancellationToken::new(),
            progress: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A handle on this uploader's progress counter, for a watchdog that has to keep
    /// reading it while the call it is watching borrows the uploader.
    ///
    /// The counter only ever goes up and starts at zero: an uploader is built for one
    /// app's repository, so what it holds is what this app's upload has got through and
    /// nothing else. The watchdog reads it for *movement* rather than for its value.
    #[must_use]
    pub fn progress(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.progress)
    }

    /// What that counter reads right now.
    #[must_use]
    pub fn progress_bytes(&self) -> u64 {
        self.progress.load(Ordering::Relaxed)
    }

    /// Records `bytes` of progress. Relaxed: the watchdog polls the value on a timer and
    /// wants the number, not an ordering against anything else.
    fn advance(&self, bytes: u64) {
        self.progress.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Abandons whatever this uploader is doing, as fast as each step can be left.
    ///
    /// The caller must still **await** the in-flight call: an encoder is a blocking
    /// thread reading the frozen view it was handed, and only the call's return says
    /// that thread is gone and the view can be released. See the module docs.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Whether this uploader has been abandoned.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Awaits `work` unless the uploader is cancelled first. `None` = cancelled.
    async fn racing<T>(&self, work: impl std::future::Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => None,
            done = work => Some(done),
        }
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The client to use, minting a fresh bearer when asked to.
    async fn client(&self, refresh: bool) -> Result<RegistryClient> {
        let mut cached = self.client.lock().await;
        if !refresh && let Some(client) = cached.as_ref() {
            return Ok(client.clone());
        }
        let token = self.provider.bearer(refresh).await?;
        let client = RegistryClient::with_bearer(&self.registry, token, self.insecure)?;
        *cached = Some(client.clone());
        Ok(client)
    }

    /// Uploads one planned layer and returns its digest and stored size.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] for a read failure, a sealing failure, or a negotiation that
    /// does not converge. There is no monolithic fallback: see the module docs.
    pub async fn upload_layer(&self, plan: &LayerPlan) -> Result<LayerRef> {
        match plan.kind {
            LayerKind::Pack => self.upload_pack(&plan.files).await,
            LayerKind::Whole => {
                let file = plan.files.first().ok_or_else(|| {
                    CliError::Operational("a whole-file layer plan names no file".to_owned())
                })?;
                self.upload_whole_file(file).await
            }
        }
    }

    /// Uploads a buffer as a layer of its own — the index layer's path.
    ///
    /// # Errors
    ///
    /// As [`upload_layer`](Self::upload_layer).
    pub async fn upload_bytes(&self, bytes: Vec<u8>) -> Result<LayerRef> {
        let sealer = Arc::clone(&self.sealer);
        let cancel = self.cancel.clone();
        let (layer, frames) = tokio::task::spawn_blocking(move || {
            let mut frames: Vec<Vec<u8>> = Vec::new();
            let layer = encode_sealed_stream(bytes.as_slice(), &sealer, &mut |frame| {
                if cancel.is_cancelled() {
                    return Err(abandoned_read());
                }
                frames.push(frame.to_vec());
                Ok(())
            })?;
            Ok::<_, CliError>((layer, frames))
        })
        .await
        .map_err(|err| join_error(&err))??;
        self.push_buffered(&layer, frames).await
    }

    /// Seals a run of small files into one layer held in memory, then negotiates it.
    async fn upload_pack(&self, files: &[PlannedFile]) -> Result<LayerRef> {
        let sealer = Arc::clone(&self.sealer);
        let planned = files.to_vec();
        let cancel = self.cancel.clone();
        let (layer, frames) = tokio::task::spawn_blocking(move || {
            let mut frames: Vec<Vec<u8>> = Vec::new();
            let layer = encode_sealed_stream(FileChain::new(&planned), &sealer, &mut |frame| {
                // The chain reads the frozen view, so a cancelled cycle wants this
                // thread off it now rather than at the end of the run of files.
                if cancel.is_cancelled() {
                    return Err(abandoned_read());
                }
                frames.push(frame.to_vec());
                Ok(())
            })?;
            Ok::<_, CliError>((layer, frames))
        })
        .await
        .map_err(|err| join_error(&err))??;
        self.push_buffered(&layer, frames).await
    }

    /// Negotiates a layer whose frames are already in memory.
    async fn push_buffered(&self, layer: &SealedLayer, frames: Vec<Vec<u8>>) -> Result<LayerRef> {
        let recipe = recipe_bytes(layer)?;
        for attempt in 0..2 {
            let client = self.client(attempt > 0).await?;
            let result = self.buffered_ladder(&client, layer, &frames, &recipe).await;
            match result {
                Err(CliError::Auth(_)) if attempt == 0 => {}
                other => return other.map(|()| layer_ref(layer)),
            }
        }
        Err(CliError::Auth(format!(
            "app data: the registry rejected a freshly minted push token for {}",
            self.repository
        )))
    }

    async fn buffered_ladder(
        &self,
        client: &RegistryClient,
        layer: &SealedLayer,
        frames: &[Vec<u8>],
        recipe: &[u8],
    ) -> Result<()> {
        let mut open = OpenSession::default();
        let result = self
            .buffered_walk(client, layer, frames, recipe, &mut open)
            .await;
        self.close_out(client, open, result.as_ref().err()).await;
        result
    }

    async fn buffered_walk(
        &self,
        client: &RegistryClient,
        layer: &SealedLayer,
        frames: &[Vec<u8>],
        recipe: &[u8],
        open: &mut OpenSession,
    ) -> Result<()> {
        for _ in 0..MAX_RESUME {
            let (session, missing) = self
                .racing(client.chunked_negotiate(&self.repository, recipe))
                .await
                .ok_or_else(abandoned)??;
            self.advance(skipped_bytes(layer, &missing));
            open.hold(&session);
            let mut batch: Vec<u8> = Vec::new();
            let mut retry = false;
            for index in &missing {
                let Some(frame) = frames.get(*index as usize) else {
                    return Err(open.spent(CliError::Operational(format!(
                        "app data: the registry asked for frame {index}, which this layer \
                         does not have"
                    ))));
                };
                push_record(&mut batch, *index, frame);
                if batch.len() >= MAX_BATCH_BYTES {
                    match self
                        .flush(client, &session, std::mem::take(&mut batch))
                        .await
                    {
                        Ok(true) => {
                            retry = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(err) => return Err(open.spent(err)),
                    }
                }
            }
            if !retry && !batch.is_empty() {
                retry = match self.flush(client, &session, batch).await {
                    Ok(retry) => retry,
                    Err(err) => return Err(open.spent(err)),
                };
            }
            if !retry {
                match self.finalize(client, &session, &layer.layer_digest).await {
                    Ok(Finalized::Done) => {
                        open.finalized();
                        return Ok(());
                    }
                    Ok(Finalized::Resume) => {}
                    Err(err) => return Err(open.spent(err)),
                }
            }
        }
        Err(open.spent(stuck(&self.repository, &layer.layer_digest)))
    }

    /// Settles what becomes of the session the ladder was working in, once it has
    /// stopped.
    ///
    /// Keeping it is the common case and the one that matters. The watchdog cuts an
    /// upload that is taking too long while the volume is frozen, and the cycle after it
    /// offers the very same recipe — which the registry answers with this same session
    /// and a `missing` set that no longer includes the frames this cycle uploaded. Handing
    /// the session back here would throw those frames away, and a node whose big layer is
    /// cut every cycle would restart it from zero forever. An expired bearer reads the
    /// same way: the attempt that re-mints one resumes this session.
    ///
    /// What is handed back is a session no retry will resume — see [`OpenSession::spent`].
    /// One `DELETE` releases its staged frames rather than leaving them for the registry's
    /// idle TTL to collect.
    ///
    /// Deliberately not raced against the cancellation token: this is a single bounded
    /// request rather than a read of the frozen view, and a cancelled ladder does not
    /// reach it with anything to send anyway. A failure is not reported — the session
    /// expires on its own.
    async fn close_out(&self, client: &RegistryClient, open: OpenSession, err: Option<&CliError>) {
        let Some(session) = open.id else {
            return;
        };
        // A cancelled cycle keeps its session whatever the step that noticed the cut
        // reported — the encoders surface the cut as a read error of their own.
        if open.keep || self.is_cancelled() || matches!(err, Some(CliError::Auth(_))) {
            return;
        }
        client.chunked_abandon(&self.repository, &session).await;
    }

    /// `PATCH` one batch. `true` means the session went away and the caller should
    /// re-negotiate; a genuine failure surfaces.
    ///
    /// A batch the registry acknowledged is the upload's coarsest unit of progress:
    /// [`MAX_BATCH_BYTES`] is sized so that even a very slow link gets one through
    /// well inside the watchdog's patience for a counter that is not moving.
    async fn flush(&self, client: &RegistryClient, session: &str, batch: Vec<u8>) -> Result<bool> {
        let sent = batch.len() as u64;
        match self
            .racing(client.chunked_patch(&self.repository, session, batch))
            .await
            .ok_or_else(abandoned)?
        {
            Ok(()) => {
                self.advance(sent);
                Ok(false)
            }
            Err(ChunkedResume::Retry) => Ok(true),
            Err(ChunkedResume::Fatal(err)) => Err(err),
        }
    }

    /// Closes one chunked session out. `Resume` means the registry wants the ladder
    /// walked again.
    async fn finalize(
        &self,
        client: &RegistryClient,
        session: &str,
        digest: &str,
    ) -> Result<Finalized> {
        match self
            .racing(client.chunked_finalize(&self.repository, session, digest))
            .await
            .ok_or_else(abandoned)?
        {
            Ok(()) => Ok(Finalized::Done),
            Err(ChunkedResume::Retry) => Ok(Finalized::Resume),
            Err(ChunkedResume::Fatal(err)) => Err(err),
        }
    }

    /// The two-pass path: learn the framing, then re-encode and send only what is missing.
    async fn upload_whole_file(&self, file: &PlannedFile) -> Result<LayerRef> {
        let sealer = Arc::clone(&self.sealer);
        let source = file.source.clone();
        let cancel = self.cancel.clone();
        // Pass 1 sends nothing, and on a file of any size it is the longest stretch of
        // the upload with no network traffic at all — so it reports its own progress,
        // or a watchdog reading only the wire would call a healthy seal stuck.
        let progress = Arc::clone(&self.progress);
        let layer = tokio::task::spawn_blocking(move || {
            let handle = std::fs::File::open(&source).map_err(|err| {
                CliError::Operational(format!("read {}: {err}", source.display()))
            })?;
            let layer =
                encode_sealed_stream(std::io::BufReader::new(handle), &sealer, &mut |frame| {
                    if cancel.is_cancelled() {
                        return Err(abandoned_read());
                    }
                    progress.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    Ok(())
                })?;
            Ok::<_, CliError>(layer)
        })
        .await
        .map_err(|err| join_error(&err))??;

        let recipe = recipe_bytes(&layer)?;
        for attempt in 0..2 {
            let client = self.client(attempt > 0).await?;
            let result = self.two_pass_ladder(&client, file, &layer, &recipe).await;
            match result {
                Err(CliError::Auth(_)) if attempt == 0 => {}
                other => return other.map(|()| layer_ref(&layer)),
            }
        }
        Err(CliError::Auth(format!(
            "app data: the registry rejected a freshly minted push token for {}",
            self.repository
        )))
    }

    async fn two_pass_ladder(
        &self,
        client: &RegistryClient,
        file: &PlannedFile,
        layer: &SealedLayer,
        recipe: &[u8],
    ) -> Result<()> {
        let mut open = OpenSession::default();
        let result = self
            .two_pass_walk(client, file, layer, recipe, &mut open)
            .await;
        self.close_out(client, open, result.as_ref().err()).await;
        result
    }

    async fn two_pass_walk(
        &self,
        client: &RegistryClient,
        file: &PlannedFile,
        layer: &SealedLayer,
        recipe: &[u8],
        open: &mut OpenSession,
    ) -> Result<()> {
        for _ in 0..MAX_RESUME {
            let (session, missing) = self
                .racing(client.chunked_negotiate(&self.repository, recipe))
                .await
                .ok_or_else(abandoned)??;
            self.advance(skipped_bytes(layer, &missing));
            open.hold(&session);
            let mut retry = false;
            if !missing.is_empty() {
                // Pass 2 runs on a blocking thread and pushes finished batches through a
                // channel of one, so the encoder is throttled by the upload and at most two
                // batches (64 MiB) are ever in flight.
                let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
                let sealer = Arc::clone(&self.sealer);
                let source = file.source.clone();
                let expected = layer.layer_digest.clone();
                let wanted: std::collections::HashSet<u32> = missing.iter().copied().collect();
                let cancel = self.cancel.clone();
                let encode = tokio::task::spawn_blocking(move || {
                    second_pass(&source, &sealer, &wanted, &expected, &sender, &cancel)
                });
                while let Some(batch) = receiver.recv().await {
                    match self.flush(client, &session, batch).await {
                        Ok(true) => {
                            retry = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(err) => return Err(open.spent(err)),
                    }
                }
                // Dropping the receiver is what lets the encoder finish when the loop was
                // cut short: it is parked on a blocking send into a channel of one, and
                // nothing else would ever wake it.
                drop(receiver);
                let encoded = match encode.await {
                    Ok(encoded) => encoded,
                    Err(err) => return Err(open.spent(join_error(&err))),
                };
                if !retry && let Err(err) = encoded {
                    // A second pass that could not be read or did not converge is this
                    // recipe's own failure — but a cancelled read reaches here too, and
                    // `close_out` keeps the session for it.
                    return Err(open.spent(err));
                }
            }
            if !retry {
                match self.finalize(client, &session, &layer.layer_digest).await {
                    Ok(Finalized::Done) => {
                        open.finalized();
                        return Ok(());
                    }
                    Ok(Finalized::Resume) => {}
                    Err(err) => return Err(open.spent(err)),
                }
            }
        }
        Err(open.spent(stuck(&self.repository, &layer.layer_digest)))
    }

    /// Commits a restore point over the uploaded layers.
    ///
    /// # Errors
    ///
    /// Returns the server's own verdict — [`CommitError::Fenced`] is terminal for this
    /// node, [`CommitError::Quota`] and [`CommitError::RateLimited`] are transient, and
    /// [`CommitError::Transport`] carries anything below the endpoint.
    pub async fn commit(
        &self,
        request: &CommitRequest,
    ) -> std::result::Result<CommitOutcome, CommitError> {
        let body = serde_json::to_vec(request)
            .map_err(|err| CliError::Operational(format!("encode restore point: {err}")))?;
        let path = format!("/v2/{}/_orc/restore-points", self.repository);
        for attempt in 0..2 {
            let client = self.client(attempt > 0).await?;
            match client.post_extension_json(&path, &body).await {
                Err(CliError::Auth(_)) if attempt == 0 => {}
                Err(err) => return Err(CommitError::Transport(err)),
                Ok((status, body)) => return commit_outcome(status, &body, &self.repository),
            }
        }
        Err(CommitError::Transport(CliError::Auth(format!(
            "app data: the registry rejected a freshly minted push token for {}",
            self.repository
        ))))
    }
}

/// Classifies the commit endpoint's answer.
fn commit_outcome(
    status: reqwest::StatusCode,
    body: &[u8],
    repository: &str,
) -> std::result::Result<CommitOutcome, CommitError> {
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        id: String,
        #[serde(default)]
        error: String,
        #[serde(default)]
        digest: String,
        #[serde(default)]
        stored: u64,
        #[serde(default)]
        limit: u64,
        #[serde(default)]
        app: String,
        #[serde(default)]
        retry_after: i64,
    }
    let answer: Answer = serde_json::from_slice(body).unwrap_or_default();
    match status.as_u16() {
        201 => Ok(CommitOutcome {
            id: answer.id,
            created: true,
        }),
        200 => Ok(CommitOutcome {
            id: answer.id,
            created: false,
        }),
        403 => Err(CommitError::Scope(repository.to_owned())),
        409 => Err(CommitError::Fenced),
        413 => Err(CommitError::Quota {
            stored: answer.stored,
            limit: answer.limit,
        }),
        422 => Err(match answer.error.as_str() {
            "size-mismatch" => CommitError::SizeMismatch(answer.digest),
            "unknown-app" => CommitError::UnknownApp(answer.app),
            _ => CommitError::UnknownBlob(answer.digest),
        }),
        429 => Err(CommitError::RateLimited {
            retry_after_secs: answer.retry_after,
        }),
        503 => Err(CommitError::Store),
        other => Err(CommitError::Unexpected {
            status: other,
            body: String::from_utf8_lossy(body).chars().take(512).collect(),
        }),
    }
}

/// Re-encodes `source` and sends the frames `wanted` names, batched.
///
/// The convergence assertion lives here: if the second pass produced a different layer
/// digest the frames would not match the recipe the session was opened with, so the layer
/// is abandoned rather than finalized into something the index would misread.
fn second_pass(
    source: &std::path::Path,
    sealer: &Sealer,
    wanted: &std::collections::HashSet<u32>,
    expected: &str,
    sender: &tokio::sync::mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
) -> Result<()> {
    let handle = std::fs::File::open(source)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", source.display())))?;
    let mut batch: Vec<u8> = Vec::new();
    let mut index = 0u32;
    let mut closed = false;
    let layer = encode_sealed_stream(std::io::BufReader::new(handle), sealer, &mut |frame| {
        // This thread is the one holding the frozen view open, so it is the one a
        // cancelled cycle is waiting on.
        if cancel.is_cancelled() {
            return Err(abandoned_read());
        }
        let this = index;
        index += 1;
        if closed || !wanted.contains(&this) {
            return Ok(());
        }
        push_record(&mut batch, this, frame);
        if batch.len() >= MAX_BATCH_BYTES
            && sender.blocking_send(std::mem::take(&mut batch)).is_err()
        {
            // The upload side gave up (a resume, or a failure). Stop feeding it, but
            // let the encode run out so the caller sees a clean result.
            closed = true;
        }
        Ok(())
    })?;
    if !closed && !batch.is_empty() {
        let _ = sender.blocking_send(batch);
    }
    if layer.layer_digest != *expected {
        return Err(CliError::Operational(format!(
            "app data: re-encoding {} produced {} instead of {expected}; the sealed codec \
             must be deterministic and this layer is abandoned",
            source.display(),
            layer.layer_digest
        )));
    }
    Ok(())
}

/// Wire bytes of `layer` that negotiation did *not* ask for.
///
/// Progress just as real as an uploaded byte: a frame the registry already holds is a
/// frame this capture is done with. On a node whose apps rewrite a little of a large
/// file every cycle, this is most of every layer, and a watchdog that counted only
/// `PATCH`ed bytes would see nothing happen while the ladder walked past it.
fn skipped_bytes(layer: &SealedLayer, missing: &[u32]) -> u64 {
    let wanted: std::collections::HashSet<u32> = missing.iter().copied().collect();
    layer
        .recipe_entries()
        .iter()
        .enumerate()
        .filter(|(index, _)| !u32::try_from(*index).is_ok_and(|index| wanted.contains(&index)))
        .map(|(_, entry)| entry.frame_length)
        .sum()
}

fn push_record(batch: &mut Vec<u8>, index: u32, frame: &[u8]) {
    batch.extend_from_slice(&index.to_le_bytes());
    batch.extend_from_slice(&u32::try_from(frame.len()).unwrap_or(u32::MAX).to_le_bytes());
    batch.extend_from_slice(frame);
}

fn recipe_bytes(layer: &SealedLayer) -> Result<Vec<u8>> {
    let recipe = sealed_recipe_body(
        &layer.layer_digest,
        layer.total_length,
        APPDATA_LAYER_MEDIA_TYPE,
        &layer.recipe_entries(),
    );
    serde_json::to_vec(&recipe)
        .map_err(|err| CliError::Operational(format!("encode app data recipe: {err}")))
}

/// The layer as the index and the commit body name it: digest plus **stored** size, which
/// is the whole wire stream — payload frames and the trailing table of contents.
fn layer_ref(layer: &SealedLayer) -> LayerRef {
    LayerRef {
        digest: layer.layer_digest.clone(),
        size: layer.toc_offset + layer.toc_frame_length,
    }
}

/// The chunked session a ladder is working in, and whether the next attempt at this layer
/// should be allowed to resume it.
#[derive(Default)]
struct OpenSession {
    /// The negotiated session id, until it is finalized.
    id: Option<String>,
    /// Whether to leave the session open on the way out. Kept by default: what ends most
    /// ladders early is a cut cycle or a lost token, and both come back offering the same
    /// recipe, which the registry answers with this same session.
    keep: bool,
}

impl OpenSession {
    /// Records the session this attempt negotiated.
    fn hold(&mut self, session: &str) {
        self.id = Some(session.to_owned());
        self.keep = true;
    }

    /// The layer is stored. Finalizing closes the session on the registry's side, so
    /// there is nothing left to hand back.
    fn finalized(&mut self) {
        self.id = None;
    }

    /// `err` is one that re-offering this recipe cannot get past — a rejected `PATCH` or
    /// finalize, a re-encode that did not converge, a ladder out of negotiations. The
    /// session is handed back rather than left staged for a retry that would fail the
    /// same way. Returns `err` so a caller can `return Err(open.spent(err))`.
    fn spent(&mut self, err: CliError) -> CliError {
        self.keep = false;
        err
    }
}

/// What closing a chunked session out came back with.
enum Finalized {
    /// The layer is stored.
    Done,
    /// The registry wants the ladder walked again.
    Resume,
}

/// What an abandoned upload comes back with, from whichever step noticed first.
const ABANDONED: &str =
    "app data: this upload was abandoned so the frozen volume could be released";

fn abandoned() -> CliError {
    CliError::Operational(ABANDONED.to_owned())
}

/// The same, in the shape an encoder's sink hands back.
fn abandoned_read() -> std::io::Error {
    std::io::Error::other(ABANDONED)
}

fn stuck(repository: &str, digest: &str) -> CliError {
    CliError::Operational(format!(
        "app data: uploading {digest} to {repository} did not converge after {MAX_RESUME} \
         negotiations"
    ))
}

fn join_error(err: &tokio::task::JoinError) -> CliError {
    CliError::Operational(format!("app data: the sealing task failed: {err}"))
}

/// Reads a run of planned files back to back, exactly the bytes the plan claims.
///
/// A short file is a refusal, not a pad: the index records every file's offset within the
/// layer, and a silent shortfall would slide every later file's bytes.
struct FileChain {
    files: std::vec::IntoIter<(PathBuf, u64)>,
    current: Option<(std::fs::File, PathBuf, u64)>,
}

impl FileChain {
    fn new(files: &[PlannedFile]) -> Self {
        Self {
            files: files
                .iter()
                .map(|file| (file.source.clone(), file.len))
                .collect::<Vec<_>>()
                .into_iter(),
            current: None,
        }
    }
}

impl std::io::Read for FileChain {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some((handle, path, remaining)) = self.current.as_mut() else {
                let Some((path, len)) = self.files.next() else {
                    return Ok(0);
                };
                let handle = std::fs::File::open(&path)?;
                self.current = Some((handle, path, len));
                continue;
            };
            if *remaining == 0 {
                self.current = None;
                continue;
            }
            let want = usize::try_from(*remaining)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            let read = handle.read(&mut buf[..want])?;
            if read == 0 {
                return Err(std::io::Error::other(format!(
                    "{} is shorter than the {remaining} bytes still planned for it; the \
                     capture view changed underneath the upload",
                    path.display()
                )));
            }
            *remaining -= read as u64;
            return Ok(read);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::seal::DataKey;
    use std::io::Read as _;

    fn sealer() -> Arc<Sealer> {
        Arc::new(Sealer::new(&DataKey::new([9u8; 32])))
    }

    fn planned(path: &std::path::Path, len: u64) -> PlannedFile {
        PlannedFile {
            path: path.display().to_string(),
            source: path.to_path_buf(),
            offset: 0,
            len,
        }
    }

    /// The addressing rule every caller uses: the supplied base repository and the app's
    /// own last segment under it.
    #[test]
    fn an_apps_repository_is_its_leaf_under_the_pools_base() {
        assert_eq!(
            app_repository("acme/prod/appdata-workers", "sys/sys/persist-probe"),
            "acme/prod/appdata-workers/persist-probe"
        );
        // An app id with no namespace is its own leaf.
        assert_eq!(
            app_repository("acme/prod/appdata-workers", "postgres"),
            "acme/prod/appdata-workers/postgres"
        );
        // Two apps of one pool are two repositories, never one.
        assert_ne!(
            app_repository("acme/prod/appdata-workers", "sys/sys/postgres"),
            app_repository("acme/prod/appdata-workers", "sys/sys/redis")
        );
    }

    /// Nothing here may panic or produce a path with an empty segment: the base is the
    /// base repository and app id are external inputs.
    #[test]
    fn a_malformed_base_or_app_still_addresses_one_repository() {
        assert_eq!(
            app_repository("acme/prod/appdata-workers/", "sys/sys/postgres"),
            "acme/prod/appdata-workers/postgres"
        );
        assert_eq!(
            app_repository("acme/prod/appdata-workers", "sys/sys/postgres/"),
            "acme/prod/appdata-workers/postgres"
        );
        // No leaf at all leaves the base addressed rather than a trailing slash.
        assert_eq!(
            app_repository("acme/prod/appdata-workers", ""),
            "acme/prod/appdata-workers"
        );
        assert_eq!(app_leaf("sys/sys/postgres"), "postgres");
        assert_eq!(app_leaf("postgres"), "postgres");
    }

    fn commit_request(kind: CommitKind) -> CommitRequest {
        CommitRequest {
            app: "postgres".to_owned(),
            key_id: "0123456789abcdef".to_owned(),
            created_at: 1_700_000_000,
            index: LayerRef {
                digest: "sha256:aa".to_owned(),
                size: 1,
            },
            layers: Vec::new(),
            files: 1,
            bytes: 2,
            kind,
        }
    }

    /// The server reads `kind` off the wire as a lowercase word.
    #[test]
    fn a_commit_body_spells_its_kind_the_way_the_server_reads_it() {
        let periodic =
            serde_json::to_string(&commit_request(CommitKind::default())).expect("encode periodic");
        assert!(periodic.contains(r#""kind":"periodic""#), "{periodic}");
        let final_point =
            serde_json::to_string(&commit_request(CommitKind::Final)).expect("encode final");
        assert!(final_point.contains(r#""kind":"final""#), "{final_point}");
        assert!(CommitKind::Final.is_final());
        assert!(!CommitKind::Periodic.is_final());
    }

    #[test]
    fn a_file_chain_reads_exactly_what_the_plan_declares() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = dir.path().join("a");
        let second = dir.path().join("b");
        std::fs::write(&first, b"hello ").expect("write");
        std::fs::write(&second, b"world").expect("write");
        let mut chain = FileChain::new(&[planned(&first, 6), planned(&second, 5)]);
        let mut body = String::new();
        chain.read_to_string(&mut body).expect("read");
        assert_eq!(body, "hello world");
    }

    #[test]
    fn a_file_chain_stops_at_the_planned_length_of_a_grown_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a");
        std::fs::write(&path, b"planned+extra").expect("write");
        let mut chain = FileChain::new(&[planned(&path, 7)]);
        let mut body = String::new();
        chain.read_to_string(&mut body).expect("read");
        assert_eq!(body, "planned");
    }

    #[test]
    fn a_file_chain_refuses_a_file_that_shrank() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a");
        std::fs::write(&path, b"short").expect("write");
        let mut chain = FileChain::new(&[planned(&path, 50)]);
        let mut body = Vec::new();
        let err = chain.read_to_end(&mut body).expect_err("refused");
        assert!(err.to_string().contains("shorter than"), "{err}");
    }

    /// The property the two-pass path rests on: the same bytes seal to the same layer,
    /// frame for frame, however many times they are encoded.
    #[test]
    fn re_encoding_is_byte_identical() {
        let sealer = sealer();
        // Compressible and incompressible runs, long enough to cross several chunks.
        let mut body = Vec::new();
        for index in 0..200_000u32 {
            body.extend_from_slice(&index.to_le_bytes());
            body.extend_from_slice(b"the quick brown fox ");
        }
        let encode = || {
            let mut frames: Vec<Vec<u8>> = Vec::new();
            let layer = encode_sealed_stream(body.as_slice(), &sealer, &mut |frame| {
                frames.push(frame.to_vec());
                Ok(())
            })
            .expect("encode");
            (layer.layer_digest, frames)
        };
        let (first_digest, first_frames) = encode();
        let (second_digest, second_frames) = encode();
        assert_eq!(first_digest, second_digest);
        assert_eq!(first_frames, second_frames);
        assert!(first_frames.len() > 2, "the body must cross frames");
    }

    #[test]
    fn a_commit_answer_maps_to_the_contract_vocabulary() {
        let outcome = commit_outcome(
            reqwest::StatusCode::CREATED,
            br#"{"id":"rp-7"}"#,
            "org/proj/appdata-pool",
        )
        .expect("created");
        assert_eq!(
            outcome,
            CommitOutcome {
                id: "rp-7".to_owned(),
                created: true
            }
        );
        let outcome = commit_outcome(
            reqwest::StatusCode::OK,
            br#"{"id":"rp-6"}"#,
            "org/proj/appdata-pool",
        )
        .expect("idempotent");
        assert!(!outcome.created, "a matched point is not a new one");

        let cases: Vec<(u16, &[u8], &str)> = vec![
            (409, b"{\"error\":\"fenced\"}", "no longer occupies"),
            (403, b"{\"error\":\"scope\"}", "does not authorize"),
            (
                413,
                b"{\"error\":\"quota\",\"stored\":10,\"limit\":20}",
                "20-byte allowance",
            ),
            (
                422,
                b"{\"error\":\"unknown-blob\",\"digest\":\"sha256:aa\"}",
                "does not hold layer sha256:aa",
            ),
            (
                422,
                b"{\"error\":\"size-mismatch\",\"digest\":\"sha256:bb\"}",
                "different size",
            ),
            (
                422,
                b"{\"error\":\"unknown-app\",\"app\":\"ghost\"}",
                "not a persisting app",
            ),
            (429, b"{}", "committed moments ago"),
            (503, b"{\"error\":\"store\"}", "could not verify"),
            (500, b"boom", "commit returned 500"),
        ];
        for (status, body, expected) in cases {
            let err = commit_outcome(
                reqwest::StatusCode::from_u16(status).expect("status"),
                body,
                "org/proj/appdata-pool",
            )
            .expect_err("refused");
            assert!(
                err.to_string().contains(expected),
                "{status}: {err} does not mention {expected:?}"
            );
        }
    }
}
