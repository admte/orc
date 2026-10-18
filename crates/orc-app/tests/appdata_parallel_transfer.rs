//! App-data layers move in parallel, over a registry that answers every request a round
//! trip late.
//!
//! The fake registry here sleeps [`LATENCY`] before it answers anything, the way a node far
//! from its server sees every request: a sequential pass then costs one round trip per
//! request per layer, and a parallel one about a quarter of that. It holds frames, blobs
//! and sessions the way the real `_orc` chunked-upload extension does, closely enough for
//! a capture to land and a restore to read it back, and it can be told to refuse or stall
//! a `PATCH` or a blob `GET` so a test can fail one layer while others are mid-flight.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use orc_app::persist::KeyRing;
use orc_app::persist::pack::{BuiltLayer, LayerKind, LayerPlan, PlannedFile, assign_refs};
use orc_app::persist::restore::{RestoreError, RestorePoint, Restorer};
use orc_app::persist::seal::{DataKey, Sealer};
use orc_app::persist::tree::{INDEX_VERSION, IndexHeader, IndexWriter, LayerRef};
use orc_app::persist::upload::Uploader;

/// What every request waits before it is answered.
const LATENCY: Duration = Duration::from_millis(100);

const REPOSITORY: &str = "acme/prod/appdata-workers/probe";
const KEY_ID: &str = "0123456789abcdef";

/// What the fake does with a request it was told to single out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rule {
    Serve,
    /// Answer 400 (a `PATCH`) or 500 (a `GET`).
    Refuse,
    /// Never answer a `PATCH`; for a `GET`, send half the blob and then trickle a byte
    /// at a time, forever — a download that is moving but will never end.
    Stall,
}

#[derive(Default)]
struct Store {
    frames: HashMap<String, Vec<u8>>,
    blobs: HashMap<String, Vec<u8>>,
    /// Session id to the layer digest it was opened for and its frames in blob order.
    sessions: HashMap<String, (String, Vec<String>)>,
    /// Every negotiation, as `(layer digest, frames declared missing, session id)`.
    negotiations: Vec<(String, usize, String)>,
    deleted: Vec<String>,
}

#[derive(Clone)]
struct Fake {
    store: Arc<Mutex<Store>>,
    /// Requests being answered right now, and the most there ever were at once.
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    /// A `PATCH` whose body is at least this long is a "big" one.
    big_patch: Arc<AtomicUsize>,
    rules: Arc<Mutex<Rules>>,
    /// A rule for a `GET` of one particular blob, ahead of [`Rules::other_get`].
    get_rules: Arc<Mutex<HashMap<String, Rule>>>,
    /// Stalled blob bodies the client has since walked away from.
    abandoned_bodies: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
struct Rules {
    big_patch: Rule,
    small_patch: Rule,
    other_get: Rule,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            big_patch: Rule::Serve,
            small_patch: Rule::Serve,
            other_get: Rule::Serve,
        }
    }
}

/// Counts a request in and out of [`Fake::in_flight`].
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Counts a stalled body the client dropped.
struct BodyDropped(Arc<AtomicUsize>);

impl Drop for BodyDropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn fake() -> Fake {
    Fake {
        store: Arc::default(),
        in_flight: Arc::default(),
        peak: Arc::default(),
        big_patch: Arc::new(AtomicUsize::new(usize::MAX)),
        rules: Arc::default(),
        get_rules: Arc::default(),
        abandoned_bodies: Arc::default(),
    }
}

impl Fake {
    fn get_rule(&self, digest: &str, rule: Rule) {
        self.get_rules
            .lock()
            .expect("get rules")
            .insert(digest.to_owned(), rule);
    }

    fn rules(&self) -> Rules {
        *self.rules.lock().expect("rules")
    }

    fn set_rules(&self, rules: Rules) {
        *self.rules.lock().expect("rules") = rules;
    }

    fn reset_peak(&self) {
        self.peak.store(0, Ordering::SeqCst);
    }
}

async fn dispatch(
    State(state): State<Fake>,
    Path(rest): Path<String>,
    method: Method,
    uri: Uri,
    body: Body,
) -> Response {
    let now = state.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    state.peak.fetch_max(now, Ordering::SeqCst);
    let _counted = InFlight(Arc::clone(&state.in_flight));
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("body")
        .to_vec();
    tokio::time::sleep(LATENCY).await;

    if rest.ends_with("/_orc/chunked-uploads/") && method == Method::POST {
        return negotiate(&state, &body);
    }
    if let Some((_, session)) = rest.split_once("/_orc/chunked-uploads/") {
        let session = session.to_owned();
        return match method {
            Method::PATCH => patch(&state, &session, &body).await,
            Method::PUT => finalize(&state, &session, uri.query().unwrap_or_default()),
            Method::DELETE => {
                let mut store = state.store.lock().expect("store");
                store.sessions.remove(&session);
                store.deleted.push(session);
                StatusCode::NO_CONTENT.into_response()
            }
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
    }
    if let Some((_, digest)) = rest.split_once("/blobs/")
        && method == Method::GET
    {
        let Some(blob) = state
            .store
            .lock()
            .expect("store")
            .blobs
            .get(digest)
            .cloned()
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let rule = state
            .get_rules
            .lock()
            .expect("get rules")
            .get(digest)
            .copied()
            .unwrap_or(state.rules().other_get);
        return match rule {
            Rule::Serve => (StatusCode::OK, blob).into_response(),
            Rule::Refuse => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Rule::Stall => {
                // Half the blob, then a byte at a time forever. The trickle is what lets
                // the server notice a client that hung up: its next write fails, and the
                // body — with the guard in it — is dropped.
                let half = blob[..blob.len() / 2].to_vec();
                let guard = BodyDropped(Arc::clone(&state.abandoned_bodies));
                let stream = futures_util::stream::unfold(
                    (Some(half), guard),
                    |(first, guard)| async move {
                        if let Some(first) = first {
                            return Some((Ok::<_, std::io::Error>(first), (None, guard)));
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Some((Ok(vec![0u8]), (None, guard)))
                    },
                );
                (StatusCode::OK, Body::from_stream(stream)).into_response()
            }
        };
    }
    StatusCode::NOT_FOUND.into_response()
}

fn negotiate(state: &Fake, body: &[u8]) -> Response {
    let recipe: serde_json::Value = serde_json::from_slice(body).expect("recipe");
    let digest = recipe["digest"].as_str().expect("digest").to_owned();
    let chunks: Vec<String> = recipe["chunks"]
        .as_array()
        .expect("chunks")
        .iter()
        .map(|chunk| {
            let cid = chunk["frame_cid"].as_str().expect("cid");
            cid.strip_prefix("blake3:").unwrap_or(cid).to_owned()
        })
        .collect();
    let mut store = state.store.lock().expect("store");
    let missing: Vec<u32> = chunks
        .iter()
        .enumerate()
        .filter(|(_, cid)| !store.frames.contains_key(*cid))
        .map(|(index, _)| u32::try_from(index).expect("index"))
        .collect();
    let session = store
        .sessions
        .iter()
        .find(|(_, (held, frames))| *held == digest && *frames == chunks)
        .map_or_else(
            || format!("sess-{}", store.negotiations.len()),
            |(id, _)| id.clone(),
        );
    store
        .sessions
        .insert(session.clone(), (digest.clone(), chunks));
    store
        .negotiations
        .push((digest, missing.len(), session.clone()));
    axum::Json(serde_json::json!({"session_id": session, "missing": missing})).into_response()
}

async fn patch(state: &Fake, session: &str, body: &[u8]) -> Response {
    let rules = state.rules();
    let rule = if body.len() >= state.big_patch.load(Ordering::SeqCst) {
        rules.big_patch
    } else {
        rules.small_patch
    };
    match rule {
        Rule::Serve => {}
        Rule::Refuse => return StatusCode::BAD_REQUEST.into_response(),
        Rule::Stall => std::future::pending::<()>().await,
    }
    let mut store = state.store.lock().expect("store");
    let Some((_, chunks)) = store.sessions.get(session).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut offset = 0usize;
    while offset < body.len() {
        let index = u32::from_le_bytes(body[offset..offset + 4].try_into().expect("index"));
        let len = u32::from_le_bytes(body[offset + 4..offset + 8].try_into().expect("len"));
        offset += 8;
        let frame = body[offset..offset + len as usize].to_vec();
        offset += len as usize;
        assert_eq!(
            blake3::hash(&frame).to_hex().to_string(),
            chunks[index as usize]
        );
        store.frames.insert(chunks[index as usize].clone(), frame);
    }
    StatusCode::ACCEPTED.into_response()
}

fn finalize(state: &Fake, session: &str, query: &str) -> Response {
    use sha2::Digest as _;

    let mut store = state.store.lock().expect("store");
    let Some((digest, chunks)) = store.sessions.get(session).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    assert!(query.contains(&digest), "finalize names the layer");
    let mut blob = Vec::new();
    for cid in &chunks {
        let Some(frame) = store.frames.get(cid) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        blob.extend_from_slice(frame);
    }
    assert_eq!(format!("sha256:{:x}", sha2::Sha256::digest(&blob)), digest);
    store.blobs.insert(digest, blob);
    store.sessions.remove(session);
    StatusCode::CREATED.into_response()
}

async fn serve(state: Fake) -> String {
    let app = axum::Router::new()
        .route("/v2/{*rest}", any(dispatch))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

struct FixedToken;

#[async_trait::async_trait]
impl orc_app::persist::upload::TokenProvider for FixedToken {
    async fn bearer(&self, _refresh: bool) -> orc_app::error::Result<String> {
        Ok("appdata-token".to_owned())
    }
}

fn sealer(seed: u8) -> Arc<Sealer> {
    Arc::new(Sealer::new(&DataKey::new([seed; 32])))
}

fn uploader(addr: &str, sealer: &Arc<Sealer>) -> Uploader {
    Uploader::new(
        addr.to_owned(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(sealer),
        Arc::new(FixedToken),
    )
}

/// Bytes zstd cannot shrink, so the wire size is the data's own.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// One app's captured tree: `sizes.len()` files, each of which is given a layer of its
/// own, so a test controls exactly how many layers move.
struct Tree {
    _dir: tempfile::TempDir,
    planned: Vec<orc_app::persist::tree::Planned>,
    plans: Vec<LayerPlan>,
    files: Vec<(String, Vec<u8>)>,
}

fn tree(sizes: &[usize], seed: u64) -> Tree {
    let dir = tempfile::tempdir().expect("tempdir");
    let view = dir.path().join("probe");
    let data = view.join("srv/app");
    std::fs::create_dir_all(&data).expect("mkdir");
    let mut files = Vec::new();
    for (number, size) in sizes.iter().enumerate() {
        let body = incompressible(*size, seed * 1000 + number as u64);
        let name = format!("file-{number:02}");
        std::fs::write(data.join(&name), &body).expect("write");
        files.push((format!("srv/app/{name}"), body));
    }
    let spec = orc_app::persist::PersistSpec::parse(&orc_app::app::PersistBlock {
        paths: vec!["/srv/app".to_owned()],
        hook_pre: None,
        hook_post: None,
    })
    .expect("spec");
    let entries = orc_app::persist::tree::walk(&view, &spec).expect("walk");
    let empty = IndexHeader {
        v: INDEX_VERSION,
        app: "sys/sys/probe".to_owned(),
        created_at: 0,
        layers: Vec::new(),
    };
    let planned = orc_app::persist::tree::diff(&empty, std::iter::empty(), entries).expect("diff");
    let plans = planned
        .iter()
        .filter(|item| item.entry.kind == orc_app::persist::tree::Kind::File)
        .map(|item| LayerPlan {
            kind: LayerKind::Whole,
            files: vec![PlannedFile {
                path: item.entry.path.clone(),
                source: item.entry.source.clone(),
                offset: 0,
                len: item.entry.size,
            }],
            bytes: item.entry.size,
        })
        .collect();
    Tree {
        _dir: dir,
        planned,
        plans,
        files,
    }
}

/// Uploads the tree's layers and its index; returns the point and its layer references.
async fn capture(
    uploader: &Uploader,
    tree: &Tree,
    concurrency: usize,
) -> (RestorePoint, Vec<LayerRef>) {
    let references = uploader
        .upload_layers_with(&tree.plans, concurrency)
        .await
        .expect("upload layers");
    let built: Vec<BuiltLayer> = tree
        .plans
        .iter()
        .zip(&references)
        .map(|(plan, layer)| BuiltLayer {
            plan: plan.clone(),
            layer: layer.clone(),
        })
        .collect();
    let (layers, entries) = assign_refs(&tree.planned, &built).expect("refs");
    let mut writer = IndexWriter::new(
        Vec::new(),
        &IndexHeader {
            v: INDEX_VERSION,
            app: "sys/sys/probe".to_owned(),
            created_at: 1,
            layers: layers.clone(),
        },
    )
    .expect("header");
    for entry in &entries {
        writer.push(entry).expect("entry");
    }
    let (document, files) = writer.finish().expect("index");
    let index = uploader.upload_bytes(document).await.expect("index layer");
    let point = RestorePoint {
        app: "probe".to_owned(),
        id: "rp-1".to_owned(),
        key_id: KEY_ID.to_owned(),
        created_at: 1,
        index,
        files,
        bytes: 0,
    };
    (point, references)
}

fn client(addr: &str) -> orc_app::registry::RegistryClient {
    orc_app::registry::RegistryClient::with_bearer(addr, "appdata-token".to_owned(), true)
        .expect("client")
}

const LAYERS: usize = 8;
const LAYER_BYTES: usize = 192 * 1024;

/// Round trips one layer costs a capture: negotiate, `PATCH`, finalize.
const CAPTURE_TRIPS: u32 = 3;

/// A capture of eight layers takes about two layers' worth of round trips, not eight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_uploads_its_layers_four_at_a_time() {
    let tree = tree(&[LAYER_BYTES; LAYERS], 1);

    // Sequential, for the comparison: a fresh registry so nothing is already held.
    let one = fake();
    let addr = serve(one.clone()).await;
    let started = Instant::now();
    let sequential = uploader(&addr, &sealer(1));
    sequential
        .upload_layers_with(&tree.plans, 1)
        .await
        .expect("sequential");
    let sequential_took = started.elapsed();
    assert_eq!(one.peak.load(Ordering::SeqCst), 1);

    let four = fake();
    let addr = serve(four.clone()).await;
    let started = Instant::now();
    let parallel = uploader(&addr, &sealer(1));
    let references = parallel.upload_layers(&tree.plans).await.expect("parallel");
    let parallel_took = started.elapsed();

    let trip = LATENCY * CAPTURE_TRIPS;
    eprintln!(
        "capture of {LAYERS} layers at {LATENCY:?} per request: sequential {sequential_took:?}, \
         four at a time {parallel_took:?}"
    );
    assert!(
        sequential_took >= trip * u32::try_from(LAYERS).expect("layers"),
        "sequential is one layer after another: {sequential_took:?}"
    );
    // ceil(8 / 4) = 2 layers' worth of round trips rather than 8 — about a quarter of the
    // sequential time locally. Asserted at half, which a slow runner's per-request
    // overhead (Windows loopback adds tens of milliseconds) still clears; the peak below
    // is the exact check on how many are in flight.
    assert!(
        parallel_took * 2 < sequential_took,
        "four at a time is about two layers' worth of round trips: {parallel_took:?}"
    );
    let peak = four.peak.load(Ordering::SeqCst);
    assert!(
        (3..=4).contains(&peak),
        "four in flight, never more: {peak}"
    );

    // In plan order, every one stored, and the counter says what crossed the wire.
    assert_eq!(references.len(), LAYERS);
    let store = four.store.lock().expect("store");
    for (reference, plan) in references.iter().zip(&tree.plans) {
        let blob = store.blobs.get(&reference.digest).expect("stored");
        assert_eq!(blob.len() as u64, reference.size);
        assert!(
            reference.size >= plan.bytes,
            "incompressible data stays its size"
        );
    }
    let stored: u64 = references.iter().map(|reference| reference.size).sum();
    assert_eq!(
        parallel.sent_bytes(),
        stored,
        "a fresh registry is sent every frame of every layer, and only once"
    );
    assert_eq!(parallel.sent_bytes(), sequential.sent_bytes());
}

/// A restore of eight layers takes about two layers' worth of round trips, not eight,
/// and puts back exactly the bytes that were captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_fetches_its_layers_four_at_a_time() {
    let tree = tree(&[LAYER_BYTES; LAYERS], 2);
    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = sealer(2);
    let (point, references) = capture(&uploader(&addr, &sealer), &tree, 4).await;
    let ring = KeyRing::single(KEY_ID, Arc::clone(&sealer));
    let client = client(&addr);

    let restore = |concurrency: usize| {
        let (client, ring, point) = (&client, &ring, &point);
        async move {
            let dest = tempfile::tempdir().expect("tempdir");
            let restored = Restorer::materialize_with(
                client,
                REPOSITORY,
                ring,
                point,
                dest.path(),
                None,
                concurrency,
            )
            .await
            .expect("restore");
            (dest, restored)
        }
    };

    state.reset_peak();
    let (_one_dest, one) = restore(1).await;
    assert_eq!(state.peak.load(Ordering::SeqCst), 1);
    state.reset_peak();
    let (_four_dest, four) = restore(4).await;
    let peak = state.peak.load(Ordering::SeqCst);
    assert!(
        (3..=4).contains(&peak),
        "four in flight, never more: {peak}"
    );

    let sequential_took = one.stats().elapsed;
    let parallel_took = four.stats().elapsed;
    eprintln!(
        "restore of {LAYERS} layers at {LATENCY:?} per request: sequential {sequential_took:?}, \
         four at a time {parallel_took:?} ({} bytes on the wire, {} bytes/s)",
        four.stats().wire_bytes,
        four.stats().wire_rate()
    );
    // The index, then one GET per layer.
    let layers = u32::try_from(LAYERS).expect("layers");
    assert!(sequential_took >= LATENCY * (1 + layers));
    // The index, then ceil(8 / 4) = 2 rounds of four rather than 8 — about a third of the
    // sequential time locally. Asserted at half, for the same reason as the capture's.
    assert!(
        parallel_took * 2 < sequential_took,
        "four at a time is about two rounds: {parallel_took:?}"
    );

    // Every byte came back.
    for (path, body) in &tree.files {
        assert_eq!(
            &std::fs::read(four.root().join(path)).expect("read"),
            body,
            "{path}"
        );
    }

    // The numbers the log lines are made of.
    let stats = four.stats();
    let logical: u64 = tree.files.iter().map(|(_, body)| body.len() as u64).sum();
    let wire: u64 = references.iter().map(|layer| layer.size).sum::<u64>() + point.index.size;
    assert_eq!(stats.files, LAYERS as u64);
    assert_eq!(stats.layers, LAYERS);
    assert_eq!(stats.bytes, logical, "the plaintext written");
    assert_eq!(
        stats.wire_bytes, wire,
        "the index and every layer, as stored"
    );
    assert_eq!(
        stats.wire_rate(),
        orc_app::persist::bytes_per_second(wire, stats.elapsed)
    );
    let expected_rate = u128::from(wire) * 1_000_000 / stats.elapsed.as_micros();
    assert_eq!(u128::from(stats.wire_rate()), expected_rate);
    assert_eq!(one.stats().wire_bytes, wire, "the same bytes either way");
    assert_eq!(one.stats().bytes, logical);
}

/// One layer that fails fails the restore, at once: the layers still downloading are cut
/// off rather than awaited to their end, and the error is the failing layer's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_layer_fails_the_restore_and_stops_the_rest() {
    let tree = tree(&[LAYER_BYTES; LAYERS], 3);
    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = sealer(3);
    let (point, references) = capture(&uploader(&addr, &sealer), &tree, 4).await;

    // The fourth layer is refused; every other one sends half its bytes and never ends.
    // The index is served whole: no layer is asked for until it has been read.
    let refused = references[3].digest.clone();
    state.get_rule(&point.index.digest, Rule::Serve);
    state.get_rule(&refused, Rule::Refuse);
    state.set_rules(Rules {
        other_get: Rule::Stall,
        ..Rules::default()
    });
    let dest = tempfile::tempdir().expect("tempdir");
    let ring = KeyRing::single(KEY_ID, Arc::clone(&sealer));
    let client = client(&addr);
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Restorer::materialize_with(&client, REPOSITORY, &ring, &point, dest.path(), None, 4),
    )
    .await
    .expect("a failed layer must not leave the restore waiting on the others");
    let Err(err) = result else {
        panic!("the restore fails");
    };
    eprintln!("failed restore returned in {:?}: {err}", started.elapsed());
    assert!(
        matches!(err, RestoreError::Registry(_)),
        "the refused layer's own error comes back, not a cancellation: {err}"
    );
    assert!(
        err.to_string().contains(&refused),
        "it names the refused layer: {err}"
    );

    // The three stalled downloads in flight beside it were hung up on.
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.abandoned_bodies.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        state.abandoned_bodies.load(Ordering::SeqCst),
        3,
        "every sibling download was cancelled"
    );
}

/// One layer that fails fails the capture, at once: the others are cancelled rather than
/// awaited to their end, keep their sessions for the next cycle, and nothing commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_layer_fails_the_capture_and_stops_the_rest() {
    // One big layer among small ones: the big one's PATCH is refused, the small ones hang.
    let mut sizes = [LAYER_BYTES; 4];
    sizes[2] = 2 * 1024 * 1024;
    let tree = tree(&sizes, 4);
    let state = fake();
    state.big_patch.store(1024 * 1024, Ordering::SeqCst);
    state.set_rules(Rules {
        big_patch: Rule::Refuse,
        small_patch: Rule::Stall,
        ..Rules::default()
    });
    let addr = serve(state.clone()).await;
    let uploader = uploader(&addr, &sealer(4));

    let started = Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(10), uploader.upload_layers(&tree.plans))
        .await
        .expect("a failed layer must not leave the capture waiting on the others")
        .expect_err("the capture fails");
    eprintln!("failed capture returned in {:?}: {err}", started.elapsed());
    assert!(
        !err.to_string().contains("abandoned"),
        "the refused layer's own error comes back, not the cancellation: {err}"
    );
    assert!(uploader.is_cancelled(), "the failure spends the uploader");

    let store = state.store.lock().expect("store");
    assert_eq!(store.blobs.len(), 0, "no layer finished, so none is stored");
    assert_eq!(
        store.deleted.len(),
        1,
        "only the refused layer hands its session back: {:?}",
        store.deleted
    );
    assert_eq!(
        store.sessions.len(),
        3,
        "the cancelled ones keep theirs for the next cycle"
    );
}

/// A capture cut short after some of its layers finished is not asked for those layers
/// again, and resumes the one it was in the middle of.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_cut_short_resumes_without_resending_finished_layers() {
    let mut sizes = [LAYER_BYTES; 6];
    sizes[5] = 2 * 1024 * 1024;
    let tree = tree(&sizes, 5);
    let state = fake();
    state.big_patch.store(1024 * 1024, Ordering::SeqCst);
    state.set_rules(Rules {
        big_patch: Rule::Stall,
        ..Rules::default()
    });
    let addr = serve(state.clone()).await;
    let sealer = sealer(5);

    // The first cycle: the five small layers land, the big one hangs, the watchdog cuts.
    let first = Arc::new(uploader(&addr, &sealer));
    let upload = tokio::spawn({
        let first = Arc::clone(&first);
        let plans = tree.plans.clone();
        async move { first.upload_layers(&plans).await }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.store.lock().expect("store").blobs.len() < 5 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    first.cancel();
    let err = upload
        .await
        .expect("join")
        .expect_err("a cut capture does not succeed");
    assert!(err.to_string().contains("abandoned"), "{err}");
    let (finished, first_negotiations) = {
        let store = state.store.lock().expect("store");
        (
            store.blobs.keys().cloned().collect::<Vec<_>>(),
            store.negotiations.clone(),
        )
    };
    assert_eq!(finished.len(), 5);
    // The next cycle offers the same layers.
    state.set_rules(Rules::default());
    let second = uploader(&addr, &sealer);
    let references = second.upload_layers(&tree.plans).await.expect("next cycle");
    let store = state.store.lock().expect("store");
    let again = &store.negotiations[first_negotiations.len()..];
    assert_eq!(again.len(), 6, "one negotiation per layer");
    for (digest, missing, _) in again {
        if finished.contains(digest) {
            assert_eq!(
                *missing, 0,
                "a layer the cut cycle finished is not asked for again"
            );
        } else {
            assert!(*missing > 0, "the big layer still had frames to send");
        }
    }
    let big = &references[5].digest;
    let first_session = first_negotiations
        .iter()
        .find(|(digest, _, _)| digest == big)
        .map(|(_, _, session)| session.clone())
        .expect("first big negotiation");
    let resumed = again
        .iter()
        .find(|(digest, _, _)| digest == big)
        .map(|(_, _, session)| session.clone())
        .expect("second big negotiation");
    assert_eq!(resumed, first_session, "the cut layer's session is resumed");
    assert_eq!(
        second.sent_bytes(),
        references[5].size,
        "only the layer that was cut crosses the wire again"
    );
    assert!(store.deleted.is_empty());
}

/// Layers start largest first: a big layer a cut cycle left half-sent resumes its session
/// before a new session is opened beside it, so the registry's per-principal cap never
/// makes room by abandoning it. One at a time, so the order the registry sees is the
/// order they were started in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_largest_layer_is_started_first() {
    let mut sizes = [LAYER_BYTES / 4; 3];
    sizes[2] = LAYER_BYTES;
    let tree = tree(&sizes, 6);
    let state = fake();
    let addr = serve(state.clone()).await;
    let references = uploader(&addr, &sealer(6))
        .upload_layers_with(&tree.plans, 1)
        .await
        .expect("upload");
    let store = state.store.lock().expect("store");
    let order: Vec<&str> = store
        .negotiations
        .iter()
        .map(|(digest, _, _)| digest.as_str())
        .collect();
    assert_eq!(
        order.first().copied(),
        Some(references[2].digest.as_str()),
        "last in plan order, but largest"
    );
    assert_eq!(order.len(), 3);
}
