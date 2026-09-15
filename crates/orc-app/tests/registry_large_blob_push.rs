//! The fake registry, and what the two tests here put through it.
//!
//! 1. A large blob PUT must carry the token the client already exchanged.
//! 2. A whole App-data capture cycle — walk, diff, pack, seal, negotiate, `PATCH`,
//!    finalize, commit — and the restore that reads it all back byte for byte.
//!
//! The fake registry models the `/v2` protocol in the two respects that matter:
//! it challenges a write with `scope="repository:{name}:push"`
//! (the action it authorizes, not `pull,push`), and an unauthenticated request
//! is rejected before its body is read. Blast an 18MB body at that and the
//! registry never drains it — the client dies mid-write with a transport error
//! instead of a 401 it could act on.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};

/// A negotiated chunked-upload session, as the real `ChunkedUploads` holds one: the
/// declared layer digest and the recipe's frames in blob order.
#[derive(Clone)]
struct Session {
    layer_digest: String,
    media_type: String,
    chunks: Vec<(String, u64)>,
}

#[derive(Clone, Default)]
struct Store {
    /// Frames the registry holds, by blake3 hex — this is what negotiation answers from.
    frames: HashMap<String, Vec<u8>>,
    /// Committed blobs by `sha256:…`.
    blobs: HashMap<String, Vec<u8>>,
    sessions: HashMap<String, Session>,
    /// Every negotiation, as `(layer digest, frames declared missing, session id)`.
    negotiations: Vec<(String, usize, String)>,
    /// Sessions the client `DELETE`d, in order.
    deleted: Vec<String>,
    /// Committed restore points as `(repository, body)`: one repository per app, so
    /// which one a point arrived at is part of what these tests check.
    points: Vec<(String, serde_json::Value)>,
    /// Every `/v2` request served, as `(method, repository)` — what proves an app's
    /// layers, frames and commit all address that app's own repository.
    requests: Vec<(String, String)>,
}

#[derive(Clone)]
struct Fake {
    addr: Arc<std::sync::OnceLock<String>>,
    /// Set when a blob PUT arrives carrying an Authorization header.
    put_authed: Arc<AtomicBool>,
    /// Set when a blob PUT arrives without one — the bug.
    put_anonymous: Arc<AtomicBool>,
    /// While set, a `PATCH` announces itself and then never answers — a stand-in for the
    /// slow upload a capture watchdog cuts short. `stall_after` many `PATCH`es are served
    /// normally first, so a test can cut an upload that has already got some frames in.
    stall_patches: Arc<AtomicBool>,
    stall_after: Arc<std::sync::atomic::AtomicUsize>,
    patches: Arc<std::sync::atomic::AtomicUsize>,
    /// While set, a `PATCH` is refused outright — the failure no retry of this layer can
    /// get past.
    reject_patches: Arc<AtomicBool>,
    /// Signalled when a stalled `PATCH` has arrived, so a test can cancel at exactly the
    /// moment the real ladder is mid-upload.
    patch_arrived: Arc<tokio::sync::Notify>,
    store: Arc<std::sync::Mutex<Store>>,
}

fn challenge(state: &Fake, scope: &str) -> Response {
    let addr = state.addr.get().expect("addr");
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!(
                "Bearer realm=\"http://{addr}/api/auth/registry/token\",service=\"orc-registry\",scope=\"{scope}\""
            ),
        )],
    )
        .into_response()
}

/// The repository a `/v2` path addresses: everything ahead of the first `/_orc/` or
/// `/blobs/`. For App data that is one app's repository — the pool's base plus the app's
/// leaf — and never the base on its own.
fn repository_of(rest: &str) -> &str {
    for marker in ["/_orc/", "/blobs/"] {
        if let Some((repository, _)) = rest.split_once(marker) {
            return repository;
        }
    }
    rest
}

/// Authorize first, and return the challenge without ever
/// touching `body`.
async fn dispatch(
    State(state): State<Fake>,
    Path(rest): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let authed = headers.contains_key(header::AUTHORIZATION);
    let is_read = matches!(method, Method::GET | Method::HEAD);

    // A blob PUT is the request under test: record how it arrived.
    let is_blob_put = method == Method::PUT && rest.contains("/blobs/uploads/");
    if is_blob_put {
        if authed {
            state.put_authed.store(true, Ordering::SeqCst);
        } else {
            state.put_anonymous.store(true, Ordering::SeqCst);
        }
    }

    if !authed {
        let action = if is_read { "pull" } else { "push" };
        // Note: `body` is dropped here undrained, matching an early auth refusal.
        return challenge(&state, &format!("repository:acme/app:{action}"));
    }

    // What this request addressed, recorded before it is routed: an App-data push is
    // scoped to one app's repository, and nothing but that repository may appear.
    state
        .store
        .lock()
        .expect("store")
        .requests
        .push((method.to_string(), repository_of(&rest).to_owned()));

    // ── The `_orc` chunked-upload extension ──────────────────────────────────
    if let Some((repository, _)) = rest.split_once("/_orc/chunked-uploads")
        && rest.ends_with("/_orc/chunked-uploads/")
        && method == Method::POST
    {
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("recipe");
        return negotiate(&state, repository, &body);
    }
    if let Some((_, tail)) = rest.split_once("/_orc/chunked-uploads/")
        && !tail.is_empty()
    {
        let session = tail.to_owned();
        return session_route(&state, &session, &method, uri.query(), body).await;
    }
    if rest.ends_with("/_orc/restore-points") && method == Method::POST {
        let repository = repository_of(&rest).to_owned();
        let body = axum::body::to_bytes(body, usize::MAX).await.expect("point");
        let point: serde_json::Value = serde_json::from_slice(&body).expect("point json");
        // The real endpoint refuses a body whose app is not the one the repository
        // names; here the pairing is recorded so a test can say which arrived where.
        let mut store = state.store.lock().expect("store");
        // Every declared layer must be a blob the store actually holds, exactly as the
        // real endpoint verifies before it records anything.
        for layer in point["layers"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(std::iter::once(&point["index"]))
        {
            let digest = layer["digest"].as_str().expect("digest");
            let held = store.blobs.get(digest).map(Vec::len).unwrap_or_default() as u64;
            if held == 0 {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    axum::Json(serde_json::json!({"error":"unknown-blob","digest":digest})),
                )
                    .into_response();
            }
            assert_eq!(held, layer["size"].as_u64().expect("size"), "declared size");
        }
        let id = format!("rp-{}", store.points.len() + 1);
        store.points.push((repository, point));
        return (
            StatusCode::CREATED,
            axum::Json(serde_json::json!({"id": id})),
        )
            .into_response();
    }
    if let Some((_, digest)) = rest.split_once("/blobs/")
        && matches!(method, Method::GET)
    {
        let store = state.store.lock().expect("store");
        return match store.blobs.get(digest) {
            Some(blob) => (StatusCode::OK, blob.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }

    if rest.ends_with("/blobs/uploads/") && method == Method::POST {
        return (
            StatusCode::ACCEPTED,
            [(header::LOCATION, "/v2/acme/app/blobs/uploads/sess")],
        )
            .into_response();
    }
    if is_blob_put {
        // Drain the upload, like the real handler streams it to storage.
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("drain body");
        assert_eq!(bytes.len(), 18 * 1024 * 1024, "whole body must arrive");
        return StatusCode::CREATED.into_response();
    }
    if method == Method::HEAD {
        return StatusCode::NOT_FOUND.into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

/// The three verbs an open session answers: `PATCH` frames into it, `PUT` to finalize it,
/// `DELETE` to give it back.
async fn session_route(
    state: &Fake,
    session: &str,
    method: &Method,
    query: Option<&str>,
    body: Body,
) -> Response {
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("frames");
    match *method {
        Method::PATCH => {
            let served = state.patches.fetch_add(1, Ordering::SeqCst);
            if state.reject_patches.load(Ordering::SeqCst) {
                return StatusCode::BAD_REQUEST.into_response();
            }
            if state.stall_patches.load(Ordering::SeqCst)
                && served >= state.stall_after.load(Ordering::SeqCst)
            {
                state.patch_arrived.notify_one();
                // Never answers: the client is expected to walk away from this.
                std::future::pending::<()>().await;
            }
            patch_frames(state, session, &body)
        }
        Method::PUT => finalize(state, session, query.unwrap_or_default()),
        Method::DELETE => abandon(state, session),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// `POST` a recipe: record the session and answer with the frames the store lacks.
fn negotiate(state: &Fake, repository: &str, body: &[u8]) -> Response {
    let recipe: serde_json::Value = serde_json::from_slice(body).expect("recipe json");
    let layer_digest = recipe["digest"].as_str().expect("digest").to_owned();
    let media_type = recipe["media_type"].as_str().unwrap_or_default().to_owned();
    let chunks: Vec<(String, u64)> = recipe["chunks"]
        .as_array()
        .expect("chunks")
        .iter()
        .map(|chunk| {
            let cid = chunk["frame_cid"].as_str().expect("cid");
            // The server accepts a bare hex cid or a `blake3:` prefixed one.
            let cid = cid.strip_prefix("blake3:").unwrap_or(cid).to_owned();
            (cid, chunk["frame_length"].as_u64().expect("length"))
        })
        .collect();
    // The recipe must tile the blob exactly, and its raw lengths must sum to the declared
    // total — the same two checks `ValidatedRecipe::validate` makes.
    let mut cursor = 0u64;
    let mut raw_total = 0u64;
    for chunk in recipe["chunks"].as_array().expect("chunks") {
        assert_eq!(chunk["frame_offset"].as_u64().expect("offset"), cursor);
        cursor += chunk["frame_length"].as_u64().expect("length");
        raw_total += chunk["raw_length"].as_u64().expect("raw");
    }
    assert_eq!(raw_total, recipe["total_length"].as_u64().expect("total"));

    let mut store = state.store.lock().expect("store");
    let missing: Vec<u32> = chunks
        .iter()
        .enumerate()
        .filter(|(_, (cid, _))| !store.frames.contains_key(cid))
        .map(|(index, _)| u32::try_from(index).expect("index"))
        .collect();
    // Re-negotiating a layer resumes the session already open for it, exactly as the real
    // server does: a client that was cut off mid-upload retries the same recipe, and
    // handing it a new session every time would burn its whole session allowance.
    let resumed = store
        .sessions
        .iter()
        .find(|(_, session)| session.layer_digest == layer_digest && session.chunks == chunks)
        .map(|(id, _)| id.clone());
    let session_id = resumed.unwrap_or_else(|| {
        format!(
            "sess-{}-{}",
            repository.len(),
            store.negotiations.len() + 1000
        )
    });
    store.sessions.insert(
        session_id.clone(),
        Session {
            layer_digest: layer_digest.clone(),
            media_type,
            chunks,
        },
    );
    store
        .negotiations
        .push((layer_digest, missing.len(), session_id.clone()));
    axum::Json(serde_json::json!({"session_id": session_id, "missing": missing})).into_response()
}

/// `DELETE`: the client is done with a session it will not finalize.
fn abandon(state: &Fake, session_id: &str) -> Response {
    let mut store = state.store.lock().expect("store");
    if store.sessions.remove(session_id).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    store.deleted.push(session_id.to_owned());
    StatusCode::NO_CONTENT.into_response()
}

/// `PATCH`: `(index u32 LE, len u32 LE, frame bytes)` records, each verified by its cid.
fn patch_frames(state: &Fake, session_id: &str, body: &[u8]) -> Response {
    let mut store = state.store.lock().expect("store");
    let Some(session) = store.sessions.get(session_id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut offset = 0usize;
    while offset < body.len() {
        let index = u32::from_le_bytes(body[offset..offset + 4].try_into().expect("index"));
        let length = u32::from_le_bytes(body[offset + 4..offset + 8].try_into().expect("len"));
        offset += 8;
        let frame = &body[offset..offset + length as usize];
        offset += length as usize;
        let (cid, declared) = &session.chunks[index as usize];
        assert_eq!(*declared, u64::from(length), "declared frame length");
        assert_eq!(
            blake3::hash(frame).to_hex().to_string(),
            *cid,
            "a frame must arrive under the cid the recipe named"
        );
        store.frames.insert(cid.clone(), frame.to_vec());
    }
    StatusCode::ACCEPTED.into_response()
}

/// `PUT ?digest=`: reassemble the recipe from held frames and commit it as a blob.
fn finalize(state: &Fake, session_id: &str, query: &str) -> Response {
    use sha2::Digest as _;

    let mut store = state.store.lock().expect("store");
    let Some(session) = store.sessions.get(session_id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let declared = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("digest="))
        .expect("digest query");
    assert_eq!(declared, session.layer_digest, "finalize digest");
    assert_eq!(
        session.media_type,
        orc_app::persist::upload::APPDATA_LAYER_MEDIA_TYPE,
        "an app data layer declares its own media type"
    );

    let mut blob = Vec::new();
    for (cid, _) in &session.chunks {
        let Some(frame) = store.frames.get(cid) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        blob.extend_from_slice(frame);
    }
    let digest = format!("sha256:{:x}", sha2::Sha256::digest(&blob));
    assert_eq!(
        digest, session.layer_digest,
        "the frames must rebuild the layer"
    );
    store.blobs.insert(digest, blob);
    store.sessions.remove(session_id);
    StatusCode::CREATED.into_response()
}

async fn token() -> Response {
    axum::Json(serde_json::json!({ "token": "tok", "expires_in": 300 })).into_response()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_blob_put_carries_the_exchanged_push_token() {
    let state = fake();
    let app = axum::Router::new()
        .route("/v2/{*rest}", any(dispatch))
        .route("/api/auth/registry/token", get(token))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    state.addr.set(addr.to_string()).expect("set addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let body = vec![0x41u8; 18 * 1024 * 1024];
    let client = orc_app::registry::RegistryClient::with_basic(
        &addr.to_string(),
        "apikey".to_owned(),
        "secret".to_owned(),
        true,
    )
    .expect("client");
    let digest = orc_app::registry::digest_bytes(&body);

    let result = client.ensure_blob("acme/app", &digest, body).await;

    assert!(
        !state.put_anonymous.load(Ordering::SeqCst),
        "the blob PUT went out anonymous: 18MB blasted at a registry that 401s \
         without draining the body, so the upload dies mid-write"
    );
    assert!(
        state.put_authed.load(Ordering::SeqCst),
        "blob PUT never arrived"
    );
    assert!(result.expect("18MB blob uploads"), "blob reported uploaded");
}

fn fake() -> Fake {
    Fake {
        addr: Arc::new(std::sync::OnceLock::new()),
        put_authed: Arc::new(AtomicBool::new(false)),
        put_anonymous: Arc::new(AtomicBool::new(false)),
        stall_patches: Arc::new(AtomicBool::new(false)),
        stall_after: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        patches: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        reject_patches: Arc::new(AtomicBool::new(false)),
        patch_arrived: Arc::new(tokio::sync::Notify::new()),
        store: Arc::new(std::sync::Mutex::new(Store::default())),
    }
}

/// Brings the fake registry up and returns its address.
async fn serve(state: Fake) -> String {
    let app = axum::Router::new()
        .route("/v2/{*rest}", any(dispatch))
        .route("/api/auth/registry/token", get(token))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    state.addr.set(addr.clone()).expect("set addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// A fixed credential provider whose bearer never expires.
struct FixedToken;

#[async_trait::async_trait]
impl orc_app::persist::upload::TokenProvider for FixedToken {
    async fn bearer(&self, _refresh: bool) -> orc_app::error::Result<String> {
        Ok("appdata-token".to_owned())
    }
}

/// The pool's App-data repository, as `AppDataLogin` names it. Nothing is pushed here:
/// it is the base every app's own repository hangs off.
const REPOSITORY_BASE: &str = "acme/prod/appdata-builders";

/// The app these tests capture, as its id travels on the wire, and the repository that
/// id resolves to under the base. An uploader is bound to one app's repository.
const APP: &str = "sys/sys/persist-probe";
const REPOSITORY: &str = "acme/prod/appdata-builders/persist-probe";

/// The addressing every test here leans on, stated once: the constants above are what
/// [`orc_app::persist::upload::app_repository`] produces, not a hand-written guess.
#[test]
fn the_app_repository_is_the_pools_base_plus_the_apps_leaf() {
    assert_eq!(
        orc_app::persist::upload::app_repository(REPOSITORY_BASE, APP),
        REPOSITORY
    );
}

fn spec(paths: &[&str]) -> orc_app::persist::PersistSpec {
    orc_app::persist::PersistSpec::parse(&orc_app::app::PersistBlock {
        paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        hook_pre: None,
        hook_post: None,
    })
    .expect("spec")
}

/// Builds the subtree a graft leaves on the volume for one app: mirrored roots, a
/// shadowed hole, a filtered file, one file large enough to own its layer, and enough
/// small files to make packing matter.
fn capture_view(root: &std::path::Path) -> std::path::PathBuf {
    let app = root.join("postgres");
    let write = |path: std::path::PathBuf, body: &[u8]| {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, body).expect("write");
    };
    // 9 MiB, over the own-layer threshold and across several sealed frames. Compressible
    // in parts and not in others, so both sealed flag values travel.
    let mut big = Vec::with_capacity(9 * 1024 * 1024);
    while big.len() < 9 * 1024 * 1024 {
        let index = u32::try_from(big.len()).unwrap_or_default();
        big.extend_from_slice(&index.to_le_bytes());
        big.extend_from_slice(b"                                ");
    }
    big.truncate(9 * 1024 * 1024);
    write(app.join("var/lib/pg/base/1/big.dat"), &big);
    for index in 0..2000u32 {
        write(
            app.join(format!("var/lib/pg/base/1/rel-{index:04}")),
            format!("relation {index} contents\n").as_bytes(),
        );
    }
    write(
        app.join("var/lib/pg/postgresql.conf"),
        b"shared_buffers=1GB\n",
    );
    write(app.join("var/lib/pg/scratch.bkp"), b"never captured\n");
    // The hole's mirrored subtree: on the volume, shadowed by the graft, never captured.
    write(app.join("var/lib/pg/pg_wal/000001"), b"write ahead log\n");
    write(app.join("srv/app/state.db"), b"state\n");
    std::fs::create_dir_all(app.join("srv/app/empty")).expect("mkdir");
    write(app.join("srv/app/zero"), b"");
    app
}

/// Every path under `root` with its bytes, for a byte-for-byte comparison.
fn snapshot(root: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(
        dir: &std::path::Path,
        prefix: &str,
        out: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().to_string_lossy().to_string();
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let meta = entry.metadata().expect("stat");
            if meta.is_dir() {
                out.insert(format!("{path}/"), Vec::new());
                walk(&entry.path(), &path, out);
            } else {
                out.insert(path, std::fs::read(entry.path()).expect("read"));
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, "", &mut out);
    out
}

/// The whole capture pipeline, then the restore that reads it back.
///
/// This is the contract between the halves in one place: what the walk records, what the
/// packer groups, what the sealed uploader negotiates, what the commit body declares —
/// and then, from nothing but the point's index digest, a byte-for-byte reconstruction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_uploads_and_restores_the_tree_byte_for_byte() {
    use orc_app::persist::KeyRing;
    use orc_app::persist::pack::{BuiltLayer, assign_refs, plan_layers};
    use orc_app::persist::restore::{RestorePoint, Restorer};
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::tree::{INDEX_VERSION, IndexHeader, IndexReader, IndexWriter};
    use orc_app::persist::upload::{CommitRequest, Uploader};

    let state = fake();
    let addr = serve(state.clone()).await;

    let source = tempfile::tempdir().expect("tempdir");
    let view = capture_view(source.path());
    let spec = spec(&[
        "/var/lib/pg",
        "/srv/app",
        "!/var/lib/pg/pg_wal",
        "!**/*.bkp",
    ]);

    let sealer = Arc::new(Sealer::new(&DataKey::new([3u8; 32])));
    let uploader = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&sealer),
        Arc::new(FixedToken),
    );

    // ── Cycle one: everything is new ──────────────────────────────────────────────
    let entries = orc_app::persist::tree::walk(&view, &spec).expect("walk");
    assert!(
        !entries.iter().any(|entry| entry.path.contains("pg_wal")),
        "a hole's shadowed content must never reach a restore point"
    );
    assert!(
        !entries.iter().any(|entry| entry.path.contains(".bkp")),
        "a filtered file must never reach a restore point"
    );
    let empty = IndexHeader {
        v: INDEX_VERSION,
        app: APP.to_owned(),
        created_at: 0,
        layers: Vec::new(),
    };
    let planned = orc_app::persist::tree::diff(&empty, std::iter::empty(), entries).expect("diff");
    let plans = plan_layers(&planned);
    assert!(
        plans
            .iter()
            .any(|plan| plan.kind == orc_app::persist::pack::LayerKind::Whole),
        "the 9 MiB file must own its layer"
    );
    assert!(
        plans
            .iter()
            .any(|plan| plan.kind == orc_app::persist::pack::LayerKind::Pack),
        "the small files must pack"
    );

    let mut built = Vec::new();
    for plan in &plans {
        let layer = uploader.upload_layer(plan).await.expect("upload layer");
        built.push(BuiltLayer {
            plan: plan.clone(),
            layer,
        });
    }
    let (layers, index_entries) = assign_refs(&planned, &built).expect("refs");
    let mut writer = IndexWriter::new(
        Vec::new(),
        &IndexHeader {
            v: INDEX_VERSION,
            app: APP.to_owned(),
            created_at: 1_700_000_000,
            layers: layers.clone(),
        },
    )
    .expect("index header");
    for entry in &index_entries {
        writer.push(entry).expect("index entry");
    }
    let (index_bytes, files) = writer.finish().expect("index");
    let local_index = source.path().join("postgres.jsonl");
    std::fs::write(&local_index, &index_bytes).expect("write index");
    let index = uploader
        .upload_bytes(index_bytes)
        .await
        .expect("upload index");

    let point = uploader
        .commit(&CommitRequest {
            app: APP.to_owned(),
            key_id: "0123456789abcdef".to_owned(),
            created_at: 1_700_000_000,
            index: index.clone(),
            layers: layers.clone(),
            files,
            bytes: plans.iter().map(|plan| plan.bytes).sum(),
            kind: orc_app::persist::upload::CommitKind::Periodic,
        })
        .await
        .expect("commit");
    assert!(point.created);
    assert_eq!(point.id, "rp-1");

    // ── Everything that just travelled went to this app's repository ──────────────
    // The negotiation, every `PATCH`, the finalize and the commit: one app's capture
    // never addresses the pool's base, which holds no blobs of its own.
    {
        let store = state.store.lock().expect("store");
        let addressed: std::collections::BTreeSet<&str> = store
            .requests
            .iter()
            .map(|(_, repository)| repository.as_str())
            .collect();
        assert_eq!(
            addressed,
            std::collections::BTreeSet::from([REPOSITORY]),
            "an app's capture addresses its own repository and nothing else"
        );
        let methods: std::collections::BTreeSet<&str> = store
            .requests
            .iter()
            .map(|(method, _)| method.as_str())
            .collect();
        assert!(
            methods.contains("POST") && methods.contains("PATCH") && methods.contains("PUT"),
            "the whole ladder ran against it: {methods:?}"
        );
        assert_eq!(store.points.len(), 1);
        assert_eq!(store.points[0].0, REPOSITORY, "the commit went there too");
        assert_eq!(store.points[0].1["app"], APP);
    }

    // ── The restore, from the point's index digest alone ──────────────────────────
    let destination = tempfile::tempdir().expect("tempdir");
    let client =
        orc_app::registry::RegistryClient::with_bearer(&addr, "appdata-token".to_owned(), true)
            .expect("client");
    let restored = Restorer::materialize(
        &client,
        REPOSITORY,
        &KeyRing::single("0123456789abcdef", Arc::clone(&sealer)),
        &RestorePoint {
            // The subtree key, as the node stages a point: the app id names the
            // repository the layers are read from, never a directory.
            app: orc_app::persist::upload::app_leaf(APP).to_owned(),
            id: point.id.clone(),
            key_id: "0123456789abcdef".to_owned(),
            created_at: 1_700_000_000,
            index,
            files,
            bytes: 0,
        },
        destination.path(),
    )
    .await
    .expect("materialize");

    let expected: std::collections::BTreeMap<String, Vec<u8>> = snapshot(&view)
        .into_iter()
        .filter(|(path, _)| {
            !path.contains("pg_wal") && !path.contains(".bkp") && !path.starts_with("c/")
        })
        .collect();
    let actual = snapshot(restored.root());
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "the restored tree must have exactly the captured paths"
    );
    assert_eq!(actual, expected, "every byte must come back");
    assert_eq!(restored.stats().files, 2004);
    assert!(restored.stats().bytes >= 9 * 1024 * 1024);

    // The read is the mirror of the write: the index and every layer were fetched from
    // the same app repository they were pushed to.
    {
        let store = state.store.lock().expect("store");
        let reads: Vec<&str> = store
            .requests
            .iter()
            .filter(|(method, _)| method == "GET")
            .map(|(_, repository)| repository.as_str())
            .collect();
        assert!(!reads.is_empty(), "the restore read blobs back");
        assert!(
            reads.iter().all(|repository| *repository == REPOSITORY),
            "a restore reads the app's repository: {reads:?}"
        );
    }

    // ── A restored tree seeds an index that does not re-upload itself ─────────────
    // This is what makes a replacement node cheap: without the seeded index its first
    // capture would be a full upload of everything it had just downloaded.
    let seeded = destination.path().join("postgres.jsonl");
    let seeded_count = restored
        .seed_index(restored.root(), &spec, &seeded)
        .expect("seed index");
    assert_eq!(
        seeded_count, files,
        "the seeded index covers the whole tree"
    );
    let restored_entries =
        orc_app::persist::tree::walk(restored.root(), &spec).expect("walk restored");
    let reader = IndexReader::open(std::io::BufReader::new(
        std::fs::File::open(&seeded).expect("open seeded"),
    ))
    .expect("seeded reader");
    let header = reader.header().clone();
    assert_eq!(
        header.layers, layers,
        "the seeded index carries the point's layers"
    );
    let planned = orc_app::persist::tree::diff(&header, reader, restored_entries).expect("diff");
    assert!(
        plan_layers(&planned).is_empty(),
        "a freshly restored tree must plan no upload at all"
    );

    // ── Cycle two: nothing changed, so nothing is planned ─────────────────────────
    let again = orc_app::persist::tree::walk(&view, &spec).expect("walk");
    let reader = IndexReader::open(std::io::BufReader::new(
        std::fs::File::open(&local_index).expect("open index"),
    ))
    .expect("index reader");
    let header = reader.header().clone();
    let planned = orc_app::persist::tree::diff(&header, reader, again).expect("diff");
    assert!(
        plan_layers(&planned).is_empty(),
        "an unchanged tree must plan no layers at all"
    );

    // ── Cycle three: one small file changes, and only its pack is re-sent ─────────
    std::fs::write(
        view.join("var/lib/pg/postgresql.conf"),
        b"shared_buffers=2GB\n",
    )
    .expect("rewrite");
    let changed = orc_app::persist::tree::walk(&view, &spec).expect("walk");
    let reader = IndexReader::open(std::io::BufReader::new(
        std::fs::File::open(&local_index).expect("open index"),
    ))
    .expect("index reader");
    let header = reader.header().clone();
    let planned = orc_app::persist::tree::diff(&header, reader, changed).expect("diff");
    let plans = plan_layers(&planned);
    assert_eq!(plans.len(), 1, "only the changed file's pack is planned");
    assert_eq!(plans[0].files.len(), 1);

    let before = state.store.lock().expect("store").frames.len();
    let layer = uploader.upload_layer(&plans[0]).await.expect("upload");
    let after = state.store.lock().expect("store").frames.len();
    assert!(
        after > before,
        "the changed pack is a new layer and its frame is new"
    );
    let (layers, _) = assign_refs(
        &planned,
        &[BuiltLayer {
            plan: plans[0].clone(),
            layer,
        }],
    )
    .expect("refs");
    assert!(
        layers.len() >= 2,
        "the layers the unchanged files still live in must be carried forward"
    );

    // Re-uploading a layer the registry already holds sends no frames at all.
    let repeat = uploader.upload_layer(&plans[0]).await.expect("re-upload");
    let store = state.store.lock().expect("store");
    let last = store.negotiations.last().expect("negotiation");
    assert_eq!(last.0, repeat.digest);
    assert_eq!(last.1, 0, "a converged layer re-sends nothing");
}

/// Writes the index a walk earned, with every file pointed at the whole of one layer.
///
/// The real writer, so the sorted order it enforces is the order the restore re-checks.
#[cfg(unix)]
fn index_over_one_layer(
    entries: &[orc_app::persist::tree::WalkEntry],
    layer: &orc_app::persist::tree::LayerRef,
) -> (Vec<u8>, u64) {
    use orc_app::persist::tree::{Entry, EntryRef, INDEX_VERSION, IndexHeader, IndexWriter, Kind};

    let mut writer = IndexWriter::new(
        Vec::new(),
        &IndexHeader {
            v: INDEX_VERSION,
            app: APP.to_owned(),
            created_at: 1,
            layers: vec![layer.clone()],
        },
    )
    .expect("writer");
    for entry in entries {
        writer
            .push(&Entry {
                p: entry.path.clone(),
                k: entry.kind,
                s: entry.size,
                m: entry.mtime_ns,
                c: 0,
                mode: entry.mode,
                t: entry.target.clone(),
                r: (entry.kind == Kind::File).then_some(EntryRef {
                    l: 0,
                    o: 0,
                    n: entry.size,
                }),
            })
            .expect("push");
    }
    writer.finish().expect("finish")
}

/// An honest app tree with an absolute symlink in it still produces a point that restores.
///
/// A restore refuses an index that carries a target it could not recreate, so a walk that
/// recorded `localtime -> /usr/share/zoneinfo/UTC` would make the whole point
/// unrestorable — and undownloadable — over one link nobody was attacking with. The walk
/// leaves it out and counts it; the refusal stays as the hard line for an index that
/// arrives carrying one anyway.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tree_with_an_absolute_symlink_still_captures_and_restores() {
    use orc_app::persist::KeyRing;
    use orc_app::persist::restore::{RestorePoint, Restorer};
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::tree::walk_with_stats;
    use orc_app::persist::upload::Uploader;

    let source = tempfile::tempdir().expect("tempdir");
    let app = source.path().join("postgres/srv/app");
    std::fs::create_dir_all(&app).expect("mkdir");
    std::fs::write(app.join("state.db"), b"state\n").expect("write");
    std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", app.join("localtime")).expect("link");
    std::os::unix::fs::symlink("state.db", app.join("current")).expect("link");

    let spec = spec(&["/srv/app"]);
    let walked = walk_with_stats(&source.path().join("postgres"), &spec).expect("walk");
    assert_eq!(walked.skipped_symlinks, 1, "the absolute link is left out");
    assert!(
        !walked
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("/localtime")),
        "and it is not in the index"
    );

    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = Arc::new(Sealer::new(&DataKey::new([13u8; 32])));
    let uploader = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&sealer),
        Arc::new(FixedToken),
    );
    let data = uploader
        .upload_bytes(b"state\n".to_vec())
        .await
        .expect("data layer");

    // The index the walk earned, written through the real writer — which is also what
    // enforces the sorted order the restore side re-checks.
    let (document, count) = index_over_one_layer(&walked.entries, &data);
    let index = uploader.upload_bytes(document).await.expect("index layer");

    let destination = tempfile::tempdir().expect("tempdir");
    let client =
        orc_app::registry::RegistryClient::with_bearer(&addr, "appdata-token".to_owned(), true)
            .expect("client");
    let restored = Restorer::materialize(
        &client,
        REPOSITORY,
        &KeyRing::single("0123456789abcdef", Arc::clone(&sealer)),
        &RestorePoint {
            app: "postgres".to_owned(),
            id: "rp-honest".to_owned(),
            key_id: "0123456789abcdef".to_owned(),
            created_at: 1,
            index,
            files: count,
            bytes: 6,
        },
        destination.path(),
    )
    .await
    .expect("the point must restore");

    let root = restored.root().join("srv/app");
    assert_eq!(
        std::fs::read(root.join("state.db")).expect("read"),
        b"state\n"
    );
    assert_eq!(
        std::fs::read_link(root.join("current")).expect("read_link"),
        std::path::Path::new("state.db"),
        "the link that stays inside the tree comes back"
    );
    assert!(
        root.join("localtime").symlink_metadata().is_err(),
        "the one the walk left out is simply absent"
    );
}

/// Runs the hostile index shape — `a` declared a symlink to `target`, `a/x` declared a
/// file inside it — and returns whatever the restore refused with.
///
/// Both paths are textually clean, and `a` sorts before `a/x`, so a naive materializer
/// meets them in exactly that order: create the link, then write straight through it. The
/// restore's temporary directory is later renamed over live app data, so a write that
/// lands outside it is a write outside the app.
async fn restore_a_file_under_a_declared_symlink(
    target: &str,
) -> orc_app::persist::restore::RestoreError {
    use orc_app::persist::KeyRing;
    use orc_app::persist::restore::{RestorePoint, Restorer};
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = Arc::new(Sealer::new(&DataKey::new([11u8; 32])));
    let uploader = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&sealer),
        Arc::new(FixedToken),
    );

    // One data layer whose whole plaintext is the payload the file entry claims.
    let data = uploader
        .upload_bytes(b"LOOT!".to_vec())
        .await
        .expect("data layer");
    let index_document = format!(
        "{}\n{}\n{}\n",
        serde_json::json!({
            "v": 1, "app": "evil", "created_at": 1,
            "layers": [{"digest": data.digest, "size": data.size}],
        }),
        serde_json::json!({"p": "a", "k": "l", "m": 1, "t": target}),
        serde_json::json!({"p": "a/x", "k": "f", "s": 5, "m": 1, "r": {"l": 0, "o": 0, "n": 5}}),
    );
    let index = uploader
        .upload_bytes(index_document.into_bytes())
        .await
        .expect("index layer");

    let destination = tempfile::tempdir().expect("tempdir");
    let client =
        orc_app::registry::RegistryClient::with_bearer(&addr, "appdata-token".to_owned(), true)
            .expect("client");
    Restorer::materialize(
        &client,
        REPOSITORY,
        &KeyRing::single("0123456789abcdef", Arc::clone(&sealer)),
        &RestorePoint {
            app: "evil".to_owned(),
            id: "rp-hostile".to_owned(),
            key_id: "0123456789abcdef".to_owned(),
            created_at: 1,
            index,
            files: 2,
            bytes: 5,
        },
        destination.path(),
    )
    .await
    .err()
    .expect("a file under a declared symlink must be refused")
}

/// First line of the rule: a symlink target that leaves the tree is refused when the index
/// is parsed, so the phases never see it and nothing appears where it pointed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_symlink_in_the_index_cannot_redirect_a_file_out_of_the_restore() {
    // Somewhere the restore has no business touching.
    let outside = tempfile::tempdir().expect("tempdir");
    let loot = outside.path().join("x");

    let err = restore_a_file_under_a_declared_symlink(&outside.path().to_string_lossy()).await;
    assert!(
        err.to_string()
            .contains("cannot be restored inside the app tree"),
        "unexpected refusal: {err}"
    );
    assert!(
        !loot.exists(),
        "the restore wrote through the index's symlink and landed at {}",
        loot.display()
    );
    assert_eq!(
        std::fs::read_dir(outside.path())
            .expect("read outside")
            .count(),
        0,
        "nothing at all may appear outside the restore root"
    );
}

/// Second line, which stands on its own: the same shape with a target that *does* stay
/// inside the tree parses fine, and the file under the declared link is still refused —
/// a file is only ever created inside a directory this restore itself made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_under_a_declared_symlink_is_refused_even_when_the_target_stays_inside() {
    let err = restore_a_file_under_a_declared_symlink("inside").await;
    assert!(
        err.to_string().contains("no directory to be restored into"),
        "unexpected refusal: {err}"
    );
}

/// The other half of the same rule: a symlink the index legitimately declares is still
/// recreated, and it is created after every byte has been written.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_legitimate_symlink_is_restored_after_the_files_it_sits_beside() {
    use orc_app::persist::KeyRing;
    use orc_app::persist::restore::{RestorePoint, Restorer};
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = Arc::new(Sealer::new(&DataKey::new([12u8; 32])));
    let uploader = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&sealer),
        Arc::new(FixedToken),
    );

    let data = uploader
        .upload_bytes(b"body!".to_vec())
        .await
        .expect("data layer");
    let index_document = format!(
        "{}\n{}\n{}\n{}\n",
        serde_json::json!({
            "v": 1, "app": "linky", "created_at": 1,
            "layers": [{"digest": data.digest, "size": data.size}],
        }),
        serde_json::json!({"p": "d", "k": "d", "m": 1, "mode": 0o755}),
        serde_json::json!({"p": "d/file", "k": "f", "s": 5, "m": 1, "mode": 0o644,
                           "r": {"l": 0, "o": 0, "n": 5}}),
        serde_json::json!({"p": "d/link", "k": "l", "m": 1, "t": "file"}),
    );
    let index = uploader
        .upload_bytes(index_document.into_bytes())
        .await
        .expect("index layer");

    let destination = tempfile::tempdir().expect("tempdir");
    let client =
        orc_app::registry::RegistryClient::with_bearer(&addr, "appdata-token".to_owned(), true)
            .expect("client");
    let restored = Restorer::materialize(
        &client,
        REPOSITORY,
        &KeyRing::single("0123456789abcdef", Arc::clone(&sealer)),
        &RestorePoint {
            app: "linky".to_owned(),
            id: "rp-1".to_owned(),
            key_id: "0123456789abcdef".to_owned(),
            created_at: 1,
            index,
            files: 3,
            bytes: 5,
        },
        destination.path(),
    )
    .await
    .expect("materialize");

    let link = restored.root().join("d/link");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("stat link")
            .file_type()
            .is_symlink(),
        "the link must come back as a link"
    );
    assert_eq!(
        std::fs::read_link(&link).expect("read link"),
        std::path::Path::new("file")
    );
    // It resolves, which it only can because the file it names was written first.
    assert_eq!(std::fs::read(&link).expect("read through link"), b"body!");
    assert_eq!(restored.stats().symlinks, 1);
    assert_eq!(restored.stats().files, 1);
}

/// The browser egress path, end to end: two layers sealed under two different keys, an
/// index that names every entry shape the format allows, and one `tar.zst` that must come
/// back holding all of it.
///
/// The two keys are the point of the test. A layer carried forward from an earlier point
/// keeps the key that sealed it then, and the point records only the key it wrote its own
/// layers under — so an archive that knew one key would silently fail on half the tree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // One story: build the point, archive it, read it back.
async fn an_archive_streams_a_point_whose_layers_span_a_key_rotation() {
    use std::io::Read as _;

    use orc_app::persist::KeyRing;
    use orc_app::persist::archive::write_point_archive;
    use orc_app::persist::restore::RestorePoint;
    use orc_app::persist::seal::{DataKey, Sealer, key_id};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;

    // The pool's ring: `older` sealed a layer that a later point carried forward, `newer`
    // sealed everything that point wrote itself.
    let older = Arc::new(Sealer::new(&DataKey::new([21u8; 32])));
    let newer = Arc::new(Sealer::new(&DataKey::new([22u8; 32])));
    let older_id = key_id(&DataKey::new([21u8; 32]));
    let newer_id = key_id(&DataKey::new([22u8; 32]));

    let by_older = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&older),
        Arc::new(FixedToken),
    );
    let by_newer = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&newer),
        Arc::new(FixedToken),
    );

    // The carried layer: one file over the own-layer threshold, then a small one after
    // it — the layer's plaintext is exactly their concatenation, in offset order.
    let big: Vec<u8> = (0..4 * 1024 * 1024u32)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect();
    let mut carried_plaintext = big.clone();
    carried_plaintext.extend_from_slice(b"tail of the carried layer\n");
    let carried = by_older
        .upload_bytes(carried_plaintext)
        .await
        .expect("carried layer");

    // The layer this point wrote itself, under the new key.
    let fresh = by_newer
        .upload_bytes(b"fresh bytes\n".to_vec())
        .await
        .expect("fresh layer");

    // A path over tar's 100-byte name field, so the archive has to emit a GNU long name.
    let long_path = format!("var/lib/pg/{}/deep.conf", "segment".repeat(20));
    assert!(long_path.len() > 100);

    let index_document = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        serde_json::json!({
            "v": 1, "app": "postgres", "created_at": 1_700_000_000,
            "layers": [
                {"digest": carried.digest, "size": carried.size},
                {"digest": fresh.digest, "size": fresh.size},
            ],
        }),
        serde_json::json!({"p": "var", "k": "d", "m": 1_700_000_000_000_000_000i64, "mode": 0o755}),
        serde_json::json!({"p": "var/lib", "k": "d", "m": 1_700_000_000_000_000_000i64, "mode": 0}),
        // The 4 MiB file, and the small one that follows it in the same layer.
        serde_json::json!({"p": "var/lib/big.dat", "k": "f", "s": big.len(),
                           "m": 1_700_000_001_500_000_000i64, "mode": 0o600,
                           "r": {"l": 0, "o": 0, "n": big.len()}}),
        // Zero-length: never cut from a layer, created from the index alone.
        serde_json::json!({"p": "var/lib/empty", "k": "f", "s": 0,
                           "m": 1_700_000_003_000_000_000i64, "mode": 0o644,
                           "r": {"l": 1, "o": 0, "n": 0}}),
        serde_json::json!({"p": "var/lib/link", "k": "l",
                           "m": 1_700_000_005_000_000_000i64, "t": "big.dat"}),
        serde_json::json!({"p": long_path, "k": "f", "s": 12,
                           "m": 1_700_000_004_000_000_000i64, "mode": 0o640,
                           "r": {"l": 1, "o": 0, "n": 12}}),
        // Last by path, though it is second in its layer: the index is ordered by path,
        // and the archive re-orders the files it cuts back into layer-offset order.
        serde_json::json!({"p": "var/lib/tail.txt", "k": "f", "s": 26,
                           "m": 1_700_000_002_000_000_000i64, "mode": 0,
                           "r": {"l": 0, "o": big.len(), "n": 26}}),
    );
    let index = by_newer
        .upload_bytes(index_document.into_bytes())
        .await
        .expect("index layer");

    let client =
        orc_app::registry::RegistryClient::with_bearer(&addr, "appdata-token".to_owned(), true)
            .expect("client");
    // Newest first, as the login reply hands it over.
    let ring = KeyRing::new(vec![
        (newer_id.clone(), Arc::clone(&newer)),
        (older_id, Arc::clone(&older)),
    ]);
    let point = RestorePoint {
        app: "postgres".to_owned(),
        id: "rp-77".to_owned(),
        key_id: newer_id,
        created_at: 1_700_000_000,
        index,
        files: 4,
        bytes: 0,
    };

    let archive = tempfile::tempdir().expect("tempdir");
    let path = archive.path().join("point.tar.zst");
    let file = std::fs::File::create(&path).expect("create");
    let stats = write_point_archive(&client, REPOSITORY, &ring, &point, file)
        .await
        .expect("archive");
    assert_eq!(stats.files, 4, "three placed files and the empty one");
    assert_eq!(stats.dirs, 2);
    assert_eq!(stats.symlinks, 1);
    assert_eq!(stats.layers, 2, "both layers were read");
    assert_eq!(stats.bytes, big.len() as u64 + 26 + 12);

    // Read it back the way a person would.
    let reader = zstd::Decoder::new(std::fs::File::open(&path).expect("open")).expect("zstd");
    let mut tar = tar::Archive::new(reader);
    let mut files: std::collections::BTreeMap<String, Vec<u8>> = std::collections::BTreeMap::new();
    let mut modes: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut mtimes: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut kinds: std::collections::BTreeMap<String, tar::EntryType> =
        std::collections::BTreeMap::new();
    let mut link_targets: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for entry in tar.entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let name = entry.path().expect("path").to_string_lossy().into_owned();
        let header = entry.header().clone();
        modes.insert(name.clone(), header.mode().expect("mode"));
        mtimes.insert(name.clone(), header.mtime().expect("mtime"));
        kinds.insert(name.clone(), header.entry_type());
        if let Ok(Some(target)) = entry.link_name() {
            link_targets.insert(name.clone(), target.to_string_lossy().into_owned());
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body).expect("read entry");
        files.insert(name, body);
    }

    assert_eq!(files.get("var/lib/big.dat").expect("big"), &big);
    assert_eq!(
        files.get("var/lib/tail.txt").expect("tail").as_slice(),
        b"tail of the carried layer\n",
        "the carried layer opened under the older key"
    );
    assert_eq!(
        files.get("var/lib/empty").expect("empty").len(),
        0,
        "a zero-length file comes from the index, not from a layer"
    );
    assert_eq!(
        files.get(&long_path).expect("long path").as_slice(),
        b"fresh bytes\n",
        "a path over 100 bytes survives as a GNU long name"
    );
    assert_eq!(
        kinds.get("var/lib/link").copied(),
        Some(tar::EntryType::Symlink)
    );
    assert_eq!(
        link_targets.get("var/lib/link").map(String::as_str),
        Some("big.dat")
    );
    assert_eq!(kinds.get("var").copied(), Some(tar::EntryType::Directory));
    assert_eq!(modes.get("var/lib/big.dat").copied(), Some(0o600));
    assert_eq!(
        modes.get("var/lib/tail.txt").copied(),
        Some(0o644),
        "a Windows capture's mode 0 becomes a readable default"
    );
    assert_eq!(
        modes.get("var/lib").copied(),
        Some(0o755),
        "and a directory's becomes the directory default"
    );
    assert_eq!(
        mtimes.get("var/lib/big.dat").copied(),
        Some(1_700_000_001),
        "nanoseconds become whole seconds"
    );
}

/// The digest is what says a layer is the layer the point named. A store that hands back
/// something else — a truncated blob, a mixed-up one — must not produce an archive that
/// looks complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_archive_refuses_a_layer_whose_bytes_are_not_the_ones_the_point_named() {
    use orc_app::persist::KeyRing;
    use orc_app::persist::archive::write_point_archive;
    use orc_app::persist::restore::RestorePoint;
    use orc_app::persist::seal::{DataKey, Sealer, key_id};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = Arc::new(Sealer::new(&DataKey::new([23u8; 32])));
    let id = key_id(&DataKey::new([23u8; 32]));
    let uploader = Uploader::new(
        addr.clone(),
        true,
        REPOSITORY.to_owned(),
        Arc::clone(&sealer),
        Arc::new(FixedToken),
    );
    let data = uploader
        .upload_bytes(b"the real bytes\n".to_vec())
        .await
        .expect("data layer");
    let decoy = uploader
        .upload_bytes(b"some other layer\n".to_vec())
        .await
        .expect("decoy layer");

    // The index names the decoy's digest, and the store is then made to answer it with
    // the other layer's bytes — the substitution a digest check exists to catch.
    let index_document = format!(
        "{}\n{}\n",
        serde_json::json!({
            "v": 1, "app": "postgres", "created_at": 1,
            "layers": [{"digest": decoy.digest, "size": decoy.size}],
        }),
        serde_json::json!({"p": "f", "k": "f", "s": 15, "m": 1, "mode": 0o644,
                           "r": {"l": 0, "o": 0, "n": 15}}),
    );
    let index = uploader
        .upload_bytes(index_document.into_bytes())
        .await
        .expect("index layer");
    {
        let mut store = state.store.lock().expect("store");
        let real = store.blobs.get(&data.digest).cloned().expect("real blob");
        store.blobs.insert(decoy.digest.clone(), real);
    }

    let client =
        orc_app::registry::RegistryClient::with_bearer(&addr, "appdata-token".to_owned(), true)
            .expect("client");
    let result = write_point_archive(
        &client,
        REPOSITORY,
        &KeyRing::single(id.clone(), Arc::clone(&sealer)),
        &RestorePoint {
            app: "postgres".to_owned(),
            id: "rp-1".to_owned(),
            key_id: id,
            created_at: 1,
            index,
            files: 1,
            bytes: 15,
        },
        Vec::new(),
    )
    .await;
    assert!(
        result.is_err(),
        "a layer whose bytes do not hash to the digest the point names must abort"
    );
}

/// Bytes zstd cannot do anything with, so a sealed layer of them is about the size of
/// the plaintext it came from and the counters below can be read against it.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24).to_le_bytes()[0]
        })
        .collect()
}

/// The counter a caller reads to tell a slow upload from a stopped
/// one, on the leg where nothing at all is on the wire.
///
/// A whole-file layer is encoded twice — pass 1 to learn the framing, pass 2 to send
/// what is missing — and on a file of any size pass 1 is the longest stretch of the
/// upload with no network traffic. A watchdog reading only the wire would call a
/// perfectly healthy seal stuck.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uploads_progress_counter_moves_while_a_layer_is_only_being_sealed() {
    use orc_app::persist::pack::{LayerKind, LayerPlan, PlannedFile};
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let uploader = Arc::new(Uploader::new(
        addr,
        true,
        REPOSITORY.to_owned(),
        Arc::new(Sealer::new(&DataKey::new([21u8; 32]))),
        Arc::new(FixedToken),
    ));
    let counter = uploader.progress();
    assert_eq!(uploader.progress_bytes(), 0, "nothing done yet");

    let len = 6 * 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.dat");
    std::fs::write(&path, incompressible(len)).expect("write");

    state.stall_patches.store(true, Ordering::SeqCst);
    let sealing = tokio::spawn({
        let uploader = Arc::clone(&uploader);
        async move {
            uploader
                .upload_layer(&LayerPlan {
                    kind: LayerKind::Whole,
                    files: vec![PlannedFile {
                        path: "big.dat".to_owned(),
                        source: path,
                        offset: 0,
                        len: len as u64,
                    }],
                    bytes: len as u64,
                })
                .await
        }
    });

    // The first PATCH has arrived and is hanging: pass 1 is behind us, the registry held
    // none of these frames, and not one byte has been acknowledged.
    state.patch_arrived.notified().await;
    let sealed = uploader.progress_bytes();
    assert!(
        sealed >= len as u64 / 2,
        "the sealing pass must report its own progress rather than wait for the wire: \
         {sealed}"
    );
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::Relaxed),
        sealed,
        "the handle the watchdog holds is the same counter"
    );

    uploader.cancel();
    sealing
        .await
        .expect("join")
        .expect_err("a cancelled upload does not succeed");
}

/// The same counter on the two legs that do talk to the registry: a `PATCH` it
/// acknowledged, and — just as real — the frames it said it already holds.
///
/// The skipping leg is the one that would bite. On a node whose apps rewrite a little
/// of a large file every cycle, most of every layer is already in the registry, and a
/// counter that moved only for `PATCH`ed bytes would sit still while the ladder walked
/// past all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uploads_progress_counter_moves_for_patched_and_for_skipped_frames() {
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([22u8; 32]);
    let new_uploader = || {
        Uploader::new(
            addr.clone(),
            true,
            REPOSITORY.to_owned(),
            Arc::new(Sealer::new(&key)),
            Arc::new(FixedToken),
        )
    };
    let missing_last = || {
        state
            .store
            .lock()
            .expect("store")
            .negotiations
            .last()
            .expect("negotiation")
            .1
    };
    let body = incompressible(6 * 1024 * 1024);

    // ── Patching: nothing of this layer is in the registry, so all of it is sent ───
    let uploader = new_uploader();
    uploader
        .upload_bytes(body.clone())
        .await
        .expect("first upload");
    let patched = uploader.progress_bytes();
    assert!(missing_last() > 0, "the first upload sends real frames");
    assert!(
        patched >= body.len() as u64 / 2,
        "every acknowledged batch counts: {patched} for a {}-byte layer",
        body.len()
    );

    // ── Skipping: the same bytes again, so the registry asks for nothing ───────────
    let uploader = new_uploader();
    uploader
        .upload_bytes(body.clone())
        .await
        .expect("second upload");
    let skipped = uploader.progress_bytes();
    assert_eq!(missing_last(), 0, "a converged layer re-sends nothing");
    assert!(
        skipped >= body.len() as u64 / 2,
        "a frame the registry already holds is progress too, and this upload sent none \
         of them: {skipped}"
    );
}

/// A capture the watchdog cuts off mid-upload must **keep** its session, so the next
/// cycle carries on from the frames it already sent.
///
/// This is the whole point of the registry's resume rule. A node uploading a large layer
/// over a slow link is cut every cycle at the same place; if each cut handed the session
/// back, every cycle would re-negotiate from zero and the layer would never land, however
/// long the node kept trying. Keeping it means the next identical recipe resumes the same
/// session and is asked only for what is still missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_upload_keeps_its_session_so_the_next_cycle_resumes_it() {
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([7u8; 32]);
    let new_uploader = || {
        Arc::new(Uploader::new(
            addr.clone(),
            true,
            REPOSITORY.to_owned(),
            Arc::new(Sealer::new(&key)),
            Arc::new(FixedToken),
        ))
    };
    // Big enough to need several batches, so the cut lands after real frames are in.
    let body = incompressible(24 * 1024 * 1024);

    // The first batch is accepted; the one after it hangs, which is exactly where the
    // engine's watchdog cancels a capture that is running long.
    state.stall_after.store(1, Ordering::SeqCst);
    state.stall_patches.store(true, Ordering::SeqCst);
    let uploader = new_uploader();
    let upload = tokio::spawn({
        let uploader = Arc::clone(&uploader);
        let body = body.clone();
        async move { uploader.upload_bytes(body).await }
    });
    state.patch_arrived.notified().await;
    uploader.cancel();

    let err = upload
        .await
        .expect("join")
        .expect_err("a cancelled upload does not succeed");
    assert!(
        err.to_string().contains("abandoned"),
        "the cancel path's own error should surface: {err}"
    );
    state.stall_patches.store(false, Ordering::SeqCst);

    let (deleted, open, first) = {
        let store = state.store.lock().expect("store");
        (
            store.deleted.clone(),
            store.sessions.len(),
            store.negotiations.first().expect("negotiation").clone(),
        )
    };
    assert!(
        deleted.is_empty(),
        "a cut cycle keeps its session rather than DELETEing it: {deleted:?}"
    );
    assert_eq!(open, 1, "the registry is still holding it");
    assert!(first.1 > 0, "the first attempt was asked for real frames");

    // The next cycle offers the same layer: same session, and only what is still missing.
    new_uploader()
        .upload_bytes(body)
        .await
        .expect("the next cycle finishes the layer");
    let store = state.store.lock().expect("store");
    let second = store.negotiations.last().expect("second negotiation");
    assert_eq!(store.negotiations.len(), 2, "one negotiation per cycle");
    assert_eq!(second.2, first.2, "the same session is resumed");
    assert!(
        second.1 < first.1,
        "the frames the cut cycle got through are not asked for again: {} then {}",
        first.1,
        second.1
    );
    assert!(
        store.deleted.is_empty(),
        "and finalizing closes the session server-side, with nothing to DELETE"
    );
    // Resuming turns on offering the same recipe at the same repository. A cycle that
    // re-derived the app's repository differently after a cut would negotiate a second
    // session and re-send everything, which is the failure this rule exists to prevent.
    assert!(
        store
            .requests
            .iter()
            .all(|(_, repository)| repository == REPOSITORY),
        "both attempts addressed the app's own repository"
    );
}

/// Two apps captured in one cycle are two repositories, and neither can be reached
/// through the other's name.
///
/// This is the shape of a cycle after per-app repositories: one login, one bearer, and
/// an uploader per app bound to the pool's base plus that app's leaf. What it buys is
/// that an app's blobs, its index and its points are addressed by the app they belong
/// to, so nothing one app writes can collide with — or be read through — another's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_apps_of_one_pool_capture_into_two_repositories() {
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::tree::LayerRef;
    use orc_app::persist::upload::{CommitKind, CommitRequest, Uploader, app_repository};

    let state = fake();
    let addr = serve(state.clone()).await;
    let sealer = Arc::new(Sealer::new(&DataKey::new([13u8; 32])));

    let apps = ["sys/sys/postgres", "sys/sys/redis"];
    for (index, app) in (0i64..).zip(apps.iter()) {
        let repository = app_repository(REPOSITORY_BASE, app);
        let uploader = Uploader::new(
            addr.clone(),
            true,
            repository.clone(),
            Arc::clone(&sealer),
            Arc::new(FixedToken),
        );
        let body = format!("{app} state\n").repeat(4096).into_bytes();
        let layer = uploader.upload_bytes(body).await.expect("layer");
        let point = uploader
            .commit(&CommitRequest {
                app: (*app).to_owned(),
                key_id: "0123456789abcdef".to_owned(),
                created_at: 1_700_000_000 + index,
                index: LayerRef {
                    digest: layer.digest.clone(),
                    size: layer.size,
                },
                layers: vec![layer],
                files: 1,
                bytes: 1,
                kind: CommitKind::Periodic,
            })
            .await
            .expect("commit");
        assert!(point.created);
    }

    let store = state.store.lock().expect("store");
    let addressed: std::collections::BTreeSet<&str> = store
        .requests
        .iter()
        .map(|(_, repository)| repository.as_str())
        .collect();
    assert_eq!(
        addressed,
        std::collections::BTreeSet::from([
            "acme/prod/appdata-builders/postgres",
            "acme/prod/appdata-builders/redis",
        ]),
        "one repository per app, and never the pool's base itself"
    );
    // And each point landed at its own app's repository, which is what the server
    // checks the commit body against.
    let landed: Vec<(&str, &str)> = store
        .points
        .iter()
        .map(|(repository, point)| {
            (
                repository.as_str(),
                point["app"].as_str().expect("app on the point"),
            )
        })
        .collect();
    assert_eq!(
        landed,
        vec![
            ("acme/prod/appdata-builders/postgres", "sys/sys/postgres"),
            ("acme/prod/appdata-builders/redis", "sys/sys/redis"),
        ]
    );
}

/// The other half of the rule: a failure no retry of this layer can get past hands the
/// session back at once, rather than leaving its staged frames for the idle TTL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_the_registry_refuses_hands_its_session_back() {
    use orc_app::persist::seal::{DataKey, Sealer};
    use orc_app::persist::upload::Uploader;

    let state = fake();
    let addr = serve(state.clone()).await;
    let uploader = Uploader::new(
        addr,
        true,
        REPOSITORY.to_owned(),
        Arc::new(Sealer::new(&DataKey::new([11u8; 32]))),
        Arc::new(FixedToken),
    );

    state.reject_patches.store(true, Ordering::SeqCst);
    let err = uploader
        .upload_bytes(vec![0x5Au8; 256 * 1024])
        .await
        .expect_err("a refused PATCH is not something a retry gets past");
    assert!(err.to_string().contains("400"), "{err}");

    let store = state.store.lock().expect("store");
    assert_eq!(
        store.deleted.len(),
        1,
        "the ladder DELETEs the session it will not come back to"
    );
    assert_eq!(store.sessions.len(), 0, "so the registry holds none");
}
