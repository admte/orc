//! Pulling one restore point from a registry, end to end, the way `orc pull` does it.
//!
//! The fake registry here serves the two verbs that path needs — a manifest by tag and a
//! blob by digest — and counts every blob it hands out, because half of what these tests
//! pin is what does **not** get fetched: a wrong key must cost one manifest request and
//! nothing else.
//!
//! What each test puts through it is a hand-written point index over one sealed layer. It
//! is written by hand deliberately: the capture side has its own round-trip test, and this
//! one is about the client's half of the contract — the manifest shape, the key check, and
//! that the tree (and the archive) come out holding exactly what the index declares.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use orc_app::encryption::{self, ANNOTATION_KEY_ID, ANNOTATION_SCHEME, SCHEME_SEALED_STREAM};
use orc_app::persist::point::{
    self, ANNOTATION_APP, ANNOTATION_BYTES, ANNOTATION_CREATED, ANNOTATION_FILES, ANNOTATION_KIND,
    ANNOTATION_NODE, ANNOTATION_POINT, ANNOTATION_POOL, ANNOTATION_REF_NAME, ANNOTATION_SLOT,
    RESTORE_POINT_ARTIFACT_TYPE,
};
use orc_app::persist::seal::{DataKey, Sealer, key_id};
use orc_app::persist::stream::encode_sealed_stream;
use orc_app::pull::{self, PullTarget};
use orc_app::registry::RegistryClient;

const REPOSITORY: &str = "acme/prod/appdata-builders";
const TAG: &str = "20260906T081105Z-s1-sys.sys.postgres";
const ENCRYPTED_LAYER: &str = "application/vnd.orc.appdata.layer.v1+zstd+encrypted";
const ENCRYPTED_CONFIG: &str = "application/vnd.orc.appdata.restore-point.config.v1+json+encrypted";

// ── The fake registry ────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Store {
    blobs: HashMap<String, Vec<u8>>,
    /// `tag or digest` → the manifest document served for it.
    manifests: HashMap<String, (String, Vec<u8>)>,
    /// Every blob digest handed out, in order. What a wrong key must leave empty.
    blob_gets: Vec<String>,
    /// Every manifest reference asked for. Routing must cost exactly one of these.
    manifest_gets: Vec<String>,
}

#[derive(Clone, Default)]
struct Fake {
    store: Arc<std::sync::Mutex<Store>>,
}

impl Fake {
    fn blob_gets(&self) -> Vec<String> {
        self.store.lock().expect("store").blob_gets.clone()
    }

    fn manifest_gets(&self) -> Vec<String> {
        self.store.lock().expect("store").manifest_gets.clone()
    }
}

fn get_manifest(state: &Fake, reference: &str) -> Response {
    let mut store = state.store.lock().expect("store");
    store.manifest_gets.push(reference.to_owned());
    match store.manifests.get(reference) {
        Some((media_type, body)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, media_type.clone()),
                (
                    header::HeaderName::from_static("docker-content-digest"),
                    digest_of(body),
                ),
            ],
            body.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn get_blob(state: &Fake, digest: &str) -> Response {
    let mut store = state.store.lock().expect("store");
    store.blob_gets.push(digest.to_owned());
    match store.blobs.get(digest) {
        Some(blob) => (StatusCode::OK, blob.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(state: Fake) -> String {
    let app = axum::Router::new()
        .route("/v2/{*rest}", get(dispatch))
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

/// `/v2/{repo…}/{manifests|blobs}/{reference}`, with a repository of any depth.
async fn dispatch(State(state): State<Fake>, AxumPath(rest): AxumPath<String>) -> Response {
    if let Some((_repository, reference)) = rest.split_once("/manifests/") {
        return get_manifest(&state, reference);
    }
    if let Some((_repository, digest)) = rest.split_once("/blobs/") {
        return get_blob(&state, digest);
    }
    StatusCode::NOT_FOUND.into_response()
}

fn digest_of(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("sha256:{:x}", sha2::Sha256::digest(bytes))
}

// ── The point under test ─────────────────────────────────────────────────────────────

/// The plaintext of the one data layer: the two non-empty files, back to back, in the
/// offset order the index declares.
const ALPHA: &[u8] = b"alpha, and then some\n";
fn beta() -> Vec<u8> {
    (0..=255u8).cycle().take(9000).collect()
}

/// The tree the point declares, as `path → bytes` (directories as a trailing `/`).
fn expected_tree() -> std::collections::BTreeMap<String, Vec<u8>> {
    std::collections::BTreeMap::from([
        ("conf/".to_owned(), Vec::new()),
        ("conf/alpha.txt".to_owned(), ALPHA.to_vec()),
        ("conf/beta.bin".to_owned(), beta()),
        ("conf/empty".to_owned(), Vec::new()),
        ("data/".to_owned(), Vec::new()),
    ])
}

/// Seals `payload` into a layer and files it in the store; returns `(digest, size)`.
fn seal_layer(state: &Fake, sealer: &Sealer, payload: &[u8]) -> (String, u64) {
    let mut wire = Vec::new();
    let layer = encode_sealed_stream(payload, sealer, &mut |frame| {
        wire.extend_from_slice(frame);
        Ok(())
    })
    .expect("seal layer");
    let size = wire.len() as u64;
    state
        .store
        .lock()
        .expect("store")
        .blobs
        .insert(layer.layer_digest.clone(), wire);
    (layer.layer_digest, size)
}

/// Publishes the point: one data layer, the index that describes it, and the manifest that
/// names both — under the time tag and under its `rp-<id>` alias.
fn publish(state: &Fake, sealer: &Sealer, key: &DataKey) -> String {
    let mut plaintext = ALPHA.to_vec();
    plaintext.extend_from_slice(&beta());
    let (layer_digest, layer_size) = seal_layer(state, sealer, &plaintext);

    let index_document = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        serde_json::json!({
            "v": 1, "app": "sys/sys/postgres", "created_at": 1_788_682_265,
            "layers": [{"digest": layer_digest, "size": layer_size}],
        }),
        serde_json::json!({"p": "conf", "k": "d", "m": 1_700_000_000_000_000_000i64,
                           "mode": 0o750}),
        serde_json::json!({"p": "conf/alpha.txt", "k": "f", "s": ALPHA.len(),
                           "m": 1_700_000_001_000_000_000i64, "mode": 0o640,
                           "r": {"l": 0, "o": 0, "n": ALPHA.len()}}),
        serde_json::json!({"p": "conf/beta.bin", "k": "f", "s": 9000,
                           "m": 1_700_000_002_000_000_000i64, "mode": 0o600,
                           "r": {"l": 0, "o": ALPHA.len(), "n": 9000}}),
        // An empty file still names a place in a layer; it is just a zero-length one, and
        // the read creates it from the index rather than cutting it out of anything.
        serde_json::json!({"p": "conf/empty", "k": "f", "s": 0,
                           "m": 1_700_000_003_000_000_000i64, "mode": 0o644,
                           "r": {"l": 0, "o": ALPHA.len() + 9000, "n": 0}}),
        serde_json::json!({"p": "data", "k": "d", "m": 1_700_000_004_000_000_000i64,
                           "mode": 0o755}),
    );
    let (index_digest, index_size) = seal_layer(state, sealer, index_document.as_bytes());

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": RESTORE_POINT_ARTIFACT_TYPE,
        "config": {
            "mediaType": ENCRYPTED_CONFIG,
            "digest": index_digest,
            "size": index_size,
        },
        "layers": [{
            "mediaType": ENCRYPTED_LAYER,
            "digest": layer_digest,
            "size": layer_size,
        }],
        "annotations": {
            ANNOTATION_POINT: "rp-986165",
            ANNOTATION_POOL: "builders",
            ANNOTATION_SLOT: "1",
            ANNOTATION_NODE: "n_a0",
            ANNOTATION_APP: "sys/sys/postgres",
            ANNOTATION_KIND: "periodic",
            ANNOTATION_FILES: "3",
            ANNOTATION_BYTES: (ALPHA.len() + 9000).to_string(),
            ANNOTATION_CREATED: "2026-09-06T08:11:05Z",
            ANNOTATION_REF_NAME: TAG,
            ANNOTATION_SCHEME: SCHEME_SEALED_STREAM,
            ANNOTATION_KEY_ID: key_id(key),
        },
    });
    let body = serde_json::to_vec(&manifest).expect("manifest json");
    let digest = digest_of(&body);
    let mut store = state.store.lock().expect("store");
    for reference in [TAG, "rp-986165", digest.as_str()] {
        store.manifests.insert(
            reference.to_owned(),
            (
                "application/vnd.oci.image.manifest.v1+json".to_owned(),
                body.clone(),
            ),
        );
    }
    digest
}

/// Publishes the same point as [`publish`] with its two files in two layers sealed under
/// two different keys — what a pool looks like after its App data key has been rotated.
///
/// `older` sealed the layer holding `conf/alpha.txt`, carried forward unchanged by dedup
/// from before the rotation; `sealing` sealed the layer written by this point and the
/// index, and is the key the manifest names. Nothing on the wire says which layer belongs
/// to which key — that is the whole reason a pull needs the pool's whole ring.
fn publish_rotated(state: &Fake, older: &DataKey, sealing: &DataKey) -> String {
    let (carried_digest, carried_size) = seal_layer(state, &Sealer::new(older), ALPHA);
    let (fresh_digest, fresh_size) = seal_layer(state, &Sealer::new(sealing), &beta());

    let index_document = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        serde_json::json!({
            "v": 1, "app": "sys/sys/postgres", "created_at": 1_788_682_265,
            "layers": [
                {"digest": carried_digest, "size": carried_size},
                {"digest": fresh_digest, "size": fresh_size},
            ],
        }),
        serde_json::json!({"p": "conf", "k": "d", "m": 1_700_000_000_000_000_000i64,
                           "mode": 0o750}),
        serde_json::json!({"p": "conf/alpha.txt", "k": "f", "s": ALPHA.len(),
                           "m": 1_700_000_001_000_000_000i64, "mode": 0o640,
                           "r": {"l": 0, "o": 0, "n": ALPHA.len()}}),
        serde_json::json!({"p": "conf/beta.bin", "k": "f", "s": 9000,
                           "m": 1_700_000_002_000_000_000i64, "mode": 0o600,
                           "r": {"l": 1, "o": 0, "n": 9000}}),
        serde_json::json!({"p": "conf/empty", "k": "f", "s": 0,
                           "m": 1_700_000_003_000_000_000i64, "mode": 0o644,
                           "r": {"l": 1, "o": 9000, "n": 0}}),
        serde_json::json!({"p": "data", "k": "d", "m": 1_700_000_004_000_000_000i64,
                           "mode": 0o755}),
    );
    // The index is the point's own writing, so it is sealed under the point's own key.
    let (index_digest, index_size) =
        seal_layer(state, &Sealer::new(sealing), index_document.as_bytes());

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": RESTORE_POINT_ARTIFACT_TYPE,
        "config": {
            "mediaType": ENCRYPTED_CONFIG,
            "digest": index_digest,
            "size": index_size,
        },
        "layers": [
            {"mediaType": ENCRYPTED_LAYER, "digest": carried_digest, "size": carried_size},
            {"mediaType": ENCRYPTED_LAYER, "digest": fresh_digest, "size": fresh_size},
        ],
        "annotations": {
            ANNOTATION_POINT: "rp-986165",
            ANNOTATION_POOL: "builders",
            ANNOTATION_SLOT: "1",
            ANNOTATION_NODE: "n_a0",
            ANNOTATION_APP: "sys/sys/postgres",
            ANNOTATION_KIND: "periodic",
            ANNOTATION_FILES: "3",
            ANNOTATION_BYTES: (ALPHA.len() + 9000).to_string(),
            ANNOTATION_CREATED: "2026-09-06T08:11:05Z",
            ANNOTATION_REF_NAME: TAG,
            ANNOTATION_SCHEME: SCHEME_SEALED_STREAM,
            ANNOTATION_KEY_ID: key_id(sealing),
        },
    });
    let body = serde_json::to_vec(&manifest).expect("manifest json");
    let digest = digest_of(&body);
    let mut store = state.store.lock().expect("store");
    for reference in [TAG, "rp-986165", digest.as_str()] {
        store.manifests.insert(
            reference.to_owned(),
            (
                "application/vnd.oci.image.manifest.v1+json".to_owned(),
                body.clone(),
            ),
        );
    }
    carried_digest
}

/// Publishes an ordinary app manifest, so the probe can be shown to walk past it.
fn publish_app(state: &Fake) {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "artifactType": orc_app::app::APP_ARTIFACT_TYPE,
        "config": {
            "mediaType": orc_app::app::APP_CONFIG_MEDIA_TYPE,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "size": 2,
        },
        "layers": [],
    });
    let body = serde_json::to_vec(&manifest).expect("manifest json");
    state
        .store
        .lock()
        .expect("store")
        .manifests
        .insert("default".to_owned(), ("application/json".to_owned(), body));
}

fn client(addr: &str) -> RegistryClient {
    RegistryClient::with_anonymous(addr, true).expect("client")
}

/// Every path under `root` with its bytes, directories as a trailing `/`.
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
            if entry.metadata().expect("stat").is_dir() {
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

// ── The tests ────────────────────────────────────────────────────────────────────────

/// The whole client path: resolve the reference, check the key, fetch the layers, and
/// land the tree the point declares — bytes and permission bits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_point_pulls_into_the_tree_it_declares() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([5u8; 32]);
    let manifest_digest = publish(&state, &Sealer::new(&key), &key);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");
    assert_eq!(point.digest, manifest_digest);
    assert_eq!(point.point.app, "sys/sys/postgres");
    assert_eq!(point.point.files, 3);
    assert_eq!(point.slot, Some(1));
    assert_eq!(point.output_name(), TAG, "the tree is named after the tag");
    assert!(
        state.blob_gets().is_empty(),
        "resolving a reference must not fetch content"
    );

    let ring = encryption::key_ring(&point.encryption, std::slice::from_ref(&key)).expect("ring");
    let dest_dir = tempfile::tempdir().expect("tempdir");
    let dest = dest_dir.path().join(TAG);
    let stats =
        point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, false, None)
            .await
            .expect("materialize");

    assert_eq!(
        snapshot(&dest),
        expected_tree(),
        "every byte must come back"
    );
    assert_eq!(stats.files, 3);
    assert_eq!(stats.dirs, 2);
    assert_eq!(stats.bytes, (ALPHA.len() + 9000) as u64);
    assert_eq!(
        state.blob_gets().len(),
        2,
        "the index and its one layer, each fetched once: {:?}",
        state.blob_gets()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &str| {
            std::fs::metadata(dest.join(path))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("conf"), 0o750);
        assert_eq!(mode("conf/alpha.txt"), 0o640);
        assert_eq!(mode("conf/beta.bin"), 0o600);
    }
    std::fs::remove_dir_all(&dest).expect("clean up");
}

/// The archive is the same read with tar entries where the files would have been, so it
/// must extract to exactly the tree the directory pull produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_archive_extracts_to_the_same_tree() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([6u8; 32]);
    publish(&state, &Sealer::new(&key), &key);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, "rp-986165")
        .await
        .expect("resolve")
        .expect("a restore point");
    assert_eq!(
        point.ref_name, TAG,
        "an alias still reports the canonical tag"
    );
    let ring = encryption::key_ring(&point.encryption, std::slice::from_ref(&key)).expect("ring");

    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("point.tar.zst");
    let stats = point::write_archive(
        &client,
        REPOSITORY,
        &ring,
        &point.point,
        &archive,
        false,
        None,
    )
    .await
    .expect("archive");
    assert_eq!(stats.files, 3);
    assert_eq!(stats.dirs, 2);
    assert!(
        !dir.path().join("point.tar.zst.partial").exists(),
        "the partial name must not survive a successful write"
    );

    let extracted = dir.path().join("extracted");
    std::fs::create_dir(&extracted).expect("mkdir");
    let decoder = zstd::Decoder::new(std::fs::File::open(&archive).expect("open")).expect("zstd");
    tar::Archive::new(decoder)
        .unpack(&extracted)
        .expect("unpack");
    assert_eq!(snapshot(&extracted), expected_tree());
}

/// The key check is worth nothing if it happens after the download. It must land on the
/// manifest's key id, before a single layer is asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_key_is_refused_before_any_layer_is_fetched() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([7u8; 32]);
    publish(&state, &Sealer::new(&key), &key);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");

    let wrong = DataKey::new([8u8; 32]);
    let err = encryption::key_ring(&point.encryption, std::slice::from_ref(&wrong))
        .expect_err("wrong key");
    assert!(
        err.to_string().contains(&key_id(&key)),
        "the error names the key the point wants: {err}"
    );
    assert!(
        !err.to_string().contains(&"08".repeat(32)),
        "the key itself must never be printed: {err}"
    );
    assert!(
        state.blob_gets().is_empty(),
        "a wrong key must cost the manifest and nothing else: {:?}",
        state.blob_gets()
    );

    // And with no key at all, the same: a usage error naming both ways to give one.
    let _guard = env_lock();
    set_env(None);
    let err = encryption::resolve_keys(&point.encryption, &[]).expect_err("no key");
    assert!(err.to_string().contains("--key"), "{err}");
    assert!(state.blob_gets().is_empty());
}

/// A failed pull must leave nothing that looks like a finished one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_layer_the_registry_does_not_hold_leaves_nothing_behind() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([9u8; 32]);
    publish(&state, &Sealer::new(&key), &key);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");
    let ring = encryption::key_ring(&point.encryption, std::slice::from_ref(&key)).expect("ring");

    // The data layer disappears between resolving the point and reading it.
    {
        let mut store = state.store.lock().expect("store");
        let index = point.point.index.digest.clone();
        store.blobs.retain(|digest, _| *digest == index);
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join(TAG);
    point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, false, None)
        .await
        .expect_err("the layer is gone");
    assert!(!dest.exists(), "no destination may be left behind");
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("read_dir").count(),
        0,
        "and no staging directory either"
    );

    let archive = dir.path().join("point.tar.zst");
    point::write_archive(
        &client,
        REPOSITORY,
        &ring,
        &point.point,
        &archive,
        false,
        None,
    )
    .await
    .expect_err("the layer is gone");
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("read_dir").count(),
        0,
        "a truncated archive must not be left under either name"
    );
}

/// An output that already exists is a refusal, not an overwrite — until it is asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_existing_output_is_refused_and_left_untouched() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([10u8; 32]);
    publish(&state, &Sealer::new(&key), &key);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");
    let ring = encryption::key_ring(&point.encryption, std::slice::from_ref(&key)).expect("ring");

    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join(TAG);
    std::fs::create_dir(&dest).expect("dest");
    std::fs::write(dest.join("mine"), b"do not lose this").expect("write");

    let err = point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, false, None)
        .await
        .expect_err("exists");
    assert!(err.to_string().contains("--force"), "{err}");
    assert_eq!(
        std::fs::read(dest.join("mine")).expect("still there"),
        b"do not lose this"
    );

    point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, true, None)
        .await
        .expect("force");
    assert_eq!(snapshot(&dest), expected_tree());
}

/// The probe walks past anything that is not a restore point, so an app pull is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_app_artifact_is_not_a_restore_point() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    publish_app(&state);
    let client = client(&addr);

    assert!(
        point::resolve(&client, REPOSITORY, "default")
            .await
            .expect("resolve")
            .is_none(),
        "an app manifest must fall through to the app path"
    );
    // A reference that does not resolve at all is also "not a point" to this standalone
    // form — which is exactly why `orc pull` does not route through it.
    assert!(
        point::resolve(&client, REPOSITORY, "nothing-here")
            .await
            .expect("resolve")
            .is_none()
    );
    assert!(state.blob_gets().is_empty());
}

/// The whole point of routing on the manifest: deciding what a reference names must cost
/// exactly one manifest request, and the app path must be handed that same document to
/// carry on with rather than asking for it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_costs_one_manifest_fetch_for_either_kind() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let key = DataKey::new([11u8; 32]);
    publish(&state, &Sealer::new(&key), &key);
    publish_app(&state);
    let client = client(&addr);

    let target = pull::resolve_pull_target(&client, REPOSITORY, TAG)
        .await
        .expect("route");
    match target {
        PullTarget::RestorePoint(point) => assert_eq!(point.ref_name, TAG),
        PullTarget::App(_) => panic!("a restore point routed to the app path"),
    }
    assert_eq!(state.manifest_gets(), vec![TAG.to_owned()], "exactly one");
    assert!(state.blob_gets().is_empty(), "and no content");

    let expected = state
        .store
        .lock()
        .expect("store")
        .manifests
        .get("default")
        .map(|(_, body)| digest_of(body))
        .expect("app manifest");
    let target = pull::resolve_pull_target(&client, REPOSITORY, "default")
        .await
        .expect("route");
    match target {
        PullTarget::App(fetched) => assert_eq!(
            fetched.response.digest, expected,
            "the app path is handed the document that was already fetched"
        ),
        PullTarget::RestorePoint(_) => panic!("an app routed to the point path"),
    }
    assert_eq!(
        state.manifest_gets(),
        vec![TAG.to_owned(), "default".to_owned()],
        "one fetch per pull, whichever kind it turns out to be"
    );
}

/// A reference that will not fetch must fail with the error the app path has always
/// reported, not be swallowed into "not a restore point" and asked for a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reference_that_does_not_resolve_fails_once() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let client = client(&addr);

    let err = pull::resolve_pull_target(&client, REPOSITORY, "nothing-here")
        .await
        .expect_err("no such reference");
    assert!(
        matches!(err, orc_app::CliError::NotFound(_)),
        "the registry's own verdict survives routing: {err}"
    );
    assert_eq!(state.manifest_gets(), vec!["nothing-here".to_owned()]);
}

// ── A rotated pool: one point, layers under two keys ─────────────────────────────────

/// Serializes the tests that read or write the process-global environment.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[allow(unsafe_code)]
fn set_env(value: Option<&str>) {
    // SAFETY: every test touching the environment holds `env_lock`, so no other thread
    // reads or writes it concurrently.
    unsafe {
        match value {
            Some(value) => std::env::set_var(encryption::KEY_ENV, value),
            None => std::env::remove_var(encryption::KEY_ENV),
        }
    }
}

/// Lowercase hex of a key, as the node page's Pull command hands one over.
fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The live bug this all exists for: a pool whose key was rotated produces a point whose
/// layers are sealed under two keys, and only the whole ring opens it. Order must not
/// matter — the point's own key is put first wherever it was given.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_point_whose_layers_span_two_keys_pulls_with_both_in_either_order() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let older = [11u8; 32];
    let sealing = [12u8; 32];
    publish_rotated(&state, &DataKey::new(older), &DataKey::new(sealing));
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");
    assert_eq!(
        point.point.key_id,
        key_id(&DataKey::new(sealing)),
        "the manifest names the key the point itself sealed under"
    );

    for order in [[older, sealing], [sealing, older]] {
        let keys: Vec<DataKey> = order.iter().map(|bytes| DataKey::new(*bytes)).collect();
        let ring = encryption::key_ring(&point.encryption, &keys).expect("ring");
        assert_eq!(
            ring.key_ids().next(),
            Some(key_id(&DataKey::new(sealing)).as_str()),
            "the point's own key leads whichever way they were given"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join(TAG);
        point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, false, None)
            .await
            .expect("both keys open every layer");
        assert_eq!(snapshot(&dest), expected_tree());

        // The archive is the same read, and must span the two keys just as well.
        let archive = dir.path().join("point.tar.zst");
        point::write_archive(
            &client,
            REPOSITORY,
            &ring,
            &point.point,
            &archive,
            false,
            None,
        )
        .await
        .expect("archive");
    }
}

/// With only the key the point names, the layer carried forward from before the rotation
/// fails — and the message has to say which layer and what to do, because the bare AEAD
/// refusal ("wrong key or tampered bytes") sends a reader hunting for corruption.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_key_of_two_fails_on_the_carried_layer_and_says_to_pass_them_all() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let older = DataKey::new([13u8; 32]);
    let sealing = DataKey::new([14u8; 32]);
    let carried = publish_rotated(&state, &older, &sealing);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");

    // The point's own key passes the up-front check — it is the right key for the index
    // and for what this point wrote — so this can only fail at the layer.
    let ring = encryption::key_ring(&point.encryption, std::slice::from_ref(&sealing))
        .expect("the sealing key is accepted");
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join(TAG);
    let err = point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, false, None)
        .await
        .expect_err("the carried layer needs the older key");
    let message = err.to_string();
    assert!(
        message.contains("layer 1 of 2"),
        "the failing layer is named by position: {message}"
    );
    assert!(message.contains(&carried), "and by digest: {message}");
    assert!(
        message.contains("more than one key"),
        "and the reader is told why: {message}"
    );
    assert!(
        message.contains("pass every key the pool holds"),
        "and what to do about it: {message}"
    );
    assert!(!dest.exists(), "a failed pull leaves nothing behind");

    // The archive path reports the same thing rather than the bare AEAD refusal.
    let archive = dir.path().join("point.tar.zst");
    let err = point::write_archive(
        &client,
        REPOSITORY,
        &ring,
        &point.point,
        &archive,
        false,
        None,
    )
    .await
    .expect_err("the carried layer needs the older key");
    assert!(err.to_string().contains("pass every key"), "{err}");
}

/// The environment variable takes the whole ring too, so the keys need never be typed
/// where a shell records them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_keys_arrive_through_one_environment_variable() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let older = DataKey::new([15u8; 32]);
    let sealing = DataKey::new([16u8; 32]);
    publish_rotated(&state, &older, &sealing);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");

    let ring = {
        let _guard = env_lock();
        set_env(Some(&format!("{},{}", hex(&[15u8; 32]), hex(&[16u8; 32]))));
        let keys =
            encryption::resolve_keys(&point.encryption, &[]).expect("both keys from the env");
        assert_eq!(keys.len(), 2);
        let ring = encryption::key_ring(&point.encryption, &keys).expect("ring");
        set_env(None);
        ring
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join(TAG);
    point::materialize_into(&client, REPOSITORY, &ring, &point.point, &dest, false, None)
        .await
        .expect("materialize");
    assert_eq!(snapshot(&dest), expected_tree());
}

/// The up-front check still costs one manifest request and nothing else: without the key
/// the point names, no ring is built and no blob is asked for, however many other keys
/// were handed over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ring_without_the_points_own_key_is_refused_before_any_blob_get() {
    let state = Fake::default();
    let addr = serve(state.clone()).await;
    let older = DataKey::new([17u8; 32]);
    let sealing = DataKey::new([18u8; 32]);
    publish_rotated(&state, &older, &sealing);
    let client = client(&addr);

    let point = point::resolve(&client, REPOSITORY, TAG)
        .await
        .expect("resolve")
        .expect("a restore point");

    let stranger = DataKey::new([19u8; 32]);
    let err = encryption::key_ring(&point.encryption, &[older, stranger])
        .expect_err("the sealing key is missing");
    let message = err.to_string();
    assert!(
        message.contains(&key_id(&DataKey::new([18u8; 32]))),
        "the id wanted is named: {message}"
    );
    assert!(
        message.contains(&key_id(&DataKey::new([17u8; 32])))
            && message.contains(&key_id(&DataKey::new([19u8; 32]))),
        "and so are the ids given: {message}"
    );
    assert!(
        !message.contains(&hex(&[17u8; 32])) && !message.contains(&hex(&[19u8; 32])),
        "no key material may appear: {message}"
    );
    assert!(
        state.blob_gets().is_empty(),
        "and nothing was fetched: {:?}",
        state.blob_gets()
    );
}
