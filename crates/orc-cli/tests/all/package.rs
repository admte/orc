use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use orc_cli::package::{PackageOptions, plan_push};
use serde_json::json;
use sha2::{Digest as _, Sha256};

#[test]
fn package_plan_is_stable_and_spec_shaped_from_public_api() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(
        dir.path().join("app.config.v1.json"),
        r#"{"params":{"type":"object","required":["url"],"properties":{"url":{"type":"string","description":"URL"}}}}"#,
    )
    .expect("config");
    std::fs::write(dir.path().join("payload.txt"), b"hello").expect("payload");
    std::fs::write(
        dir.path().join("annotations.json"),
        r#"{"org.opencontainers.image.description":"example"}"#,
    )
    .expect("annotations");

    let first = plan_push(
        dir.path(),
        &[
            PathBuf::from("payload.txt"),
            PathBuf::from("annotations.json"),
            PathBuf::from("app.config.v1.json"),
        ],
        PackageOptions::default(),
    )
    .expect("first plan");
    let second = plan_push(
        dir.path(),
        &[
            PathBuf::from("app.config.v1.json"),
            PathBuf::from("annotations.json"),
            PathBuf::from("payload.txt"),
        ],
        PackageOptions::default(),
    )
    .expect("second plan");

    assert_eq!(first.manifest_digest, second.manifest_digest);
    assert_eq!(first.manifest_bytes, second.manifest_bytes);
    assert_eq!(first.payloads.len(), 1);
    assert_eq!(first.payloads[0].title, "payload.txt");
    assert_eq!(first.payloads[0].media_type, "text/plain");

    let manifest: serde_json::Value = serde_json::from_slice(&first.manifest_bytes).expect("json");
    assert_eq!(manifest["schemaVersion"], 2);
    assert_eq!(
        manifest["mediaType"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(manifest["artifactType"], "application/vnd.orc8r.app.v1");
    assert_eq!(
        manifest["config"]["mediaType"],
        "application/vnd.orc8r.app.config.v1+json"
    );
    assert_eq!(manifest["layers"][0]["mediaType"], "text/plain");
    assert_eq!(
        manifest["layers"][0]["annotations"]["org.opencontainers.image.title"],
        "payload.txt"
    );
    assert_eq!(
        manifest["annotations"]["org.opencontainers.image.description"],
        "example"
    );
    assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "none");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_uploads_missing_blobs_and_publishes_all_tags() {
    let package = tempfile::tempdir().expect("package dir");
    let config = br#"{"params":{"type":"object","properties":{}}}"#;
    let payload = b"already present";
    std::fs::write(package.path().join("app.config.v1.json"), config).expect("config");
    std::fs::write(package.path().join("payload.txt"), payload).expect("payload");
    std::fs::write(
        package.path().join("annotations.json"),
        r#"{"org.opencontainers.image.description":"pushed"}"#,
    )
    .expect("annotations");

    let payload_digest = digest_bytes(payload);
    let server =
        PushMockServer::start("push-token", BTreeSet::from([payload_digest.clone()])).await;
    let config_dir = tempfile::tempdir().expect("config dir");
    let mut credentials = serde_json::Map::new();
    credentials.insert(
        server.registry(),
        json!({"username": "token", "token": "push-token"}),
    );
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({ "credentials": credentials }).to_string(),
    )
    .expect("config");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .current_dir(package.path())
        .args([
            "push",
            "--chunker",
            "none",
            &format!("{}/acme/pushed:1.0,latest", server.registry()),
            "app.config.v1.json",
            "annotations.json",
            "payload.txt",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run push");
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pushed_digest = stdout.trim();
    assert!(pushed_digest.starts_with("sha256:"), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Uploaded 1 blobs, skipped 1, pushed 2 tags"),
        "{stderr}"
    );

    let uploaded = server.uploaded_blobs();
    assert!(uploaded.contains_key(&digest_bytes(config)));
    assert!(!uploaded.contains_key(&payload_digest));
    let manifests = server.manifests();
    assert_eq!(manifests.len(), 2);
    assert_eq!(manifests[0].body, manifests[1].body);
    assert_eq!(digest_bytes(&manifests[0].body), pushed_digest);
    assert_eq!(
        manifests
            .iter()
            .map(|manifest| manifest.reference.as_str())
            .collect::<Vec<_>>(),
        ["1.0", "latest"]
    );
    assert!(
        manifests
            .iter()
            .all(|manifest| manifest.content_type == "application/vnd.oci.image.manifest.v1+json")
    );
    let manifest: serde_json::Value = serde_json::from_slice(&manifests[0].body).expect("manifest");
    assert_eq!(
        manifest["annotations"]["org.opencontainers.image.description"],
        "pushed"
    );
    assert_eq!(manifest["layers"][0]["digest"], payload_digest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_then_push_uploads_from_cache_without_paths() {
    let package = tempfile::tempdir().expect("package");
    std::fs::write(package.path().join("payload.txt"), b"payload").expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v1
config:
  default_version: "1.0"
files:
  - payload.txt
"#,
    )
    .expect("recipe");
    let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
    let cache_dir = tempfile::tempdir().expect("cache");
    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                push_server.registry(): {"username": "token", "token": "push-token"}
            }
        })
        .to_string(),
    )
    .expect("config");
    let reference = format!("{}/acme/built:1.0", push_server.registry());

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "build",
            package.path().to_str().expect("package"),
            "-t",
            &reference,
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run build");
    assert_success(&output);

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["push", &reference])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run push");
    assert_success(&output);
    // config + payload + recipe artifact.yaml + empty config.
    assert_eq!(push_server.uploaded_blobs().len(), 4);
    let manifests = push_server.manifests();
    // app manifest (by digest + tag 1.0) + recipe referrer + referrers fallback tag.
    assert_eq!(manifests.len(), 4);
    assert!(manifests.iter().any(|manifest| manifest.reference == "1.0"));
    // The mock omits OCI-Subject, so the recipe is registered via the fallback tag.
    assert!(
        manifests
            .iter()
            .any(|manifest| manifest.reference.starts_with("sha256-")),
        "referrers fallback tag was pushed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_defaults_to_whole_blob_and_pull_materializes() {
    // Spec 146 rev 2.2: client chunking is gone. `orc push` emits one whole-blob
    // layer per file (registry-side CDC deduplicates); the manifest records `chunker: none`.
    let package = tempfile::tempdir().expect("package dir");
    let config = br#"{"params":{"type":"object","properties":{}}}"#;
    let payload = vec![7u8; 4096];
    std::fs::write(package.path().join("app.config.v1.json"), config).expect("config");
    std::fs::write(package.path().join("payload.bin"), &payload).expect("payload");

    let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
    let config_dir = tempfile::tempdir().expect("config dir");
    let mut credentials = serde_json::Map::new();
    credentials.insert(
        push_server.registry(),
        json!({"username": "token", "token": "push-token"}),
    );
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({ "credentials": credentials }).to_string(),
    )
    .expect("config");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .current_dir(package.path())
        .args([
            "push",
            &format!("{}/acme/whole:1.0", push_server.registry()),
            "app.config.v1.json",
            "payload.bin",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run push");
    assert_success(&output);

    let manifests = push_server.manifests();
    assert_eq!(manifests.len(), 1);
    let manifest: serde_json::Value = serde_json::from_slice(&manifests[0].body).expect("manifest");
    assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "none");
    let layers = manifest["layers"].as_array().expect("layers");
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0]["digest"], digest_bytes(&payload));

    let mut routes = BTreeMap::from([(
        "/v2/acme/whole/manifests/1.0".to_owned(),
        MockBytes::new(
            manifests[0].body.clone(),
            "application/vnd.oci.image.manifest.v1+json",
        ),
    )]);
    for (digest, body) in push_server.uploaded_blobs() {
        routes.insert(
            format!("/v2/acme/whole/blobs/{digest}"),
            MockBytes::new(body, "application/octet-stream"),
        );
    }
    let pull_server = PullMockServer::start(routes).await;
    let dest = tempfile::tempdir().expect("dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", pull_server.registry()),
            "pull",
            "whole:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert_success(&output);
    assert_eq!(
        std::fs::read(dest.path().join("payload.bin")).expect("payload"),
        payload
    );
}

/// A deterministic, highly compressible payload above the 8 MiB chunk floor.
fn chunkable_payload() -> Vec<u8> {
    let mut out = String::with_capacity(10 * 1024 * 1024 + 128);
    let mut i = 0u64;
    while out.len() < 10 * 1024 * 1024 {
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "record {i:012} | alpha beta gamma delta epsilon zeta eta theta"
        );
        i += 1;
    }
    out.into_bytes()
}

fn push_config_dir(registry: &str) -> tempfile::TempDir {
    let config_dir = tempfile::tempdir().expect("config dir");
    let mut credentials = serde_json::Map::new();
    credentials.insert(
        registry.to_owned(),
        json!({"username": "token", "token": "push-token"}),
    );
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({ "credentials": credentials }).to_string(),
    )
    .expect("config");
    config_dir
}

/// `orc push --format chunked-zstd` of a large file to a non-`_orc` mock: the packager emits
/// the chunked-zstd layer, the negotiated upload falls back to a monolithic PUT of the same
/// stream (operator override), and `orc pull` decodes it back byte-exact through the 146
/// reader. Also `--no-compress` stores raw frames (the layer blob stays ~raw-sized).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_format_chunked_zstd_round_trips_and_no_compress_stays_raw() {
    for no_compress in [false, true] {
        let package = tempfile::tempdir().expect("package dir");
        let config = br#"{"params":{"type":"object","properties":{}}}"#;
        let payload = chunkable_payload();
        std::fs::write(package.path().join("app.config.v1.json"), config).expect("config");
        std::fs::write(package.path().join("payload.bin"), &payload).expect("payload");

        let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
        let config_dir = push_config_dir(&push_server.registry());

        let mut args = vec![
            "push".to_owned(),
            "--format".to_owned(),
            "chunked-zstd".to_owned(),
        ];
        if no_compress {
            args.push("--no-compress".to_owned());
        }
        args.push(format!("{}/acme/chunked:1.0", push_server.registry()));
        args.push("app.config.v1.json".to_owned());
        args.push("payload.bin".to_owned());
        let output = Command::new(env!("CARGO_BIN_EXE_orc"))
            .current_dir(package.path())
            .args(&args)
            .env("ORC_CONFIG_DIR", config_dir.path())
            .output()
            .expect("run push");
        assert_success(&output);

        let manifests = push_server.manifests();
        assert_eq!(manifests.len(), 1);
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifests[0].body).expect("manifest");
        assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "zstd-chunked");
        let layer = &manifest["layers"][0];
        let media_type = layer["mediaType"].as_str().expect("media type");
        assert!(
            media_type.ends_with("+zstd-chunked"),
            "chunked layer media type: {media_type}"
        );
        let annotations = &layer["annotations"];
        assert!(annotations["org.orc8r.chunked.toc-offset"].is_string());
        assert!(annotations["org.orc8r.chunked.toc-digest"].is_string());
        let layer_digest = layer["digest"].as_str().expect("digest").to_owned();
        let blobs = push_server.uploaded_blobs();
        let layer_blob = blobs.get(&layer_digest).expect("layer blob uploaded");
        if no_compress {
            // Raw frames never shrink; the assembled stream stays at least the raw size.
            assert!(
                layer_blob.len() >= payload.len(),
                "--no-compress must not compress: blob {} vs raw {}",
                layer_blob.len(),
                payload.len()
            );
        } else {
            // The compressible payload compresses well end to end.
            assert!(
                layer_blob.len() < payload.len() / 2,
                "compressible payload should shrink: blob {} vs raw {}",
                layer_blob.len(),
                payload.len()
            );
        }

        // Pull it back through the reader (the mock serves the stored monolithic stream).
        let mut routes = BTreeMap::from([(
            "/v2/acme/chunked/manifests/1.0".to_owned(),
            MockBytes::new(
                manifests[0].body.clone(),
                "application/vnd.oci.image.manifest.v1+json",
            ),
        )]);
        for (digest, body) in blobs {
            routes.insert(
                format!("/v2/acme/chunked/blobs/{digest}"),
                MockBytes::new(body, "application/octet-stream"),
            );
        }
        let pull_server = PullMockServer::start(routes).await;
        let dest = tempfile::tempdir().expect("dest");
        let output = Command::new(env!("CARGO_BIN_EXE_orc"))
            .args([
                "--registry",
                &format!("{}/acme", pull_server.registry()),
                "pull",
                "chunked:1.0",
                dest.path().to_str().expect("dest"),
            ])
            .output()
            .expect("run pull");
        assert_success(&output);
        assert_eq!(
            std::fs::read(dest.path().join("payload.bin")).expect("payload"),
            payload,
            "chunked layer round-trips byte-exact (no_compress={no_compress})"
        );
    }
}

/// `orc push --format plain` of a large file forces whole blobs even though chunked is the
/// default: the layer digest equals the raw digest and the media type has no chunked suffix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_format_plain_forces_whole_blob_for_large_files() {
    let package = tempfile::tempdir().expect("package dir");
    let config = br#"{"params":{"type":"object","properties":{}}}"#;
    let payload = chunkable_payload();
    std::fs::write(package.path().join("app.config.v1.json"), config).expect("config");
    std::fs::write(package.path().join("payload.bin"), &payload).expect("payload");

    let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
    let config_dir = push_config_dir(&push_server.registry());

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .current_dir(package.path())
        .args([
            "push",
            "--format",
            "plain",
            &format!("{}/acme/plain:1.0", push_server.registry()),
            "app.config.v1.json",
            "payload.bin",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run push");
    assert_success(&output);

    let manifests = push_server.manifests();
    let manifest: serde_json::Value = serde_json::from_slice(&manifests[0].body).expect("manifest");
    assert_eq!(manifest["annotations"]["vnd.orc8r.chunker"], "none");
    let layer = &manifest["layers"][0];
    assert_eq!(layer["mediaType"], "application/octet-stream");
    assert_eq!(layer["digest"], digest_bytes(&payload));
}

/// A chunked-built artifact pushed to a non-`_orc` registry fails with a rebuild hint
/// (spec 146 §CLI Surface) — the format was fixed at build time and no non-orc consumer
/// could read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_chunked_then_push_to_non_capable_registry_errors() {
    let package = tempfile::tempdir().expect("package");
    std::fs::write(package.path().join("payload.bin"), chunkable_payload()).expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v1
config:
  default_version: "1.0"
files:
  - payload.bin
"#,
    )
    .expect("recipe");
    let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
    let cache_dir = tempfile::tempdir().expect("cache");
    let config_dir = push_config_dir(&push_server.registry());
    let reference = format!("{}/acme/built:1.0", push_server.registry());

    // Build defaults to the chunked-zstd format in the cache.
    let build = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "build",
            package.path().to_str().expect("package"),
            "-t",
            &reference,
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run build");
    assert_success(&build);

    // Pushing the cached chunked artifact to the non-capable mock must fail with the hint.
    let push = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["push", &reference])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run push");
    assert!(
        !push.status.success(),
        "push must fail: {}",
        output_text(&push)
    );
    let text = output_text(&push);
    assert!(
        text.contains("--format plain") && text.contains("chunked"),
        "error must hint at rebuilding with --format plain: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_rejects_removed_chunker_flags() {
    // The legacy `--chunker fastcdc|fixed` flags are deleted; clap refuses them.
    let package = tempfile::tempdir().expect("package dir");
    std::fs::write(package.path().join("app.config.v1.json"), b"{}").expect("config");
    std::fs::write(package.path().join("payload.bin"), b"data").expect("payload");

    for value in ["fastcdc", "fixed"] {
        let output = Command::new(env!("CARGO_BIN_EXE_orc"))
            .current_dir(package.path())
            .args([
                "push",
                "--chunker",
                value,
                "acme/x:1.0",
                "app.config.v1.json",
                "payload.bin",
            ])
            .output()
            .expect("run push");
        assert_eq!(
            output.status.code(),
            Some(2),
            "--chunker {value} must be rejected: {}",
            output_text(&output)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn platform_pushes_accumulate_index_and_pull_selects_platform() {
    let package = tempfile::tempdir().expect("package dir");
    let config = br#"{"params":{"type":"object","properties":{}}}"#;
    std::fs::write(package.path().join("app.config.v1.json"), config).expect("config");
    std::fs::write(package.path().join("payload.txt"), b"amd64").expect("payload");

    let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
    let config_dir = tempfile::tempdir().expect("config dir");
    let mut credentials = serde_json::Map::new();
    credentials.insert(
        push_server.registry(),
        json!({"username": "token", "token": "push-token"}),
    );
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({ "credentials": credentials }).to_string(),
    )
    .expect("config");

    for (platform, body) in [
        ("linux/amd64", b"amd64".as_slice()),
        ("linux/arm64", b"arm64".as_slice()),
    ] {
        std::fs::write(package.path().join("payload.txt"), body).expect("payload");
        let output = Command::new(env!("CARGO_BIN_EXE_orc"))
            .current_dir(package.path())
            .args([
                "--platform",
                platform,
                "push",
                "--chunker",
                "none",
                &format!("{}/acme/multi:1.0", push_server.registry()),
                "app.config.v1.json",
                "payload.txt",
            ])
            .env("ORC_CONFIG_DIR", config_dir.path())
            .output()
            .expect("run push");
        assert_success(&output);
    }

    let manifests = push_server.manifests();
    let index = manifests
        .iter()
        .rev()
        .find(|manifest| manifest.reference == "1.0")
        .expect("index");
    let index_json: serde_json::Value = serde_json::from_slice(&index.body).expect("index json");
    assert_eq!(
        index_json["mediaType"],
        "application/vnd.oci.image.index.v1+json"
    );
    let platforms = index_json["manifests"]
        .as_array()
        .expect("manifests")
        .iter()
        .map(|manifest| {
            format!(
                "{}/{}",
                manifest["platform"]["os"].as_str().expect("os"),
                manifest["platform"]["architecture"]
                    .as_str()
                    .expect("architecture")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(platforms, ["linux/amd64", "linux/arm64"]);

    let mut routes = BTreeMap::from([(
        "/v2/acme/multi/manifests/1.0".to_owned(),
        MockBytes::new(index.body.clone(), index.content_type.clone()),
    )]);
    for manifest in &manifests {
        if manifest.reference.starts_with("sha256:") {
            routes.insert(
                format!("/v2/acme/multi/manifests/{}", manifest.reference),
                MockBytes::new(manifest.body.clone(), manifest.content_type.clone()),
            );
        }
    }
    for (digest, body) in push_server.uploaded_blobs() {
        routes.insert(
            format!("/v2/acme/multi/blobs/{digest}"),
            MockBytes::new(body, "application/octet-stream"),
        );
    }
    let pull_server = PullMockServer::start(routes).await;
    let dest = tempfile::tempdir().expect("dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--platform",
            "linux/arm64",
            "--registry",
            &format!("{}/acme", pull_server.registry()),
            "pull",
            "multi:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert_success(&output);
    assert_stderr_contains(&output, "Pulled 2 files to");
    assert_eq!(
        std::fs::read(dest.path().join("payload.txt")).expect("payload"),
        b"arm64"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_materializes_unchunked_manifest_and_refuses_conflicts() {
    let config = br#"{"default_version":"1.0"}"#.to_vec();
    let payload = b"#!/bin/sh\necho hi\n".to_vec();
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.orc8r.app.v1",
        "config": {
            "mediaType": "application/vnd.orc8r.app.config.v1+json",
            "digest": config_digest,
            "size": config.len()
        },
        "layers": [{
            "mediaType": "text/x-shellscript",
            "digest": payload_digest,
            "size": payload.len(),
            "annotations": {
                "org.opencontainers.image.title": "bin/run.sh",
                "vnd.orc8r.file.executable": "true"
            }
        }],
        "annotations": {
            "org.opencontainers.image.description": "pulled",
            "vnd.orc8r.chunker": "none"
        }
    }))
    .expect("manifest");
    let manifest_digest = digest_bytes(&manifest);
    let server = PullMockServer::start(BTreeMap::from([
        (
            "/v2/acme/demo/manifests/1.0".to_owned(),
            MockBytes::new(manifest, "application/vnd.oci.image.manifest.v1+json"),
        ),
        (
            format!("/v2/acme/demo/blobs/{config_digest}"),
            MockBytes::new(config.clone(), "application/json"),
        ),
        (
            format!("/v2/acme/demo/blobs/{payload_digest}"),
            MockBytes::new(payload.clone(), "text/x-shellscript"),
        ),
    ]))
    .await;
    let dest = tempfile::tempdir().expect("dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("{}/acme/demo:1.0@{manifest_digest}", server.registry())
    );
    assert_eq!(
        std::fs::read(dest.path().join("app.config.v1.json")).expect("config"),
        config
    );
    assert_eq!(
        std::fs::read(dest.path().join("bin/run.sh")).expect("payload"),
        payload
    );
    let annotations: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dest.path().join("annotations.json")).expect("annotations"),
    )
    .expect("annotations json");
    assert_eq!(
        annotations["org.opencontainers.image.description"],
        "pulled"
    );
    assert!(annotations.get("vnd.orc8r.chunker").is_none());
    assert_executable(dest.path().join("bin/run.sh"));

    std::fs::write(dest.path().join("unrelated.txt"), b"keep").expect("unrelated");
    let conflict = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert_eq!(
        conflict.status.code(),
        Some(5),
        "{}",
        output_text(&conflict)
    );
    assert_eq!(
        std::fs::read(dest.path().join("unrelated.txt")).expect("unrelated"),
        b"keep"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_without_dir_caches_blobs_and_does_not_materialize_files() {
    let config = b"{}".to_vec();
    let payload = b"payload".to_vec();
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let manifest = single_file_app_manifest(
        &config_digest,
        config.len(),
        "payload.txt",
        &payload_digest,
        payload.len(),
        "text/plain",
    );
    let manifest_digest = digest_bytes(&manifest);
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config.clone(),
        "payload.txt",
        payload.clone(),
        "text/plain",
    ))
    .await;
    let cache_dir = tempfile::tempdir().expect("cache");
    let cwd = tempfile::tempdir().expect("cwd");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .current_dir(cwd.path())
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run pull");
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("{}/acme/demo:1.0@{manifest_digest}", server.registry())
    );
    assert!(!cwd.path().join("payload.txt").exists());
    assert_cached_blob(cache_dir.path(), &config_digest, &config);
    assert_cached_blob(cache_dir.path(), &payload_digest, &payload);
    assert_eq!(count_files(cache_dir.path().join("manifests/sha256")), 1);
    assert_eq!(count_files(cache_dir.path().join("refs")), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_reuses_cached_config_and_payload_blobs() {
    let config = b"{}".to_vec();
    let payload = b"payload".to_vec();
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let manifest = single_file_app_manifest(
        &config_digest,
        config.len(),
        "payload.txt",
        &payload_digest,
        payload.len(),
        "text/plain",
    );
    let cold_server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config.clone(),
        "payload.txt",
        payload.clone(),
        "text/plain",
    ))
    .await;
    let warm_server = PullMockServer::start(BTreeMap::from([(
        "/v2/acme/demo/manifests/1.0".to_owned(),
        MockBytes::new(manifest, "application/vnd.oci.image.manifest.v1+json"),
    )]))
    .await;
    let cache_dir = tempfile::tempdir().expect("cache");
    let cold_dest = tempfile::tempdir().expect("cold dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", cold_server.registry()),
            "pull",
            "demo:1.0",
            cold_dest.path().to_str().expect("dest"),
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run cold pull");
    assert_success(&output);
    assert_cached_blob(cache_dir.path(), &config_digest, &config);
    assert_cached_blob(cache_dir.path(), &payload_digest, &payload);

    let warm_dest = tempfile::tempdir().expect("warm dest");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", warm_server.registry()),
            "pull",
            "demo:1.0",
            warm_dest.path().to_str().expect("dest"),
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run warm pull");
    assert_success(&output);
    assert_file_bytes(warm_dest.path().join("app.config.v1.json"), &config);
    assert_file_bytes(warm_dest.path().join("payload.txt"), &payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_rejects_app_artifact_with_non_app_config_media_type() {
    let config = b"{}".to_vec();
    let payload = b"payload".to_vec();
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.orc8r.app.v1",
        "config": {
            "mediaType": "application/vnd.orc8r.kvm.image.config.v1+json",
            "digest": config_digest,
            "size": config.len()
        },
        "layers": [{
            "mediaType": "text/plain",
            "digest": payload_digest,
            "size": payload.len(),
            "annotations": {"org.opencontainers.image.title": "payload.txt"}
        }]
    }))
    .expect("manifest");
    let server = PullMockServer::start(BTreeMap::from([
        (
            "/v2/acme/demo/manifests/1.0".to_owned(),
            MockBytes::new(manifest, "application/vnd.oci.image.manifest.v1+json"),
        ),
        (
            format!("/v2/acme/demo/blobs/{config_digest}"),
            MockBytes::new(config, "application/json"),
        ),
        (
            format!("/v2/acme/demo/blobs/{payload_digest}"),
            MockBytes::new(payload, "text/plain"),
        ),
    ]))
    .await;
    let dest = tempfile::tempdir().expect("dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert_eq!(output.status.code(), Some(4), "{}", output_text(&output));
    assert_stderr_contains(&output, "is not an ORC app artifact");
    assert!(!dest.path().join("payload.txt").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_materializes_and_records_parametrized_app() {
    let config = br#"{
        "params": {
            "required": ["url"],
            "properties": {
                "url": {"type": "string"},
                "debug": {"type": "boolean"}
            }
        },
        "install": {"command": "printf \"$URL $DEBUG $APP_VERSION\n\" >> hook.txt"},
        "start": {"service": "demo-service"}
    }"#
    .to_vec();
    let payload = b"payload".to_vec();
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config,
        "payload.txt",
        payload.clone(),
        "text/plain",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let config_dir = tempfile::tempdir().expect("config");

    let output = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", server.registry()),
            "install",
            "demo:1.0",
            "--url",
            "https://example.com",
            "--debug",
        ],
    );
    assert_success(&output);
    assert_stderr_contains(
        &output,
        &format!("Resolved reference: {}/acme/demo:1.0", server.registry()),
    );
    assert_file_bytes(state_dir.path().join("apps/demo/1.0/payload.txt"), &payload);
    assert_file_text(
        state_dir.path().join("apps/demo/1.0/hook.txt"),
        "https://example.com true 1.0\n",
    );

    let status = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &["status", "demo", "--format", "json"],
    );
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows.as_array().expect("rows").len(), 1);
    assert_eq!(rows[0]["mode"], "service");
    assert_eq!(rows[0]["state"], "stopped");
    // The record names the service the way the platform does, not the way the package
    // declared it: what is in that column is what an operator types at their manager.
    assert_eq!(
        rows[0]["pid_service"],
        orc_cli::service::platform_name("demo-service")
    );
    assert_eq!(rows[0]["params"]["url"], "https://example.com");
    assert_eq!(rows[0]["params"]["debug"], "true");
    assert_blob_digests(&rows[0], &[&config_digest, &payload_digest]);
    assert_install_reruns_without_gating(
        state_dir.path(),
        config_dir.path(),
        &format!("{}/acme", server.registry()),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_runs_script_before_recording_app() {
    // No configured command: the packaged script is what the phase falls back to.
    let config = br#"{
        "install": {"timeout": "5s"}
    }"#
    .to_vec();
    let script = b"printf script > hook.txt\n".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "2.0",
        config,
        "install-demo.sh",
        script,
        "text/x-shellscript",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let config_dir = tempfile::tempdir().expect("config");

    let output = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", server.registry()),
            "install",
            "demo:2.0",
        ],
    );
    assert_success(&output);
    assert_file_text(state_dir.path().join("apps/demo/2.0/hook.txt"), "script");

    let status = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &["status", "demo", "--format", "json"],
    );
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["version"], "2.0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uninstall_runs_hook_and_removes_installed_state_but_keeps_cache() {
    // No configured command: the packaged script is what the phase falls back to.
    let config = br#"{
        "uninstall": {"timeout": "5s"}
    }"#
    .to_vec();
    let script = b"printf \"script $APP_VERSION\" > ../uninstall.txt\n".to_vec();
    let config_digest = digest_bytes(&config);
    let script_digest = digest_bytes(&script);
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "3.0",
        config.clone(),
        "uninstall-demo.sh",
        script.clone(),
        "text/x-shellscript",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let cache_dir = tempfile::tempdir().expect("cache");
    let config_dir = tempfile::tempdir().expect("config");

    let install = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "install",
            "demo:3.0",
        ])
        .env("ORC_STATE_DIR", state_dir.path())
        .env("ORC_CACHE_DIR", cache_dir.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run install");
    assert_success(&install);
    assert_file_bytes(
        state_dir.path().join("apps/demo/3.0/uninstall-demo.sh"),
        &script,
    );

    let uninstall = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["uninstall", "demo:3.0"])
        .env("ORC_STATE_DIR", state_dir.path())
        .env("ORC_CACHE_DIR", cache_dir.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run uninstall");
    assert_success(&uninstall);
    assert_file_text(
        state_dir.path().join("apps/demo/uninstall.txt"),
        "script 3.0",
    );
    assert!(!state_dir.path().join("apps/demo/3.0").exists());

    let status = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &["status", "demo", "--format", "json"],
    );
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows.as_array().expect("rows").len(), 0);
    assert_cached_blob(cache_dir.path(), &config_digest, &config);
    assert_cached_blob(cache_dir.path(), &script_digest, &script);

    let absent = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["uninstall", "demo:3.0"])
        .env("ORC_STATE_DIR", state_dir.path())
        .env("ORC_CACHE_DIR", cache_dir.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run absent uninstall");
    assert_success(&absent);
    assert_stderr_contains(&absent, "demo:3.0 is not installed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_runs_installed_command_mode_app_foreground_and_records_completion() {
    let config = br#"{
        "params": {
            "required": ["url"],
            "properties": {
                "url": {"type": "string"}
            }
        },
        "start": {"command": "printf \"out:$URL:$APP_VERSION\\n\"; printf \"$URL $APP_VERSION\" > started.txt"}
    }"#
    .to_vec();
    let payload = b"payload".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "4.0",
        config,
        "payload.txt",
        payload,
        "text/plain",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let config_dir = tempfile::tempdir().expect("config");

    let install = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", server.registry()),
            "install",
            "demo:4.0",
            "--url",
            "https://example.com",
        ],
    );
    assert_success(&install);

    let start = run_orc_with_state(state_dir.path(), config_dir.path(), &["start", "demo:4.0"]);
    assert_success(&start);
    assert_eq!(
        String::from_utf8_lossy(&start.stdout),
        "out:https://example.com:4.0\n"
    );
    assert_file_text(
        state_dir.path().join("apps/demo/4.0/started.txt"),
        "https://example.com 4.0",
    );

    let status = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &["status", "demo", "--format", "json"],
    );
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["mode"], "process");
    assert_eq!(rows[0]["state"], "completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_materializes_inline_content_param_as_file() {
    // A content-typed param (contentMediaType) passed an INLINE value must be written to a
    // temp file and exposed as <NAME>_FILE (regression: it used to be silently dropped, so
    // `sh "${CMD_FILE}"` ran `sh ""`).
    let config = br#"{
        "params": {
            "required": ["cmd"],
            "properties": {
                "cmd": {"type": "string", "contentMediaType": "text/x-sh"}
            }
        },
        "start": {"command": "sh \"${CMD_FILE}\" > out.txt"}
    }"#
    .to_vec();
    let payload = b"payload".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "6.0",
        config,
        "payload.txt",
        payload,
        "text/plain",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let config_dir = tempfile::tempdir().expect("config");

    let start = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", server.registry()),
            "start",
            "demo:6.0",
            "--cmd",
            "echo hi",
        ],
    );
    assert_success(&start);
    assert_file_text(state_dir.path().join("apps/demo/6.0/out.txt"), "hi\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_cold_installs_with_params_then_runs_command_mode_app() {
    let config = br#"{
        "params": {
            "required": ["url"],
            "properties": {
                "url": {"type": "string"}
            }
        },
        "install": {"command": "printf \"installed:$URL:$APP_VERSION\" > installed.txt"},
        "start": {"command": "printf \"started:$URL:$APP_VERSION\\n\"; printf \"$URL $APP_VERSION\" > started.txt"}
    }"#
    .to_vec();
    let payload = b"payload".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "5.0",
        config,
        "payload.txt",
        payload,
        "text/plain",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let config_dir = tempfile::tempdir().expect("config");

    let start = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", server.registry()),
            "start",
            "demo:5.0",
            "--url",
            "https://example.com",
        ],
    );
    assert_success(&start);
    assert_eq!(
        String::from_utf8_lossy(&start.stdout),
        "started:https://example.com:5.0\n"
    );
    assert_file_text(
        state_dir.path().join("apps/demo/5.0/installed.txt"),
        "installed:https://example.com:5.0",
    );
    assert_file_text(
        state_dir.path().join("apps/demo/5.0/started.txt"),
        "https://example.com 5.0",
    );

    let status = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &["status", "demo", "--format", "json"],
    );
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["state"], "completed");
    assert_eq!(rows[0]["params"]["url"], "https://example.com");

    let stop = run_orc_with_state(state_dir.path(), config_dir.path(), &["stop", "demo:5.0"]);
    assert_success(&stop);
    assert_stderr_contains(&stop, "demo:5.0 is not running");

    let uninstall = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &["uninstall", "demo:5.0"],
    );
    assert_success(&uninstall);
    assert!(!state_dir.path().join("apps/demo/5.0").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_reinstalls_without_conflict_on_different_digest() {
    let config = b"{}".to_vec();
    let first_payload = b"first".to_vec();
    let second_payload = b"second".to_vec();
    let first_server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config.clone(),
        "payload.txt",
        first_payload.clone(),
        "text/plain",
    ))
    .await;
    let second_server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config,
        "payload.txt",
        second_payload.clone(),
        "text/plain",
    ))
    .await;
    let state_dir = tempfile::tempdir().expect("state");
    let config_dir = tempfile::tempdir().expect("config");

    let output = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", first_server.registry()),
            "install",
            "demo:1.0",
        ],
    );
    assert_success(&output);
    assert_file_bytes(
        state_dir.path().join("apps/demo/1.0/payload.txt"),
        &first_payload,
    );

    // No gating: re-installing a different package without --force now succeeds (the app
    // decides idempotency). --force is what actually re-materializes the changed payload.
    let reinstall = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", second_server.registry()),
            "install",
            "demo:1.0",
        ],
    );
    assert_success(&reinstall);

    let output = run_orc_with_state(
        state_dir.path(),
        config_dir.path(),
        &[
            "--registry",
            &format!("{}/acme", second_server.registry()),
            "install",
            "--force",
            "demo:1.0",
        ],
    );
    assert_success(&output);
    assert_file_bytes(
        state_dir.path().join("apps/demo/1.0/payload.txt"),
        &second_payload,
    );
}

/// Builds a spec-146 single-blob chunked-zstd layer from `(raw, compressed?)`
/// chunks and returns its blob plus the descriptor annotations.
fn build_chunked_blob(chunks: &[(&[u8], bool)]) -> (Vec<u8>, serde_json::Value) {
    use orc_app::chunked::{
        CHUNKED_TOC_DIGEST_ANNOTATION, CHUNKED_TOC_OFFSET_ANNOTATION, CHUNKED_VERSION_ANNOTATION,
        ChunkEntry, ChunkerParams, FORMAT_VERSION, Toc, compressed_frame,
        encode_skippable_toc_frame, frame_cid, raw_frame,
    };
    let mut blob = Vec::new();
    let mut entries = Vec::new();
    for (raw, compressed) in chunks {
        let frame = if *compressed {
            compressed_frame(raw, 3).expect("compress")
        } else {
            raw_frame(raw)
        };
        entries.push(ChunkEntry {
            frame_cid: frame_cid(&frame),
            frame_offset: blob.len() as u64,
            frame_length: frame.len() as u64,
            raw_length: u32::try_from(raw.len()).expect("raw len"),
            compressed: *compressed,
            raw_sha256: None,
        });
        blob.extend_from_slice(&frame);
    }
    let toc_offset = blob.len() as u64;
    let toc = Toc {
        format_version: FORMAT_VERSION,
        chunker: ChunkerParams {
            min: 1 << 20,
            avg: 4 << 20,
            max: 12 << 20,
        },
        chunks: entries,
    };
    let toc_bytes = toc.encode().expect("encode toc");
    let toc_digest = digest_bytes(&toc_bytes);
    blob.extend_from_slice(&encode_skippable_toc_frame(&toc_bytes));
    let annotations = json!({
        "org.opencontainers.image.title": "data.txt",
        CHUNKED_TOC_OFFSET_ANNOTATION: toc_offset.to_string(),
        CHUNKED_TOC_DIGEST_ANNOTATION: toc_digest,
        CHUNKED_VERSION_ANNOTATION: FORMAT_VERSION.to_string(),
    });
    (blob, annotations)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_decodes_single_blob_chunked_zstd_layer() {
    // A framed compressed + raw + skippable-TOC blob (spec 146) pulls through the
    // new multi-frame streaming reader and materializes the decompressed payload.
    let config = br#"{"default_version":"2.0"}"#.to_vec();
    let first = vec![0xABu8; 5000]; // compressible → compressed frame
    let second = b"raw literal tail bytes".to_vec(); // stored raw
    let (blob, annotations) = build_chunked_blob(&[(&first, true), (&second, false)]);
    let config_digest = digest_bytes(&config);
    let blob_digest = digest_bytes(&blob);

    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.orc8r.app.v1",
        "config": {
            "mediaType": "application/vnd.orc8r.app.config.v1+json",
            "digest": config_digest,
            "size": config.len()
        },
        "layers": [{
            "mediaType": "application/octet-stream+zstd-chunked",
            "digest": blob_digest,
            "size": blob.len(),
            "annotations": annotations
        }],
        "annotations": {"vnd.orc8r.chunker": "none"}
    }))
    .expect("manifest");
    let server = PullMockServer::start(BTreeMap::from([
        (
            "/v2/acme/chunked/manifests/2.0".to_owned(),
            MockBytes::new(manifest, "application/vnd.oci.image.manifest.v1+json"),
        ),
        (
            format!("/v2/acme/chunked/blobs/{config_digest}"),
            MockBytes::new(config, "application/json"),
        ),
        (
            format!("/v2/acme/chunked/blobs/{blob_digest}"),
            MockBytes::new(blob, "application/octet-stream"),
        ),
    ]))
    .await;
    let dest = tempfile::tempdir().expect("dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "chunked:2.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert_success(&output);
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(
        std::fs::read(dest.path().join("data.txt")).expect("payload"),
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_fails_loudly_on_unknown_orc_payload_media_type() {
    // The deleted legacy `chunk.v1+zstd` media type (any unhandled orc8r payload
    // encoding) must fail loudly — never install undecoded bytes.
    let config = b"{}".to_vec();
    let payload = b"undecodable".to_vec();
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.orc8r.app.v1",
        "config": {
            "mediaType": "application/vnd.orc8r.app.config.v1+json",
            "digest": config_digest,
            "size": config.len()
        },
        "layers": [{
            "mediaType": "application/vnd.orc8r.chunk.v1+zstd",
            "digest": payload_digest,
            "size": payload.len(),
            "annotations": {"org.opencontainers.image.title": "data.txt"}
        }]
    }))
    .expect("manifest");
    let server = PullMockServer::start(BTreeMap::from([
        (
            "/v2/acme/legacy/manifests/1.0".to_owned(),
            MockBytes::new(manifest, "application/vnd.oci.image.manifest.v1+json"),
        ),
        (
            format!("/v2/acme/legacy/blobs/{config_digest}"),
            MockBytes::new(config, "application/json"),
        ),
        (
            format!("/v2/acme/legacy/blobs/{payload_digest}"),
            MockBytes::new(payload, "application/octet-stream"),
        ),
    ]))
    .await;
    let dest = tempfile::tempdir().expect("dest");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "legacy:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .output()
        .expect("run pull");
    assert!(!output.status.success(), "{}", output_text(&output));
    assert_stderr_contains(&output, "unsupported media type");
    assert!(!dest.path().join("data.txt").exists());
}

struct PushMockServer {
    addr: SocketAddr,
    state: PushMockShared,
}

impl PushMockServer {
    async fn start(token: &str, existing_blobs: BTreeSet<String>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("addr");
        let state = PushMockShared {
            token: token.to_owned(),
            addr,
            existing_blobs: Arc::new(existing_blobs),
            uploaded_blobs: Arc::new(Mutex::new(BTreeMap::new())),
            manifests: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .fallback(any(push_mock_handler))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock");
        });
        Self { addr, state }
    }

    fn registry(&self) -> String {
        self.addr.to_string()
    }

    fn uploaded_blobs(&self) -> BTreeMap<String, Vec<u8>> {
        self.state.uploaded_blobs.lock().expect("uploads").clone()
    }

    fn manifests(&self) -> Vec<PushedManifest> {
        self.state.manifests.lock().expect("manifests").clone()
    }
}

struct PullMockServer {
    addr: SocketAddr,
}

impl PullMockServer {
    async fn start(routes: BTreeMap<String, MockBytes>) -> Self {
        let routes = Arc::new(routes);
        let app = Router::new()
            .fallback(any(pull_mock_handler))
            .with_state(routes);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock");
        });
        Self { addr }
    }

    fn registry(&self) -> String {
        self.addr.to_string()
    }
}

#[derive(Clone)]
struct MockBytes {
    body: Vec<u8>,
    content_type: String,
}

impl MockBytes {
    fn new(body: Vec<u8>, content_type: impl Into<String>) -> Self {
        Self {
            body,
            content_type: content_type.into(),
        }
    }
}

fn single_file_app_routes(
    repository: &str,
    version: &str,
    config: Vec<u8>,
    payload_title: &str,
    payload: Vec<u8>,
    payload_media_type: &str,
) -> BTreeMap<String, MockBytes> {
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(&payload);
    let manifest = single_file_app_manifest(
        &config_digest,
        config.len(),
        payload_title,
        &payload_digest,
        payload.len(),
        payload_media_type,
    );
    BTreeMap::from([
        (
            format!("/v2/{repository}/manifests/{version}"),
            MockBytes::new(manifest, "application/vnd.oci.image.manifest.v1+json"),
        ),
        (
            format!("/v2/{repository}/blobs/{config_digest}"),
            MockBytes::new(config, "application/json"),
        ),
        (
            format!("/v2/{repository}/blobs/{payload_digest}"),
            MockBytes::new(payload, payload_media_type),
        ),
    ])
}

fn single_file_app_manifest(
    config_digest: &str,
    config_size: usize,
    payload_title: &str,
    payload_digest: &str,
    payload_size: usize,
    payload_media_type: &str,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.orc8r.app.v1",
        "config": {
            "mediaType": "application/vnd.orc8r.app.config.v1+json",
            "digest": config_digest,
            "size": config_size
        },
        "layers": [{
            "mediaType": payload_media_type,
            "digest": payload_digest,
            "size": payload_size,
            "annotations": {"org.opencontainers.image.title": payload_title}
        }]
    }))
    .expect("manifest")
}

async fn pull_mock_handler(
    State(routes): State<Arc<BTreeMap<String, MockBytes>>>,
    request: Request,
) -> Response {
    if request.method() != Method::GET {
        return response(StatusCode::METHOD_NOT_ALLOWED, HeaderMap::new(), Vec::new());
    }
    let Some(item) = routes.get(request.uri().path()) else {
        return response(
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            b"not found".to_vec(),
        );
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        item.content_type.parse().expect("content type"),
    );
    response(StatusCode::OK, headers, item.body.clone())
}

#[derive(Clone)]
struct PushMockShared {
    token: String,
    addr: SocketAddr,
    existing_blobs: Arc<BTreeSet<String>>,
    uploaded_blobs: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    manifests: Arc<Mutex<Vec<PushedManifest>>>,
}

#[derive(Clone)]
struct PushedManifest {
    reference: String,
    content_type: String,
    body: Vec<u8>,
}

async fn push_mock_handler(State(state): State<PushMockShared>, request: Request) -> Response {
    if request.uri().path() == "/token" {
        let body = format!(r#"{{"token":"{}","expires_in":300}}"#, state.token);
        return response(StatusCode::OK, HeaderMap::new(), body.into_bytes());
    }
    if !has_bearer(&request, &state.token) {
        let realm = format!("http://{}/token", state.addr);
        let challenge = format!("Bearer realm=\"{realm}\",service=\"push-mock\"");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::WWW_AUTHENTICATE,
            challenge.parse().expect("challenge header"),
        );
        return response(StatusCode::UNAUTHORIZED, headers, Vec::new());
    }
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_owned();

    if method == Method::HEAD
        && let Some((_, digest)) = split_registry_route(&path, "/blobs/")
    {
        let exists = state.existing_blobs.contains(digest)
            || state
                .uploaded_blobs
                .lock()
                .expect("uploads")
                .contains_key(digest);
        return response(
            if exists {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            },
            HeaderMap::new(),
            Vec::new(),
        );
    }

    if method == Method::POST && path.ends_with("/blobs/uploads/") {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::LOCATION,
            format!("{path}session-1").parse().expect("location"),
        );
        return response(StatusCode::ACCEPTED, headers, Vec::new());
    }

    if method == Method::GET
        && let Some((_, reference)) = split_registry_route(&path, "/manifests/")
    {
        return push_mock_manifest_get(&state, reference);
    }

    if method == Method::PUT
        && path.contains("/blobs/uploads/")
        && let Some(digest) = uri.query().and_then(|query| query.strip_prefix("digest="))
    {
        let body = to_bytes(request.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec();
        state
            .uploaded_blobs
            .lock()
            .expect("uploads")
            .insert(digest.to_owned(), body);
        let mut headers = HeaderMap::new();
        headers.insert("Docker-Content-Digest", digest.parse().expect("digest"));
        return response(StatusCode::CREATED, headers, Vec::new());
    }

    if method == Method::PUT
        && let Some((_, reference)) = split_registry_route(&path, "/manifests/")
    {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = to_bytes(request.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec();
        let digest = digest_bytes(&body);
        state
            .manifests
            .lock()
            .expect("manifests")
            .push(PushedManifest {
                reference: reference.to_owned(),
                content_type,
                body,
            });
        let mut headers = HeaderMap::new();
        headers.insert("Docker-Content-Digest", digest.parse().expect("digest"));
        return response(StatusCode::CREATED, headers, Vec::new());
    }

    response(
        StatusCode::NOT_FOUND,
        HeaderMap::new(),
        b"not found".to_vec(),
    )
}

fn push_mock_manifest_get(state: &PushMockShared, reference: &str) -> Response {
    let manifest = state
        .manifests
        .lock()
        .expect("manifests")
        .iter()
        .rev()
        .find(|manifest| manifest.reference == reference)
        .cloned();
    let Some(manifest) = manifest else {
        return response(
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            b"not found".to_vec(),
        );
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        manifest.content_type.parse().expect("content type"),
    );
    response(StatusCode::OK, headers, manifest.body)
}

fn split_registry_route<'a>(path: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let rest = path.strip_prefix("/v2/")?;
    let idx = rest.rfind(marker)?;
    let (repository, suffix) = (&rest[..idx], &rest[idx + marker.len()..]);
    (!repository.is_empty() && !suffix.is_empty()).then_some((repository, suffix))
}

fn has_bearer(request: &Request, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(expected.as_str())
}

fn response(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(unix)]
fn assert_executable(path: impl AsRef<std::path::Path>) {
    use std::os::unix::fs::PermissionsExt as _;
    assert!(
        std::fs::metadata(path.as_ref())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o100
            != 0
    );
}

#[cfg(not(unix))]
fn assert_executable(_path: impl AsRef<std::path::Path>) {}

fn digest_bytes(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status: {:?}\n{}",
        output.status.code(),
        output_text(output)
    );
}

fn run_orc_with_state(
    state_dir: &std::path::Path,
    config_dir: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_STATE_DIR", state_dir)
        .env("ORC_CONFIG_DIR", config_dir)
        .output()
        .expect("run orc")
}

fn assert_install_reruns_without_gating(
    state_dir: &std::path::Path,
    config_dir: &std::path::Path,
    registry: &str,
) {
    // Re-installing with the SAME params succeeds and re-runs the install phase (no
    // idempotency gate); the hook command appends, so the line now appears twice.
    let same = run_orc_with_state(
        state_dir,
        config_dir,
        &[
            "--registry",
            registry,
            "install",
            "demo:1.0",
            "--url",
            "https://example.com",
            "--debug",
        ],
    );
    assert_success(&same);
    let hook = state_dir.join("apps/demo/1.0/hook.txt");
    assert_file_text(
        &hook,
        "https://example.com true 1.0\nhttps://example.com true 1.0\n",
    );

    // Re-installing with DIFFERENT params also succeeds (no "different params" conflict);
    // the install phase runs again with the new value and the record reflects it.
    let changed = run_orc_with_state(
        state_dir,
        config_dir,
        &[
            "--registry",
            registry,
            "install",
            "demo:1.0",
            "--url",
            "https://other.example.com",
            "--debug",
        ],
    );
    assert_success(&changed);
    assert_file_text(
        &hook,
        "https://example.com true 1.0\nhttps://example.com true 1.0\nhttps://other.example.com true 1.0\n",
    );

    let status = run_orc_with_state(
        state_dir,
        config_dir,
        &["status", "demo", "--format", "json"],
    );
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["params"]["url"], "https://other.example.com");
}

fn assert_file_bytes(path: impl AsRef<std::path::Path>, expected: &[u8]) {
    assert_eq!(std::fs::read(path).expect("file bytes"), expected);
}

fn assert_file_text(path: impl AsRef<std::path::Path>, expected: &str) {
    assert_eq!(std::fs::read_to_string(path).expect("file text"), expected);
}

fn assert_cached_blob(cache_dir: &std::path::Path, digest: &str, expected: &[u8]) {
    let hex = digest.strip_prefix("sha256:").expect("sha256 digest");
    assert_file_bytes(cache_dir.join("blobs/sha256").join(hex), expected);
}

fn count_files(path: impl AsRef<std::path::Path>) -> usize {
    let path = path.as_ref();
    if !path.exists() {
        return 0;
    }
    std::fs::read_dir(path)
        .expect("read dir")
        .filter(|entry| {
            entry
                .as_ref()
                .is_ok_and(|entry| entry.metadata().is_ok_and(|metadata| metadata.is_file()))
        })
        .count()
}

fn assert_blob_digests(record: &serde_json::Value, expected: &[&str]) {
    let blob_digests = record["blob_digests"]
        .as_array()
        .expect("blob digests")
        .iter()
        .map(|value| value.as_str().expect("digest"))
        .collect::<Vec<_>>();
    for digest in expected {
        assert!(blob_digests.contains(digest), "missing digest {digest}");
    }
}

fn assert_stderr_contains(output: &std::process::Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected),
        "stderr did not contain {expected:?}: {stderr}"
    );
}

fn output_text(output: &std::process::Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// --- Progress rendering (ORC_PROGRESS) -------------------------------------
//
// Tests run without a stderr terminal, so the renderer takes the plain
// (line-per-phase) path; `ORC_PROGRESS=always` forces it on regardless.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_progress_reports_phases_on_stderr_and_keeps_stdout_clean() {
    let config = br#"{"default_version":"1.0"}"#.to_vec();
    let payload = b"#!/bin/sh\necho hi\n".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config.clone(),
        "bin/run.sh",
        payload,
        "text/x-shellscript",
    ))
    .await;
    let dest = tempfile::tempdir().expect("dest");
    let cache_dir = tempfile::tempdir().expect("cache");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .env("ORC_PROGRESS", "always")
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run pull");
    assert_success(&output);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Downloading"), "stderr: {stderr}");
    assert!(stderr.contains("Done"), "stderr: {stderr}");
    // A cold pull never reports a cache hit.
    assert!(!stderr.contains("Cached"), "stderr: {stderr}");

    // stdout stays script-safe: exactly the digest line, no progress words.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    assert!(stdout.contains("@sha256:"), "stdout: {stdout}");
    assert!(!stdout.contains("Downloading"), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_progress_is_suppressed_by_quiet_even_when_forced() {
    let config = br#"{"default_version":"1.0"}"#.to_vec();
    let payload = b"data".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config,
        "payload.txt",
        payload,
        "text/plain",
    ))
    .await;
    let dest = tempfile::tempdir().expect("dest");
    let cache_dir = tempfile::tempdir().expect("cache");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--quiet",
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            dest.path().to_str().expect("dest"),
        ])
        .env("ORC_PROGRESS", "always")
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run pull");
    assert_success(&output);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Downloading"), "stderr: {stderr}");
    assert!(!stderr.contains("Done"), "stderr: {stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_progress_warm_cache_reports_cached() {
    let config = br#"{"default_version":"1.0"}"#.to_vec();
    let payload = b"reused bytes".to_vec();
    let server = PullMockServer::start(single_file_app_routes(
        "acme/demo",
        "1.0",
        config.clone(),
        "payload.txt",
        payload.clone(),
        "text/plain",
    ))
    .await;
    let cache_dir = tempfile::tempdir().expect("cache");
    let cold = tempfile::tempdir().expect("cold dest");
    let warm = tempfile::tempdir().expect("warm dest");

    // Cold pull populates the shared cache.
    let first = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            cold.path().to_str().expect("dest"),
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run cold pull");
    assert_success(&first);

    // Warm pull materializes the same blobs straight from the cache.
    let second = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "pull",
            "demo:1.0",
            warm.path().to_str().expect("dest"),
        ])
        .env("ORC_PROGRESS", "always")
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run warm pull");
    assert_success(&second);

    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("Cached"), "warm pull stderr: {stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_progress_reports_upload_on_stderr() {
    let package = tempfile::tempdir().expect("package");
    std::fs::write(package.path().join("payload.txt"), b"payload").expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        "\nartifactType: application/vnd.orc8r.app.v1\nconfig:\n  default_version: \"1.0\"\nfiles:\n  - payload.txt\n",
    )
    .expect("recipe");
    let push_server = PushMockServer::start("push-token", BTreeSet::new()).await;
    let cache_dir = tempfile::tempdir().expect("cache");
    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                push_server.registry(): {"username": "token", "token": "push-token"}
            }
        })
        .to_string(),
    )
    .expect("config");
    let reference = format!("{}/acme/built:1.0", push_server.registry());

    let build = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "build",
            package.path().to_str().expect("package"),
            "-t",
            &reference,
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run build");
    assert_success(&build);

    let push = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["push", &reference])
        .env("ORC_PROGRESS", "always")
        .env("ORC_CACHE_DIR", cache_dir.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run push");
    assert_success(&push);

    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(stderr.contains("Uploading"), "push stderr: {stderr}");
    assert!(stderr.contains("Done"), "push stderr: {stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_progress_reports_url_download_on_stderr() {
    let payload = b"downloaded build input".to_vec();
    let server = PullMockServer::start(BTreeMap::from([(
        "/files/data.bin".to_owned(),
        MockBytes::new(payload, "application/octet-stream"),
    )]))
    .await;
    let package = tempfile::tempdir().expect("package");
    let recipe = format!(
        "\nartifactType: application/vnd.orc8r.app.v1\nconfig:\n  default_version: \"1.0\"\nfiles:\n  - path: data.bin\n    url: http://{}/files/data.bin\n",
        server.registry()
    );
    std::fs::write(package.path().join("artifact.yaml"), recipe).expect("recipe");
    let cache_dir = tempfile::tempdir().expect("cache");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "build",
            package.path().to_str().expect("package"),
            "-t",
            "acme/built:1.0",
        ])
        .env("ORC_PROGRESS", "always")
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run build");
    assert_success(&output);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("data.bin"), "build stderr: {stderr}");
    assert!(stderr.contains("Downloading"), "build stderr: {stderr}");
    assert!(stderr.contains("Done"), "build stderr: {stderr}");
}
