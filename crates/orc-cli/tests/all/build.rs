use std::process::{Command, Output};

use serde_json::json;

#[test]
fn build_universal_recipe_writes_cache_ref_and_blobs() {
    let package = tempfile::tempdir().expect("package");
    let cache = tempfile::tempdir().expect("cache");
    std::fs::write(package.path().join("README.md"), "hello\n").expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: demo
config:
  default_version: "1.0"
files:
  - README.md
"#,
    )
    .expect("recipe");

    let output = run_orc(
        &cache,
        &[
            "build",
            package.path().to_str().expect("package"),
            "-t",
            "localhost:5000/acme/demo:1.0",
        ],
    );
    assert_success(&output);
    let digest = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(digest.starts_with("sha256:"), "{digest}");

    assert_eq!(count_files(cache.path().join("refs")), 1);
    // App manifest + recipe referrer manifest.
    assert_eq!(count_files(cache.path().join("manifests/sha256")), 2);
    // config + README + artifact.yaml + empty config.
    assert_eq!(count_files(cache.path().join("blobs/sha256")), 4);

    // The recipe referrer embeds the verbatim artifact.yaml and points at the package.
    let recipe = find_recipe_manifest(cache.path());
    assert_eq!(recipe["subject"]["digest"], digest);
    let layer_digest = recipe["layers"][0]["digest"]
        .as_str()
        .expect("layer digest");
    let recipe_bytes = read_blob(cache.path(), layer_digest);
    let source = std::fs::read(package.path().join("artifact.yaml")).expect("source");
    assert_eq!(
        recipe_bytes, source,
        "recipe blob is byte-identical to artifact.yaml"
    );
}

#[test]
fn build_platform_recipe_filters_and_writes_index() {
    let package = tempfile::tempdir().expect("package");
    let cache = tempfile::tempdir().expect("cache");
    std::fs::write(package.path().join("tool-linux-amd64"), "amd64").expect("amd64");
    std::fs::write(package.path().join("tool-linux-arm64"), "arm64").expect("arm64");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v1
config:
  default_version: "{arch}"
files:
  - path: "tool-{os}-{arch}"
platforms:
  - { os: linux, arch: amd64 }
  - { os: linux, arch: arm64 }
"#,
    )
    .expect("recipe");

    let output = run_orc(
        &cache,
        &[
            "build",
            package.path().to_str().expect("package"),
            "--platform",
            "linux/amd64",
            "-t",
            "localhost:5000/acme/tool:1.0",
        ],
    );
    assert_success(&output);
    let manifests = cache.path().join("manifests/sha256");
    // Platform manifest + image index + recipe referrer manifest.
    assert_eq!(count_files(&manifests), 3);
    let index = std::fs::read_dir(&manifests)
        .expect("manifests")
        .find_map(|entry| {
            let body = std::fs::read(entry.ok()?.path()).ok()?;
            let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
            (value.get("manifests").is_some()).then_some(value)
        })
        .expect("index");
    assert_eq!(index["manifests"].as_array().expect("children").len(), 1);
    assert_eq!(
        index["manifests"][0]["platform"],
        json!({"os": "linux", "architecture": "amd64"})
    );
}

#[test]
fn build_output_writes_oci_layout() {
    let package = tempfile::tempdir().expect("package");
    let cache = tempfile::tempdir().expect("cache");
    let output_dir = tempfile::tempdir().expect("layout");
    std::fs::write(package.path().join("README.md"), "hello").expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r"
artifactType: application/vnd.orc8r.app.v1
config: {}
files:
  - README.md
",
    )
    .expect("recipe");

    let output = run_orc(
        &cache,
        &[
            "build",
            package.path().to_str().expect("package"),
            "-t",
            "localhost:5000/acme/demo:1.0",
            "-o",
            output_dir.path().to_str().expect("layout"),
        ],
    );
    assert_success(&output);
    assert!(output_dir.path().join("oci-layout").exists());
    assert!(output_dir.path().join("index.json").exists());
    assert_eq!(count_files(cache.path().join("refs")), 0);
}

#[test]
fn rebuild_overwrites_stale_cached_ref() {
    let package = tempfile::tempdir().expect("package");
    let cache = tempfile::tempdir().expect("cache");
    let recipe = |ver: &str| {
        format!(
            "artifactType: application/vnd.orc8r.app.v1\nannotations:\n  org.opencontainers.image.title: demo\nconfig:\n  default_version: \"{ver}\"\n"
        )
    };
    let args = [
        "build",
        package.path().to_str().expect("package"),
        "-t",
        "localhost:5000/acme/demo:1.0",
    ];

    std::fs::write(package.path().join("artifact.yaml"), recipe("1.0")).expect("recipe");
    assert_success(&run_orc(&cache, &args));
    let first = read_only_ref(cache.path());
    let first_digest = first["target"]["digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    assert!(
        !first["referrers"].as_array().expect("referrers").is_empty(),
        "recipe referrer recorded on the ref"
    );

    // Rebuild the SAME reference with changed config: the ref must update, not
    // keep the stale target (the write_digest_file skip-if-exists bug).
    std::fs::write(package.path().join("artifact.yaml"), recipe("2.0")).expect("recipe2");
    assert_success(&run_orc(&cache, &args));
    let second = read_only_ref(cache.path());
    assert_ne!(
        second["target"]["digest"].as_str().expect("digest"),
        first_digest,
        "cached ref must update to the rebuilt digest"
    );
    assert!(
        !second["referrers"]
            .as_array()
            .expect("referrers")
            .is_empty()
    );
}

fn run_orc(cache: &tempfile::TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_CACHE_DIR", cache.path())
        .output()
        .expect("run orc")
}

/// Finds the cached recipe referrer manifest (`artifactType vnd.orc8r.recipe.v1`).
fn find_recipe_manifest(cache: &std::path::Path) -> serde_json::Value {
    std::fs::read_dir(cache.join("manifests/sha256"))
        .expect("manifests")
        .find_map(|entry| {
            let body = std::fs::read(entry.ok()?.path()).ok()?;
            let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
            (value.get("artifactType")?.as_str()? == "application/vnd.orc8r.recipe.v1")
                .then_some(value)
        })
        .expect("recipe referrer manifest")
}

/// Reads a cached blob by its `sha256:<hex>` digest.
fn read_blob(cache: &std::path::Path, digest: &str) -> Vec<u8> {
    let hex = digest.strip_prefix("sha256:").expect("sha256 digest");
    std::fs::read(cache.join("blobs/sha256").join(hex)).expect("blob")
}

/// Reads the single cached ref JSON from `refs/`.
fn read_only_ref(cache: &std::path::Path) -> serde_json::Value {
    let file = std::fs::read_dir(cache.join("refs"))
        .expect("refs dir")
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.is_file().then_some(path)
        })
        .expect("one ref file");
    serde_json::from_slice(&std::fs::read(file).expect("ref body")).expect("ref json")
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

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
