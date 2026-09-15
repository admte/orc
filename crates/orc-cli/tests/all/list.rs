use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[test]
fn list_reads_cached_refs_and_filters_locally() {
    let dirs = TestDirs::new();
    let package = tempfile::tempdir().expect("package");
    write_recipe(package.path());
    let build = run_orc(
        &dirs,
        &[
            "build",
            package.path().to_str().expect("package"),
            "-t",
            "platform-info",
        ],
    );
    assert_success(&build);

    let list = run_orc(&dirs, &["list", "--format", "json"]);
    assert_success(&list);
    let rows: serde_json::Value = serde_json::from_slice(&list.stdout).expect("list json");
    assert_eq!(rows.as_array().expect("rows").len(), 1);
    assert_eq!(rows[0]["reference"], "orc8r.com/platform-info:default");
    assert_eq!(rows[0]["registry"], "orc8r.com");
    assert_eq!(rows[0]["repository"], "platform-info");
    assert_eq!(rows[0]["tag"], "default");
    assert_eq!(
        rows[0]["media_type"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert!(
        rows[0]["digest"]
            .as_str()
            .expect("digest")
            .starts_with("sha256:")
    );
    assert!(rows[0]["size"].as_u64().expect("size") > 0);
    assert_eq!(rows[0]["platforms"], serde_json::json!(["any"]));
    assert_eq!(rows[0]["description"], "Tiny local app");
    assert_eq!(rows[0]["error"], serde_json::Value::Null);

    assert_filter_count(&dirs, "platform-info", 1);
    assert_filter_count(&dirs, "default", 1);
    assert_filter_count(&dirs, "orc8r.com", 1);
    assert_filter_count(&dirs, "missing", 0);

    let scoped = run_orc(
        &dirs,
        &["--registry", "orc8r.com", "list", "--format", "json"],
    );
    assert_success(&scoped);
    assert_eq!(json_rows(&scoped).len(), 1);

    let other_registry = run_orc(
        &dirs,
        &[
            "--registry",
            "localhost:5000/acme",
            "list",
            "--format",
            "json",
        ],
    );
    assert_success(&other_registry);
    assert_eq!(json_rows(&other_registry).len(), 0);

    let quiet = run_orc(&dirs, &["list", "-q"]);
    assert_success(&quiet);
    assert_eq!(
        String::from_utf8_lossy(&quiet.stdout),
        "orc8r.com/platform-info:default\n"
    );

    let text = run_orc(&dirs, &["list"]);
    assert_success(&text);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("REFERENCE"), "{stdout}");
    assert!(stdout.contains("PLATFORMS"), "{stdout}");
    assert!(!stdout.contains("DIGEST"), "{stdout}");
    assert!(!stdout.contains("sha256:"), "{stdout}");

    let old_remote_flag = run_orc(&dirs, &["list", "--remote"]);
    assert_eq!(
        old_remote_flag.status.code(),
        Some(2),
        "{}",
        output_text(&old_remote_flag)
    );
}

#[test]
fn list_reports_cached_ref_with_missing_manifest() {
    let dirs = TestDirs::new();
    let package = tempfile::tempdir().expect("package");
    write_recipe(package.path());
    let build = run_orc(
        &dirs,
        &[
            "build",
            package.path().to_str().expect("package"),
            "-t",
            "platform-info",
        ],
    );
    assert_success(&build);
    let digest = String::from_utf8_lossy(&build.stdout).trim().to_owned();
    std::fs::remove_file(cached_manifest_path(dirs.cache.path(), &digest))
        .expect("remove manifest");

    let list = run_orc(&dirs, &["list", "--format", "json"]);
    assert_success(&list);
    let rows = json_rows(&list);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["reference"], "orc8r.com/platform-info:default");
    assert_eq!(rows[0]["platforms"], serde_json::json!([]));
    assert!(
        rows[0]["error"]
            .as_str()
            .expect("error")
            .contains("cached manifest"),
        "{}",
        rows[0]["error"]
    );

    let text = run_orc(&dirs, &["list"]);
    assert_success(&text);
    assert!(
        String::from_utf8_lossy(&text.stdout).contains("ERROR: cached manifest"),
        "{}",
        output_text(&text)
    );
}

struct TestDirs {
    cache: tempfile::TempDir,
    config: tempfile::TempDir,
}

impl TestDirs {
    fn new() -> Self {
        Self {
            cache: tempfile::tempdir().expect("cache dir"),
            config: tempfile::tempdir().expect("config dir"),
        }
    }
}

fn write_recipe(path: &Path) {
    std::fs::write(path.join("README.md"), "hello\n").expect("payload");
    std::fs::write(
        path.join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.description: Tiny local app
config:
  default_version: "1.0"
files:
  - README.md
"#,
    )
    .expect("recipe");
}

fn run_orc(dirs: &TestDirs, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_CACHE_DIR", dirs.cache.path())
        .env("ORC_CONFIG_DIR", dirs.config.path())
        .output()
        .expect("run orc")
}

fn assert_filter_count(dirs: &TestDirs, filter: &str, expected: usize) {
    let output = run_orc(dirs, &["list", filter, "--format", "json"]);
    assert_success(&output);
    assert_eq!(json_rows(&output).len(), expected);
}

fn json_rows(output: &Output) -> Vec<serde_json::Value> {
    serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout).expect("json rows")
}

fn cached_manifest_path(cache: &Path, digest: &str) -> PathBuf {
    let hex = digest
        .strip_prefix("sha256:")
        .expect("sha256 digest prefix");
    cache.join("manifests/sha256").join(hex)
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\n{}",
        output.status.code(),
        output_text(output)
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
