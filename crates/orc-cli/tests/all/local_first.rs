use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest as _, Sha256};

const UNREACHABLE_PREFIX: &str = "127.0.0.1:1/acme";

#[test]
fn install_uses_cached_short_ref_without_registry() {
    let dirs = TestDirs::new();
    let package = tempfile::tempdir().expect("package");
    std::fs::write(package.path().join("README.md"), "cached payload\n").expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        serde_yaml::to_string(&serde_json::json!({
            "artifactType": "application/vnd.orc8r.app.v1",
            "annotations": {"org.opencontainers.image.title": "platform-info"},
            "config": {"install": {"command": install_command()}},
            "files": ["README.md"],
        }))
        .expect("serialize recipe"),
    )
    .expect("recipe");

    let build = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "build",
            package.path().to_str().expect("package"),
            "--tag",
            "platform-info",
        ],
    );
    assert_success(&build);

    let install = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "install", "platform-info"],
    );
    assert_success(&install);
    assert_file_text(
        dirs.state
            .path()
            .join("apps/platform-info/default/README.md"),
        "cached payload\n",
    );
    assert_file_text(
        dirs.state
            .path()
            .join("apps/platform-info/default/installed.txt"),
        "installed",
    );
    assert_stderr_not_contains(&install, "registry token endpoint");
}

#[test]
fn start_cold_installs_from_cached_short_ref_without_registry() {
    let dirs = TestDirs::new();
    let package = tempfile::tempdir().expect("package");
    std::fs::write(package.path().join("README.md"), "cached payload\n").expect("payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        serde_yaml::to_string(&serde_json::json!({
            "artifactType": "application/vnd.orc8r.app.v1",
            "config": {
                "install": {"command": install_command()},
                "start": {"command": start_command()},
            },
            "files": ["README.md"],
        }))
        .expect("serialize recipe"),
    )
    .expect("recipe");

    let build = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "build",
            package.path().to_str().expect("package"),
            "--tag",
            "platform-info",
        ],
    );
    assert_success(&build);

    let start = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "start", "platform-info"],
    );
    assert_success(&start);
    assert_eq!(
        String::from_utf8_lossy(&start.stdout).replace("\r\n", "\n"),
        "started from cache\n"
    );
    assert_file_text(
        dirs.state
            .path()
            .join("apps/platform-info/default/installed.txt"),
        "installed",
    );
    assert_file_text(
        dirs.state
            .path()
            .join("apps/platform-info/default/started.txt"),
        "started",
    );
    assert_stderr_not_contains(&start, "registry token endpoint");
}

#[test]
fn install_cached_index_honors_platform_selection() {
    let dirs = TestDirs::new();
    let package = tempfile::tempdir().expect("package");
    std::fs::write(
        package.path().join("payload-linux-amd64.txt"),
        "linux amd64\n",
    )
    .expect("amd64 payload");
    std::fs::write(
        package.path().join("payload-linux-arm64.txt"),
        "linux arm64\n",
    )
    .expect("arm64 payload");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v1
config:
  default_version: "{os}-{arch}"
files:
  - path: "payload-{os}-{arch}.txt"
platforms:
  - { os: linux, arch: amd64 }
  - { os: linux, arch: arm64 }
"#,
    )
    .expect("recipe");

    let build = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "build",
            package.path().to_str().expect("package"),
            "--tag",
            "platform-info:1.0.0",
        ],
    );
    assert_success(&build);

    let install = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "--platform",
            "linux/amd64",
            "install",
            "platform-info:1.0.0",
        ],
    );
    assert_success(&install);
    let materialized = dirs.state.path().join("apps/platform-info/1.0.0");
    assert_file_text(
        materialized.join("payload-linux-amd64.txt"),
        "linux amd64\n",
    );
    assert!(!materialized.join("payload-linux-arm64.txt").exists());

    let status = run_orc(&dirs, &["status", "platform-info", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["platform"], "linux/amd64");
}

#[test]
fn install_cached_ref_with_missing_blob_fails_without_registry_fallback() {
    let dirs = TestDirs::new();
    let package = tempfile::tempdir().expect("package");
    let payload = b"cached payload\n";
    std::fs::write(package.path().join("README.md"), payload).expect("payload");
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

    let build = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "build",
            package.path().to_str().expect("package"),
            "--tag",
            "platform-info:broken",
        ],
    );
    assert_success(&build);

    let payload_digest = digest_bytes(payload);
    std::fs::remove_file(cached_blob_path(dirs.cache.path(), &payload_digest))
        .expect("remove payload blob");

    let install = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "install",
            "platform-info:broken",
        ],
    );
    assert!(!install.status.success(), "{}", output_text(&install));
    assert_stderr_contains(
        &install,
        &format!("cached blob {payload_digest} is missing"),
    );
    assert_stderr_not_contains(&install, "registry token endpoint");
    assert_stderr_not_contains(&install, "connection refused");
}

struct TestDirs {
    cache: tempfile::TempDir,
    state: tempfile::TempDir,
    config: tempfile::TempDir,
}

impl TestDirs {
    fn new() -> Self {
        Self {
            cache: tempfile::tempdir().expect("cache dir"),
            state: tempfile::tempdir().expect("state dir"),
            config: tempfile::tempdir().expect("config dir"),
        }
    }
}

fn run_orc(dirs: &TestDirs, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_CACHE_DIR", dirs.cache.path())
        .env("ORC_STATE_DIR", dirs.state.path())
        .env("ORC_CONFIG_DIR", dirs.config.path())
        .output()
        .expect("run orc")
}

fn cached_blob_path(cache: &Path, digest: &str) -> PathBuf {
    let hex = digest
        .strip_prefix("sha256:")
        .expect("sha256 digest prefix");
    cache.join("blobs/sha256").join(hex)
}

fn digest_bytes(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\n{}",
        output.status.code(),
        output_text(output)
    );
}

fn assert_file_text(path: impl AsRef<Path>, expected: &str) {
    assert_eq!(std::fs::read_to_string(path).expect("read file"), expected);
}

fn assert_stderr_contains(output: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected), "missing {expected:?}\n{stderr}");
}

fn assert_stderr_not_contains(output: &Output, unexpected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(unexpected),
        "unexpected {unexpected:?}\n{stderr}"
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn install_command() -> &'static str {
    if cfg!(windows) {
        "[IO.File]::WriteAllText((Join-Path $PWD 'installed.txt'), 'installed')"
    } else {
        "printf installed > installed.txt"
    }
}

fn start_command() -> &'static str {
    if cfg!(windows) {
        "Write-Output 'started from cache'; [IO.File]::WriteAllText((Join-Path $PWD 'started.txt'), 'started')"
    } else {
        "printf 'started from cache\\n'; printf started > started.txt"
    }
}
