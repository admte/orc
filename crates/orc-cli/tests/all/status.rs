use std::process::{Command, Output};

use serde_json::json;

#[test]
fn status_reports_empty_state() {
    let dirs = TestDirs::new();
    let output = run_orc(&dirs, &["status"]);
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("APP"), "{stdout}");
    assert!(stdout.contains("PID/SERVICE"), "{stdout}");
    assert!(!stdout.contains("runner"), "{stdout}");

    let output = run_orc(&dirs, &["status", "--format", "json"]);
    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status json");
    assert_eq!(rows, json!([]));

    let old_output_flag = run_orc(&dirs, &["status", "-o", "json"]);
    assert_eq!(
        old_output_flag.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&old_output_flag.stdout),
        String::from_utf8_lossy(&old_output_flag.stderr)
    );
}

#[test]
fn status_lists_seeded_records_and_filters_by_app() {
    let dirs = TestDirs::new();
    write_record(
        &dirs,
        "runner",
        "2.321.0",
        &json!({
            "app": "runner",
            "version": "2.321.0",
            "reference": "ghcr.io/acme/runner:2.321.0",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "platform": "linux/amd64",
            "mode": "service",
            "state": "running",
            "pid_service": "github-runner"
        }),
    );
    write_record(
        &dirs,
        "jenkins-agent",
        "3.46",
        &json!({
            "app": "jenkins-agent",
            "version": "3.46",
            "reference": "ghcr.io/acme/jenkins-agent:3.46",
            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "platform": "linux/arm64",
            "mode": "process",
            "state": "stopped"
        }),
    );

    let output = run_orc(&dirs, &["status"]);
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("jenkins-agent"), "{stdout}");
    assert!(stdout.contains("runner"), "{stdout}");
    assert!(stdout.contains("github-runner"), "{stdout}");

    let output = run_orc(&dirs, &["status", "runner", "--format", "json"]);
    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status json");
    assert_eq!(rows.as_array().expect("rows").len(), 1);
    assert_eq!(rows[0]["app"], "runner");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["pid_service"], "github-runner");
}

struct TestDirs {
    state: tempfile::TempDir,
    config: tempfile::TempDir,
}

impl TestDirs {
    fn new() -> Self {
        Self {
            state: tempfile::tempdir().expect("state dir"),
            config: tempfile::tempdir().expect("config dir"),
        }
    }
}

fn write_record(dirs: &TestDirs, app: &str, version: &str, body: &serde_json::Value) {
    let dir = dirs.state.path().join("installs").join(app);
    std::fs::create_dir_all(&dir).expect("install app dir");
    std::fs::write(
        dir.join(format!("{version}.json")),
        serde_json::to_vec_pretty(body).expect("record json"),
    )
    .expect("write record");
}

fn run_orc(dirs: &TestDirs, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_STATE_DIR", dirs.state.path())
        .env("ORC_CONFIG_DIR", dirs.config.path())
        .output()
        .expect("run orc")
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
