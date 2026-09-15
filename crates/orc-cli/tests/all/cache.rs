use std::process::{Command, Output};

use serde_json::json;

#[test]
fn cache_ls_and_clean_report_content_addressed_blobs() {
    let cache_dir = tempfile::tempdir().expect("cache dir");
    let blobs = cache_dir.path().join("blobs/sha256");
    std::fs::create_dir_all(&blobs).expect("blob dir");
    std::fs::write(
        blobs.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"abcd",
    )
    .expect("blob a");
    std::fs::write(
        blobs.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        b"ef",
    )
    .expect("blob b");
    std::fs::write(blobs.join("not-a-digest"), b"ignored").expect("ignored");

    let output = run_orc(cache_dir.path(), &["cache", "ls"]);
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("6 B in 2 blobs"), "{stdout}");
    assert!(stdout.contains("0 manifests, 0 refs"), "{stdout}");
    assert!(
        stdout.contains(&cache_dir.path().display().to_string()),
        "{stdout}"
    );

    let output = run_orc(cache_dir.path(), &["cache", "clean"]);
    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "freed 6 B");
    assert!(!blobs.exists());

    let output = run_orc(cache_dir.path(), &["cache", "clean"]);
    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "freed 0 B");
}

#[test]
fn cache_clean_unused_preserves_installed_blob_digests() {
    let cache_dir = tempfile::tempdir().expect("cache dir");
    let state_dir = tempfile::tempdir().expect("state dir");
    let blobs = cache_dir.path().join("blobs/sha256");
    let kept = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let removed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    std::fs::create_dir_all(&blobs).expect("blob dir");
    std::fs::write(blobs.join(kept), b"keep").expect("kept blob");
    std::fs::write(blobs.join(removed), b"rm").expect("removed blob");
    write_install_record(
        state_dir.path(),
        &json!({
            "app": "demo",
            "version": "1.0",
            "reference": "registry/acme/demo:1.0",
            "digest": "sha256:manifest",
            "platform": "any",
            "mode": "process",
            "state": "stopped",
            "blob_digests": [format!("sha256:{kept}")]
        }),
    );

    let output = run_orc_with_state(
        cache_dir.path(),
        state_dir.path(),
        &["cache", "clean", "--unused"],
    );
    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "freed 2 B");
    assert!(blobs.join(kept).exists());
    assert!(!blobs.join(removed).exists());
}

fn run_orc(cache_dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_CACHE_DIR", cache_dir)
        .output()
        .expect("run orc")
}

fn run_orc_with_state(
    cache_dir: &std::path::Path,
    state_dir: &std::path::Path,
    args: &[&str],
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(args)
        .env("ORC_CACHE_DIR", cache_dir)
        .env("ORC_STATE_DIR", state_dir)
        .output()
        .expect("run orc")
}

fn write_install_record(state_dir: &std::path::Path, record: &serde_json::Value) {
    let path = state_dir.join("installs/demo/1.0.json");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("record dir");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&record).expect("record json"),
    )
    .expect("record");
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
