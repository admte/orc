use std::io::{Read as _, Write as _};
use std::process::{Command, Output, Stdio};

/// Minimal one-thread registry stub: answers `GET /v2/` with 200 so the login
/// verification ping succeeds without touching the network.
fn spawn_registry_stub() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    let handle = std::thread::spawn(move || {
        // One connection is all the test needs; extra connections just drop.
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}");
        }
    });
    (addr, handle)
}

#[test]
fn login_config_and_logout_manage_credentials_without_echoing_secret() {
    let config_dir = tempfile::tempdir().expect("config dir");
    let (addr, stub) = spawn_registry_stub();
    let registry = addr.to_string();

    let login = run_orc(
        config_dir.path(),
        &[
            "--insecure",
            "login",
            "-u",
            "alice",
            "--password-stdin",
            &registry,
        ],
        Some("topsecret\n"),
    );
    stub.join().expect("stub thread");
    assert_success(&login);
    assert!(!output_text(&login).contains("topsecret"));

    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(config_dir.path().join("config.json")).expect("config body"),
    )
    .expect("config json");
    assert_eq!(config["default_registry"], registry);
    assert_eq!(config["credentials"][&registry]["username"], "alice");
    assert_eq!(config["credentials"][&registry]["token"], "topsecret");

    let get = run_orc(
        config_dir.path(),
        &["config", "get", "default-registry"],
        None,
    );
    assert_success(&get);
    assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), registry);

    let set = run_orc(
        config_dir.path(),
        &["config", "set", "default-registry", "localhost:5000/dev"],
        None,
    );
    assert_success(&set);
    let get = run_orc(
        config_dir.path(),
        &["config", "get", "default-registry"],
        None,
    );
    assert_success(&get);
    assert_eq!(
        String::from_utf8_lossy(&get.stdout).trim(),
        "localhost:5000/dev"
    );

    // The legacy client-chunker config keys are gone (spec 146, rev 2.2): setting
    // one is a usage error.
    let invalid = run_orc(
        config_dir.path(),
        &["config", "set", "chunker.fixed.size", "4KiB"],
        None,
    );
    assert_eq!(invalid.status.code(), Some(2), "{}", output_text(&invalid));

    let logout = run_orc(config_dir.path(), &["logout", &registry], None);
    assert_success(&logout);
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(config_dir.path().join("config.json")).expect("config body"),
    )
    .expect("config json");
    assert!(
        config.get("chunker").is_none(),
        "no chunker config is persisted"
    );
    assert!(
        config["credentials"]
            .as_object()
            .expect("credentials")
            .is_empty()
    );

    let idempotent = run_orc(config_dir.path(), &["logout", &registry], None);
    assert_success(&idempotent);
    assert!(String::from_utf8_lossy(&idempotent.stderr).contains("No credentials stored"));
}

#[test]
fn login_accepts_registry_prefix_and_stores_credentials_by_host() {
    let config_dir = tempfile::tempdir().expect("config dir");
    let (addr, stub) = spawn_registry_stub();
    let registry = addr.to_string();
    let prefix = format!("{registry}/admte");

    let login = run_orc(
        config_dir.path(),
        &[
            "--insecure",
            "login",
            "-u",
            "alice",
            "--password-stdin",
            &prefix,
        ],
        Some("topsecret\n"),
    );
    stub.join().expect("stub thread");
    assert_success(&login);

    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(config_dir.path().join("config.json")).expect("config body"),
    )
    .expect("config json");
    assert_eq!(config["default_registry"], prefix);
    assert_eq!(config["credentials"][&registry]["username"], "alice");
    assert_eq!(config["credentials"][&registry]["token"], "topsecret");
    assert!(config["credentials"][&prefix].is_null());

    let get = run_orc(
        config_dir.path(),
        &["config", "get", "default-registry"],
        None,
    );
    assert_success(&get);
    assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), prefix);

    let logout = run_orc(config_dir.path(), &["logout", &prefix], None);
    assert_success(&logout);
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(config_dir.path().join("config.json")).expect("config body"),
    )
    .expect("config json");
    assert!(
        config["credentials"]
            .as_object()
            .expect("credentials")
            .is_empty()
    );
}

#[test]
fn login_without_password_stdin_is_usage_error() {
    let config_dir = tempfile::tempdir().expect("config dir");
    let output = run_orc(config_dir.path(), &["login", "ghcr.io"], None);
    assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--password-stdin"));
}

fn run_orc(config_dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_orc"));
    command
        .args(args)
        .env("ORC_CONFIG_DIR", config_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("spawn orc");
    if let Some(stdin_body) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin_body.as_bytes())
            .expect("write stdin");
    }
    child.wait_with_output().expect("orc output")
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
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
