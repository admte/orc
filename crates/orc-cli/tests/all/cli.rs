use std::process::Command;

#[test]
fn version_subcommand_prints_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .arg("version")
        .output()
        .expect("run orc");
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        env!("ORC_VERSION")
    );
}

#[cfg(windows)]
#[test]
fn windows_uses_local_app_data_without_home() {
    let dir = tempfile::tempdir().expect("local app data");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["config", "set", "default-registry", "registry.example.com"])
        .env_remove("HOME")
        .env_remove("ORC_CONFIG_DIR")
        .env("LOCALAPPDATA", dir.path())
        .output()
        .expect("run orc");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = std::fs::read_to_string(dir.path().join("orc/config/config.json"))
        .expect("configuration under local app data");
    assert!(config.contains("registry.example.com"));
}
