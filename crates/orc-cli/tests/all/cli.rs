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
