use std::process::Command;

fn main() {
    emit_orc_version();
}

fn emit_orc_version() {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");

    let version = std::env::var("GITHUB_REF_NAME")
        .ok()
        .filter(|name| name.starts_with('v'))
        .map(|name| name.trim_start_matches('v').to_owned())
        .or_else(git_describe)
        .unwrap_or_else(|| {
            std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_owned())
        });

    println!("cargo:rustc-env=ORC_VERSION={version}");
}

fn git_describe() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.trim_start_matches('v').to_owned())
}
