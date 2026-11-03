//! App format v2 (spec 214) through the real binary: `orc build` resolves a recipe per
//! platform and runs the publish checks, and `orc install` / `orc uninstall` run the
//! host platform's argv with params as tokens and nothing of them in the environment.

use std::path::Path;
use std::process::{Command, Output};

/// A prefix nothing answers on: everything here works off the local cache.
const UNREACHABLE_PREFIX: &str = "127.0.0.1:1/acme";

const RECIPE: &str = r#"
artifactType: application/vnd.orc8r.app.v2
annotations:
  org.opencontainers.image.title: demo
config:
  params:
    type: object
    required: [url, out]
    properties:
      url: {type: string, description: {unix: "POSIX url", windows: "Windows url"}}
      out: {type: string}
      token: {type: string, sensitive: true}
      pool: {type: string}
  install:
    command:
      unix: ["./install.sh", "--os=${os}", "--out=${out}", "--url=${url}",
             "--token-file=${token_file}", "--pool=${pool}", "--version=${version}",
             "--instance=${instance}", "$${url}"]
      windows: ["install.ps1", "-Os:${os}", "-Out:${out}", "-Url:${url}",
                "-TokenFile:${token_file}", "-Pool:${pool}", "-Instance:${instance}"]
  uninstall:
    command:
      unix: ["./uninstall.sh", "--out=${out}", "--token-file=${token_file}"]
      windows: ["uninstall.ps1", "-Out:${out}", "-TokenFile:${token_file}"]
files:
  - install.sh
  - uninstall.sh
  - install.ps1
  - uninstall.ps1
platforms:
  - {os: linux, arch: amd64}
  - {os: linux, arch: arm64}
  - {os: darwin, arch: amd64}
  - {os: darwin, arch: arm64}
  - {os: windows, arch: amd64}
"#;

const INSTALL_SH: &str = r#"#!/bin/sh
for arg; do
  case $arg in --out=*) out=${arg#--out=} ;; --token-file=*) token=${arg#--token-file=} ;; esac
done
for arg; do printf '%s\n' "$arg"; done > "$out/install.args"
cat "$token" > "$out/install.token"
env > "$out/install.env"
"#;

const UNINSTALL_SH: &str = r#"#!/bin/sh
for arg; do
  case $arg in --out=*) out=${arg#--out=} ;; --token-file=*) token=${arg#--token-file=} ;; esac
done
cat "$token" > "$out/uninstall.token"
"#;

const INSTALL_PS1: &str = r#"param([string]$Os, [string]$Out, [string]$Url, [string]$TokenFile,
      [string]$Pool = '<unset>', [string]$Instance)
@("--os=$Os", "--url=$Url", "--pool=$Pool", "--instance=$Instance") |
  Set-Content -Path (Join-Path $Out 'install.args')
Get-Content -Raw -Path $TokenFile | Set-Content -NoNewline -Path (Join-Path $Out 'install.token')
Get-ChildItem env: | ForEach-Object { "$($_.Name)=$($_.Value)" } |
  Set-Content -Path (Join-Path $Out 'install.env')
"#;

const UNINSTALL_PS1: &str = r"param([string]$Out, [string]$TokenFile)
Get-Content -Raw -Path $TokenFile | Set-Content -NoNewline -Path (Join-Path $Out 'uninstall.token')
";

fn write_package(dir: &Path, executable: bool) {
    std::fs::write(dir.join("artifact.yaml"), RECIPE).expect("recipe");
    for (name, body) in [
        ("install.sh", INSTALL_SH),
        ("uninstall.sh", UNINSTALL_SH),
        ("install.ps1", INSTALL_PS1),
        ("uninstall.ps1", UNINSTALL_PS1),
    ] {
        std::fs::write(dir.join(name), body).expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let script = Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "sh");
            let mode = if executable && script { 0o755 } else { 0o644 };
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        }
    }
    #[cfg(not(unix))]
    let _ = executable;
}

struct Dirs {
    cache: tempfile::TempDir,
    state: tempfile::TempDir,
    config: tempfile::TempDir,
}

impl Dirs {
    fn new() -> Self {
        Self {
            cache: tempfile::tempdir().expect("cache"),
            state: tempfile::tempdir().expect("state"),
            config: tempfile::tempdir().expect("config"),
        }
    }

    fn orc(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_orc"))
            .args(args)
            .env("ORC_CACHE_DIR", self.cache.path())
            .env("ORC_STATE_DIR", self.state.path())
            .env("ORC_CONFIG_DIR", self.config.path())
            .output()
            .expect("run orc")
    }
}

fn host_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}/{arch}")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn cached_manifests(cache: &Path) -> Vec<serde_json::Value> {
    std::fs::read_dir(cache.join("manifests/sha256"))
        .expect("manifests")
        .filter_map(|entry| {
            let body = std::fs::read(entry.ok()?.path()).ok()?;
            serde_json::from_slice(&body).ok()
        })
        .collect()
}

#[cfg(unix)]
fn blob(cache: &Path, digest: &str) -> serde_json::Value {
    let hex = digest.strip_prefix("sha256:").expect("digest");
    serde_json::from_slice(&std::fs::read(cache.join("blobs/sha256").join(hex)).expect("blob"))
        .expect("json blob")
}

/// Each platform's config blob holds that platform's plain values: per-OS values are
/// resolved, build tokens filled, run-time tokens and escapes left for the runtime.
#[cfg(unix)]
#[test]
fn orc_build_resolves_a_v2_recipe_for_each_platform() {
    let dirs = Dirs::new();
    let package = tempfile::tempdir().expect("package");
    write_package(package.path(), true);
    let output = dirs.orc(&[
        "--registry",
        UNREACHABLE_PREFIX,
        "build",
        package.path().to_str().expect("path"),
        "--tag",
        "demo",
    ]);
    assert_success(&output);
    let manifests = cached_manifests(dirs.cache.path());
    let index = manifests
        .iter()
        .find(|manifest| manifest.get("manifests").is_some())
        .expect("index");
    assert_eq!(index["artifactType"], "application/vnd.orc8r.app.v2");
    let config_for = |os: &str, arch: &str| {
        let child = index["manifests"]
            .as_array()
            .expect("children")
            .iter()
            .find(|child| {
                child["platform"]["os"] == os && child["platform"]["architecture"] == arch
            })
            .expect("child");
        let hex = child["digest"]
            .as_str()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .expect("digest");
        let body = std::fs::read(dirs.cache.path().join("manifests/sha256").join(hex))
            .expect("child manifest");
        let child_manifest: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            child_manifest["artifactType"],
            "application/vnd.orc8r.app.v2"
        );
        assert_eq!(
            child_manifest["config"]["mediaType"],
            "application/vnd.orc8r.app.config.v2+json"
        );
        blob(
            dirs.cache.path(),
            child_manifest["config"]["digest"].as_str().expect("digest"),
        )
    };
    let linux = config_for("linux", "arm64");
    assert_eq!(
        linux["install"]["command"],
        serde_json::json!([
            "./install.sh",
            "--os=linux",
            "--out=${out}",
            "--url=${url}",
            "--token-file=${token_file}",
            "--pool=${pool}",
            "--version=${version}",
            "--instance=${instance}",
            "$${url}"
        ])
    );
    assert_eq!(
        linux["params"]["properties"]["url"]["description"],
        "POSIX url"
    );
    let windows = config_for("windows", "amd64");
    assert_eq!(windows["install"]["command"][0], "install.ps1");
    assert_eq!(windows["install"]["command"][1], "-Os:windows");
    assert_eq!(
        windows["params"]["properties"]["url"]["description"],
        "Windows url"
    );
}

/// A Unix `./name` program must be packaged executable; the refusal names the platform,
/// the phase, the element.
#[cfg(unix)]
#[test]
fn orc_build_refuses_a_unix_program_packaged_without_its_executable_bit() {
    let dirs = Dirs::new();
    let package = tempfile::tempdir().expect("package");
    write_package(package.path(), false);
    let output = dirs.orc(&[
        "--registry",
        UNREACHABLE_PREFIX,
        "build",
        package.path().to_str().expect("path"),
        "--platform",
        "linux/amd64",
        "--tag",
        "demo",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("linux/amd64: install.command[0] \"./install.sh\": names `install.sh`, which the package carries without its executable bit"),
        "{stderr}"
    );
}

#[test]
fn orc_build_refuses_an_unknown_token_naming_where_it_is() {
    let dirs = Dirs::new();
    let package = tempfile::tempdir().expect("package");
    std::fs::write(
        package.path().join("artifact.yaml"),
        r#"
artifactType: application/vnd.orc8r.app.v2
config:
  install: {command: ["installer", "--pool=${pol}"]}
platforms:
  - {os: windows, arch: amd64}
"#,
    )
    .expect("recipe");
    let output = dirs.orc(&[
        "--registry",
        UNREACHABLE_PREFIX,
        "build",
        package.path().to_str().expect("path"),
        "--tag",
        "demo",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "windows/amd64: install.command[1] \"--pool=${pol}\": ${pol} names no build var, \
             param, file path or context"
        ),
        "{stderr}"
    );
}

/// The host platform's argv runs, a sensitive `@file` param reaches install and
/// uninstall as a file path, and the environment carries no param.
#[test]
fn orc_installs_and_uninstalls_a_v2_app_with_params_as_tokens() {
    let dirs = Dirs::new();
    let package = tempfile::tempdir().expect("package");
    write_package(package.path(), true);
    let host = host_platform();
    let build = dirs.orc(&[
        "--registry",
        UNREACHABLE_PREFIX,
        "--platform",
        &host,
        "build",
        package.path().to_str().expect("path"),
        "--tag",
        "demo",
    ]);
    assert_success(&build);

    let out = tempfile::tempdir().expect("out");
    let token = out.path().join("operator-token");
    std::fs::write(&token, "hunter2").expect("token");
    let out_dir = out.path().to_str().expect("out path");
    let install = dirs.orc(&[
        "--registry",
        UNREACHABLE_PREFIX,
        "install",
        "demo",
        "--url=https://example.test/a b",
        &format!("--out={out_dir}"),
        &format!("--token=@{}", token.display()),
    ]);
    assert_success(&install);

    let args: Vec<String> = std::fs::read_to_string(out.path().join("install.args"))
        .expect("install args")
        .lines()
        .map(|line| line.trim_end().to_owned())
        .collect();
    let os = host.split('/').next().expect("os");
    if cfg!(windows) {
        assert_eq!(
            args,
            [
                format!("--os={os}"),
                "--url=https://example.test/a b".to_owned(),
                "--pool=<unset>".to_owned(),
                "--instance=demo".to_owned(),
            ]
        );
    } else {
        assert_eq!(args[0], format!("--os={os}"));
        assert_eq!(args[1], format!("--out={out_dir}"));
        assert_eq!(args[2], "--url=https://example.test/a b");
        assert!(args[3].starts_with("--token-file="), "{args:?}");
        // The unset pool and the default tag's version are dropped whole.
        assert_eq!(args[4..], ["--instance=demo", "${url}"]);
    }
    assert_eq!(
        std::fs::read_to_string(out.path().join("install.token")).expect("token"),
        "hunter2"
    );
    let env = std::fs::read_to_string(out.path().join("install.env")).expect("env");
    for line in env.lines() {
        let key = line
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        assert!(
            !key.starts_with("APP_")
                && !["URL", "OUT", "TOKEN_FILE", "POOL"].contains(&key.as_str()),
            "{key} reached a v2 phase's environment"
        );
        assert!(
            !line.contains("hunter2") && !line.contains("example.test"),
            "{line}"
        );
    }
    let work_dir = dirs.state.path().join("apps/demo/default");
    assert!(work_dir.join("app.config.v2.json").exists());
    assert!(!work_dir.join("app.config.v1.json").exists());

    let uninstall = dirs.orc(&["--registry", UNREACHABLE_PREFIX, "uninstall", "demo"]);
    assert_success(&uninstall);
    assert_eq!(
        std::fs::read_to_string(out.path().join("uninstall.token")).expect("token"),
        "hunter2"
    );
    assert!(!work_dir.exists());
    // The operator's own file is theirs; the runtime only ever handed over copies.
    assert!(token.exists());
}

/// `orc install` materializes through the same path as `orc pull`. A work dir an earlier
/// install left behind (its install phase failed, so nothing was recorded) keeps its
/// config when a later install of the same tag, now v2, is refused for the files there.
#[test]
fn a_refused_install_keeps_the_config_a_failed_one_left() {
    let dirs = Dirs::new();
    let build = |recipe: &str| {
        let package = tempfile::tempdir().expect("package");
        std::fs::write(package.path().join("artifact.yaml"), recipe).expect("recipe");
        std::fs::write(package.path().join("run.sh"), "#!/bin/sh\n").expect("payload");
        let output = dirs.orc(&[
            "--registry",
            UNREACHABLE_PREFIX,
            "build",
            package.path().to_str().expect("path"),
            "--tag",
            "demo",
        ]);
        assert_success(&output);
    };
    build(
        "artifactType: application/vnd.orc8r.app.v1\nconfig:\n  install: {command: \"exit 3\"}\nfiles: [run.sh]\n",
    );
    let failed = dirs.orc(&["--registry", UNREACHABLE_PREFIX, "install", "demo"]);
    assert!(!failed.status.success(), "{failed:?}");
    let work_dir = dirs.state.path().join("apps/demo/default");
    assert!(work_dir.join("app.config.v1.json").exists(), "{failed:?}");

    build("artifactType: application/vnd.orc8r.app.v2\nconfig: {}\nfiles: [run.sh]\n");
    let refused = dirs.orc(&["--registry", UNREACHABLE_PREFIX, "install", "demo"]);
    assert_eq!(refused.status.code(), Some(5), "{refused:?}");
    assert!(
        work_dir.join("app.config.v1.json").exists(),
        "a refused install deleted the config"
    );
    assert!(!work_dir.join("app.config.v2.json").exists());
}
