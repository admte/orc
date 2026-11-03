//! Format v2 (spec 214) through the real lifecycle functions: each phase runs the argv
//! its manifest declares, with params, file paths and context as tokens and nothing of
//! them in the environment.

use super::*;
use crate::app::AppFormat;

struct Secret(Vec<u8>);

impl SecretResolver for Secret {
    fn resolve<'a>(
        &'a self,
        _reference: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        let value = self.0.clone();
        Box::pin(async move { Ok(value) })
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites build the value inline"
)]
fn v2(value: serde_json::Value) -> AppConfig {
    AppConfig::parse(AppFormat::V2, &serde_json::to_vec(&value).expect("json")).expect("config")
}

fn param(name: &str, value: ParsedParamValue, file_backed: bool) -> (String, ParsedParam) {
    (
        name.to_owned(),
        ParsedParam {
            name: name.to_owned(),
            value,
            file_backed,
            lifetime: ParamLifetime::Runtime,
        },
    )
}

fn string(value: &str) -> ParsedParamValue {
    ParsedParamValue::String(value.to_owned())
}

/// The runner's params: a plain url, a sensitive token held as a secret reference, and
/// an optional pool left unset.
fn runner_params() -> BTreeMap<String, ParsedParam> {
    BTreeMap::from([
        param("url", string("https://example.test/a b"), false),
        param(
            "token",
            ParsedParamValue::SecretRef("sec:token".to_owned()),
            true,
        ),
        param("labels", string(""), false),
    ])
}

fn runner_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "token": {"type": "string", "sensitive": true},
            "pool": {"type": "string"},
            "labels": {"type": "string"},
            "slot": {"type": "string", "x-source": {"kind": "peers.first"}}
        }
    })
}

fn no_log() -> LogLine {
    Arc::new(|_, _| {})
}

/// A packaged script that writes each argument on a line of `<first arg>`, the
/// environment to `<first arg>.env`, and the content of every `--*-file=` path it is
/// handed to `<first arg>.<flag>`, so a test reads exactly what the phase received.
#[cfg(unix)]
const RECORDER: &str = r#"#!/bin/sh
out="$1"
shift
: > "$out"
for arg; do
  printf '%s\n' "$arg" >> "$out"
  case $arg in
    --*-file=*) name=${arg%%=*}; cat "${arg#*=}" > "$out.${name#--}" ;;
  esac
done
env > "$out.env"
"#;

#[cfg(unix)]
fn install_recorder(work_dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = work_dir.join("rec.sh");
    std::fs::write(&path, RECORDER).expect("recorder");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[cfg(unix)]
fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

#[cfg(unix)]
fn assert_no_params_in_env(env_file: &Path) {
    let env = std::fs::read_to_string(env_file).expect("env");
    for line in env.lines() {
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        assert!(
            !key.starts_with("APP_")
                && !["URL", "TOKEN", "TOKEN_FILE", "POOL", "LABELS", "PEERS_FILE"].contains(&key),
            "{key} leaked into the environment:\n{env}"
        );
        assert!(
            !value.contains("hunter2") && !value.contains("example.test"),
            "a param value leaked into the environment as {key}:\n{env}"
        );
    }
    assert!(env.lines().any(|line| line.starts_with("PATH=")), "{env}");
}

#[cfg(unix)]
#[tokio::test]
async fn an_install_receives_params_as_argv_and_none_as_environment() {
    let work = tempfile::tempdir().expect("work");
    install_recorder(work.path());
    let config = v2(serde_json::json!({
        "params": runner_schema(),
        "persist": {"paths": ["/srv/runner"]},
        "install": {"command": [
            "./rec.sh", "install.args",
            "--url=${url}",
            "--token-file=${token_file}",
            "--pool=${pool}",
            "--pool-or=${pool:-main}",
            "--labels=${labels:-none}",
            "--slot=${slot}",
            "--version=${version}",
            "--instance=${instance}",
            "--state=${persist_state}",
            "$${url} costs $$5",
            "two words"
        ]}
    }));
    let mut params = runner_params();
    // A host-sourced value that resolved to nothing counts as unset.
    params.extend([param("slot", string(""), false)]);
    let _ = run_install_phase(
        "runner",
        "runner-2",
        "2.1",
        &config,
        &params,
        work.path(),
        Some(&Secret(b"hunter2".to_vec())),
        no_log(),
        None,
        Some(PersistState::Restored),
        None,
    )
    .await
    .expect("install");

    let args = read_lines(&work.path().join("install.args"));
    assert_eq!(args[0], "--url=https://example.test/a b");
    let token_path = args[1].strip_prefix("--token-file=").expect("token file");
    assert_eq!(
        args[2..],
        [
            "--pool-or=main",
            "--labels=",
            "--version=2.1",
            "--instance=runner-2",
            "--state=restored",
            "${url} costs $5",
            "two words",
        ]
    );
    // The file held the secret while the phase ran, and is gone once it ended.
    assert_eq!(
        std::fs::read_to_string(work.path().join("install.args.token-file")).expect("token"),
        "hunter2"
    );
    assert!(
        !Path::new(token_path).exists(),
        "{token_path} outlived the phase"
    );
    assert_no_params_in_env(&work.path().join("install.args.env"));
}

/// The phase environment carries the reboot shim's `PATH` entry and request file and
/// nothing derived from params; the params are tokens.
#[tokio::test]
async fn a_v2_phase_environment_keeps_the_reboot_shim_and_nothing_else() {
    let state = tempfile::tempdir().expect("state");
    let work = tempfile::tempdir().expect("work");
    let reboot = PhaseReboot::enter(state.path(), "demo", "1.0", "install").expect("enter");
    let config = v2(serde_json::json!({
        "params": runner_schema(),
        "start": {"service": "runner-${instance}", "command": ["./run"]}
    }));
    let env = phase_env_v2(
        V2Phase::Install,
        &config,
        "1.0",
        "demo",
        &runner_params(),
        Some(&Secret(b"hunter2".to_vec())),
        Some(work.path()),
        Some(&reboot),
        None,
    )
    .await
    .expect("env");
    assert!(
        env.vars["PATH"].starts_with(&reboot.shim_dir().display().to_string()),
        "{:?}",
        env.vars
    );
    assert!(env.vars.contains_key(crate::reboot::REQUEST_ENV));
    assert!(
        env.vars
            .keys()
            .all(|key| key == "PATH" || key.starts_with("ORC_REBOOT")),
        "{:?}",
        env.vars
    );
    assert_eq!(env.tokens["url"], "https://example.test/a b");
    assert_eq!(env.tokens["version"], "1.0");
    assert_eq!(env.tokens["instance"], "demo");
    assert_eq!(env.tokens["service"], service::platform_name("runner-demo"));
    assert!(
        !env.tokens.contains_key("token"),
        "a file-backed param has no value token"
    );
    let token = PathBuf::from(&env.tokens["token_file"]);
    assert_eq!(token, work.path().join("token"));
    assert_eq!(std::fs::read(&token).expect("token"), b"hunter2");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&token)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Context a phase does not read is never set, whatever the caller knows.
    assert!(!env.tokens.contains_key("pid"));
    let _ = reboot.finish();
}

/// File-backed comes from the manifest alone (spec 214 *Tokens*): a param marked
/// `sensitive` or setting `contentMediaType` is a file, and no `x-source` kind makes one —
/// whatever v1's rule, carried in [`ParsedParam::file_backed`], says.
#[tokio::test]
async fn only_the_manifest_makes_a_v2_param_file_backed() {
    let work = tempfile::tempdir().expect("work");
    let config = v2(serde_json::json!({
        "params": {"properties": {
            "peers": {"type": "string", "x-source": {"kind": "peers.all"}},
            "listing": {"type": "string", "contentMediaType": "text/plain", "x-source": {"kind": "peers.all"}},
            "runner": {"type": "string", "sensitive": true, "x-source": {"kind": "github.runner"}}
        }}
    }));
    // As the host hands them over: v1's rule marks every one of them file-backed, and the
    // runner's credential arrives as content the host minted.
    let params = BTreeMap::from([
        param("peers", string("a.internal\nb.internal"), true),
        param("listing", string("a.internal\nb.internal"), true),
        param("runner", string("minted-credential"), true),
    ]);
    let env = phase_env_v2(
        V2Phase::Install,
        &config,
        "1.0",
        "demo",
        &params,
        None,
        Some(work.path()),
        None,
        None,
    )
    .await
    .expect("env");
    assert_eq!(env.tokens["peers"], "a.internal\nb.internal");
    assert!(!env.tokens.contains_key("peers_file"), "{:?}", env.tokens);
    assert!(!env.tokens.contains_key("listing"), "{:?}", env.tokens);
    assert_eq!(
        std::fs::read_to_string(&env.tokens["listing_file"]).expect("listing"),
        "a.internal\nb.internal"
    );
    assert!(!env.tokens.contains_key("runner"), "{:?}", env.tokens);
    assert_eq!(
        std::fs::read_to_string(&env.tokens["runner_file"]).expect("runner"),
        "minted-credential"
    );
}

/// The uninstall map follows the same rule: a kept value for a param no manifest flag
/// makes file-backed is a value token, whichever kind filled it.
#[tokio::test]
async fn a_v2_uninstall_keeps_a_sourced_value_as_a_value() {
    let config = v2(serde_json::json!({
        "params": {"properties": {"peers": {"type": "string", "x-source": {"kind": "peers.all"}}}}
    }));
    let params = BTreeMap::from([("peers".to_owned(), "a\nb".to_owned())]);
    let env = durable_phase_env_v2(&config, "1.0", "demo", &params, None).expect("env");
    assert_eq!(env.tokens["peers"], "a\nb");
    assert!(env.param_files.is_empty());
}

/// A program and a service name cannot lose a piece: each fails, naming the token.
#[test]
fn a_dropped_program_or_service_piece_is_an_error_naming_the_token() {
    let err = v2::command::command_argv(
        &["${tool}".to_owned(), "x".to_owned()],
        &BTreeMap::new(),
        Path::new("/srv"),
        v2::command::CommandHost::Unix,
    )
    .expect_err("no program");
    assert!(err.to_string().contains("${tool} is not set"), "{err}");
    let config = v2(serde_json::json!({"start": {"service": "runner-${pool}-${version}"}}));
    let err = instance_service_name(&config, "runner", "1.0", &BTreeMap::new()).expect_err("unset");
    assert!(err.to_string().contains("${pool} is not set"), "{err}");
}

#[cfg(unix)]
struct V2App {
    work: tempfile::TempDir,
    state: tempfile::TempDir,
    config: AppConfig,
    params: BTreeMap<String, ParsedParam>,
    secret: Secret,
}

#[cfg(unix)]
impl V2App {
    fn new(config: serde_json::Value) -> Self {
        let work = tempfile::tempdir().expect("work");
        install_recorder(work.path());
        Self {
            work,
            state: tempfile::tempdir().expect("state"),
            config: v2(config),
            params: runner_params(),
            secret: Secret(b"hunter2".to_vec()),
        }
    }

    fn context(&self) -> AppContext<'_> {
        AppContext {
            app: "runner",
            instance: "runner",
            version: "2.1",
            config: &self.config,
            params: &self.params,
            work_dir: self.work.path(),
            state_dir: self.state.path(),
            secrets: Some(&self.secret),
            log_line: no_log(),
        }
    }

    fn lines(&self, name: &str) -> Vec<String> {
        read_lines(&self.work.path().join(name))
    }

    async fn wait_for(&self, name: &str) {
        for _ in 0..200 {
            if self.work.path().join(format!("{name}.env")).exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("{name} was never written");
    }
}

/// A packaged long-running app: records its argv, then `exec`s so the stop signal, the
/// pid and the exit status are its own.
#[cfg(unix)]
const SERVER: &str = r#"#!/bin/sh
./rec.sh start.args "$@"
exec sleep 30
"#;

#[cfg(unix)]
#[tokio::test]
async fn start_stop_and_stopped_run_their_argv_with_their_own_context() {
    use std::os::unix::fs::PermissionsExt as _;
    let app = V2App::new(serde_json::json!({
        "params": runner_schema(),
        "start": {"command": ["./server.sh", "--url=${url}", "--token-file=${token_file}", "--pool=${pool}"]},
        "stop": {
            "command": ["./rec.sh", "stop.args", "--pid=${pid}", "--reason=${stop_reason}", "--status=${stop_status}"],
            "timeout": "5s",
            "grace": "5s"
        },
        "stopped": {"command": [
            "./rec.sh", "stopped.args",
            "--reason=${stop_reason}", "--status=${stop_status}", "--code=${exit_code}",
            "--signal=${exit_signal}", "--ran=${run_duration}", "--pid=${pid}",
            "--token-file=${token_file}"
        ]}
    }));
    let server = app.work.path().join("server.sh");
    std::fs::write(&server, SERVER).expect("server");
    std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let start = start_command(
        "runner",
        "runner",
        &app.config,
        "2.1",
        &app.params,
        app.work.path(),
        Some(&app.secret),
        None,
        None,
    )
    .await
    .expect("start command");
    assert!(start.env.is_empty(), "{:?}", start.env);
    assert_eq!(start.tokens["url"], "https://example.test/a b");
    let mut child = crate::process::spawn_app(start.command, |_, _| {}).expect("spawn");
    app.wait_for("start.args").await;
    let args = app.lines("start.args");
    assert_eq!(args[0], "--url=https://example.test/a b");
    assert!(args[1].starts_with("--token-file="), "{args:?}");
    assert_eq!(args.len(), 2, "the unset pool was dropped: {args:?}");
    assert_eq!(
        std::fs::read_to_string(app.work.path().join("start.args.token-file")).expect("token"),
        "hunter2"
    );
    assert_no_params_in_env(&app.work.path().join("start.args.env"));
    let pid = child.id().expect("pid");

    let outcome = {
        let mut process = AppProcess::subprocess(&mut child, std::time::Instant::now());
        stop_sequence(
            &app.context(),
            &mut process,
            StopReason::Terminate,
            &CancellationToken::new(),
        )
        .await
    };
    assert_eq!(outcome.stop_status, StopStatus::Ok);
    // `${stop_status}` is a `stopped` token: the stop phase never sees it.
    assert_eq!(
        app.lines("stop.args"),
        [format!("--pid={pid}"), "--reason=terminate".to_owned()]
    );
    assert_no_params_in_env(&app.work.path().join("stop.args.env"));

    run_stopped_phase(
        &app.context(),
        StoppedReason::Stopped(StopReason::Terminate),
        outcome.stop_status,
        &outcome.exit,
        None,
        None,
    )
    .await;
    let stopped = app.lines("stopped.args");
    assert_eq!(stopped[0], "--reason=terminate");
    assert_eq!(stopped[1], "--status=ok");
    // Exactly one of the two: the app was ended by a signal.
    assert_eq!(stopped[2], format!("--signal={}", libc::SIGTERM));
    assert!(stopped[3].starts_with("--ran="), "{stopped:?}");
    assert_eq!(stopped[4], format!("--pid={pid}"));
    assert!(stopped[5].starts_with("--token-file="), "{stopped:?}");
    assert_eq!(stopped.len(), 6, "{stopped:?}");
    // The stop-side hooks got the secret afresh, though the app's own copy may be gone.
    assert_eq!(
        std::fs::read_to_string(app.work.path().join("stopped.args.token-file")).expect("token"),
        "hunter2"
    );
    remove_param_files(app.work.path());
}

/// The service manager restarts a v2 app with nothing but the work dir: the shim reads
/// the format from `app.config.v2.json` and rebuilds the same argv from the persisted
/// params.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn the_shim_rebuilds_a_v2_managed_service_from_its_work_dir() {
    let work = tempfile::tempdir().expect("work");
    let config = serde_json::json!({
        "params": runner_schema(),
        "start": {
            "service": "runner-${version}",
            "command": ["./run.sh", "--url=${url}", "--token-file=${token_file}", "--svc=${service}"]
        }
    });
    std::fs::write(
        work.path().join(crate::app::CONFIG_FILE_V2),
        serde_json::to_vec(&config).expect("json"),
    )
    .expect("config");
    let resolved = resolved_params(&runner_params(), Some(&Secret(b"hunter2".to_vec())))
        .await
        .expect("resolve");
    write_app_env(
        work.path(),
        &AppEnv {
            app: "runner".to_owned(),
            instance: "runner".to_owned(),
            version: "2.1".to_owned(),
            params: resolved.clone(),
            persist_state: None,
        },
    )
    .expect("app env");

    let read = crate::app::read_config(work.path()).expect("read");
    assert_eq!(read.format, AppFormat::V2);
    assert_eq!(
        instance_service_name(&read, "runner", "2.1", &resolved).expect("name"),
        Some(service::platform_name("runner-2.1"))
    );
    let spec = managed_service_spec(
        "runner",
        "runner",
        "2.1",
        &read,
        work.path(),
        &service::platform_name("runner-2.1"),
        Path::new("/usr/bin/orc"),
    );
    assert_eq!(spec.exec[1], SHIM_SUBCOMMAND);

    let start = shim_start_command(work.path(), "runner", "runner", "2.1")
        .await
        .expect("shim start");
    let command = start.command.as_std();
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        Path::new(command.get_program()),
        work.path().join("run.sh").as_path()
    );
    assert_eq!(args[0], "--url=https://example.test/a b");
    let token = args[1].strip_prefix("--token-file=").expect("token");
    assert_eq!(std::fs::read(token).expect("token"), b"hunter2");
    assert_eq!(
        args[2],
        format!("--svc={}", service::platform_name("runner-2.1"))
    );
    assert!(
        command
            .get_envs()
            .all(|(key, _)| !key.to_string_lossy().starts_with("APP_")),
        "no APP_ variable reaches a v2 app"
    );
    remove_param_files(work.path());
}

#[cfg(unix)]
#[tokio::test]
async fn an_uninstall_hands_file_backed_params_over_as_files_it_then_removes() {
    let work = tempfile::tempdir().expect("work");
    install_recorder(work.path());
    let host_file = work.path().join("host-written");
    std::fs::write(&host_file, "from-the-host").expect("host file");
    let config = v2(serde_json::json!({
        "params": {
            "properties": {
                "url": {"type": "string"},
                "token": {"type": "string", "sensitive": true},
                "peers": {"type": "string", "contentMediaType": "text/plain", "x-source": {"kind": "peers.all"}},
                "doc": {"type": "string", "contentMediaType": "application/json"}
            }
        },
        "start": {"service": "runner", "command": ["./run.sh"]},
        "uninstall": {"command": [
            "./rec.sh", "uninstall.args",
            "--url=${url}", "--token-file=${token_file}", "--peers-file=${peers_file}",
            "--doc-file=${doc_file}", "--service=${service}", "--version=${version}"
        ]}
    }));
    // What a host kept: plain values, a secret it resolved to a file of its own, and
    // file-backed values it kept as values.
    let params = BTreeMap::from([
        ("url".to_owned(), "https://x".to_owned()),
        ("token_file".to_owned(), host_file.display().to_string()),
        ("peers".to_owned(), "a\nb\n".to_owned()),
        ("doc".to_owned(), "{\"k\":1}".to_owned()),
    ]);
    let _ = run_uninstall_phase(
        "runner",
        "runner",
        "default",
        &config,
        &params,
        work.path(),
        no_log(),
        None,
        None,
    )
    .await
    .expect("uninstall");
    let args = read_lines(&work.path().join("uninstall.args"));
    assert_eq!(args[0], "--url=https://x");
    assert_eq!(args[1], format!("--token-file={}", host_file.display()));
    assert_eq!(
        args[4],
        format!("--service={}", service::platform_name("runner"))
    );
    // `${version}` is unset for the implicit `default` tag: the element is dropped.
    assert_eq!(args.len(), 5, "{args:?}");
    let read = |flag: &str| {
        std::fs::read_to_string(work.path().join(format!("uninstall.args.{flag}")))
            .expect("file content")
    };
    assert_eq!(read("token-file"), "from-the-host");
    assert_eq!(read("peers-file"), "a\nb\n");
    assert_eq!(read("doc-file"), "{\"k\":1}");
    // The runtime's own copies are gone; the host's file is the host's to remove.
    for flag in ["--peers-file=", "--doc-file="] {
        let path = args
            .iter()
            .find_map(|arg| arg.strip_prefix(flag))
            .expect("path");
        assert!(!Path::new(path).exists(), "{path} outlived the phase");
    }
    assert!(host_file.exists());
    assert_no_params_in_env(&work.path().join("uninstall.args.env"));
}

#[cfg(unix)]
#[tokio::test]
async fn a_capture_hook_takes_params_version_and_instance_only() {
    let work = tempfile::tempdir().expect("work");
    install_recorder(work.path());
    let config = v2(serde_json::json!({
        "params": runner_schema(),
        "start": {"service": "runner", "command": ["./run.sh"]},
        "persist": {
            "paths": ["/srv/data"],
            "hook_pre": {"command": [
                "./rec.sh", "hook.args", "--url=${url}", "--token-file=${token_file}",
                "--v=${version}", "--i=${instance}", "--s=${service}", "--p=${persist_state}"
            ]}
        }
    }));
    run_capture_hook_phase(
        "hook_pre",
        "runner",
        "3.0",
        &config,
        config
            .persist
            .as_ref()
            .and_then(|persist| persist.hook_pre.as_ref()),
        &runner_params(),
        work.path(),
        Some(&Secret(b"hunter2".to_vec())),
        no_log(),
    )
    .await
    .expect("hook");
    let args = read_lines(&work.path().join("hook.args"));
    assert_eq!(args[0], "--url=https://example.test/a b");
    assert!(args[1].starts_with("--token-file="), "{args:?}");
    assert_eq!(args[2..], ["--v=3.0", "--i=runner"]);
}

#[cfg(unix)]
#[tokio::test]
async fn a_probe_command_takes_the_tokens_of_start() {
    let work = tempfile::tempdir().expect("work");
    let config = v2(serde_json::json!({
        "endpoints": {"web": {"port": 8080, "probe": {"command": [
            "sh", "-c", "test \"$1\" = ready && test \"$2\" = demo", "probe", "${state}", "${instance}"
        ]}}}
    }));
    let plans = crate::probe::plan_endpoint_probes(&config);
    assert!(
        matches!(&plans[0].kind, crate::probe::ProbeKind::CommandV2(argv) if argv[0] == "sh"),
        "{plans:?}"
    );
    let ctx = |state: &str| crate::probe::ProbeContext {
        work_dir: work.path().to_path_buf(),
        tokens: BTreeMap::from([
            ("state".to_owned(), state.to_owned()),
            ("instance".to_owned(), "demo".to_owned()),
        ]),
        ..crate::probe::ProbeContext::default()
    };
    crate::probe::run_probe(&plans[0], &ctx("ready"))
        .await
        .expect("probe passes");
    crate::probe::run_probe(&plans[0], &ctx("starting"))
        .await
        .expect_err("probe fails");
}

#[test]
fn a_v2_app_discovers_no_scripts() {
    let work = tempfile::tempdir().expect("work");
    for phase in ["install", "start", "stop", "stopped", "uninstall"] {
        std::fs::write(work.path().join(format!("{phase}-demo.sh")), "exit 0\n").expect("script");
        std::fs::write(work.path().join(format!("{phase}-demo.ps1")), "exit 0\n").expect("script");
    }
    let config = v2(serde_json::json!({"start": {}, "stop": {"grace": "5s"}}));
    assert_eq!(resolve_start_command("demo", &config, work.path()), None);
    assert!(
        phase_command(AppFormat::V2, "install", "demo", None, work.path())
            .expect("resolve")
            .is_none()
    );
    // A stop with no declared command charges only its grace.
    assert_eq!(
        stop_budget("demo", &config, work.path()),
        Duration::from_secs(5)
    );
    // `[]` skips a phase on purpose.
    let skipped = v2(serde_json::json!({"start": {"command": [], "service": "demo"}}));
    assert_eq!(resolve_start_command("demo", &skipped, work.path()), None);
    assert_eq!(
        resolve_start_mode("demo", &skipped, work.path(), &BTreeMap::new()).expect("mode"),
        Some(StartMode::Service {
            name: service::platform_name("demo")
        })
    );
}

#[tokio::test]
async fn a_v2_string_command_is_refused_rather_than_run_through_a_shell() {
    let work = tempfile::tempdir().expect("work");
    let config = v2(serde_json::json!({"install": {"command": "touch ran"}}));
    let err = run_install_phase(
        "demo",
        "demo",
        "1.0",
        &config,
        &BTreeMap::new(),
        work.path(),
        None,
        no_log(),
        None,
        None,
        None,
    )
    .await
    .expect_err("string command");
    assert!(err.to_string().contains("argv list"), "{err}");
    assert!(!work.path().join("ran").exists());
}

#[test]
fn a_v2_service_name_naming_an_unset_value_is_an_error() {
    let config = v2(serde_json::json!({"start": {"service": "runner-${pool}"}}));
    let err = instance_service_name(&config, "runner", "1.0", &BTreeMap::new()).expect_err("unset");
    assert!(err.to_string().contains("not set"), "{err}");
    let config = v2(serde_json::json!({"start": {"service": "runner-${pool:-main}"}}));
    assert_eq!(
        instance_service_name(&config, "runner", "1.0", &BTreeMap::new()).expect("name"),
        Some(service::platform_name("runner-main"))
    );
}

// ── Windows: a packaged .ps1 runs under `powershell -File` ──────────────────────

/// A script that writes the parameters it was bound to as JSON, one case per run.
#[cfg(windows)]
const PS_RECORDER: &str = r#"param(
  [string]$Out,
  [string]$Value = '<unbound>',
  [Parameter(ValueFromRemainingArguments = $true)] $Rest
)
$result = [ordered]@{ Value = $Value; Rest = @($Rest | ForEach-Object { "$_" }) }
$result | ConvertTo-Json -Compress | Set-Content -Path $Out -Encoding UTF8
"#;

/// What a `-Value:<value>` element arrives as in a `.ps1` run by the shorthand:
/// Windows PowerShell 5.1's `-File` binding, measured on the Windows CI runner. Every
/// value arrives as written except an empty one, which leaves the parameter unbound.
#[cfg(windows)]
#[tokio::test]
async fn powershell_file_binds_name_colon_value_elements() {
    let work = tempfile::tempdir().expect("work");
    std::fs::write(work.path().join("rec.ps1"), PS_RECORDER).expect("script");
    let cases: &[(&str, &str)] = &[
        (
            "-Value:https://example.test/a b",
            "https://example.test/a b",
        ),
        ("-Value:a,b", "a,b"),
        ("-Value:-starts-with-dash", "-starts-with-dash"),
        ("-Value:$env:PATH", "$env:PATH"),
        ("-Value:it's", "it's"),
        ("-Value:say \"hi\"", "say \"hi\""),
        ("-Value:trailing\\", "trailing\\"),
        // Measured: Windows PowerShell 5.1 drops an empty `-Name:` value, leaving the
        // parameter at its declared default. Pinned here so a change is noticed.
        ("-Value:", "<unbound>"),
    ];
    let mut report = Vec::new();
    for (index, (element, expected)) in cases.iter().enumerate() {
        let out = format!("case{index}.json");
        let config = v2(serde_json::json!({
            "install": {"command": ["rec.ps1", format!("-Out:{out}"), element], "timeout": "60s"}
        }));
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let log: LogLine = Arc::new(move |_, line: &str| {
            sink.lock().expect("lines").push(line.to_owned());
        });
        let ran = run_install_phase(
            "demo",
            "demo",
            "1.0",
            &config,
            &BTreeMap::new(),
            work.path(),
            None,
            log,
            None,
            None,
            None,
        )
        .await;
        let got = match ran {
            Ok(_) => std::fs::read_to_string(work.path().join(&out))
                .map(|body| body.trim_start_matches('\u{feff}').trim().to_owned())
                .unwrap_or_else(|err| format!("no output: {err}")),
            Err(err) => format!("failed: {err}: {:?}", lines.lock().expect("lines")),
        };
        let parsed: Option<serde_json::Value> = serde_json::from_str(&got).ok();
        let value = parsed
            .as_ref()
            .and_then(|parsed| parsed["Value"].as_str().map(str::to_owned));
        report.push((
            (*element).to_owned(),
            (*expected).to_owned(),
            value.clone().unwrap_or_else(|| got.clone()),
            value.as_deref() == Some(*expected),
        ));
    }
    let failures: Vec<_> = report.iter().filter(|case| !case.3).collect();
    assert!(
        failures.is_empty(),
        "powershell -File binding (element, expected, got):\n{}",
        report
            .iter()
            .map(|(element, expected, got, ok)| format!(
                "  {} {element:?} -> {got:?} (expected {expected:?})",
                if *ok { "ok  " } else { "FAIL" }
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
