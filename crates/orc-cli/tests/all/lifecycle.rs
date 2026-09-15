//! Stopping and uninstalling what this machine is running.
//!
//! Everything here runs the real binary against a real install: an app package built
//! from a recipe, installed into a temp state dir, started for real, and then stopped
//! the way an operator stops it — from a second process that has to find the first one.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

/// A prefix nothing answers on: every command here works off the local cache, and a
/// registry round trip would be a bug rather than a slow test.
const UNREACHABLE_PREFIX: &str = "127.0.0.1:1/acme";

/// An app that stays up until it is asked to stop, and writes down every step of the
/// termination flow as it happens.
const SLEEPER_RECIPE: &str = r#"
artifactType: application/vnd.orc8r.app.v1
config:
  start:
    command: |
      printf running > running.txt
      while true; do sleep 0.2; done
  stop:
    command: |
      printf "stop\n" >> steps.txt
    timeout: 10s
    grace: 5s
  stopped:
    command: |
      printf "stopped:$APP_STOP_STATUS\n" >> steps.txt
    timeout: 10s
"#;

#[test]
fn stopping_an_app_this_machine_never_installed_is_a_clean_no_op() {
    let dirs = TestDirs::new();
    let output = run_orc(&dirs, &["--registry", UNREACHABLE_PREFIX, "stop", "ghost"]);
    assert_success(&output);
    assert_stderr_contains(&output, "ghost:default is not installed");
}

#[test]
fn stopping_an_installed_app_that_is_not_running_is_a_clean_no_op() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);

    let output = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "stop", "sleeper"],
    );
    assert_success(&output);
    assert_stderr_contains(&output, "sleeper:default is not running");
}

/// The recorded pid is a number the operating system hands out again. A stop that finds
/// the process behind it gone says so and reconciles the record; it never signals.
#[test]
fn stopping_an_app_whose_supervisor_is_gone_signals_nothing_and_says_so() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    let work_dir = dirs.state.path().join("apps/sleeper/default");
    let dead = reaped_pid();
    write_supervisor_marker(&work_dir, dead);
    record_running(&dirs, "sleeper", dead);

    let output = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "stop", "sleeper"],
    );
    assert_success(&output);
    assert_stderr_contains(&output, &format!("(pid {dead}) is gone"));
    assert_stderr_contains(&output, "now recorded as stopped");
    assert_eq!(record(&dirs, "sleeper")["state"], "stopped");
    assert_eq!(record(&dirs, "sleeper")["pid_service"], json!(null));
}

/// A record claiming a run with no marker to back it is the same answer: this machine is
/// not supervising the app, so nothing is signalled on the strength of the number alone.
#[test]
fn stopping_an_app_with_no_supervisor_recorded_reconciles_the_record() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    record_running(&dirs, "sleeper", reaped_pid());

    let output = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "stop", "sleeper"],
    );
    assert_success(&output);
    assert_stderr_contains(&output, "now recorded as stopped");
    assert_eq!(record(&dirs, "sleeper")["state"], "stopped");
}

/// A foreground app belongs to the process supervising it, and that is not this one.
#[test]
fn uninstalling_a_running_foreground_app_refuses() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    let work_dir = dirs.state.path().join("apps/sleeper/default");
    let pid = reaped_pid();
    write_supervisor_marker(&work_dir, pid);
    record_running(&dirs, "sleeper", pid);
    // The supervisor is gone, but the record still says running, which is the state an
    // uninstall must refuse rather than remove files underneath.
    let output = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "uninstall", "sleeper"],
    );
    assert_eq!(output.status.code(), Some(5), "{}", output_text(&output));
    assert_stderr_contains(&output, "stop it before uninstall");
}

#[test]
fn detaching_a_foreground_app_is_still_refused() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    let output = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "start",
            "--detach",
            "sleeper",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
    assert_stderr_contains(&output, "--detach is not implemented yet");
}

/// The whole loop: a foreground start in one process, a stop in another, and the
/// termination flow running where the app actually is.
#[cfg(unix)]
#[test]
fn stopping_a_running_foreground_app_runs_the_whole_termination_flow() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    let work_dir = dirs.state.path().join("apps/sleeper/default");
    let started = start_in_background(&dirs, "sleeper", &work_dir);

    // While it runs, the status table names the process an operator would have to reach
    // to stop it: the supervisor, not the app's own child.
    let status = run_orc(&dirs, &["status", "sleeper", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["mode"], "process");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["pid_service"], started.pid.to_string());

    let stop = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "stop", "sleeper"],
    );
    let supervisor = started.wait();
    assert_success(&stop);
    assert!(
        supervisor.success(),
        "the supervisor exited {supervisor:?}\n{}",
        output_text(&stop)
    );
    assert_stderr_contains(&stop, "Asked the supervisor of sleeper:default");
    assert_stderr_contains(&stop, "Stopped sleeper:default");
    // The stop command ran while the app was still up, and the stopped hook was told it
    // had gone well.
    assert_eq!(
        std::fs::read_to_string(work_dir.join("steps.txt")).expect("steps"),
        "stop\nstopped:ok\n"
    );
    assert_eq!(record(&dirs, "sleeper")["state"], "stopped");
    assert_eq!(record(&dirs, "sleeper")["pid_service"], json!(null));
    assert!(!work_dir.join(".orc-supervisor.json").exists());
}

/// `--force` is the loud path: no stop command, no grace period, and the stopped hook is
/// told the stop command never decided anything.
#[cfg(unix)]
#[test]
fn forcing_a_stop_skips_the_stop_command() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    let work_dir = dirs.state.path().join("apps/sleeper/default");
    let started = start_in_background(&dirs, "sleeper", &work_dir);

    let stop = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "stop",
            "sleeper",
            "--force",
        ],
    );
    let supervisor = started.wait();
    assert_success(&stop);
    assert!(supervisor.success(), "the supervisor exited {supervisor:?}");
    assert_stderr_contains(&stop, "skipping the stop command and the grace period");
    assert_eq!(
        std::fs::read_to_string(work_dir.join("steps.txt")).expect("steps"),
        "stopped:skipped\n"
    );
    assert_eq!(record(&dirs, "sleeper")["state"], "stopped");
}

/// An app whose stop command takes its time, so a second ask has something to interrupt.
const SLOW_STOP_RECIPE: &str = r#"
artifactType: application/vnd.orc8r.app.v1
config:
  start:
    command: |
      printf running > running.txt
      while true; do sleep 0.2; done
  stop:
    command: |
      printf "stop-start\n" >> steps.txt
      sleep 20
      printf "stop-end\n" >> steps.txt
    timeout: 60s
    grace: 5s
  stopped:
    command: |
      printf "stopped:$APP_STOP_STATUS\n" >> steps.txt
"#;

/// The second ask is the operator saying "now": the stop command it interrupts never
/// finishes, and the app is ended immediately rather than waited out.
#[cfg(unix)]
#[test]
fn a_second_stop_ends_an_app_that_is_still_quiescing() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "slowpoke", SLOW_STOP_RECIPE);
    let work_dir = dirs.state.path().join("apps/slowpoke/default");
    let started = start_in_background(&dirs, "slowpoke", &work_dir);

    let first = {
        let state = dirs.state.path().to_path_buf();
        let cache = dirs.cache.path().to_path_buf();
        let config = dirs.config.path().to_path_buf();
        std::thread::spawn(move || {
            Command::new(env!("CARGO_BIN_EXE_orc"))
                .args(["--registry", UNREACHABLE_PREFIX, "stop", "slowpoke"])
                .env("ORC_CACHE_DIR", cache)
                .env("ORC_STATE_DIR", state)
                .env("ORC_CONFIG_DIR", config)
                .output()
                .expect("run orc stop")
        })
    };
    let steps_path = work_dir.join("steps.txt");
    wait_until("the stop command to be running", || {
        std::fs::read_to_string(&steps_path).is_ok_and(|steps| steps.contains("stop-start"))
    });

    let second = run_orc(
        &dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "stop",
            "slowpoke",
            "--force",
        ],
    );
    let supervisor = started.wait();
    let first = first.join().expect("join the first stop");
    assert_success(&first);
    assert_success(&second);
    assert!(supervisor.success(), "the supervisor exited {supervisor:?}");
    // The stop command was cut short where it stood, and the stopped hook was told the
    // app's own stop never got to say it was safe.
    assert_eq!(
        std::fs::read_to_string(&steps_path).expect("steps"),
        "stop-start\nstopped:failed\n"
    );
    assert_eq!(record(&dirs, "slowpoke")["state"], "stopped");
}

/// A stopped foreground app uninstalls like any other, and takes its files with it.
#[cfg(unix)]
#[test]
fn uninstalling_after_a_foreground_stop_removes_everything() {
    let dirs = TestDirs::new();
    build_and_install(&dirs, "sleeper", SLEEPER_RECIPE);
    let work_dir = dirs.state.path().join("apps/sleeper/default");
    let started = start_in_background(&dirs, "sleeper", &work_dir);
    let stop = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "stop", "sleeper"],
    );
    started.wait();
    assert_success(&stop);

    let uninstall = run_orc(
        &dirs,
        &["--registry", UNREACHABLE_PREFIX, "uninstall", "sleeper"],
    );
    assert_success(&uninstall);
    assert!(!work_dir.exists());
    let status = run_orc(&dirs, &["status", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows, json!([]));
}

// ─── harness ────────────────────────────────────────────────────────────────────

struct TestDirs {
    cache: tempfile::TempDir,
    state: tempfile::TempDir,
    config: tempfile::TempDir,
    logs: tempfile::TempDir,
}

impl TestDirs {
    fn new() -> Self {
        Self {
            cache: tempfile::tempdir().expect("cache dir"),
            state: tempfile::tempdir().expect("state dir"),
            config: tempfile::tempdir().expect("config dir"),
            logs: tempfile::tempdir().expect("log dir"),
        }
    }
}

/// A foreground `orc start` running in the background of this test, reaped on its own
/// thread so the stop under test never waits on a zombie.
struct Background {
    pid: u32,
    waiter: std::thread::JoinHandle<std::process::ExitStatus>,
}

impl Background {
    fn wait(self) -> std::process::ExitStatus {
        self.waiter.join().expect("join the supervisor")
    }
}

fn orc_command(dirs: &TestDirs, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_orc"));
    command
        .args(args)
        .env("ORC_CACHE_DIR", dirs.cache.path())
        .env("ORC_STATE_DIR", dirs.state.path())
        .env("ORC_CONFIG_DIR", dirs.config.path());
    command
}

fn run_orc(dirs: &TestDirs, args: &[&str]) -> Output {
    orc_command(dirs, args).output().expect("run orc")
}

/// Builds the package from its recipe into the local cache and installs it, with no
/// registry involved at any point.
fn build_and_install(dirs: &TestDirs, app: &str, recipe: &str) {
    let package = tempfile::tempdir().expect("package dir");
    std::fs::write(package.path().join("artifact.yaml"), recipe).expect("recipe");
    let build = run_orc(
        dirs,
        &[
            "--registry",
            UNREACHABLE_PREFIX,
            "build",
            package.path().to_str().expect("package path"),
            "--tag",
            app,
        ],
    );
    assert_success(&build);
    let install = run_orc(dirs, &["--registry", UNREACHABLE_PREFIX, "install", app]);
    assert_success(&install);
}

/// Starts the app in the foreground in another process and waits until it is up: the
/// app has written its own marker file and the install record says it is running.
fn start_in_background(dirs: &TestDirs, app: &str, work_dir: &Path) -> Background {
    let out = std::fs::File::create(dirs.logs.path().join("start.out")).expect("start log");
    let err = out.try_clone().expect("clone start log");
    let child = orc_command(dirs, &["--registry", UNREACHABLE_PREFIX, "start", app])
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn orc start");
    let running = work_dir.join("running.txt");
    let record_path = record_path(dirs, app);
    wait_until("the app to be running", || {
        running.exists() && record_state(&record_path).as_deref() == Some("running")
    });
    Background {
        pid: child.id(),
        waiter: std::thread::spawn(move || {
            let mut child = child;
            child.wait().expect("wait for orc start")
        }),
    }
}

/// A process id that is certainly not in use: a child that has already been reaped.
fn reaped_pid() -> u32 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_orc"))
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn a short-lived process");
    let pid = child.id();
    child.wait().expect("reap it");
    pid
}

fn write_supervisor_marker(work_dir: &Path, pid: u32) {
    std::fs::write(
        work_dir.join(".orc-supervisor.json"),
        serde_json::to_vec(&json!({"pid": pid})).expect("marker json"),
    )
    .expect("write marker");
}

fn record_path(dirs: &TestDirs, app: &str) -> PathBuf {
    dirs.state
        .path()
        .join("installs")
        .join(app)
        .join("default.json")
}

fn record(dirs: &TestDirs, app: &str) -> serde_json::Value {
    let body = std::fs::read(record_path(dirs, app)).expect("read install record");
    serde_json::from_slice(&body).expect("install record json")
}

fn record_state(path: &Path) -> Option<String> {
    let body = std::fs::read(path).ok()?;
    let record: serde_json::Value = serde_json::from_slice(&body).ok()?;
    record["state"].as_str().map(str::to_owned)
}

/// Rewrites an install record as a run in progress under `pid`.
fn record_running(dirs: &TestDirs, app: &str, pid: u32) {
    let path = record_path(dirs, app);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read record")).expect("record json");
    record["state"] = json!("running");
    record["pid_service"] = json!(pid.to_string());
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&record).expect("record json"),
    )
    .expect("write record");
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\n{}",
        output.status.code(),
        output_text(output)
    );
}

fn assert_stderr_contains(output: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected), "missing {expected:?}\n{stderr}");
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
