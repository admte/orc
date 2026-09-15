//! `orc install` across phase-requested reboots.
//!
//! The install scripts here call `shutdown -r now` exactly as a real one would; the
//! runtime's shim intercepts it, and `ORC_REBOOT_EXEC=fake:<path>` records the reboot
//! instead of taking the machine away, so one test process can drive several cycles.
//! `ORC_RESUME_HOOK_ROOT` puts the boot hook under a temporary root instead of `/etc`.
//!
//! Unix only: the scripts are `sh`, and the shim a phase reaches on Windows is
//! `shutdown.cmd` under `PowerShell`.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const UNREACHABLE_PREFIX: &str = "127.0.0.1:1/acme";
const APP: &str = "reboot-app";

/// An install that asks for the machine once, then converges on the next pass.
const REBOOT_ONCE: u32 = 1;
/// Two reboots, then convergence.
const REBOOT_TWICE: u32 = 2;

/// Install script body shared by the cycle tests: counts its own passes in the work dir
/// (which survives the "reboot", exactly as a real app's install state would) and asks for
/// a restart until it has had `reboots` of them.
fn cycle_script(reboots: u32) -> String {
    format!(
        r#"
      count=0
      [ -f cycles ] && count=$(cat cycles)
      count=$((count + 1))
      printf '%s' "$count" > cycles
      if [ "$count" -le {reboots} ]; then
        printf 'pass %s: restarting\n' "$count"
        shutdown -r now
        exit 0
      fi
      printf 'pass %s: converged\n' "$count"
      printf installed > installed.txt
"#
    )
}

/// An install that never settles: it asks on every pass and tolerates a refusal, which is
/// what the reboot cap is for.
const ALWAYS_REBOOT_SCRIPT: &str = r"
      shutdown -r now || printf refused > refused.txt
      printf installed > installed.txt
";

#[test]
fn an_install_that_asks_for_a_reboot_leaves_a_hook_and_a_marker_but_no_record() {
    let dirs = TestDirs::new();
    build_app(&dirs, &cycle_script(REBOOT_ONCE));

    let install = run_orc(&dirs, &["install", APP]);
    assert_success(&install);
    assert_stderr_contains(&install, "requested a reboot (1/5)");
    assert_stderr_contains(&install, "continues automatically after the restart");

    // The hook is what makes the promise in that message true.
    let hook = std::fs::read_to_string(dirs.hook_file()).expect("boot hook");
    assert!(hook.contains("--resume"), "{hook}");
    #[cfg(target_os = "linux")]
    {
        assert!(hook.contains("Type=oneshot"), "{hook}");
        assert!(hook.contains("install --resume"), "{hook}");
        assert!(hook.contains("WantedBy=multi-user.target"), "{hook}");
        assert!(
            hook.contains(&format!(
                "Environment=\"ORC_STATE_DIR={}\"",
                dirs.state.path().display()
            )),
            "the hook must resume against the same state dir\n{hook}"
        );
    }

    let marker = dirs.resume_marker().expect("resume marker");
    assert_eq!(marker["record"]["app"], APP);
    assert_eq!(marker["record"]["state"], "pending-reboot");
    assert_eq!(marker["reboot_count"], 1);

    // An interrupted install is not an installed app.
    assert!(!dirs.install_record_path().exists(), "no install record");
    assert_eq!(
        dirs.reboots(),
        1,
        "the executor was handed the machine once"
    );

    // ...and `orc status` says so, without inventing a row for an app that is not there.
    let status = run_orc(&dirs, &["status", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows.as_array().expect("rows").len(), 0);
    assert_stderr_contains(&status, &format!("{APP}:default is pending-reboot"));
}

#[test]
fn resume_finishes_the_install_and_clears_the_hook() {
    let dirs = TestDirs::new();
    build_app(&dirs, &cycle_script(REBOOT_ONCE));
    assert_success(&run_orc(&dirs, &["install", APP]));

    let resume = run_orc(&dirs, &["install", "--resume"]);
    assert_success(&resume);
    assert_stderr_contains(&resume, "Resuming the install of reboot-app:default");
    assert_stderr_contains(&resume, "continued across 1 reboot(s)");
    assert!(
        String::from_utf8_lossy(&resume.stdout).contains("pass 2: converged"),
        "the phase re-runs from the top\n{}",
        output_text(&resume)
    );

    // The app's own convergence marker, written by the second pass.
    assert!(
        dirs.state
            .path()
            .join("apps/reboot-app/default/installed.txt")
            .exists()
    );

    // Nothing is left waiting: no marker, no hook, and now a real install record.
    assert!(dirs.resume_marker().is_none(), "resume marker retired");
    assert!(!dirs.hook_file().exists(), "boot hook retired");
    assert!(
        !dirs.phase_marker_path().exists(),
        "the phase counter is retired on convergence"
    );
    let record = dirs.install_record().expect("install record");
    assert_eq!(record["state"], "stopped");
    assert_eq!(record["app"], APP);
    assert_eq!(dirs.reboots(), 1);

    let status = run_orc(&dirs, &["status", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows[0]["app"], APP);
    assert_stderr_not_contains(&status, "pending-reboot");
}

#[test]
fn an_install_survives_two_reboots_under_one_counter() {
    let dirs = TestDirs::new();
    build_app(&dirs, &cycle_script(REBOOT_TWICE));

    assert_success(&run_orc(&dirs, &["install", APP]));
    assert_eq!(
        dirs.phase_marker().expect("phase marker")["reboot_count"],
        1
    );

    // The hook fired and (on Windows) deleted itself; every cycle re-registers it.
    std::fs::remove_file(dirs.hook_file()).expect("simulate a one-shot hook firing");
    let second = run_orc(&dirs, &["install", "--resume"]);
    assert_success(&second);
    assert_stderr_contains(&second, "requested a reboot (2/5)");
    assert!(
        dirs.hook_file().exists(),
        "the hook is re-registered for the second cycle"
    );
    assert_eq!(
        dirs.phase_marker().expect("phase marker")["reboot_count"],
        2
    );
    assert!(!dirs.install_record_path().exists(), "still not installed");

    let third = run_orc(&dirs, &["install", "--resume"]);
    assert_success(&third);
    assert!(
        String::from_utf8_lossy(&third.stdout).contains("pass 3: converged"),
        "{}",
        output_text(&third)
    );
    assert_eq!(dirs.reboots(), 2, "one reboot per cycle, and no more");
    assert!(dirs.resume_marker().is_none());
    assert!(!dirs.hook_file().exists());
    assert!(!dirs.phase_marker_path().exists());
    assert_eq!(dirs.install_record().expect("record")["state"], "stopped");
}

#[test]
fn the_reboot_cap_holds_across_resumes() {
    let dirs = TestDirs::new();
    build_app(&dirs, ALWAYS_REBOOT_SCRIPT);

    assert_success(&run_orc(&dirs, &["install", APP]));
    for cycle in 2..=5 {
        let resume = run_orc(&dirs, &["install", "--resume"]);
        assert_success(&resume);
        assert_stderr_contains(&resume, &format!("requested a reboot ({cycle}/5)"));
    }
    assert_eq!(dirs.reboots(), 5, "the cap is five reboots per execution");

    // The sixth pass has no budget: the shim refuses the request in the phase's own log,
    // the script carries on, and the install completes on its own merits.
    let last = run_orc(&dirs, &["install", "--resume"]);
    assert_success(&last);
    assert_stderr_contains(&last, "spent its reboot budget (5/5)");
    assert_stderr_contains(&last, "orc: reboot budget exhausted; request refused");
    assert_eq!(dirs.reboots(), 5, "no sixth reboot");
    assert!(
        dirs.state
            .path()
            .join("apps/reboot-app/default/refused.txt")
            .exists(),
        "the script saw the refusal"
    );
    assert!(dirs.resume_marker().is_none());
    assert!(!dirs.hook_file().exists());
    assert!(!dirs.phase_marker_path().exists());
    assert_eq!(dirs.install_record().expect("record")["state"], "stopped");
}

#[test]
fn a_resume_whose_phase_fails_reports_it_and_stops_retrying_at_boot() {
    let dirs = TestDirs::new();
    // Reboots once, then fails: a hook left behind would repeat that failure unattended
    // at every boot for the rest of the machine's life.
    build_app(
        &dirs,
        r"
      if [ ! -f cycles ]; then
        printf done > cycles
        shutdown -r now
        exit 0
      fi
      echo 'the install cannot finish' >&2
      exit 3
",
    );
    assert_success(&run_orc(&dirs, &["install", APP]));

    let resume = run_orc(&dirs, &["install", "--resume"]);
    assert!(!resume.status.success(), "{}", output_text(&resume));
    assert_stderr_contains(&resume, "the install cannot finish");
    assert!(dirs.resume_marker().is_none(), "resume marker retired");
    assert!(!dirs.hook_file().exists(), "boot hook retired");
    assert!(!dirs.install_record_path().exists(), "nothing installed");
}

#[test]
fn resume_with_nothing_pending_is_a_clean_no_op() {
    let dirs = TestDirs::new();
    let resume = run_orc(&dirs, &["install", "--resume"]);
    assert_success(&resume);
    assert_stderr_contains(&resume, "Nothing to resume");
    assert!(!dirs.hook_file().exists());
}

#[test]
fn a_marker_whose_parameters_drifted_refuses_to_resume() {
    let dirs = TestDirs::new();
    build_app(&dirs, &cycle_script(REBOOT_ONCE));
    assert_success(&run_orc(&dirs, &["install", APP]));

    // A marker that no longer describes the install it names — hand-edited here, a build
    // skew in the field — must not be run unattended at boot.
    let mut marker = dirs.resume_marker().expect("resume marker");
    marker["params"] = serde_json::json!(["--unexpected"]);
    std::fs::write(
        dirs.resume_marker_path(),
        serde_json::to_vec_pretty(&marker).expect("marker json"),
    )
    .expect("write marker");

    let resume = run_orc(&dirs, &["install", "--resume"]);
    assert_eq!(resume.status.code(), Some(5), "{}", output_text(&resume));
    assert_stderr_contains(&resume, "does not match its recorded parameters");
    assert_stderr_contains(&resume, "without --resume");
    assert!(!dirs.install_record_path().exists(), "nothing installed");
}

#[test]
fn an_unregisterable_hook_refuses_to_reboot_at_all() {
    let dirs = TestDirs::new();
    build_app(&dirs, &cycle_script(REBOOT_ONCE));
    // A hook root that is a file, not a directory: the same shape as an /etc no
    // unprivileged caller may write.
    let blocked = dirs.work.path().join("blocked-root");
    std::fs::write(&blocked, "not a directory").expect("blocker");

    let install = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["--registry", UNREACHABLE_PREFIX, "install", APP])
        .env("ORC_CACHE_DIR", dirs.cache.path())
        .env("ORC_STATE_DIR", dirs.state.path())
        .env("ORC_CONFIG_DIR", dirs.config.path())
        .env(
            "ORC_REBOOT_EXEC",
            format!("fake:{}", dirs.reboots_path().display()),
        )
        .env("ORC_RESUME_HOOK_ROOT", &blocked)
        .output()
        .expect("run orc");

    assert!(!install.status.success(), "{}", output_text(&install));
    assert_stderr_contains(&install, "boot hook");
    assert_stderr_contains(&install, "Nothing was restarted");
    // The machine must never go down without a hook to bring the install back...
    assert!(
        !dirs.reboots_path().exists(),
        "no reboot was executed\n{}",
        output_text(&install)
    );
    // ...and nothing is left claiming an install is in flight.
    assert!(dirs.resume_marker().is_none());
    assert!(!dirs.phase_marker_path().exists(), "the counter is cleared");
    assert!(!dirs.install_record_path().exists());
}

// ─── Harness ─────────────────────────────────────────────────────────────────────

struct TestDirs {
    cache: tempfile::TempDir,
    state: tempfile::TempDir,
    config: tempfile::TempDir,
    /// Fake-reboot log and the boot hook's temporary filesystem root.
    work: tempfile::TempDir,
}

impl TestDirs {
    fn new() -> Self {
        Self {
            cache: tempfile::tempdir().expect("cache dir"),
            state: tempfile::tempdir().expect("state dir"),
            config: tempfile::tempdir().expect("config dir"),
            work: tempfile::tempdir().expect("work dir"),
        }
    }

    fn hook_root(&self) -> PathBuf {
        self.work.path().join("hook-root")
    }

    fn hook_file(&self) -> PathBuf {
        let root = self.hook_root();
        #[cfg(target_os = "linux")]
        {
            root.join("etc/systemd/system/orc-install-resume.service")
        }
        #[cfg(target_os = "macos")]
        {
            root.join("Library/LaunchDaemons/com.orc8r.install-resume.plist")
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            root.join("runonce/orc-install-resume.cmd")
        }
    }

    fn reboots_path(&self) -> PathBuf {
        self.work.path().join("reboots")
    }

    /// How many reboots the fake executor was handed.
    fn reboots(&self) -> usize {
        std::fs::read_to_string(self.reboots_path())
            .map(|body| body.lines().count())
            .unwrap_or_default()
    }

    fn resume_marker_path(&self) -> PathBuf {
        self.state.path().join("install-resume.json")
    }

    fn resume_marker(&self) -> Option<serde_json::Value> {
        read_json(&self.resume_marker_path())
    }

    fn phase_marker_path(&self) -> PathBuf {
        self.state.path().join("phase-reboot.json")
    }

    fn phase_marker(&self) -> Option<serde_json::Value> {
        read_json(&self.phase_marker_path())
    }

    fn install_record_path(&self) -> PathBuf {
        self.state
            .path()
            .join("installs")
            .join(APP)
            .join("default.json")
    }

    fn install_record(&self) -> Option<serde_json::Value> {
        read_json(&self.install_record_path())
    }
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let body = std::fs::read(path).ok()?;
    Some(serde_json::from_slice(&body).expect("json"))
}

/// Builds and caches a one-file app whose install phase runs `script`.
fn build_app(dirs: &TestDirs, script: &str) {
    let package = tempfile::tempdir().expect("package");
    std::fs::write(package.path().join("README.md"), "payload\n").expect("payload");
    let indented = script.lines().fold(String::new(), |mut body, line| {
        body.push_str(line);
        body.push('\n');
        body
    });
    std::fs::write(
        package.path().join("artifact.yaml"),
        format!(
            "artifactType: application/vnd.orc8r.app.v1\n\
             annotations:\n  \
               org.opencontainers.image.title: {APP}\n\
             config:\n  \
               install:\n    \
                 command: |{indented}\
             files:\n  \
               - README.md\n"
        ),
    )
    .expect("recipe");

    let build = run_orc(
        dirs,
        &[
            "build",
            package.path().to_str().expect("package"),
            "--tag",
            APP,
        ],
    );
    assert_success(&build);
}

fn run_orc(dirs: &TestDirs, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_orc"));
    command
        .args(["--registry", UNREACHABLE_PREFIX])
        .args(args)
        .env("ORC_CACHE_DIR", dirs.cache.path())
        .env("ORC_STATE_DIR", dirs.state.path())
        .env("ORC_CONFIG_DIR", dirs.config.path())
        .env(
            "ORC_REBOOT_EXEC",
            format!("fake:{}", dirs.reboots_path().display()),
        )
        .env("ORC_RESUME_HOOK_ROOT", dirs.hook_root());
    command.output().expect("run orc")
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
    assert!(
        stderr.contains(expected),
        "missing {expected:?}\n{}",
        output_text(output)
    );
}

fn assert_stderr_not_contains(output: &Output, unexpected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(unexpected),
        "unexpected {unexpected:?}\n{}",
        output_text(output)
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
