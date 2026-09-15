//! Unit tests for the service contract and the systemd backend's generated text.

use super::*;

#[test]
fn bare_identifiers_are_accepted() {
    for name in [
        "jenkins-agent",
        "jenkins-agent-3.46",
        "python2",
        "app_one",
        "runner@1",
    ] {
        validate_identifier(name).unwrap_or_else(|err| panic!("{name} should be valid: {err}"));
    }
}

/// The suffix rejection is the one an author hits: the runtime adds `.service` itself,
/// so a package that spells it gets `foo.service.service`.
#[test]
fn platform_suffixes_are_rejected_with_the_name_to_use() {
    let err = validate_identifier("jenkins-agent.service").expect_err("suffixed");
    let message = err.to_string();
    assert!(message.contains(".service"), "{message}");
    assert!(message.contains("\"jenkins-agent\""), "{message}");
    assert!(validate_identifier("agent.plist").is_err());
    assert!(validate_identifier("agent.socket").is_err());
}

#[test]
fn path_separators_and_stray_characters_are_rejected() {
    for name in [
        "",
        "../escape",
        "etc/systemd/foo",
        r"windows\service",
        "-leading-dash",
        "has space",
        "quote\"d",
        "semi;colon",
    ] {
        assert!(
            validate_identifier(name).is_err(),
            "{name:?} should be rejected"
        );
    }
}

#[test]
fn platform_names_follow_the_platform() {
    let derived = platform_name("jenkins-agent");
    #[cfg(target_os = "linux")]
    assert_eq!(derived, "jenkins-agent.service");
    #[cfg(target_os = "macos")]
    assert_eq!(derived, "com.orc8r.app.jenkins-agent");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert_eq!(derived, "jenkins-agent");
}

/// `ExecMainStatus` is the exit code under `CLD_EXITED` and the signal number under
/// `CLD_KILLED`; read without the code, a service killed by signal 9 reads as a clean
/// exit 9 that never happened.
#[test]
fn si_code_decides_whether_the_status_is_a_code_or_a_signal() {
    assert_eq!(exit_from_si_code(1, 0), (Some(0), None));
    assert_eq!(exit_from_si_code(1, 3), (Some(3), None));
    assert_eq!(exit_from_si_code(2, 9), (None, Some(9)));
    assert_eq!(exit_from_si_code(3, 11), (None, Some(11)));
    assert_eq!(exit_from_si_code(0, 0), (None, None));
}

#[test]
fn restart_policies_are_a_closed_set() {
    assert_eq!(
        RestartPolicy::parse("never").expect("never"),
        RestartPolicy::Never
    );
    assert_eq!(
        RestartPolicy::parse("on-failure").expect("on-failure"),
        RestartPolicy::OnFailure
    );
    assert_eq!(
        RestartPolicy::parse("Always").expect("always"),
        RestartPolicy::Always
    );
    assert!(RestartPolicy::parse("sometimes").is_err());
}

#[test]
fn only_inactive_and_failed_end_the_wait() {
    assert!(ServiceState::Inactive.is_terminal());
    assert!(ServiceState::Failed.is_terminal());
    assert!(!ServiceState::Active.is_terminal());
    // The auto-restart window: a manager honoring its own restart policy must not read
    // as an app that ended.
    assert!(!ServiceState::Activating.is_terminal());
    assert!(!ServiceState::Unknown.is_terminal());
}

#[cfg(target_os = "linux")]
mod systemd_units {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::super::systemd::{
        GENERATED_MARKER, Systemd, is_generated, render_unit, status_from,
    };
    use super::*;
    use crate::process::StopSignal;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            name: "jenkins-agent.service".to_owned(),
            description: "ORC app jenkins-agent".to_owned(),
            exec: vec![
                "/usr/bin/orc-runtime".to_owned(),
                "app-exec".to_owned(),
                "--work-dir".to_owned(),
                "/var/lib/orc/apps/jenkins-agent".to_owned(),
                "--app".to_owned(),
                "jenkins-agent".to_owned(),
                "--instance".to_owned(),
                "jenkins-agent".to_owned(),
                "--version".to_owned(),
                "3.46".to_owned(),
            ],
            work_dir: PathBuf::from("/var/lib/orc/apps/jenkins-agent"),
            restart: RestartPolicy::OnFailure,
            kill_signal: StopSignal::Term,
            stop_timeout: Duration::from_secs(30),
        }
    }

    /// An app that fails at every single start must eventually be reported, not
    /// restarted forever. Manager-driven restarts are deliberately invisible to the
    /// runtime, so without a start limit systemd retries every five seconds for ever
    /// and the node stays online while the app has never once come up — which is what
    /// a real jenkins-agent misconfiguration did. The Windows service manager already
    /// gives up after three recovery actions; this is systemd told to match.
    #[test]
    fn a_unit_gives_up_restarting_so_a_broken_app_is_eventually_reported() {
        let unit = render_unit(&spec());
        assert!(
            unit.contains("StartLimitBurst=3"),
            "the manager must stop restarting after a few failures: {unit}"
        );
        assert!(
            unit.contains("StartLimitIntervalSec=3600"),
            "the failure count needs a window to decay over: {unit}"
        );
        // In `[Unit]`, not `[Service]`: systemd moved these and only warns about the
        // old placement, so a silently-ignored limit would look exactly like none.
        let unit_section = unit
            .split("[Service]")
            .next()
            .expect("the unit section comes first");
        assert!(
            unit_section.contains("StartLimitBurst="),
            "the limit belongs in [Unit] where systemd still reads it: {unit}"
        );
    }

    #[test]
    fn the_generated_unit_is_exactly_this() {
        assert_eq!(
            render_unit(&spec()),
            "# orc8r-runtime-managed\n\
             # Written by the ORC runtime; it is rewritten on every start and removed on\n\
             # uninstall. Never enabled for boot: the runtime decides what runs after a reboot.\n\
             [Unit]\n\
             Description=ORC app jenkins-agent\n\
             StartLimitIntervalSec=3600\n\
             StartLimitBurst=3\n\
             \n\
             [Service]\n\
             Type=simple\n\
             WorkingDirectory=/var/lib/orc/apps/jenkins-agent\n\
             ExecStart=\"/usr/bin/orc-runtime\" \"app-exec\" \"--work-dir\" \
             \"/var/lib/orc/apps/jenkins-agent\" \"--app\" \"jenkins-agent\" \"--instance\" \
             \"jenkins-agent\" \"--version\" \"3.46\"\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             KillMode=control-group\n\
             KillSignal=SIGTERM\n\
             TimeoutStopSec=30\n"
        );
    }

    /// A unit with no `[Install]` section cannot be enabled for boot even by hand,
    /// which is the property the contract asks for stated in the file itself.
    #[test]
    fn the_generated_unit_is_not_installable() {
        let unit = render_unit(&spec());
        assert!(!unit.contains("[Install]"), "{unit}");
        assert!(!unit.contains("WantedBy"), "{unit}");
        assert!(unit.starts_with(GENERATED_MARKER), "{unit}");
    }

    #[test]
    fn restart_policies_and_signals_reach_the_unit() {
        let mut never = spec();
        never.restart = RestartPolicy::Never;
        assert!(render_unit(&never).contains("\nRestart=no\n"));

        let mut always = spec();
        always.restart = RestartPolicy::Always;
        always.kill_signal = StopSignal::Int;
        always.stop_timeout = Duration::from_secs(90);
        let unit = render_unit(&always);
        assert!(unit.contains("\nRestart=always\n"), "{unit}");
        assert!(unit.contains("\nKillSignal=SIGINT\n"), "{unit}");
        assert!(unit.contains("\nTimeoutStopSec=90\n"), "{unit}");
    }

    /// `%` starts a systemd specifier. An app argument carrying one — a Windows-style
    /// path, a printf format — would otherwise be rewritten behind the app's back.
    #[test]
    fn specifiers_and_quotes_in_arguments_are_escaped() {
        let mut spec = spec();
        spec.description = "50% of the\nthing".to_owned();
        spec.exec = vec![
            "/opt/app".to_owned(),
            "--fmt=%H".to_owned(),
            "--say=\"hi\"".to_owned(),
            r"C:\dir".to_owned(),
        ];
        let unit = render_unit(&spec);
        assert!(unit.contains("Description=50%% of the thing\n"), "{unit}");
        assert!(
            unit.contains(
                "ExecStart=\"/opt/app\" \"--fmt=%%H\" \"--say=\\\"hi\\\"\" \"C:\\\\dir\"\n"
            ),
            "{unit}"
        );
    }

    #[tokio::test]
    async fn a_unit_the_runtime_did_not_write_is_not_removed() {
        let dir = tempfile::tempdir().expect("unit dir");
        let backend = Systemd::in_dir(dir.path().to_path_buf());
        let path = dir.path().join("jenkins-agent.service");
        std::fs::write(&path, "[Unit]\nDescription=hand written\n").expect("write unit");

        let err = backend
            .undefine("jenkins-agent.service")
            .await
            .expect_err("a foreign unit must not be removed");
        assert!(err.to_string().contains("not defined by this runtime"));
        assert!(path.exists(), "the operator's unit is still there");

        // Nothing to remove is the state the call is for, not an error.
        backend
            .undefine("absent.service")
            .await
            .expect("removing an absent unit succeeds");
    }

    #[test]
    fn generated_units_are_recognized_only_by_the_marker() {
        assert!(is_generated(&render_unit(&spec())));
        assert!(!is_generated("[Unit]\nDescription=hand written\n"));
        // The marker is only the marker on the first line: a comment further down is
        // something an operator wrote, not a claim of ownership.
        assert!(!is_generated(&format!("[Unit]\n{GENERATED_MARKER}\n")));
    }

    #[test]
    fn a_killed_service_is_read_as_a_signal_not_an_exit_code() {
        let properties = std::collections::HashMap::from([
            ("ExecMainCode", "2"),
            ("ExecMainStatus", "9"),
            ("ExecMainPID", "0"),
            ("NRestarts", "3"),
        ]);
        let status = status_from("failed", "failed", &|name| {
            properties.get(name).map(|value| (*value).to_owned())
        });
        assert_eq!(status.state, ServiceState::Failed);
        assert_eq!(status.exit_signal, Some(9));
        assert_eq!(status.exit_code, None);
        assert_eq!(status.main_pid, None);
        assert_eq!(status.restarts, 3);
    }

    #[test]
    fn a_running_service_reports_its_main_pid() {
        let properties = std::collections::HashMap::from([
            ("ExecMainCode", "0"),
            ("ExecMainStatus", "0"),
            ("ExecMainPID", "4242"),
        ]);
        let status = status_from("active", "running", &|name| {
            properties.get(name).map(|value| (*value).to_owned())
        });
        assert_eq!(status.state, ServiceState::Active);
        assert_eq!(status.main_pid, Some(4242));
    }

    /// The auto-restart window systemd reports while it honors `Restart=`. Reading it
    /// as inactive would report an app failure the manager is already fixing.
    #[test]
    fn the_auto_restart_window_is_not_terminal() {
        let none = |_: &str| None;
        assert_eq!(
            status_from("inactive", "auto-restart", &none).state,
            ServiceState::Activating
        );
        assert_eq!(
            status_from("activating", "start", &none).state,
            ServiceState::Activating
        );
        assert_eq!(
            status_from("inactive", "dead", &none).state,
            ServiceState::Inactive
        );
        assert_eq!(
            status_from("deactivating", "stop-sigterm", &none).state,
            ServiceState::Active
        );
    }

    /// REAL SYSTEMD: runs only where a systemd user manager answers, so a container or
    /// a non-systemd host skips it rather than failing. It exercises the `systemctl
    /// show` parsing against the real binary; defining and starting a unit needs root
    /// and is validated on a node, not here.
    #[tokio::test]
    async fn status_of_an_absent_unit_reads_as_inactive_on_a_real_systemd() {
        let available = tokio::process::Command::new("systemctl")
            .arg("--user")
            .arg("is-system-running")
            .output()
            .await
            .is_ok();
        if !available {
            eprintln!("skipped: no systemctl on this host");
            return;
        }
        let backend = Systemd::in_dir(std::path::PathBuf::from("/etc/systemd/system"));
        let status = backend
            .status("orc-does-not-exist-test.service")
            .await
            .expect("querying an absent unit is not an error");
        assert!(
            matches!(status.state, ServiceState::Inactive | ServiceState::Unknown),
            "{:?}",
            status.state
        );
        assert_eq!(status.main_pid, None);
    }
}
