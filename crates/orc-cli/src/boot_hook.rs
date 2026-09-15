//! The one-shot boot hook that carries an interrupted installation across a reboot.
//!
//! When an install phase asks for the machine, the CLI has to arrange its own return:
//! nothing else will re-invoke it after the restart. The arrangement is one entry in the
//! platform's native "run this at boot" facility — a systemd oneshot unit, a `RunOnce`
//! registry value, a `LaunchDaemon` — whose command is `<this exe> install --resume`.
//!
//! Two properties matter more than the platform details:
//!
//! * **The hook is written before the machine goes down.** A reboot taken without a
//!   registered hook strands the install, so a registration that fails is a hard error
//!   and the restart never happens.
//! * **The hook is re-registered on every cycle.** Windows' `RunOnce` deletes its value
//!   as it fires, so a phase that reboots twice needs two registrations; running the same
//!   code on all three platforms (`systemctl enable` and a file write are both idempotent)
//!   keeps one path instead of three, and repairs a unit removed by hand between cycles.
//!
//! The content builders are pure and unit-tested on every platform; only registration is
//! platform-specific, and it is a file write plus at most one service-manager call.

#![allow(clippy::missing_errors_doc)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{CliError, Result};

/// Filesystem root the hook is written under. Unset in production, where the hook goes to
/// its real absolute location; set by the test suite to a temporary tree, which also
/// suppresses the service-manager call that could not work under a fake root.
pub const HOOK_ROOT_ENV: &str = "ORC_RESUME_HOOK_ROOT";

/// systemd unit name (Linux).
#[cfg(target_os = "linux")]
const UNIT_NAME: &str = "orc-install-resume.service";
/// Unit path relative to the filesystem root.
#[cfg(target_os = "linux")]
const UNIT_RELATIVE: &str = "etc/systemd/system/orc-install-resume.service";
/// `LaunchDaemon` label; part of the plist, so it is built on every platform.
#[cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "the three hook formats are built on every platform so each stays unit-tested wherever the suite runs; only the matching one is registered"
    )
)]
const LAUNCHD_LABEL: &str = "com.orc8r.install-resume";
/// `LaunchDaemon` path relative to the filesystem root (macOS).
#[cfg(target_os = "macos")]
const LAUNCHD_RELATIVE: &str = "Library/LaunchDaemons/com.orc8r.install-resume.plist";
/// `RunOnce` key and value name (Windows).
#[cfg(target_os = "windows")]
const RUNONCE_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
#[cfg(target_os = "windows")]
const RUNONCE_VALUE: &str = "orc-install-resume";
/// Where a rooted (test) Windows registration records the command instead.
#[cfg(target_os = "windows")]
const RUNONCE_RELATIVE: &str = "runonce/orc-install-resume.cmd";

/// Environment the hook must reproduce for the resumed CLI to find the same state.
///
/// The hook runs as root at boot, out of any user session: the installing user's `HOME` —
/// and therefore the `StateDir` holding the resume marker — is not something the boot
/// context would derive on its own. Carrying the values the current process resolved is
/// what makes `sudo orc install` resumable at all.
const CARRIED_ENV: [&str; 4] = ["ORC_STATE_DIR", "ORC_CACHE_DIR", "ORC_CONFIG_DIR", "HOME"];

/// What the hook re-invokes: this executable, plus the environment the resumed run needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSpec {
    exe: PathBuf,
    /// Sorted `(name, value)` pairs, so a regenerated hook is byte-identical.
    env: Vec<(String, String)>,
}

impl HookSpec {
    /// Reads the spec from the running process.
    pub fn from_env() -> Result<Self> {
        let exe = std::env::current_exe().map_err(|err| {
            CliError::Operational(format!("locate this executable for the boot hook: {err}"))
        })?;
        let mut env: Vec<(String, String)> = CARRIED_ENV
            .iter()
            .filter_map(|name| {
                std::env::var(name)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(|value| ((*name).to_owned(), value))
            })
            .collect();
        env.sort();
        Ok(Self { exe, env })
    }

    /// The command line the hook runs, as argv.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(
            dead_code,
            reason = "the three hook formats are built on every platform so each stays unit-tested wherever the suite runs; only the matching one is registered"
        )
    )]
    fn argv(&self) -> Vec<String> {
        vec![
            self.exe.display().to_string(),
            "install".to_owned(),
            "--resume".to_owned(),
        ]
    }
}

// ─── Content builders (pure; tested on every platform) ───────────────────────────

/// The systemd oneshot unit. `network-online.target` because an app's install phase may
/// well want the network the moment it resumes; `multi-user.target` because the resume
/// must not wait for a graphical or user session that a server never reaches.
#[must_use]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the three hook formats are built on every platform so each stays unit-tested wherever the suite runs; only the matching one is registered"
    )
)]
pub fn systemd_unit(spec: &HookSpec) -> String {
    let mut unit = String::from(
        "[Unit]\n\
         Description=Resume an ORC app installation interrupted by a reboot\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n",
    );
    for (name, value) in &spec.env {
        let _ = writeln!(unit, "Environment=\"{name}={value}\"");
    }
    let _ = write!(
        unit,
        "ExecStart={} install --resume\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        spec.exe.display()
    );
    unit
}

/// The `RunOnce` command string. With no environment to carry it is the bare command;
/// otherwise `cmd.exe` sets the variables first, in the `set "K=V"` form that survives
/// paths with spaces and ampersands.
#[must_use]
#[cfg_attr(
    not(target_os = "windows"),
    allow(
        dead_code,
        reason = "the three hook formats are built on every platform so each stays unit-tested wherever the suite runs; only the matching one is registered"
    )
)]
pub fn runonce_command(spec: &HookSpec) -> String {
    let command = format!("\"{}\" install --resume", spec.exe.display());
    if spec.env.is_empty() {
        return command;
    }
    let sets = spec
        .env
        .iter()
        .fold(String::new(), |mut sets, (name, value)| {
            let _ = write!(sets, "set \"{name}={value}\" && ");
            sets
        });
    format!("cmd.exe /c \"{sets}{command}\"")
}

/// The `LaunchDaemon` plist. `RunAtLoad` with no `KeepAlive`: launchd runs it once when it
/// loads the daemon at boot, which is exactly the one-shot semantics of the other two.
#[must_use]
#[cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "the three hook formats are built on every platform so each stays unit-tested wherever the suite runs; only the matching one is registered"
    )
)]
pub fn launchd_plist(spec: &HookSpec) -> String {
    let mut plist = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n",
    );
    let _ = writeln!(
        plist,
        "  <key>Label</key>\n  <string>{LAUNCHD_LABEL}</string>"
    );
    plist.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    for argument in spec.argv() {
        let _ = writeln!(plist, "    <string>{}</string>", xml_escape(&argument));
    }
    plist.push_str("  </array>\n");
    if !spec.env.is_empty() {
        plist.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
        for (name, value) in &spec.env {
            let _ = writeln!(
                plist,
                "    <key>{}</key>\n    <string>{}</string>",
                xml_escape(name),
                xml_escape(value)
            );
        }
        plist.push_str("  </dict>\n");
    }
    plist.push_str("  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n");
    plist
}

#[cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "the three hook formats are built on every platform so each stays unit-tested wherever the suite runs; only the matching one is registered"
    )
)]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ─── Registration ────────────────────────────────────────────────────────────────

/// Alternate filesystem root for the hook, when the test suite named one.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn hook_root() -> Option<PathBuf> {
    std::env::var_os(HOOK_ROOT_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Absolute path of a hook file, honoring the test root.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn hook_path(relative: &str) -> PathBuf {
    match hook_root() {
        Some(root) => root.join(relative),
        None => Path::new("/").join(relative),
    }
}

/// Human-readable name of the hook this platform registers, for the operator-facing
/// message that promises the install continues after the restart.
#[must_use]
pub fn describe() -> String {
    #[cfg(target_os = "linux")]
    {
        format!("systemd unit {}", hook_path(UNIT_RELATIVE).display())
    }
    #[cfg(target_os = "macos")]
    {
        format!("LaunchDaemon {}", hook_path(LAUNCHD_RELATIVE).display())
    }
    #[cfg(target_os = "windows")]
    {
        match hook_root() {
            Some(_) => format!("RunOnce file {}", hook_path(RUNONCE_RELATIVE).display()),
            None => format!("registry value {RUNONCE_KEY}\\{RUNONCE_VALUE}"),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "boot hook".to_owned()
    }
}

/// Registers the hook so the next boot re-invokes `orc install --resume`.
///
/// Failure is always reported with the file (or key) it could not write: the caller must
/// not reboot without it, and an operator who ran the install unprivileged needs to know
/// exactly which path wants root.
#[cfg(target_os = "linux")]
pub fn register(spec: &HookSpec) -> Result<()> {
    let path = hook_path(UNIT_RELATIVE);
    write_hook_file(&path, systemd_unit(spec).as_bytes())?;
    if hook_root().is_some() {
        return Ok(());
    }
    // `enable` is idempotent, so re-registering a cycle later is a no-op symlink; a
    // failure here would leave a unit nothing starts, so the file goes back out.
    for arguments in [vec!["daemon-reload"], vec!["enable", UNIT_NAME]] {
        if let Err(err) = run_tool("systemctl", &arguments) {
            let _ = std::fs::remove_file(&path);
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn register(spec: &HookSpec) -> Result<()> {
    // A LaunchDaemon with `RunAtLoad` in /Library/LaunchDaemons is loaded by launchd at
    // boot on its own. Deliberately not bootstrapped here: that would run the resume
    // immediately, in the middle of the pass that is still asking for the reboot.
    write_hook_file(&hook_path(LAUNCHD_RELATIVE), launchd_plist(spec).as_bytes())
}

#[cfg(target_os = "windows")]
pub fn register(spec: &HookSpec) -> Result<()> {
    let command = runonce_command(spec);
    if hook_root().is_some() {
        return write_hook_file(&hook_path(RUNONCE_RELATIVE), command.as_bytes());
    }
    run_tool(
        "reg",
        &[
            "add",
            RUNONCE_KEY,
            "/v",
            RUNONCE_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            &command,
            "/f",
        ],
    )
    .map_err(|err| {
        CliError::Operational(format!(
            "write the boot hook {RUNONCE_KEY}\\{RUNONCE_VALUE}: {err}"
        ))
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn register(_spec: &HookSpec) -> Result<()> {
    Err(CliError::Operational(
        "this platform has no boot hook, so an installation cannot continue across a reboot"
            .to_owned(),
    ))
}

/// Retires the hook. Idempotent by contract: a hook that is already gone — never
/// registered, fired and self-deleted, removed by hand — is success, because the state
/// the caller wants is the state it is in.
#[cfg(target_os = "linux")]
pub fn unregister() -> Result<()> {
    if hook_root().is_none() {
        // Best-effort: `disable` fails loudly for a unit that was never enabled, which is
        // precisely the case this must treat as done.
        let _ = run_tool("systemctl", &["disable", UNIT_NAME]);
    }
    remove_hook_file(&hook_path(UNIT_RELATIVE))?;
    if hook_root().is_none() {
        let _ = run_tool("systemctl", &["daemon-reload"]);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn unregister() -> Result<()> {
    if hook_root().is_none() {
        let _ = run_tool(
            "launchctl",
            &["bootout", &format!("system/{LAUNCHD_LABEL}")],
        );
    }
    remove_hook_file(&hook_path(LAUNCHD_RELATIVE))
}

#[cfg(target_os = "windows")]
pub fn unregister() -> Result<()> {
    if hook_root().is_some() {
        return remove_hook_file(&hook_path(RUNONCE_RELATIVE));
    }
    // `RunOnce` deletes its own value as it fires, so a missing value is the normal case.
    let _ = run_tool("reg", &["delete", RUNONCE_KEY, "/v", RUNONCE_VALUE, "/f"]);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn unregister() -> Result<()> {
    Ok(())
}

/// Writes one hook file, naming it in every failure.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn write_hook_file(path: &Path, body: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            CliError::Operational(format!(
                "create the boot hook directory {}: {err}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(path, body).map_err(|err| {
        CliError::Operational(format!("write the boot hook {}: {err}", path.display()))
    })
}

/// Removes one hook file; a missing file is already the wanted state.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn remove_hook_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CliError::Operational(format!(
            "remove the boot hook {}: {err}",
            path.display()
        ))),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_tool(program: &str, arguments: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .map_err(|err| CliError::Operational(format!("run {program}: {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(CliError::Operational(format!(
        "{program} {} failed: {}",
        arguments.join(" "),
        stderr.trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> HookSpec {
        HookSpec {
            exe: PathBuf::from("/usr/local/bin/orc"),
            env: vec![
                ("HOME".to_owned(), "/root".to_owned()),
                ("ORC_STATE_DIR".to_owned(), "/var/lib/orc".to_owned()),
            ],
        }
    }

    fn bare_spec() -> HookSpec {
        HookSpec {
            exe: PathBuf::from("/usr/local/bin/orc"),
            env: Vec::new(),
        }
    }

    #[test]
    fn the_systemd_unit_runs_the_resume_once_at_boot() {
        let unit = systemd_unit(&spec());
        assert!(unit.contains("Type=oneshot"), "{unit}");
        assert!(
            unit.contains("ExecStart=/usr/local/bin/orc install --resume"),
            "{unit}"
        );
        assert!(unit.contains("After=network-online.target"), "{unit}");
        assert!(unit.contains("WantedBy=multi-user.target"), "{unit}");
        // The installing user's state dir is what holds the resume marker; without it a
        // hook running as root at boot would find nothing to resume.
        assert!(unit.contains("Environment=\"HOME=/root\""), "{unit}");
        assert!(
            unit.contains("Environment=\"ORC_STATE_DIR=/var/lib/orc\""),
            "{unit}"
        );
    }

    #[test]
    fn the_runonce_command_carries_the_environment_through_cmd() {
        assert_eq!(
            runonce_command(&bare_spec()),
            "\"/usr/local/bin/orc\" install --resume"
        );
        assert_eq!(
            runonce_command(&spec()),
            "cmd.exe /c \"set \"HOME=/root\" && set \"ORC_STATE_DIR=/var/lib/orc\" && \
             \"/usr/local/bin/orc\" install --resume\""
        );
    }

    #[test]
    fn the_launch_daemon_runs_at_load_with_the_resume_argv() {
        let plist = launchd_plist(&spec());
        assert!(
            plist.contains("<string>com.orc8r.install-resume</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("<string>/usr/local/bin/orc</string>"),
            "{plist}"
        );
        assert!(plist.contains("<string>install</string>"), "{plist}");
        assert!(plist.contains("<string>--resume</string>"), "{plist}");
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"), "{plist}");
        assert!(plist.contains("<key>ORC_STATE_DIR</key>"), "{plist}");
    }

    #[test]
    fn plist_values_are_xml_escaped() {
        let plist = launchd_plist(&HookSpec {
            exe: PathBuf::from("/opt/a&b/orc"),
            env: vec![("HOME".to_owned(), "/home/<x>".to_owned())],
        });
        assert!(
            plist.contains("<string>/opt/a&amp;b/orc</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("<string>/home/&lt;x&gt;</string>"),
            "{plist}"
        );
    }

    #[test]
    fn a_regenerated_spec_is_byte_identical() {
        // Re-registration happens once per reboot cycle; identical content keeps a
        // hand-diffed unit from looking like it changed under the operator.
        let mut shuffled = spec();
        shuffled.env.reverse();
        shuffled.env.sort();
        assert_eq!(systemd_unit(&shuffled), systemd_unit(&spec()));
    }

    #[test]
    fn removing_a_missing_hook_is_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("never-written.service");
        remove_hook_file(&path).expect("missing hook removes cleanly");

        std::fs::write(&path, "unit").expect("write");
        remove_hook_file(&path).expect("present hook removes cleanly");
        assert!(!path.exists());
        // ...and again, which is what a second convergence pass does.
        remove_hook_file(&path).expect("second removal is a no-op");
    }

    #[test]
    fn a_hook_path_that_cannot_be_written_names_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A file where the hook wants a directory: the same shape as an unwritable /etc.
        let blocker = dir.path().join("blocked");
        std::fs::write(&blocker, "not a directory").expect("write");
        let err = write_hook_file(&blocker.join("orc-install-resume.service"), b"unit")
            .expect_err("registration must fail");
        assert!(
            err.to_string().contains("orc-install-resume.service")
                || err.to_string().contains("blocked"),
            "{err}"
        );
    }
}
