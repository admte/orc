//! What the runtime does to a v2 command before it spawns it (spec 214 *Commands*).
//!
//! A command is an argv list run directly, with no shell. Its run-time tokens are
//! substituted element by element ([`super::token::substitute_argv`]), an element naming
//! an unset value is dropped, and then the first element is resolved:
//!
//! - **Unix**: `./name` is the app directory's `name`, resolved by the runtime itself;
//!   any other program is run as written, so a bare name is looked up in `PATH`.
//! - **Windows**: a first element naming a packaged `.ps1` runs as
//!   `powershell -NoProfile -ExecutionPolicy Bypass -File <app dir>\name.ps1 …`; a
//!   packaged `.exe` runs directly; anything else is looked up in `PATH`. A leading `./`
//!   (or `.\`) is accepted and names the app directory's file.
//!
//! On the `-File` form, as measured by the Windows CI suite running a real script through
//! this builder (`powershell_file_binds_name_colon_value_elements` in `lifecycle`): Windows
//! PowerShell 5.1 binds each `-Name:value` element after the script path to the script's
//! `param()` block with the value intact — spaces, commas, a leading `-`, `$env:X`, single
//! and double quotes, and a trailing backslash all arrive as written. The one exception is
//! an **empty** value: `-Name:` leaves the parameter unbound, so the script sees its
//! declared default (or `$null`, which a `[string]` reads as `""`). A manifest that must
//! tell "set to empty" from "not given" on Windows cannot do it with `-Name:${x:-}`.

use std::collections::BTreeMap;
use std::path::Path;

use super::token;
use crate::error::{CliError, Result};

/// Which host's program rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandHost {
    Unix,
    Windows,
}

impl CommandHost {
    /// The host this runtime is running on.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

/// What a packaged `.ps1` runs under: the script path and its arguments follow.
pub const POWERSHELL_FILE: [&str; 5] = [
    "powershell",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
];

/// The argv a v2 command spawns: tokens substituted from `tokens`, unset elements
/// dropped, the program resolved for `host` against `app_dir`.
///
/// # Errors
///
/// An empty command, invalid token syntax, or a first element that names an unset value
/// (a command with no program cannot run).
pub fn command_argv(
    template: &[String],
    tokens: &BTreeMap<String, String>,
    app_dir: &Path,
    host: CommandHost,
) -> Result<Vec<String>> {
    if template.is_empty() {
        return Err(CliError::Operational(
            "lifecycle command argv cannot be empty".to_owned(),
        ));
    }
    let substituted = token::substitute_argv(template, tokens)
        .map_err(|err| CliError::Operational(format!("lifecycle command: {err}")))?;
    let mut elements = substituted.into_iter();
    let Some(program) = elements.next().flatten() else {
        return Err(CliError::Operational(format!(
            "lifecycle command's program {:?} names a value that is not set",
            template[0]
        )));
    };
    let mut argv = vec![program];
    argv.extend(elements.flatten());
    Ok(resolve_program(argv, app_dir, host))
}

/// Resolves the first element of an already substituted argv for `host`.
#[must_use]
pub fn resolve_program(mut argv: Vec<String>, app_dir: &Path, host: CommandHost) -> Vec<String> {
    let Some(first) = argv.first().cloned() else {
        return argv;
    };
    match host {
        CommandHost::Unix => {
            if let Some(relative) = first.strip_prefix("./") {
                // Joined as Unix writes a path, whichever host computes it.
                let dir = app_dir.display().to_string();
                argv[0] = format!("{}/{relative}", dir.trim_end_matches('/'));
            }
            argv
        }
        CommandHost::Windows => {
            let (explicit, name) = first
                .strip_prefix("./")
                .or_else(|| first.strip_prefix(".\\"))
                .map_or((false, first.as_str()), |name| (true, name));
            let local = windows_join(app_dir, name);
            let extension = Path::new(name)
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default();
            let packaged = Path::new(&local).is_file();
            if extension.eq_ignore_ascii_case("ps1") && packaged {
                let mut out: Vec<String> = POWERSHELL_FILE
                    .iter()
                    .map(|part| (*part).to_owned())
                    .collect();
                out.push(local);
                out.extend(argv.into_iter().skip(1));
                return out;
            }
            if (extension.eq_ignore_ascii_case("exe") && packaged) || explicit {
                argv[0] = local;
            }
            argv
        }
    }
}

/// `app_dir\name`, with `/` in `name` spelled `\` as Windows writes a path.
fn windows_join(app_dir: &Path, name: &str) -> String {
    let dir = app_dir.display().to_string();
    let name = name.replace('/', "\\");
    if dir.ends_with('\\') || dir.ends_with('/') {
        format!("{dir}{name}")
    } else if cfg!(windows) {
        format!("{dir}\\{name}")
    } else {
        // Built on a Unix host (the tests), the directory is a Unix path; joining it the
        // host's way keeps the file check meaningful.
        app_dir.join(name).display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn a_dot_slash_program_is_resolved_against_the_app_dir_on_unix() {
        let dir = Path::new("/srv/app");
        assert_eq!(
            resolve_program(argv(&["./run.sh", "--a"]), dir, CommandHost::Unix),
            argv(&["/srv/app/run.sh", "--a"])
        );
        assert_eq!(
            resolve_program(argv(&["sh", "-c", "x"]), dir, CommandHost::Unix),
            argv(&["sh", "-c", "x"])
        );
        assert_eq!(
            resolve_program(argv(&["/bin/true"]), dir, CommandHost::Unix),
            argv(&["/bin/true"])
        );
    }

    #[test]
    fn a_packaged_ps1_runs_under_powershell_file_on_windows() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("start.ps1"), "param()").expect("script");
        std::fs::write(dir.path().join("tool.exe"), "MZ").expect("exe");
        let script = windows_join(dir.path(), "start.ps1");
        assert_eq!(
            resolve_program(
                argv(&["start.ps1", "-Url:x", "-Empty:"]),
                dir.path(),
                CommandHost::Windows
            ),
            argv(&[
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &script,
                "-Url:x",
                "-Empty:"
            ])
        );
        // The `./` spelling names the same packaged script.
        assert_eq!(
            resolve_program(argv(&["./start.ps1"]), dir.path(), CommandHost::Windows)[5],
            script
        );
        // The extension is matched without regard to case.
        std::fs::write(dir.path().join("loud.PS1"), "param()").expect("script");
        let upper = resolve_program(argv(&["loud.PS1"]), dir.path(), CommandHost::Windows);
        assert_eq!(upper[0], "powershell");
        // A packaged .exe runs directly, by its full path.
        assert_eq!(
            resolve_program(argv(&["tool.exe", "/q"]), dir.path(), CommandHost::Windows),
            argv(&[&windows_join(dir.path(), "tool.exe"), "/q"])
        );
        // Anything else is looked up in PATH: pwsh spelled out, or a script not packaged.
        assert_eq!(
            resolve_program(
                argv(&["pwsh", "-File", "x.ps1"]),
                dir.path(),
                CommandHost::Windows
            ),
            argv(&["pwsh", "-File", "x.ps1"])
        );
        assert_eq!(
            resolve_program(argv(&["other.ps1"]), dir.path(), CommandHost::Windows),
            argv(&["other.ps1"])
        );
    }

    #[test]
    fn command_argv_substitutes_drops_and_resolves() {
        let tokens = BTreeMap::from([
            ("url".to_owned(), "https://x y".to_owned()),
            ("token_file".to_owned(), "/p/token".to_owned()),
        ]);
        assert_eq!(
            command_argv(
                &argv(&[
                    "./run.sh",
                    "--url=${url}",
                    "--pool=${pool}",
                    "--t=${token_file}"
                ]),
                &tokens,
                Path::new("/srv/app"),
                CommandHost::Unix
            )
            .expect("argv"),
            argv(&["/srv/app/run.sh", "--url=https://x y", "--t=/p/token"])
        );
        let err = command_argv(
            &argv(&["${prog}", "x"]),
            &tokens,
            Path::new("/srv/app"),
            CommandHost::Unix,
        )
        .expect_err("no program");
        assert!(err.to_string().contains("not set"), "{err}");
        assert!(command_argv(&[], &tokens, Path::new("/"), CommandHost::Unix).is_err());
    }
}
