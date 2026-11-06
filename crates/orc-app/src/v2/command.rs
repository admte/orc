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
//! an **empty** value: a trailing `-Name:` leaves the parameter unbound, but one followed by
//! another element takes that element as its value. So when PowerShell runs a script file,
//! an element after the script path that is `-Name:` followed only by tokens (`-Dir:${dir}`)
//! is dropped when they resolve to the empty string, the same as when one names an unset
//! value: the script sees its declared default wherever the element stood. An element with
//! text beside its tokens (`-Dir:a${x}`) is kept, since its value is not empty.
//!
//! PowerShell runs a script file when the first element names a packaged `.ps1` (the
//! `-File` form above), or when the program is `powershell` or `pwsh` spelled out (by name
//! or path, with or without `.exe`) and its arguments carry `-File <script>` before any
//! `-Command`. Only the elements after the script path are the script's parameters; the
//! ones before it are PowerShell's own. Every other program — a packaged `.exe`, `cmd.exe`,
//! any program looked up in `PATH`, `pwsh -Command …` — receives a `-Name:` element as
//! written, empty or not, and so does every Unix program: there `--name=` with an empty
//! value is a value like any other.

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
    let mut substituted = token::substitute_argv(template, tokens)
        .map_err(|err| CliError::Operational(format!("lifecycle command: {err}")))?;
    let Some(program) = substituted.first_mut().and_then(Option::take) else {
        let token = token::first_unset(&template[0], |name| tokens.get(name).map(String::as_str))
            .unwrap_or_default();
        return Err(CliError::Operational(format!(
            "lifecycle command's program {:?}: {token} is not set, and a program cannot be \
             dropped",
            template[0]
        )));
    };
    stays_in_app_dir(&template[0], &program)?;
    // The Windows program is classified once, and that one answer both decides which
    // elements are a script's parameters and resolves the program, so the two cannot
    // disagree.
    let windows = (host == CommandHost::Windows).then(|| classify_windows(&program, app_dir));
    let script_params = windows
        .as_ref()
        .and_then(|class| script_params_start(class, &program, &substituted[1..]));
    let mut argv = vec![program];
    for (index, (element, written)) in substituted.into_iter().zip(template).enumerate().skip(1) {
        let Some(value) = element else {
            continue;
        };
        if script_params.is_some_and(|start| index >= start)
            && is_empty_powershell_flag(written, &value)
        {
            continue;
        }
        argv.push(value);
    }
    Ok(match windows {
        Some(class) => resolve_windows(argv, class),
        None => resolve_program(argv, app_dir, host),
    })
}

/// Where a Windows program's script parameters start, as an index into the command
/// (the program is index 0), when PowerShell runs a script file: right after the
/// program for a packaged `.ps1`, or after `-File <script>` for `powershell` or `pwsh`
/// spelled out. `None` for every other program, and for PowerShell running anything
/// but a file. `rest` is the substituted command after the program; an unset element
/// (`None`) is not there to be a switch or the script.
fn script_params_start(
    class: &WindowsProgram,
    program: &str,
    rest: &[Option<String>],
) -> Option<usize> {
    if matches!(class, WindowsProgram::PackagedScript(_)) {
        return Some(1);
    }
    if !is_powershell(program) {
        return None;
    }
    let mut present = rest
        .iter()
        .enumerate()
        .filter_map(|(index, element)| element.as_deref().map(|value| (index + 1, value)));
    while let Some((_, element)) = present.next() {
        if powershell_switch(element, "file", "f") {
            // The script is the next element there is; its parameters follow it.
            return present.next().map(|(script, _)| script + 1);
        }
        if powershell_switch(element, "command", "c")
            || powershell_switch(element, "encodedcommand", "e")
            || powershell_switch(element, "ec", "ec")
        {
            // Everything after `-Command` is the command, never a script's parameters.
            return None;
        }
    }
    None
}

/// Whether `program` names Windows PowerShell or PowerShell 7: its file name, whatever
/// the directory, is `powershell` or `pwsh`, with or without `.exe`, in any case.
fn is_powershell(program: &str) -> bool {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    stem == "powershell" || stem == "pwsh"
}

/// Whether `element` is PowerShell's own `-name` switch, as both `powershell.exe` and
/// `pwsh` match one: a leading `-`, `--` or `/`, then any prefix of `name` at least as
/// long as `shortest`, in any case.
fn powershell_switch(element: &str, name: &str, shortest: &str) -> bool {
    let Some(spelled) = element
        .strip_prefix("--")
        .or_else(|| element.strip_prefix('-'))
        .or_else(|| element.strip_prefix('/'))
    else {
        return false;
    };
    let spelled = spelled.to_ascii_lowercase();
    spelled.starts_with(shortest) && name.starts_with(&spelled)
}

/// Whether `written`, resolved to `value`, is a PowerShell `-Name:` flag its tokens left
/// empty: the element as written is `-Name:` followed by tokens and nothing else, and
/// `value` is that `-Name:` alone. PowerShell would bind an empty `-Name:` to the element
/// after it (module docs), so such an element is dropped.
fn is_empty_powershell_flag(written: &str, value: &str) -> bool {
    let Ok(pieces) = token::parse(written) else {
        return false;
    };
    let Some((token::Piece::Text { text, .. }, rest)) = pieces.split_first() else {
        return false;
    };
    let is_flag = text
        .strip_prefix('-')
        .and_then(|rest| rest.strip_suffix(':'))
        .is_some_and(token::is_name);
    is_flag
        && !rest.is_empty()
        && rest
            .iter()
            .all(|piece| matches!(piece, token::Piece::Token(_)))
        && value == *text
}

/// Refuses a `./` (or `.\`) program whose substituted path leaves the app directory:
/// a `..` segment, or a path that is absolute once its `./` is gone. The publish checks
/// already refuse a run-time token in such a program; this holds even for a config
/// that never met them. Both separators count, whatever the host.
fn stays_in_app_dir(template: &str, program: &str) -> Result<()> {
    let Some(rest) = program
        .strip_prefix("./")
        .or_else(|| program.strip_prefix(".\\"))
    else {
        return Ok(());
    };
    let segments: Vec<&str> = rest.split(['/', '\\']).collect();
    let absolute =
        rest.starts_with(['/', '\\']) || segments.first().is_some_and(|first| first.contains(':'));
    if absolute || segments.contains(&"..") {
        let tokens = token::tokens(template)
            .map(|tokens| {
                tokens
                    .iter()
                    .map(|found| found.raw)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        return Err(CliError::Operational(format!(
            "lifecycle command's program {template:?} resolves to {program:?}, outside the \
             app directory (filled by {tokens}); a `./` program names a file the package \
             carries"
        )));
    }
    Ok(())
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
        CommandHost::Windows => resolve_windows(argv, classify_windows(&first, app_dir)),
    }
}

/// What a Windows command's first element names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsProgram {
    /// A packaged `.ps1`, by its path in the app directory: it runs under
    /// [`POWERSHELL_FILE`].
    PackagedScript(String),
    /// A packaged `.exe`, or any `./` (`.\`) name, by its path in the app directory.
    Local(String),
    /// Anything else, run as written and so looked up in `PATH`.
    Path,
}

/// Classifies a Windows command's (substituted) first element against `app_dir`.
fn classify_windows(first: &str, app_dir: &Path) -> WindowsProgram {
    let (explicit, name) = first
        .strip_prefix("./")
        .or_else(|| first.strip_prefix(".\\"))
        .map_or((false, first), |name| (true, name));
    let local = windows_join(app_dir, name);
    let extension = Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let packaged = Path::new(&local).is_file();
    if extension.eq_ignore_ascii_case("ps1") && packaged {
        WindowsProgram::PackagedScript(local)
    } else if (extension.eq_ignore_ascii_case("exe") && packaged) || explicit {
        WindowsProgram::Local(local)
    } else {
        WindowsProgram::Path
    }
}

/// Resolves a Windows argv whose first element was classified as `class`.
fn resolve_windows(mut argv: Vec<String>, class: WindowsProgram) -> Vec<String> {
    match class {
        WindowsProgram::PackagedScript(script) => {
            let mut out: Vec<String> = POWERSHELL_FILE
                .iter()
                .map(|part| (*part).to_owned())
                .collect();
            out.push(script);
            out.extend(argv.into_iter().skip(1));
            out
        }
        WindowsProgram::Local(local) => {
            if let Some(first) = argv.first_mut() {
                *first = local;
            }
            argv
        }
        WindowsProgram::Path => argv,
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

    /// Defence in depth behind the publish check: a `./` program whose substituted path
    /// leaves the app directory is refused at run time, naming the element and the token.
    #[test]
    fn a_dot_slash_program_never_leaves_the_app_dir() {
        for host in [CommandHost::Unix, CommandHost::Windows] {
            for (first, value) in [
                ("./${tool}", "../../../bin/sh"),
                ("./bin/${tool}", "../../etc/x"),
                ("./${tool}", "/bin/sh"),
                ("./${tool}", "\\Windows\\System32\\cmd.exe"),
                ("./${tool}", "C:\\Windows\\System32\\cmd.exe"),
                ("./${tool}", "a\\..\\..\\x"),
                (".\\${tool}", "..\\x.exe"),
            ] {
                let tokens = BTreeMap::from([("tool".to_owned(), value.to_owned())]);
                let err = command_argv(
                    &argv(&[first, "-c", "id"]),
                    &tokens,
                    Path::new("/srv/app"),
                    host,
                )
                .expect_err(value);
                let message = err.to_string();
                assert!(message.contains(&format!("{first:?}")), "{message}");
                assert!(message.contains("${tool}"), "{message}");
                assert!(message.contains("outside the app directory"), "{message}");
            }
        }
        // Inside the app dir is fine.
        let tokens = BTreeMap::from([("tool".to_owned(), "bin/run.sh".to_owned())]);
        assert_eq!(
            command_argv(
                &argv(&["./${tool}"]),
                &tokens,
                Path::new("/srv/app"),
                CommandHost::Unix
            )
            .expect("inside"),
            argv(&["/srv/app/bin/run.sh"])
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

    /// The tokens and the app directory the empty-flag tests run against: `dir` is set
    /// but empty, `pool` is unset. The directory packages `start.ps1` and `tool.exe`.
    fn empty_flag_fixture() -> (tempfile::TempDir, BTreeMap<String, String>) {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("start.ps1"), "param()").expect("script");
        std::fs::write(dir.path().join("tool.exe"), "MZ").expect("exe");
        let tokens = BTreeMap::from([
            ("dir".to_owned(), String::new()),
            ("cmd_file".to_owned(), "C:\\p\\cmd".to_owned()),
            ("label".to_owned(), "x".to_owned()),
        ]);
        (dir, tokens)
    }

    /// What follows the program (or, for a packaged script, the script path).
    fn args_after(argv: &[String], skip: usize) -> Vec<String> {
        argv[skip..].to_vec()
    }

    /// A packaged `.ps1` runs under `powershell -File`, where an empty `-Name:` would
    /// bind the next element as its value: an element that is `-Name:` and tokens alone,
    /// all of them empty, is dropped like an unset one.
    #[test]
    fn an_empty_powershell_flag_is_dropped_for_a_packaged_script() {
        let (dir, tokens) = empty_flag_fixture();
        let run = |template: &[&str]| {
            let argv = command_argv(&argv(template), &tokens, dir.path(), CommandHost::Windows)
                .expect("argv");
            assert_eq!(argv[0], "powershell", "{argv:?}");
            args_after(&argv, POWERSHELL_FILE.len() + 1)
        };
        // Empty: dropped, wherever it stands. Non-empty: kept. Unset: dropped as before.
        assert_eq!(
            run(&[
                "start.ps1",
                "-Dir:${dir}",
                "-CmdFile:${cmd_file}",
                "-Pool:${pool}"
            ]),
            argv(&["-CmdFile:C:\\p\\cmd"])
        );
        // A `:-` default that resolves to the empty string is empty too, and the `./`
        // spelling names the same packaged script.
        assert_eq!(
            run(&["./start.ps1", "-Pool:${pool:-}", "-Label:${label}"]),
            argv(&["-Label:x"])
        );
        // Only an element that is `-Name:` and tokens alone, all of them empty: text beside
        // a token makes the value non-empty, or the element no PowerShell flag, and it
        // stays.
        assert_eq!(
            run(&[
                "start.ps1",
                "-Dir:a${dir}",
                "-Dir:${dir}b",
                "-Dir:${dir}${dir}",
                "/Dir:${dir}",
                "--dir=${dir}",
                "${dir}"
            ]),
            argv(&["-Dir:a", "-Dir:b", "/Dir:", "--dir=", ""])
        );
    }

    /// `powershell` or `pwsh` spelled out runs a script file with `-File <script>`: the
    /// elements after the script are its parameters and drop when empty; the ones before
    /// it are PowerShell's own and stay as written.
    #[test]
    fn an_empty_powershell_flag_is_dropped_after_an_explicit_file() {
        let (dir, tokens) = empty_flag_fixture();
        let run = |template: &[&str]| {
            command_argv(&argv(template), &tokens, dir.path(), CommandHost::Windows).expect("argv")
        };
        assert_eq!(
            run(&[
                "powershell",
                "-NoProfile",
                "-File",
                "x.ps1",
                "-Dir:${dir}",
                "-Label:${label}"
            ]),
            argv(&["powershell", "-NoProfile", "-File", "x.ps1", "-Label:x"])
        );
        // By path, with `.exe`, in any case; `-f` and `-file` are `-File` too.
        for program in [
            "pwsh",
            "PWSH.EXE",
            "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
            "C:/Windows/System32/WindowsPowerShell/v1.0/PowerShell.exe",
        ] {
            for file in ["-File", "-f", "-file", "--file", "/File"] {
                assert_eq!(
                    run(&[program, file, "x.ps1", "-Dir:${dir}"]),
                    argv(&[program, file, "x.ps1"]),
                    "{program} {file}"
                );
            }
        }
        // An element before the script is not the script's: it stays as written.
        assert_eq!(
            run(&["pwsh", "-Dir:${dir}", "-File", "x.ps1", "-Dir:${dir}"]),
            argv(&["pwsh", "-Dir:", "-File", "x.ps1"])
        );
        // An unset element between `-File` and the script is not the script.
        assert_eq!(
            run(&["pwsh", "-File", "${pool}", "x.ps1", "-Dir:${dir}"]),
            argv(&["pwsh", "-File", "x.ps1"])
        );
    }

    /// Every other program receives a `-Name:` element as written, empty or not: a
    /// packaged `.exe`, `cmd.exe` or any program looked up in `PATH`, PowerShell running
    /// a command rather than a file, and every program on Unix.
    #[test]
    fn an_empty_flag_is_kept_for_any_other_program() {
        let (dir, tokens) = empty_flag_fixture();
        let template =
            |program: &str| argv(&[program, "-Dir:${dir}", "-Label:${label}", "-Pool:${pool}"]);
        let run = |template: &[String], host| {
            command_argv(template, &tokens, dir.path(), host).expect("argv")
        };
        // A packaged .exe, by its path in the app directory.
        assert_eq!(
            run(&template("tool.exe"), CommandHost::Windows),
            argv(&[&windows_join(dir.path(), "tool.exe"), "-Dir:", "-Label:x"])
        );
        // PATH programs, including a script that is not packaged.
        for program in ["tool", "cmd.exe", "other.ps1", "powershell-helper.exe"] {
            assert_eq!(
                run(&template(program), CommandHost::Windows),
                argv(&[program, "-Dir:", "-Label:x"]),
                "{program}"
            );
        }
        // PowerShell running a command: the rest is the command, `-File` in it included.
        for switch in ["-Command", "-c", "-EncodedCommand", "-ec"] {
            assert_eq!(
                run(
                    &argv(&[
                        "pwsh",
                        switch,
                        "& ./x.ps1",
                        "-Dir:${dir}",
                        "-File",
                        "y.ps1",
                        "-Dir:${dir}"
                    ]),
                    CommandHost::Windows
                ),
                argv(&[
                    "pwsh",
                    switch,
                    "& ./x.ps1",
                    "-Dir:",
                    "-File",
                    "y.ps1",
                    "-Dir:"
                ]),
                "{switch}"
            );
        }
        // PowerShell with neither: nothing is a script's parameter.
        assert_eq!(
            run(&template("powershell"), CommandHost::Windows),
            argv(&["powershell", "-Dir:", "-Label:x"])
        );
        // Unix: an empty value is a value; only an unset one drops its element.
        assert_eq!(
            run(
                &argv(&["tool", "--dir=${dir}", "-Dir:${dir}", "--pool=${pool}"]),
                CommandHost::Unix
            ),
            argv(&["tool", "--dir=", "-Dir:"])
        );
        for program in ["./start.ps1", "pwsh"] {
            assert_eq!(
                run(
                    &argv(&[program, "-File", "x.ps1", "-Dir:${dir}"]),
                    CommandHost::Unix
                )[1..],
                argv(&["-File", "x.ps1", "-Dir:"]),
                "{program}"
            );
        }
    }
}
