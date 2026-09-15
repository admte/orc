//! Interactive terminal prompts for `orc login` (docker parity): a plain
//! username prompt and a password prompt with terminal echo disabled.

use std::io::{IsTerminal as _, Write as _};

use crate::error::{CliError, Result};

#[must_use]
pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

#[must_use]
pub fn stderr_is_terminal() -> bool {
    std::io::stderr().is_terminal()
}

/// Prompts on stderr and reads one line from stdin. Returns `default` on
/// empty input.
pub fn prompt_line(prompt: &str, default: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let line = read_stdin_line()?;
    let value = line.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

/// Prompts on stderr and reads one line from stdin with echo disabled, so the
/// secret never appears on the terminal.
pub fn prompt_password(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let guard = EchoGuard::disable()?;
    let line = read_stdin_line();
    drop(guard);
    // The user's Enter was swallowed with the echo; keep the prompt line tidy.
    eprintln!();
    Ok(line?.trim_end_matches(['\r', '\n']).to_owned())
}

fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|err| CliError::Operational(format!("read from stdin: {err}")))?;
    Ok(line)
}

/// Disables terminal echo on stdin for its lifetime; the original settings
/// are restored on drop even when reading fails.
#[cfg(unix)]
struct EchoGuard {
    original: libc::termios,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Result<Self> {
        // SAFETY: tcgetattr/tcsetattr only read/write the termios out-param
        // for the stdin descriptor; failures are reported via return code.
        #[allow(unsafe_code)]
        unsafe {
            let mut term = std::mem::zeroed::<libc::termios>();
            if libc::tcgetattr(libc::STDIN_FILENO, &raw mut term) != 0 {
                return Err(CliError::Operational(
                    "disable terminal echo: tcgetattr failed".to_owned(),
                ));
            }
            let original = term;
            term.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const term) != 0 {
                return Err(CliError::Operational(
                    "disable terminal echo: tcsetattr failed".to_owned(),
                ));
            }
            Ok(Self { original })
        }
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: restores the settings captured in `disable`.
        #[allow(unsafe_code)]
        unsafe {
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const self.original);
        }
    }
}

#[cfg(windows)]
struct EchoGuard {
    original_mode: u32,
}

#[cfg(windows)]
impl EchoGuard {
    fn disable() -> Result<Self> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
        };

        // SAFETY: Get/SetConsoleMode only read/write the mode out-param for stdin.
        #[allow(unsafe_code)]
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle == INVALID_HANDLE_VALUE {
                return Err(CliError::Operational(
                    "disable terminal echo: GetStdHandle failed".to_owned(),
                ));
            }
            let mut mode = 0u32;
            if GetConsoleMode(handle, &raw mut mode) == 0 {
                return Err(CliError::Operational(
                    "disable terminal echo: GetConsoleMode failed".to_owned(),
                ));
            }
            if SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) == 0 {
                return Err(CliError::Operational(
                    "disable terminal echo: SetConsoleMode failed".to_owned(),
                ));
            }
            Ok(Self {
                original_mode: mode,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode};

        // SAFETY: restores the mode captured in `disable`.
        #[allow(unsafe_code)]
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let _ = SetConsoleMode(handle, self.original_mode);
        }
    }
}
