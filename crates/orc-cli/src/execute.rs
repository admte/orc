//! Remote process execution over the forwarding access connection.
use crate::config::StoredConfig;
use crate::forward::{authorized, connect, credential_token, server_host, status_error};
use crate::{CliError, Result};
use clap::Args;
use orc_access::{
    ExecuteFrame, ExecuteOpen, ExecuteSize, OpenSessionRequest, execute_frame::Kind, session_event,
};
use std::io::{IsTerminal, Read, Write};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Debug, Args)]
pub struct NodeArgs {
    /// Node ID, as shown in the ORC console.
    #[arg(value_name = "NODE")]
    node: String,
    /// Access server (default: the stored login host).
    #[arg(long, value_name = "HOST")]
    server: Option<String>,
    /// Organization (default: stored organization, or the only one in reach).
    #[arg(long, value_name = "CODE")]
    org: Option<String>,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  orc exec NODE -- whoami\n  orc exec -it NODE -- bash\n  orc exec -it NODE -- powershell.exe\n  cat script.sh | orc exec -i NODE -- sh\n\nArguments are passed directly. Use sh -c or powershell.exe -Command for shell expressions.\nWithout a TTY, stdout and stderr stay separate. The remote exit code becomes orc's exit code."
)]
pub struct ExecArgs {
    #[command(flatten)]
    target: NodeArgs,
    /// Forward standard input (including piped input).
    #[arg(short = 'i', long = "stdin", visible_alias = "interactive")]
    stdin: bool,
    /// Allocate a remote terminal. With -i, requires a local terminal on stdin.
    #[arg(short = 't', long = "tty")]
    tty: bool,
    /// Executable followed by arguments, after --.
    #[arg(last = true, required = true, num_args = 1.., value_name = "COMMAND")]
    command: Vec<String>,
}

pub async fn shell(target: NodeArgs, config: &StoredConfig) -> Result<i32> {
    execute(
        ExecArgs {
            target,
            stdin: true,
            tty: true,
            command: Vec::new(),
        },
        config,
    )
    .await
}

#[allow(clippy::too_many_lines)] // One access session and its terminal lifecycle.
pub async fn execute(args: ExecArgs, config: &StoredConfig) -> Result<i32> {
    if args.tty && args.stdin && !std::io::stdin().is_terminal() {
        return Err(CliError::Usage(
            "a TTY requires a terminal on stdin; omit -t for piped input".into(),
        ));
    }
    let (rows, cols) = console::Term::stdout().size();
    let mut open = ExecuteOpen {
        session_id: String::new(),
        node: args.target.node,
        command: args.command,
        tty: args.tty,
        stdin: args.stdin,
        cols: u32::from(cols.max(1)),
        rows: u32::from(rows.max(1)),
    };
    orc_access::validate_execute(&open).map_err(|e| CliError::Usage(e.into()))?;
    let server = server_host(args.target.server.as_deref(), config)?;
    let token = credential_token(&server, config)?;
    let channel = connect(&server).await?;
    let mut client = orc_access::access_service_client::AccessServiceClient::new(channel);
    let mut events = client
        .open_session(authorized(
            OpenSessionRequest {
                org: args
                    .target
                    .org
                    .or_else(|| config.default_org.clone())
                    .unwrap_or_default(),
                targets: Vec::new(),
                break_glass: true,
            },
            &token,
        )?)
        .await
        .map_err(|e| status_error(&e))?
        .into_inner();
    let Some(event) = events.message().await.map_err(|e| status_error(&e))? else {
        return Err(failure("server opened no access session"));
    };
    let Some(session_event::Kind::Opened(session)) = event.kind else {
        return Err(failure("server opened no access session"));
    };
    open.session_id = session.session_id;
    let (tx, rx) = mpsc::channel(2);
    tx.send(ExecuteFrame {
        kind: Some(Kind::Open(open)),
    })
    .await
    .map_err(|_| failure("execution stream closed"))?;
    let mut remote = client
        .execute(authorized(ReceiverStream::new(rx), &token)?)
        .await
        .map_err(|e| {
            if e.code() == tonic::Code::Unimplemented {
                failure(&format!(
                    "remote execution unavailable: {}; upgrade the server and node agent",
                    e.message()
                ))
            } else {
                status_error(&e)
            }
        })?
        .into_inner();
    let Some(ExecuteFrame {
        kind: Some(Kind::Ready(true)),
    }) = remote.message().await.map_err(|e| status_error(&e))?
    else {
        return Err(failure("server did not confirm execution"));
    };
    let _raw = if args.tty && args.stdin {
        Some(RawTerminal::enable().map_err(|e| failure(&format!("configure terminal: {e}")))?)
    } else {
        None
    };
    if args.stdin {
        let input = tx.clone();
        std::thread::spawn(move || {
            let mut buf = [0; 8192];
            let mut stdin = std::io::stdin().lock();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        let _ = input.blocking_send(ExecuteFrame {
                            kind: Some(Kind::StdinEof(true)),
                        });
                        break;
                    }
                    Ok(n) => {
                        if input
                            .blocking_send(ExecuteFrame {
                                kind: Some(Kind::Stdin(bytes::Bytes::copy_from_slice(&buf[..n]))),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
    }
    let stop = termination();
    tokio::pin!(stop);
    let mut resize = tokio::time::interval(Duration::from_millis(200));
    let mut size = (rows, cols);
    loop {
        tokio::select! {
            () = &mut stop => return Ok(143),
            frame = remote.message() => {
                let frame = frame.map_err(|e| status_error(&e))?.ok_or_else(|| failure("connection lost without a remote exit status; command was not retried"))?;
                match frame.kind {
                    Some(Kind::Stdout(data)) => { let mut out = std::io::stdout().lock(); out.write_all(&data).and_then(|()| out.flush()).map_err(|e| failure(&e.to_string()))?; }
                    Some(Kind::Stderr(data)) => { let mut out = std::io::stderr().lock(); out.write_all(&data).and_then(|()| out.flush()).map_err(|e| failure(&e.to_string()))?; }
                    Some(Kind::Exit(exit)) => return Ok(exit.code),
                    _ => return Err(failure("unexpected execution frame")),
                }
            }
            event = events.message() => {
                let reason = match event {
                    Ok(Some(event)) => match event.kind { Some(session_event::Kind::Closed(closed)) => closed.reason, _ => "unexpected access event".into() },
                    Ok(None) => "access session ended".into(),
                    Err(err) => err.to_string(),
                };
                return Err(failure(&reason));
            }
            _ = resize.tick(), if args.tty => {
                let next = console::Term::stdout().size();
                if next != size {
                    size = next;
                    tx.send(ExecuteFrame { kind: Some(Kind::Resize(ExecuteSize { rows: u32::from(size.0.max(1)), cols: u32::from(size.1.max(1)) })) }).await.map_err(|_| failure("execution stream closed"))?;
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|e| failure(&e.to_string()))?;
                tx.send(ExecuteFrame { kind: Some(Kind::Signal("INT".into())) }).await.map_err(|_| failure("execution stream closed"))?;
            }
        }
    }
}
fn failure(message: &str) -> CliError {
    CliError::Operational(message.into())
}

#[cfg(unix)]
struct RawTerminal(libc::termios);
#[cfg(unix)]
impl RawTerminal {
    fn enable() -> std::io::Result<Self> {
        // SAFETY: valid termios storage; changes only this process's stdin terminal.
        #[allow(unsafe_code)]
        unsafe {
            let mut original = std::mem::zeroed();
            if libc::tcgetattr(0, &raw mut original) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut raw = original;
            libc::cfmakeraw(&raw mut raw);
            if libc::tcsetattr(0, libc::TCSANOW, &raw const raw) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self(original))
        }
    }
}
#[cfg(unix)]
impl Drop for RawTerminal {
    fn drop(&mut self) {
        // SAFETY: restores the settings read when entering raw mode.
        #[allow(unsafe_code)]
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &raw const self.0);
        }
    }
}

#[cfg(windows)]
struct RawTerminal {
    input: u32,
    output: Option<u32>,
}
#[cfg(windows)]
impl RawTerminal {
    fn enable() -> std::io::Result<Self> {
        use windows_sys::Win32::System::Console::*;
        #[allow(unsafe_code)]
        unsafe {
            let mut mode = 0;
            let input = GetStdHandle(STD_INPUT_HANDLE);
            if GetConsoleMode(input, &raw mut mode) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut guard = Self {
                input: mode,
                output: None,
            };
            if SetConsoleMode(
                input,
                (mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let output = GetStdHandle(STD_OUTPUT_HANDLE);
            if GetConsoleMode(output, &raw mut mode) != 0 {
                guard.output = Some(mode);
                if SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(guard)
        }
    }
}
#[cfg(windows)]
impl Drop for RawTerminal {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::*;
        #[allow(unsafe_code)]
        unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.input);
            if let Some(mode) = self.output {
                SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), mode);
            }
        }
    }
}

/// Return through the terminal guard on OS shutdown signals, too.
async fn termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let (Ok(mut term), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) {
            tokio::select! { _ = term.recv() => {}, _ = hup.recv() => {} }
            return;
        }
    }
    #[cfg(windows)]
    {
        if let (Ok(mut close), Ok(mut stop)) = (
            tokio::signal::windows::ctrl_close(),
            tokio::signal::windows::ctrl_break(),
        ) {
            tokio::select! { _ = close.recv() => {}, _ = stop.recv() => {} }
            return;
        }
    }
    std::future::pending::<()>().await;
}
