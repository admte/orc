#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    Operational = 1,
    Usage = 2,
    Auth = 3,
    NotFound = 4,
    Conflict = 5,
    /// The operator interrupted the command with Ctrl-C (`128 + SIGINT`).
    Interrupted = 130,
    /// The command was asked to terminate (`128 + SIGTERM`).
    Terminated = 143,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Auth(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Operational(String),
    /// The operator interrupted a running phase; `signal` is what interrupted it.
    #[error("{phase} phase interrupted by the operator")]
    Interrupted { phase: String, signal: i32 },
}

impl CliError {
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::Usage,
            Self::Auth(_) => ExitCode::Auth,
            Self::NotFound(_) => ExitCode::NotFound,
            Self::Conflict(_) => ExitCode::Conflict,
            Self::Operational(_) => ExitCode::Operational,
            Self::Interrupted { signal, .. } if *signal == SIGTERM => ExitCode::Terminated,
            Self::Interrupted { .. } => ExitCode::Interrupted,
        }
    }
}

/// `SIGTERM`'s number, spelled out so the exit status reads the same on every platform.
const SIGTERM: i32 = 15;

pub type Result<T> = std::result::Result<T, CliError>;
