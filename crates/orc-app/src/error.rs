#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    Operational = 1,
    Usage = 2,
    Auth = 3,
    NotFound = 4,
    Conflict = 5,
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
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
