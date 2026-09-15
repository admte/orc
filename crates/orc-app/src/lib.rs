//! Shared ORC app runtime: OCI package contract, blob cache, install state, and lifecycle phases.

pub mod app;
pub mod cache;
pub mod certs;
pub mod chunked;
pub mod credential;
pub mod discovery;
pub mod encryption;
pub mod endpoint_source;
pub mod error;
pub mod lifecycle;
pub mod package;
pub mod params;
pub mod persist;
pub mod probe;
pub mod process;
pub mod progress;
pub mod pull;
pub mod reboot;
pub mod recipe;
pub mod reference;
pub mod registry;
pub mod service;
pub mod state;

pub use error::{CliError, ExitCode, Result};
