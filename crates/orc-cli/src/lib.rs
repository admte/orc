mod boot_hook;
mod build_recipe;
mod cli;
pub mod config;
pub mod forward;
mod github;
mod info;
mod local_artifact_store;
mod oci_layout;
mod output;
mod pb;
mod progress;
pub mod proxy;
mod resume;
mod socks;
mod supervisor;
mod terminal;
mod versions;

// Re-export all modules that moved to orc-app, so existing orc_cli::app::... paths keep working.
pub use orc_app::app;
pub use orc_app::cache;
pub use orc_app::error;
pub use orc_app::lifecycle;
pub use orc_app::package;
pub use orc_app::params;
pub use orc_app::pull;
pub use orc_app::reference;
pub use orc_app::registry;
pub use orc_app::service;
pub use orc_app::state;

pub use orc_app::{CliError, ExitCode, Result};

/// Runs the CLI from process arguments and maps failures onto the stable exit-code contract.
#[must_use]
pub fn main_entry() -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("failed to start async runtime: {err}");
            return ExitCode::Operational as i32;
        }
    };

    match runtime.block_on(cli::run(std::env::args_os())) {
        Ok(()) => ExitCode::Success as i32,
        Err(err) => {
            eprintln!("{err}");
            err.exit_code() as i32
        }
    }
}
