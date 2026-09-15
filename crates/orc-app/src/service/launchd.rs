//! The launchd backend: specified, not yet available.
//!
//! The contract is here so a macOS host fails with one clear sentence rather than
//! reporting an app started that nothing is running, and so the shape of the work is
//! already stated when someone comes to do it. Every call but the name derivation
//! refuses.

use async_trait::async_trait;
use futures_util::stream::BoxStream;

use super::{ServiceBackend, ServiceSpec, ServiceStatus};
use crate::error::{CliError, Result};

/// launchd labels are reverse-DNS; the runtime's apps live under one prefix so an
/// operator can see at a glance which ORC services on a Mac belong to it.
pub const LABEL_PREFIX: &str = "com.orc8r.app.";

const UNAVAILABLE: &str = "launchd service backend is not available yet";

/// The launchd service manager.
pub struct Launchd;

fn unavailable<T>() -> Result<T> {
    Err(CliError::Operational(UNAVAILABLE.to_owned()))
}

#[async_trait]
impl ServiceBackend for Launchd {
    fn platform_name(&self, name: &str) -> String {
        format!("{LABEL_PREFIX}{name}")
    }

    async fn define(&self, _spec: &ServiceSpec) -> Result<()> {
        unavailable()
    }

    async fn undefine(&self, _name: &str) -> Result<()> {
        unavailable()
    }

    async fn start(&self, _name: &str) -> Result<()> {
        unavailable()
    }

    async fn stop(&self, _name: &str) -> Result<()> {
        unavailable()
    }

    async fn kill(&self, _name: &str) -> Result<()> {
        unavailable()
    }

    async fn status(&self, _name: &str) -> Result<ServiceStatus> {
        unavailable()
    }

    fn watch(&self, name: &str) -> BoxStream<'static, ServiceStatus> {
        tracing::error!(service = %name, "service manager unavailable");
        Box::pin(futures_util::stream::empty())
    }
}
