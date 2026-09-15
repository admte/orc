//! Structured progress events for long-running registry and materialization
//! work. The SDK only *emits* events; rendering (terminal status lines, bars,
//! logs) is the caller's concern. Attach a [`ProgressReporter`] to a
//! [`RegistryClient`](crate::registry::RegistryClient) with
//! [`with_progress`](crate::registry::RegistryClient::with_progress) and every
//! blob transfer and materialization step reports against it; leave it unset
//! and the runtime behaves exactly as before.

use std::sync::Arc;

/// What an event refers to. Drives how a renderer labels the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressKind {
    /// An OCI manifest or index document.
    Manifest,
    /// A content-addressed blob (config or layer).
    Blob,
    /// A materialized output file written to disk.
    File,
}

/// Lifecycle phase of a single tracked item. Byte phases carry `total: None`
/// when the transfer size is unknown (e.g. the response had no `Content-Length`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressPhase {
    /// Bytes arriving over the network.
    Downloading { done: u64, total: Option<u64> },
    /// Bytes leaving over the network.
    Uploading { done: u64, total: Option<u64> },
    /// Hashing a fetched blob to confirm its digest.
    Verifying,
    /// Writing bytes to disk (blob cache or materialized output).
    Writing,
    /// Served from the local cache; no download happened.
    Cached,
    /// Already present on the remote; no upload happened.
    Exists,
    /// The item finished successfully.
    Done,
    /// The item failed; `message` is human-readable.
    Failed { message: String },
}

/// A single progress update for one tracked item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvent {
    /// Stable identity for in-place updates across a sequence of phases: the
    /// digest for blobs/manifests, the logical title/path for files.
    pub key: String,
    pub kind: ProgressKind,
    pub phase: ProgressPhase,
}

impl ProgressEvent {
    /// Convenience constructor.
    #[must_use]
    pub fn new(key: impl Into<String>, kind: ProgressKind, phase: ProgressPhase) -> Self {
        Self {
            key: key.into(),
            kind,
            phase,
        }
    }
}

/// Sink for [`ProgressEvent`]s. Implemented by callers (e.g. a CLI renderer);
/// the SDK never implements it. `report` is called from byte-transfer loops, so
/// implementations must be cheap and non-blocking.
pub trait ProgressReporter: Send + Sync {
    fn report(&self, event: ProgressEvent);
}

/// Shared handle stored on a [`RegistryClient`](crate::registry::RegistryClient).
pub type SharedProgress = Arc<dyn ProgressReporter>;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use super::{ProgressEvent, ProgressPhase, ProgressReporter};

    /// A reporter that records every event for assertions. Shared via `Arc`, so
    /// a test can hand a clone to `with_progress` and read the captured events
    /// back through the original handle.
    #[derive(Default)]
    pub(crate) struct RecordingReporter {
        events: Mutex<Vec<ProgressEvent>>,
    }

    impl RecordingReporter {
        pub(crate) fn shared() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self::default())
        }

        pub(crate) fn events(&self) -> Vec<ProgressEvent> {
            self.events.lock().expect("events lock").clone()
        }

        pub(crate) fn phases(&self) -> Vec<ProgressPhase> {
            self.events
                .lock()
                .expect("events lock")
                .iter()
                .map(|event| event.phase.clone())
                .collect()
        }
    }

    impl ProgressReporter for RecordingReporter {
        fn report(&self, event: ProgressEvent) {
            self.events.lock().expect("events lock").push(event);
        }
    }
}
