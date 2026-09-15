//! The resume marker: what a standalone `orc install` leaves behind when its install
//! phase asks for the machine.
//!
//! The phase-reboot primitive already persists *that* a phase is mid-execution and how
//! many restarts it has spent. What it cannot know is how to run the CLI again — which
//! app, which version, which parameters, from which directory the `@file` parameters were
//! read. That is this marker, written next to the phase marker in the `StateDir` and
//! consumed by `orc install --resume`.
//!
//! It carries the *whole* install record the converged install will write, in a
//! `pending-reboot` state. Two things follow from that: an interrupted install is never
//! recorded as installed (the record only reaches `installs/` once the phase converges),
//! and the resume needs no registry, no re-materialization, and no second pull — the files
//! are already on disk, and anything the phase wrote into them survives the restart.
//!
//! A digest over the fields that decide what gets run guards against a marker that no
//! longer describes the install it names — hand-edited, or written by a different build.
//! A mismatch refuses rather than running a half-understood install unattended at boot.

#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{CliError, Result};
use crate::state::InstallRecord;

/// Marker file inside the `StateDir`.
const MARKER_FILE: &str = "install-resume.json";

/// Record state of an install that is waiting for a reboot.
pub const PENDING_STATE: &str = "pending-reboot";

/// A standalone installation interrupted by a phase-requested reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeMarker {
    /// The install record to write once the phase converges, with `state` =
    /// [`PENDING_STATE`] while it waits.
    pub record: InstallRecord,
    /// The app parameter arguments exactly as the caller typed them. Literal values for
    /// sensitive parameters are refused at parse time, so what lands here is references
    /// (`@file`, `vault://`, …) — never a secret.
    #[serde(default)]
    pub params: Vec<String>,
    /// Working directory the parameters were read relative to. The boot hook runs from
    /// `/`, so an `@file` parameter would otherwise resolve somewhere else entirely.
    #[serde(default)]
    pub base_dir: String,
    /// Reboots the phase had spent when this marker was written. Informational: the
    /// phase-reboot marker remains the counter of record.
    #[serde(default)]
    pub reboot_count: u32,
    /// The boot hook registered for this cycle, for the operator-facing message.
    #[serde(default)]
    pub hook: String,
    /// Digest over the fields above that decide what the resume runs.
    pub params_digest: String,
}

impl ResumeMarker {
    /// Builds a marker for a pending install, stamping the record `pending-reboot`.
    #[must_use]
    pub fn new(
        mut record: InstallRecord,
        params: Vec<String>,
        base_dir: &Path,
        reboot_count: u32,
        hook: String,
    ) -> Self {
        PENDING_STATE.clone_into(&mut record.state);
        let base_dir = base_dir.display().to_string();
        let params_digest = digest(&record, &params, &base_dir);
        Self {
            record,
            params,
            base_dir,
            reboot_count,
            hook,
            params_digest,
        }
    }

    /// Refuses a marker whose recorded digest no longer matches its own contents.
    ///
    /// This runs unattended, as root, straight out of a boot hook. A marker that drifted
    /// from what the operator asked for is not something to guess at.
    pub fn verify(&self) -> Result<()> {
        let actual = digest(&self.record, &self.params, &self.base_dir);
        if actual == self.params_digest {
            return Ok(());
        }
        Err(CliError::Conflict(format!(
            "the resume marker for {}:{} does not match its recorded parameters \
             (expected digest {}, got {actual}); re-run `orc install {}` without --resume",
            self.record.app, self.record.version, self.params_digest, self.record.reference
        )))
    }

    /// Directory the parameters were originally read relative to.
    #[must_use]
    pub fn base_dir(&self) -> PathBuf {
        if self.base_dir.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(&self.base_dir)
        }
    }
}

/// Digest over everything that decides what a resume actually runs.
fn digest(record: &InstallRecord, params: &[String], base_dir: &str) -> String {
    let mut hasher = Sha256::new();
    for field in [
        record.app.as_str(),
        record.version.as_str(),
        record.reference.as_str(),
        record.digest.as_str(),
        record.platform.as_str(),
        record.materialized_dir.as_str(),
        base_dir,
    ] {
        hasher.update(field.as_bytes());
        hasher.update([0]);
    }
    for param in params {
        hasher.update(param.as_bytes());
        hasher.update([0]);
    }
    let mut out = String::from("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Path of the marker inside a state dir.
#[must_use]
pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MARKER_FILE)
}

/// Reads the marker, if an install is waiting for a reboot.
///
/// An unreadable or garbled marker is an error rather than a silent `None`: unlike the
/// phase counter, this file is the only record of an installation in flight, and quietly
/// forgetting one would strand it.
pub fn read(state_dir: &Path) -> Result<Option<ResumeMarker>> {
    let path = marker_path(state_dir);
    match std::fs::read(&path) {
        Ok(body) => serde_json::from_slice(&body)
            .map(Some)
            .map_err(|err| CliError::Operational(format!("parse {}: {err}", path.display()))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CliError::Operational(format!(
            "read {}: {err}",
            path.display()
        ))),
    }
}

/// Persists the marker before the machine goes down.
pub fn write(state_dir: &Path, marker: &ResumeMarker) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", state_dir.display())))?;
    let path = marker_path(state_dir);
    let body = serde_json::to_vec_pretty(marker)
        .map_err(|err| CliError::Operational(format!("encode resume marker: {err}")))?;
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))
}

/// Retires the marker. A marker that is already gone is the wanted state.
pub fn remove(state_dir: &Path) -> Result<()> {
    let path = marker_path(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CliError::Operational(format!(
            "remove {}: {err}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> InstallRecord {
        InstallRecord {
            app: "os-update".to_owned(),
            version: "default".to_owned(),
            reference: "ghcr.io/admte/os-update:default".to_owned(),
            digest: "sha256:abc".to_owned(),
            platform: "linux/amd64".to_owned(),
            mode: "process".to_owned(),
            state: "stopped".to_owned(),
            pid_service: None,
            params: std::collections::BTreeMap::new(),
            blob_digests: vec!["sha256:def".to_owned()],
            materialized_dir: "/var/lib/orc/apps/os-update/default".to_owned(),
        }
    }

    fn marker() -> ResumeMarker {
        ResumeMarker::new(
            record(),
            vec!["--security-only".to_owned()],
            Path::new("/home/dan/work"),
            1,
            "systemd unit /etc/systemd/system/orc-install-resume.service".to_owned(),
        )
    }

    #[test]
    fn a_pending_marker_round_trips_through_the_state_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read(dir.path()).expect("read"), None, "nothing in flight");

        let marker = marker();
        assert_eq!(
            marker.record.state, PENDING_STATE,
            "an interrupted install is never recorded as installed"
        );
        write(dir.path(), &marker).expect("write");

        let loaded = read(dir.path()).expect("read").expect("marker");
        assert_eq!(loaded, marker);
        loaded.verify().expect("an untouched marker verifies");
        assert_eq!(loaded.base_dir(), Path::new("/home/dan/work"));

        remove(dir.path()).expect("remove");
        assert_eq!(read(dir.path()).expect("read"), None);
        remove(dir.path()).expect("removing a missing marker is success");
    }

    #[test]
    fn a_marker_whose_parameters_drifted_is_refused() {
        let mut drifted = marker();
        drifted.params.push("--extra".to_owned());
        let err = drifted.verify().expect_err("drift must be refused");
        assert!(err.to_string().contains("without --resume"), "{err}");
        assert_eq!(err.exit_code() as i32, 5, "refused operation");

        // The same guard covers the app the marker names and where its params came from.
        let mut retargeted = marker();
        "other-app".clone_into(&mut retargeted.record.app);
        retargeted.verify().expect_err("app drift must be refused");
        let mut moved = marker();
        "/tmp".clone_into(&mut moved.base_dir);
        moved.verify().expect_err("base dir drift must be refused");
    }

    #[test]
    fn the_digest_ignores_fields_the_resume_does_not_act_on() {
        // The reboot counter and the hook description change between cycles; rewriting
        // the marker each cycle must not read as drift.
        let mut later = marker();
        later.reboot_count = 4;
        "another hook".clone_into(&mut later.hook);
        later.verify().expect("a later cycle still verifies");
    }

    #[test]
    fn a_garbled_marker_is_reported_rather_than_forgotten() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(marker_path(dir.path()), b"{oops").expect("write");
        let err = read(dir.path()).expect_err("a garbled marker is an error");
        assert!(err.to_string().contains("install-resume.json"), "{err}");
    }
}
