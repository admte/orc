//! Reading one App-data restore point out of the registry, from the client side.
//!
//! Archive export ([`crate::persist::archive`]) and local materialization use the same
//! read path. Encrypted registry content is opened only with keys supplied by the caller,
//! so plaintext exists only on the machine that requested it.
//!
//! So what this module adds over [`crate::persist::restore`] is the *addressing*: a
//! restore point published as an OCI artifact, resolved by reference the way any other
//! `orc pull` target is.
//!
//! ```text
//! GET /v2/{repo}/manifests/20260906T081105Z-s1
//!   artifactType: application/vnd.orc.appdata.restore-point.v1
//!   config:       the point index    (…restore-point.config.v1+json[+encrypted])
//!   layers[]:     the layers         (…appdata.layer.v1+zstd[+encrypted]), header order
//!   annotations:  org.orc8r.appdata.{point,pool,slot,node,app,kind,files,bytes}
//!                 org.orc8r.enc.{scheme,key-id}, org.opencontainers.image.{created,ref.name}
//! ```
//!
//! Whether that content is encrypted, under what scheme and under which key, is read from
//! the **descriptors** by [`crate::encryption`] and is no business of this module — the
//! `artifactType` decides only how plaintext is materialized (a tree, or one `tar.zst`).
//!
//! The manifest is a *pointer*, not a source of truth: the index layer's own header names
//! the layers and every entry's place in them, so a manifest that disagreed with the index
//! could only make this read fail, never make it produce a wrong tree. The tag is opaque
//! here for the same reason — the time-based name a point is published under is a label
//! for people, and this code never parses meaning out of it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::app::ManifestDocument;
use crate::encryption::{self, Encryption};
use crate::error::{CliError, Result};
use crate::persist::archive::{ArchiveStats, write_point_archive_observed};
use crate::persist::restore::{
    LayerObserver, RESTORING_SUFFIX, RestoreError, RestorePoint, RestoreStats, Restorer,
};
use crate::persist::seal::KeyRing;
use crate::persist::tree::LayerRef;
use crate::persist::upload::APPDATA_LAYER_MEDIA_TYPE;

/// `artifactType` of the manifest that publishes one restore point.
pub const RESTORE_POINT_ARTIFACT_TYPE: &str = "application/vnd.orc.appdata.restore-point.v1";

/// Media type of the point's index, carried as the manifest's `config` descriptor. The
/// published descriptor carries the `+encrypted` suffix when the index is sealed.
pub const RESTORE_POINT_CONFIG_MEDIA_TYPE: &str =
    "application/vnd.orc.appdata.restore-point.config.v1+json";

/// The point id, as `rp-<id>`.
pub const ANNOTATION_POINT: &str = "org.orc8r.appdata.point";
pub const ANNOTATION_POOL: &str = "org.orc8r.appdata.pool";
pub const ANNOTATION_SLOT: &str = "org.orc8r.appdata.slot";
pub const ANNOTATION_NODE: &str = "org.orc8r.appdata.node";
pub const ANNOTATION_APP: &str = "org.orc8r.appdata.app";
pub const ANNOTATION_KIND: &str = "org.orc8r.appdata.kind";
pub const ANNOTATION_FILES: &str = "org.orc8r.appdata.files";
pub const ANNOTATION_BYTES: &str = "org.orc8r.appdata.bytes";
pub const ANNOTATION_CREATED: &str = "org.opencontainers.image.created";
/// The canonical tag the point is published under, when the manifest names it — the
/// time-based `<YYYYMMDD>T<HHMMSS>Z-s<slot>-<app>` form, whatever alias was pulled.
pub const ANNOTATION_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// One restore point as its manifest describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPoint {
    /// Digest of the manifest itself, for `<reference>@<digest>` output.
    pub digest: String,
    /// What the decoders need: index layer, key id, declared totals.
    pub point: RestorePoint,
    /// How the content is encrypted, read from the descriptors.
    pub encryption: Encryption,
    /// The layers, in the order the manifest lists them. Narration only — the index
    /// header is what the read actually walks.
    pub layers: Vec<LayerRef>,
    /// The canonical tag, from [`ANNOTATION_REF_NAME`], falling back to the reference the
    /// caller pulled. This is what an output directory is named after.
    pub ref_name: String,
    /// `org.opencontainers.image.created`, verbatim.
    pub created: String,
    pub pool: String,
    pub slot: Option<u64>,
    pub node: String,
    pub kind: String,
}

impl ResolvedPoint {
    /// Bytes the layers occupy in the registry — what a download transfers, as opposed to
    /// [`RestorePoint::bytes`], which is the plaintext it expands to.
    #[must_use]
    pub fn transfer_bytes(&self) -> u64 {
        self.layers.iter().map(|layer| layer.size).sum::<u64>() + self.point.index.size
    }

    /// A directory or file name for this point: its canonical tag, reduced to one safe
    /// path segment. This is `orc pull`'s default output name.
    #[must_use]
    pub fn output_name(&self) -> String {
        safe_segment(&self.ref_name)
    }
}

/// Resolves `reference` as a restore point, or reports that it is not one.
///
/// The standalone form, for a caller that only wants to ask this question. `orc pull` does
/// **not** use it: it routes through [`crate::pull::resolve_pull_target`], which decides
/// from the one manifest fetch the app path then reuses. Here a reference that will not
/// fetch is simply "not a point" (`Ok(None)`), which is why it is not the routing path —
/// swallowing that error would cost the caller the error it should have reported. An
/// artifact that *claims* to be a restore point and is malformed is an error either way:
/// a caller who asked for a point must never be told it is an app.
///
/// # Errors
///
/// Returns [`CliError::Operational`] when the manifest declares itself a restore point but
/// does not carry the config descriptor, layer media types, encryption declaration, or
/// annotations the format requires.
pub async fn resolve(
    registry: &crate::registry::RegistryClient,
    repository: &str,
    reference: &str,
) -> Result<Option<ResolvedPoint>> {
    let Ok(fetched) = crate::pull::fetch_manifest(registry, repository, reference).await else {
        return Ok(None);
    };
    let ManifestDocument::Manifest(manifest) = &fetched.document else {
        return Ok(None);
    };
    if manifest.artifact_type != RESTORE_POINT_ARTIFACT_TYPE {
        return Ok(None);
    }
    parse(manifest, fetched.response.digest.clone(), reference).map(Some)
}

/// The manifest half of [`resolve`], split out so it can be tested without a registry.
///
/// # Errors
///
/// As [`resolve`].
pub fn parse(
    manifest: &crate::app::ImageManifest,
    digest: String,
    reference: &str,
) -> Result<ResolvedPoint> {
    let media_types = std::iter::once(manifest.config.media_type.as_str()).chain(
        manifest
            .layers
            .iter()
            .map(|layer| layer.media_type.as_str()),
    );
    let encryption = encryption::declared(&manifest.annotations, media_types)?;

    if encryption::plain_media_type(&manifest.config.media_type) != RESTORE_POINT_CONFIG_MEDIA_TYPE
    {
        return Err(CliError::Operational(format!(
            "restore point {reference} carries its index as {:?}, not \
             {RESTORE_POINT_CONFIG_MEDIA_TYPE}",
            manifest.config.media_type
        )));
    }
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        if encryption::plain_media_type(&layer.media_type) != APPDATA_LAYER_MEDIA_TYPE {
            return Err(CliError::Operational(format!(
                "restore point {reference} carries a layer of type {:?}; this client can \
                 only read {APPDATA_LAYER_MEDIA_TYPE}",
                layer.media_type
            )));
        }
        layers.push(layer_ref(layer)?);
    }
    // Every layer is a stream of sealed frames; there is no unsealed form of one, so a
    // point whose descriptors claim plaintext could not be decoded even with a key.
    let Encryption::Sealed { key_id } = &encryption else {
        return Err(CliError::Operational(format!(
            "restore point {reference} does not declare itself encrypted; App data layers \
             are always sealed, so this is not a point this client can read"
        )));
    };

    let annotations = &manifest.annotations;
    let app = required(annotations, ANNOTATION_APP, reference)?;
    let id = annotations
        .get(ANNOTATION_POINT)
        .cloned()
        .unwrap_or_else(|| reference.to_owned());
    let created = annotations
        .get(ANNOTATION_CREATED)
        .cloned()
        .unwrap_or_default();
    let ref_name = annotations
        .get(ANNOTATION_REF_NAME)
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| reference.to_owned());
    Ok(ResolvedPoint {
        digest,
        point: RestorePoint {
            app,
            id,
            key_id: key_id.clone(),
            created_at: epoch_seconds(&created).unwrap_or_default(),
            index: layer_ref(&manifest.config)?,
            files: number(annotations, ANNOTATION_FILES).unwrap_or_default(),
            bytes: number(annotations, ANNOTATION_BYTES).unwrap_or_default(),
        },
        encryption,
        layers,
        ref_name,
        created,
        pool: annotations
            .get(ANNOTATION_POOL)
            .cloned()
            .unwrap_or_default(),
        slot: number(annotations, ANNOTATION_SLOT),
        node: annotations
            .get(ANNOTATION_NODE)
            .cloned()
            .unwrap_or_default(),
        kind: annotations
            .get(ANNOTATION_KIND)
            .cloned()
            .unwrap_or_default(),
    })
}

fn layer_ref(descriptor: &crate::app::Descriptor) -> Result<LayerRef> {
    Ok(LayerRef {
        digest: descriptor.digest.clone(),
        size: u64::try_from(descriptor.size).map_err(|_| {
            CliError::Operational(format!(
                "restore point layer {} declares a negative size",
                descriptor.digest
            ))
        })?,
    })
}

fn required(annotations: &BTreeMap<String, String>, key: &str, reference: &str) -> Result<String> {
    annotations
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| {
            CliError::Operational(format!(
                "restore point {reference} does not carry the {key} annotation"
            ))
        })
}

fn number(annotations: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    annotations.get(key)?.parse().ok()
}

/// Materializes `point` into `dest` — the tree a restore would have written, files, dirs,
/// symlinks, modes and mtimes included.
///
/// Nothing lands at `dest` until the whole point has decoded: the tree is built under a
/// sibling `.restoring` directory and renamed into place, so an interrupted or failed
/// download leaves either nothing or an obviously-temporary directory, never a `dest` that
/// looks complete and is not. `dest` must not already exist unless `force` is set, in
/// which case what is there is removed first.
///
/// Every layer is fetched exactly once, in index-header order. There is no per-layer
/// resume: a point is materialized whole or not at all, because a partial tree carries no
/// record of which of its files came out of a layer that verified.
///
/// # Errors
///
/// Returns [`RestoreError`] on any integrity failure (layer digest, AEAD, malformed index,
/// a path that would escape `dest`) and on any I/O failure, including a `dest` that exists.
pub async fn materialize_into(
    client: &crate::registry::RegistryClient,
    repository: &str,
    ring: &KeyRing,
    point: &RestorePoint,
    dest: &Path,
    force: bool,
    observer: Option<&dyn LayerObserver>,
) -> std::result::Result<RestoreStats, RestoreError> {
    let parent = claim_destination(dest, force)?;
    // The staging name is derived, not taken from the manifest: an `app` annotation is
    // whatever the point recorded, and it becomes a directory name next to the caller's
    // own files.
    let staging = RestorePoint {
        app: staging_name(point),
        ..point.clone()
    };
    let root = parent.join(format!("{}{RESTORING_SUFFIX}", staging.app));
    let restored =
        match Restorer::materialize_observed(client, repository, ring, &staging, &parent, observer)
            .await
        {
            Ok(restored) => restored,
            Err(err) => {
                // `materialize` leaves its temporary directory for the caller; here the
                // caller is a command line, and a failed pull leaves nothing behind.
                let _ = std::fs::remove_dir_all(&root);
                return Err(err);
            }
        };
    let stats = restored.stats();
    let root = restored.root().to_path_buf();
    if let Err(err) = std::fs::rename(&root, dest) {
        let _ = std::fs::remove_dir_all(&root);
        return Err(RestoreError::Io(err));
    }
    Ok(stats)
}

/// Writes `point` to `dest` as the same `tar.zst` the pool page's download link produces.
///
/// The archive is written under a `.partial` name and renamed once it has ended cleanly,
/// so a failed or interrupted run never leaves a truncated file under the name the caller
/// asked for — which matters more here than in a browser, where a half-file at least
/// announces itself as an interrupted download.
///
/// # Errors
///
/// Returns [`RestoreError`] on any integrity or I/O failure, including a `dest` that
/// already exists and no `force`.
pub async fn write_archive(
    client: &crate::registry::RegistryClient,
    repository: &str,
    ring: &KeyRing,
    point: &RestorePoint,
    dest: &Path,
    force: bool,
    observer: Option<&dyn LayerObserver>,
) -> std::result::Result<ArchiveStats, RestoreError> {
    claim_destination(dest, force)?;
    let partial = partial_path(dest);
    let out = std::io::BufWriter::new(std::fs::File::create(&partial)?);
    match write_point_archive_observed(client, repository, ring, point, out, observer).await {
        Ok(stats) => {
            std::fs::rename(&partial, dest).inspect_err(|_| {
                let _ = std::fs::remove_file(&partial);
            })?;
            Ok(stats)
        }
        Err(err) => {
            // An archive that failed mid-stream is a truncated zstd frame. Nothing can be
            // done with it, and leaving it under a name a person might try to extract is
            // worse than leaving nothing.
            let _ = std::fs::remove_file(&partial);
            Err(err)
        }
    }
}

/// Makes `dest` writable — refusing an existing one unless `force` — and returns the
/// directory it will live in, created if it was missing.
fn claim_destination(dest: &Path, force: bool) -> std::result::Result<PathBuf, RestoreError> {
    if dest.symlink_metadata().is_ok() {
        if !force {
            return Err(RestoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists; use --force to replace it",
                    dest.display()
                ),
            )));
        }
        let removed = if dest.is_dir() && !dest.is_symlink() {
            std::fs::remove_dir_all(dest)
        } else {
            std::fs::remove_file(dest)
        };
        removed?;
    }
    let parent = dest.parent().unwrap_or(Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        parent.to_path_buf()
    };
    std::fs::create_dir_all(&parent)?;
    Ok(parent)
}

/// `<dest>.partial`, in the same directory so the rename is atomic.
fn partial_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    dest.parent().unwrap_or(Path::new("")).join(name)
}

/// The staging directory's name, from the point's app and id. Two pulls of the same point
/// into the same directory collide, which is the one case where they were going to
/// collide anyway.
fn staging_name(point: &RestorePoint) -> String {
    let app = safe_segment(&point.app);
    let id = safe_segment(&point.id);
    format!(
        "{}-{}",
        if app.is_empty() { "app" } else { &app },
        if id.is_empty() { "point" } else { &id }
    )
}

/// One path segment from a name that came off the network: a tag, an app id, a point id.
///
/// Anything that is not an unreserved filename character is dropped rather than replaced,
/// so `../..` collapses instead of becoming a run of dashes. A dot survives only between
/// other characters — the time tag's `sys.sys.postgres` keeps its shape, while `..`, a
/// leading dot, and a trailing dot (which Windows will not store) cannot survive. Capped,
/// because a tag runs to 128 characters and a filename is not always allowed to.
fn safe_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(96));
    for character in value.chars() {
        let keep = match character {
            '-' | '_' => true,
            '.' => !out.ends_with('.'),
            _ => character.is_ascii_alphanumeric(),
        };
        if keep {
            out.push(character);
        }
        if out.len() >= 96 {
            break;
        }
    }
    out.trim_matches('.').to_owned()
}

/// Seconds since the epoch for an RFC 3339 timestamp, to the second.
///
/// The annotation is narration — the read walks the index, not the clock — so anything
/// that does not parse simply has no time attached rather than failing a download.
fn epoch_seconds(value: &str) -> Option<i64> {
    let (date, rest) = value.split_once(['T', 't', ' '])?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let time = rest.split(['Z', 'z', '+']).next()?;
    let time = time.split_once('.').map_or(time, |(head, _)| head);
    let mut clock = time.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next().unwrap_or("0").parse().ok()?;
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Days between 1970-01-01 and `y-m-d`, proleptic Gregorian (Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Descriptor, ImageManifest};
    use crate::encryption::{ANNOTATION_KEY_ID, ANNOTATION_SCHEME, SCHEME_SEALED_STREAM};

    const ENCRYPTED_LAYER: &str = "application/vnd.orc.appdata.layer.v1+zstd+encrypted";
    const ENCRYPTED_CONFIG: &str =
        "application/vnd.orc.appdata.restore-point.config.v1+json+encrypted";
    const TAG: &str = "20260906T081105Z-s1-sys.sys.postgres";

    fn manifest(annotations: &[(&str, &str)], config: &str, layer: &str) -> ImageManifest {
        ImageManifest {
            schema_version: 2,
            artifact_type: RESTORE_POINT_ARTIFACT_TYPE.to_owned(),
            config: Descriptor {
                media_type: config.to_owned(),
                digest: "sha256:index".to_owned(),
                size: 120,
                platform: None,
                annotations: BTreeMap::new(),
            },
            layers: vec![Descriptor {
                media_type: layer.to_owned(),
                digest: "sha256:layer".to_owned(),
                size: 4096,
                platform: None,
                annotations: BTreeMap::new(),
            }],
            annotations: annotations
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn complete() -> Vec<(&'static str, &'static str)> {
        vec![
            (ANNOTATION_POINT, "rp-986165"),
            (ANNOTATION_POOL, "workers"),
            (ANNOTATION_SLOT, "1"),
            (ANNOTATION_NODE, "n_a0"),
            (ANNOTATION_APP, "sys/sys/postgres"),
            (ANNOTATION_KIND, "periodic"),
            (ANNOTATION_FILES, "2004"),
            (ANNOTATION_BYTES, "9437184"),
            (ANNOTATION_CREATED, "2026-09-06T08:11:05Z"),
            (ANNOTATION_REF_NAME, TAG),
            (ANNOTATION_SCHEME, SCHEME_SEALED_STREAM),
            (ANNOTATION_KEY_ID, "0123456789abcdef"),
        ]
    }

    #[test]
    fn a_manifest_becomes_the_point_the_decoders_want() {
        let resolved = parse(
            &manifest(&complete(), ENCRYPTED_CONFIG, ENCRYPTED_LAYER),
            "sha256:manifest".to_owned(),
            TAG,
        )
        .expect("parsed");
        assert_eq!(resolved.point.id, "rp-986165");
        assert_eq!(resolved.point.app, "sys/sys/postgres");
        assert_eq!(resolved.point.key_id, "0123456789abcdef");
        assert_eq!(resolved.point.index.digest, "sha256:index");
        assert_eq!(resolved.point.index.size, 120);
        assert_eq!(resolved.point.files, 2004);
        assert_eq!(resolved.point.bytes, 9_437_184);
        assert_eq!(resolved.slot, Some(1));
        assert_eq!(resolved.pool, "workers");
        assert_eq!(resolved.kind, "periodic");
        assert_eq!(resolved.layers.len(), 1);
        assert_eq!(resolved.transfer_bytes(), 4096 + 120);
        assert_eq!(resolved.point.created_at, 1_788_682_265);
        assert_eq!(
            resolved.encryption,
            Encryption::Sealed {
                key_id: "0123456789abcdef".to_owned()
            }
        );
    }

    /// The canonical time tag names the output, whatever alias was pulled.
    #[test]
    fn the_output_is_named_after_the_canonical_tag() {
        let resolved = parse(
            &manifest(&complete(), ENCRYPTED_CONFIG, ENCRYPTED_LAYER),
            "sha256:manifest".to_owned(),
            "rp-986165",
        )
        .expect("parsed");
        assert_eq!(resolved.ref_name, TAG);
        assert_eq!(resolved.output_name(), TAG);

        // No canonical tag: the reference the caller pulled, made safe.
        let mut annotations = complete();
        annotations.retain(|(key, _)| *key != ANNOTATION_REF_NAME);
        let resolved = parse(
            &manifest(&annotations, ENCRYPTED_CONFIG, ENCRYPTED_LAYER),
            "sha256:manifest".to_owned(),
            "rp-986165",
        )
        .expect("parsed");
        assert_eq!(resolved.output_name(), "rp-986165");
    }

    #[test]
    fn a_point_that_names_no_key_is_refused_rather_than_downloaded() {
        let mut annotations = complete();
        annotations.retain(|(key, _)| *key != ANNOTATION_KEY_ID);
        let err = parse(
            &manifest(&annotations, ENCRYPTED_CONFIG, ENCRYPTED_LAYER),
            "sha256:manifest".to_owned(),
            TAG,
        )
        .expect_err("no key id");
        assert!(err.to_string().contains(ANNOTATION_KEY_ID), "{err}");
    }

    /// A layer this client cannot decode must stop the pull, never be written as bytes.
    #[test]
    fn an_unreadable_layer_type_is_refused() {
        let err = parse(
            &manifest(
                &complete(),
                ENCRYPTED_CONFIG,
                "application/vnd.orc.appdata.layer.v99+aes+encrypted",
            ),
            "sha256:manifest".to_owned(),
            TAG,
        )
        .expect_err("unknown layer type");
        assert!(err.to_string().contains("can only read"), "{err}");
    }

    /// App-data layers are sealed frames; there is no plaintext form of one.
    #[test]
    fn a_point_declaring_plaintext_content_is_refused() {
        let err = parse(
            &manifest(
                &complete(),
                RESTORE_POINT_CONFIG_MEDIA_TYPE,
                APPDATA_LAYER_MEDIA_TYPE,
            ),
            "sha256:manifest".to_owned(),
            TAG,
        )
        .expect_err("not encrypted");
        assert!(err.to_string().contains("always sealed"), "{err}");
    }

    #[test]
    fn a_staging_name_cannot_leave_the_output_directory() {
        let point = RestorePoint {
            app: "../../etc/passwd".to_owned(),
            id: "rp-1/../..".to_owned(),
            key_id: String::new(),
            created_at: 0,
            index: LayerRef {
                digest: String::new(),
                size: 0,
            },
            files: 0,
            bytes: 0,
        };
        let name = staging_name(&point);
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");
        assert!(!name.starts_with('.'), "{name}");
        assert!(!name.ends_with('.'), "{name}");
        assert_eq!(name, "etcpasswd-rp-1");
    }

    #[test]
    fn an_output_name_is_one_safe_path_segment() {
        assert_eq!(safe_segment(TAG), TAG);
        assert_eq!(safe_segment("../../etc/passwd"), "etcpasswd");
        assert_eq!(safe_segment("..."), "");
        assert_eq!(safe_segment(".hidden."), "hidden");
        assert_eq!(safe_segment("a..b"), "a.b");
        assert_eq!(safe_segment("rp-1"), "rp-1");
        assert!(!safe_segment(&"a/".repeat(200)).contains('/'));
        assert!(safe_segment(&"a".repeat(200)).len() <= 96);
    }

    #[test]
    fn an_existing_destination_is_refused_without_force() {
        let dir = tempfile::tempdir().expect("dir");
        let dest = dir.path().join(TAG);
        std::fs::create_dir(&dest).expect("dest");
        std::fs::write(dest.join("keep"), b"x").expect("file");
        let err = claim_destination(&dest, false).expect_err("exists");
        assert!(err.to_string().contains("already exists"), "{err}");
        assert!(dest.join("keep").exists(), "nothing is touched on refusal");

        claim_destination(&dest, true).expect("force");
        assert!(!dest.exists(), "force clears the way");
    }

    #[test]
    fn a_missing_output_directory_is_created() {
        let dir = tempfile::tempdir().expect("dir");
        let dest = dir.path().join("a/b/rp-1");
        let parent = claim_destination(&dest, false).expect("claim");
        assert!(parent.is_dir());
        assert_eq!(parent, dir.path().join("a/b"));
    }

    #[test]
    fn the_partial_name_sits_next_to_the_archive() {
        assert_eq!(
            partial_path(Path::new("/tmp/out/point.tar.zst")),
            Path::new("/tmp/out/point.tar.zst.partial")
        );
        assert_eq!(
            partial_path(Path::new("point.tar.zst")),
            Path::new("point.tar.zst.partial")
        );
    }

    #[test]
    fn created_timestamps_parse_and_junk_does_not() {
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_seconds("2026-09-06T08:11:05Z"), Some(1_788_682_265));
        assert_eq!(
            epoch_seconds("2026-09-06T08:11:05.123456Z"),
            Some(1_788_682_265)
        );
        assert_eq!(epoch_seconds(""), None);
        assert_eq!(epoch_seconds("yesterday"), None);
        assert_eq!(epoch_seconds("2026-13-05T00:00:00Z"), None);
    }
}
