//! The App-data index: what a restore point says the app's subtree contained, and how
//! a capture decides what changed since the last one.
//!
//! # Shape
//!
//! The index is a **flat** JSON-Lines document, not a tree of manifests. Line 1 is the
//! [`IndexHeader`]; every following line is one [`Entry`], in byte-wise sorted
//! relative-path order. Flatness is deliberate: the index is itself uploaded as a sealed
//! chunked layer, so content-defined chunking dedups it against the previous cycle's
//! index — a million-file index re-uploads only the chunks its changed lines fall in,
//! which a tree of per-directory manifests would not beat.
//!
//! Paths are relative to `appdata/<app>/` on the volume and always use `/`, whatever the
//! node's operating system. That is the *mirrored* shape the graft builds: a declared
//! root `/var/lib/postgresql/data` lives at `appdata/<app>/var/lib/postgresql/data`, and
//! a Windows root `c:/jenkins-agent` at `appdata/<app>/c/jenkins-agent`.
//!
//! # What is never captured
//!
//! * A **hole**'s mirrored subtree. The graft binds a hole to an empty directory on the
//!   OS disk, but whatever the root migration already carried onto the volume stays
//!   there, shadowed and invisible to the app. Capturing it would restore data the
//!   operator declared disposable — and would grow every point by the size of a cache.
//! * Anything a **capture filter** matches. The filter is matched against the path
//!   *within its declared root*, exactly as [`PersistSpec::is_capture_filtered`]
//!   documents — never against the mirrored path, which carries the root itself.
//! * Anything that is not a regular file, a directory, or a symlink. A socket or a device
//!   node cannot be restored as itself, so recording it would promise something the
//!   restore cannot keep.
//!
//! # Diff
//!
//! Two entries name the same content when their `(size, mtime_ns)` agree. `ctime` is
//! recorded but advisory: a restore cannot reproduce it, so keying on it would make the
//! first cycle after every restore a full re-upload.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::persist::PersistSpec;

/// Index format version recorded in the header.
pub const INDEX_VERSION: u32 = 1;

/// Errors from writing, reading, or walking an index.
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("app data index I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("app data index is empty (no header line)")]
    NoHeader,
    #[error("app data index header is malformed: {0}")]
    BadHeader(String),
    #[error("app data index line {line} is malformed: {source}")]
    BadEntry {
        line: usize,
        source: serde_json::Error,
    },
    #[error("app data index version {0} is unsupported (expected {INDEX_VERSION})")]
    UnsupportedVersion(u32),
    #[error("app data index entry {actual:?} does not follow {previous:?} in sorted order")]
    OutOfOrder { previous: String, actual: String },
    #[error("app data index entry {0:?} references layer {1}, which the header does not list")]
    DanglingLayer(String, u32),
    #[error("walk {path}: {source}")]
    Walk {
        path: String,
        source: std::io::Error,
    },
    #[error("persisted path {0:?} is not absolute and cannot be mirrored onto the volume")]
    NotMirrorable(String),
}

/// A layer of a restore point: its content digest and its stored (sealed) size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRef {
    pub digest: String,
    pub size: u64,
}

/// The index's first line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexHeader {
    pub v: u32,
    pub app: String,
    pub created_at: i64,
    /// The point's data layers, in the order the entries below first reference them.
    #[serde(default)]
    pub layers: Vec<LayerRef>,
}

/// What kind of thing an entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "f")]
    File,
    #[serde(rename = "d")]
    Dir,
    #[serde(rename = "l")]
    Symlink,
}

/// Where a file's bytes live: layer index into [`IndexHeader::layers`], byte offset in
/// that layer's *plaintext*, and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRef {
    pub l: u32,
    pub o: u64,
    pub n: u64,
}

/// One line of the index. Unknown keys are ignored on read, so a later version may add
/// fields without stranding an older reader during an upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Path relative to `appdata/<app>/`, `/`-separated.
    pub p: String,
    pub k: Kind,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub s: u64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub m: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub c: i64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub mode: u32,
    /// Symlink target, verbatim, for `k == "l"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
    /// Where the bytes are, for `k == "f"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r: Option<EntryRef>,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip predicate shape"
)]
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip predicate shape"
)]
fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip predicate shape"
)]
fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// Writes an index: the header, then entries the caller pushes in sorted order.
///
/// The sort is not a convention the writer hopes for — it is checked on every push,
/// because the restore side merges the index against a walk of the same shape and a
/// single misplaced line would silently drop a file.
pub struct IndexWriter<W: Write> {
    out: W,
    previous: Option<String>,
    layers: usize,
    entries: u64,
}

impl<W: Write> IndexWriter<W> {
    /// Writes `header` as the first line.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError::Io`] if the sink refuses the header line.
    pub fn new(mut out: W, header: &IndexHeader) -> Result<Self, TreeError> {
        let line =
            serde_json::to_vec(header).map_err(|err| TreeError::BadHeader(err.to_string()))?;
        out.write_all(&line)?;
        out.write_all(b"\n")?;
        Ok(Self {
            out,
            previous: None,
            layers: header.layers.len(),
            entries: 0,
        })
    }

    /// Appends one entry.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError::OutOfOrder`] if `entry` does not sort strictly after the
    /// previous one, [`TreeError::DanglingLayer`] if it references a layer the header
    /// does not list, and [`TreeError::Io`] if the sink fails.
    pub fn push(&mut self, entry: &Entry) -> Result<(), TreeError> {
        if let Some(previous) = &self.previous
            && previous.as_bytes() >= entry.p.as_bytes()
        {
            return Err(TreeError::OutOfOrder {
                previous: previous.clone(),
                actual: entry.p.clone(),
            });
        }
        if let Some(reference) = &entry.r
            && reference.l as usize >= self.layers
        {
            return Err(TreeError::DanglingLayer(entry.p.clone(), reference.l));
        }
        let line =
            serde_json::to_vec(entry).map_err(|err| TreeError::BadHeader(err.to_string()))?;
        self.out.write_all(&line)?;
        self.out.write_all(b"\n")?;
        self.previous = Some(entry.p.clone());
        self.entries += 1;
        Ok(())
    }

    /// Flushes and returns the sink plus the number of entries written.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError::Io`] if the flush fails.
    pub fn finish(mut self) -> Result<(W, u64), TreeError> {
        self.out.flush()?;
        Ok((self.out, self.entries))
    }
}

/// Reads an index: the header up front, then entries one line at a time.
///
/// Streaming is the point — the diff walks this against a freshly sorted walk without
/// either side being held whole in memory.
pub struct IndexReader<R: BufRead> {
    header: IndexHeader,
    lines: std::io::Lines<R>,
    line: usize,
}

impl<R: BufRead> IndexReader<R> {
    /// Reads and validates the header line.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError::NoHeader`] for an empty document, [`TreeError::BadHeader`]
    /// for an unparseable one, and [`TreeError::UnsupportedVersion`] for a version this
    /// build does not know.
    pub fn open(reader: R) -> Result<Self, TreeError> {
        let mut lines = reader.lines();
        let first = lines.next().ok_or(TreeError::NoHeader)??;
        let header: IndexHeader =
            serde_json::from_str(&first).map_err(|err| TreeError::BadHeader(err.to_string()))?;
        if header.v != INDEX_VERSION {
            return Err(TreeError::UnsupportedVersion(header.v));
        }
        Ok(Self {
            header,
            lines,
            line: 1,
        })
    }

    #[must_use]
    pub fn header(&self) -> &IndexHeader {
        &self.header
    }

    /// Takes the header, leaving the reader positioned at the first entry.
    #[must_use]
    pub fn into_header(self) -> IndexHeader {
        self.header
    }
}

impl<R: BufRead> Iterator for IndexReader<R> {
    type Item = Result<Entry, TreeError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(err) => return Some(Err(TreeError::Io(err))),
            };
            self.line += 1;
            if line.trim().is_empty() {
                continue;
            }
            return Some(serde_json::from_str::<Entry>(&line).map_err(|source| {
                TreeError::BadEntry {
                    line: self.line,
                    source,
                }
            }));
        }
    }
}

/// One thing the walk found, ready to become an [`Entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Path relative to `appdata/<app>/`, `/`-separated.
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub mode: u32,
    pub target: Option<String>,
    /// Where to read the bytes from — inside the frozen capture view, not the live tree.
    pub source: PathBuf,
}

/// The mirrored, volume-relative form of an absolute persisted path: `/var/lib/pg`
/// becomes `var/lib/pg`, `c:/jenkins-agent` becomes `c/jenkins-agent`. Mirrors the
/// graft's own mapping — the index and the volume must agree on where a root lives.
///
/// # Errors
///
/// Returns [`TreeError::NotMirrorable`] for a path that is neither `/`-rooted nor
/// drive-rooted (which [`PersistSpec`] already refuses at parse time).
pub fn mirror(path: &str) -> Result<String, TreeError> {
    if let Some(rest) = path.strip_prefix('/') {
        return Ok(rest.to_owned());
    }
    if let Some((drive, rest)) = path.split_once(":/") {
        return Ok(format!("{drive}/{rest}"));
    }
    Err(TreeError::NotMirrorable(path.to_owned()))
}

/// Bytes a path — or a symlink target — may take in an index. Longer than any filesystem
/// this captures from or restores onto accepts.
pub const MAX_PATH_LEN: usize = 4096;

/// Whether a symlink's target is one a restore would recreate.
///
/// **This is the one definition of the rule.** The walk skips a link that fails it, so an
/// honest tree still produces a restorable point; the restore and the archive writer
/// refuse an index that carries one anyway, which is the hard line — an index arrives over
/// the network and was not necessarily written by this walk.
///
/// A target is followed from where the link sits, so it is resolved against the link's own
/// parent rather than against the root: `../conf/x` under `data/link` stays inside, and
/// under `link` it does not. Refused outright are an empty or absolute target, a `NUL`,
/// anything over [`MAX_PATH_LEN`], and any backslash or colon — which is how every Windows
/// path that is not what it looks like begins (`c:\…`, `\\host\share`, `\\?\`, `\\.\`, and
/// an NTFS `file:stream`). A path in an index cannot hold either character, so a target
/// that does could only ever point outside the point.
///
/// `link` must already be a checked relative path: no `.` or `..` segments of its own.
#[must_use]
pub fn link_target_is_safe(link: &str, target: &str) -> bool {
    if target.is_empty() || target.len() > MAX_PATH_LEN {
        return false;
    }
    if target.starts_with('/')
        || target.contains('\0')
        || target.contains('\\')
        || target.contains(':')
    {
        return false;
    }
    // The depth of the link's own parent, counted in segments below the root.
    let mut depth = link.split('/').count() - 1;
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(next) => depth = next,
                None => return false,
            },
            _ => depth += 1,
        }
    }
    true
}

/// What one [`walk`] found, with the count of what it deliberately left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Walked {
    /// Every entry a restore point should carry, in byte-wise sorted path order.
    pub entries: Vec<WalkEntry>,
    /// Symlinks left out because [`link_target_is_safe`] refused their target — an
    /// absolute `localtime -> /usr/share/zoneinfo/UTC` and the like. Each one is warned
    /// about by path as it is skipped; this count is what a cycle's narration reports.
    pub skipped_symlinks: usize,
}

/// Walks one app's subtree of a capture view and returns every entry a restore point
/// should carry, in byte-wise sorted relative-path order.
///
/// `app_root` is `<view>/appdata/<app>` — the mirrored subtree the graft built. Each of
/// `spec`'s roots is walked at its mirrored location; each of its holes is skipped at
/// its mirrored location; each capture filter is matched against the remainder *within*
/// the root it belongs to.
///
/// A root the view does not have (an app that has not written anything yet) is not an
/// error — it contributes nothing.
///
/// # Memory
///
/// Entries are collected and sorted, because byte-wise order over full paths is not the
/// order a depth-first walk produces (`a.txt` sorts before `a/b`). One `WalkEntry` per
/// path, ~160 bytes plus the path itself.
///
/// # Errors
///
/// Returns [`TreeError::Walk`] if a directory cannot be read or a file cannot be
/// stat'ed, and [`TreeError::NotMirrorable`] for a root the graft could not have built.
pub fn walk(app_root: &Path, spec: &PersistSpec) -> Result<Vec<WalkEntry>, TreeError> {
    Ok(walk_with_stats(app_root, spec)?.entries)
}

/// [`walk`], keeping the count of what it left out.
///
/// # Errors
///
/// As [`walk`].
pub fn walk_with_stats(app_root: &Path, spec: &PersistSpec) -> Result<Walked, TreeError> {
    let mut holes: BTreeSet<String> = BTreeSet::new();
    for hole in spec.holes() {
        holes.insert(mirror(hole)?);
    }
    let mut walked = Walked::default();
    for root in spec.roots() {
        let mirrored = mirror(root)?;
        let start = app_root.join(sub_path(&mirrored));
        let Some(meta) = symlink_metadata(&start)? else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        walked
            .entries
            .push(entry_from(&mirrored, &start, &meta, None));
        walk_dir(&start, &mirrored, "", spec, &holes, &mut walked)?;
    }
    walked
        .entries
        .sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    if walked.skipped_symlinks > 0 {
        tracing::warn!(
            skipped = walked.skipped_symlinks,
            "app data: symlinks whose target a restore would refuse are left out of this \
             capture; the files around them are unaffected"
        );
    }
    Ok(walked)
}

/// Recurses one directory. `mirrored` is the entry path of `dir`; `within` is the same
/// directory expressed relative to the declared root, which is what a capture filter is
/// matched against.
fn walk_dir(
    dir: &Path,
    mirrored: &str,
    within: &str,
    spec: &PersistSpec,
    holes: &BTreeSet<String>,
    out: &mut Walked,
) -> Result<(), TreeError> {
    let listing = std::fs::read_dir(dir).map_err(|source| TreeError::Walk {
        path: dir.display().to_string(),
        source,
    })?;
    for child in listing {
        let child = child.map_err(|source| TreeError::Walk {
            path: dir.display().to_string(),
            source,
        })?;
        let name = child.file_name();
        // A name the platform cannot render as UTF-8 cannot be written to a JSON index
        // and could not be restored faithfully; skipping it is the honest answer.
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = join_rel(mirrored, name);
        let relative = join_rel(within, name);
        if holes.contains(&path) {
            continue;
        }
        if spec.is_capture_filtered(&relative) {
            continue;
        }
        let full = child.path();
        let Some(meta) = symlink_metadata(&full)? else {
            // The tree moved under the walk. A capture view is frozen, so this is a
            // genuine race only on an unfrozen directory; either way it is not fatal.
            continue;
        };
        let kind = kind_of(&meta);
        let Some(kind) = kind else {
            continue;
        };
        let mut target = None;
        if kind == Kind::Symlink {
            // A link whose target a restore would refuse is left out rather than carried:
            // an index holding one is refused whole, so a single `localtime ->
            // /usr/share/zoneinfo/UTC` would otherwise make the entire point unrestorable
            // and undownloadable. What the link pointed at is still captured on its own
            // path if it lives inside the tree.
            let found = std::fs::read_link(&full)
                .ok()
                .map(|target| target.to_string_lossy().replace('\\', "/"));
            let Some(found) = found.filter(|found| link_target_is_safe(&path, found)) else {
                out.skipped_symlinks += 1;
                tracing::warn!(
                    path = %path,
                    "app data: this symlink's target cannot be restored inside the app \
                     tree, so it is left out of the capture"
                );
                continue;
            };
            target = Some(found);
        }
        out.entries.push(entry_from(&path, &full, &meta, target));
        if kind == Kind::Dir {
            walk_dir(&full, &path, &relative, spec, holes, out)?;
        }
    }
    Ok(())
}

fn join_rel(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

/// The relative form as a native path, so `join` behaves on Windows too.
fn sub_path(relative: &str) -> PathBuf {
    relative.split('/').fold(PathBuf::new(), |path, segment| {
        if segment.is_empty() {
            path
        } else {
            path.join(segment)
        }
    })
}

/// `symlink_metadata` that treats "gone" as absence rather than failure.
fn symlink_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, TreeError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(TreeError::Walk {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn kind_of(meta: &std::fs::Metadata) -> Option<Kind> {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        Some(Kind::Symlink)
    } else if file_type.is_dir() {
        Some(Kind::Dir)
    } else if file_type.is_file() {
        Some(Kind::File)
    } else {
        None
    }
}

fn entry_from(
    path: &str,
    source: &Path,
    meta: &std::fs::Metadata,
    target: Option<String>,
) -> WalkEntry {
    let kind = kind_of(meta).unwrap_or(Kind::File);
    WalkEntry {
        path: path.to_owned(),
        kind,
        size: if kind == Kind::File { meta.len() } else { 0 },
        mtime_ns: mtime_ns(meta),
        ctime_ns: ctime_ns(meta),
        mode: mode_of(meta),
        target,
        source: source.to_owned(),
    }
}

/// Modification time in nanoseconds since the Unix epoch, clamped rather than wrapped: a
/// filesystem is free to hand back a time before 1970 or past 2262, and neither may
/// panic mid-capture.
#[must_use]
pub fn mtime_ns(meta: &std::fs::Metadata) -> i64 {
    meta.modified().map_or(0, system_time_ns)
}

/// Converts a [`std::time::SystemTime`] to nanoseconds since the Unix epoch.
#[must_use]
pub fn system_time_ns(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_nanos()).unwrap_or(i64::MAX),
        Err(err) => i64::try_from(err.duration().as_nanos()).map_or(i64::MIN, |ns| -ns),
    }
}

#[cfg(unix)]
fn ctime_ns(meta: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt as _;
    meta.ctime()
        .saturating_mul(1_000_000_000)
        .saturating_add(meta.ctime_nsec())
}

#[cfg(windows)]
fn ctime_ns(meta: &std::fs::Metadata) -> i64 {
    // Windows change time is only exposed through `MetadataExt::change_time` on recent
    // toolchains; `created` is the portable stand-in and, like ctime, is advisory here.
    meta.created().map_or(0, system_time_ns)
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    meta.mode() & 0o7777
}

#[cfg(windows)]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    // Windows carries an ACL, not a mode; the index records 0 and the restore leaves the
    // inherited ACL of the directory it materializes into.
    0
}

/// One entry of the capture plan: what the walk found, and where its bytes already live
/// when nothing about them changed.
#[derive(Debug, Clone)]
pub struct Planned {
    pub entry: WalkEntry,
    /// Set for an unchanged file: the layer its bytes are already in, resolved against
    /// the *previous* index's header so the new header can carry that layer forward.
    pub carried: Option<Carried>,
}

/// A still-good reference into a layer of an earlier point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub layer: LayerRef,
    pub offset: u64,
    pub len: u64,
}

/// Matches a fresh walk against the previous index, marking each file that can be
/// carried forward instead of re-uploaded.
///
/// A file is unchanged when its `(size, mtime_ns)` match the previous entry's — the
/// diff key of the contract. `ctime` is deliberately not part of it: a restore
/// materializes fresh inodes, so keying on ctime would make the cycle after every
/// restore a full re-upload of everything.
///
/// Both sides are in byte-wise sorted path order, so this is a merge, not a lookup
/// table: the previous index streams through and nothing is held whole.
///
/// # Errors
///
/// Returns whatever the previous-index iterator yields, and
/// [`TreeError::DanglingLayer`] if an entry references a layer the previous header does
/// not list.
pub fn diff(
    previous_header: &IndexHeader,
    previous: impl Iterator<Item = Result<Entry, TreeError>>,
    current: Vec<WalkEntry>,
) -> Result<Vec<Planned>, TreeError> {
    let mut planned: Vec<Planned> = Vec::with_capacity(current.len());
    let mut previous = previous.peekable();
    let mut pending: Option<Entry> = None;

    for entry in current {
        // Advance the previous side to the first path that is not behind this one.
        loop {
            if pending.is_none() {
                match previous.next() {
                    Some(Ok(line)) => pending = Some(line),
                    Some(Err(err)) => return Err(err),
                    None => break,
                }
            }
            let Some(line) = &pending else { break };
            if line.p.as_bytes() < entry.path.as_bytes() {
                pending = None;
                continue;
            }
            break;
        }
        let carried = match &pending {
            Some(line)
                if line.p == entry.path
                    && line.k == Kind::File
                    && entry.kind == Kind::File
                    && line.s == entry.size
                    && line.m == entry.mtime_ns =>
            {
                match line.r {
                    Some(reference) => {
                        let layer = previous_header
                            .layers
                            .get(reference.l as usize)
                            .ok_or_else(|| TreeError::DanglingLayer(line.p.clone(), reference.l))?;
                        Some(Carried {
                            layer: layer.clone(),
                            offset: reference.o,
                            len: reference.n,
                        })
                    }
                    // An entry with no reference (a seeded index that could not resolve
                    // one) is treated as changed rather than trusted.
                    None => None,
                }
            }
            _ => None,
        };
        planned.push(Planned { entry, carried });
    }
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::PersistBlock;

    fn spec(paths: &[&str]) -> PersistSpec {
        PersistSpec::parse(&PersistBlock {
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            hook_pre: None,
            hook_post: None,
        })
        .expect("spec")
    }

    fn header() -> IndexHeader {
        IndexHeader {
            v: INDEX_VERSION,
            app: "postgres".to_owned(),
            created_at: 1_700_000_000,
            layers: vec![
                LayerRef {
                    digest: "sha256:aa".to_owned(),
                    size: 10,
                },
                LayerRef {
                    digest: "sha256:bb".to_owned(),
                    size: 20,
                },
            ],
        }
    }

    fn file_entry(path: &str, size: u64, mtime: i64, layer: u32) -> Entry {
        Entry {
            p: path.to_owned(),
            k: Kind::File,
            s: size,
            m: mtime,
            c: 5,
            mode: 0o644,
            t: None,
            r: Some(EntryRef {
                l: layer,
                o: 0,
                n: size,
            }),
        }
    }

    #[test]
    fn index_round_trips_through_the_writer_and_reader() {
        let header = header();
        let entries = vec![
            Entry {
                p: "var".to_owned(),
                k: Kind::Dir,
                s: 0,
                m: 7,
                c: 8,
                mode: 0o755,
                t: None,
                r: None,
            },
            file_entry("var/data", 12, 99, 1),
            Entry {
                p: "var/link".to_owned(),
                k: Kind::Symlink,
                s: 0,
                m: 3,
                c: 4,
                mode: 0o777,
                t: Some("data".to_owned()),
                r: None,
            },
        ];
        let mut writer = IndexWriter::new(Vec::new(), &header).expect("header");
        for entry in &entries {
            writer.push(entry).expect("push");
        }
        let (bytes, count) = writer.finish().expect("finish");
        assert_eq!(count, 3);

        let reader = IndexReader::open(std::io::Cursor::new(bytes)).expect("open");
        assert_eq!(reader.header(), &header);
        let read: Vec<Entry> = reader.map(|entry| entry.expect("entry")).collect();
        assert_eq!(read, entries);
    }

    #[test]
    fn the_writer_refuses_an_out_of_order_entry() {
        let mut writer = IndexWriter::new(Vec::new(), &header()).expect("header");
        writer.push(&file_entry("b", 1, 1, 0)).expect("push");
        let err = writer.push(&file_entry("a", 1, 1, 0)).expect_err("refused");
        assert!(err.to_string().contains("sorted order"), "{err}");
        // A repeat of the same path is out of order too: the sort is strict.
        let err = writer.push(&file_entry("b", 1, 1, 0)).expect_err("refused");
        assert!(err.to_string().contains("sorted order"), "{err}");
    }

    #[test]
    fn the_writer_refuses_a_reference_the_header_does_not_carry() {
        let mut writer = IndexWriter::new(Vec::new(), &header()).expect("header");
        let err = writer.push(&file_entry("a", 1, 1, 7)).expect_err("refused");
        assert!(err.to_string().contains("references layer 7"), "{err}");
    }

    #[test]
    fn the_reader_tolerates_unknown_keys_and_refuses_a_future_version() {
        let document = "{\"v\":1,\"app\":\"a\",\"created_at\":1,\"layers\":[],\"future\":9}\n\
             {\"p\":\"x\",\"k\":\"f\",\"s\":3,\"m\":4,\"tomorrow\":true}\n";
        let reader = IndexReader::open(std::io::Cursor::new(document)).expect("open");
        let entries: Vec<Entry> = reader.map(|entry| entry.expect("entry")).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].s, 3);

        let future = "{\"v\":2,\"app\":\"a\",\"created_at\":1,\"layers\":[]}\n";
        let Err(err) = IndexReader::open(std::io::Cursor::new(future)) else {
            panic!("a future version must be refused")
        };
        assert!(err.to_string().contains("version 2"), "{err}");
    }

    #[test]
    fn mirroring_matches_the_graft() {
        assert_eq!(mirror("/var/lib/pg").expect("unix"), "var/lib/pg");
        assert_eq!(
            mirror("c:/jenkins-agent").expect("windows"),
            "c/jenkins-agent"
        );
        assert!(mirror("relative").is_err());
    }

    /// Builds the shape `graft_on` leaves on the volume: one mirrored subtree per root,
    /// with the hole's content still present but shadowed.
    fn graft_shaped_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("postgres");
        let write = |path: &Path, body: &str| {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, body).expect("write");
        };
        // Root one, with a filtered file and a nested directory.
        write(&app.join("var/lib/pg/base/1/1234"), "row data");
        write(&app.join("var/lib/pg/base/1/1234.bkp"), "backup");
        write(&app.join("var/lib/pg/postgresql.conf"), "config");
        // The hole's mirrored subtree: carried onto the volume by the migration, then
        // shadowed by the graft. Never captured.
        write(&app.join("var/lib/pg/pg_wal/000001"), "write ahead");
        // Root two.
        write(&app.join("srv/app/state.db"), "state");
        dir
    }

    fn walked(dir: &Path, spec: &PersistSpec) -> Vec<String> {
        walk(&dir.join("postgres"), spec)
            .expect("walk")
            .into_iter()
            .map(|entry| entry.path)
            .collect()
    }

    #[test]
    fn walking_a_graft_shaped_tree_skips_holes_and_filters() {
        let dir = graft_shaped_tree();
        let spec = spec(&[
            "/var/lib/pg",
            "/srv/app",
            "!/var/lib/pg/pg_wal",
            "!**/*.bkp",
        ]);
        assert_eq!(
            walked(dir.path(), &spec),
            [
                "srv/app",
                "srv/app/state.db",
                "var/lib/pg",
                "var/lib/pg/base",
                "var/lib/pg/base/1",
                "var/lib/pg/base/1/1234",
                "var/lib/pg/postgresql.conf",
            ]
        );
    }

    #[test]
    fn a_filter_is_matched_within_its_root_not_against_the_mirrored_path() {
        let dir = graft_shaped_tree();
        // `base/*` is relative to `/var/lib/pg`, so it prunes the mirrored
        // `var/lib/pg/base/1` subtree.
        let within = spec(&["/var/lib/pg", "!/var/lib/pg/pg_wal", "!base/*"]);
        assert_eq!(
            walked(dir.path(), &within),
            [
                "var/lib/pg",
                "var/lib/pg/base",
                "var/lib/pg/postgresql.conf"
            ]
        );
        // The same pattern written against the mirrored path matches nothing: it would
        // need a `var/lib/pg` directory *inside* the root to hit.
        let mirrored = spec(&["/var/lib/pg", "!/var/lib/pg/pg_wal", "!var/lib/pg/*"]);
        assert!(
            walked(dir.path(), &mirrored).contains(&"var/lib/pg/base/1/1234".to_owned()),
            "a mirrored-path pattern must not match"
        );
    }

    #[test]
    fn walking_records_sizes_and_a_missing_root_is_not_an_error() {
        let dir = graft_shaped_tree();
        let spec = spec(&["/var/lib/pg", "/opt/never-written", "!/var/lib/pg/pg_wal"]);
        let entries = walk(&dir.path().join("postgres"), &spec).expect("walk");
        let conf = entries
            .iter()
            .find(|entry| entry.path == "var/lib/pg/postgresql.conf")
            .expect("conf");
        assert_eq!(conf.kind, Kind::File);
        assert_eq!(conf.size, 6);
        assert!(conf.mtime_ns > 0);
        assert!(!entries.iter().any(|entry| entry.path.starts_with("opt")));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_recorded_by_its_target_and_never_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("postgres/srv/app");
        std::fs::create_dir_all(app.join("real")).expect("mkdir");
        std::fs::write(app.join("real/file"), "body").expect("write");
        std::os::unix::fs::symlink("real", app.join("link")).expect("symlink");
        let spec = spec(&["/srv/app"]);
        let entries = walk(&dir.path().join("postgres"), &spec).expect("walk");
        let link = entries
            .iter()
            .find(|entry| entry.path == "srv/app/link")
            .expect("link");
        assert_eq!(link.kind, Kind::Symlink);
        assert_eq!(link.target.as_deref(), Some("real"));
        // Not followed: the target's contents appear once, under `real`.
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.path.ends_with("/file"))
                .count(),
            1
        );
    }

    /// An honest app tree holds absolute symlinks — `localtime -> /usr/share/zoneinfo/UTC`
    /// is the everyday one. A restore refuses an index carrying such a target, so carrying
    /// it would make the whole point unrestorable over one link. It is left out instead,
    /// counted, and warned about; everything around it is captured as before.
    #[cfg(unix)]
    #[test]
    fn a_symlink_a_restore_would_refuse_is_left_out_of_the_walk_and_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("postgres/srv/app");
        std::fs::create_dir_all(app.join("real")).expect("mkdir");
        std::fs::write(app.join("real/file"), "body").expect("write");
        // The one an honest tree has, and the one only a hostile index would.
        std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", app.join("localtime"))
            .expect("symlink");
        std::os::unix::fs::symlink("real", app.join("link")).expect("symlink");

        let walked =
            walk_with_stats(&dir.path().join("postgres"), &spec(&["/srv/app"])).expect("walk");
        assert_eq!(walked.skipped_symlinks, 1);
        assert!(
            !walked
                .entries
                .iter()
                .any(|entry| entry.path == "srv/app/localtime"),
            "the absolute link must not reach the index"
        );
        // Everything else is untouched — the link beside it, and the files.
        assert_eq!(
            walked
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            [
                "srv/app",
                "srv/app/link",
                "srv/app/real",
                "srv/app/real/file"
            ]
        );
        // And what is left is an index the restore side accepts: every target passes the
        // one shared rule.
        for entry in &walked.entries {
            if entry.kind == Kind::Symlink {
                assert!(link_target_is_safe(
                    &entry.path,
                    entry.target.as_deref().unwrap_or_default()
                ));
            }
        }
    }

    /// A link whose target cannot even be read is left out the same way: an index entry
    /// with no target is one the restore refuses.
    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_tree_is_skipped_whatever_shape_it_takes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("postgres/srv/app");
        std::fs::create_dir_all(&app).expect("mkdir");
        for (name, target) in [
            ("absolute", "/etc/shadow"),
            ("climbing", "../../../outside"),
            ("windows", "c:/windows"),
            ("unc", "\\\\host\\share"),
        ] {
            std::os::unix::fs::symlink(target, app.join(name)).expect("symlink");
        }
        let walked =
            walk_with_stats(&dir.path().join("postgres"), &spec(&["/srv/app"])).expect("walk");
        assert_eq!(walked.skipped_symlinks, 4);
        assert_eq!(
            walked.entries.len(),
            1,
            "only the root directory survives: {:?}",
            walked.entries
        );
    }

    #[test]
    fn a_walk_is_sorted_byte_wise_over_whole_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("postgres/srv/app");
        std::fs::create_dir_all(app.join("a")).expect("mkdir");
        std::fs::write(app.join("a/b"), "x").expect("write");
        std::fs::write(app.join("a.txt"), "y").expect("write");
        let spec = spec(&["/srv/app"]);
        let paths = walked(dir.path(), &spec);
        // '.' (0x2E) sorts before '/' (0x2F), so `a.txt` precedes `a/b` even though a
        // depth-first walk meets the directory first.
        assert_eq!(
            paths,
            ["srv/app", "srv/app/a", "srv/app/a.txt", "srv/app/a/b"]
        );
    }

    fn walk_entry(path: &str, size: u64, mtime: i64) -> WalkEntry {
        WalkEntry {
            path: path.to_owned(),
            kind: Kind::File,
            size,
            mtime_ns: mtime,
            ctime_ns: 0,
            mode: 0o644,
            target: None,
            source: PathBuf::from(path),
        }
    }

    #[test]
    fn diff_carries_unchanged_files_and_re_reads_changed_ones() {
        let header = header();
        let previous = vec![
            Ok(file_entry("a", 10, 100, 0)),
            Ok(file_entry("b", 20, 200, 1)),
            Ok(file_entry("c", 30, 300, 1)),
        ];
        let current = vec![
            walk_entry("a", 10, 100), // unchanged
            walk_entry("b", 20, 201), // touched: mtime moved
            walk_entry("c", 31, 300), // grew
            walk_entry("d", 5, 5),    // new
        ];
        let planned = diff(&header, previous.into_iter(), current).expect("diff");
        let carried: Vec<bool> = planned.iter().map(|item| item.carried.is_some()).collect();
        assert_eq!(carried, [true, false, false, false]);
        let first = planned[0].carried.as_ref().expect("carried");
        assert_eq!(first.layer.digest, "sha256:aa");
        assert_eq!(first.len, 10);
    }

    #[test]
    fn diff_ignores_ctime_and_entries_the_walk_no_longer_sees() {
        let header = header();
        let mut previous_entry = file_entry("a", 10, 100, 0);
        previous_entry.c = 42;
        let previous = vec![
            Ok(file_entry("0-gone", 1, 1, 0)),
            Ok(previous_entry),
            Ok(file_entry("z-gone", 1, 1, 0)),
        ];
        let mut current = walk_entry("a", 10, 100);
        current.ctime_ns = 999;
        let planned = diff(&header, previous.into_iter(), vec![current]).expect("diff");
        assert_eq!(planned.len(), 1);
        assert!(planned[0].carried.is_some(), "ctime is advisory");
    }

    #[test]
    fn diff_never_carries_a_directory_or_a_reference_free_entry() {
        let header = header();
        let mut reference_free = file_entry("a", 10, 100, 0);
        reference_free.r = None;
        let mut directory = walk_entry("d", 0, 7);
        directory.kind = Kind::Dir;
        let previous = vec![
            Ok(reference_free),
            Ok(Entry {
                p: "d".to_owned(),
                k: Kind::Dir,
                s: 0,
                m: 7,
                c: 0,
                mode: 0o755,
                t: None,
                r: None,
            }),
        ];
        let planned = diff(
            &header,
            previous.into_iter(),
            vec![walk_entry("a", 10, 100), directory],
        )
        .expect("diff");
        assert!(planned.iter().all(|item| item.carried.is_none()));
    }
}
