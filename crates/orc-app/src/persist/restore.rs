//! Materializing a restore point: index first, then one sequential pass per layer.
//!
//! # Shape of the pass
//!
//! The index layer is read first and held in a **compact** form — one fixed-size record
//! per file plus a single path arena, capped on entry count rather than bytes, because a
//! million-file tree is a size the design promises to survive. Directories, symlinks, and
//! empty files are created while the index streams past; they need no layer.
//!
//! The remaining records are then sorted by `(layer, offset)` and each data layer is read
//! **once**, start to finish, scattering bytes into files as their offsets are reached.
//! A layer is never seeked, never buffered whole, and never re-read: the layer's plaintext
//! is the concatenation of the files that reference it, in offset order, so one forward
//! pass fills them all.
//!
//! # Where it lands
//!
//! Everything is written to `<dest_parent>/<app>.restoring`. The caller performs the swap
//! into place once the whole point has materialized, so a failure part-way leaves the live
//! subtree untouched. On failure the temporary directory is left where it is — the caller
//! removes it, and an operator who wants to look at it can.
//!
//! # Symlinks come last, and that is not cosmetic
//!
//! The index arrives over the network and the directory it builds is later renamed over
//! live data, so it is treated as hostile input. Refusing `..` and absolute paths in
//! [`safe_join`] is not enough on its own: an index holding a symlink `a -> /etc` followed
//! by a file `a/x` would, if the two were materialized in index order, write through the
//! link it had just created — every path in it passing the textual check.
//!
//! So materialization runs in phases: **directories, then files, then every file's mode
//! and time, then symlinks**, and only then the link and directory times. While bytes are
//! being written — and while `chmod` is being called — no symlink exists anywhere under
//! the destination, which is what makes "the path is textually inside the root" mean "the
//! write lands inside the root". `chmod(2)` follows a symlink, so a metadata pass that ran
//! after the links existed would be one an index could aim: name a path a file, then name
//! it again a symlink to somewhere else, and the mode meant for the file lands on the
//! link's target instead.
//!
//! Three things close that, and all three are kept. The parser refuses an index that names
//! any path twice (the writer emits strictly ascending paths, so reading them back the same
//! way is free). Metadata is applied before a single symlink exists. And the metadata pass
//! itself `symlink_metadata`-checks each path and skips anything that turned out to be a
//! link. As a further line, a file is only ever created inside a directory this restore
//! itself created — the parent is `symlink_metadata`-checked and never `create_dir_all`ed
//! on the file path, so a parent that is anything but a real directory is a refusal.
//!
//! Symlink targets are checked where the paths are: at parse time. A target that is
//! absolute, that climbs out of the root from where the link sits, or that is a Windows
//! path in disguise (a drive letter, a UNC or device prefix) is refused rather than
//! created, because the tree is renamed over live data and handed to people who extract it.
//!
//! # Failing loudly
//!
//! Every failure aborts: a layer whose sha256 does not match (the blob reader reports it at
//! EOF), a frame the AEAD refuses, an index line that will not parse, a path that tries to
//! escape the destination. A restore that silently dropped a file would hand the app a tree
//! that looks complete and is not, and the node would carry that hole forward into every
//! later point.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::CliError;
use crate::persist::PersistSpec;
use crate::persist::seal::{KeyRing, Opener, SealError};
use crate::persist::stream::{StreamError, decode_sealed_sequential};
use crate::persist::tree::{
    Entry, EntryRef, IndexHeader, IndexWriter, Kind, LayerRef, TreeError, mirror,
};
use crate::registry::RegistryClient;

/// Entries one restore point may carry. A tree past this is beyond what the format is
/// designed for, and the cap is what stops a malformed index from exhausting the node.
pub const MAX_INDEX_ENTRIES: usize = 2_000_000;

/// Bytes of path and symlink-target text one index may hold — 2 M entries at an average
/// 128-byte path. Every path is charged against it, whatever its entry's kind, and so is
/// every symlink target: charging only the file paths would bound a third of the memory
/// the number names.
pub const MAX_PATH_ARENA: usize = 256 * 1024 * 1024;

/// Bytes one line of the index may take. Every field on a line is bounded well under
/// this; the cap is what stops a document with no newline in it from being accumulated
/// whole while the parser waits for one.
pub const MAX_INDEX_LINE: usize = 64 * 1024;

/// Bytes one path — or one symlink target — may take. Longer than any filesystem this
/// restores onto accepts, and short enough that a million of them are a bounded cost.
/// Defined with the walk that writes an index, so both halves hold one number.
pub use crate::persist::tree::MAX_PATH_LEN;

/// Suffix of the directory a restore materializes into before the caller swaps it in.
pub const RESTORING_SUFFIX: &str = ".restoring";

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("app data restore I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Index(#[from] TreeError),
    #[error(transparent)]
    Registry(#[from] CliError),
    #[error("app data index carries more than {MAX_INDEX_ENTRIES} entries")]
    TooManyEntries,
    #[error("app data index paths exceed the {MAX_PATH_ARENA}-byte budget")]
    PathsTooLarge,
    #[error("app data index carries a line longer than {MAX_INDEX_LINE} bytes")]
    LineTooLong,
    #[error("app data index carries a path longer than the {MAX_PATH_LEN}-byte limit")]
    PathTooLong,
    #[error(
        "app data index entry {0:?} is a symlink whose target cannot be restored inside \
         the app tree"
    )]
    UnsafeLinkTarget(String),
    #[error("app data index entry {0:?} references layer {1}, which the index does not list")]
    DanglingLayer(String, u32),
    #[error("app data index entry {0:?} is not a path that can be restored inside the app tree")]
    UnsafePath(String),
    #[error("app data index entry {0:?} is a file with no location in any layer")]
    Unplaced(String),
    #[error(
        "app data index entry {0:?} has no directory to be restored into, or its parent is \
         not one this restore created"
    )]
    BadParent(String),
    #[error("app data layer {digest} ends after {read} bytes; entries reach to {needed}")]
    LayerShort {
        digest: String,
        read: u64,
        needed: u64,
    },
    #[error(
        "app data layer {digest} holds an entry at offset {offset} of length {len}, a \
         range no layer can have"
    )]
    LayerRange {
        digest: String,
        offset: u64,
        len: u64,
    },
    #[error(
        "app data layer {number} of {total} ({digest}) failed authentication: no key given \
         opens it. This restore point has layers sealed under more than one key: pass every \
         key the pool holds (the node page's Pull command lists them all)"
    )]
    LayerUnauthentic {
        /// 1-based position of the layer in the pass, as the progress lines count it.
        number: usize,
        total: usize,
        digest: String,
    },
    #[error("app data restore task failed: {0}")]
    Task(String),
}

/// Names the layer an authentication failure happened on, and says what a person can do
/// about it.
///
/// A layer that no key in the ring opens is almost always a rotated pool read with fewer
/// keys than it holds: the point's own key opens what the point wrote, and a layer dedup
/// carried forward from before the rotation needs the key of the day it was written. The
/// bare AEAD message ("wrong key or tampered bytes") sends a reader looking for
/// corruption instead; this one names the layer and the remedy. Anything else passes
/// through untouched — a digest mismatch or a short read is not a key problem.
pub(crate) fn name_the_layer(
    err: RestoreError,
    number: usize,
    total: usize,
    digest: &str,
) -> RestoreError {
    if matches!(
        err,
        RestoreError::Stream(StreamError::Seal(SealError::Unauthentic))
    ) {
        return RestoreError::LayerUnauthentic {
            number,
            total,
            digest: digest.to_owned(),
        };
    }
    err
}

/// So a command line can return a restore failure with the exit code it deserves.
///
/// A registry failure keeps the kind it arrived with — "not found" and "unauthorized" are
/// worth telling apart from "this point will not decode". An output that already exists is
/// a conflict, the same answer `orc pull` gives for any file it will not overwrite.
/// Everything else is operational: a digest, an AEAD tag, or a malformed index, none of
/// which the caller can do anything about but retry.
impl From<RestoreError> for CliError {
    fn from(err: RestoreError) -> Self {
        match err {
            RestoreError::Registry(err) => err,
            RestoreError::Io(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::Conflict(err.to_string())
            }
            other => Self::Operational(other.to_string()),
        }
    }
}

/// A restore point as the login reply describes it.
///
/// It deliberately carries no layer list: the index layer's own header names the layers,
/// so the reply cannot disagree with the thing it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    pub app: String,
    pub id: String,
    pub key_id: String,
    pub created_at: i64,
    pub index: LayerRef,
    /// Declared by the writer that created the point; narration only.
    pub files: u64,
    /// Declared plaintext total; narration only.
    pub bytes: u64,
}

/// What a restore actually put on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreStats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub layers: usize,
}

/// One file's place in the point, in the compact form the restore holds a million of.
#[derive(Debug, Clone, Copy)]
struct FileRecord {
    layer: u32,
    offset: u64,
    len: u64,
    /// Byte range of the path within the arena.
    path: u32,
    path_len: u32,
    mtime_ns: i64,
    mode: u32,
}

/// A directory whose metadata is applied once everything inside it exists.
#[derive(Debug, Clone)]
struct MetaRecord {
    path: String,
    mtime_ns: i64,
    mode: u32,
}

/// A symlink, held back until every byte of the point has been written. See the module
/// docs: creating one earlier would give a hostile index a path out of the destination.
#[derive(Debug, Clone)]
struct SymlinkRecord {
    path: String,
    target: String,
    mtime_ns: i64,
}

/// The parsed index of a point: enough to materialize it, and enough to seed the local
/// index afterwards without downloading it again.
pub struct PointIndex {
    header: IndexHeader,
    /// File records in index (path) order, so a path lookup is a binary search.
    files: Vec<FileRecord>,
    arena: String,
    dirs: Vec<MetaRecord>,
    symlinks: Vec<SymlinkRecord>,
}

impl std::fmt::Debug for PointIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PointIndex")
            .field("app", &self.header.app)
            .field("layers", &self.header.layers.len())
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

/// One file of a point, as an enumerator hands it out: where its bytes live and what
/// metadata to restore with them.
#[derive(Debug, Clone, Copy)]
pub struct IndexFile<'a> {
    pub path: &'a str,
    /// Index into [`IndexHeader::layers`].
    pub layer: u32,
    /// Byte offset of this file's bytes within that layer's plaintext.
    pub offset: u64,
    pub len: u64,
    /// Modification time in **nanoseconds** since the Unix epoch.
    pub mtime_ns: i64,
    /// Unix permission bits, or `0` for a point captured on Windows.
    pub mode: u32,
}

/// One directory of a point.
#[derive(Debug, Clone, Copy)]
pub struct IndexDir<'a> {
    pub path: &'a str,
    pub mtime_ns: i64,
    pub mode: u32,
}

/// One symlink of a point. The target is the point's own bytes and is never rewritten.
#[derive(Debug, Clone, Copy)]
pub struct IndexSymlink<'a> {
    pub path: &'a str,
    pub target: &'a str,
    pub mtime_ns: i64,
}

impl PointIndex {
    /// Parses a point's index layer off `reader`, opening its frames with `opener`.
    ///
    /// Touches no filesystem: what comes back is the whole point in compact form, which
    /// is what lets a restore materialize it and an archive writer stream it without
    /// either duplicating the parse. Paths are validated here, whatever their kind, so a
    /// refusal never depends on an entry surviving to the phase that would have used it.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError`] for a malformed header or entry, an entry count or path
    /// arena over budget, a file that names a layer the header does not list or no
    /// location at all, a path that could escape its root, and any decode failure the
    /// sealed stream reports.
    pub fn read(reader: impl std::io::Read, opener: &dyn Opener) -> Result<Self, RestoreError> {
        let mut parser = IndexParser {
            header: None,
            files: Vec::new(),
            arena: String::new(),
            dirs: Vec::new(),
            symlinks: Vec::new(),
            previous: String::new(),
            charged: 0,
            pending: Vec::new(),
            failure: None,
        };
        decode_sealed_sequential(reader, opener, &mut |chunk| {
            parser.feed(chunk);
            Ok(())
        })?;
        parser.finish()
    }

    #[must_use]
    pub fn header(&self) -> &IndexHeader {
        &self.header
    }

    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// What the point holds, for a caller that reports it without materializing it.
    #[must_use]
    pub fn stats(&self) -> RestoreStats {
        RestoreStats {
            files: self.files.len() as u64,
            dirs: self.dirs.len() as u64,
            symlinks: self.symlinks.len() as u64,
            bytes: 0,
            layers: 0,
        }
    }

    /// Every file, in index (path) order.
    pub fn files(&self) -> impl Iterator<Item = IndexFile<'_>> {
        self.files.iter().map(|record| IndexFile {
            path: self.path_of(record),
            layer: record.layer,
            offset: record.offset,
            len: record.len,
            mtime_ns: record.mtime_ns,
            mode: record.mode,
        })
    }

    /// Every directory, in index (path) order — parents before their children.
    pub fn dirs(&self) -> impl Iterator<Item = IndexDir<'_>> {
        self.dirs.iter().map(|record| IndexDir {
            path: &record.path,
            mtime_ns: record.mtime_ns,
            mode: record.mode,
        })
    }

    /// Every symlink, in index (path) order.
    pub fn symlinks(&self) -> impl Iterator<Item = IndexSymlink<'_>> {
        self.symlinks.iter().map(|record| IndexSymlink {
            path: &record.path,
            target: &record.target,
            mtime_ns: record.mtime_ns,
        })
    }

    fn path_of(&self, record: &FileRecord) -> &str {
        let start = record.path as usize;
        &self.arena[start..start + record.path_len as usize]
    }

    /// Where a path's bytes live in this point, if it holds that path at all.
    #[must_use]
    pub fn reference(&self, path: &str) -> Option<EntryRef> {
        let found = self
            .files
            .binary_search_by(|record| self.path_of(record).as_bytes().cmp(path.as_bytes()))
            .ok()?;
        let record = &self.files[found];
        Some(EntryRef {
            l: record.layer,
            o: record.offset,
            n: record.len,
        })
    }
}

/// A materialized restore point, still under its temporary name.
pub struct RestoredPoint {
    root: PathBuf,
    stats: RestoreStats,
    index: PointIndex,
}

impl RestoredPoint {
    /// The temporary directory the point was written to. The caller renames it into place.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn stats(&self) -> RestoreStats {
        self.stats
    }

    #[must_use]
    pub fn index(&self) -> &PointIndex {
        &self.index
    }

    /// Writes the local capture index for the restored tree.
    ///
    /// This is what keeps the first capture after a restore incremental. The tree is
    /// walked as a capture would walk it — same filters, same holes — and every file that
    /// the point placed keeps the point's `{layer, offset, length}`, while its size and
    /// **mtime are taken from the materialized file**, not from the index. A restore
    /// cannot reproduce the original timestamps exactly on every filesystem, and the diff
    /// keys on `(size, mtime)`; re-stat'ing is what makes the next diff say "unchanged"
    /// instead of re-uploading the whole tree.
    ///
    /// `root` is where the subtree now lives (after the caller's swap), not the temporary
    /// directory.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError::Index`] if the tree cannot be walked or the index cannot be
    /// written.
    pub fn seed_index(
        &self,
        root: &Path,
        spec: &PersistSpec,
        dest: &Path,
    ) -> Result<u64, RestoreError> {
        let entries = crate::persist::tree::walk(root, spec)?;
        let file = std::fs::File::create(dest)?;
        let header = IndexHeader {
            v: crate::persist::tree::INDEX_VERSION,
            app: self.index.header.app.clone(),
            created_at: self.index.header.created_at,
            layers: self.index.header.layers.clone(),
        };
        let mut writer = IndexWriter::new(std::io::BufWriter::new(file), &header)?;
        for entry in entries {
            let reference = if entry.kind == Kind::File {
                self.index.reference(&entry.path).map(|reference| EntryRef {
                    // The bytes on disk are the point's bytes; only the length recorded
                    // here has to agree with what was actually materialized.
                    n: entry.size,
                    ..reference
                })
            } else {
                None
            };
            writer.push(&Entry {
                p: entry.path,
                k: entry.kind,
                s: entry.size,
                m: entry.mtime_ns,
                c: entry.ctime_ns,
                mode: entry.mode,
                t: entry.target,
                r: reference,
            })?;
        }
        let (mut out, count) = writer.finish()?;
        out.flush()?;
        Ok(count)
    }
}

/// Watches a point's layer pass, so a caller with a person waiting on it can say how far
/// along it is.
///
/// A node restoring on its own behalf reports nothing; `orc pull` prints a line. The
/// callback runs on the async task driving the pass, between layers, so it must not block.
pub trait LayerObserver: Send + Sync {
    /// Called just before layer `number` of `total` is fetched, both 1-based over the
    /// layers this pass will actually read (a listed layer nothing references is skipped
    /// and not counted). `bytes` is the plaintext written by the layers before it.
    fn layer(&self, number: usize, total: usize, bytes: u64);
}

/// Materializes restore points.
pub struct Restorer;

impl Restorer {
    /// Materializes `point` into `<dest_parent>/<app>.restoring` and returns what landed.
    ///
    /// A leftover directory from an earlier attempt is removed first — the point is
    /// materialized whole or not at all, so there is nothing in it worth resuming.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError`] on any integrity failure (digest, AEAD, malformed index,
    /// escaping path) or I/O failure. The temporary directory is left in place for the
    /// caller to remove.
    pub async fn materialize(
        client: &RegistryClient,
        repository: &str,
        ring: &KeyRing,
        point: &RestorePoint,
        dest_parent: &Path,
    ) -> Result<RestoredPoint, RestoreError> {
        Self::materialize_observed(client, repository, ring, point, dest_parent, None).await
    }

    /// [`Self::materialize`], reporting each layer to `observer` as it is reached.
    ///
    /// # Errors
    ///
    /// As [`Self::materialize`].
    pub async fn materialize_observed(
        client: &RegistryClient,
        repository: &str,
        ring: &KeyRing,
        point: &RestorePoint,
        dest_parent: &Path,
        observer: Option<&dyn LayerObserver>,
    ) -> Result<RestoredPoint, RestoreError> {
        // The point names the key it was sealed under, which is the right one to try
        // first — but layers it carried forward from an earlier point were sealed under
        // whatever key the pool held then, so the whole ring travels with it.
        let ring = Arc::new(ring.preferring(&point.key_id));
        let root = dest_parent.join(format!("{}{RESTORING_SUFFIX}", point.app));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;

        // 1. The index, streamed through the sequential decoder into compact records,
        //    then the directories it declares. Files and symlinks are only recorded.
        let reader = client
            .get_blob_reader(repository, &point.index.digest)
            .await?;
        let index_ring = Arc::clone(&ring);
        let index = tokio::task::spawn_blocking(move || PointIndex::read(reader, &*index_ring))
            .await
            .map_err(|err| RestoreError::Task(err.to_string()))??;
        let mut stats = index.stats();
        for record in index.dirs() {
            std::fs::create_dir_all(safe_join(&root, record.path)?)?;
        }

        // 2. Files. Empty ones first, then one forward pass per layer in header order.
        //    No symlink exists anywhere under `root` while any of this runs.
        let mut verified: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        for record in &index.files {
            if record.len == 0 {
                create_in_place(&root, index.path_of(record), &mut verified)?;
            }
        }
        let mut order: Vec<usize> = (0..index.files.len())
            .filter(|position| index.files[*position].len > 0)
            .collect();
        order.sort_unstable_by_key(|position| {
            let record = &index.files[*position];
            (record.layer, record.offset)
        });
        let mut by_layer: HashMap<u32, Vec<usize>> = HashMap::new();
        for position in order {
            by_layer
                .entry(index.files[position].layer)
                .or_default()
                .push(position);
        }

        let total_layers = by_layer.len();
        for (number, layer) in index.header.layers.iter().enumerate() {
            let Some(positions) = by_layer.remove(&u32::try_from(number).unwrap_or(u32::MAX))
            else {
                // A layer nothing references. Harmless — a carried layer whose last
                // reference vanished would simply not be listed — but not worth reading.
                continue;
            };
            let position_in_pass = stats.layers + 1;
            if let Some(observer) = observer {
                observer.layer(position_in_pass, total_layers, stats.bytes);
            }
            let plan: Vec<(FileRecord, String)> = positions
                .iter()
                .map(|position| {
                    let record = index.files[*position];
                    (record, index.path_of(&record).to_owned())
                })
                .collect();
            let reader = client.get_blob_reader(repository, &layer.digest).await?;
            let layer_root = root.clone();
            let layer_ring = Arc::clone(&ring);
            let digest = layer.digest.clone();
            let written = tokio::task::spawn_blocking(move || {
                scatter_layer(reader, &*layer_ring, &layer_root, &digest, &plan)
            })
            .await
            .map_err(|err| RestoreError::Task(err.to_string()))?
            .map_err(|err| name_the_layer(err, position_in_pass, total_layers, &layer.digest))?;
            stats.bytes += written;
            stats.layers += 1;
        }

        // 3. Every file's mode and time, while there is still no symlink anywhere under
        //    `root` for `chmod(2)` to follow. See the module docs: this ordering is the
        //    reason an index cannot aim a mode at a path outside the destination.
        for record in &index.files {
            let path = safe_join(&root, index.path_of(record))?;
            apply_metadata(&path, record.mtime_ns, record.mode);
        }

        // 4. Symlinks, only now that every byte is written and every mode is set. See the
        //    module docs: this ordering is what keeps a hostile index from being handed a
        //    path out.
        for record in &index.symlinks {
            let path = safe_join(&root, &record.path)?;
            create_symlink(&record.target, &path, &verified);
        }

        // 5. The times that had to wait: a symlink's own, and a directory's only once
        //    everything inside it has been created — symlinks included, since creating one
        //    moves its parent's mtime. Deepest directory first, so a parent is set after
        //    its children.
        for record in &index.symlinks {
            let path = safe_join(&root, &record.path)?;
            apply_link_mtime(&path, record.mtime_ns);
        }
        for record in index.dirs.iter().rev() {
            let path = safe_join(&root, &record.path)?;
            apply_metadata(&path, record.mtime_ns, record.mode);
        }

        Ok(RestoredPoint { root, stats, index })
    }
}

/// Parses the index layer's lines into the compact records [`PointIndex`] holds.
struct IndexParser {
    header: Option<IndexHeader>,
    files: Vec<FileRecord>,
    arena: String,
    dirs: Vec<MetaRecord>,
    symlinks: Vec<SymlinkRecord>,
    /// The path of the entry before this one. The index is written in strictly ascending
    /// path order, and reading it back the same way is what rules out a path named twice.
    /// Empty means "no entry yet": a path is never empty.
    previous: String,
    /// Path and symlink-target bytes held so far, whichever collection holds them —
    /// [`MAX_PATH_ARENA`] is charged against this, not against the file arena alone.
    charged: usize,
    /// Bytes of a line the previous chunk ended in the middle of.
    pending: Vec<u8>,
    failure: Option<RestoreError>,
}

impl IndexParser {
    /// The decoder's sink cannot fail informatively, so the first error is latched and
    /// surfaced by [`finish`](Self::finish); later lines are ignored.
    ///
    /// A line is capped at [`MAX_INDEX_LINE`], the partial one included. Without that cap
    /// an index layer holding no newline at all — which the AEAD happily authenticates,
    /// since it is the key holder who wrote it — would be accumulated whole in `pending`
    /// while the parser waited for a line it is never going to get.
    fn feed(&mut self, chunk: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let mut rest = chunk;
        while let Some(position) = rest.iter().position(|byte| *byte == b'\n') {
            let (line, tail) = rest.split_at(position);
            if self.pending.len() + line.len() > MAX_INDEX_LINE {
                self.failure = Some(RestoreError::LineTooLong);
                return;
            }
            if self.pending.is_empty() {
                self.line(line);
            } else {
                let mut whole = std::mem::take(&mut self.pending);
                whole.extend_from_slice(line);
                self.line(&whole);
            }
            rest = &tail[1..];
            if self.failure.is_some() {
                return;
            }
        }
        if self.pending.len() + rest.len() > MAX_INDEX_LINE {
            self.failure = Some(RestoreError::LineTooLong);
            return;
        }
        self.pending.extend_from_slice(rest);
    }

    fn line(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        if self.header.is_none() {
            match serde_json::from_slice::<IndexHeader>(line) {
                Ok(header) if header.v == crate::persist::tree::INDEX_VERSION => {
                    self.header = Some(header);
                }
                Ok(header) => {
                    self.failure = Some(TreeError::UnsupportedVersion(header.v).into());
                }
                Err(err) => self.failure = Some(TreeError::BadHeader(err.to_string()).into()),
            }
            return;
        }
        let entry: Entry = match serde_json::from_slice(line) {
            Ok(entry) => entry,
            Err(source) => {
                self.failure = Some(
                    TreeError::BadEntry {
                        line: self.entries() + 2,
                        source,
                    }
                    .into(),
                );
                return;
            }
        };
        if let Err(err) = self.entry(&entry) {
            self.failure = Some(err);
        }
    }

    fn entry(&mut self, entry: &Entry) -> Result<(), RestoreError> {
        if self.entries() >= MAX_INDEX_ENTRIES {
            return Err(RestoreError::TooManyEntries);
        }
        // Validate every path as it is parsed, whatever its kind: a refusal must not
        // depend on the entry surviving to the phase that would have used it.
        check_relative(&entry.p)?;
        // [`IndexWriter::push`] emits strictly ascending paths and refuses anything else,
        // so requiring the same here costs one comparison and buys the guarantee the
        // phases lean on: no path is named twice. Two entries of different kinds for one
        // path would have the later phase write over what the earlier one made — a file,
        // then a symlink over it — and the mode meant for the file would land on whatever
        // the link points at.
        if !self.previous.is_empty() && self.previous.as_bytes() >= entry.p.as_bytes() {
            return Err(TreeError::OutOfOrder {
                previous: self.previous.clone(),
                actual: entry.p.clone(),
            }
            .into());
        }
        self.charge(entry.p.len())?;
        match entry.k {
            Kind::Dir => {
                self.dirs.push(MetaRecord {
                    path: entry.p.clone(),
                    mtime_ns: entry.m,
                    mode: entry.mode,
                });
            }
            Kind::Symlink => {
                // Recorded only. Every symlink is created in the last phase, after the
                // final byte of the last layer has landed — but its target is checked
                // here, with the paths, because that is where a refusal belongs.
                let target = entry.t.as_deref().unwrap_or_default();
                check_link_target(&entry.p, target)?;
                self.charge(target.len())?;
                self.symlinks.push(SymlinkRecord {
                    path: entry.p.clone(),
                    target: target.to_owned(),
                    mtime_ns: entry.m,
                });
            }
            Kind::File => {
                let reference = entry
                    .r
                    .ok_or_else(|| RestoreError::Unplaced(entry.p.clone()))?;
                if let Some(header) = &self.header
                    && reference.l as usize >= header.layers.len()
                {
                    return Err(RestoreError::DanglingLayer(entry.p.clone(), reference.l));
                }
                let start = u32::try_from(self.arena.len()).unwrap_or(u32::MAX);
                self.arena.push_str(&entry.p);
                self.files.push(FileRecord {
                    layer: reference.l,
                    offset: reference.o,
                    len: reference.n,
                    path: start,
                    path_len: u32::try_from(entry.p.len()).unwrap_or(u32::MAX),
                    mtime_ns: entry.m,
                    mode: entry.mode,
                });
            }
        }
        self.previous.clear();
        self.previous.push_str(&entry.p);
        Ok(())
    }

    /// Entries held so far, of every kind. The cap has to bound the whole index:
    /// symlinks going uncounted made it a cap on two thirds of what one can carry.
    fn entries(&self) -> usize {
        self.files.len() + self.dirs.len() + self.symlinks.len()
    }

    /// Charges `bytes` of path or target text against [`MAX_PATH_ARENA`].
    fn charge(&mut self, bytes: usize) -> Result<(), RestoreError> {
        self.charged = self.charged.saturating_add(bytes);
        if self.charged > MAX_PATH_ARENA {
            return Err(RestoreError::PathsTooLarge);
        }
        Ok(())
    }

    fn finish(mut self) -> Result<PointIndex, RestoreError> {
        // The last line of a document that ended without a newline still has to be
        // parsed — but only if nothing has failed yet. Parsing it after a latched failure
        // would replace the first refusal with whatever the leftover bytes look like.
        if self.failure.is_none() && !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.line(&line);
        }
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        let header = self.header.ok_or(TreeError::NoHeader)?;
        Ok(PointIndex {
            header,
            files: self.files,
            arena: self.arena,
            dirs: self.dirs,
            symlinks: self.symlinks,
        })
    }
}

/// Reads one layer front to back, writing each file's slice as its offset is reached.
///
/// `plan` is in ascending offset order and its ranges do not overlap — the layer's
/// plaintext is exactly the concatenation of those files — so this never seeks and never
/// holds more than the decoder's current chunk.
fn scatter_layer(
    reader: impl std::io::Read,
    opener: &dyn Opener,
    root: &Path,
    digest: &str,
    plan: &[(FileRecord, String)],
) -> Result<u64, RestoreError> {
    let mut cursor = 0u64;
    let mut next = 0usize;
    let mut verified: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut open: Option<(std::fs::File, u64)> = None;
    let mut written = 0u64;
    let mut failure: Option<RestoreError> = None;

    let read = decode_sealed_sequential(reader, opener, &mut |chunk| {
        if failure.is_some() {
            return Ok(());
        }
        let mut position = 0usize;
        while position < chunk.len() {
            let absolute = cursor + position as u64;
            if open.is_none() {
                let Some((record, path)) = plan.get(next) else {
                    // Past the last file this layer holds; the tail is padding that no
                    // entry claims (it cannot happen for a layer this codec wrote, but a
                    // shorter plan must not spin).
                    break;
                };
                if absolute < record.offset {
                    let skip = usize::try_from(record.offset - absolute).unwrap_or(usize::MAX);
                    position += skip.min(chunk.len() - position);
                    continue;
                }
                let end = match range_end(record, digest) {
                    Ok(end) => end,
                    Err(err) => {
                        failure = Some(err);
                        return Ok(());
                    }
                };
                match create_in_place(root, path, &mut verified) {
                    Ok(file) => open = Some((file, end)),
                    Err(err) => {
                        failure = Some(err);
                        return Ok(());
                    }
                }
                next += 1;
            }
            let Some((file, end)) = open.as_mut() else {
                break;
            };
            let take = usize::try_from(*end - absolute)
                .unwrap_or(usize::MAX)
                .min(chunk.len() - position);
            if let Err(err) = file.write_all(&chunk[position..position + take]) {
                failure = Some(err.into());
                return Ok(());
            }
            written += take as u64;
            position += take;
            if absolute + take as u64 >= *end {
                open = None;
            }
        }
        cursor += chunk.len() as u64;
        Ok(())
    })?;

    if let Some(failure) = failure {
        return Err(failure);
    }
    if let Some((record, _)) = plan.last() {
        let needed = range_end(record, digest)?;
        if read < needed {
            return Err(RestoreError::LayerShort {
                digest: digest.to_owned(),
                read,
                needed,
            });
        }
    }
    Ok(written)
}

/// Where a record's bytes end in its layer's plaintext, refusing a range that would wrap
/// past the end of the number line.
///
/// The index arrives over the network and may declare any offset and length it likes;
/// `offset + len` is what the pass compares its cursor against, and in a release build an
/// unchecked one wraps to a small number, which would have the scatter close a file the
/// moment it opened it and call the layer complete.
fn range_end(record: &FileRecord, digest: &str) -> Result<u64, RestoreError> {
    record
        .offset
        .checked_add(record.len)
        .ok_or_else(|| RestoreError::LayerRange {
            digest: digest.to_owned(),
            offset: record.offset,
            len: record.len,
        })
}

/// Creates a file for writing at `relative` under `root`, refusing to write through
/// anything but a directory this restore itself created.
///
/// The parent must already exist as a **real directory**: it is `symlink_metadata`-checked
/// (which does not follow), and this never calls `create_dir_all` on a file's path. Between
/// them those two rules mean a file can only ever be created inside a directory the index's
/// own `k:"d"` entries produced, so an index that names a file under something it also
/// declares a symlink is a refusal rather than a write somewhere else. Verified parents are
/// remembered, so the cost is one `stat` per directory, not per file.
///
/// This is belt to the phase ordering's braces — no symlink exists under `root` at all
/// while files are being written — and it is cheap enough to keep both.
fn create_in_place(
    root: &Path,
    relative: &str,
    verified: &mut std::collections::HashSet<PathBuf>,
) -> Result<std::fs::File, RestoreError> {
    let path = safe_join(root, relative)?;
    let parent = path
        .parent()
        .ok_or_else(|| RestoreError::BadParent(relative.to_owned()))?
        .to_path_buf();
    if !verified.contains(&parent) {
        let real = std::fs::symlink_metadata(&parent)
            .ok()
            .is_some_and(|meta| meta.is_dir());
        if !real {
            return Err(RestoreError::BadParent(relative.to_owned()));
        }
        verified.insert(parent);
    }
    Ok(std::fs::File::create(&path)?)
}

/// Joins a path from the index onto `root`, refusing anything that could land outside it.
///
/// The index arrives over the network. A path with a `..` segment, an absolute path, or a
/// Windows drive prefix would materialize outside the temporary directory — and the caller
/// then renames that directory over a live subtree. Every segment is checked.
fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, RestoreError> {
    check_relative(relative)?;
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        path.push(segment);
    }
    Ok(path)
}

/// The textual rule [`safe_join`] enforces, on its own.
///
/// It is checked while the index parses rather than only where a path is used, so every
/// consumer of a [`PointIndex`] — the restore that writes files, and the archive writer
/// that names tar entries a person will extract somewhere — inherits the same refusal.
fn check_relative(relative: &str) -> Result<(), RestoreError> {
    if relative.is_empty() {
        return Err(RestoreError::UnsafePath(relative.to_owned()));
    }
    if relative.len() > MAX_PATH_LEN {
        // Not echoed: a path this long is not something a message should carry.
        return Err(RestoreError::PathTooLong);
    }
    for segment in relative.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.contains('\\')
            || segment.contains(':')
            || segment.contains('\0')
        {
            return Err(RestoreError::UnsafePath(relative.to_owned()));
        }
    }
    Ok(())
}

/// The rule a symlink target has to pass, checked where the paths are checked: at parse
/// time, so every consumer of a [`PointIndex`] inherits the same refusal — the restore
/// that creates the link, and the archive writer that hands a person a tar to extract.
///
/// The rule itself lives in [`crate::persist::tree::link_target_is_safe`], one definition
/// shared with the walk that writes an index: the walk *skips* a link that fails it, so an
/// honest tree still captures, and this is the hard line for an index that carries one
/// anyway — one written by an older implementation, or by nobody friendly at all.
fn check_link_target(link: &str, target: &str) -> Result<(), RestoreError> {
    if crate::persist::tree::link_target_is_safe(link, target) {
        Ok(())
    } else {
        Err(RestoreError::UnsafeLinkTarget(link.to_owned()))
    }
}

/// Recreates a symlink, in the last phase of the restore.
///
/// The target is written verbatim — a link's target is the app's data, and rewriting it
/// would change what the app finds. That is safe here only because the target passed
/// [`check_link_target`] when the index was parsed, and because nothing is written through
/// it afterwards: this runs after the final layer and after every file's mode.
///
/// A failure is warned about rather than fatal: on Windows creating one needs a privilege
/// the current runtime may not hold, and losing a link is not worth losing the data around it.
fn create_symlink(target: &str, path: &Path, verified: &std::collections::HashSet<PathBuf>) {
    let Some(parent) = path.parent() else {
        return;
    };
    if !verified.contains(parent)
        && !std::fs::symlink_metadata(parent).is_ok_and(|meta| meta.is_dir())
    {
        tracing::warn!(
            path = %path.display(),
            "app data: a symlink names a parent this restore did not create; skipped"
        );
        return;
    }
    let _ = std::fs::remove_file(path);
    #[cfg(unix)]
    let result = std::os::unix::fs::symlink(target, path);
    #[cfg(windows)]
    let result = {
        let native = target.replace('/', "\\");
        let resolved = path.parent().map(|parent| parent.join(&native));
        if resolved.is_some_and(|resolved| resolved.is_dir()) {
            std::os::windows::fs::symlink_dir(&native, path)
        } else {
            std::os::windows::fs::symlink_file(&native, path)
        }
    };
    if let Err(err) = result {
        tracing::warn!(
            path = %path.display(),
            target = %target,
            error = %err,
            "app data: a symlink could not be recreated during restore"
        );
    }
}

/// Restores modification time and, on Unix, permission bits, for a path the index called a
/// file or a directory. Best effort by design: a filesystem that cannot carry them is not a
/// reason to fail a restore that otherwise placed every byte.
///
/// Two things here are not best effort. A path that turns out to be a **symlink** is left
/// alone entirely: `chmod(2)` follows one, and on Windows the time call opens the path for
/// writing, which follows a junction — so a metadata pass that trusted the index's word for
/// what a path is would be one a hostile index could aim at an arbitrary file. The phase
/// ordering is the real guarantee (no symlink exists under the root while this runs, and no
/// path is ever named twice); this check is what makes that guarantee cheap to keep.
///
/// And the mode is masked to the permission bits. **Setuid, setgid and the sticky bit are
/// dropped** — a restore point is bytes from another machine, materialized here by a node's
/// root or by whoever ran `orc pull`, and re-creating a setuid binary out of it would hand
/// its author a privilege the operator never granted. An app that genuinely needs one sets
/// it in its own start-up.
fn apply_metadata(path: &Path, mtime_ns: i64, mode: u32) {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            tracing::warn!(
                path = %path.display(),
                "app data: a restored path is a symlink where the index called it a file \
                 or a directory; its metadata is not applied"
            );
            return;
        }
        Ok(_) => {}
        // Nothing there to carry metadata. A symlink the restore declined to create lands
        // here, and so does a path a filter removed.
        Err(_) => return,
    }
    if mode != 0 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
        }
    }
    if mtime_ns != 0 {
        set_mtime(path, mtime_ns);
    }
}

/// A symlink's own modification time — never its target's.
///
/// On Unix `utimensat` takes `AT_SYMLINK_NOFOLLOW` and the link's time is restored. On
/// Windows setting one means opening the path for writing, which follows the link (and a
/// junction), so it is left alone: a link's recorded time is not worth writing through it.
fn apply_link_mtime(path: &Path, mtime_ns: i64) {
    if mtime_ns == 0 {
        return;
    }
    #[cfg(unix)]
    set_mtime(path, mtime_ns);
    #[cfg(windows)]
    let _ = path;
}

#[cfg(unix)]
fn set_mtime(path: &Path, mtime_ns: i64) {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let seconds = mtime_ns.div_euclid(1_000_000_000);
    let nanos = mtime_ns.rem_euclid(1_000_000_000);
    let times = [
        // Leave the access time alone; only the modification time is part of the point.
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: seconds as libc::time_t,
            tv_nsec: nanos,
        },
    ];
    // Never follow a symlink: the point records the link's own time, and following it
    // would rewrite the target's.
    #[allow(unsafe_code)] // utimensat is the only way to set a time from std.
    unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        );
    }
}

#[cfg(windows)]
fn set_mtime(path: &Path, mtime_ns: i64) {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::SetFileTime;

    // Windows counts 100 ns ticks from 1601-01-01; the epoch gap is a fixed constant.
    const EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) else {
        return;
    };
    let ticks = EPOCH_TICKS.saturating_add(mtime_ns / 100);
    let Ok(ticks) = u64::try_from(ticks) else {
        return;
    };
    #[allow(clippy::cast_possible_truncation)]
    let written = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    #[allow(unsafe_code)] // SetFileTime is the only way to set a time from std.
    unsafe {
        SetFileTime(
            file.as_raw_handle() as _,
            std::ptr::null(),
            std::ptr::null(),
            &raw const written,
        );
    }
}

/// The mirrored roots of `spec` under an app subtree — the paths a caller swapping a
/// restored tree into place has to create.
///
/// # Errors
///
/// Returns [`RestoreError::Index`] for a root the graft could not have mirrored.
pub fn mirrored_roots(spec: &PersistSpec) -> Result<Vec<String>, RestoreError> {
    spec.roots()
        .iter()
        .map(|root| mirror(root).map_err(RestoreError::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_that_escapes_the_destination_is_refused() {
        let root = Path::new("/tmp/app.restoring");
        for path in [
            "../etc/passwd",
            "a/../../b",
            "/etc/passwd",
            "c:/windows",
            "a//b",
            "",
            "a/./b",
            "a\\b",
        ] {
            assert!(
                safe_join(root, path).is_err(),
                "{path:?} must not be joinable"
            );
        }
        assert_eq!(
            safe_join(root, "var/lib/pg/base").expect("safe"),
            Path::new("/tmp/app.restoring/var/lib/pg/base")
        );
    }

    #[cfg(unix)]
    #[test]
    fn metadata_is_restored_without_following_a_symlink() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"body").expect("write");
        apply_metadata(&file, 1_600_000_000_123_456_789, 0o640);
        let meta = std::fs::metadata(&file).expect("stat");
        assert_eq!(
            crate::persist::tree::mtime_ns(&meta),
            1_600_000_000_123_456_789
        );
        assert_eq!(meta.permissions().mode() & 0o777, 0o640);

        let link = dir.path().join("link");
        std::os::unix::fs::symlink("file", &link).expect("symlink");
        apply_link_mtime(&link, 1_500_000_000_000_000_000);
        let target = std::fs::metadata(&file).expect("stat");
        assert_eq!(
            crate::persist::tree::mtime_ns(&target),
            1_600_000_000_123_456_789,
            "the link's time must not have followed through to its target"
        );
        assert_eq!(
            crate::persist::tree::mtime_ns(&std::fs::symlink_metadata(&link).expect("lstat")),
            1_500_000_000_000_000_000,
            "the link's own time is still restored"
        );
    }

    /// H1. An index may name one path twice with two kinds — a file, then a symlink over
    /// it — and the metadata phase would then `chmod` whatever the link points at. The
    /// index is refused before any of that, and this is the check that refuses it.
    #[test]
    fn an_index_that_names_a_path_twice_is_refused() {
        let file = |path: &str| Entry {
            p: path.to_owned(),
            k: Kind::File,
            s: 0,
            m: 0,
            c: 0,
            mode: 0o7777,
            t: None,
            r: Some(EntryRef { l: 0, o: 0, n: 0 }),
        };
        let link = |path: &str, target: &str| Entry {
            p: path.to_owned(),
            k: Kind::Symlink,
            s: 0,
            m: 0,
            c: 0,
            mode: 0,
            t: Some(target.to_owned()),
            r: None,
        };

        // The same path, twice, with different kinds: the attack shape.
        let err = parse_entries(&[file("x"), link("x", "target")]).expect_err("duplicate");
        assert!(
            matches!(err, RestoreError::Index(TreeError::OutOfOrder { .. })),
            "{err}"
        );
        // The same path twice with the same kind, and a path out of order, go the same way
        // — the writer emits strictly ascending paths and nothing else is an index.
        assert!(parse_entries(&[file("x"), file("x")]).is_err());
        assert!(parse_entries(&[file("b"), file("a")]).is_err());
        // Ascending is accepted.
        parse_entries(&[file("a"), file("b"), link("c", "a")]).expect("sorted");
    }

    /// H1. The other half: even reached, the metadata pass never writes through a link.
    /// A file materialized at `x` and then replaced by a symlink to somewhere else must
    /// leave that somewhere else exactly as it was.
    #[cfg(unix)]
    #[test]
    fn a_symlink_standing_where_a_file_was_is_never_chmodded_through() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"shadow").expect("write");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let before = std::fs::metadata(&secret).expect("stat");

        // Phase 2 wrote the file; phase 4 replaced it with a link, as a duplicate-path
        // index would have. Phase 3's metadata must decline.
        let path = dir.path().join("x");
        std::fs::write(&path, b"body").expect("write");
        std::fs::remove_file(&path).expect("remove");
        std::os::unix::fs::symlink(&secret, &path).expect("symlink");

        apply_metadata(&path, 1_500_000_000_000_000_000, 0o7777);

        let after = std::fs::metadata(&secret).expect("stat");
        assert_eq!(
            after.permissions().mode() & 0o7777,
            before.permissions().mode() & 0o7777,
            "the link's target must not have been chmodded"
        );
        assert_eq!(
            crate::persist::tree::mtime_ns(&after),
            crate::persist::tree::mtime_ns(&before),
            "the link's target must not have been re-timed"
        );
    }

    /// M2. Setuid, setgid and the sticky bit never come back off the wire.
    #[cfg(unix)]
    #[test]
    fn a_restored_mode_carries_no_setuid_setgid_or_sticky_bit() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"body").expect("write");
        apply_metadata(&file, 0, 0o6755);
        let mode = std::fs::metadata(&file).expect("stat").permissions().mode();
        assert_eq!(mode & 0o7777, 0o755, "mode {mode:o} kept a special bit");
    }

    /// H2. Each cap, on its own.
    #[test]
    fn the_index_parser_holds_every_cap_it_declares() {
        // One line, with no newline anywhere, cannot be accumulated without bound.
        let mut parser = fresh();
        parser.feed(b"{\"v\":1,\"app\":\"a\",\"created_at\":0,\"layers\":[]}\n");
        parser.feed(&vec![b'x'; MAX_INDEX_LINE + 1]);
        assert!(
            matches!(parser.finish(), Err(RestoreError::LineTooLong)),
            "a line over {MAX_INDEX_LINE} bytes must be refused"
        );
        // And in pieces, none of which is over the cap on its own.
        let mut parser = fresh();
        parser.feed(b"{\"v\":1,\"app\":\"a\",\"created_at\":0,\"layers\":[]}\n");
        for _ in 0..=(MAX_INDEX_LINE / 1024) {
            parser.feed(&vec![b'y'; 1024]);
        }
        assert!(matches!(parser.finish(), Err(RestoreError::LineTooLong)));

        // A path over the per-path cap is refused, whatever its kind.
        let long = "a".repeat(MAX_PATH_LEN + 1);
        for kind in [Kind::File, Kind::Dir, Kind::Symlink] {
            let err = parse_entries(&[Entry {
                p: long.clone(),
                k: kind,
                s: 0,
                m: 0,
                c: 0,
                mode: 0,
                t: Some("t".to_owned()),
                r: Some(EntryRef { l: 0, o: 0, n: 0 }),
            }])
            .expect_err("long path");
            assert!(matches!(err, RestoreError::PathTooLong), "{kind:?}: {err}");
        }

        // So is a symlink target over it.
        let err = parse_entries(&[Entry {
            p: "link".to_owned(),
            k: Kind::Symlink,
            s: 0,
            m: 0,
            c: 0,
            mode: 0,
            t: Some("t".repeat(MAX_PATH_LEN + 1)),
            r: None,
        }])
        .expect_err("long target");
        assert!(matches!(err, RestoreError::UnsafeLinkTarget(_)), "{err}");
    }

    /// H2. Symlinks and directories count against the entry cap and the path budget, not
    /// only files — the cap has to bound the whole index or it bounds nothing.
    #[test]
    fn every_kind_of_entry_is_charged_against_the_caps() {
        // The entry cap counts every kind. Symlinks going uncounted made
        // `MAX_INDEX_ENTRIES` a cap on two thirds of what an index can carry.
        let mut parser = fresh();
        parser.files.push(FileRecord {
            layer: 0,
            offset: 0,
            len: 0,
            path: 0,
            path_len: 0,
            mtime_ns: 0,
            mode: 0,
        });
        parser.dirs.push(MetaRecord {
            path: String::new(),
            mtime_ns: 0,
            mode: 0,
        });
        parser.symlinks.push(SymlinkRecord {
            path: String::new(),
            target: String::new(),
            mtime_ns: 0,
        });
        assert_eq!(parser.entries(), 3, "every kind counts against the cap");

        // The path budget covers dirs and symlink targets, not just the file arena.
        let mut parser = fresh();
        parser.charged = MAX_PATH_ARENA;
        assert!(matches!(
            parser.entry(&Entry {
                p: "d".to_owned(),
                k: Kind::Dir,
                s: 0,
                m: 0,
                c: 0,
                mode: 0,
                t: None,
                r: None,
            }),
            Err(RestoreError::PathsTooLarge)
        ));
        let mut parser = fresh();
        parser.charged = MAX_PATH_ARENA - 1;
        assert!(
            matches!(
                parser.entry(&Entry {
                    p: "l".to_owned(),
                    k: Kind::Symlink,
                    s: 0,
                    m: 0,
                    c: 0,
                    mode: 0,
                    t: Some("target".to_owned()),
                    r: None,
                }),
                Err(RestoreError::PathsTooLarge)
            ),
            "the symlink's target must be charged too"
        );
    }

    /// M1. A target is followed from where the link sits, and anything that leaves the
    /// tree from there — or that is a Windows path in disguise — is refused at parse time.
    #[test]
    fn a_symlink_target_that_leaves_the_tree_is_refused() {
        for (link, target) in [
            ("link", "/etc/shadow"),
            ("link", "/"),
            ("link", "../outside"),
            ("a/link", "../../outside"),
            ("a/b/link", "../../../outside"),
            ("link", "c:/windows"),
            ("link", "c:\\windows"),
            ("link", "\\\\host\\share"),
            ("link", "\\\\?\\c:\\x"),
            ("link", "\\\\.\\pipe\\x"),
            ("link", "a\\b"),
            ("link", "file:stream"),
            ("link", "with\0nul"),
            ("link", ""),
        ] {
            assert!(
                check_link_target(link, target).is_err(),
                "{link} -> {target:?} must be refused"
            );
        }
        for (link, target) in [
            ("link", "sibling"),
            ("a/link", "../conf/x"),
            ("a/b/link", "../../conf/x"),
            ("a/link", "b/../c"),
            ("link", "./here"),
            ("a/b/link", "../x/../../y"),
        ] {
            check_link_target(link, target)
                .unwrap_or_else(|err| panic!("{link} -> {target:?} must be allowed: {err}"));
        }
    }

    /// M3. An index that declares a range wrapping past the end of the number line is a
    /// refusal, not a wrap.
    #[test]
    fn a_layer_range_that_would_overflow_is_refused() {
        let record = FileRecord {
            layer: 0,
            offset: u64::MAX - 1,
            len: 4,
            path: 0,
            path_len: 0,
            mtime_ns: 0,
            mode: 0,
        };
        assert!(matches!(
            range_end(&record, "sha256:x"),
            Err(RestoreError::LayerRange { .. })
        ));
        assert_eq!(
            range_end(
                &FileRecord {
                    offset: 10,
                    len: 5,
                    ..record
                },
                "sha256:x"
            )
            .expect("in range"),
            15
        );
    }

    fn fresh() -> IndexParser {
        IndexParser {
            header: None,
            files: Vec::new(),
            arena: String::new(),
            dirs: Vec::new(),
            symlinks: Vec::new(),
            previous: String::new(),
            charged: 0,
            pending: Vec::new(),
            failure: None,
        }
    }

    /// Runs `entries` through the parser behind a minimal header, as a sealed index layer
    /// would arrive.
    fn parse_entries(entries: &[Entry]) -> Result<PointIndex, RestoreError> {
        let mut document = serde_json::to_vec(&IndexHeader {
            v: crate::persist::tree::INDEX_VERSION,
            app: "sys/sys/app".to_owned(),
            created_at: 0,
            layers: vec![LayerRef {
                digest: "sha256:0".to_owned(),
                size: 0,
            }],
        })
        .expect("header");
        document.push(b'\n');
        for entry in entries {
            document.extend_from_slice(&serde_json::to_vec(entry).expect("entry"));
            document.push(b'\n');
        }
        let mut parser = fresh();
        parser.feed(&document);
        parser.finish()
    }
}
