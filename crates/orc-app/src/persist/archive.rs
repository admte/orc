//! Synthesizing one restore point into a `tar.zst` stream.
//!
//! This is the egress path a person takes: the browser (and, later, anything else that
//! wants a point as a file) asks for a restore point and gets a single archive back. It
//! is the same read a restore performs — index first, then one forward pass per layer —
//! with tar entries written where a restore would have written files, so nothing is
//! staged on disk and memory stays bounded by the index plus one chunk.
//!
//! # Why it is shaped like this
//!
//! A point's plaintext does not exist anywhere as files. Every file is a byte range
//! inside a sealed, content-defined layer that other points share, so "download one file"
//! and "download the point" cost the same read; the point is what is offered. The layers
//! are read in header order and each is cut into its files by ascending offset, exactly
//! as [`crate::persist::restore`] does, because that is the order the bytes arrive in and
//! the layer is never seeked.
//!
//! The sealed decoder pushes plaintext at a sink while `tar` pulls a file's bytes from a
//! reader, so the two are bridged by a channel: a helper thread runs the decode and the
//! archive thread pulls. That is also what bounds memory — the channel holds a couple of
//! chunks and nothing else.
//!
//! # What the archive holds
//!
//! Directories first (parents before children, so an extraction has somewhere to put
//! things), then the point's empty files, then each layer's files in offset order, then
//! symlinks. Permission bits and modification times travel with every entry; a point
//! captured on Windows carries `mode == 0`, which becomes `0644` for files and `0755` for
//! directories rather than an unreadable zero. Only the permission bits travel — setuid,
//! setgid and the sticky bit are dropped, exactly as they are on a restore. Paths and
//! symlink targets longer than tar's 100-byte fields are written as GNU long-name and
//! long-link entries.
//!
//! # Integrity
//!
//! Every layer is verified against the digest the index names, and the AEAD authenticates
//! every frame. A failure anywhere aborts the stream mid-archive: the zstd frame is left
//! unterminated and the tar has no end-of-archive marker, so the reader sees a truncated
//! file rather than a plausible one that is quietly missing bytes.

use std::io::{Read, Write};
use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use tokio::io::AsyncRead;

use crate::error::CliError;
use crate::persist::restore::{LayerObserver, PointIndex, RestoreError, RestorePoint};
use crate::persist::seal::KeyRing;
use crate::persist::stream::decode_sealed_sequential;
use crate::registry::RegistryClient;

/// zstd level for the archive wrapper. Level 3 is the usual default: the payload is
/// already-compressed application data as often as not, and a download is not the place
/// to spend minutes of CPU for a few percent.
const ARCHIVE_ZSTD_LEVEL: i32 = 3;

/// Plaintext chunks the decode thread may run ahead of the archive writer.
const BRIDGE_QUEUE: usize = 4;

/// Default permissions for an entry whose point recorded none (a Windows capture).
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIR_MODE: u32 = 0o755;

/// Where an archive writer reads a point's sealed blobs from.
///
/// One method is enough for registry and local-store adapters to supply blobs without
/// taking on archive-specific behavior.
#[async_trait::async_trait]
pub trait BlobSource: Send + Sync {
    /// Opens one blob for streaming reads.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NotFound`] when the blob is not held, and an operational
    /// error for any transport or store failure.
    async fn open(
        &self,
        repository: &str,
        digest: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, CliError>;
}

#[async_trait::async_trait]
impl BlobSource for RegistryClient {
    async fn open(
        &self,
        repository: &str,
        digest: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, CliError> {
        let (reader, writer) = tokio::io::duplex(64 * 1024);
        let blob = self.get_blob_reader(repository, digest).await?;
        // `get_blob_reader` hands back a blocking reader; the trait deals in async ones,
        // so the copy runs where blocking is allowed.
        tokio::task::spawn_blocking(move || {
            let mut blob = blob;
            let mut writer = tokio_util::io::SyncIoBridge::new(writer);
            let _ = std::io::copy(&mut blob, &mut writer);
            let _ = writer.shutdown();
        });
        Ok(Box::new(reader))
    }
}

/// What one archive turned out to hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArchiveStats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    /// Plaintext bytes written into the archive.
    pub bytes: u64,
    pub layers: usize,
}

/// Streams `point` into `out` as a zstd-compressed tar archive.
///
/// `ring` is the pool's whole keyring: the point names the key it was sealed under, but
/// layers it carried forward from earlier points were sealed under older ones.
///
/// `out` is written only from blocking threads, so a caller may hand over a writer that
/// blocks — a bounded channel feeding an HTTP body, for instance. Dropping the far end of
/// such a channel makes the next write fail, which is how a client that goes away stops
/// the work.
///
/// # Errors
///
/// Returns [`RestoreError`] for an unreadable or unauthentic blob, a malformed index, a
/// layer that ends before the entries that reference it, a path that could escape an
/// extraction root, and any write failure on `out`.
pub async fn write_point_archive<W>(
    blobs: &dyn BlobSource,
    repository: &str,
    ring: &KeyRing,
    point: &RestorePoint,
    out: W,
) -> Result<ArchiveStats, RestoreError>
where
    W: Write + Send + 'static,
{
    write_point_archive_observed(blobs, repository, ring, point, out, None).await
}

/// [`write_point_archive`], reporting each layer to `observer` as it is reached.
///
/// # Errors
///
/// As [`write_point_archive`].
pub async fn write_point_archive_observed<W>(
    blobs: &dyn BlobSource,
    repository: &str,
    ring: &KeyRing,
    point: &RestorePoint,
    out: W,
    observer: Option<&dyn LayerObserver>,
) -> Result<ArchiveStats, RestoreError>
where
    W: Write + Send + 'static,
{
    let ring = Arc::new(ring.preferring(&point.key_id));

    // 1. The index. Parsed off the blob exactly as a restore parses it, with no
    //    filesystem in sight.
    let reader = layer_reader(blobs, repository, &point.index.digest).await?;
    let index_ring = Arc::clone(&ring);
    let index = tokio::task::spawn_blocking(move || PointIndex::read(reader, &*index_ring))
        .await
        .map_err(|err| RestoreError::Task(err.to_string()))??;
    let index = Arc::new(index);

    // 2. Directories, then the empty files: everything the point holds that needs no
    //    layer at all. An empty file is created from the index rather than cut out of a
    //    layer — consecutive empties share one offset, and cutting them would need a
    //    strictly ascending plan.
    let mut stats = ArchiveStats::default();
    let encoder = zstd::Encoder::new(out, ARCHIVE_ZSTD_LEVEL)
        .map_err(RestoreError::Io)?
        .auto_finish();
    let mut builder = tar::Builder::new(encoder);
    let head = Arc::clone(&index);
    let (mut builder, head_stats) = tokio::task::spawn_blocking(move || {
        let mut stats = ArchiveStats::default();
        for record in head.dirs() {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(mode_or(record.mode, DEFAULT_DIR_MODE));
            header.set_mtime(seconds(record.mtime_ns));
            append(&mut builder, &mut header, record.path, std::io::empty())?;
            stats.dirs += 1;
        }
        for record in head.files().filter(|record| record.len == 0) {
            let mut header = file_header(record.mode, record.mtime_ns, 0);
            append(&mut builder, &mut header, record.path, std::io::empty())?;
            stats.files += 1;
        }
        Ok::<_, RestoreError>((builder, stats))
    })
    .await
    .map_err(|err| RestoreError::Task(err.to_string()))??;
    stats.dirs = head_stats.dirs;
    stats.files = head_stats.files;

    // 3. One forward pass per layer, in header order, cutting the plaintext into files
    //    by ascending offset. The builder travels in and out of the blocking pool so
    //    every write to `out` happens where blocking is allowed.
    let plans = layer_plans(&index);
    let total_layers = plans.len();
    for (number, layer) in index.header().layers.iter().enumerate() {
        let Some(plan) = plans.get(&u32::try_from(number).unwrap_or(u32::MAX)) else {
            // A layer nothing references: a carried layer whose last reference vanished
            // is listed but never read.
            continue;
        };
        let position_in_pass = stats.layers + 1;
        if let Some(observer) = observer {
            observer.layer(position_in_pass, total_layers, stats.bytes);
        }
        let reader = layer_reader(blobs, repository, &layer.digest).await?;
        let layer_ring = Arc::clone(&ring);
        let plan = plan.clone();
        let digest = layer.digest.clone();
        let (returned, written, files) = tokio::task::spawn_blocking(move || {
            cut_layer(reader, &layer_ring, &digest, &plan, builder)
        })
        .await
        .map_err(|err| RestoreError::Task(err.to_string()))?
        .map_err(|err| {
            crate::persist::restore::name_the_layer(
                err,
                position_in_pass,
                total_layers,
                &layer.digest,
            )
        })?;
        builder = returned;
        stats.bytes += written;
        stats.files += files;
        stats.layers += 1;
    }

    // 4. Symlinks last, and then the end-of-archive marker: a reader that gets this far
    //    has every byte the point holds.
    let tail = Arc::clone(&index);
    let symlinks = tokio::task::spawn_blocking(move || {
        let mut count = 0u64;
        for record in tail.symlinks() {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(DEFAULT_FILE_MODE);
            header.set_mtime(seconds(record.mtime_ns));
            // `append_link` rather than `set_link_name` + `append`: the header's link
            // field is 100 bytes, and a longer target made `set_link_name` fail in the
            // middle of the stream — an archive already half-written, truncated over a
            // link. `append_link` emits the GNU long-link record instead, exactly as the
            // path side already did for long names.
            builder
                .append_link(&mut header, record.path, record.target)
                .map_err(RestoreError::Io)?;
            count += 1;
        }
        builder.into_inner().map_err(RestoreError::Io)?;
        Ok::<_, RestoreError>(count)
    })
    .await
    .map_err(|err| RestoreError::Task(err.to_string()))??;
    stats.symlinks = symlinks;
    Ok(stats)
}

/// One file's place in a layer, in the order the layer will be read.
#[derive(Debug, Clone)]
struct PlanEntry {
    path: String,
    offset: u64,
    len: u64,
    mtime_ns: i64,
    mode: u32,
}

/// Groups the point's non-empty files by layer, each group in ascending offset order —
/// which is the order the layer's plaintext concatenates them in.
fn layer_plans(index: &PointIndex) -> std::collections::HashMap<u32, Vec<PlanEntry>> {
    let mut plans: std::collections::HashMap<u32, Vec<PlanEntry>> =
        std::collections::HashMap::new();
    for record in index.files().filter(|record| record.len > 0) {
        plans.entry(record.layer).or_default().push(PlanEntry {
            path: record.path.to_owned(),
            offset: record.offset,
            len: record.len,
            mtime_ns: record.mtime_ns,
            mode: record.mode,
        });
    }
    for plan in plans.values_mut() {
        plan.sort_unstable_by_key(|entry| entry.offset);
    }
    plans
}

/// Reads one layer front to back, appending each file as its offset is reached.
///
/// The decode runs on its own thread and pushes plaintext into a channel this thread
/// pulls from: `tar` wants a reader per entry, the sealed decoder hands out chunks. The
/// channel is what makes one a source for the other without buffering the layer.
fn cut_layer<W: Write>(
    reader: impl Read + Send + 'static,
    ring: &Arc<KeyRing>,
    digest: &str,
    plan: &[PlanEntry],
    mut builder: tar::Builder<W>,
) -> Result<(tar::Builder<W>, u64, u64), RestoreError> {
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(BRIDGE_QUEUE);
    let decode_ring = Arc::clone(ring);
    let expected = digest.to_owned();
    let decoder = std::thread::spawn(move || {
        let verified = DigestReader::new(reader, &expected);
        decode_sealed_sequential(verified, &*decode_ring, &mut |chunk| {
            // A closed receiver means the archive gave up (a failed write, a client that
            // went away). Reporting it as an I/O error stops the decode here.
            sender.send(chunk.to_vec()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "archive stopped reading")
            })
        })
    });

    let mut source = ChannelReader {
        receiver,
        current: Vec::new(),
        offset: 0,
    };
    let mut cursor = 0u64;
    let mut written = 0u64;
    let mut files = 0u64;
    let mut outcome = Ok(());
    for entry in plan {
        if entry.offset > cursor {
            let skip = entry.offset - cursor;
            match std::io::copy(&mut (&mut source).take(skip), &mut std::io::sink()) {
                Ok(skipped) if skipped == skip => cursor += skipped,
                Ok(skipped) => {
                    outcome = Err(RestoreError::LayerShort {
                        digest: digest.to_owned(),
                        read: cursor + skipped,
                        needed: entry.offset.saturating_add(entry.len),
                    });
                    break;
                }
                Err(err) => {
                    outcome = Err(RestoreError::Io(err));
                    break;
                }
            }
        }
        let mut header = file_header(entry.mode, entry.mtime_ns, entry.len);
        let mut body = (&mut source).take(entry.len);
        if let Err(err) = append(&mut builder, &mut header, &entry.path, &mut body) {
            outcome = Err(err);
            break;
        }
        // `append` writes exactly `size` bytes and pads; a body that ended early is a
        // layer that does not hold what the index says it does.
        if body.limit() != 0 {
            outcome = Err(RestoreError::LayerShort {
                digest: digest.to_owned(),
                read: cursor + entry.len - body.limit(),
                needed: entry.offset.saturating_add(entry.len),
            });
            break;
        }
        cursor += entry.len;
        written += entry.len;
        files += 1;
    }

    // Draining is what lets the decoder finish and report its own verdict — a digest
    // mismatch or a refused frame is only known at the end of the stream.
    if outcome.is_ok() {
        let _ = std::io::copy(&mut source, &mut std::io::sink());
    }
    drop(source);
    let decoded = decoder
        .join()
        .map_err(|_| RestoreError::Task("app data layer decode panicked".to_owned()))?;
    // Whose verdict to report when both sides failed. A layer that ends early is usually
    // the decoder having stopped first — a refused frame, a digest that did not match —
    // and this side then reading a channel that will never deliver again; reporting the
    // short read instead would hide the reason. The exception is the decode that only
    // stopped because *this* side gave up (the broken pipe the sink reports), which says
    // nothing the cutting loop has not already said better.
    if let Err(err) = decoded
        && !gave_up_writing(&err)
    {
        return Err(err.into());
    }
    outcome?;
    Ok((builder, written, files))
}

/// Whether a decode failure is only the echo of this side having stopped reading.
fn gave_up_writing(err: &crate::persist::stream::StreamError) -> bool {
    matches!(
        err,
        crate::persist::stream::StreamError::Io(io) if io.kind() == std::io::ErrorKind::BrokenPipe
    )
}

/// A tar header for one file entry.
fn file_header(mode: u32, mtime_ns: i64, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(mode_or(mode, DEFAULT_FILE_MODE));
    header.set_mtime(seconds(mtime_ns));
    header
}

/// Appends one entry, letting the `tar` crate emit a GNU long-name record for a path
/// that does not fit the header's 100-byte field.
fn append<W: Write, R: Read>(
    builder: &mut tar::Builder<W>,
    header: &mut tar::Header,
    path: &str,
    body: R,
) -> Result<(), RestoreError> {
    header.set_cksum();
    builder
        .append_data(header, path, body)
        .map_err(RestoreError::Io)
}

/// A point captured where permissions are not Unix bits records `0`; an archive entry
/// with mode zero is one nobody can read, so a sensible default stands in.
///
/// Only the permission bits travel. **Setuid, setgid and the sticky bit are dropped**, as
/// they are on a restore: this archive is handed to a person who extracts it wherever they
/// like, often as root, and a tar that recreates a setuid binary out of another machine's
/// app data hands its author a privilege nobody granted.
fn mode_or(mode: u32, default: u32) -> u32 {
    if mode == 0 { default } else { mode & 0o777 }
}

/// Index times are nanoseconds; tar counts whole seconds since the epoch. Times before
/// the epoch are clamped to it rather than wrapping into the far future.
fn seconds(mtime_ns: i64) -> u64 {
    u64::try_from(mtime_ns.div_euclid(1_000_000_000)).unwrap_or(0)
}

/// Opens a blob and hands back a blocking reader over it.
async fn layer_reader(
    blobs: &dyn BlobSource,
    repository: &str,
    digest: &str,
) -> Result<impl Read + Send + 'static, RestoreError> {
    let reader = blobs.open(repository, digest).await?;
    let handle = tokio::runtime::Handle::current();
    Ok(tokio_util::io::SyncIoBridge::new_with_handle(
        reader, handle,
    ))
}

/// The pull half of the bridge: a `Read` over the chunks the decode thread pushes.
struct ChannelReader {
    receiver: std::sync::mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.offset < self.current.len() {
                let take = (self.current.len() - self.offset).min(buf.len());
                buf[..take].copy_from_slice(&self.current[self.offset..self.offset + take]);
                self.offset += take;
                return Ok(take);
            }
            match self.receiver.recv() {
                Ok(chunk) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                // The decode thread ended. Whether that was the end of the layer or a
                // failure is the thread's own verdict, collected by the caller.
                Err(_) => return Ok(0),
            }
        }
    }
}

/// A reader that checks the bytes against the digest they were asked for, at EOF.
///
/// The blob arrives from a store, not from the key holder, so nothing else in the pass
/// would notice a substituted layer that happens to be sealed under the same pool key.
/// The check lands at the end of the stream, which is why a mismatch truncates an archive
/// rather than preventing one.
struct DigestReader<R> {
    inner: R,
    hasher: Option<Sha256>,
    expected: String,
}

impl<R: Read> DigestReader<R> {
    fn new(inner: R, expected: &str) -> Self {
        Self {
            inner,
            hasher: Some(Sha256::new()),
            expected: expected
                .strip_prefix("sha256:")
                .unwrap_or(expected)
                .to_owned(),
        }
    }
}

impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read > 0 {
            if let Some(hasher) = self.hasher.as_mut() {
                hasher.update(&buf[..read]);
            }
            return Ok(read);
        }
        if let Some(hasher) = self.hasher.take() {
            let actual = format!("{:x}", hasher.finalize());
            if actual != self.expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "app data layer bytes hash to sha256:{actual}, the point names \
                         sha256:{}",
                        self.expected
                    ),
                ));
            }
        }
        Ok(0)
    }
}
