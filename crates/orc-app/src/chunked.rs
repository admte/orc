//! Chunked-zstd artifact format (spec 146): the framed single-blob payload layer
//! and its pull-side reader.
//!
//! A chunked layer's blob is a concatenation of **zstd frames** — one per
//! content-defined chunk, each either a standard compressed frame or a
//! byte-pinned *raw* frame — followed by one **skippable frame** (magic
//! `0x184D2A5E`) carrying the table of contents (TOC). The layer digest is the
//! plain sha256 of the whole wire stream, exactly as OCI expects; the TOC lives
//! inside the blob and is located/verified through the descriptor annotations
//! ([`crate::app::CHUNKED_TOC_OFFSET_ANNOTATION`] and friends).
//!
//! # TOC binary encoding (stable, version 1)
//!
//! The TOC bytes (what `toc-digest` covers and what the skippable frame wraps) are
//! a compact little-endian binary record:
//!
//! ```text
//! magic            u32   "OTOC" as 0x434F544F little-endian  (0x4F 0x54 0x4F 0x43)
//! format_version   u32
//! chunker.min      u32
//! chunker.avg      u32
//! chunker.max      u32
//! chunk_count      u32
//! repeat chunk_count times:
//!   frame_cid      [u8; 32]   blake3 of the frame's wire bytes
//!   frame_offset   u64        byte offset of the frame within the blob
//!   frame_length   u64        byte length of the frame
//!   raw_length     u32        decompressed length of the chunk (<= 12 MiB)
//!   flags          u8         bit0 = compressed, bit1 = raw_sha256 present
//!   raw_sha256     [u8; 32]   present iff flags bit1 set
//! ```
//!
//! The encoding is exact-consume (trailing bytes are rejected) so it round-trips
//! byte-for-byte and is safe to hash. All reader paths bounds-check every offset
//! and length against the actual blob length (overflow-checked) and verify the TOC
//! bytes against `toc-digest` **before** trusting a single field.

use std::collections::BTreeMap;
use std::io::Read as _;

use crate::error::CliError;
use crate::registry::digest_bytes;

// Re-exported so the chunked-format annotation keys are reachable through this
// module (they are declared in `app` alongside the other media-type constants).
pub use crate::app::{
    CHUNKED_TOC_DIGEST_ANNOTATION, CHUNKED_TOC_OFFSET_ANNOTATION, CHUNKED_VERSION_ANNOTATION,
};

/// Current chunked-format version recorded in the TOC and the `version` annotation.
pub const FORMAT_VERSION: u32 = 1;

/// Maximum decompressed size of a single chunk (spec 146: `FastCDC` max 12 MiB).
pub const MAX_CHUNK_RAW: usize = 12 * 1024 * 1024;

/// Absolute cap on TOC entries (spec 146 Limits), enforced before per-entry work.
pub const MAX_TOC_ENTRIES: usize = 1_048_576;

/// Maximum TOC byte length (spec 146 Limits), enforced before deserialization.
pub const MAX_TOC_BYTES: usize = 64 * 1024 * 1024;

/// zstd skippable-frame magic that wraps the TOC.
pub const SKIPPABLE_MAGIC: u32 = 0x184D_2A5E;

/// Magic prefixing the TOC binary record.
const TOC_MAGIC: u32 = 0x434F_544F; // "OTOC" little-endian

/// zstd frame magic (`ZSTD_MAGICNUMBER`).
pub(crate) const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;

/// Maximum zstd block payload (the spec-fixed 128 KiB block cap).
pub(crate) const MAX_BLOCK: usize = 128 * 1024;

/// Decoder window bound. 12 MiB max chunk fits under 2^24; capping the decoder's
/// window here keeps decompression memory bounded regardless of declared sizes.
pub(crate) const WINDOW_LOG_MAX: u32 = 25;

/// Errors from encoding, verifying, or reading a chunked layer. Every variant is an
/// operator-facing integrity or bounds failure; [`CliError`] maps them to the
/// operational exit class.
#[derive(Debug, thiserror::Error)]
pub enum ChunkedError {
    #[error("chunked layer is missing annotation {0}")]
    MissingAnnotation(&'static str),
    #[error("chunked layer annotation {0} is malformed")]
    BadAnnotation(&'static str),
    #[error("chunked TOC offset/length is out of bounds of the {blob_len}-byte blob")]
    OutOfBounds { blob_len: usize },
    #[error("chunked TOC arithmetic overflowed")]
    Overflow,
    #[error("chunked TOC skippable frame magic is wrong (blob is not chunked-zstd)")]
    BadSkippableMagic,
    #[error("chunked TOC skippable frame must be the final frame in the blob")]
    TocNotFinal,
    #[error("chunked TOC byte length {0} exceeds the {MAX_TOC_BYTES}-byte cap")]
    TocTooLarge(usize),
    #[error("chunked TOC entry count {0} exceeds the {MAX_TOC_ENTRIES}-entry cap")]
    TooManyEntries(usize),
    #[error("chunked TOC bytes are truncated or malformed")]
    MalformedToc,
    #[error("chunked TOC bad magic (not an ORC chunked TOC)")]
    BadTocMagic,
    #[error("chunked TOC format version {0} is unsupported (expected {FORMAT_VERSION})")]
    UnsupportedVersion(u32),
    #[error("chunked TOC digest mismatch: expected {expected}, computed {actual}")]
    TocDigestMismatch { expected: String, actual: String },
    #[error("chunked chunk raw length {0} exceeds the {MAX_CHUNK_RAW}-byte max chunk size")]
    RawLengthTooLarge(u32),
    #[error("chunked TOC frames do not tile the frame region exactly")]
    BadTiling,
    #[error("chunked layer digest mismatch: expected {expected}, computed {actual}")]
    LayerDigestMismatch { expected: String, actual: String },
    #[error("chunked stream decompressed to more bytes than the TOC declares")]
    DecompressedTooLarge,
    #[error("chunked stream decompressed to {actual} bytes, TOC declares {expected}")]
    DecompressedSizeMismatch { expected: usize, actual: usize },
    #[error("decode chunked zstd stream: {0}")]
    Zstd(String),
}

impl From<ChunkedError> for CliError {
    fn from(err: ChunkedError) -> Self {
        CliError::Operational(err.to_string())
    }
}

/// Chunker parameters (`FastCDC` min/avg/max on raw content), recorded so artifacts
/// chunked with different params still interoperate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkerParams {
    pub min: u32,
    pub avg: u32,
    pub max: u32,
}

/// One chunk's entry in the TOC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEntry {
    /// blake3 of the frame's wire bytes — the storage/dedup/negotiation key.
    pub frame_cid: [u8; 32],
    /// Byte offset of the frame within the blob.
    pub frame_offset: u64,
    /// Byte length of the frame.
    pub frame_length: u64,
    /// Decompressed length of the chunk (MUST be <= [`MAX_CHUNK_RAW`]).
    pub raw_length: u32,
    /// Whether the frame is a standard compressed frame (`true`) or a raw frame.
    pub compressed: bool,
    /// Optional raw-content sha256 (reserved for a future raw-keyed dedup upgrade;
    /// never verified on the ingest path).
    pub raw_sha256: Option<[u8; 32]>,
}

/// The table of contents for a chunked layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toc {
    pub format_version: u32,
    pub chunker: ChunkerParams,
    pub chunks: Vec<ChunkEntry>,
}

/// A TOC that has been located within a blob, digest-verified, and validated to
/// tile the frame region exactly.
#[derive(Debug, Clone)]
pub struct VerifiedToc {
    pub toc: Toc,
    /// Byte length of the frame region `[0, frame_region_len)` (== the TOC offset).
    pub frame_region_len: u64,
    /// Sum of every chunk's `raw_length` — the exact decompressed payload length.
    pub expected_total: u64,
}

/// Returns `blake3(frame)` — the frame content id keyed on by dedup/negotiation.
#[must_use]
pub fn frame_cid(frame: &[u8]) -> [u8; 32] {
    *blake3::hash(frame).as_bytes()
}

/// Builds a standard compressed zstd frame of `raw` at compression `level`. Uses
/// the one-shot bulk API, which writes the frame content-size header.
///
/// # Errors
///
/// Returns [`ChunkedError::Zstd`] if the encoder fails.
pub fn compressed_frame(raw: &[u8], level: i32) -> Result<Vec<u8>, ChunkedError> {
    zstd::bulk::compress(raw, level).map_err(|err| ChunkedError::Zstd(err.to_string()))
}

/// Builds a **byte-pinned** raw zstd frame of `raw`: an explicit frame header
/// (single-segment, 4-byte content size, no checksum, no dictionary) followed by
/// `Raw` blocks of at most 128 KiB. This construction is fixed and independent of
/// the zstd library version — the byte-stability that lets raw frames dedup across
/// zstd versions rests on it, so `encode_all`/`bulk::compress` must NOT be used.
#[must_use]
pub fn raw_frame(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 16);
    out.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
    // Frame_Header_Descriptor: Frame_Content_Size_flag = 2 (4-byte FCS), and
    // Single_Segment_flag = 1 → 0b1010_0000 = 0xA0. No checksum, no dict id.
    out.push(0xA0);
    // 4-byte frame content size (raw length; chunks are <= 12 MiB < 2^32).
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    if raw.is_empty() {
        // A single empty last Raw block: Last_Block = 1, Block_Type = Raw, size 0.
        push_block_header(&mut out, 0, true);
    } else {
        let mut offset = 0;
        while offset < raw.len() {
            let end = (offset + MAX_BLOCK).min(raw.len());
            let last = end == raw.len();
            push_block_header(&mut out, end - offset, last);
            out.extend_from_slice(&raw[offset..end]);
            offset = end;
        }
    }
    out
}

/// Writes a 3-byte zstd `Raw` block header (`Block_Type` 0): bit0 `Last_Block`,
/// bits 1-2 `Block_Type`, bits 3-23 `Block_Size`.
fn push_block_header(out: &mut Vec<u8>, size: usize, last: bool) {
    debug_assert!(size <= MAX_BLOCK);
    #[allow(clippy::cast_possible_truncation)]
    let header = (u32::from(last)) | ((size as u32) << 3);
    out.extend_from_slice(&header.to_le_bytes()[..3]);
}

/// Wraps `toc_bytes` in a zstd skippable frame (magic + 4-byte size + payload).
#[must_use]
pub fn encode_skippable_toc_frame(toc_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(toc_bytes.len() + 8);
    out.extend_from_slice(&SKIPPABLE_MAGIC.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(toc_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(toc_bytes);
    out
}

impl Toc {
    /// Serializes the TOC to its stable binary form.
    ///
    /// # Errors
    ///
    /// Returns [`ChunkedError::RawLengthTooLarge`] if any chunk declares a raw
    /// length over [`MAX_CHUNK_RAW`], or [`ChunkedError::TooManyEntries`] if the
    /// chunk count exceeds [`MAX_TOC_ENTRIES`].
    pub fn encode(&self) -> Result<Vec<u8>, ChunkedError> {
        if self.chunks.len() > MAX_TOC_ENTRIES {
            return Err(ChunkedError::TooManyEntries(self.chunks.len()));
        }
        let mut out = Vec::with_capacity(24 + self.chunks.len() * 85);
        out.extend_from_slice(&TOC_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.extend_from_slice(&self.chunker.min.to_le_bytes());
        out.extend_from_slice(&self.chunker.avg.to_le_bytes());
        out.extend_from_slice(&self.chunker.max.to_le_bytes());
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.chunks.len() as u32).to_le_bytes());
        for chunk in &self.chunks {
            if chunk.raw_length as usize > MAX_CHUNK_RAW {
                return Err(ChunkedError::RawLengthTooLarge(chunk.raw_length));
            }
            out.extend_from_slice(&chunk.frame_cid);
            out.extend_from_slice(&chunk.frame_offset.to_le_bytes());
            out.extend_from_slice(&chunk.frame_length.to_le_bytes());
            out.extend_from_slice(&chunk.raw_length.to_le_bytes());
            let flags = u8::from(chunk.compressed) | (u8::from(chunk.raw_sha256.is_some()) << 1);
            out.push(flags);
            if let Some(sha) = &chunk.raw_sha256 {
                out.extend_from_slice(sha);
            }
        }
        Ok(out)
    }

    /// Deserializes a TOC from its binary form, enforcing the entry-count and
    /// per-chunk raw-length caps and rejecting any trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`ChunkedError`] for a bad magic, unsupported version, oversized
    /// entry count or raw length, or a truncated/overlong record.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChunkedError> {
        let mut reader = ByteReader::new(bytes);
        if reader.u32()? != TOC_MAGIC {
            return Err(ChunkedError::BadTocMagic);
        }
        let format_version = reader.u32()?;
        let chunker = ChunkerParams {
            min: reader.u32()?,
            avg: reader.u32()?,
            max: reader.u32()?,
        };
        let count = reader.u32()? as usize;
        if count > MAX_TOC_ENTRIES {
            return Err(ChunkedError::TooManyEntries(count));
        }
        let mut chunks = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let frame_cid = reader.array32()?;
            let frame_offset = reader.u64()?;
            let frame_length = reader.u64()?;
            let raw_length = reader.u32()?;
            if raw_length as usize > MAX_CHUNK_RAW {
                return Err(ChunkedError::RawLengthTooLarge(raw_length));
            }
            let flags = reader.u8()?;
            let compressed = flags & 0b1 != 0;
            let raw_sha256 = if flags & 0b10 != 0 {
                Some(reader.array32()?)
            } else {
                None
            };
            chunks.push(ChunkEntry {
                frame_cid,
                frame_offset,
                frame_length,
                raw_length,
                compressed,
                raw_sha256,
            });
        }
        if !reader.is_empty() {
            return Err(ChunkedError::MalformedToc);
        }
        Ok(Self {
            format_version,
            chunker,
            chunks,
        })
    }

    /// Verifies that the chunk frames tile `[0, frame_region_len)` exactly with no
    /// gaps, overlaps, or zero-length frames, and returns the sum of raw lengths
    /// (the decompressed payload size). All arithmetic is overflow-checked.
    ///
    /// # Errors
    ///
    /// Returns [`ChunkedError::BadTiling`] on any gap/overlap/zero-length frame or
    /// a region-length mismatch, and [`ChunkedError::Overflow`] on overflow.
    pub fn validate_tiling(&self, frame_region_len: u64) -> Result<u64, ChunkedError> {
        let mut cursor = 0u64;
        let mut total = 0u64;
        for chunk in &self.chunks {
            if chunk.frame_offset != cursor || chunk.frame_length == 0 {
                return Err(ChunkedError::BadTiling);
            }
            cursor = cursor
                .checked_add(chunk.frame_length)
                .ok_or(ChunkedError::Overflow)?;
            if cursor > frame_region_len {
                return Err(ChunkedError::BadTiling);
            }
            total = total
                .checked_add(u64::from(chunk.raw_length))
                .ok_or(ChunkedError::Overflow)?;
        }
        if cursor != frame_region_len {
            return Err(ChunkedError::BadTiling);
        }
        Ok(total)
    }
}

/// Locates the TOC via the descriptor annotations, bounds-checks every offset and
/// length against the blob, verifies the TOC bytes against `toc-digest`, decodes
/// it, and validates the frame tiling. No TOC field is trusted before this returns.
///
/// # Errors
///
/// Returns a [`ChunkedError`] for a missing/malformed annotation, an out-of-bounds
/// or non-final TOC frame, a digest mismatch, or an invalid/oversized TOC.
// The `expect`/index sites below are all preceded by explicit bounds checks, so
// they are unreachable; no `# Panics` section applies.
#[allow(clippy::missing_panics_doc)]
pub fn locate_and_verify_toc(
    blob: &[u8],
    annotations: &BTreeMap<String, String>,
) -> Result<VerifiedToc, ChunkedError> {
    let toc_offset = annotations
        .get(CHUNKED_TOC_OFFSET_ANNOTATION)
        .ok_or(ChunkedError::MissingAnnotation(
            CHUNKED_TOC_OFFSET_ANNOTATION,
        ))?
        .parse::<u64>()
        .map_err(|_| ChunkedError::BadAnnotation(CHUNKED_TOC_OFFSET_ANNOTATION))?;
    let toc_digest =
        annotations
            .get(CHUNKED_TOC_DIGEST_ANNOTATION)
            .ok_or(ChunkedError::MissingAnnotation(
                CHUNKED_TOC_DIGEST_ANNOTATION,
            ))?;
    if let Some(version) = annotations.get(CHUNKED_VERSION_ANNOTATION) {
        let version = version
            .parse::<u32>()
            .map_err(|_| ChunkedError::BadAnnotation(CHUNKED_VERSION_ANNOTATION))?;
        if version != FORMAT_VERSION {
            return Err(ChunkedError::UnsupportedVersion(version));
        }
    }

    let blob_len = blob.len();
    let oob = || ChunkedError::OutOfBounds { blob_len };
    // Skippable header: 4-byte magic + 4-byte size.
    let header_end = toc_offset.checked_add(8).ok_or(ChunkedError::Overflow)?;
    if header_end > blob_len as u64 {
        return Err(oob());
    }
    let offset = usize::try_from(toc_offset).map_err(|_| oob())?;
    let magic = u32::from_le_bytes(blob[offset..offset + 4].try_into().expect("4 bytes"));
    if magic != SKIPPABLE_MAGIC {
        return Err(ChunkedError::BadSkippableMagic);
    }
    let frame_size =
        u32::from_le_bytes(blob[offset + 4..offset + 8].try_into().expect("4 bytes")) as usize;
    if frame_size > MAX_TOC_BYTES {
        return Err(ChunkedError::TocTooLarge(frame_size));
    }
    let toc_end = header_end
        .checked_add(frame_size as u64)
        .ok_or(ChunkedError::Overflow)?;
    // The skippable TOC frame must be exactly the tail of the blob.
    if toc_end != blob_len as u64 {
        return Err(ChunkedError::TocNotFinal);
    }
    let toc_bytes = &blob[offset + 8..offset + 8 + frame_size];
    let actual = digest_bytes(toc_bytes);
    if actual != *toc_digest {
        return Err(ChunkedError::TocDigestMismatch {
            expected: toc_digest.clone(),
            actual,
        });
    }
    let toc = Toc::decode(toc_bytes)?;
    if toc.format_version != FORMAT_VERSION {
        return Err(ChunkedError::UnsupportedVersion(toc.format_version));
    }
    let expected_total = toc.validate_tiling(toc_offset)?;
    Ok(VerifiedToc {
        toc,
        frame_region_len: toc_offset,
        expected_total,
    })
}

/// Reads a chunked-zstd blob into its decompressed payload.
///
/// Verifies the layer sha256 over the wire bytes, locates and verifies the TOC,
/// then **stream-decompresses** the frame region with a multi-frame zstd decoder —
/// the trailing skippable TOC frame is excluded explicitly by slicing at the TOC
/// offset. Decompression is bounded: the decoder window is capped and output is
/// held to the TOC-declared total, so no allocation is driven by attacker-declared
/// sizes.
///
/// # Errors
///
/// Returns a [`ChunkedError`] for a layer or TOC integrity failure, a bounds
/// violation, or a decode error / size mismatch.
pub fn read_chunked_blob(
    blob: &[u8],
    annotations: &BTreeMap<String, String>,
    layer_digest: &str,
) -> Result<Vec<u8>, ChunkedError> {
    let actual = digest_bytes(blob);
    if actual != layer_digest {
        return Err(ChunkedError::LayerDigestMismatch {
            expected: layer_digest.to_owned(),
            actual,
        });
    }
    let verified = locate_and_verify_toc(blob, annotations)?;
    let frame_region_end =
        usize::try_from(verified.frame_region_len).map_err(|_| ChunkedError::OutOfBounds {
            blob_len: blob.len(),
        })?;
    let expected =
        usize::try_from(verified.expected_total).map_err(|_| ChunkedError::OutOfBounds {
            blob_len: blob.len(),
        })?;

    let frame_region = &blob[..frame_region_end];
    let mut decoder = zstd::stream::read::Decoder::new(frame_region)
        .map_err(|err| ChunkedError::Zstd(err.to_string()))?;
    decoder
        .window_log_max(WINDOW_LOG_MAX)
        .map_err(|err| ChunkedError::Zstd(err.to_string()))?;

    let mut out = Vec::with_capacity(expected.min(MAX_CHUNK_RAW));
    let mut buf = vec![0u8; MAX_BLOCK];
    loop {
        let read = decoder
            .read(&mut buf)
            .map_err(|err| ChunkedError::Zstd(err.to_string()))?;
        if read == 0 {
            break;
        }
        if out.len() + read > expected {
            return Err(ChunkedError::DecompressedTooLarge);
        }
        out.extend_from_slice(&buf[..read]);
    }
    if out.len() != expected {
        return Err(ChunkedError::DecompressedSizeMismatch {
            expected,
            actual: out.len(),
        });
    }
    Ok(out)
}

// ── Packager (spec 146 §Chunking parameters, §Compressibility heuristic) ──────────
//
// `encode_chunked_layer` turns a file's raw bytes into the framed single-blob layer:
// FastCDC over the raw content, a two-level compressibility heuristic per chunk, and a
// trailing skippable TOC frame. Per-chunk compression and blake3 are fanned out across a
// bounded worker pool; the CDC scan and the whole-stream sha256 are the sequential floor.

/// Whole-blob size floor (spec 146 §CLI Surface / Open Question 4): files below this stay
/// plain whole blobs; only files at or above it are chunked.
pub const CHUNK_SIZE_FLOOR: usize = 8 * 1024 * 1024;

/// `FastCDC` minimum chunk over raw content (spec 146 §Chunking parameters: min 1 MiB).
pub const FASTCDC_MIN: u32 = 1 << 20;
/// `FastCDC` average chunk over raw content (spec 146: 4 MiB).
pub const FASTCDC_AVG: u32 = 4 << 20;
/// `FastCDC` maximum chunk over raw content (spec 146: max 12 MiB == [`MAX_CHUNK_RAW`]).
pub const FASTCDC_MAX: u32 = 12 << 20;

/// Default zstd compression level for compressed frames (`--zstd-level` overrides).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Keep the compressed frame only if it saves at least this many bytes (spec 146: the
/// existing `package.rs` threshold — 64 KiB).
const COMPRESSION_MIN_SAVINGS: usize = 64 * 1024;
/// ...and compresses to at most this percent of the raw chunk (spec 146: ≥ 5 % — the
/// existing `package.rs` threshold).
const COMPRESSION_RATIO_PERCENT: usize = 95;

/// File-level probe: number of sampled windows (spec 146 §Compressibility heuristic).
const PROBE_WINDOWS: usize = 4;
/// File-level probe: sampled window size (128 KiB).
const PROBE_WINDOW_BYTES: usize = 128 * 1024;
/// File-level probe: a compressed/raw ratio at or above this percent (≈ 97 %) marks the
/// file raw-biased; below it, zstd-biased.
const PROBE_RAW_RATIO_PERCENT: u64 = 97;
/// Biased-mode re-probe cadence: the batch size over which one authoritative compression
/// probe drives a mode flip, so mixed files switch between raw- and zstd-biased.
const REPROBE_INTERVAL: usize = 16;

/// Operator knobs for [`encode_chunked_layer`].
#[derive(Debug, Clone, Copy)]
pub struct ChunkedEncodeOptions {
    /// zstd level for compressed frames.
    pub zstd_level: i32,
    /// Force every chunk to a raw (uncompressed) frame — `--no-compress`.
    pub no_compress: bool,
}

impl Default for ChunkedEncodeOptions {
    fn default() -> Self {
        Self {
            zstd_level: DEFAULT_ZSTD_LEVEL,
            no_compress: false,
        }
    }
}

/// A fully assembled chunked-zstd layer: the wire blob, its digest, and everything the
/// negotiated upload and the descriptor annotations need.
#[derive(Debug, Clone)]
pub struct EncodedChunkedLayer {
    /// The full wire stream: per-chunk frames followed by the skippable TOC frame.
    pub blob: Vec<u8>,
    /// `sha256:…` of the whole wire stream — the OCI layer digest.
    pub layer_digest: String,
    /// The table of contents (also embedded in the blob's skippable frame).
    pub toc: Toc,
    /// Byte offset of the skippable TOC frame within the blob.
    pub toc_offset: u64,
    /// `sha256:…` of the TOC bytes.
    pub toc_digest: String,
    /// Decompressed payload length (sum of every chunk's raw length).
    pub total_length: u64,
}

impl EncodedChunkedLayer {
    /// The descriptor annotations a manifest carries for this layer, located and verified
    /// by the reader before any TOC field is trusted.
    #[must_use]
    pub fn annotations(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                CHUNKED_TOC_OFFSET_ANNOTATION.to_owned(),
                self.toc_offset.to_string(),
            ),
            (
                CHUNKED_TOC_DIGEST_ANNOTATION.to_owned(),
                self.toc_digest.clone(),
            ),
            (
                CHUNKED_VERSION_ANNOTATION.to_owned(),
                FORMAT_VERSION.to_string(),
            ),
        ])
    }
}

/// One assembled chunk frame plus its identity, produced by the worker pool.
struct ChunkFrame {
    bytes: Vec<u8>,
    compressed: bool,
    cid: [u8; 32],
    raw_length: u32,
}

/// Whether the compressed frame clears both keep thresholds (spec 146 §Compressibility
/// heuristic step 2): saves ≥ 64 KiB **and** ≥ 5 %.
pub(crate) fn keeps_compressed(raw_len: usize, frame_len: usize) -> bool {
    let savings = raw_len.saturating_sub(frame_len);
    frame_len.saturating_mul(100) <= raw_len.saturating_mul(COMPRESSION_RATIO_PERCENT)
        && savings >= COMPRESSION_MIN_SAVINGS
}

/// Compress `chunk` and apply the authoritative per-chunk keep decision, returning the
/// frame to store (the compressed frame if it clears the thresholds, else the pinned raw
/// frame) and whether it is compressed.
fn compress_and_decide(chunk: &[u8], level: i32) -> Result<(Vec<u8>, bool), ChunkedError> {
    let compressed = compressed_frame(chunk, level)?;
    if keeps_compressed(chunk.len(), compressed.len()) {
        Ok((compressed, true))
    } else {
        Ok((raw_frame(chunk), false))
    }
}

/// Compress-bias mode of the file-level probe (spec 146 §Compressibility heuristic step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bias {
    /// Chunks stored raw by default; every Nth chunk re-probed so mixed files can flip.
    Raw,
    /// Every chunk compressed, subject to the per-chunk keep decision (symmetric flip-back
    /// when a batch's probe fails).
    Zstd,
}

/// Runs the fast file-level probe: compresses up to [`PROBE_WINDOWS`] evenly-sampled
/// windows and returns the initial bias. A raw-biased verdict means the sampled windows
/// barely compress (ratio ≥ ~97 %), so the authoritative per-chunk pass can be skipped for
/// most chunks and client zstd CPU stays probe-bounded.
fn probe_bias(raw: &[u8], level: i32) -> Bias {
    if raw.is_empty() {
        return Bias::Zstd;
    }
    let window = PROBE_WINDOW_BYTES.min(raw.len());
    let mut raw_total = 0u64;
    let mut compressed_total = 0u64;
    for index in 0..PROBE_WINDOWS {
        // Evenly space the window starts across the file; clamp the last to fit.
        let span = raw.len().saturating_sub(window);
        let start = if PROBE_WINDOWS <= 1 {
            0
        } else {
            span * index / (PROBE_WINDOWS - 1)
        };
        let end = (start + window).min(raw.len());
        let sample = &raw[start..end];
        let Ok(compressed) = zstd::bulk::compress(sample, level) else {
            // A probe failure biases toward attempting compression (safe, just more CPU).
            return Bias::Zstd;
        };
        raw_total += sample.len() as u64;
        compressed_total += compressed.len() as u64;
        if end == raw.len() {
            break;
        }
    }
    if raw_total == 0 {
        return Bias::Zstd;
    }
    if compressed_total.saturating_mul(100) >= raw_total.saturating_mul(PROBE_RAW_RATIO_PERCENT) {
        Bias::Raw
    } else {
        Bias::Zstd
    }
}

/// The per-chunk plan: for each chunk, whether the parallel pass should attempt
/// compression, plus any probe frame already computed (so probe chunks are compressed
/// exactly once). Derived by the sequential biased-mode walk with flips.
struct ChunkPlan {
    attempt: Vec<bool>,
    cached: std::collections::HashMap<usize, (Vec<u8>, bool)>,
}

/// Walk the chunks in [`REPROBE_INTERVAL`]-sized batches, evolving the bias with an
/// authoritative probe at each batch boundary (spec 146 §Compressibility heuristic). In
/// raw-biased mode only the batch's first chunk is compressed as a probe; a passing probe
/// flips the file to zstd-biased for the rest. In zstd-biased mode every chunk is attempted
/// and a failing batch probe flips back to raw-biased — the symmetric case.
fn plan_chunks(
    raw: &[u8],
    boundaries: &[(usize, usize)],
    options: ChunkedEncodeOptions,
) -> ChunkPlan {
    let n = boundaries.len();
    let mut attempt = vec![false; n];
    let mut cached = std::collections::HashMap::new();
    if options.no_compress {
        return ChunkPlan { attempt, cached };
    }
    let mut bias = probe_bias(raw, options.zstd_level);
    let mut i = 0;
    while i < n {
        match bias {
            Bias::Zstd => {
                let end = (i + REPROBE_INTERVAL).min(n);
                // Probe the batch head authoritatively; reuse its frame in the parallel
                // pass. A failing probe flips subsequent batches back to raw-biased.
                let (off, len) = boundaries[i];
                if let Ok((frame, compressed)) =
                    compress_and_decide(&raw[off..off + len], options.zstd_level)
                {
                    if !compressed {
                        bias = Bias::Raw;
                    }
                    cached.insert(i, (frame, compressed));
                }
                for slot in attempt.iter_mut().take(end).skip(i) {
                    *slot = true;
                }
                i = end;
            }
            Bias::Raw => {
                let (off, len) = boundaries[i];
                let probe = compress_and_decide(&raw[off..off + len], options.zstd_level);
                match probe {
                    Ok((frame, true)) => {
                        // The re-probe compresses well: keep it and flip to zstd-biased so
                        // the compressible region that follows is captured too.
                        attempt[i] = true;
                        cached.insert(i, (frame, true));
                        bias = Bias::Zstd;
                        i += 1;
                    }
                    _ => {
                        // Incompressible batch: store the whole batch raw, no attempts.
                        i = (i + REPROBE_INTERVAL).min(n);
                    }
                }
            }
        }
    }
    ChunkPlan { attempt, cached }
}

/// Encodes `raw` into a chunked-zstd layer (spec 146 §The Format). `FastCDC` establishes the
/// raw-content chunk boundaries; a two-level compressibility heuristic picks a compressed
/// or byte-pinned raw frame per chunk; per-chunk compression and blake3 fan out across the
/// cores; and the layer sha256 is the single sequential pass over the assembled stream.
///
/// # Errors
///
/// Returns [`ChunkedError::Zstd`] on a compression failure or [`ChunkedError`] on a TOC
/// encoding limit violation.
pub fn encode_chunked_layer(
    raw: &[u8],
    options: &ChunkedEncodeOptions,
) -> Result<EncodedChunkedLayer, ChunkedError> {
    // 1. FastCDC over the RAW content (sequential scan) → chunk boundaries.
    let boundaries: Vec<(usize, usize)> = if raw.is_empty() {
        vec![(0, 0)]
    } else {
        fastcdc::v2020::FastCDC::new(
            raw,
            FASTCDC_MIN as usize,
            FASTCDC_AVG as usize,
            FASTCDC_MAX as usize,
        )
        .map(|chunk| (chunk.offset, chunk.length))
        .collect()
    };

    // 2. Sequential biased-mode plan (cheap; compresses only probe chunks).
    let plan = plan_chunks(raw, &boundaries, *options);

    // 3. Parallel per-chunk frame construction + blake3 across the worker pool.
    let level = options.zstd_level;
    let frames: Vec<ChunkFrame> = parallel_try_map(boundaries.len(), |index| {
        let (off, len) = boundaries[index];
        let chunk = &raw[off..off + len];
        let (bytes, compressed) = if let Some((frame, compressed)) = plan.cached.get(&index) {
            (frame.clone(), *compressed)
        } else if plan.attempt[index] {
            compress_and_decide(chunk, level)?
        } else {
            (raw_frame(chunk), false)
        };
        let cid = frame_cid(&bytes);
        let raw_length =
            u32::try_from(len).map_err(|_| ChunkedError::RawLengthTooLarge(u32::MAX))?;
        Ok(ChunkFrame {
            bytes,
            compressed,
            cid,
            raw_length,
        })
    })?;

    // 4. Assemble: concatenate frames, build the TOC, append the skippable TOC frame, and
    //    take the layer sha256 in one final pass over the stream.
    let mut blob = Vec::with_capacity(raw.len() + boundaries.len() * 16 + 64);
    let mut entries = Vec::with_capacity(frames.len());
    let mut total_length = 0u64;
    for frame in &frames {
        let offset = blob.len() as u64;
        entries.push(ChunkEntry {
            frame_cid: frame.cid,
            frame_offset: offset,
            frame_length: frame.bytes.len() as u64,
            raw_length: frame.raw_length,
            compressed: frame.compressed,
            raw_sha256: None,
        });
        total_length += u64::from(frame.raw_length);
        blob.extend_from_slice(&frame.bytes);
    }
    let toc_offset = blob.len() as u64;
    let toc = Toc {
        format_version: FORMAT_VERSION,
        chunker: ChunkerParams {
            min: FASTCDC_MIN,
            avg: FASTCDC_AVG,
            max: FASTCDC_MAX,
        },
        chunks: entries,
    };
    let toc_bytes = toc.encode()?;
    let toc_digest = digest_bytes(&toc_bytes);
    blob.extend_from_slice(&encode_skippable_toc_frame(&toc_bytes));
    let layer_digest = digest_bytes(&blob);

    Ok(EncodedChunkedLayer {
        blob,
        layer_digest,
        toc,
        toc_offset,
        toc_digest,
        total_length,
    })
}

/// Fans `f` out over `0..n` on a bounded worker pool (one thread per core, work-stolen via
/// an atomic cursor), preserving index order in the result and short-circuiting on the
/// first error. The compression and blake3 in `f` are the parallel work; the caller's CDC
/// scan and final sha256 stay sequential (spec 146: zstd never the wall-clock floor).
fn parallel_try_map<R, F>(n: usize, f: F) -> Result<Vec<R>, ChunkedError>
where
    R: Send,
    F: Fn(usize) -> Result<R, ChunkedError> + Sync,
{
    use std::sync::atomic::{AtomicUsize, Ordering};

    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(n.max(1));
    if workers <= 1 || n <= 1 {
        return (0..n).map(f).collect();
    }

    let cursor = AtomicUsize::new(0);
    let f = &f;
    let cursor = &cursor;
    // Each worker collects (index, result) pairs; results are re-ordered afterward.
    let collected: Vec<Result<Vec<(usize, R)>, ChunkedError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(move || {
                    let mut local = Vec::new();
                    loop {
                        let index = cursor.fetch_add(1, Ordering::Relaxed);
                        if index >= n {
                            break;
                        }
                        local.push((index, f(index)?));
                    }
                    Ok(local)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("chunk worker panicked"))
            .collect()
    });

    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    for batch in collected {
        for (index, value) in batch? {
            out[index] = Some(value);
        }
    }
    Ok(out
        .into_iter()
        .map(|value| value.expect("all indices filled"))
        .collect())
}

/// A bounds-checked little-endian reader over a byte slice.
struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ChunkedError> {
        let end = self.pos.checked_add(n).ok_or(ChunkedError::Overflow)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(ChunkedError::MalformedToc)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ChunkedError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ChunkedError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ChunkedError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], ChunkedError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMS: ChunkerParams = ChunkerParams {
        min: 1 << 20,
        avg: 4 << 20,
        max: 12 << 20,
    };

    /// Assembles a chunked blob from `(raw, compressed?)` chunks and returns the
    /// blob plus the annotations a descriptor would carry.
    fn build_blob(chunks: &[(&[u8], bool)]) -> (Vec<u8>, BTreeMap<String, String>) {
        let mut blob = Vec::new();
        let mut entries = Vec::new();
        for (raw, compressed) in chunks {
            let frame = if *compressed {
                compressed_frame(raw, 3).expect("compress")
            } else {
                raw_frame(raw)
            };
            let offset = blob.len() as u64;
            entries.push(ChunkEntry {
                frame_cid: frame_cid(&frame),
                frame_offset: offset,
                frame_length: frame.len() as u64,
                raw_length: u32::try_from(raw.len()).expect("raw len"),
                compressed: *compressed,
                raw_sha256: None,
            });
            blob.extend_from_slice(&frame);
        }
        let toc_offset = blob.len() as u64;
        let toc = Toc {
            format_version: FORMAT_VERSION,
            chunker: PARAMS,
            chunks: entries,
        };
        let toc_bytes = toc.encode().expect("encode toc");
        let toc_digest = digest_bytes(&toc_bytes);
        blob.extend_from_slice(&encode_skippable_toc_frame(&toc_bytes));

        let annotations = BTreeMap::from([
            (
                CHUNKED_TOC_OFFSET_ANNOTATION.to_owned(),
                toc_offset.to_string(),
            ),
            (CHUNKED_TOC_DIGEST_ANNOTATION.to_owned(), toc_digest),
            (
                CHUNKED_VERSION_ANNOTATION.to_owned(),
                FORMAT_VERSION.to_string(),
            ),
        ]);
        (blob, annotations)
    }

    #[test]
    fn raw_frame_golden_bytes_are_pinned() {
        let frame = raw_frame(b"hello");
        assert_eq!(
            frame,
            vec![
                0x28, 0xB5, 0x2F, 0xFD, // magic
                0xA0, // frame header descriptor
                0x05, 0x00, 0x00, 0x00, // content size = 5
                0x29, 0x00, 0x00, // block header: last=1, raw, size=5 → (5<<3)|1
                0x68, 0x65, 0x6C, 0x6C, 0x6F, // "hello"
            ]
        );
        // Stock zstd must accept the pinned raw frame.
        assert_eq!(
            zstd::stream::decode_all(frame.as_slice()).expect("decode"),
            b"hello"
        );
    }

    #[test]
    fn raw_frame_multi_block_round_trips_through_stock_zstd() {
        let raw = vec![0x5Au8; MAX_BLOCK * 2 + 123];
        let frame = raw_frame(&raw);
        assert_eq!(
            zstd::stream::decode_all(frame.as_slice()).expect("decode"),
            raw
        );
    }

    #[test]
    fn toc_round_trips() {
        let toc = Toc {
            format_version: FORMAT_VERSION,
            chunker: PARAMS,
            chunks: vec![
                ChunkEntry {
                    frame_cid: [7u8; 32],
                    frame_offset: 0,
                    frame_length: 40,
                    raw_length: 100,
                    compressed: true,
                    raw_sha256: Some([9u8; 32]),
                },
                ChunkEntry {
                    frame_cid: [8u8; 32],
                    frame_offset: 40,
                    frame_length: 60,
                    raw_length: 200,
                    compressed: false,
                    raw_sha256: None,
                },
            ],
        };
        let bytes = toc.encode().expect("encode");
        assert_eq!(Toc::decode(&bytes).expect("decode"), toc);
    }

    #[test]
    fn toc_decode_rejects_trailing_bytes_and_bad_magic() {
        let toc = Toc {
            format_version: FORMAT_VERSION,
            chunker: PARAMS,
            chunks: Vec::new(),
        };
        let mut bytes = toc.encode().expect("encode");
        bytes.push(0);
        assert!(matches!(
            Toc::decode(&bytes),
            Err(ChunkedError::MalformedToc)
        ));

        let mut bad = toc.encode().expect("encode");
        bad[0] ^= 0xFF;
        assert!(matches!(Toc::decode(&bad), Err(ChunkedError::BadTocMagic)));
    }

    #[test]
    fn toc_encode_rejects_oversized_raw_length() {
        let toc = Toc {
            format_version: FORMAT_VERSION,
            chunker: PARAMS,
            chunks: vec![ChunkEntry {
                frame_cid: [0u8; 32],
                frame_offset: 0,
                frame_length: 10,
                raw_length: u32::try_from(MAX_CHUNK_RAW + 1).expect("fits u32"),
                compressed: false,
                raw_sha256: None,
            }],
        };
        assert!(matches!(
            toc.encode(),
            Err(ChunkedError::RawLengthTooLarge(_))
        ));
    }

    #[test]
    fn multi_frame_stream_decodes_with_reader_and_stock_zstd() {
        // compressed + raw + (skippable TOC) — the validity property.
        let a = vec![0xABu8; 5000];
        let b = b"raw literal chunk bytes".to_vec();
        let (blob, annotations) = build_blob(&[(&a, true), (&b, false)]);
        let digest = digest_bytes(&blob);

        let mut expected = a.clone();
        expected.extend_from_slice(&b);

        // Reader path.
        let out = read_chunked_blob(&blob, &annotations, &digest).expect("read");
        assert_eq!(out, expected);

        // Stock multi-frame decode over the WHOLE blob (skips the skippable TOC).
        let stock = zstd::stream::decode_all(blob.as_slice()).expect("stock decode");
        assert_eq!(stock, expected);
    }

    #[test]
    fn reader_rejects_bad_toc_digest() {
        let (blob, mut annotations) = build_blob(&[(b"payload", false)]);
        let digest = digest_bytes(&blob);
        annotations.insert(
            CHUNKED_TOC_DIGEST_ANNOTATION.to_owned(),
            digest_bytes(b"not the toc"),
        );
        assert!(matches!(
            read_chunked_blob(&blob, &annotations, &digest),
            Err(ChunkedError::TocDigestMismatch { .. })
        ));
    }

    #[test]
    fn reader_rejects_out_of_bounds_toc_offset() {
        let (blob, mut annotations) = build_blob(&[(b"payload", false)]);
        let digest = digest_bytes(&blob);
        annotations.insert(
            CHUNKED_TOC_OFFSET_ANNOTATION.to_owned(),
            (blob.len() as u64 + 1000).to_string(),
        );
        assert!(matches!(
            read_chunked_blob(&blob, &annotations, &digest),
            Err(ChunkedError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn reader_rejects_truncated_stream() {
        let (blob, annotations) = build_blob(&[(&vec![1u8; 4096], true)]);
        let full_digest = digest_bytes(&blob);
        // Drop the last frame-region byte (keep TOC offset annotation pointing past
        // the end → out of bounds; instead truncate inside the frame region and fix
        // the digest so we exercise the decode failure, not the digest gate).
        let mut truncated = blob.clone();
        // Remove one byte from the middle of the frame region.
        truncated.remove(10);
        // The layer digest no longer matches — the wire-level gate fires first.
        assert!(matches!(
            read_chunked_blob(&truncated, &annotations, &full_digest),
            Err(ChunkedError::LayerDigestMismatch { .. })
        ));
    }

    #[test]
    fn reader_rejects_layer_digest_mismatch() {
        let (blob, annotations) = build_blob(&[(b"payload", false)]);
        assert!(matches!(
            read_chunked_blob(&blob, &annotations, &digest_bytes(b"wrong")),
            Err(ChunkedError::LayerDigestMismatch { .. })
        ));
    }

    #[test]
    fn validate_tiling_rejects_gaps_and_lying_region() {
        let toc = Toc {
            format_version: FORMAT_VERSION,
            chunker: PARAMS,
            chunks: vec![
                ChunkEntry {
                    frame_cid: [0u8; 32],
                    frame_offset: 0,
                    frame_length: 10,
                    raw_length: 10,
                    compressed: false,
                    raw_sha256: None,
                },
                ChunkEntry {
                    frame_cid: [0u8; 32],
                    frame_offset: 20, // gap: should be 10
                    frame_length: 10,
                    raw_length: 10,
                    compressed: false,
                    raw_sha256: None,
                },
            ],
        };
        assert!(matches!(
            toc.validate_tiling(30),
            Err(ChunkedError::BadTiling)
        ));
    }

    #[test]
    fn decode_rejects_oversized_raw_length_in_wire_bytes() {
        // Hand-craft a TOC whose encoded raw_length exceeds MAX_CHUNK_RAW: encode a
        // valid one, then overwrite the raw_length field.
        let toc = Toc {
            format_version: FORMAT_VERSION,
            chunker: PARAMS,
            chunks: vec![ChunkEntry {
                frame_cid: [0u8; 32],
                frame_offset: 0,
                frame_length: 10,
                raw_length: 1,
                compressed: false,
                raw_sha256: None,
            }],
        };
        let mut bytes = toc.encode().expect("encode");
        // raw_length sits at: 24 header + 32 cid + 8 offset + 8 length = byte 72.
        let raw_len_pos = 24 + 32 + 8 + 8;
        bytes[raw_len_pos..raw_len_pos + 4].copy_from_slice(
            &u32::try_from(MAX_CHUNK_RAW + 1)
                .expect("fits u32")
                .to_le_bytes(),
        );
        assert!(matches!(
            Toc::decode(&bytes),
            Err(ChunkedError::RawLengthTooLarge(_))
        ));
    }
}
