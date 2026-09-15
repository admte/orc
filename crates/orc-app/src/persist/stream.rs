//! Streaming sealed chunked codec: the upload and restore halves of the App-data pipeline.
//!
//! The wire stream this module writes is an ordinary spec-146 chunked-zstd stream — the
//! registry verifies and stores unchanged — but every frame carries a *sealed*
//! payload rather than the plaintext chunk:
//!
//! ```text
//! plaintext ──FastCDC──▶ chunk ──zstd?──▶ payload ──seal──▶ sealed ──raw_frame──▶ frame
//! ```
//!
//! Boundaries are cut over the **plaintext**, so an edit shifts chunks only locally and
//! dedup survives encryption. The sealed bytes are then wrapped in a byte-pinned *raw* zstd
//! frame ([`raw_frame`]), which is what makes the stream a valid chunked-zstd blob without
//! exposing decompressible content to the registry: the frame's declared `raw_length` is
//! the sealed length and its `compressed` flag is `false`, so a reader that follows the
//! spec-146 rules recovers exactly the sealed bytes. Compression happens *inside* the seal,
//! recorded in a flags byte that is itself sealed.
//!
//! The trailing table of contents is sealed too, under its own seal context, so a reader
//! without the key sees the sizes of the sealed frames and nothing else — not the
//! content-defined chunk-length sequence, which is a fingerprint of the plaintext, and not
//! which chunks compressed. Version 1 of this stream (plaintext table of contents, flags in
//! the clear) is not read; see [`SEALED_STREAM_VERSION`].
//!
//! Both directions are streaming: [`encode_sealed_stream`] hands each frame to a sink as
//! soon as it is built and never holds the layer, and [`decode_sealed_stream`] walks the
//! TOC reading exactly one frame at a time.
//!
//! There are two decoders because there are two situations. The pull path has the whole
//! blob and its verified TOC, so [`decode_sealed_stream`] can check every frame's cid
//! before touching it. The restore path has only a byte stream off the registry — no
//! seekable blob, no TOC until the last frame arrives — so
//! [`decode_sealed_sequential`] parses the pinned frame layout as the bytes come and
//! leans on the AEAD for integrity, checking the trailing TOC against what it read.
//!
//! # Memory bound
//!
//! Encoding holds the `FastCDC` read buffer (one max chunk) plus at most four live
//! chunk-sized buffers (the chunk, its compressed form, the sealed payload, the frame) —
//! `≤ 5 × 12 MiB` in the worst case and `~5 × 4 MiB` at the average chunk size, regardless
//! of input length. Decoding holds one frame plus its sealed and plaintext forms, `≤ 3 ×
//! 12 MiB`. Neither direction allocates from a length an attacker declares: every bound is
//! a compile-time constant.

use std::io::{Read, Write};

use sha2::{Digest as _, Sha256};

use crate::chunked::{
    ChunkEntry, ChunkedError, ChunkerParams, DEFAULT_ZSTD_LEVEL, FASTCDC_AVG, FASTCDC_MAX,
    FASTCDC_MIN, FORMAT_VERSION, MAX_BLOCK, MAX_CHUNK_RAW, MAX_TOC_BYTES, SKIPPABLE_MAGIC, Toc,
    WINDOW_LOG_MAX, ZSTD_FRAME_MAGIC, encode_skippable_toc_frame, frame_cid, keeps_compressed,
    raw_frame,
};
use crate::error::CliError;
use crate::persist::seal::{Opener, SEAL_OVERHEAD, SealContext, SealError, Sealer};
use crate::registry::digest_bytes;

/// Version of the sealed-stream format this codec writes and the only one it reads.
/// It is the seal envelope's own version — every payload frame and the sealed table of
/// contents carry it — so one number describes the whole stream.
pub const SEALED_STREAM_VERSION: u8 = crate::persist::seal::SEAL_VERSION;

/// Plaintext `FastCDC` maximum for sealed streams.
///
/// Sealing adds [`SEAL_OVERHEAD`] bytes, and the frame's `raw_length` — the sealed length —
/// is capped at [`MAX_CHUNK_RAW`] by spec 146. Cutting plaintext at 12 MiB − 4 KiB keeps
/// every sealed payload under that cap with room to spare (the exact overhead is 31 bytes;
/// the round number is deliberate).
pub const SEALED_FASTCDC_MAX: u32 = FASTCDC_MAX - 4096;

/// Upper bound on one frame's wire length: the sealed payload plus the byte-pinned raw
/// frame's headers (9 bytes of frame header and 3 per 128 `KiB` block — 297 bytes at the
/// 12 MiB cap).
pub const MAX_SEALED_FRAME: u64 = MAX_CHUNK_RAW as u64 + 4096;

/// Read buffer for unwrapping a frame's zstd wrapper (the zstd block size).
const DECODE_BUFFER: usize = 128 * 1024;

/// Errors from encoding or decoding a sealed chunked stream. Every decode failure names the
/// frame index it refused, because a restore aborts loudly on the first one.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("read the plaintext stream: {0}")]
    Source(String),
    #[error("sealed stream I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error(transparent)]
    Chunked(#[from] ChunkedError),
    #[error("compress chunk {index}: {source}")]
    Compress {
        index: usize,
        source: std::io::Error,
    },
    #[error("sealed chunk {index} is {len} bytes, over the {MAX_CHUNK_RAW}-byte frame limit")]
    SealedChunkTooLarge { index: usize, len: usize },
    #[error("frame {index} declares {len} bytes, over the {MAX_SEALED_FRAME}-byte frame limit")]
    FrameTooLarge { index: usize, len: u64 },
    #[error("frame {index} does not start where the preceding frames end")]
    BadTiling { index: usize },
    #[error("frame {index} is truncated: the stream ended mid-frame")]
    TruncatedFrame { index: usize },
    #[error("frame {index} content id does not match the TOC")]
    CidMismatch { index: usize },
    #[error("frame {index} unwraps to {actual} bytes, the TOC declares {expected}")]
    SealedSizeMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("frame {index}: unwrap the zstd frame: {source}")]
    Unwrap {
        index: usize,
        source: std::io::Error,
    },
    #[error("frame {index}: decompress the sealed payload: {source}")]
    Decompress {
        index: usize,
        source: std::io::Error,
    },
    #[error("frame {index} does not start with a zstd frame magic")]
    BadFrameMagic { index: usize },
    #[error("frame {index} is not the pinned raw-block frame this codec writes")]
    BadFrameLayout { index: usize },
    #[error("the sealed stream ends without its table-of-contents frame")]
    MissingToc,
    #[error("the sealed stream carries {0} bytes after its table-of-contents frame")]
    TrailingBytes(u64),
    #[error("the sealed stream carries {frames} frames, its table of contents declares {declared}")]
    TocFrameCount { frames: usize, declared: usize },
    #[error(
        "frame {index} carries {actual} sealed bytes, the table of contents declares {expected}"
    )]
    TocLengthMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
}

impl From<StreamError> for CliError {
    fn from(err: StreamError) -> Self {
        CliError::Operational(err.to_string())
    }
}

/// One frame of the wire stream in the shape the registry's chunked-upload recipe expects
/// (`RecipeRequest.chunks`).
///
/// Field contract for a chunked-upload recipe entry: `frame_cid` is the blake3 of the
/// frame's wire bytes as lowercase hex — consumers accept a bare 64-char hex string or a
/// `blake3:<hex>` digest; `frame_offset`/`frame_length` locate the frame within the blob,
/// and the concatenation of every entry in order *is* the blob; `raw_length` is the frame's
/// decompressed length (the sealed payload's length here, and 0 for the trailing TOC
/// frame); `compressed` is informational and is always `false` for a sealed stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SealedRecipeEntry {
    pub frame_cid: String,
    pub frame_offset: u64,
    pub frame_length: u64,
    pub raw_length: u64,
    pub compressed: bool,
}

/// Everything the upload needs after a stream has been encoded. The layer bytes themselves
/// went to the sink — nothing here grows with the input.
#[derive(Debug, Clone)]
pub struct SealedLayer {
    /// The table of contents, carried *sealed* in the stream's trailing skippable frame.
    pub toc: Toc,
    /// `sha256:…` of the whole wire stream (frames plus the TOC frame) — the layer digest.
    pub layer_digest: String,
    /// Byte offset of the skippable TOC frame within the stream.
    pub toc_offset: u64,
    /// `sha256:…` of the bytes the skippable frame actually carries — the *sealed* table of
    /// contents, not its plaintext encoding.
    pub toc_digest: String,
    /// blake3 of the trailing skippable TOC frame's wire bytes.
    pub toc_frame_cid: [u8; 32],
    /// Wire length of the trailing skippable TOC frame.
    pub toc_frame_length: u64,
    /// Sum of every frame's `raw_length` — the sealed byte total the recipe declares.
    pub total_length: u64,
    /// Plaintext bytes consumed from the reader.
    pub raw_total: u64,
}

impl SealedLayer {
    /// The recipe entries for the negotiated upload: one per payload frame, followed by the
    /// trailing skippable TOC frame (`raw_length` 0).
    #[must_use]
    pub fn recipe_entries(&self) -> Vec<SealedRecipeEntry> {
        let mut entries: Vec<SealedRecipeEntry> = self
            .toc
            .chunks
            .iter()
            .map(|chunk| SealedRecipeEntry {
                frame_cid: hex(&chunk.frame_cid),
                frame_offset: chunk.frame_offset,
                frame_length: chunk.frame_length,
                raw_length: u64::from(chunk.raw_length),
                compressed: chunk.compressed,
            })
            .collect();
        entries.push(SealedRecipeEntry {
            frame_cid: hex(&self.toc_frame_cid),
            frame_offset: self.toc_offset,
            frame_length: self.toc_frame_length,
            raw_length: 0,
            compressed: false,
        });
        entries
    }
}

/// Lowercase hex, the form both a frame cid and a digest string carry.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Compresses `chunk` and applies the spec-146 keep decision (saves ≥ 64 `KiB` **and**
/// ≥ 5 %), returning the compressed payload only when it is worth carrying.
///
/// The decision depends on the chunk's bytes alone — never on its position in the stream —
/// because a chunk that seals differently depending on where it landed would not dedup
/// against its own earlier copy. That rules out the artifact packager's stateful
/// probe/bias heuristic (`chunked::plan_chunks`), which skips compression for whole batches
/// and so decides differently once an insertion shifts chunk indices.
fn worthwhile_compression(chunk: &[u8], index: usize) -> Result<Option<Vec<u8>>, StreamError> {
    let compressed = zstd::bulk::compress(chunk, DEFAULT_ZSTD_LEVEL)
        .map_err(|source| StreamError::Compress { index, source })?;
    Ok(keeps_compressed(chunk.len(), compressed.len()).then_some(compressed))
}

/// Encodes `reader`'s plaintext into a sealed chunked-zstd stream, handing each frame to
/// `sink` as it is built and finishing with the skippable TOC frame.
///
/// The returned [`SealedLayer`] carries the TOC, the layer digest, and the totals the
/// negotiated upload needs; the bytes themselves were emitted, never accumulated.
///
/// # Errors
///
/// Returns [`StreamError::Source`] if the reader or the chunker fails,
/// [`StreamError::Io`] if the sink fails, [`StreamError::Seal`] if sealing fails, and
/// [`StreamError::SealedChunkTooLarge`] if a sealed chunk would exceed the spec-146
/// per-frame `raw_length` cap (unreachable while chunking at [`SEALED_FASTCDC_MAX`]).
pub fn encode_sealed_stream(
    reader: impl Read,
    sealer: &Sealer,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<SealedLayer, StreamError> {
    let chunker = fastcdc::v2020::StreamCDC::new(
        reader,
        FASTCDC_MIN as usize,
        FASTCDC_AVG as usize,
        SEALED_FASTCDC_MAX as usize,
    );

    let mut hasher = Sha256::new();
    let mut entries: Vec<ChunkEntry> = Vec::new();
    let mut offset = 0u64;
    let mut raw_total = 0u64;
    let mut total_length = 0u64;

    for (index, chunk) in chunker.enumerate() {
        let chunk = chunk.map_err(|err| StreamError::Source(err.to_string()))?;
        let plaintext = chunk.data;

        let compressed = worthwhile_compression(&plaintext, index)?;
        let payload = compressed.as_deref().unwrap_or(&plaintext);
        let sealed = sealer.seal(SealContext::Frame, payload, compressed.is_some())?;
        // The spec-146 `raw_length` cap is what chunking at SEALED_FASTCDC_MAX buys room
        // for; check it rather than trust the arithmetic.
        let raw_length = match u32::try_from(sealed.len()) {
            Ok(len) if len as usize <= MAX_CHUNK_RAW => len,
            _ => {
                return Err(StreamError::SealedChunkTooLarge {
                    index,
                    len: sealed.len(),
                });
            }
        };
        let frame = raw_frame(&sealed);
        let frame_length = frame.len() as u64;

        hasher.update(&frame);
        sink(&frame)?;

        entries.push(ChunkEntry {
            frame_cid: frame_cid(&frame),
            frame_offset: offset,
            frame_length,
            raw_length,
            // The frame carries the sealed bytes verbatim in uncompressed zstd blocks; any
            // compression happened inside the seal.
            compressed: false,
            raw_sha256: None,
        });
        offset += frame_length;
        raw_total += plaintext.len() as u64;
        total_length += u64::from(raw_length);
    }

    let toc = Toc {
        format_version: FORMAT_VERSION,
        // The recorded parameters are the plaintext boundaries the chunker cut on — what
        // dedup keys on — not the lengths of the sealed payloads the frames carry.
        chunker: ChunkerParams {
            min: FASTCDC_MIN,
            avg: FASTCDC_AVG,
            max: SEALED_FASTCDC_MAX,
        },
        chunks: entries,
    };
    // The table of contents is the chunk-length sequence, which is a fingerprint of the
    // plaintext; it goes into the skippable frame sealed, under its own context so it can
    // never be opened as a payload frame. `toc_digest` is over the bytes actually carried.
    let toc_bytes = toc.encode()?;
    let sealed_toc = sealer.seal(SealContext::Toc, &toc_bytes, false)?;
    let toc_digest = digest_bytes(&sealed_toc);
    let toc_frame = encode_skippable_toc_frame(&sealed_toc);
    hasher.update(&toc_frame);
    sink(&toc_frame)?;

    let layer_digest = format!("sha256:{}", hex(&hasher.finalize()));
    Ok(SealedLayer {
        toc,
        layer_digest,
        toc_offset: offset,
        toc_digest,
        toc_frame_cid: frame_cid(&toc_frame),
        toc_frame_length: toc_frame.len() as u64,
        total_length,
        raw_total,
    })
}

/// Decodes a sealed chunked stream back into plaintext, walking `toc` in order and writing
/// each chunk to `writer` as it is opened.
///
/// `reader` must be positioned at the first frame; it is left positioned just after the
/// last payload frame (the trailing skippable TOC frame is not consumed). Every frame is
/// verified against its TOC cid **before** it is decoded or opened, and the AEAD tag is
/// checked before a byte reaches `writer`.
///
/// Returns the number of plaintext bytes written.
///
/// # Errors
///
/// Returns a [`StreamError`] naming the offending frame index for a bad tiling, an
/// oversized or truncated frame, a cid mismatch, a size mismatch, a failed unseal, or a
/// decompression failure — and [`StreamError::Io`] if the reader or writer fails.
pub fn decode_sealed_stream(
    mut reader: impl Read,
    toc: &Toc,
    sealer: &Sealer,
    writer: &mut dyn Write,
) -> Result<u64, StreamError> {
    if toc.format_version != FORMAT_VERSION {
        return Err(ChunkedError::UnsupportedVersion(toc.format_version).into());
    }

    let mut cursor = 0u64;
    let mut written = 0u64;
    let mut frame = Vec::new();
    for (index, entry) in toc.chunks.iter().enumerate() {
        if entry.frame_offset != cursor || entry.frame_length == 0 {
            return Err(StreamError::BadTiling { index });
        }
        if entry.frame_length > MAX_SEALED_FRAME {
            return Err(StreamError::FrameTooLarge {
                index,
                len: entry.frame_length,
            });
        }
        if entry.raw_length as usize > MAX_CHUNK_RAW {
            return Err(ChunkedError::RawLengthTooLarge(entry.raw_length).into());
        }

        let len = usize::try_from(entry.frame_length).map_err(|_| StreamError::FrameTooLarge {
            index,
            len: entry.frame_length,
        })?;
        frame.clear();
        frame.resize(len, 0);
        if let Err(err) = reader.read_exact(&mut frame) {
            return if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Err(StreamError::TruncatedFrame { index })
            } else {
                Err(StreamError::Io(err))
            };
        }
        if frame_cid(&frame) != entry.frame_cid {
            return Err(StreamError::CidMismatch { index });
        }

        let sealed = unwrap_frame(&frame, entry.raw_length, index)?;
        let (payload, compressed) = sealer.open(SealContext::Frame, &sealed)?;
        let plaintext = if compressed {
            zstd::bulk::decompress(&payload, MAX_CHUNK_RAW)
                .map_err(|source| StreamError::Decompress { index, source })?
        } else {
            payload
        };
        writer.write_all(&plaintext)?;
        written += plaintext.len() as u64;
        cursor += entry.frame_length;
    }
    Ok(written)
}

/// Decodes a sealed chunked stream **without its table of contents**, frame by frame, in
/// the order the bytes arrive.
///
/// The restore path reads layers straight off the registry as a byte stream: there is no
/// seekable blob to locate a TOC in, and buffering one to find it would defeat the point.
/// That is affordable here only because [`encode_sealed_stream`] always emits the
/// byte-pinned raw frame [`crate::chunked::raw_frame`] writes, whose layout this function
/// parses directly — magic, a `0xA0` frame-header descriptor, a 4-byte frame content size,
/// then `Raw` blocks of at most 128 `KiB` until one carries the last-block flag. The zstd
/// crate exposes no frame-boundary API, so the layout is read rather than delegated; it is
/// pinned by a golden test on both sides.
///
/// Integrity does not depend on the TOC: every frame's payload is opened by the AEAD,
/// which authenticates it under the pool's key. The trailing skippable TOC frame is still
/// required — its absence means the stream was truncated — and it is itself sealed, so the
/// same key that opens the frames is what makes the table of contents readable at all; its
/// entry count and sealed lengths are then checked against what was actually read.
///
/// Each plaintext chunk is handed to `sink` as it is opened; nothing accumulates.
/// Returns the number of plaintext bytes written.
///
/// # Errors
///
/// Returns [`StreamError::BadFrameMagic`] or [`StreamError::BadFrameLayout`] for bytes
/// that are not this codec's output, [`StreamError::TruncatedFrame`] for a short stream,
/// [`StreamError::MissingToc`] when the TOC frame never arrives,
/// [`StreamError::TocFrameCount`]/[`StreamError::TocLengthMismatch`] when it disagrees
/// with the frames read, [`StreamError::Seal`] for a failed unseal, and
/// [`StreamError::Io`] for a reader or sink failure.
pub fn decode_sealed_sequential(
    reader: impl Read,
    opener: &dyn Opener,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<u64, StreamError> {
    let mut reader = std::io::BufReader::with_capacity(MAX_BLOCK, reader);
    let mut written = 0u64;
    let mut sealed_lengths: Vec<u64> = Vec::new();
    let mut sealed = Vec::new();

    loop {
        let index = sealed_lengths.len();
        let Some(magic) = read_u32_or_eof(&mut reader)? else {
            return Err(StreamError::MissingToc);
        };
        if magic == SKIPPABLE_MAGIC {
            let toc = read_toc_frame(&mut reader, opener)?;
            verify_toc(&toc, &sealed_lengths)?;
            let trailing = std::io::copy(&mut reader, &mut std::io::sink())?;
            if trailing > 0 {
                return Err(StreamError::TrailingBytes(trailing));
            }
            return Ok(written);
        }
        if magic != ZSTD_FRAME_MAGIC {
            return Err(StreamError::BadFrameMagic { index });
        }
        read_raw_frame_body(&mut reader, index, &mut sealed)?;
        sealed_lengths.push(sealed.len() as u64);

        let (payload, compressed) = opener.open(SealContext::Frame, &sealed)?;
        let plaintext = if compressed {
            zstd::bulk::decompress(&payload, MAX_CHUNK_RAW)
                .map_err(|source| StreamError::Decompress { index, source })?
        } else {
            payload
        };
        sink(&plaintext)?;
        written += plaintext.len() as u64;
    }
}

/// Reads the body of one pinned raw frame (everything after its magic) into `out`.
fn read_raw_frame_body(
    reader: &mut impl Read,
    index: usize,
    out: &mut Vec<u8>,
) -> Result<(), StreamError> {
    let mut descriptor = [0u8; 5];
    read_exact(reader, &mut descriptor, index)?;
    // Single_Segment_flag = 1, Frame_Content_Size_flag = 2 (4-byte size), no checksum, no
    // dictionary — the one descriptor `raw_frame` ever writes.
    if descriptor[0] != 0xA0 {
        return Err(StreamError::BadFrameLayout { index });
    }
    let declared = u32::from_le_bytes([descriptor[1], descriptor[2], descriptor[3], descriptor[4]]);
    if declared as usize > MAX_CHUNK_RAW {
        return Err(ChunkedError::RawLengthTooLarge(declared).into());
    }
    out.clear();
    out.reserve(declared as usize);
    loop {
        let mut header = [0u8; 3];
        read_exact(reader, &mut header, index)?;
        let header =
            u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16);
        let last = header & 1 == 1;
        let block_type = (header >> 1) & 0b11;
        let size = (header >> 3) as usize;
        // Block_Type 0 is `Raw`; the pinned frame never writes any other kind, and a
        // compressed block here would mean the bytes did not come from this codec.
        if block_type != 0 || size > MAX_BLOCK {
            return Err(StreamError::BadFrameLayout { index });
        }
        if out.len() + size > declared as usize {
            return Err(StreamError::BadFrameLayout { index });
        }
        let start = out.len();
        out.resize(start + size, 0);
        read_exact(reader, &mut out[start..], index)?;
        if last {
            break;
        }
    }
    if out.len() != declared as usize {
        return Err(StreamError::BadFrameLayout { index });
    }
    if out.len() < SEAL_OVERHEAD {
        return Err(SealError::Truncated.into());
    }
    Ok(())
}

/// Reads the skippable frame's declared length, opens its sealed payload, and decodes the
/// table of contents from the plaintext.
///
/// The wire cap is the TOC byte cap plus one seal envelope, because the frame carries the
/// sealed form; the plaintext cap is whatever [`Toc::decode`] accepts. A stream that left
/// its table of contents in the clear — the old format — fails here at the seal, not at the
/// TOC parser.
fn read_toc_frame(reader: &mut impl Read, opener: &dyn Opener) -> Result<Toc, StreamError> {
    let index = usize::MAX;
    let mut length = [0u8; 4];
    read_exact(reader, &mut length, index)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_TOC_BYTES + SEAL_OVERHEAD {
        return Err(ChunkedError::TocTooLarge(length).into());
    }
    let mut bytes = vec![0u8; length];
    read_exact(reader, &mut bytes, index)?;
    let (toc_bytes, _) = opener.open(SealContext::Toc, &bytes)?;
    Ok(Toc::decode(&toc_bytes)?)
}

/// Cross-checks the frames actually read against what the trailing TOC declares. The AEAD
/// already authenticated every payload; this catches a stream that was cut short or spliced
/// between two valid layers.
fn verify_toc(toc: &Toc, sealed_lengths: &[u64]) -> Result<(), StreamError> {
    if toc.format_version != FORMAT_VERSION {
        return Err(ChunkedError::UnsupportedVersion(toc.format_version).into());
    }
    if toc.chunks.len() != sealed_lengths.len() {
        return Err(StreamError::TocFrameCount {
            frames: sealed_lengths.len(),
            declared: toc.chunks.len(),
        });
    }
    for (index, (entry, actual)) in toc.chunks.iter().zip(sealed_lengths).enumerate() {
        if u64::from(entry.raw_length) != *actual {
            return Err(StreamError::TocLengthMismatch {
                index,
                expected: u64::from(entry.raw_length),
                actual: *actual,
            });
        }
    }
    Ok(())
}

/// A 4-byte little-endian read that distinguishes a clean end of stream from a short one.
fn read_u32_or_eof(reader: &mut impl Read) -> Result<Option<u32>, StreamError> {
    let mut buf = [0u8; 4];
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(StreamError::MissingToc),
            Ok(read) => filled += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(StreamError::Io(err)),
        }
    }
    Ok(Some(u32::from_le_bytes(buf)))
}

fn read_exact(reader: &mut impl Read, buf: &mut [u8], index: usize) -> Result<(), StreamError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(StreamError::TruncatedFrame { index })
        }
        Err(err) => Err(StreamError::Io(err)),
    }
}

/// Unwraps one frame's zstd envelope into the sealed payload, bounded by the TOC's declared
/// `raw_length` (itself capped at 12 MiB) and by a fixed decoder window.
fn unwrap_frame(frame: &[u8], raw_length: u32, index: usize) -> Result<Vec<u8>, StreamError> {
    let expected = raw_length as usize;
    let mut decoder = zstd::stream::read::Decoder::new(frame)
        .map_err(|source| StreamError::Unwrap { index, source })?;
    decoder
        .window_log_max(WINDOW_LOG_MAX)
        .map_err(|source| StreamError::Unwrap { index, source })?;
    let mut out = Vec::with_capacity(expected.min(MAX_CHUNK_RAW));
    let mut buf = vec![0u8; DECODE_BUFFER];
    loop {
        let read = decoder
            .read(&mut buf)
            .map_err(|source| StreamError::Unwrap { index, source })?;
        if read == 0 {
            break;
        }
        if out.len() + read > expected {
            return Err(StreamError::SealedSizeMismatch {
                index,
                expected: u64::from(raw_length),
                actual: (out.len() + read) as u64,
            });
        }
        out.extend_from_slice(&buf[..read]);
    }
    if out.len() != expected {
        return Err(StreamError::SealedSizeMismatch {
            index,
            expected: u64::from(raw_length),
            actual: out.len() as u64,
        });
    }
    if out.len() < SEAL_OVERHEAD {
        return Err(SealError::Truncated.into());
    }
    Ok(out)
}

#[cfg(test)]
mod sequential_tests {
    use super::*;
    use crate::persist::seal::{DATA_KEY_LEN, DataKey};

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    fn golden_sealer() -> Sealer {
        let mut key = [0u8; DATA_KEY_LEN];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or_default();
        }
        Sealer::new(&DataKey::new(key))
    }

    fn encode(body: &[u8], sealer: &Sealer) -> (Vec<u8>, SealedLayer) {
        let mut stream = Vec::new();
        let layer = encode_sealed_stream(body, sealer, &mut |frame| {
            stream.extend_from_slice(frame);
            Ok(())
        })
        .expect("encode");
        (stream, layer)
    }

    fn decode(stream: &[u8], sealer: &Sealer) -> Result<Vec<u8>, StreamError> {
        let mut out = Vec::new();
        decode_sealed_sequential(stream, sealer, &mut |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(out)
    }

    /// Golden vector: pins the wire bytes the sequential decoder parses by hand. If this
    /// changes, every existing restore point becomes unreadable by this code path — the
    /// frame layout is a format, not an implementation detail.
    #[test]
    fn the_sequential_frame_layout_is_pinned() {
        let sealer = golden_sealer();
        let (stream, layer) = encode(b"orc8r appdata sequential golden vector", &sealer);
        assert_eq!(
            hex(&stream),
            "28b52ffda045000000290200020020fad55ecdfb4b6fbf013ffc9815757c62e257a8be6f1b4783e8accaa02c9dcdc12359d84102f39eaa210c5195a98f7674a30827fc9029d2f6c9d8b949f4730b95e9c15e2a4d186c0000000201700355052eecdac127bc117d5a0b36bb8debc2d4e545190dddc2d04d78b3af43c3a711ab56d42187bc4ed997be6b3b80e3d12e965b42411d155de1f815f05b383f7ad939f83677a0107ec4a81b61e99b45ddcf9652368f5311c74610b8dd747e7d1551c8ca53fb5a725c"
        );
        assert_eq!(layer.toc.chunks.len(), 1);
        assert_eq!(
            decode(&stream, &sealer).expect("decode"),
            b"orc8r appdata sequential golden vector"
        );
    }

    #[test]
    fn the_sequential_decoder_agrees_with_the_toc_walking_one() {
        let sealer = golden_sealer();
        // Long enough to cross several frames, with a compressible and an incompressible
        // stretch so both sealed flag values appear.
        let mut body = Vec::new();
        for index in 0..1_000_000u32 {
            body.extend_from_slice(&index.to_le_bytes());
            body.extend_from_slice(b"aaaaaaaaaaaaaaaa");
        }
        let (stream, layer) = encode(&body, &sealer);
        assert!(layer.toc.chunks.len() > 3, "the body must cross frames");

        let mut walked = Vec::new();
        decode_sealed_stream(stream.as_slice(), &layer.toc, &sealer, &mut walked).expect("toc");
        assert_eq!(walked, body);
        assert_eq!(decode(&stream, &sealer).expect("sequential"), body);
    }

    #[test]
    fn an_empty_stream_still_carries_its_table_of_contents() {
        let sealer = golden_sealer();
        let (stream, layer) = encode(b"", &sealer);
        assert!(layer.toc.chunks.is_empty());
        assert!(decode(&stream, &sealer).expect("decode").is_empty());
    }

    #[test]
    fn a_stream_cut_short_of_its_table_of_contents_is_refused() {
        let sealer = golden_sealer();
        let (stream, layer) = encode(
            b"a body long enough to frame".repeat(64).as_slice(),
            &sealer,
        );
        let truncated = &stream[..usize::try_from(layer.toc_offset).expect("offset")];
        assert!(
            matches!(decode(truncated, &sealer), Err(StreamError::MissingToc)),
            "a stream without its TOC frame must not read as complete"
        );
        // Cut inside a frame instead: the frame itself is short.
        let inside = &stream[..stream.len() / 3];
        assert!(matches!(
            decode(inside, &sealer),
            Err(StreamError::TruncatedFrame { .. })
        ));
    }

    #[test]
    fn a_tampered_frame_fails_the_aead_rather_than_decoding() {
        let sealer = golden_sealer();
        let (mut stream, _) = encode(
            b"tamper with me please, at length".repeat(8).as_slice(),
            &sealer,
        );
        // Byte 20 is inside the first frame's sealed ciphertext.
        stream[20] ^= 0x01;
        assert!(matches!(
            decode(&stream, &sealer),
            Err(StreamError::Seal(SealError::Unauthentic))
        ));
    }

    #[test]
    fn a_table_of_contents_that_disagrees_with_the_frames_is_refused() {
        let sealer = golden_sealer();
        let (stream, layer) = encode(b"a body".repeat(2000).as_slice(), &sealer);
        let offset = usize::try_from(layer.toc_offset).expect("offset");
        // Re-seals a doctored TOC into a stream the decoder will accept as far as the
        // cross-check — a holder of the key is the only party that can forge this far.
        let rebuild = |toc: &Toc| {
            let sealed = sealer
                .seal(SealContext::Toc, &toc.encode().expect("toc"), false)
                .expect("seal toc");
            let mut rebuilt = stream[..offset].to_vec();
            rebuilt.extend_from_slice(&encode_skippable_toc_frame(&sealed));
            rebuilt
        };

        // Rebuild the stream with a TOC that claims one frame too few.
        let mut short = layer.toc.clone();
        short.chunks.pop();
        assert!(matches!(
            decode(&rebuild(&short), &sealer),
            Err(StreamError::TocFrameCount { .. })
        ));

        // And one that claims a different sealed length for a frame it does list.
        let mut lying = layer.toc.clone();
        lying.chunks[0].raw_length += 1;
        assert!(matches!(
            decode(&rebuild(&lying), &sealer),
            Err(StreamError::TocLengthMismatch { index: 0, .. })
        ));
    }

    /// The old format put the table of contents in the skippable frame in the clear. It is
    /// not read: the decoder unseals that payload, so a plaintext one fails at the seal.
    #[test]
    fn a_stream_with_a_plaintext_table_of_contents_is_refused() {
        let sealer = golden_sealer();
        let (stream, layer) = encode(b"a body".repeat(2000).as_slice(), &sealer);
        let offset = usize::try_from(layer.toc_offset).expect("offset");
        let mut old_format = stream[..offset].to_vec();
        old_format.extend_from_slice(&encode_skippable_toc_frame(
            &layer.toc.encode().expect("toc"),
        ));
        assert!(
            matches!(decode(&old_format, &sealer), Err(StreamError::Seal(_))),
            "a table of contents in the clear must not be read"
        );
    }

    #[test]
    fn bytes_after_the_table_of_contents_are_refused() {
        let sealer = golden_sealer();
        let (mut stream, _) = encode(b"a body".repeat(2000).as_slice(), &sealer);
        stream.extend_from_slice(b"spliced");
        assert!(matches!(
            decode(&stream, &sealer),
            Err(StreamError::TrailingBytes(7))
        ));
    }

    #[test]
    fn bytes_that_are_not_this_codecs_output_are_refused() {
        let sealer = golden_sealer();
        assert!(matches!(
            decode(b"not a zstd frame at all", &sealer),
            Err(StreamError::BadFrameMagic { index: 0 })
        ));
        // A stock zstd frame is a valid zstd frame and still not our layout.
        let compressed = zstd::bulk::compress(&[0x5Au8; 4096], 3).expect("compress");
        assert!(matches!(
            decode(&compressed, &sealer),
            Err(StreamError::BadFrameLayout { index: 0 })
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::app::{
        CHUNKED_TOC_DIGEST_ANNOTATION, CHUNKED_TOC_OFFSET_ANNOTATION, CHUNKED_VERSION_ANNOTATION,
    };
    use crate::chunked::locate_and_verify_toc;
    use crate::persist::seal::{DATA_KEY_LEN, DataKey};

    const MIB: usize = 1024 * 1024;

    /// Narrows a wire offset for slicing in tests (the suite runs on 64-bit hosts).
    fn at(offset: u64) -> usize {
        usize::try_from(offset).expect("offset fits a 64-bit usize")
    }

    fn sealer(seed: u8) -> Sealer {
        Sealer::new(&DataKey::new([seed; DATA_KEY_LEN]))
    }

    /// Deterministic pseudo-random bytes (xorshift64*), so a failure reproduces exactly.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Incompressible and highly compressible regions alternating, so both the compressed
    /// and the plaintext seal paths run in one stream.
    fn mixed_input(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut round = 0u64;
        while out.len() < len {
            out.extend_from_slice(&pseudo_random(3 * MIB, seed + round));
            out.resize((out.len() + 5 * MIB).min(len.max(out.len() + 1)), b'x');
            round += 1;
        }
        out.truncate(len);
        out
    }

    fn encode(input: &[u8], sealer: &Sealer) -> (Vec<u8>, SealedLayer) {
        let mut wire = Vec::new();
        let layer = encode_sealed_stream(input, sealer, &mut |bytes| {
            wire.extend_from_slice(bytes);
            Ok(())
        })
        .expect("encode");
        (wire, layer)
    }

    fn decode(wire: &[u8], layer: &SealedLayer, sealer: &Sealer) -> Result<Vec<u8>, StreamError> {
        let mut out = Vec::new();
        decode_sealed_stream(wire, &layer.toc, sealer, &mut out)?;
        Ok(out)
    }

    #[test]
    fn round_trips_a_mixed_multi_mib_input() {
        let sealer = sealer(11);
        let input = mixed_input(24 * MIB, 0x5eed);
        let (wire, layer) = encode(&input, &sealer);

        assert_eq!(layer.raw_total, input.len() as u64);
        assert!(layer.toc.chunks.len() > 2, "expected several chunks");
        assert_eq!(decode(&wire, &layer, &sealer).expect("decode"), input);
    }

    #[test]
    fn an_empty_input_yields_an_empty_layer() {
        let sealer = sealer(11);
        let (wire, layer) = encode(&[], &sealer);
        assert!(layer.toc.chunks.is_empty());
        assert_eq!(layer.raw_total, 0);
        assert_eq!(layer.toc_offset, 0);
        assert_eq!(wire.len() as u64, layer.toc_frame_length);
        assert!(decode(&wire, &layer, &sealer).expect("decode").is_empty());
    }

    /// The stream is still a well-formed spec-146 layer — the frame region tiles exactly
    /// and the skippable TOC frame is the last thing in it — but its table of contents is
    /// sealed, so a reader without the key cannot recover it. A plain spec-146 reader is
    /// exactly that reader.
    ///
    /// Sealed appdata layers never publish the `CHUNKED_TOC_*` annotations, so nothing in
    /// production takes this path; the annotations are synthesised here to stand in for a
    /// reader that has everything except the key.
    #[test]
    fn the_table_of_contents_is_sealed_against_a_keyless_reader() {
        let sealer = sealer(4);
        let input = mixed_input(20 * MIB, 0xabc);
        let (wire, layer) = encode(&input, &sealer);

        // The frame region tiles exactly — what the registry re-checks on ingest.
        assert_eq!(
            layer.toc.validate_tiling(layer.toc_offset).expect("tiling"),
            layer.total_length
        );

        // The skippable TOC frame is the final frame, and `toc_digest` covers the bytes it
        // actually carries.
        let frame = &wire[at(layer.toc_offset)..];
        assert_eq!(frame.len() as u64, layer.toc_frame_length);
        assert_eq!(
            u32::from_le_bytes(frame[..4].try_into().expect("magic")),
            SKIPPABLE_MAGIC
        );
        let declared = u32::from_le_bytes(frame[4..8].try_into().expect("length")) as usize;
        assert_eq!(declared, frame.len() - 8);
        assert_eq!(digest_bytes(&frame[8..]), layer.toc_digest);

        // And the payload is a seal, not a TOC: a reader without the key gets nothing.
        let annotations = std::collections::BTreeMap::from([
            (
                CHUNKED_TOC_OFFSET_ANNOTATION.to_owned(),
                layer.toc_offset.to_string(),
            ),
            (
                CHUNKED_TOC_DIGEST_ANNOTATION.to_owned(),
                layer.toc_digest.clone(),
            ),
            (
                CHUNKED_VERSION_ANNOTATION.to_owned(),
                FORMAT_VERSION.to_string(),
            ),
        ]);
        assert!(
            locate_and_verify_toc(&wire, &annotations).is_err(),
            "a keyless reader must not recover the chunk-length sequence"
        );
    }

    #[test]
    fn the_frame_region_decodes_to_the_sealed_payloads() {
        let sealer = sealer(6);
        let input = mixed_input(20 * MIB, 0xfeed);
        let (wire, layer) = encode(&input, &sealer);

        // A plain spec-146 reader — one that knows nothing about sealing — recovers the
        // sealed payloads and nothing else.
        let region = &wire[..at(layer.toc_offset)];
        let mut payloads = Vec::new();
        let mut decoder = zstd::stream::read::Decoder::new(region).expect("decoder");
        decoder.read_to_end(&mut payloads).expect("decode region");
        assert_eq!(payloads.len() as u64, layer.total_length);

        let mut cursor = 0usize;
        let mut plaintext = Vec::new();
        let mut compressed_chunks = 0;
        for chunk in &layer.toc.chunks {
            assert!(!chunk.compressed, "frames carry sealed bytes verbatim");
            let sealed = &payloads[cursor..cursor + chunk.raw_length as usize];
            let (payload, was_compressed) = sealer.open(SealContext::Frame, sealed).expect("open");
            if was_compressed {
                compressed_chunks += 1;
                plaintext
                    .extend_from_slice(&zstd::bulk::decompress(&payload, MAX_CHUNK_RAW).unwrap());
            } else {
                plaintext.extend_from_slice(&payload);
            }
            cursor += chunk.raw_length as usize;
        }
        assert_eq!(plaintext, input);
        assert!(
            compressed_chunks > 0,
            "the compressible regions must seal compressed"
        );
    }

    #[test]
    fn the_layer_digest_is_the_sha256_of_the_wire_stream() {
        let sealer = sealer(2);
        let (wire, layer) = encode(&mixed_input(12 * MIB, 7), &sealer);
        assert_eq!(layer.layer_digest, digest_bytes(&wire));
    }

    #[test]
    fn a_one_byte_insertion_changes_at_most_three_cids() {
        let sealer = sealer(8);
        let input = pseudo_random(24 * MIB, 0x00c0_ffee);
        let mut edited = input.clone();
        edited.insert(input.len() / 2, 0x42);

        let (_, before) = encode(&input, &sealer);
        let (_, after) = encode(&edited, &sealer);

        let known: HashSet<[u8; 32]> = before.toc.chunks.iter().map(|c| c.frame_cid).collect();
        let fresh = after
            .toc
            .chunks
            .iter()
            .filter(|chunk| !known.contains(&chunk.frame_cid))
            .count();
        assert!(
            fresh <= 3,
            "a 1-byte insertion re-uploaded {fresh} of {} chunks",
            after.toc.chunks.len()
        );
    }

    #[test]
    fn every_frame_stays_within_the_spec_146_caps() {
        let sealer = sealer(3);
        // Incompressible input: every chunk seals to its plaintext length plus the
        // envelope, which is where the `raw_length` cap is closest.
        let (_, layer) = encode(&pseudo_random(64 * MIB, 0xdad), &sealer);
        for chunk in &layer.toc.chunks {
            assert!(
                chunk.raw_length as usize <= MAX_CHUNK_RAW,
                "raw_length {} exceeds the 12 MiB cap",
                chunk.raw_length
            );
            assert!(chunk.frame_length <= MAX_SEALED_FRAME);
            assert!(u64::from(chunk.raw_length) <= chunk.frame_length);
        }
        assert!(
            layer
                .toc
                .chunks
                .iter()
                .any(|chunk| u64::from(chunk.raw_length) > u64::from(FASTCDC_AVG)),
            "expected at least one chunk well above the average size"
        );
    }

    #[test]
    fn encoding_streams_without_buffering_the_layer() {
        struct Counting<'a> {
            inner: &'a [u8],
            read: &'a std::cell::Cell<u64>,
        }
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let read = self.inner.read(buf)?;
                self.read.set(self.read.get() + read as u64);
                Ok(read)
            }
        }

        let sealer = sealer(5);
        let input = pseudo_random(64 * MIB, 0x1234);
        let read = std::cell::Cell::new(0u64);
        let source = Counting {
            inner: &input,
            read: &read,
        };

        // Read-ahead must stay bounded by the chunker's buffer plus the chunks already
        // emitted — never by the length of the input. A whole-buffer encoder would have
        // read all 64 MiB before the first frame reached the sink.
        let mut frames = 0u64;
        let mut emitted = 0u64;
        let layer = encode_sealed_stream(source, &sealer, &mut |bytes| {
            frames += 1;
            emitted += bytes.len() as u64;
            let bound = (frames + 1) * u64::from(SEALED_FASTCDC_MAX);
            assert!(
                read.get() <= bound,
                "read {} bytes before emitting frame {frames} (bound {bound})",
                read.get()
            );
            assert!(
                bytes.len() as u64 <= MAX_SEALED_FRAME,
                "a single sink call must never exceed one frame"
            );
            Ok(())
        })
        .expect("encode");
        assert_eq!(emitted, layer.toc_offset + layer.toc_frame_length);
        assert!(frames > 4, "expected many frames, saw {frames}");
    }

    #[test]
    fn recipe_entries_cover_the_whole_blob() {
        let sealer = sealer(9);
        let (wire, layer) = encode(&mixed_input(16 * MIB, 0x99), &sealer);

        let entries = layer.recipe_entries();
        assert_eq!(entries.len(), layer.toc.chunks.len() + 1);
        let mut cursor = 0u64;
        for entry in &entries {
            assert_eq!(entry.frame_offset, cursor);
            assert!(!entry.compressed);
            let frame = &wire[at(cursor)..at(cursor + entry.frame_length)];
            assert_eq!(entry.frame_cid, hex(&frame_cid(frame)));
            cursor += entry.frame_length;
        }
        assert_eq!(cursor, wire.len() as u64);
        let toc_entry = entries.last().expect("toc entry");
        assert_eq!(toc_entry.raw_length, 0, "the TOC frame carries no payload");
        assert_eq!(toc_entry.frame_offset, layer.toc_offset);
        assert_eq!(
            entries.iter().map(|entry| entry.raw_length).sum::<u64>(),
            layer.total_length
        );
    }

    #[test]
    fn the_decoder_rejects_a_swapped_frame() {
        let sealer = sealer(1);
        let (wire, layer) = encode(&mixed_input(20 * MIB, 0x77), &sealer);
        assert!(layer.toc.chunks.len() >= 2);

        // Rebuild the stream with the first two frames exchanged.
        let first = &layer.toc.chunks[0];
        let second = &layer.toc.chunks[1];
        let mut swapped = Vec::with_capacity(wire.len());
        swapped.extend_from_slice(
            &wire[at(second.frame_offset)..at(second.frame_offset + second.frame_length)],
        );
        swapped.extend_from_slice(&wire[..at(first.frame_length)]);
        swapped.extend_from_slice(&wire[at(second.frame_offset + second.frame_length)..]);

        assert!(matches!(
            decode(&swapped, &layer, &sealer),
            Err(StreamError::CidMismatch { index: 0 })
        ));
    }

    #[test]
    fn the_decoder_rejects_a_tampered_frame() {
        let sealer = sealer(1);
        let (mut wire, layer) = encode(&mixed_input(12 * MIB, 0x21), &sealer);
        let target = at(layer.toc.chunks[0].frame_offset) + 32;
        wire[target] ^= 0x01;
        assert!(matches!(
            decode(&wire, &layer, &sealer),
            Err(StreamError::CidMismatch { index: 0 })
        ));
    }

    #[test]
    fn the_decoder_rejects_a_truncated_stream() {
        let sealer = sealer(1);
        let (wire, layer) = encode(&mixed_input(12 * MIB, 0x22), &sealer);
        let last = layer.toc.chunks.last().expect("a chunk");
        let cut = at(last.frame_offset + last.frame_length / 2);
        let index = layer.toc.chunks.len() - 1;
        assert!(matches!(
            decode(&wire[..cut], &layer, &sealer),
            Err(StreamError::TruncatedFrame { index: got }) if got == index
        ));
    }

    #[test]
    fn the_decoder_rejects_a_toc_that_lies_about_a_cid() {
        let sealer = sealer(1);
        let (wire, mut layer) = encode(&mixed_input(12 * MIB, 0x23), &sealer);
        layer.toc.chunks[0].frame_cid = [0u8; 32];
        assert!(matches!(
            decode(&wire, &layer, &sealer),
            Err(StreamError::CidMismatch { index: 0 })
        ));
    }

    #[test]
    fn the_decoder_rejects_a_toc_that_lies_about_the_tiling() {
        let sealer = sealer(1);
        let (wire, mut layer) = encode(&mixed_input(12 * MIB, 0x24), &sealer);
        layer.toc.chunks[0].frame_offset += 1;
        assert!(matches!(
            decode(&wire, &layer, &sealer),
            Err(StreamError::BadTiling { index: 0 })
        ));
    }

    #[test]
    fn the_decoder_rejects_a_toc_that_lies_about_a_raw_length() {
        let sealer = sealer(1);
        let (wire, mut layer) = encode(&mixed_input(12 * MIB, 0x25), &sealer);
        layer.toc.chunks[0].raw_length -= 1;
        assert!(matches!(
            decode(&wire, &layer, &sealer),
            Err(StreamError::SealedSizeMismatch { index: 0, .. })
        ));
    }

    #[test]
    fn the_decoder_rejects_an_oversized_frame_declaration() {
        let sealer = sealer(1);
        let (wire, mut layer) = encode(&mixed_input(12 * MIB, 0x26), &sealer);
        layer.toc.chunks[0].frame_length = MAX_SEALED_FRAME + 1;
        assert!(matches!(
            decode(&wire, &layer, &sealer),
            Err(StreamError::FrameTooLarge { index: 0, .. })
        ));
    }

    #[test]
    fn the_decoder_rejects_the_wrong_key() {
        let (wire, layer) = encode(&mixed_input(12 * MIB, 0x27), &sealer(1));
        assert!(matches!(
            decode(&wire, &layer, &sealer(2)),
            Err(StreamError::Seal(SealError::Unauthentic))
        ));
    }

    #[test]
    fn the_decoder_rejects_an_unsupported_toc_version() {
        let sealer = sealer(1);
        let (wire, mut layer) = encode(b"", &sealer);
        layer.toc.format_version = FORMAT_VERSION + 1;
        assert!(matches!(
            decode(&wire, &layer, &sealer),
            Err(StreamError::Chunked(ChunkedError::UnsupportedVersion(_)))
        ));
    }
}
