//! Convergent sealing for App-data chunks: AES-256-GCM under a per-pool data key with a
//! nonce derived from the payload, so equal payloads under the same key seal to identical
//! bytes.
//!
//! The store only ever holds sealed bytes — at-rest encryption is a property of the data,
//! not of any disk — and the frame content id is taken over those sealed bytes, so dedup
//! works without the store ever seeing plaintext.
//!
//! # Wire format (version 2, byte-exact)
//!
//! ```text
//! version     u8        always 2
//! context     u8        0 = payload frame, 1 = table of contents
//! nonce       [u8; 12]  first 12 bytes of blake3::keyed_hash(nonce subkey, aad || plaintext)
//! ciphertext  [..]      AES-256-GCM ciphertext of `flags || payload`
//! tag         [u8; 16]  the GCM authentication tag (appended by the AEAD)
//! ```
//!
//! The two header bytes (`version || context`) are the AEAD's associated data, so a flipped
//! version or context byte fails the tag check rather than silently changing how the
//! payload is interpreted, and a table of contents can never be opened as a frame or the
//! reverse. Everything else is sealed: the plaintext is a flags byte (bit 0 = the payload is
//! a zstd frame of the source chunk; bits 1-7 reserved, MUST be 0) followed by the payload,
//! so how well a chunk compressed is not visible to a party holding only ciphertext. Total
//! overhead is [`SEAL_OVERHEAD`] (31) bytes.
//!
//! Version 1 carried the flags byte in the clear and is not read. Nothing in production ever
//! wrote it, so there is no compatibility path — a version byte of 1 is a refusal.
//!
//! # Keys
//!
//! One 32-byte [`DataKey`] per key domain (a pool by default) derives two independent
//! subkeys through `blake3::derive_key` with fixed context strings — the AES key and the
//! nonce-derivation key. The context strings are part of the format: changing one changes
//! every cid, so they carry an explicit `v1`.
//!
//! # The accepted trade
//!
//! Because the nonce is derived from the payload, sealing is *convergent*: equal payloads
//! under the same key produce identical sealed bytes and therefore identical cids. That is
//! what makes dedup survive encryption — across restore points, files, and apps sharing the
//! key. The cost is the standard keyed-content-id trade of kopia/restic: a party holding
//! ciphertext can test whether a *guessed* plaintext is present within one key domain. It
//! cannot recover unknown plaintext. Accepted deliberately; key scope is dedup scope, and
//! rotation severs both by construction.
//!
//! The same reasoning reaches inside the pool. Every node of a pool holds the same key
//! domain and cids are convergent, so any node can test a guessed plaintext against another
//! node's data for the same app. That is the same trade in a different hat, and it is
//! accepted for the same reason: a pool is one blast radius, and the alternative is one key
//! per node, which is one dedup domain per node.
//!
//! The nonce is 96 bits and derived rather than counted, so distinct payloads collide with
//! birthday probability: risk becomes non-negligible somewhere around 2^32 distinct frames
//! sealed under one key — roughly four billion — which is the practical ceiling on how long
//! a key domain should live. Rotation is what stays under it.
//!
//! Rotation appends a key; it never re-seals. Layers already written keep the key that
//! sealed them, so rotating bounds *future* dedup and future exposure and retroactively
//! protects nothing. A key believed compromised means the data it sealed is compromised.
//!
//! Nonce reuse is safe here by the same argument: the (key, nonce) pair only ever repeats
//! for identical sealed input, so the keystream is only ever applied to the same bytes. The
//! nonce commits to the associated data and to the whole sealed plaintext — version,
//! context, flags, and payload — so a frame and a table of contents never share one, and
//! neither do the same bytes sealed compressed and uncompressed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit as _, Nonce};

use crate::error::CliError;

/// Sealed-payload format version, and the only one this code reads.
pub const SEAL_VERSION: u8 = 2;

/// Nonce length (AES-GCM standard 96-bit nonce).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// Header length: `version || context || nonce`. The only bytes not under the AEAD.
const HEADER_LEN: usize = 2 + NONCE_LEN;

/// Length of the flags byte, which is sealed *inside* the ciphertext.
const FLAGS_LEN: usize = 1;

/// Bytes a seal adds to its payload: the header, the sealed flags byte, and the AEAD tag.
pub const SEAL_OVERHEAD: usize = HEADER_LEN + FLAGS_LEN + TAG_LEN;

/// Length of a data key in bytes.
pub const DATA_KEY_LEN: usize = 32;

/// `flags` bit 0: the sealed payload is a zstd frame of the source chunk.
const FLAG_COMPRESSED: u8 = 0b1;

/// Every flag bit this version defines; any other bit set is a refusal.
const KNOWN_FLAGS: u8 = FLAG_COMPRESSED;

/// `blake3::derive_key` context for the AES-256-GCM key. Part of the wire format.
const SEAL_KEY_CONTEXT: &str = "orc8r appdata seal v1";

/// `blake3::derive_key` context for the nonce-derivation key. Part of the wire format.
const NONCE_KEY_CONTEXT: &str = "orc8r appdata nonce v1";

/// What a sealed payload is. Bound into the AEAD's associated data, so a table of
/// contents can never be opened as a frame or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealContext {
    /// One chunk of the plaintext stream, carried by a payload frame.
    Frame,
    /// The stream's table of contents, carried by the trailing skippable frame.
    Toc,
}

impl SealContext {
    /// The wire byte for this context.
    #[must_use]
    const fn byte(self) -> u8 {
        match self {
            Self::Frame => 0,
            Self::Toc => 1,
        }
    }
}

/// Errors from sealing or opening a payload. A wrong key, a tampered byte, and a truncated
/// payload are all typed refusals — never a panic, and never a message carrying key or
/// plaintext material.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("sealed payload is shorter than the {SEAL_OVERHEAD}-byte envelope")]
    Truncated,
    #[error("sealed payload version {0} is unsupported (expected {SEAL_VERSION})")]
    UnsupportedVersion(u8),
    #[error("sealed payload is context {found}, the reader asked for context {expected}")]
    WrongContext { expected: u8, found: u8 },
    #[error("sealed payload sets reserved flag bits ({0:#04x})")]
    UnknownFlags(u8),
    #[error("sealed payload failed authentication (wrong key or tampered bytes)")]
    Unauthentic,
    #[error("sealing the payload failed")]
    SealFailed,
    #[error("data key must be {DATA_KEY_LEN} bytes")]
    BadKeyLength,
}

impl From<SealError> for CliError {
    fn from(err: SealError) -> Self {
        CliError::Operational(err.to_string())
    }
}

/// A 32-byte App-data key: the root of one dedup/isolation domain.
///
/// `Debug` never renders the bytes, and `Drop` overwrites them — best effort, since without
/// a `zeroize` dependency in this workspace nothing stops the optimiser from having left a
/// copy elsewhere.
pub struct DataKey([u8; DATA_KEY_LEN]);

impl DataKey {
    /// Wraps raw key bytes (as minted by the pool's sealed secret).
    #[must_use]
    pub const fn new(bytes: [u8; DATA_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Wraps key bytes delivered as a slice (the `GetSecret` grant path).
    ///
    /// # Errors
    ///
    /// Returns [`SealError::BadKeyLength`] unless the slice is exactly
    /// [`DATA_KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        let bytes: [u8; DATA_KEY_LEN] = bytes.try_into().map_err(|_| SealError::BadKeyLength)?;
        Ok(Self(bytes))
    }

    /// The raw key material. Private to this module's own derivations — nothing
    /// outside sealing and [`key_id`] has any business reading it.
    const fn raw(&self) -> &[u8; DATA_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(redacted)")
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Seals and opens payloads under one [`DataKey`].
pub struct Sealer {
    cipher: Aes256Gcm,
    nonce_key: DataKey,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer(redacted)")
    }
}

impl Sealer {
    /// Derives the AES and nonce subkeys from `key`.
    #[must_use]
    pub fn new(key: &DataKey) -> Self {
        let seal_key = blake3::derive_key(SEAL_KEY_CONTEXT, &key.0);
        let nonce_key = DataKey::new(blake3::derive_key(NONCE_KEY_CONTEXT, &key.0));
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&seal_key));
        Self { cipher, nonce_key }
    }

    /// Seals `payload` under `context`, recording in the sealed flags whether it is a zstd
    /// frame of the source chunk. Deterministic: the same `(key, context, payload,
    /// compressed)` always produces the same bytes, which is what keeps dedup working.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::SealFailed`] if the AEAD refuses the payload (only reachable
    /// at sizes far beyond a chunk).
    pub fn seal(
        &self,
        context: SealContext,
        payload: &[u8],
        compressed: bool,
    ) -> Result<Vec<u8>, SealError> {
        let flags = if compressed { FLAG_COMPRESSED } else { 0 };
        self.seal_with_flags(context, flags, payload)
    }

    /// The sealing body, with the flags byte given rather than derived. Only the tests
    /// reach for a flags byte the encoder would never write.
    fn seal_with_flags(
        &self,
        context: SealContext,
        flags: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let aad = [SEAL_VERSION, context.byte()];
        let mut plaintext = Vec::with_capacity(FLAGS_LEN + payload.len());
        plaintext.push(flags);
        plaintext.extend_from_slice(payload);
        // The nonce commits to everything sealed — the header bytes and the whole plaintext
        // — so distinct inputs get distinct nonces while equal ones still converge.
        let mut nonce_input = Vec::with_capacity(aad.len() + plaintext.len());
        nonce_input.extend_from_slice(&aad);
        nonce_input.extend_from_slice(&plaintext);
        let nonce = blake3::keyed_hash(&self.nonce_key.0, &nonce_input);
        let nonce = &nonce.as_bytes()[..NONCE_LEN];
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::SealFailed)?;
        let mut out = Vec::with_capacity(SEAL_OVERHEAD + payload.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a sealed payload sealed under `context`, returning it with the compression
    /// flag it was sealed with. The tag check is the AEAD's own constant-time comparison,
    /// and the flags byte is read only after it passes — it is authenticated plaintext, not
    /// a header a stranger can set.
    ///
    /// The nonce is taken from the wire rather than re-derived: convergence is an encoder
    /// obligation, and a sealed payload is authenticated by its tag either way.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Truncated`], [`SealError::UnsupportedVersion`],
    /// [`SealError::WrongContext`], [`SealError::UnknownFlags`], or
    /// [`SealError::Unauthentic`] — the last covering a wrong key and any tampered byte
    /// alike.
    pub fn open(&self, context: SealContext, sealed: &[u8]) -> Result<(Vec<u8>, bool), SealError> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(SealError::Truncated);
        }
        let version = sealed[0];
        if version != SEAL_VERSION {
            return Err(SealError::UnsupportedVersion(version));
        }
        // The AAD would refuse a mismatched context anyway, but as `Unauthentic` — which
        // reads as a wrong key and sends a `KeyRing` round every key it holds. Name it.
        let expected = context.byte();
        let found = sealed[1];
        if found != expected {
            return Err(SealError::WrongContext { expected, found });
        }
        let aad = [version, found];
        let mut plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&sealed[2..HEADER_LEN]),
                Payload {
                    msg: &sealed[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Unauthentic)?;
        let Some(&flags) = plaintext.first() else {
            return Err(SealError::Truncated);
        };
        if flags & !KNOWN_FLAGS != 0 {
            return Err(SealError::UnknownFlags(flags));
        }
        plaintext.drain(..FLAGS_LEN);
        Ok((plaintext, flags & FLAG_COMPRESSED != 0))
    }
}

/// `blake3::derive_key` context for the public id of a data key. This identifier is part
/// of the restore-point wire format.
const KEY_ID_CONTEXT: &str = "orc8r appdata key id v1";

/// Public, non-secret id of a data key: hex of the first 8 bytes of a key derived from
/// it under [`KEY_ID_CONTEXT`].
///
/// Derived rather than truncated so the id reveals nothing about the key itself, and
/// defined here so every producer and consumer computes it the same way. Safe to log.
#[must_use]
pub fn key_id(key: &DataKey) -> String {
    use std::fmt::Write as _;
    let derived = blake3::derive_key(KEY_ID_CONTEXT, key.raw());
    derived[..8]
        .iter()
        .fold(String::with_capacity(16), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Opens a sealed payload. Implemented by a single [`Sealer`] and by a whole
/// [`KeyRing`], so the streaming decoder does not care whether its caller holds one key
/// or the pool's entire history of them.
pub trait Opener: Send + Sync {
    /// Opens `sealed`, which must have been sealed under `context`, returning the payload
    /// and whether it is a zstd frame.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Unauthentic`] when no key this opener holds authenticates
    /// the payload, and the envelope errors for a malformed one.
    fn open(&self, context: SealContext, sealed: &[u8]) -> Result<(Vec<u8>, bool), SealError>;
}

impl Opener for Sealer {
    fn open(&self, context: SealContext, sealed: &[u8]) -> Result<(Vec<u8>, bool), SealError> {
        Sealer::open(self, context, sealed)
    }
}

/// Every key a pool holds, in the order they are tried.
///
/// A restore point records the key it was sealed under, but that covers only the layers
/// the point itself wrote: a layer carried forward from an earlier point keeps the key
/// that sealed it back then, and rotation never rewrites bytes. So a point committed
/// after a rotation legitimately mixes layers from two keys, and nothing in the point
/// says which layer belongs to which. The ring is what makes that a non-event — the
/// point's own key is tried first and the rest follow, and the AEAD tag is what decides:
/// a wrong key fails fast and cannot produce plausible plaintext.
///
/// Order is a performance detail only. The ring remembers which key last worked, so a
/// long ring costs one extra attempt per layer rather than one per frame.
pub struct KeyRing {
    sealers: Vec<(String, Arc<Sealer>)>,
    /// Index of the key that last opened something. A hint, never a correctness input.
    hint: AtomicUsize,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field(
                "keys",
                &self.sealers.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl KeyRing {
    /// A ring over `sealers`, `(key id, sealer)`, in the order they are tried.
    #[must_use]
    pub fn new(sealers: Vec<(String, Arc<Sealer>)>) -> Self {
        Self {
            sealers,
            hint: AtomicUsize::new(0),
        }
    }

    /// A ring holding one key, for a caller that only ever had one.
    #[must_use]
    pub fn single(id: impl Into<String>, sealer: Arc<Sealer>) -> Self {
        Self::new(vec![(id.into(), sealer)])
    }

    /// The same keys with `key_id` first: what a restore point's own key gets, so the
    /// first attempt is the one that opens everything the point itself wrote.
    #[must_use]
    pub fn preferring(&self, key_id: &str) -> Self {
        let mut sealers = Vec::with_capacity(self.sealers.len());
        let (preferred, rest): (Vec<_>, Vec<_>) =
            self.sealers.iter().partition(|(id, _)| id == key_id);
        for (id, sealer) in preferred.into_iter().chain(rest) {
            sealers.push((id.clone(), Arc::clone(sealer)));
        }
        Self::new(sealers)
    }

    /// Whether the ring holds a key with this id.
    #[must_use]
    pub fn holds(&self, key_id: &str) -> bool {
        self.sealers.iter().any(|(id, _)| id == key_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sealers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sealers.is_empty()
    }

    /// The ids in the ring, in the order they are tried. Safe to log.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.sealers.iter().map(|(id, _)| id.as_str())
    }
}

impl Opener for KeyRing {
    fn open(&self, context: SealContext, sealed: &[u8]) -> Result<(Vec<u8>, bool), SealError> {
        if self.sealers.is_empty() {
            return Err(SealError::Unauthentic);
        }
        let start = self
            .hint
            .load(Ordering::Relaxed)
            .min(self.sealers.len() - 1);
        for step in 0..self.sealers.len() {
            let index = (start + step) % self.sealers.len();
            match self.sealers[index].1.open(context, sealed) {
                Ok(opened) => {
                    if step != 0 {
                        self.hint.store(index, Ordering::Relaxed);
                    }
                    return Ok(opened);
                }
                // A malformed envelope — a bad version, the wrong context — is not a wrong
                // key: no other key would read it either, so it is reported as it is
                // rather than retried round the whole ring.
                Err(SealError::Unauthentic) => {}
                Err(err) => return Err(err),
            }
        }
        Err(SealError::Unauthentic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> DataKey {
        DataKey::new([seed; DATA_KEY_LEN])
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// The id is a derivation, not a prefix of the key, and it is stable: every producer
    /// and consumer computes the same 16 hex characters for the same key.
    #[test]
    fn key_id_is_stable_derived_and_not_the_key() {
        let first = key(7);
        let id = key_id(&first);
        assert_eq!(id.len(), 16);
        assert_eq!(id, key_id(&DataKey::new([7; DATA_KEY_LEN])));
        assert_ne!(id, key_id(&key(8)));
        assert!(!hex(&[7; DATA_KEY_LEN]).starts_with(&id));
    }

    #[test]
    fn round_trips_a_payload() {
        let sealer = Sealer::new(&key(7));
        let payload = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let sealed = sealer
            .seal(SealContext::Frame, &payload, false)
            .expect("seal");
        assert_eq!(sealed.len(), payload.len() + SEAL_OVERHEAD);
        let (opened, compressed) = sealer.open(SealContext::Frame, &sealed).expect("open");
        assert_eq!(opened, payload);
        assert!(!compressed);
    }

    /// The envelope is exactly the header, the sealed flags byte, and the tag — 31 bytes,
    /// and the whole streaming codec's frame-size arithmetic leans on that number.
    #[test]
    fn the_seal_overhead_is_thirty_one_bytes() {
        assert_eq!(SEAL_OVERHEAD, 31);
        let sealer = Sealer::new(&key(7));
        let payload = [0x5Au8; 1000];
        for context in [SealContext::Frame, SealContext::Toc] {
            for compressed in [false, true] {
                let sealed = sealer.seal(context, &payload, compressed).expect("seal");
                assert_eq!(sealed.len() - payload.len(), SEAL_OVERHEAD);
            }
        }
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let sealer = Sealer::new(&key(7));
        let sealed = sealer.seal(SealContext::Frame, &[], false).expect("seal");
        assert_eq!(sealed.len(), SEAL_OVERHEAD);
        assert_eq!(
            sealer.open(SealContext::Frame, &sealed).expect("open"),
            (Vec::new(), false)
        );
    }

    #[test]
    fn compression_flag_round_trips() {
        let sealer = Sealer::new(&key(3));
        let sealed = sealer
            .seal(SealContext::Frame, b"payload", true)
            .expect("seal");
        // The header carries the context, never the flags.
        assert_eq!(sealed[1], SealContext::Frame.byte());
        let (opened, compressed) = sealer.open(SealContext::Frame, &sealed).expect("open");
        assert_eq!(opened, b"payload");
        assert!(compressed);
    }

    /// The whole point of version 2: a party holding ciphertext cannot see whether a chunk
    /// compressed. Only the version and context bytes are in the clear, and the nonce
    /// commits to the flags, so the two seals differ throughout.
    #[test]
    fn the_compression_flag_is_not_visible_in_the_clear() {
        let sealer = Sealer::new(&key(3));
        let payload = b"the same bytes, sealed twice";
        let plain = sealer
            .seal(SealContext::Frame, payload, false)
            .expect("seal");
        let marked = sealer
            .seal(SealContext::Frame, payload, true)
            .expect("seal");

        assert_eq!(plain.len(), marked.len());
        assert_eq!(
            &plain[..2],
            &marked[..2],
            "only the version and context bytes are outside the seal"
        );
        assert_ne!(
            plain[2..HEADER_LEN],
            marked[2..HEADER_LEN],
            "the nonce commits to the flags byte"
        );
        assert_ne!(plain[HEADER_LEN..], marked[HEADER_LEN..]);
        // No single byte position is the flag: the two seals differ all over, not in one
        // bit of one byte the way a cleartext flags byte would.
        let differing = plain
            .iter()
            .zip(&marked)
            .filter(|(left, right)| left != right)
            .count();
        assert!(
            differing > 1,
            "a cleartext flag would show up as exactly one differing byte"
        );
    }

    #[test]
    fn equal_payloads_seal_identically() {
        let sealer = Sealer::new(&key(1));
        let a = sealer
            .seal(SealContext::Frame, b"convergent", false)
            .expect("seal");
        let b = sealer
            .seal(SealContext::Frame, b"convergent", false)
            .expect("seal");
        assert_eq!(a, b, "convergent sealing must be byte-identical");
    }

    #[test]
    fn a_different_key_seals_differently() {
        let a = Sealer::new(&key(1))
            .seal(SealContext::Frame, b"convergent", false)
            .expect("seal");
        let b = Sealer::new(&key(2))
            .seal(SealContext::Frame, b"convergent", false)
            .expect("seal");
        assert_ne!(a, b);
        // Distinct key domains must not even share a nonce.
        assert_ne!(a[2..HEADER_LEN], b[2..HEADER_LEN]);
    }

    #[test]
    fn a_different_payload_derives_a_different_nonce() {
        let sealer = Sealer::new(&key(1));
        let a = sealer
            .seal(SealContext::Frame, b"payload a", false)
            .expect("seal");
        let b = sealer
            .seal(SealContext::Frame, b"payload b", false)
            .expect("seal");
        assert_ne!(a[2..HEADER_LEN], b[2..HEADER_LEN]);
    }

    /// A frame and a table of contents are different things sealed under the same key, and
    /// neither may be read as the other — named plainly rather than as a wrong key, so a
    /// `KeyRing` refuses immediately instead of walking every key it holds.
    #[test]
    fn a_seal_cannot_be_opened_under_the_other_context() {
        let sealer = Sealer::new(&key(4));
        let frame = sealer
            .seal(SealContext::Frame, b"a chunk", false)
            .expect("seal");
        let toc = sealer
            .seal(SealContext::Toc, b"a chunk", false)
            .expect("seal");
        assert_ne!(frame, toc, "the context must reach the sealed bytes");

        assert!(matches!(
            sealer.open(SealContext::Toc, &frame),
            Err(SealError::WrongContext {
                expected: 1,
                found: 0
            })
        ));
        assert!(matches!(
            sealer.open(SealContext::Frame, &toc),
            Err(SealError::WrongContext {
                expected: 0,
                found: 1
            })
        ));
        // And a ring refuses on the spot rather than trying every key.
        let ring = KeyRing::single("k", Arc::new(Sealer::new(&key(4))));
        assert!(matches!(
            ring.open(SealContext::Toc, &frame),
            Err(SealError::WrongContext { .. })
        ));
    }

    #[test]
    fn a_flipped_context_byte_is_refused() {
        let sealer = Sealer::new(&key(5));
        let mut sealed = sealer
            .seal(SealContext::Frame, b"payload", false)
            .expect("seal");
        sealed[1] = SealContext::Toc.byte();
        assert!(matches!(
            sealer.open(SealContext::Frame, &sealed),
            Err(SealError::WrongContext { .. })
        ));
        // Asked for the context it now claims, the AAD is what refuses it.
        assert!(matches!(
            sealer.open(SealContext::Toc, &sealed),
            Err(SealError::Unauthentic)
        ));
    }

    #[test]
    fn the_version_byte_is_rejected_before_the_tag() {
        let sealer = Sealer::new(&key(5));
        let mut sealed = sealer
            .seal(SealContext::Frame, b"payload", false)
            .expect("seal");
        sealed[0] = 3;
        assert!(matches!(
            sealer.open(SealContext::Frame, &sealed),
            Err(SealError::UnsupportedVersion(3)),
        ));
    }

    /// Version 1 put the flags byte in the clear. It was never written in production and
    /// is not read: no compatibility path, just a refusal.
    #[test]
    fn a_version_one_payload_is_refused() {
        let sealer = Sealer::new(&key(5));
        let mut sealed = sealer
            .seal(SealContext::Frame, b"payload", false)
            .expect("seal");
        sealed[0] = 1;
        assert!(matches!(
            sealer.open(SealContext::Frame, &sealed),
            Err(SealError::UnsupportedVersion(1)),
        ));
    }

    /// Reserved flag bits are now *inside* the seal, so only a holder of the key can even
    /// set them — and the refusal comes after the tag check, on authenticated plaintext.
    #[test]
    fn reserved_flag_bits_are_refused() {
        let sealer = Sealer::new(&key(5));
        let sealed = sealer
            .seal_with_flags(SealContext::Frame, 0b1000_0000, b"payload")
            .expect("seal");
        assert!(matches!(
            sealer.open(SealContext::Frame, &sealed),
            Err(SealError::UnknownFlags(0b1000_0000))
        ));
    }

    #[test]
    fn any_tampered_byte_fails_to_open() {
        let sealer = Sealer::new(&key(9));
        let sealed = sealer
            .seal(SealContext::Frame, b"tamper me", false)
            .expect("seal");
        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            let opened = sealer.open(SealContext::Frame, &tampered);
            assert!(
                opened.is_err(),
                "flipping byte {index} must not open cleanly"
            );
        }
    }

    #[test]
    fn a_truncated_payload_is_refused() {
        let sealer = Sealer::new(&key(9));
        let sealed = sealer
            .seal(SealContext::Frame, b"payload", false)
            .expect("seal");
        assert!(matches!(
            sealer.open(SealContext::Frame, &sealed[..SEAL_OVERHEAD - 1]),
            Err(SealError::Truncated)
        ));
        // Truncating the tag is an authentication failure, not a length failure.
        assert!(matches!(
            sealer.open(SealContext::Frame, &sealed[..sealed.len() - 1]),
            Err(SealError::Unauthentic)
        ));
    }

    #[test]
    fn the_wrong_key_fails_to_open() {
        let sealed = Sealer::new(&key(1))
            .seal(SealContext::Frame, b"secret", false)
            .expect("seal");
        assert!(matches!(
            Sealer::new(&key(2)).open(SealContext::Frame, &sealed),
            Err(SealError::Unauthentic)
        ));
    }

    #[test]
    fn a_data_key_never_renders_its_bytes() {
        let rendered = format!("{:?}", key(0xAB));
        assert_eq!(rendered, "DataKey(redacted)");
        assert!(!rendered.contains("ab"));
        assert_eq!(format!("{:?}", Sealer::new(&key(1))), "Sealer(redacted)");
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(DataKey::from_slice(&[0u8; 31]).is_err());
        assert!(DataKey::from_slice(&[0u8; 32]).is_ok());
    }

    /// Golden vector: pins the byte-exact wire format (header layout, derived nonce, AAD
    /// and ciphertext) for a fixed key and payload. A change here changes every cid in
    /// every existing restore point.
    #[test]
    fn wire_format_is_pinned() {
        let sealer = Sealer::new(&DataKey::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]));
        let sealed = sealer
            .seal(SealContext::Frame, b"orc8r appdata golden vector", false)
            .expect("seal");
        assert_eq!(
            hex(&sealed),
            "0200fa5950d4f8ed876e5a9a755937d1b1d8268a4d4ec009b80a4deb797931ce2c67344ed43e690f7ebc048bf4a2596dca981bcfbece431bd229"
        );

        // Same key and same payload, sealed as compressed. The flags byte is inside the
        // AEAD and the nonce commits to it, so the nonce *and* the ciphertext differ —
        // version 1's "same nonce, different tag" property is gone by design.
        let marked = sealer
            .seal(SealContext::Frame, b"orc8r appdata golden vector", true)
            .expect("seal");
        assert_eq!(
            hex(&marked),
            "02007b1da9db1449d4219adb10d346b007888c56c3e79bb01e10cc3d9e83c5c50fc1803328294a5966e8e30f51e238db8e3f9f7d9c2ff2f65aa7"
        );
        assert_ne!(sealed[2..HEADER_LEN], marked[2..HEADER_LEN]);
        assert_ne!(sealed[HEADER_LEN..], marked[HEADER_LEN..]);
    }
}
