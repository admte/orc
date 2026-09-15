//! Encrypted OCI content, as the manifest declares it — and nothing about what the
//! content *is*.
//!
//! Following the ocicrypt convention, encryption is a property of a **descriptor**, not of
//! an artifact: a descriptor whose media type ends in `+encrypted` points at ciphertext,
//! and the manifest's own annotations say under which scheme and which key. So a client
//! decides "do I need a key, and is this the right one?" from the descriptors alone,
//! before it knows or cares whether the thing they describe is a restore point, an app, or
//! something that does not exist yet.
//!
//! ```text
//! layers[].mediaType   application/vnd.orc.appdata.layer.v1+zstd+encrypted
//! config.mediaType     application/vnd.orc.appdata.restore-point.config.v1+json+encrypted
//! annotations          org.orc8r.enc.scheme  = orc-sealed-stream-v1
//!                      org.orc8r.enc.key-id  = <public key id>
//! ```
//!
//! That separation is the whole reason this module knows no artifact types. The key
//! machinery — where a key comes from, that it is the right one, and that it is never
//! printed — is written once here; a materializer decides what to do with the plaintext.
//!
//! # The key never leaves this module in a printable form
//!
//! [`DataKey`] does not implement `Display`, its `Debug` is redacted, and nothing here
//! formats one into a message. A wrong key is reported by naming the **key id** the
//! content wants and the id the given key derives: both are public, derived values that
//! reveal nothing about either key.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{CliError, Result};
use crate::persist::seal::{DataKey, KeyRing, Sealer, key_id};

/// Media-type suffix marking a descriptor's content as ciphertext.
pub const ENCRYPTED_SUFFIX: &str = "+encrypted";

/// Manifest annotation naming the scheme the content is encrypted under.
pub const ANNOTATION_SCHEME: &str = "org.orc8r.enc.scheme";

/// Manifest annotation naming the key: the public [`key_id`], never key material.
pub const ANNOTATION_KEY_ID: &str = "org.orc8r.enc.key-id";

/// The one scheme this client speaks: the sealed-frame stream
/// ([`crate::persist::stream`]) — AES-256-GCM per frame under a 32-byte data key.
pub const SCHEME_SEALED_STREAM: &str = "orc-sealed-stream-v1";

/// Environment variable a key may arrive in instead of on the command line, so it stays
/// out of shell history and out of another user's `ps`.
///
/// It may hold several keys, separated by commas or whitespace: a pool whose key has been
/// rotated seals a point's layers under more than one of them, and opening such a point
/// needs every key the pool holds.
pub const KEY_ENV: &str = "ORC_ENCRYPTION_KEY";

/// Bytes a key file may hold. A rotated pool's whole history is a few hundred bytes; the
/// cap is what stops a mistyped path — a disk image, a log — from being read into memory.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Bytes in a data key, as hex characters on the command line.
const KEY_HEX_LEN: usize = crate::persist::seal::DATA_KEY_LEN * 2;

/// Whether a descriptor's media type marks its content as encrypted.
#[must_use]
pub fn is_encrypted(media_type: &str) -> bool {
    media_type.ends_with(ENCRYPTED_SUFFIX)
}

/// The media type the plaintext has, once decrypted.
#[must_use]
pub fn plain_media_type(media_type: &str) -> &str {
    media_type
        .strip_suffix(ENCRYPTED_SUFFIX)
        .unwrap_or(media_type)
}

/// What a manifest's descriptors and annotations say about opening its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encryption {
    /// No descriptor is encrypted; no key is involved.
    None,
    /// Every encrypted descriptor is sealed under one key, named by its public id.
    Sealed { key_id: String },
}

impl Encryption {
    /// The key id the content wants, or `None` when it is not encrypted.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Sealed { key_id } => Some(key_id),
        }
    }
}

/// Reads a manifest's encryption declaration from its descriptors and annotations.
///
/// `media_types` is every descriptor the manifest carries — config and layers together,
/// because the declaration covers the manifest as a whole.
///
/// # Errors
///
/// Returns [`CliError::Operational`] when the manifest mixes encrypted and plain
/// descriptors (there is no per-descriptor key to disambiguate that, so it is refused
/// rather than half-read), when the scheme is one this client does not speak, and when an
/// encrypted manifest names no key id — a download that could only fail at the first
/// frame, reported before anything is fetched.
pub fn declared<'a>(
    annotations: &BTreeMap<String, String>,
    media_types: impl IntoIterator<Item = &'a str>,
) -> Result<Encryption> {
    let mut encrypted = 0usize;
    let mut plain = 0usize;
    for media_type in media_types {
        if is_encrypted(media_type) {
            encrypted += 1;
        } else {
            plain += 1;
        }
    }
    if encrypted == 0 {
        return Ok(Encryption::None);
    }
    if plain != 0 {
        return Err(CliError::Operational(format!(
            "this artifact mixes {encrypted} encrypted and {plain} unencrypted parts; \
             nothing says which key opens which, so it cannot be read"
        )));
    }
    let scheme = annotations
        .get(ANNOTATION_SCHEME)
        .map(String::as_str)
        .unwrap_or_default();
    if scheme != SCHEME_SEALED_STREAM {
        return Err(CliError::Operational(format!(
            "this artifact is encrypted under {}, which this client cannot open; it \
             speaks {SCHEME_SEALED_STREAM}",
            if scheme.is_empty() {
                "an unnamed scheme".to_owned()
            } else {
                format!("{scheme:?}")
            }
        )));
    }
    let key_id = annotations
        .get(ANNOTATION_KEY_ID)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Operational(format!(
                "this artifact is encrypted but carries no {ANNOTATION_KEY_ID} annotation, \
                 so there is no way to tell whether a key is the right one"
            ))
        })?;
    Ok(Encryption::Sealed {
        key_id: key_id.clone(),
    })
}

/// The keys to open `encryption` with, taking none from a file.
///
/// See [`resolve_keys_from`], which this is the no-key-file spelling of.
///
/// # Errors
///
/// As [`resolve_keys_from`].
pub fn resolve_keys(encryption: &Encryption, flags: &[String]) -> Result<Vec<DataKey>> {
    resolve_keys_from(encryption, flags, &[])
}

/// The keys to open `encryption` with: whatever the command line named — `files` first,
/// then `flags` — and only if it named nothing, whatever [`KEY_ENV`] holds.
///
/// More than one key is the normal case for a pool whose key has been rotated: dedup
/// carries a layer forward under the key that sealed it, so a point committed after a
/// rotation legitimately mixes keys and only the whole set opens it. The command line wins
/// **as a whole** — a person who named keys there means those keys, not those plus
/// whatever the environment still holds — and the environment's own value may name
/// several, separated by commas or whitespace.
///
/// A key file is the form to prefer, and the one the help text recommends: a key passed as
/// `--key <hex>` is an argument, and arguments are world-readable in the process list for
/// as long as the command runs. A file's contents are not.
///
/// Content that is not encrypted takes no key, and keys offered for it are ignored rather
/// than refused — the same command line then works whether or not the artifact it names
/// happens to be encrypted. A key *file* named for such content is still read, because a
/// path that cannot be read is a mistake worth reporting either way.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when encrypted content is asked for with no key anywhere,
/// when a key file cannot be read or is over [`MAX_KEY_FILE_BYTES`], and when a key was
/// given that is not 64 hex characters. No message echoes key material.
pub fn resolve_keys_from(
    encryption: &Encryption,
    flags: &[String],
    files: &[std::path::PathBuf],
) -> Result<Vec<DataKey>> {
    // Read the files whatever the content turns out to be: a path that does not exist is
    // a typo, and reporting it only for encrypted content would hide it at random.
    let mut supplied = Vec::new();
    for path in files {
        supplied.extend(read_key_file(path)?);
    }
    if matches!(encryption, Encryption::None) {
        return Ok(Vec::new());
    }
    supplied.extend(
        flags
            .iter()
            .map(|flag| flag.trim().to_owned())
            .filter(|flag| !flag.is_empty()),
    );
    if supplied.is_empty() {
        supplied = std::env::var(KEY_ENV)
            .ok()
            .as_deref()
            .map(split_keys)
            .unwrap_or_default();
    }
    if supplied.is_empty() {
        return Err(CliError::Usage(format!(
            "this content is encrypted and needs its key: pass --key-file <path> naming a \
             file with the key the node page's Pull command hands over, one key per line \
             and every key a rotated pool holds — or put them in {KEY_ENV}, separated by \
             commas. `--key <hex>` takes one on the command line, where the process list \
             shows it to every user on this machine for as long as the pull runs"
        )));
    }
    supplied.iter().map(|value| parse_key(value)).collect()
}

/// The keys one file names: one per line, blank lines and `#` comments ignored.
///
/// This is the form to prefer over `--key`, and the reason is the process list: on Linux
/// `/proc/<pid>/cmdline` is world-readable, so a key typed as an argument is visible to
/// every user on the machine for as long as the command runs, and it lands in shell
/// history besides. A file is readable by whoever the filesystem says.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the file cannot be read, when it is over
/// [`MAX_KEY_FILE_BYTES`], when it is not UTF-8, and when it names no key at all. The
/// message carries the path and never a line of the file: every line is a key.
pub fn read_key_file(path: &std::path::Path) -> Result<Vec<String>> {
    let display = path.display();
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() > MAX_KEY_FILE_BYTES
    {
        return Err(CliError::Usage(format!(
            "the key file {display} is {} bytes, over the {MAX_KEY_FILE_BYTES}-byte limit; \
             a key file holds one {KEY_HEX_LEN}-character key per line",
            meta.len()
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|err| {
        CliError::Usage(format!(
            "the key file {display} cannot be read: {}",
            err.kind()
        ))
    })?;
    let keys: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    if keys.is_empty() {
        return Err(CliError::Usage(format!(
            "the key file {display} names no key; it holds one {KEY_HEX_LEN}-character key \
             per line, one for every key a rotated pool holds"
        )));
    }
    Ok(keys)
}

/// The keys one [`KEY_ENV`] value names: comma- or whitespace-separated, empties dropped.
fn split_keys(value: &str) -> Vec<String> {
    value
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parses a 32-byte data key written as 64 hex characters.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for anything else. The message never echoes the input:
/// a mistyped key is still a key.
pub fn parse_key(value: &str) -> Result<DataKey> {
    let value = value.trim();
    let bytes = decode_hex(value).filter(|bytes| bytes.len() * 2 == KEY_HEX_LEN);
    let bytes = bytes.ok_or_else(|| {
        CliError::Usage(format!(
            "the key must be {KEY_HEX_LEN} hexadecimal characters \
             ({} bytes), as the pool page's copy button hands it over",
            crate::persist::seal::DATA_KEY_LEN
        ))
    })?;
    DataKey::from_slice(&bytes)
        .map_err(|err| CliError::Usage(format!("unusable encryption key: {err}")))
}

/// A ring holding every key in `keys`, with the one the content names tried first.
///
/// The content's own key **must** be among them, and that check is the point of doing it
/// before a byte is fetched: without it a wrong key is only discovered when the first
/// frame fails to authenticate, after however many gigabytes it took to reach it. The
/// rest of the ring is checked against nothing — it cannot be, since nothing records
/// which key sealed a layer carried forward from an earlier point — and it costs one
/// extra attempt per layer at most ([`KeyRing`] remembers which key last worked).
///
/// Keys deriving the same id are folded together, so passing one twice is harmless.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when no key given derives the id the content names, and
/// when the content is not encrypted at all. Neither message prints key material: only
/// the public ids, wanted and given.
pub fn key_ring(encryption: &Encryption, keys: &[DataKey]) -> Result<KeyRing> {
    let Encryption::Sealed { key_id: wanted } = encryption else {
        return Err(CliError::Usage(
            "this content is not encrypted, so there is nothing for a key to open".to_owned(),
        ));
    };
    let mut sealers: Vec<(String, Arc<Sealer>)> = Vec::with_capacity(keys.len());
    for key in keys {
        let derived = key_id(key);
        if sealers.iter().any(|(id, _)| *id == derived) {
            continue;
        }
        sealers.push((derived, Arc::new(Sealer::new(key))));
    }
    if !sealers.iter().any(|(id, _)| id == wanted) {
        let given: Vec<&str> = sealers.iter().map(|(id, _)| id.as_str()).collect();
        return Err(CliError::Usage(format!(
            "none of the keys given is the one this content was sealed under: it names key \
             {wanted}, and the {} given derive {}",
            match given.len() {
                1 => "one key".to_owned(),
                count => format!("{count} keys"),
            },
            if given.is_empty() {
                "nothing".to_owned()
            } else {
                given.join(", ")
            },
        )));
    }
    Ok(KeyRing::new(sealers).preferring(wanted))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYER: &str = "application/vnd.orc.appdata.layer.v1+zstd+encrypted";
    const CONFIG: &str = "application/vnd.orc.appdata.restore-point.config.v1+json+encrypted";

    fn annotations(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn sealed() -> BTreeMap<String, String> {
        annotations(&[
            (ANNOTATION_SCHEME, SCHEME_SEALED_STREAM),
            (ANNOTATION_KEY_ID, "0123456789abcdef"),
        ])
    }

    #[test]
    fn the_suffix_is_what_marks_content_encrypted() {
        assert!(is_encrypted(LAYER));
        assert!(is_encrypted(CONFIG));
        assert!(!is_encrypted("application/vnd.orc.appdata.layer.v1+zstd"));
        assert_eq!(
            plain_media_type(LAYER),
            "application/vnd.orc.appdata.layer.v1+zstd"
        );
        assert_eq!(plain_media_type("application/json"), "application/json");
    }

    #[test]
    fn an_encrypted_manifest_names_its_scheme_and_key() {
        let found = declared(&sealed(), [CONFIG, LAYER, LAYER]).expect("declared");
        assert_eq!(
            found,
            Encryption::Sealed {
                key_id: "0123456789abcdef".to_owned()
            }
        );
        assert_eq!(found.key_id(), Some("0123456789abcdef"));
    }

    #[test]
    fn plain_content_declares_no_encryption_whatever_the_annotations_say() {
        let found = declared(&sealed(), ["application/json", "application/octet-stream"])
            .expect("declared");
        assert_eq!(found, Encryption::None);
        assert_eq!(found.key_id(), None);
        assert!(
            resolve_keys(&found, &["nonsense".to_owned()])
                .expect("ignored")
                .is_empty()
        );
    }

    #[test]
    fn a_half_encrypted_manifest_is_refused() {
        let err = declared(
            &sealed(),
            [CONFIG, "application/vnd.orc.appdata.layer.v1+zstd"],
        )
        .expect_err("mixed");
        assert!(err.to_string().contains("mixes"), "{err}");
    }

    #[test]
    fn a_scheme_this_client_cannot_open_is_named_in_the_error() {
        let err = declared(
            &annotations(&[
                (ANNOTATION_SCHEME, "someone-elses-envelope-v2"),
                (ANNOTATION_KEY_ID, "0123456789abcdef"),
            ]),
            [CONFIG],
        )
        .expect_err("unknown scheme");
        assert!(
            err.to_string().contains("someone-elses-envelope-v2"),
            "{err}"
        );
        assert!(err.to_string().contains(SCHEME_SEALED_STREAM), "{err}");

        let err = declared(
            &annotations(&[(ANNOTATION_KEY_ID, "0123456789abcdef")]),
            [CONFIG],
        )
        .expect_err("no scheme");
        assert!(err.to_string().contains("unnamed scheme"), "{err}");
    }

    #[test]
    fn encrypted_content_that_names_no_key_is_refused_before_any_fetch() {
        let err = declared(
            &annotations(&[(ANNOTATION_SCHEME, SCHEME_SEALED_STREAM)]),
            [CONFIG],
        )
        .expect_err("no key id");
        assert!(err.to_string().contains(ANNOTATION_KEY_ID), "{err}");
    }

    #[test]
    fn a_missing_key_is_a_usage_error_naming_both_ways_to_give_one() {
        let _guard = env_lock();
        set_env(None);
        let err =
            resolve_keys(&declared(&sealed(), [CONFIG]).expect("declared"), &[]).expect_err("none");
        assert!(err.to_string().contains("--key"), "{err}");
        assert!(err.to_string().contains(KEY_ENV), "{err}");
    }

    /// Serializes the tests that read or write the process-global environment.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[allow(unsafe_code)]
    fn set_env(value: Option<&str>) {
        // SAFETY: every test touching the environment holds `env_lock`, so no other
        // thread reads or writes it concurrently.
        unsafe {
            match value {
                Some(value) => std::env::set_var(KEY_ENV, value),
                None => std::env::remove_var(KEY_ENV),
            }
        }
    }

    /// The env var is there so a key need not be typed where a shell records it; the flag
    /// still wins, because a key typed on this command line is the one that was meant.
    #[test]
    fn the_keys_come_from_the_flags_first_and_the_environment_second() {
        let _guard = env_lock();
        let encryption = declared(&sealed(), [CONFIG]).expect("declared");
        let from_env = "11".repeat(32);
        let from_flag = "22".repeat(32);

        set_env(Some(&from_env));
        let keys = resolve_keys(&encryption, &[]).expect("env");
        assert_eq!(ids(&keys), vec![key_id(&DataKey::new([0x11_u8; 32]))]);

        // The flags win as a whole: the environment's key is not appended to them.
        let keys = resolve_keys(&encryption, std::slice::from_ref(&from_flag)).expect("flag");
        assert_eq!(ids(&keys), vec![key_id(&DataKey::new([0x22_u8; 32]))]);

        // An empty variable is no variable: it must not be mistaken for a bad key.
        set_env(Some("   "));
        assert!(resolve_keys(&encryption, &[]).is_err());
        set_env(None);
        assert!(resolve_keys(&encryption, &[]).is_err());
    }

    /// A rotated pool hands over several keys, and both ways of giving them take a list:
    /// `--key` repeated, or one variable naming them all.
    #[test]
    fn several_keys_arrive_by_repeated_flag_or_by_a_list_in_the_environment() {
        let _guard = env_lock();
        let encryption = declared(&sealed(), [CONFIG]).expect("declared");
        let first = "11".repeat(32);
        let second = "22".repeat(32);
        let wanted = vec![
            key_id(&DataKey::new([0x11_u8; 32])),
            key_id(&DataKey::new([0x22_u8; 32])),
        ];

        let keys = resolve_keys(&encryption, &[first.clone(), second.clone()]).expect("flags");
        assert_eq!(ids(&keys), wanted);

        for separator in [",", " ", ", ", "\n", "\t"] {
            set_env(Some(&format!("{first}{separator}{second}")));
            let keys = resolve_keys(&encryption, &[]).expect("env list");
            assert_eq!(ids(&keys), wanted, "separated by {separator:?}");
        }
        // Stray separators are not keys of their own.
        set_env(Some(&format!(" {first} , ,{second}, ")));
        assert_eq!(ids(&resolve_keys(&encryption, &[]).expect("env")), wanted);
        set_env(None);
    }

    fn ids(keys: &[DataKey]) -> Vec<String> {
        keys.iter().map(key_id).collect()
    }

    /// M5. A key file is the recommended form: one key per line, comments and blank lines
    /// ignored, and a rotated pool's whole set in one file.
    #[test]
    fn a_key_file_names_one_key_per_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = "11".repeat(32);
        let second = "22".repeat(32);

        let path = dir.path().join("keys");
        std::fs::write(
            &path,
            format!("# the pool's keys, newest first\n{second}\n\n  {first}  \n"),
        )
        .expect("write");
        assert_eq!(read_key_file(&path).expect("read"), vec![second, first]);
    }

    /// A key file that cannot be read, that is empty, or that is a file nobody meant to
    /// name is a usage error — and the message never carries a line of it, since every
    /// line is a key.
    #[test]
    fn an_unusable_key_file_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().expect("tempdir");

        let missing = dir.path().join("nowhere");
        let err = read_key_file(&missing).expect_err("missing");
        assert!(err.to_string().contains("nowhere"), "{err}");

        let empty = dir.path().join("empty");
        std::fs::write(&empty, "# nothing but a comment\n\n").expect("write");
        assert!(
            read_key_file(&empty)
                .expect_err("empty")
                .to_string()
                .contains("names no key")
        );

        // A mistyped path pointing at something large is refused by its size, not read.
        let big = dir.path().join("big");
        let over = usize::try_from(MAX_KEY_FILE_BYTES).expect("cap fits") + 1;
        std::fs::write(&big, vec![b'a'; over]).expect("write");
        let err = read_key_file(&big).expect_err("too large");
        assert!(err.to_string().contains("over the"), "{err}");

        // And a key inside a file is still never echoed when it fails to parse.
        let bad = dir.path().join("bad");
        std::fs::write(&bad, "zz".repeat(32)).expect("write");
        let err = resolve_keys_from(
            &declared(&sealed(), [CONFIG]).expect("declared"),
            &[],
            &[bad],
        )
        .expect_err("bad key");
        assert!(!err.to_string().contains(&"zz".repeat(32)), "{err}");
    }

    /// M5. `--key-file` and `--key` combine, and the command line as a whole still wins
    /// over the environment.
    #[test]
    fn key_files_join_the_flags_and_together_beat_the_environment() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let encryption = declared(&sealed(), [CONFIG]).expect("declared");
        let from_file = "11".repeat(32);
        let from_flag = "22".repeat(32);
        let from_env = "33".repeat(32);

        let path = dir.path().join("keys");
        std::fs::write(&path, format!("{from_file}\n")).expect("write");

        set_env(Some(&from_env));
        let keys = resolve_keys_from(&encryption, &[from_flag], std::slice::from_ref(&path))
            .expect("file and flag");
        assert_eq!(
            ids(&keys),
            vec![
                key_id(&DataKey::new([0x11_u8; 32])),
                key_id(&DataKey::new([0x22_u8; 32])),
            ],
            "the file's keys and the flags' keys both travel, and the environment's does not"
        );

        // A file alone also wins over the environment.
        let keys =
            resolve_keys_from(&encryption, &[], std::slice::from_ref(&path)).expect("file only");
        assert_eq!(ids(&keys), vec![key_id(&DataKey::new([0x11_u8; 32]))]);
        set_env(None);
    }

    /// The message a caller sees with no key anywhere names the file form first, and says
    /// plainly what `--key` costs.
    #[test]
    fn the_missing_key_message_recommends_the_file_and_warns_about_the_process_list() {
        let _guard = env_lock();
        set_env(None);
        let err = resolve_keys_from(&declared(&sealed(), [CONFIG]).expect("declared"), &[], &[])
            .expect_err("none");
        let message = err.to_string();
        assert!(message.contains("--key-file"), "{message}");
        assert!(message.contains("process list"), "{message}");
        assert!(message.contains(KEY_ENV), "{message}");
    }

    #[test]
    fn a_key_is_sixty_four_hex_characters_and_nothing_else() {
        let key = parse_key(&"ab".repeat(32)).expect("32 bytes");
        assert_eq!(key_id(&key), key_id(&DataKey::new([0xab_u8; 32])));
        assert!(
            parse_key(&format!("  {}\n", "ab".repeat(32))).is_ok(),
            "trimmed"
        );
        for bad in [
            "",
            "ab",
            &"ab".repeat(31),
            &"ab".repeat(33),
            &"zz".repeat(32),
        ] {
            let err = parse_key(bad).expect_err("must not parse");
            assert!(
                bad.is_empty() || !err.to_string().contains(bad),
                "the input must never be echoed back: {err}"
            );
        }
    }

    #[test]
    fn the_wrong_key_is_named_by_id_and_the_key_itself_never_appears() {
        let encryption = declared(&sealed(), [CONFIG]).expect("declared");
        let wrong = DataKey::new([7u8; 32]);
        let other = DataKey::new([8u8; 32]);
        let err = key_ring(&encryption, std::slice::from_ref(&wrong)).expect_err("wrong key");
        let message = err.to_string();
        assert!(message.contains("0123456789abcdef"), "{message}");
        assert!(message.contains(&key_id(&wrong)), "{message}");
        assert!(
            !message.contains(&"07".repeat(32)),
            "the key must never leak"
        );

        // Several wrong keys are all named, so a reader can see which ring they passed.
        let err = key_ring(&encryption, &[wrong, other]).expect_err("wrong keys");
        let message = err.to_string();
        assert!(message.contains("2 keys"), "{message}");
        assert!(
            message.contains(&key_id(&DataKey::new([7u8; 32]))),
            "{message}"
        );
        assert!(
            message.contains(&key_id(&DataKey::new([8u8; 32]))),
            "{message}"
        );

        let right = DataKey::new([7u8; 32]);
        let encryption = Encryption::Sealed {
            key_id: key_id(&right),
        };
        let ring = key_ring(&encryption, std::slice::from_ref(&right)).expect("right key");
        assert_eq!(ring.len(), 1);
        assert!(ring.holds(&key_id(&right)));
    }

    /// A rotated pool's ring: every key travels, the point's own is tried first, and a
    /// key repeated on the command line is folded rather than tried twice.
    #[test]
    fn the_ring_holds_every_key_with_the_contents_own_first() {
        let sealing = DataKey::new([3u8; 32]);
        let older = DataKey::new([4u8; 32]);
        let encryption = Encryption::Sealed {
            key_id: key_id(&sealing),
        };

        // Given newest-last, oldest-first, either way: the content's key leads.
        for keys in [
            vec![DataKey::new([4u8; 32]), DataKey::new([3u8; 32])],
            vec![DataKey::new([3u8; 32]), DataKey::new([4u8; 32])],
        ] {
            let ring = key_ring(&encryption, &keys).expect("ring");
            assert_eq!(
                ring.key_ids().collect::<Vec<_>>(),
                vec![key_id(&sealing).as_str(), key_id(&older).as_str()],
            );
        }

        let ring = key_ring(
            &encryption,
            &[
                DataKey::new([3u8; 32]),
                DataKey::new([4u8; 32]),
                DataKey::new([3u8; 32]),
            ],
        )
        .expect("ring");
        assert_eq!(ring.len(), 2, "a repeated key is folded");
    }
}
