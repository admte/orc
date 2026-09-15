#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{CliError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    pub blobs: u64,
    pub bytes: u64,
    pub path: PathBuf,
}

pub fn cache_stats() -> Result<CacheStats> {
    let blob_dir = blob_dir()?;
    let (blobs, bytes) = if blob_dir.exists() {
        count_blobs(&blob_dir)?
    } else {
        (0, 0)
    };
    Ok(CacheStats {
        blobs,
        bytes,
        path: blob_dir,
    })
}

pub fn clean_cache() -> Result<CacheStats> {
    let before = cache_stats()?;
    if before.path.exists() {
        std::fs::remove_dir_all(&before.path).map_err(|err| {
            CliError::Operational(format!("remove {}: {err}", before.path.display()))
        })?;
    }
    Ok(before)
}

pub fn clean_unused_cache(protected_digests: &BTreeSet<String>) -> Result<CacheStats> {
    let path = blob_dir()?;
    if !path.exists() {
        return Ok(CacheStats {
            blobs: 0,
            bytes: 0,
            path,
        });
    }
    let protected = protected_filenames(protected_digests)?;
    let mut removed_blobs = 0;
    let mut removed_bytes = 0;
    for entry in std::fs::read_dir(&path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?
    {
        let entry =
            entry.map_err(|err| CliError::Operational(format!("read cache entry: {err}")))?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        if protected.contains(&filename) {
            continue;
        }
        let metadata = entry.metadata().map_err(|err| {
            CliError::Operational(format!("stat {}: {err}", entry.path().display()))
        })?;
        if metadata.is_file() {
            if is_sha256_hex_name(&filename) {
                removed_blobs += 1;
                removed_bytes += metadata.len();
            }
            std::fs::remove_file(entry.path()).map_err(|err| {
                CliError::Operational(format!("remove {}: {err}", entry.path().display()))
            })?;
        }
    }
    Ok(CacheStats {
        blobs: removed_blobs,
        bytes: removed_bytes,
        path,
    })
}

pub fn read_blob(digest: &str) -> Result<Option<Vec<u8>>> {
    let path = blob_path(digest)?;
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read(&path)
        .map(Some)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))
}

pub fn write_blob(digest: &str, body: &[u8]) -> Result<()> {
    let path = blob_path(digest)?;
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Operational(format!("create {}: {err}", parent.display())))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", temporary.display())))?;
    std::fs::rename(&temporary, &path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        CliError::Operational(format!("rename {}: {err}", path.display()))
    })
}

fn blob_dir() -> Result<PathBuf> {
    Ok(cache_dir()?.join("blobs/sha256"))
}

fn blob_path(digest: &str) -> Result<PathBuf> {
    Ok(blob_dir()?.join(blob_filename(digest)?))
}

fn blob_filename(digest: &str) -> Result<&str> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(CliError::Operational(format!(
            "unsupported blob digest {digest:?}"
        )));
    };
    if !is_sha256_hex_name(hex) {
        return Err(CliError::Operational(format!(
            "invalid blob digest {digest:?}"
        )));
    }
    Ok(hex)
}

fn protected_filenames(digests: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    digests
        .iter()
        .map(|digest| blob_filename(digest).map(str::to_owned))
        .collect()
}

fn cache_dir() -> Result<PathBuf> {
    crate::paths::cache_dir()
}

fn count_blobs(dir: &Path) -> Result<(u64, u64)> {
    let mut blobs = 0;
    let mut bytes = 0;
    for entry in std::fs::read_dir(dir)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", dir.display())))?
    {
        let entry =
            entry.map_err(|err| CliError::Operational(format!("read cache entry: {err}")))?;
        let metadata = entry.metadata().map_err(|err| {
            CliError::Operational(format!("stat {}: {err}", entry.path().display()))
        })?;
        if metadata.is_file() && is_sha256_hex_name(&entry.file_name().to_string_lossy()) {
            blobs += 1;
            bytes += metadata.len();
        }
    }
    Ok((blobs, bytes))
}

fn is_sha256_hex_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut divisor = 1_u128;
    let mut unit_index = 0;
    while unit_index + 1 < UNITS.len() {
        let next = divisor * 1024;
        if u128::from(bytes) < next {
            break;
        }
        divisor = next;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{bytes} B")
    } else {
        let tenths = (u128::from(bytes) * 10 + divisor / 2) / divisor;
        format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_blob_names_are_strict_hex() {
        assert!(is_sha256_hex_name(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!is_sha256_hex_name("abc"));
        assert!(!is_sha256_hex_name(
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
        ));
    }

    #[test]
    fn human_size_formats_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1536), "1.5 KiB");
    }

    #[test]
    fn blob_filenames_are_strict_sha256_digests() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            blob_filename(digest).expect("digest"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(blob_filename("sha512:abc").is_err());
        assert!(blob_filename("sha256:../bad").is_err());
    }

    #[test]
    fn protected_digests_convert_to_blob_filenames() {
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let protected =
            protected_filenames(&BTreeSet::from([digest.to_owned()])).expect("protected");
        assert!(
            protected.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }
}
