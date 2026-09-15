//! The app manifest's `persist` block: which paths an app keeps across the life of a
//! node, and how much OS disk it needs once installed.
//!
//! This module owns the parse only. Whether a declared path exists, is a directory, or
//! can be grafted is a runtime question — nothing here touches the filesystem, so the
//! server and the node reach the same verdict from the manifest alone.

pub mod archive;
pub mod pack;
pub mod point;
pub mod restore;
pub mod seal;
pub mod stream;
pub mod tree;
pub mod upload;

pub use self::seal::KeyRing;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::app::{AppConfig, PersistBlock};

/// OS-disk space charged to an app that declares no `footprint_gb`.
pub const FOOTPRINT_DEFAULT_GB: u64 = 1;

/// The largest footprint the platform charges for one app, whatever the manifest
/// declares. A footprint is a planning figure, never a limit, so an over-declaration is
/// clamped rather than refused.
pub const FOOTPRINT_MAX_GB: u64 = 100;

/// Roots too broad to persist: grafting one of these redirects the operating system
/// itself onto the App-data volume. Matched exactly — `/var` is refused while
/// `/var/lib/postgresql` is exactly the kind of path apps do declare, and the same
/// goes for a user's own directory under `/home` or `c:/users`.
const SYSTEM_ROOTS: &[&str] = &[
    "/",
    "/var",
    "/home",
    "/root",
    "/opt",
    "/tmp",
    "c:/",
    "c:/users",
    "c:/programdata",
];

/// Trees the operating system owns, refused with everything beneath them.
///
/// A graft redirects a whole directory onto the App-data volume and migrates what was
/// there onto it, so `/etc/ssh` or `/usr/bin` is not a data directory an app may
/// declare — it is the host's own files moved onto a disk that is wiped when the pool
/// re-uses the node, and read by every app that shares the volume. `/var/lib/orc-agent`
/// and its Windows counterpart are in the same list for the same reason with one
/// addition: they hold the agent's own key material, and the App-data volume is
/// mounted inside them.
const SYSTEM_TREES: &[&str] = &[
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/orc-agent",
    "c:/windows",
    "c:/program files",
    "c:/program files (x86)",
    "c:/programdata/orc-agent",
];

/// Characters that make a `!` entry a capture filter rather than a literal hole.
const GLOB_METACHARS: &[char] = &['*', '?', '['];

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("persist.paths entry must not be empty")]
    Empty,
    #[error("persist path {0:?} must be absolute")]
    NotAbsolute(String),
    #[error("persist path {0:?} is a system location and cannot be persisted")]
    SystemRoot(String),
    #[error("persist path {0:?} must not contain a \".\" or \"..\" segment")]
    DotSegment(String),
    #[error("persist path {0:?} is a UNC path, which is not supported")]
    Unc(String),
    #[error("persist path {0:?} is declared twice")]
    Duplicate(String),
    #[error("persist path {path:?} is already covered by {root:?}")]
    NestedRoot { path: String, root: String },
    #[error("persist.paths declares no path to persist")]
    NoRoots,
    #[error("persist exclusion {0:?} is not inside any persisted path")]
    HoleOutsideRoots(String),
    #[error(
        "persist capture filter {0:?} must use \"/\" as its separator: \"\\\" is the escape character in a glob pattern"
    )]
    FilterBackslash(String),
    #[error("persist capture filter {0:?} must be relative to the persisted paths")]
    FilterAbsolute(String),
    #[error("persist capture filter {pattern:?} is not a valid glob pattern: {message}")]
    FilterPattern { pattern: String, message: String },
}

/// A parsed `persist` block: the paths to keep, the subtrees held back from the
/// App-data volume, and the patterns that keep a file off a restore point.
#[derive(Debug, Clone)]
pub struct PersistSpec {
    roots: Vec<String>,
    holes: Vec<String>,
    filters: Vec<String>,
    matcher: GlobSet,
}

impl PersistSpec {
    /// Parses the declared paths into roots, holes, and capture filters.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] when an entry is not an absolute path, names a system
    /// location, repeats another entry, excludes a path outside every root, or is a
    /// glob pattern the matcher cannot compile.
    pub fn parse(block: &PersistBlock) -> Result<Self, PersistError> {
        let mut roots: Vec<String> = Vec::new();
        let mut holes: Vec<String> = Vec::new();
        let mut filters: Vec<String> = Vec::new();
        // Roots first: a hole is checked against the roots, and an author may declare
        // them in any order.
        let mut excluded: Vec<&str> = Vec::new();
        for entry in &block.paths {
            let entry = entry.trim();
            let Some(excluded_entry) = entry.strip_prefix('!') else {
                let root = normalize_path(entry)?;
                if is_system_root(&root) {
                    return Err(PersistError::SystemRoot(root));
                }
                if roots.contains(&root) {
                    return Err(PersistError::Duplicate(root));
                }
                if let Some(outer) = roots.iter().find(|outer| is_under(&root, outer)) {
                    return Err(PersistError::NestedRoot {
                        path: root,
                        root: outer.clone(),
                    });
                }
                roots.push(root);
                continue;
            };
            excluded.push(excluded_entry.trim());
        }
        if roots.is_empty() {
            return Err(PersistError::NoRoots);
        }

        let mut builder = GlobSetBuilder::new();
        for entry in excluded {
            if entry.contains(GLOB_METACHARS) {
                let pattern = compile_filter(entry, &mut builder)?;
                if filters.contains(&pattern) {
                    return Err(PersistError::Duplicate(pattern));
                }
                filters.push(pattern);
                continue;
            }
            let hole = normalize_path(entry)?;
            if !roots.iter().any(|root| is_under(&hole, root)) {
                return Err(PersistError::HoleOutsideRoots(hole));
            }
            if holes.contains(&hole) {
                return Err(PersistError::Duplicate(hole));
            }
            holes.push(hole);
        }
        let matcher = builder.build().map_err(|err| PersistError::FilterPattern {
            pattern: filters.join(", "),
            message: err.to_string(),
        })?;
        Ok(Self {
            roots,
            holes,
            filters,
            matcher,
        })
    }

    /// The persisted paths, normalized: absolute, `/`-separated, no trailing slash.
    #[must_use]
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// Subtrees of a root that stay on the OS disk instead of the App-data volume.
    #[must_use]
    pub fn holes(&self) -> &[String] {
        &self.holes
    }

    /// The capture-filter patterns, in declaration order.
    #[must_use]
    pub fn filters(&self) -> &[String] {
        &self.filters
    }

    /// Whether a file is held back from a restore point. `relative` is the file's path
    /// under the root it lives in, `/`-separated and with no leading slash.
    ///
    /// A pattern matches that whole relative path, and `*` never crosses a `/`: `**/*.bkp`
    /// matches at any depth, `*.bkp` only directly under a root, and `logs/*.tmp` only one
    /// level below `logs`.
    #[must_use]
    pub fn is_capture_filtered(&self, relative: &str) -> bool {
        self.matcher.is_match(relative)
    }
}

/// The footprint the platform charges for `config`: the declared figure clamped to
/// [`FOOTPRINT_MAX_GB`], or [`FOOTPRINT_DEFAULT_GB`] when the manifest is silent. An
/// explicit `0` is a claim of no OS-disk cost and contributes nothing.
#[must_use]
pub fn effective_footprint_gb(config: &AppConfig) -> u64 {
    config
        .footprint_gb
        .unwrap_or(FOOTPRINT_DEFAULT_GB)
        .min(FOOTPRINT_MAX_GB)
}

/// Native paths in, one shape out: `\` becomes `/`, repeated separators collapse, a
/// drive letter lowercases, and a trailing separator is dropped. Case is otherwise
/// preserved — a Linux root is case-sensitive.
fn normalize_path(raw: &str) -> Result<String, PersistError> {
    if raw.is_empty() {
        return Err(PersistError::Empty);
    }
    // Collapsing the leading pair of a UNC path would turn `\\server\share` into
    // `/server/share` — a different location entirely — so it is refused, not rewritten.
    if raw.starts_with(['/', '\\']) && raw[1..].starts_with(['/', '\\']) {
        return Err(PersistError::Unc(raw.to_owned()));
    }
    let mut path = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let ch = if ch == '\\' { '/' } else { ch };
        if ch == '/' && path.ends_with('/') {
            continue;
        }
        path.push(ch);
    }
    if let Some(drive) = drive_letter(&path) {
        path.replace_range(..1, &drive.to_lowercase());
    }
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    // `c:` alone is the drive itself, not a path on it; keep it in root form so the
    // system-root check sees what the author wrote.
    if path.ends_with(':') && drive_letter(&path).is_some() {
        path.push('/');
    }
    if !is_absolute(&path) {
        return Err(PersistError::NotAbsolute(path));
    }
    // Every check downstream — the system-root deny list, the hole-under-root test — is
    // textual, and a relative segment makes the text lie about where the path lands:
    // `/var/lib/postgresql/../../..` is `/` at graft time.
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(PersistError::DotSegment(path));
    }
    Ok(path)
}

fn compile_filter(pattern: &str, builder: &mut GlobSetBuilder) -> Result<String, PersistError> {
    if pattern.contains('\\') {
        return Err(PersistError::FilterBackslash(pattern.to_owned()));
    }
    if is_absolute(pattern) {
        return Err(PersistError::FilterAbsolute(pattern.to_owned()));
    }
    // `literal_separator` keeps `*` and `?` inside one path component, so a pattern says
    // what it looks like it says and only `**` crosses directories.
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|err| PersistError::FilterPattern {
            pattern: pattern.to_owned(),
            message: err.kind().to_string(),
        })?;
    builder.add(glob);
    Ok(pattern.to_owned())
}

/// Whether `path` sits strictly below `root`; both must already be normalized.
fn is_under(path: &str, root: &str) -> bool {
    path.len() > root.len()
        && path.starts_with(root)
        && (root.ends_with('/') || path.as_bytes()[root.len()] == b'/')
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/') || drive_letter(path).is_some_and(|_| path[2..].starts_with('/'))
}

/// The drive letter of a `x:`-prefixed path, if it has one.
fn drive_letter(path: &str) -> Option<String> {
    let mut chars = path.chars();
    let letter = chars.next()?;
    if letter.is_ascii_alphabetic() && chars.next() == Some(':') {
        Some(letter.to_string())
    } else {
        None
    }
}

/// Whether a normalized root is one the platform refuses to graft. Windows paths are
/// compared case-insensitively (`C:\WINDOWS` is `c:/windows`); a drive root such as
/// `c:/` is as broad as `/` whatever the letter.
///
/// [`SYSTEM_ROOTS`] is matched whole and [`SYSTEM_TREES`] is matched with everything
/// under it: the first list is the containers apps legitimately keep a directory in,
/// the second is the operating system itself.
fn is_system_root(root: &str) -> bool {
    let root = match drive_letter(root) {
        Some(_) if root.len() == 3 && root.ends_with('/') => return true,
        Some(_) => root.to_lowercase(),
        None => root.to_owned(),
    };
    SYSTEM_ROOTS.contains(&root.as_str())
        || SYSTEM_TREES
            .iter()
            .any(|tree| root == *tree || is_under(&root, tree))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(paths: &[&str]) -> Result<PersistSpec, PersistError> {
        PersistSpec::parse(&PersistBlock {
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            hook_pre: None,
            hook_post: None,
        })
    }

    fn parsed(paths: &[&str]) -> PersistSpec {
        spec(paths).unwrap_or_else(|err| panic!("{paths:?}: {err}"))
    }

    fn rejected(paths: &[&str]) -> String {
        spec(paths)
            .err()
            .unwrap_or_else(|| panic!("{paths:?} should be rejected"))
            .to_string()
    }

    #[test]
    fn roots_normalize_native_paths() {
        // A Windows path as it appears in JSON, where `\\` is one backslash.
        let spec = parsed(&["C:\\jenkins-agent\\", "/var/lib/postgresql//data"]);
        assert_eq!(
            spec.roots(),
            ["c:/jenkins-agent", "/var/lib/postgresql/data"]
        );
        assert!(spec.holes().is_empty());
        assert!(spec.filters().is_empty());
    }

    #[test]
    fn a_hole_is_a_literal_path_under_a_root() {
        let spec = parsed(&["c:\\jenkins-agent", "!c:/jenkins-agent/workspace"]);
        assert_eq!(spec.roots(), ["c:/jenkins-agent"]);
        assert_eq!(spec.holes(), ["c:/jenkins-agent/workspace"]);
    }

    #[test]
    fn a_hole_accepts_the_native_form_of_its_root() {
        let spec = parsed(&["c:/jenkins-agent", "!C:\\jenkins-agent\\workspace\\"]);
        assert_eq!(spec.holes(), ["c:/jenkins-agent/workspace"]);
    }

    #[test]
    fn a_wildcard_exclusion_is_a_capture_filter() {
        let spec = parsed(&["/srv/app", "!**/*.bkp", "!cache/*"]);
        assert!(spec.holes().is_empty());
        assert_eq!(spec.filters(), ["**/*.bkp", "cache/*"]);
        assert!(spec.is_capture_filtered("logs/old.bkp"));
        assert!(spec.is_capture_filtered("old.bkp"));
        assert!(spec.is_capture_filtered("cache/blob"));
        assert!(!spec.is_capture_filtered("logs/old.log"));
        assert!(!spec.is_capture_filtered("var/cache/blob"));
    }

    #[test]
    fn a_pattern_matches_the_root_relative_path_and_only_two_stars_cross_directories() {
        let spec = parsed(&["/srv/app", "!**/*.bkp", "!*.tmp", "!logs/*.log"]);
        // `**/` stands for any number of directories, none included.
        assert!(spec.is_capture_filtered("old.bkp"));
        assert!(spec.is_capture_filtered("a/b/old.bkp"));
        // A single `*` stays inside one path component.
        assert!(spec.is_capture_filtered("scratch.tmp"));
        assert!(!spec.is_capture_filtered("a/scratch.tmp"));
        // A pattern with a directory in it is anchored at the root.
        assert!(spec.is_capture_filtered("logs/app.log"));
        assert!(!spec.is_capture_filtered("logs/2026/app.log"));
        assert!(!spec.is_capture_filtered("var/logs/app.log"));
    }

    #[test]
    fn relative_segments_are_refused_wherever_a_path_carries_them() {
        // Textually these pass the deny list and the hole-under-root test; at graft time
        // they resolve somewhere else entirely.
        assert_eq!(
            rejected(&["/var/lib/postgresql/../../.."]),
            "persist path \"/var/lib/postgresql/../../..\" must not contain a \".\" or \"..\" segment"
        );
        assert_eq!(
            rejected(&["/srv/app", "!/srv/app/../../etc"]),
            "persist path \"/srv/app/../../etc\" must not contain a \".\" or \"..\" segment"
        );
        assert_eq!(
            rejected(&["c:\\jenkins-agent\\.\\workspace"]),
            "persist path \"c:/jenkins-agent/./workspace\" must not contain a \".\" or \"..\" segment"
        );
        // A dot inside a name is not a segment.
        assert_eq!(
            parsed(&["/srv/app..d/.data"]).roots(),
            ["/srv/app..d/.data"]
        );
    }

    #[test]
    fn unc_paths_are_refused_rather_than_rewritten() {
        for path in ["\\\\server\\share", "//server/share", "\\\\server/share"] {
            let message = rejected(&[path]);
            assert!(message.contains("is a UNC path"), "{path:?}: {message:?}");
        }
        let message = rejected(&["/srv/app", "!//server/share"]);
        assert!(message.contains("is a UNC path"), "{message:?}");
    }

    #[test]
    fn declaring_no_root_is_rejected() {
        assert_eq!(rejected(&[]), "persist.paths declares no path to persist");
        assert_eq!(
            rejected(&["!/srv/app/cache"]),
            "persist.paths declares no path to persist"
        );
    }

    #[test]
    fn the_containers_apps_keep_data_in_are_refused_whole_and_only_whole() {
        for path in [
            "/",
            "/var/",
            "/home",
            "/root",
            "/opt",
            "/tmp",
            "c:\\",
            "C:/",
            "c:/users",
            "C:\\ProgramData",
            "d:/",
        ] {
            let message = rejected(&[path]);
            assert!(message.contains("system location"), "{path:?}: {message:?}");
        }
        // These are matched whole, so an ordinary data directory inside one stays
        // legal — which is what most apps declare.
        for path in [
            "/var/lib/postgresql",
            "/home/build/data",
            "/opt/app/state",
            "c:/programdata/jenkins",
            "c:/users/jenkins/agent",
        ] {
            parsed(&[path]);
        }
    }

    #[test]
    fn an_os_owned_tree_is_refused_with_everything_under_it() {
        for path in [
            "/etc",
            "/etc/ssh",
            "/usr",
            "/usr/bin",
            "/usr/local/share/app",
            "/bin",
            "/sbin/init.d",
            "/lib",
            "/lib64/security",
            "/libx32",
            "/boot/efi",
            "/proc/1",
            "/sys/class",
            "/dev/shm",
            "/run/lock",
            // The agent's own state, which is also where the App-data volume is
            // mounted: grafting it would redirect the volume onto itself.
            "/var/lib/orc-agent",
            "/var/lib/orc-agent/appdata",
            "c:/Windows",
            "c:/windows/system32/config",
            "C:\\Program Files",
            "c:/program files (x86)/app",
            "C:\\ProgramData\\orc-agent\\appdata",
        ] {
            let message = rejected(&[path]);
            assert!(message.contains("system location"), "{path:?}: {message:?}");
        }
        // A whole component, never a string prefix: these only look like they are
        // under one of those trees.
        for path in [
            "/etc-backup",
            "/usrdata",
            "/var/lib/orc-agent-backups",
            "c:/windows-old/data",
        ] {
            parsed(&[path]);
        }
    }

    #[test]
    fn windows_roots_compare_case_insensitively() {
        // The path keeps its case; only the drive letter is folded, so the deny list
        // has to fold the rest itself.
        assert!(rejected(&["C:\\WINDOWS"]).contains("system location"));
        assert_eq!(parsed(&["C:\\Jenkins-Agent"]).roots(), ["c:/Jenkins-Agent"]);
    }

    #[test]
    fn relative_paths_are_refused() {
        assert_eq!(
            rejected(&["jenkins-agent"]),
            "persist path \"jenkins-agent\" must be absolute"
        );
        assert_eq!(
            rejected(&["/srv/app", "!workspace"]),
            "persist path \"workspace\" must be absolute"
        );
    }

    #[test]
    fn a_hole_outside_every_root_is_refused() {
        assert_eq!(
            rejected(&["/srv/app", "!/srv/other/cache"]),
            "persist exclusion \"/srv/other/cache\" is not inside any persisted path"
        );
        // A hole equal to its root would persist nothing at all.
        assert_eq!(
            rejected(&["/srv/app", "!/srv/app"]),
            "persist exclusion \"/srv/app\" is not inside any persisted path"
        );
        // Sharing a prefix is not the same as being under the root.
        assert_eq!(
            rejected(&["/srv/app", "!/srv/apple/cache"]),
            "persist exclusion \"/srv/apple/cache\" is not inside any persisted path"
        );
    }

    #[test]
    fn a_backslash_in_a_pattern_is_refused_with_the_reason() {
        let message = rejected(&["c:/jenkins-agent", "!**\\*.bkp"]);
        assert!(
            message.contains("must use \"/\" as its separator"),
            "{message:?}"
        );
        assert!(message.contains("escape character"), "{message:?}");
    }

    #[test]
    fn an_absolute_pattern_is_refused() {
        assert_eq!(
            rejected(&["/srv/app", "!/srv/app/*.bkp"]),
            "persist capture filter \"/srv/app/*.bkp\" must be relative to the persisted paths"
        );
    }

    #[test]
    fn an_uncompilable_pattern_is_refused() {
        let message = rejected(&["/srv/app", "!cache/[a-"]);
        assert!(message.contains("not a valid glob pattern"), "{message:?}");
    }

    #[test]
    fn duplicate_and_nested_entries_are_refused() {
        assert_eq!(
            rejected(&["/srv/app", "/srv/app/"]),
            "persist path \"/srv/app\" is declared twice"
        );
        assert_eq!(
            rejected(&["/srv/app", "/srv/app/data"]),
            "persist path \"/srv/app/data\" is already covered by \"/srv/app\""
        );
        assert_eq!(
            rejected(&["/srv/app", "!/srv/app/cache", "!/srv/app/cache"]),
            "persist path \"/srv/app/cache\" is declared twice"
        );
        assert_eq!(
            rejected(&["/srv/app", "!*.bkp", "!*.bkp"]),
            "persist path \"*.bkp\" is declared twice"
        );
    }

    #[test]
    fn an_empty_entry_is_refused() {
        assert_eq!(rejected(&[""]), "persist.paths entry must not be empty");
        assert_eq!(
            rejected(&["/srv/app", "!"]),
            "persist.paths entry must not be empty"
        );
    }

    #[test]
    fn a_hole_may_sit_under_any_declared_root() {
        let spec = parsed(&[
            "/srv/app",
            "/var/lib/postgresql/data",
            "!/var/lib/postgresql/data/pg_wal",
        ]);
        assert_eq!(spec.holes(), ["/var/lib/postgresql/data/pg_wal"]);
    }

    #[test]
    fn footprint_defaults_to_one_and_clamps_at_the_maximum() {
        let footprint = |declared| {
            effective_footprint_gb(&AppConfig {
                footprint_gb: declared,
                ..AppConfig::default()
            })
        };
        assert_eq!(footprint(None), FOOTPRINT_DEFAULT_GB);
        assert_eq!(footprint(Some(0)), 0);
        assert_eq!(footprint(Some(35)), 35);
        assert_eq!(footprint(Some(100)), FOOTPRINT_MAX_GB);
        assert_eq!(footprint(Some(500)), FOOTPRINT_MAX_GB);
    }
}
