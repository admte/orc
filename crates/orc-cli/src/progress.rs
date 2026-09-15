//! Terminal rendering for the SDK's [`ProgressReporter`] event stream.
//!
//! All output goes to **stderr** so stdout stays script-safe. On an interactive
//! terminal we render Docker-style in-place status lines with `indicatif`; when
//! progress is forced on for a non-terminal (`ORC_PROGRESS=always`, e.g. tests
//! or CI logs) we fall back to one concise line per phase transition.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use orc_app::progress::{ProgressEvent, ProgressKind, ProgressPhase, ProgressReporter};

/// Builds a reporter when progress should be shown, honoring `--quiet` and the
/// `ORC_PROGRESS` override. Returns `None` when progress is disabled, so callers
/// simply skip attaching it.
#[must_use]
pub fn make_reporter(quiet: bool) -> Option<Arc<CliProgress>> {
    progress_enabled(quiet).then(CliProgress::new)
}

/// Borrows a reporter as a trait object for the CLI-local paths (build
/// downloads, cache materialization) that take `Option<&dyn ProgressReporter>`.
#[must_use]
pub fn as_dyn(reporter: Option<&Arc<CliProgress>>) -> Option<&dyn ProgressReporter> {
    reporter.map(|reporter| reporter.as_ref() as &dyn ProgressReporter)
}

/// Decides whether progress is shown. `--quiet` always wins; otherwise
/// `ORC_PROGRESS` selects `always`/`never`, and `auto` (the default, and any
/// unrecognized value) defers to whether stderr is a terminal.
fn progress_enabled(quiet: bool) -> bool {
    if quiet {
        return false;
    }
    match std::env::var("ORC_PROGRESS").ok().as_deref() {
        Some("never") => false,
        Some("always") => true,
        _ => crate::terminal::stderr_is_terminal(),
    }
}

pub struct CliProgress {
    sink: Sink,
}

enum Sink {
    /// Interactive terminal: rich in-place bars, one per tracked key.
    Rich {
        multi: MultiProgress,
        bars: Mutex<HashMap<String, ProgressBar>>,
    },
    /// Forced-on but non-interactive: one line per phase transition, keyed so
    /// repeated byte updates collapse to a single line.
    Plain {
        seen: Mutex<HashMap<String, &'static str>>,
    },
}

impl CliProgress {
    fn new() -> Arc<Self> {
        let sink = if crate::terminal::stderr_is_terminal() {
            // We already know stderr is a terminal, so enable colors directly
            // rather than trust `console`'s heuristics, which go colorless under
            // an empty/unknown `TERM` (some terminals, multiplexers, CI ptys).
            // Still honor an explicit `NO_COLOR` opt-out.
            if std::env::var_os("NO_COLOR").is_none() {
                console::set_colors_enabled(true);
            }
            Sink::Rich {
                multi: MultiProgress::new(),
                bars: Mutex::new(HashMap::new()),
            }
        } else {
            Sink::Plain {
                seen: Mutex::new(HashMap::new()),
            }
        };
        Arc::new(Self { sink })
    }
}

impl ProgressReporter for CliProgress {
    fn report(&self, event: ProgressEvent) {
        match &self.sink {
            Sink::Rich { multi, bars } => report_rich(multi, bars, &event),
            Sink::Plain { seen } => report_plain(seen, &event),
        }
    }
}

fn report_rich(
    multi: &MultiProgress,
    bars: &Mutex<HashMap<String, ProgressBar>>,
    event: &ProgressEvent,
) {
    let label = label(event);
    let mut bars = bars.lock().expect("progress bars lock");
    let bar = bars.entry(event.key.clone()).or_insert_with(|| {
        let bar = multi.add(ProgressBar::new(0));
        bar.set_prefix(label.clone());
        bar
    });
    match &event.phase {
        ProgressPhase::Downloading { done, total } => {
            transfer(bar, "Downloading", *done, *total);
        }
        ProgressPhase::Uploading { done, total } => {
            transfer(bar, "Uploading", *done, *total);
        }
        ProgressPhase::Verifying => spin(bar, "Verifying"),
        ProgressPhase::Writing => spin(bar, "Writing"),
        ProgressPhase::Cached => finish(bar, "Cached", cached_style()),
        ProgressPhase::Exists => finish(bar, "Exists", cached_style()),
        ProgressPhase::Done => finish(bar, "Done", done_style()),
        ProgressPhase::Failed { message } => {
            bar.set_style(failed_style());
            bar.abandon_with_message(format!("Failed: {message}"));
        }
    }
}

fn transfer(bar: &ProgressBar, verb: &str, done: u64, total: Option<u64>) {
    if let Some(total) = total {
        bar.set_style(bar_style());
        bar.set_length(total);
    } else {
        bar.set_style(spinner_bytes_style());
        bar.enable_steady_tick(Duration::from_millis(90));
    }
    bar.set_message(verb.to_owned());
    bar.set_position(done);
}

fn spin(bar: &ProgressBar, verb: &str) {
    bar.set_style(spinner_style());
    bar.set_message(verb.to_owned());
    bar.enable_steady_tick(Duration::from_millis(90));
}

fn finish(bar: &ProgressBar, verb: &str, style: ProgressStyle) {
    bar.set_style(style);
    bar.finish_with_message(verb.to_owned());
}

fn report_plain(seen: &Mutex<HashMap<String, &'static str>>, event: &ProgressEvent) {
    let tag = phase_tag(&event.phase);
    {
        let mut seen = seen.lock().expect("progress seen lock");
        if seen.insert(event.key.clone(), tag) == Some(tag) {
            // Same phase as last time for this key (e.g. another byte chunk).
            return;
        }
    }
    let label = label(event);
    match &event.phase {
        ProgressPhase::Downloading { total, .. } | ProgressPhase::Uploading { total, .. } => {
            match total {
                Some(total) => eprintln!("{label} {} {}", verb(&event.phase), HumanBytes(*total)),
                None => eprintln!("{label} {}", verb(&event.phase)),
            }
        }
        ProgressPhase::Failed { message } => eprintln!("{label} Failed: {message}"),
        _ => eprintln!("{label} {}", verb(&event.phase)),
    }
}

fn label(event: &ProgressEvent) -> String {
    match event.kind {
        ProgressKind::Manifest => "manifest".to_owned(),
        ProgressKind::Blob => short_digest(&event.key),
        ProgressKind::File => event.key.clone(),
    }
}

/// Shortens `sha256:<64 hex>` to `sha256:<12 hex>` for compact lines; passes
/// any other key (a file title) through unchanged.
fn short_digest(key: &str) -> String {
    key.strip_prefix("sha256:").map_or_else(
        || key.to_owned(),
        |hex| format!("sha256:{}", &hex[..hex.len().min(12)]),
    )
}

fn verb(phase: &ProgressPhase) -> &'static str {
    match phase {
        ProgressPhase::Downloading { .. } => "Downloading",
        ProgressPhase::Uploading { .. } => "Uploading",
        ProgressPhase::Verifying => "Verifying",
        ProgressPhase::Writing => "Writing",
        ProgressPhase::Cached => "Cached",
        ProgressPhase::Exists => "Exists",
        ProgressPhase::Done => "Done",
        ProgressPhase::Failed { .. } => "Failed",
    }
}

/// A stable tag per phase variant so the plain sink can collapse repeated
/// same-phase events (notably the byte stream) to one printed line.
fn phase_tag(phase: &ProgressPhase) -> &'static str {
    verb(phase)
}

// Column layout, Docker-style: a fixed-width id, a right-aligned status verb,
// then the bar/bytes. The prefix pads to 32 and the verb to 11 ("Downloading")
// so lines align across blobs, files, and the manifest.
fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {prefix:<32.bold} {msg:>11.cyan} [{bar:24.cyan/blue}] {bytes:>10}/{total_bytes}",
    )
    .expect("valid template")
    .progress_chars("=> ")
}

fn spinner_bytes_style() -> ProgressStyle {
    ProgressStyle::with_template("  {prefix:<32.bold} {msg:>11.cyan} {spinner:.cyan} {bytes:>10}")
        .expect("valid template")
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("  {prefix:<32.bold} {msg:>11.yellow} {spinner:.yellow}")
        .expect("valid template")
}

fn done_style() -> ProgressStyle {
    ProgressStyle::with_template("  {prefix:<32.bold} {msg:>11.green.bold}")
        .expect("valid template")
}

fn cached_style() -> ProgressStyle {
    ProgressStyle::with_template("  {prefix:<32.bold} {msg:>11.blue}").expect("valid template")
}

fn failed_style() -> ProgressStyle {
    ProgressStyle::with_template("  {prefix:<32.bold} {msg:>11.red.bold}").expect("valid template")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate the process-global `ORC_PROGRESS`.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[allow(unsafe_code)]
    fn set_progress(value: Option<&str>) {
        // SAFETY: enablement tests hold `env_lock`, so no other thread touches
        // the environment concurrently.
        unsafe {
            match value {
                Some(value) => std::env::set_var("ORC_PROGRESS", value),
                None => std::env::remove_var("ORC_PROGRESS"),
            }
        }
    }

    #[test]
    fn quiet_disables_progress_even_when_forced() {
        let _guard = env_lock();
        set_progress(Some("always"));
        assert!(!progress_enabled(true));
        set_progress(None);
    }

    #[test]
    fn always_enables_progress_off_a_terminal() {
        let _guard = env_lock();
        set_progress(Some("always"));
        assert!(progress_enabled(false));
        set_progress(None);
    }

    #[test]
    fn never_disables_progress() {
        let _guard = env_lock();
        set_progress(Some("never"));
        assert!(!progress_enabled(false));
        set_progress(None);
    }

    #[test]
    fn auto_defers_to_terminal_state() {
        let _guard = env_lock();
        set_progress(Some("auto"));
        // Tests run without a stderr terminal, so auto resolves to off.
        assert_eq!(
            progress_enabled(false),
            crate::terminal::stderr_is_terminal()
        );
        set_progress(None);
    }

    #[test]
    fn all_styles_are_valid_templates() {
        // The style builders `.expect()` on parse; tests run off a TTY (plain
        // sink), so exercise them here to catch a malformed template.
        let _ = bar_style();
        let _ = spinner_bytes_style();
        let _ = spinner_style();
        let _ = done_style();
        let _ = cached_style();
        let _ = failed_style();
    }

    #[test]
    fn short_digest_truncates_sha256() {
        assert_eq!(
            short_digest("sha256:0123456789abcdef0123456789abcdef"),
            "sha256:0123456789ab"
        );
        assert_eq!(short_digest("bin/run.sh"), "bin/run.sh");
    }
}
