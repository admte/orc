//! What a systemd service says, and how loudly.
//!
//! systemd hands a service's stdout and stderr to journald as one stream at one
//! priority, so by the time the runtime reads the unit's journal a traceback looks
//! exactly like a progress line. Two halves put the difference back:
//!
//! - Before the app is exec'd, [`stderr_at_warning`] gives its stderr a journal stream
//!   of its own, opened at warning priority.
//! - When the runtime follows the unit, [`journal_lines`] reads each record's priority
//!   and says which stream the line stands for. systemd's own lines about the unit
//!   count too: a unit that exits non-zero or gives up restarting is a failure the
//!   node's operator has to see.

use std::io::Write as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::process::LogStream;

/// The socket journald takes stream connections on — what `sd_journal_stream_fd`
/// dials.
const JOURNAL_STDOUT: &str = "/run/systemd/journal/stdout";

/// syslog's `LOG_WARNING`.
const LOG_WARNING: u8 = 4;

/// syslog's `LOG_NOTICE`.
const LOG_NOTICE: u8 = 5;

/// The journal fields [`journal_lines`] reads; `journalctl` sends only these.
pub(crate) const FIELDS: &str = "MESSAGE,PRIORITY,_PID,SYSLOG_IDENTIFIER";

/// Points `command`'s stderr at a journal stream of its own at warning priority,
/// when the runtime's own stderr is the unit's journal stream.
///
/// Only then: outside a unit, stderr is a terminal or a pipe somebody else reads, and
/// leaving it alone is the right answer. Anything that goes wrong keeps the inherited
/// stderr — an app whose errors read at info is still an app that runs.
pub(crate) fn stderr_at_warning(command: &mut Command) {
    if !stderr_is_journal() {
        return;
    }
    match open_stream(&identifier(), LOG_WARNING) {
        Ok(stream) => {
            command.stderr(Stdio::from(OwnedFd::from(stream)));
        }
        Err(err) => {
            tracing::debug!(error = %err, "app stderr stays on the unit's own journal stream");
        }
    }
}

/// Whether fd 2 is the journal stream systemd connected the unit to.
///
/// systemd says which stream that is in `JOURNAL_STREAM` (`<device>:<inode>`), so an
/// stderr redirected to a file by the unit or by an operator is told apart from one
/// journald reads.
fn stderr_is_journal() -> bool {
    let Some(stream) = std::env::var_os("JOURNAL_STREAM") else {
        return false;
    };
    let Some((device, inode)) = stream.to_str().and_then(|value| value.split_once(':')) else {
        return false;
    };
    let (Ok(device), Ok(inode)) = (device.parse::<u64>(), inode.parse::<u64>()) else {
        return false;
    };
    std::io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .and_then(|fd| std::fs::File::from(fd).metadata())
        .is_ok_and(|meta| meta.dev() == device && meta.ino() == inode)
}

/// The name the unit's journal records carry, the same one systemd gave the stream it
/// opened: the basename of the program the unit ran.
fn identifier() -> String {
    std::env::args_os()
        .next()
        .as_deref()
        .map(Path::new)
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Opens a journal stream the way `sd_journal_stream_fd` does: connect, stop reading,
/// send the header.
fn open_stream(identifier: &str, priority: u8) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(JOURNAL_STDOUT)?;
    stream.shutdown(std::net::Shutdown::Read)?;
    stream.write_all(stream_header(identifier, priority).as_bytes())?;
    Ok(stream)
}

/// The header journald reads off a new stream, one value per line: identifier, unit
/// (empty: journald finds it from the peer's cgroup), priority, whether a `<N>` prefix
/// on a line overrides the priority, and the three forward-to flags.
///
/// The level prefix is honoured, as systemd's `SyslogLevelPrefix=` default does for the
/// stream it opens itself.
fn stream_header(identifier: &str, priority: u8) -> String {
    let identifier = identifier.replace('\n', " ");
    format!("{identifier}\n\n{priority}\n1\n0\n0\n0\n")
}

/// The lines in one `journalctl --output json` record, each with the stream it reads
/// as.
///
/// A record at warning or worse is stderr. So is one from systemd itself at notice
/// that says a process of the unit exited — systemd logs that at notice only when the
/// exit counted as a failure, and at debug otherwise — while its other notices
/// (`Consumed … CPU time`) stay stdout. A record with no usable message yields
/// nothing; a message spanning lines yields one per line.
pub(crate) fn journal_lines(record: &str) -> Vec<(LogStream, String)> {
    let Ok(serde_json::Value::Object(fields)) = serde_json::from_str(record) else {
        return Vec::new();
    };
    let message = match fields.get("MESSAGE") {
        Some(serde_json::Value::String(text)) => text.clone(),
        // journalctl sends a message that is not valid UTF-8 as its bytes.
        Some(serde_json::Value::Array(bytes)) => String::from_utf8_lossy(
            &bytes
                .iter()
                .filter_map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Vec<_>>(),
        )
        .into_owned(),
        _ => return Vec::new(),
    };
    let field = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
    let priority = field("PRIORITY").and_then(|value| value.parse::<u8>().ok());
    let from_manager = field("_PID") == Some("1") || field("SYSLOG_IDENTIFIER") == Some("systemd");
    let failure = match priority {
        Some(priority) if priority <= LOG_WARNING => true,
        Some(LOG_NOTICE) => from_manager && message.contains(" process exited, code="),
        _ => false,
    };
    let stream = if failure {
        LogStream::Stderr
    } else {
        LogStream::Stdout
    };
    message
        .lines()
        .map(|line| (stream, line.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(priority: &str, pid: &str, identifier: &str, message: &str) -> String {
        serde_json::json!({
            "__CURSOR": "s=1;i=2",
            "PRIORITY": priority,
            "_PID": pid,
            "SYSLOG_IDENTIFIER": identifier,
            "MESSAGE": message,
        })
        .to_string()
    }

    #[test]
    fn the_apps_stderr_reads_as_stderr_and_its_stdout_as_stdout() {
        assert_eq!(
            journal_lines(&record(
                "4",
                "4242",
                "orc-agent",
                "Traceback (most recent call last):"
            )),
            vec![(
                LogStream::Stderr,
                "Traceback (most recent call last):".to_owned()
            )]
        );
        assert_eq!(
            journal_lines(&record("6", "4242", "orc-agent", "INFO: loading weights")),
            vec![(LogStream::Stdout, "INFO: loading weights".to_owned())]
        );
        // An app that tags a line `<3>` on stdout gets err, and that is stderr too.
        assert_eq!(
            journal_lines(&record("3", "4242", "orc-agent", "out of memory")),
            vec![(LogStream::Stderr, "out of memory".to_owned())]
        );
    }

    /// The lines from systemd an operator needs: the unit failed, and why.
    #[test]
    fn systemd_saying_the_unit_failed_reads_as_stderr() {
        for (priority, message) in [
            (
                "5",
                "vllm.service: Main process exited, code=exited, status=1/FAILURE",
            ),
            ("4", "vllm.service: Failed with result 'exit-code'."),
            ("4", "vllm.service: Start request repeated too quickly."),
            ("3", "Failed to start vllm.service - ORC app vllm."),
        ] {
            assert_eq!(
                journal_lines(&record(priority, "1", "systemd", message)),
                vec![(LogStream::Stderr, message.to_owned())],
                "{message}"
            );
        }
    }

    /// systemd's ordinary bookkeeping stays at info, including the `Consumed` notice
    /// that shares a priority with a failed exit.
    #[test]
    fn systemd_bookkeeping_reads_as_stdout() {
        for (priority, message) in [
            ("6", "Started vllm.service - ORC app vllm."),
            (
                "6",
                "vllm.service: Scheduled restart job, restart counter is at 2.",
            ),
            (
                "5",
                "vllm.service: Consumed 1min 2.345s CPU time, 1.2G memory peak.",
            ),
            ("6", "vllm.service: Deactivated successfully."),
        ] {
            assert_eq!(
                journal_lines(&record(priority, "1", "systemd", message)),
                vec![(LogStream::Stdout, message.to_owned())],
                "{message}"
            );
        }
    }

    /// The exit wording is systemd's; an app printing it at notice is just an app.
    #[test]
    fn an_app_notice_is_not_read_as_a_failure() {
        let line = "worker process exited, code=0";
        assert_eq!(
            journal_lines(&record("5", "4242", "orc-agent", line)),
            vec![(LogStream::Stdout, line.to_owned())]
        );
    }

    #[test]
    fn odd_records_are_read_without_loss_or_panic() {
        // Not UTF-8: journalctl sends the bytes.
        let bytes = r#"{"PRIORITY":"4","_PID":"9","MESSAGE":[104,105,255]}"#;
        assert_eq!(
            journal_lines(bytes),
            vec![(LogStream::Stderr, "hi\u{fffd}".to_owned())]
        );
        // Over journalctl's size limit the message is null.
        assert!(journal_lines(r#"{"PRIORITY":"6","MESSAGE":null}"#).is_empty());
        assert!(journal_lines("not json").is_empty());
        // No priority at all: stdout, as the stream would have been.
        assert_eq!(
            journal_lines(r#"{"MESSAGE":"plain"}"#),
            vec![(LogStream::Stdout, "plain".to_owned())]
        );
        assert_eq!(
            journal_lines(&record("4", "9", "app", "first\nsecond")),
            vec![
                (LogStream::Stderr, "first".to_owned()),
                (LogStream::Stderr, "second".to_owned())
            ]
        );
    }

    /// The bytes `sd_journal_stream_fd` sends; journald drops a stream whose header it
    /// cannot read, so these are pinned exactly.
    #[test]
    fn the_stream_header_is_what_journald_reads() {
        assert_eq!(
            stream_header("orc-agent", LOG_WARNING),
            "orc-agent\n\n4\n1\n0\n0\n0\n"
        );
        // An identifier cannot shift the fields after it.
        assert_eq!(stream_header("a\nb", 4), "a b\n\n4\n1\n0\n0\n0\n");
    }

    /// Under a unit this would be true; outside one there is no journal stream to
    /// replace.
    #[test]
    fn a_stderr_that_is_not_the_journal_is_left_alone() {
        if std::env::var_os("JOURNAL_STREAM").is_none() {
            assert!(!stderr_is_journal());
        }
    }
}
