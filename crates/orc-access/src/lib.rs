//! Public protocol used by ORC clients to reach private services.
//!
//! This crate owns the client-facing messages and generated gRPC client and
//! server interfaces. Authentication, authorization, routing, session storage,
//! and tunnel execution belong to the server implementation.

#![allow(
    clippy::default_trait_access,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::trivially_copy_pass_by_ref,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

tonic::include_proto!("orc.access.v1");

/// Validate a process request before opening a tunnel or spawning anything.
pub fn validate_execute(open: &ExecuteOpen) -> Result<(), &'static str> {
    if open.command.is_empty() && !(open.tty && open.stdin) {
        return Err("a command is required unless opening an interactive shell");
    }
    if open.command.first().is_some_and(String::is_empty)
        || open.command.iter().any(|arg| arg.contains('\0'))
    {
        return Err("command arguments must not contain NUL; the executable must not be empty");
    }
    if open.command.len() > 1024 || open.command.iter().map(String::len).sum::<usize>() > 65536 {
        return Err("command exceeds 1024 arguments or 64 KiB");
    }
    if open.tty && (!(1..=1000).contains(&open.cols) || !(1..=1000).contains(&open.rows)) {
        return Err("terminal dimensions must be between 1 and 1000");
    }
    Ok(())
}
