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
