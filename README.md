# ORC

ORC provides a command-line tool for building and running OCI-distributed apps,
the shared app runtime behind it, and the public service-access protocol used by
the forwarding commands.

The workspace contains:

- `orc-cli`: the `orc` command, including app build, install, start, stop,
  uninstall, restore, forward, and proxy workflows.
- `orc-app`: OCI package handling and the shared app lifecycle runtime.
- `orc-access`: generated client and server interfaces for the public access
  protocol.

## Build and test

Install the Rust toolchain declared in `rust-toolchain.toml`, then run:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

Build the release CLI with:

```sh
cargo build --release --locked -p orc-cli
```

Pushing a `v*` tag matching all three crate versions publishes the supported CLI
archives, `SHA256SUMS`, and signed build-provenance attestations to GitHub Releases.

CLI usage and package examples are documented in
[`crates/orc-cli/README.md`](crates/orc-cli/README.md).

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
