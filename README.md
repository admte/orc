# ORC

Build, publish, and manage apps from your terminal.

ORC is the open-source CLI for managing the apps used in [orc8r.com](https://orc8r.com).
Use it to package apps, distribute them through OCI registries, and run them on
Linux, macOS, and Windows.

## Manage the app lifecycle

- **Build and publish** app packages to OCI registries.
- **Install and run** apps on your machine.
- **Stop, uninstall, and restore** apps as your needs change.
- **Browse and inspect** packages before running them.

## Get started

Download the CLI for your platform from [GitHub Releases](https://github.com/admte/orc/releases).
See the [CLI guide](crates/orc-cli/README.md) for installation, app workflows,
and registry examples.

## Development

The `orc-cli` crate provides the `orc` command, and `orc-app` provides the shared
app lifecycle runtime.

Install the Rust toolchain declared in `rust-toolchain.toml`, then run:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

Build the release CLI with:

```sh
cargo build --release --locked -p orc-cli
```

Pushing a `v*` tag matching the workspace crate versions publishes the supported CLI
archives, `SHA256SUMS`, and signed build-provenance attestations to GitHub Releases.

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
