# ORC

Build, publish, and manage apps from your terminal.

ORC is a standalone, open-source CLI for building, publishing, and running apps
from OCI registries. It also powers app workflows in [orc8r.com](https://orc8r.com).

## Install

Download the `orc` binary for your platform from [GitHub Releases](https://github.com/admte/orc/releases):

| Platform | Asset |
|----------|-------|
| macOS arm64 | `orc_darwin_arm64.tar.gz` |
| Linux amd64 | `orc_linux_amd64.tar.gz` |
| Linux arm64 | `orc_linux_arm64.tar.gz` |
| Windows amd64 | `orc_windows_amd64.zip` |

```bash
tar -xzf orc_darwin_arm64.tar.gz   # macOS / Linux
orc --version
```

## Quick start

Replace `registry.example.com/team/my-app:1.0` with your app's OCI reference:

```bash
orc install registry.example.com/team/my-app:1.0
orc list
orc start my-app:1.0
```

To stop a running app, use `orc stop my-app:1.0` from another terminal. On Windows,
foreground apps use Ctrl+C in the terminal that started them. Once stopped,
`orc uninstall my-app:1.0` removes the app.

### Use apps from orc8r.com

```bash
echo "$TOKEN" | orc login -u you --password-stdin orc8r.com
orc search
orc pull github-runner
orc list
orc info github-runner
orc start github-runner --github-url https://github.com/acme --github-token @token.txt
```

## Local storage

Configuration, cache, and state can be relocated independently:

| Override | Linux / macOS default | Windows default |
| --- | --- | --- |
| `ORC_CONFIG_DIR` | `$HOME/.config/orc` | `%LOCALAPPDATA%/orc/config` |
| `ORC_CACHE_DIR` | `$HOME/.cache/orc` | `%LOCALAPPDATA%/orc/cache` |
| `ORC_STATE_DIR` | `$HOME/.local/state/orc` | `%LOCALAPPDATA%/orc/state` |

If `LOCALAPPDATA` is absent, Windows uses `%USERPROFILE%/AppData/Local` as its base.

## Build from source

Requires Rust 1.88+ (see the repository root `rust-toolchain.toml`):

```bash
git clone https://github.com/admte/orc.git
cd orc
cargo build --release -p orc-cli
./target/release/orc --version
```

## orc8r.com service connections

For orc8r.com users, `orc forward` and `orc proxy` provide authenticated connections
to services through the product. See [SPEC.md](SPEC.md) for the command reference.

## Remote shells and commands

Use the same `orc login` credentials, `--server` and `--org` options as forwarding:

```sh
orc sh n_d000000000001
orc exec n_d000000000001 -- whoami
orc exec -it n_d000000000001 -- bash
orc exec -it n_d000000000001 -- powershell.exe
cat script.sh | orc exec -i n_d000000000001 -- sh
```

`sh` opens the node's default interactive shell, including on Windows. `exec`
requires an executable after `--`; `-i/--stdin` forwards input and `-t/--tty`
allocates a terminal. `--interactive` is an alias for `--stdin`. Without `-i`,
non-TTY processes receive EOF on stdin. Arguments retain their boundaries;
use an explicit shell for expressions (`sh -c 'pwd && ls'` or
`powershell.exe -Command 'Get-Service'`).

Without a TTY, stdout and stderr remain separate and binary-safe. The remote
process's exit code becomes the CLI exit code. With a TTY, output is combined,
resizes are forwarded, and Ctrl-C interrupts the remote command. Closing the
connection cancels execution; commands are never automatically retried. Unix
process groups and Windows jobs clean up child processes. For non-TTY Windows
processes, interruption terminates the job because an agent service has no
interactive console to receive Ctrl-C.

Processes run as the node agent's account and require the existing terminal
permission. Connections use the authenticated HTTP/2 access service and routed
agent tunnels, with forwarding's session and tunnel limits. No SSH daemon is
required. The CLI, server and agent must support the execution protocol; older
peers refuse it rather than falling back to shell-command emulation.

## Development

- **CI:** pull requests and pushes to `main` run formatting, lint, build, and test checks for the public workspace.
- **Release:** a `v*` tag builds the four CLI archives, publishes SHA-256 checksums,
  signs build-provenance attestations, and creates the GitHub Release.

Changes to package runtime behavior belong in the `orc-app` crate in this repo;
this crate tracks the `orc` binary and CLI UX. The `orc-access` crate supports
orc8r.com service connections. See [SPEC.md](SPEC.md) for the package contract
and CLI specification.

## License

MIT
