# orc CLI

**Build, share, and run apps from your terminal.**

orc CLI is an open-source app manager for Linux, macOS, and Windows. Put your app's files, configuration, and lifecycle commands in a recipe. Build a package, share it through an OCI registry, and give users one CLI to install and run it.

Use it locally, with your team's registry, or as part of your release pipeline. Local workflows need no account or hosted service.

[Download orc CLI](https://github.com/admte/orc/releases/latest) · [Try it locally](#try-it-locally) · [Publish an app](#publish-an-app) · [Compare package managers](#how-orc-cli-fits-with-other-package-managers)

## Why orc CLI?

Your team already has a preferred way to install and run its software. orc CLI lets you put that knowledge into a recipe and make it easy for everyone to use.

- **Good defaults. Fewer setup decisions.** Opinionated conventions give apps a consistent way to install, accept configuration, and run. Put your recommended setup in the recipe and expose the choices users actually need.
- **Easy to make yours.** Adapt an existing recipe with your organization's configuration, install steps, or choice of version, then publish it in your own namespace. The recipe is a small, editable file that can live alongside your app.
- **Three operating systems. One CLI.** Use the same commands on Windows, Linux, and macOS. Platform-specific files and setup belong in the recipe, so users can follow the same workflow.
- **Bring your own storage—and your big installers.** Distribute small tools and large proprietary software bundles through OCI-compatible registries. Choose public or private storage that fits your organization, its apps, and its access requirements.
- **Quick tools and services that stay running.** Run an app in your terminal or manage it as a native background service. GUI app support is planned.
- **A straightforward app catalog.** Find apps, inspect their configuration, and discover available versions from the CLI. Recipes can also discover versions from upstream sources, helping you keep track of what is available.

From a developer utility to a company-wide software distribution, the goal is the same: make your preferred setup easy to install, easy to adapt, and familiar on every supported platform.

## Install

Download and extract the archive for your machine from [GitHub Releases](https://github.com/admte/orc/releases/latest), then put `orc` or `orc.exe` in a directory on your `PATH`.

| Platform | Release archive |
| --- | --- |
| macOS, Apple silicon | `orc_darwin_arm64.tar.gz` |
| Linux, x86-64 | `orc_linux_amd64.tar.gz` |
| Linux, ARM64 | `orc_linux_arm64.tar.gz` |
| Windows, x86-64 | `orc_windows_amd64.zip` |

Each release includes `SHA256SUMS` and build-provenance attestations.

Check your installation:

```sh
orc --version
```

## Try it locally

Build and run a small app before connecting to a registry. This example uses the system shell on Linux and macOS, and PowerShell on Windows.

Create a new directory and save this as `artifact.yaml`:

```yaml
artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: hello
config:
  params:
    required: [message]
    properties:
      message:
        type: string
        description: What to print when the app starts
  start:
    command: "{greet}"
platforms:
  - os: linux
    arch: amd64
    vars: {greet: 'printf "%s\n" "$MESSAGE"'}
  - os: linux
    arch: arm64
    vars: {greet: 'printf "%s\n" "$MESSAGE"'}
  - os: darwin
    arch: arm64
    vars: {greet: 'printf "%s\n" "$MESSAGE"'}
  - os: windows
    arch: amd64
    vars: {greet: 'Write-Output $env:MESSAGE'}
```

From that directory, run:

```sh
orc build . --format plain -t localhost/demo/hello:1.0.0
orc install localhost/demo/hello:1.0.0 --message "Hello from orc CLI"
orc start hello:1.0.0
```

The app prints:

```text
Hello from orc CLI
```

`localhost/demo/hello:1.0.0` names the package in the local cache. You do not need a registry running on localhost: `build` creates the cached package, and `install` uses it. orc CLI selects the matching platform and saves the parameter supplied at installation.

Inspect the app, change its message, or remove it:

```sh
orc start hello:1.0.0 --help
orc start hello:1.0.0 --message "Hello again"
orc list
orc status
orc uninstall hello:1.0.0
```

`list` shows cached packages; `status` shows installed apps and their state. This app exits after printing, so its state becomes `completed`.

## Publish an app

Use the same recipe to share the app through a registry. Here is an example using GitHub Container Registry (`ghcr.io`). Replace `YOUR_USERNAME` and `YOUR_NAMESPACE` with your GitHub username and your user or organization namespace; use lowercase for the namespace in package references.

For publishing from your terminal, prepare a token following [GitHub's registry authentication instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic), and make it available as `GHCR_TOKEN` in your environment.

On Linux or macOS:

```sh
printf '%s' "$GHCR_TOKEN" | orc login -u YOUR_USERNAME --password-stdin ghcr.io
```

On Windows PowerShell:

```powershell
$env:GHCR_TOKEN | orc login -u YOUR_USERNAME --password-stdin ghcr.io
```

Build and publish from the recipe directory:

```sh
orc build . --format plain -t ghcr.io/YOUR_NAMESPACE/hello:1.0.0 -t ghcr.io/YOUR_NAMESPACE/hello:default
orc push ghcr.io/YOUR_NAMESPACE/hello:1.0.0
orc push ghcr.io/YOUR_NAMESPACE/hello:default
```

Use `--format plain` when building for standard OCI registries. orc CLI's default chunked format for large files requires a registry with support for that format. Add `--push` to the build command to publish both tags immediately. The `default` tag supplies the app metadata used by catalog and version discovery; `1.0.0` names this release explicitly.

On another machine with orc CLI installed:

```sh
orc install ghcr.io/YOUR_NAMESPACE/hello:1.0.0 --message "Hello from another machine"
orc start hello:1.0.0
```

Authenticate on that machine if the package is private. GitHub packages start private; set the package's visibility to public if you want anonymous downloads. See [GitHub's package publishing guidance](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pushing-container-images).

To make your registry namespace the default:

```sh
orc config set default-registry ghcr.io/YOUR_NAMESPACE
```

You can then use `hello:1.0.0` for packages in that namespace. Fully qualified references always make the registry explicit. Without a configured default, unresolved short references use `orc8r.com`.

## Package your own binaries and scripts

The greeting app keeps its entire command in the recipe. For a compiled app, include the binaries you already build:

```text
my-app/
  artifact.yaml
  bin/
    my-app-linux-amd64
    my-app-linux-arm64
    my-app-darwin-arm64
    my-app-windows-amd64.exe
```

An `artifact.yaml` for that layout:

```yaml
artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: my-app
config:
  start:
    command: ["./bin/my-app-{os}-{arch}{ext}"]
files:
  - "bin/my-app-{os}-{arch}{ext}"
platforms:
  - {os: linux, arch: amd64, vars: {ext: ""}}
  - {os: linux, arch: arm64, vars: {ext: ""}}
  - {os: darwin, arch: arm64, vars: {ext: ""}}
  - {os: windows, arch: amd64, vars: {ext: ".exe"}}
```

Provide the listed files before building, with executable permissions for Unix binaries. orc CLI assembles packages from those files; compile your application with its usual build tools first.

Build every declared platform, or select one whose binary you have available:

```sh
orc build . --format plain -t localhost/demo/my-app:1.0.0
orc build . --platform linux/amd64 --format plain -t localhost/demo/my-app:linux-amd64
```

Recipes also support shared files, URL downloads with SHA-256 checks, and lifecycle hooks. See the [platform-info example](https://github.com/admte/orc/tree/main/crates/orc-cli/examples/platform-info) for a package with shared and platform-specific files.

### Configure and manage apps

App recipes declare their own parameters. orc CLI validates required values and types, shows them in app-specific `--help`, and makes them available to lifecycle commands. For example, the `message` parameter above becomes `MESSAGE` in the app's environment.

Starting an installed app without parameters reuses its saved values. If you supply parameters again, provide the complete required set.

For a long-running app packaged as `my-app:1.0.0`:

```sh
orc install localhost/demo/my-app:1.0.0
orc start my-app:1.0.0
```

For a foreground app, `start` stays attached to your terminal. On Linux and macOS, use another terminal to inspect and stop it:

```sh
orc status my-app
orc stop my-app:1.0.0
orc uninstall my-app:1.0.0
```

On Windows, stop a foreground app with **Ctrl+C in its original terminal**, then uninstall it. Stopping foreground apps from another terminal is not supported in v0.5.0.

For background operation, an app recipe can declare a native service. orc CLI integrates with systemd on Linux, launchd on macOS, and the Service Control Manager on Windows. The recipe can declare the service's command and restart policy. Permissions depend on the app and service configuration. The `--detach` option is not implemented for foreground apps in v0.5.0.

### Cache, inspect, and automate

These registry commands use your published package reference:

```sh
orc info ghcr.io/YOUR_NAMESPACE/hello:1.0.0
orc versions ghcr.io/YOUR_NAMESPACE/hello
orc pull ghcr.io/YOUR_NAMESPACE/hello:1.0.0
orc clone ghcr.io/YOUR_NAMESPACE/hello:1.0.0 ./hello-source
```

- `info` reads package metadata from the registry.
- `versions` lists registry tags and, when configured by the recipe, discovers upstream app versions.
- `pull` downloads package content into the local cache. A complete cached package can be installed later without fetching it again; app hooks may still need network access.
- `clone` retrieves the attached recipe and packaged files for inspection and modification. This requires a package published with an attached recipe; it does not recover an application's original source-code repository.

For scripts and dashboards:

```sh
orc list --format json
orc status --format json
orc info ghcr.io/YOUR_NAMESPACE/hello:1.0.0 --format json
```

`search` can discover packages where the registry supports listing. Registry authentication and listing support vary.

## How orc CLI fits with other package managers

### Choose versions independently of your Linux distribution

With [APT](https://manpages.debian.org/unstable/apt/apt.8.en.html), [DNF](https://dnf.readthedocs.io/en/stable/command_ref.html), or [pacman](https://man.archlinux.org/man/pacman.8.en), your usual choices are the versions packaged in your configured repositories. Getting another version can mean adding a repository or building your own package.

**With orc CLI, the app recipe controls which versions are available.** Publish the builds you need, or write a recipe that discovers upstream releases and downloads the selected version during installation. That recipe can support multiple releases without publishing a separate package for each one.

Need a newer SDK or an older vendor release approved by your team? You can support it in your recipe independently of your distribution's release schedule, provided compatible application files are available.

### Use the same CLI on Windows, Linux, and macOS

[Homebrew](https://docs.brew.sh/Homebrew-on-Linux) serves macOS and Linux, including Linux environments under WSL. [Chocolatey](https://docs.chocolatey.org/en-us/choco/commands/install/) and [WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/) serve Windows. A team using all three operating systems typically combines these tools and maintains different installation instructions.

**orc CLI runs natively on all three.** Use the same install, start, stop, and uninstall commands, with platform-specific files and setup defined in the app recipe. One recipe can cover your team's Windows workstations, Linux servers, and Macs.

Keep your system package manager for operating-system updates and shared dependencies. Use orc CLI for app versions, configuration, and distribution that you control.

## Planned features

- **Install and run GUI apps.** Bring desktop applications into the same app workflow on Windows, Linux, and macOS.
- **Connect your secret manager.** Supply sensitive app parameters through custom secret providers, with integrations planned for HashiCorp Vault, Bitwarden, 1Password, AWS Secrets Manager, and others.

These features are planned and are not available in the current release.

## Standalone, with an optional path to ORC8R

orc CLI also powers app workflows in [orc8r.com](https://orc8r.com). You can use the CLI on its own with local packages and your own registry; an ORC8R account is only needed for the product's account-based features.

## Build from source

The repository pins its Rust toolchain in [`rust-toolchain.toml`](https://github.com/admte/orc/blob/main/rust-toolchain.toml).

```sh
git clone https://github.com/admte/orc.git
cd orc
cargo build --release --locked -p orc-cli
```

The executable is `target/release/orc` on Linux and macOS, or `target/release/orc.exe` on Windows.

Ideas, bug reports, and contributions are welcome through [GitHub Issues](https://github.com/admte/orc/issues) and pull requests.

## License

[MIT](https://github.com/admte/orc/blob/main/LICENSE) · Copyright 2026 ADM Tech LLC and ORC8R Contributors.
