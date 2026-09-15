# ORC CLI and Package Contract

Normative specification for the `orc` CLI and the OCI package format it produces and consumes.

## Overview

- **Binary:** `orc` (crate `orc-cli`)
- **Runtime library:** [`orc-app`](../orc-app)
- **Access protocol:** [`orc-access`](../orc-access)
- **Scope:** local package inventory, registry search, local authoring (`build`/`clone`/`pull`/`push`), single-machine app lifecycle (`install`/`start`/`stop`/`uninstall`), and authenticated service access (`forward`/`proxy`)
- **Server boundary:** the CLI uses the public access protocol for `forward` and `proxy`; authentication, authorization, routing, session storage, and tunnel execution remain server responsibilities

---

## Part 1 — Package contract

### Artifact types

| Artifact | `artifactType` | Config blob `mediaType` |
|----------|----------------|-------------------------|
| ORC app | `application/vnd.orc8r.app.v1` | `application/vnd.orc8r.app.config.v1+json` |
| OS image (KVM) | `application/vnd.orc8r.kvm.image.v1` | `application/vnd.orc8r.kvm.image.config.v1+json` |

Payload layer media types:

| Layer | `mediaType` |
|-------|-------------|
| Raw chunk | `application/vnd.orc8r.chunk.v1` |
| zstd-compressed chunk | `application/vnd.orc8r.chunk.v1+zstd` |
| Unchunked file | logical type, fallback `application/octet-stream` |

Type derivation: config file `<artifactName>.config.v<version>.json` → `config.mediaType = application/vnd.orc8r.<artifactName>.config.v<version>+json`, `artifactType = application/vnd.orc8r.<artifactName>.v<version>`.

Referrer artifact type (attached via the OCI `subject` field, never primary content): source recipe — `artifactType = application/vnd.orc8r.recipe.v1`, blob `mediaType = application/vnd.orc8r.recipe.v1+yaml` (the verbatim `artifact.yaml`). See [Source recipe attachment](#source-recipe-attachment-round-trip).

### Manifest and index

- Single **image manifest** when one universal payload supports all platforms.
- **Image index** for multi-platform packages (standard).
- Index MUST list every supported platform; entries MAY reference the same manifest digest with different `platform` descriptors.
- Manifest: `schemaVersion = 2`, `artifactType` set, config blob is exact config JSON bytes (not duplicated as payload layer).
- Optional annotation `vnd.orc8r.chunker`: `none`, `fastcdc`, or `fixed`.

### Chunking and compression

- OCI blob is the deduplication unit; chunks MUST NOT be packed into super-layers.
- Default fastcdc: min 8 MiB / avg 32 MiB / max 128 MiB; fixed default 32 MiB.
- zstd when compressed ≤ 95% of raw AND savings ≥ 64 KiB; else raw.
- Every payload layer MUST carry `org.opencontainers.image.title` (logical path, `/`-separated).
- Chunk layers MUST carry `vnd.orc8r.file.media-type`, `vnd.orc8r.chunk.offset`; compressed chunks also `vnd.orc8r.chunk.raw-digest` and `vnd.orc8r.chunk.raw-size`.
- Reassembly: group by title, sort by offset, verify digests, restore execute bit from `vnd.orc8r.file.executable`.

### App config blob

Host-agnostic JSON describing params schema, version discovery, and lifecycle phases (`install`, `start`, `drain`, `stop`, `finish`, `uninstall`).

- **Params:** closed JSON Schema subset (`string`/`boolean`/`integer`/`number` only); custom `sensitive` and `placeholder` fields.
- **Commands:** string (shell) or argv array with `${VAR}` substitution.
- **Service mode:** `start.service` names a platform service created by install scripts; runtime only starts/stops/queries it.
- **Reserved env:** `APP_VERSION`, `APP_PID`, `APP_EXIT_CODE`, etc.
- **Human metadata:** OCI manifest annotations (`org.opencontainers.image.description`, etc.) from the build recipe `annotations` field (never uploaded as content).

### OS image config

`application/vnd.orc8r.kvm.image.config.v1+json` with `os` metadata and resource requirements; multi-arch via image index.

### Build recipe

`orc build` reads `artifact.yaml` from the artifact directory and produces an OCI manifest or image index in the local cache, unless `--output` is supplied.

```yaml
artifactType: application/vnd.orc8r.app.v1
annotations:
  org.opencontainers.image.title: my-cli
  org.opencontainers.image.description: "..."
config:
  # YAML-formatted app config v1. Interpolation is supported.
files:
  - README.md
  - path: "my-cli-{os}-{arch}"
    url: "https://example.com/3.4.1/my-cli-{os}-{arch}"
    sha256: "{sha256}"
platforms:
  - { os: linux,  arch: amd64, vars: { sha256: 9f2c...e1 } }
  - { os: linux,  arch: arm64, vars: { sha256: 4ab8...77 } }
  - { os: darwin, arch: arm64, vars: { sha256: c0de...12 } }
```

- `artifactType` MUST be one of the ORC-supported artifact types in this spec; arbitrary artifact types are invalid.
- `annotations` is an optional string map applied to each produced manifest and to the image index when one is produced.
- `config` is YAML-formatted config for the selected artifact type. `orc build` serializes it as the JSON config blob for that artifact type.
- `files` is a list of local file paths or objects with `path`, optional `url`, and optional `sha256`. A string entry is equivalent to `{ path: "<entry>" }`.
- `path` is the logical artifact path and MUST be relative. Local files are resolved relative to the artifact directory.
- If `url` is present, `orc build` downloads the file when the interpolated local file is missing. If `sha256` is present and an existing local file does not match, `orc build` re-downloads it; downloaded bytes MUST match `sha256`, and mismatch is a hard failure.
- Interpolation supports `{os}`, `{arch}`, and keys from the selected platform `vars` map in string scalars under `config` and in file `path`, `url`, and `sha256` fields. Unresolved placeholders are invalid.
- Platform `vars` are build-time only: they are substituted while the package is built and never reach a deployed app. The run-time values an operator hands an app are an app assignment's `params`, a separate concept with a separate name.
- If `platforms` is omitted or empty, the artifact is universal: build once, emit a single manifest without a platform descriptor, and do not emit an OCI image index.
- If `platforms` is present, build one manifest per selected platform and emit an OCI image index whose descriptors carry the corresponding platform.
- Payload layer media types are detected from the first bytes of each file, with `application/octet-stream` as the fallback.

### Source recipe attachment (round-trip)

- `orc build` SHOULD attach the verbatim `artifact.yaml` as a referrer of the produced manifest/index: a referring manifest with `subject` = the package descriptor, `artifactType = application/vnd.orc8r.recipe.v1`, empty config (`application/vnd.oci.empty.v1+json`), and one layer holding the recipe bytes (`application/vnd.orc8r.recipe.v1+yaml`, title `artifact.yaml`).
- The recipe is stored byte-for-byte (interpolation templates, `url`/`sha256`, and the `config:` block preserved). `orc clone` recovers it exactly — no synthesis — and materializes all-platform payloads, so the working tree round-trips through `orc build` to a byte-identical package.
- Discovery uses the OCI 1.1 Referrers API where available, else the referrers **tag schema** (`sha256-<hex>` index tag derived from the subject digest), so round-trip works on registries without the endpoint (`ghcr.io`). When a push response omits the `OCI-Subject` header, the producer maintains the fallback tag index itself (pull current index, append the recipe descriptor, push back; `If-Match`/ETag where supported).
- This supersedes the low-fidelity sidecar round-trip (`pull` → `app.config.v1.json` + `annotations.json` + one platform → `push`), retained for recipe-less packages and single-platform extraction.

---

## Part 2 — CLI specification

### Reference syntax

- App references: `[registry/][namespace/]app[:version]`; missing version → OCI tag `default`.
- Bare names resolve against: explicit registry → configured default prefix → fallback `orc8r.com`.
- Resolved reference printed on stderr.
- `install` and `start` use the same resolved reference for local-cache lookup and registry fallback.
- Credentials are keyed by registry host. The default prefix MAY include a namespace, for example `orc8r.com/admte`.

### Local-cache reference resolution

`orc build` and `orc pull` are local-cache producers. `orc list`, `orc install`, `orc start`, and `orc push` consume local-cache refs when available.

- `list` MUST read cached refs from `CacheDir` and MUST NOT make registry requests.
- `install` and `start` MUST resolve the input app reference to its canonical registry/repository/tag form, then check `CacheDir` for an exact local ref before making any registry request.
- If the exact local ref exists, `install` and `start` MUST select the requested or host platform from the cached manifest/index and materialize from cached blobs. The registry MUST NOT be contacted for that ref.
- If the exact local ref does not exist, `install` and `start` MUST fall back to normal registry resolution.
- If the exact local ref exists but a referenced manifest or blob is missing or fails digest verification, the command MUST fail and MUST NOT silently fall back to the registry.
- `pull` is a registry refresh command: it MUST resolve from the registry and update the local cache, not stop at an existing local ref.
- Local refs win over remote refs by default for `install` and `start`. To refresh a tag from the registry, run `orc pull <app[:version]>` first.
- `clone` is the author round-trip: it resolves the recipe referrer and all-platform payloads from the registry (referrers API, else tag-schema fallback) and writes `artifact.yaml` + payload files, not the sidecar magic files.

Scenarios:

1. After `orc build ./examples/platform-info -t platform-info`, `orc start platform-info` resolves `platform-info:default` to the same canonical ref, installs from the cached ref, and makes no registry request.
2. After `orc build ./examples/platform-info -t platform-info`, `orc list` shows the cached canonical ref and makes no registry request.
3. After `orc build ./examples/platform-info -t platform-info:1.0.0`, `orc install platform-info:1.0.0` installs from cache and records the selected manifest digest.
4. If no local ref exists for `jenkins-agent:3.46`, `orc start jenkins-agent:3.46` follows the registry cold path.
5. If no local ref exists for `jenkins-agent:3.46`, `orc list jenkins-agent` returns no local rows; use `orc search` to discover remote registry packages.
6. If local cache contains `ghcr.io/acme/app:dev`, `orc start ghcr.io/acme/app:dev` uses the cached ref even when a remote tag with the same name exists.
7. If a cached ref points to a multi-platform index, `--platform OS/ARCH` selects that cached platform. Missing platforms fail with `not found` and list available platforms.
8. If a cached ref exists but a referenced blob is missing, `install`/`start` fail with an error instructing the user to rebuild or pull the ref again.

### Directories (XDG / `%PROGRAMDATA%\orc`)

| Dir | Purpose |
|-----|---------|
| `ConfigDir` | credentials, default registry prefix |
| `CacheDir` | content-addressed blob/manifest cache and local build refs |
| `StateDir` | install records, materialized apps |

### Commands

```
orc login [PREFIX]            orc logout [PREFIX]
orc list [FILTER]             orc search [PREFIX]
orc versions <app>            orc info <app[:version]>
orc clone <app[:version]> [DIR]
orc pull <app[:version]> [DIR] [-o DIR]
orc pull <registry>/<org>/<project>/appdata-<pool>:<point-tag> [-o DIR | --archive FILE] [--key-file PATH]... [--key HEX]...
orc build [PATH] -t REF[:TAG]... [--platform OS/ARCH]... [--output DIR]
orc push <ref[:tag[,tag…]]> [PATH…]
orc install <app[:version]> [PARAMS…]
orc start <app[:version]> [PARAMS…]
orc stop <app[:version]>
orc uninstall <app[:version]>
orc status [app]
orc cache ls | clean
orc config get|set <key> [value]
orc forward [--server HOST] [--org CODE] [--bind ADDR] [-l PORT]... TARGET...
orc proxy <PROJECT> --socks PORT [--server HOST] [--org CODE] [--bind ADDR]
orc version | orc help
```

### Auth and config commands

- `orc login [PREFIX]` authenticates against the registry host from `PREFIX` and stores credentials under that host.
- If `PREFIX` includes a namespace and no default prefix is configured, login sets the default prefix to the full prefix.
- `orc login` against the built-in fallback `orc8r.com` stores credentials but MUST NOT pin it as the default prefix, which is already in effect.
- `orc logout [PREFIX]` removes credentials for the registry host from `PREFIX`.

### Access commands

`orc forward` opens local TCP or UDP listeners for one or more ORC service targets. It
authenticates with the credential stored by `orc login`, asks the server to resolve and
authorize each target, and carries each local connection over the public access protocol.
`--via NODE` enables authorized node-relative access to a plain `host:port` target.

`orc proxy` opens a SOCKS5 listener for services in one project. Clients must send host
names through the proxy so the server can resolve and authorize them. `--via NODE` permits
authorized names or address literals outside the selected project.

### Discovery commands

`orc list [FILTER]`

- Lists refs present in the local cache. It is local-only and MUST NOT contact registries, token endpoints, or registry-specific package APIs.
- Without `FILTER`, lists all cached refs.
- With `FILTER`, narrows cached refs by matching the canonical resolved reference, repository, app name, or tag. Filtering MUST NOT change the command into a registry lookup.
- JSON output SHOULD include the canonical reference, target digest, media type, size, and platform summary when the cached manifest graph is available. Text output SHOULD omit the digest column.
- Missing or corrupt cached manifests SHOULD be surfaced in the row or reported as an error; `list` MUST NOT repair the cache by pulling from a registry.

`orc search [PREFIX]`

- Searches a registry namespace for ORC apps. This is the networked discovery command formerly represented by `orc list [PREFIX]`.
- `PREFIX` resolves using the normal registry prefix rules: explicit prefix, configured default prefix, then fallback `orc8r.com`.
- Registry search MAY use registry-specific APIs such as GitHub Packages for `ghcr.io`; other registries use OCI catalog/tag APIs when available.
- Search MAY enrich results by reading each app's `default` manifest/config from the registry.
- Search results are remote inventory only. Local cached refs are shown by `orc list`, not merged into `orc search`.

### Authoring commands

`orc build [PATH]`

- `PATH` is the artifact directory; default `.`.
- `-t, --tag REF[:TAG]` stamps an output reference. It is repeatable and at least one tag is required.
- `--platform OS/ARCH` builds only this subset for recipes with explicit `platforms`; repeatable. For universal recipes, platform filtering does not change the single-manifest output.
- `-o, --output DIR` writes an OCI layout to `DIR`; default is the local cache.
- Build does not upload anything. It writes blobs, manifests, indexes, and tag metadata needed by `orc push`.

`orc clone <app[:version]> [DIR]`

- Author round-trip. Reconstructs `artifact.yaml` (verbatim, from the `application/vnd.orc8r.recipe.v1` referrer) plus all-platform payload files into `DIR` (default: a directory named after the app); `orc build`/`orc push` then work from that tree.
- Resolves the referrer via the referrers API, else the referrers tag-schema fallback (`sha256-<hex>`); works against `ghcr.io`. Writes no `app.config.v1.json`/`annotations.json` sidecars — `config:` and `annotations:` live in the recipe.
- No recipe attached → exit 4, pointing to `orc pull`. Conflicting files → exit 5 unless `--force`; the byte-identical recipe means an unedited rebuild reproduces the original digest.

`orc pull <app[:version]> [DIR]`

- Low-level / no-recipe path; for the author round-trip prefer `orc clone`.
- Without `DIR`, pull resolves the selected manifest or index, downloads the config and payload blobs into `CacheDir`, verifies descriptors and digests, and does not materialize files.
- With `DIR`, pull materializes payload files for one resolved platform — plus the config file and a regenerated `annotations.json` — into `DIR` by their logical paths after verification. The implementation MAY still use the cache internally, but the requested output is the directory tree. `-o DIR` is accepted as another spelling of the positional `DIR`; giving both a different value is a usage error.

`orc pull <appdata-repo>:<point-tag> [-o DIR | --archive FILE] [--key-file PATH]... [--key HEX]...`

- Pull selects this path when the resolved manifest's `artifactType` is `application/vnd.orc.appdata.restore-point.v1`; an app artifact keeps the app path unchanged, and anything else keeps the errors it already produced. The tag is opaque: the canonical form is time-based (`<YYYYMMDD>T<HHMMSS>Z-s<slot>-<app id>`), and `rp-<id>` is an alias for the same manifest.
- Encryption is read from the **descriptors**, not from the artifact type: a `config`/`layers[]` media type ending in `+encrypted`, with manifest annotations `org.orc8r.enc.scheme` and `org.orc8r.enc.key-id`. When any descriptor is encrypted, pull requires a key — `--key-file <path>` or `--key <hex>`, else `ORC_ENCRYPTION_KEY`; the flags win over the variable as a whole — verifies that one of the keys given derives the key id the manifest names **before** fetching any content, and never prints a key. An unknown scheme, a manifest mixing encrypted and plain descriptors, and a missing key are all refused before the first blob request.
- `--key-file` and `--key` are both repeatable and `ORC_ENCRYPTION_KEY` takes a comma- or whitespace-separated list, because a rotated pool seals one point's layers under more than one key: dedup carries an unchanged layer forward under the key that sealed it, and no descriptor records which layer belongs to which key. Every key given goes on the ring, the key the manifest names is tried first and must be present, and keys deriving the same id are folded. A layer no key on the ring opens fails with the layer's position and digest and says to pass every key the pool holds.
- `--key-file <path>` is the recommended form and reads one 64-character hex key per line, ignoring blank lines and `#` comments; a file over 64 KiB, an unreadable path, and a file naming no key are usage errors, and no message echoes a line of the file. `--key <hex>` passes a key as a process argument, which is world-readable in the process list for as long as the pull runs and is recorded in shell history — the help text says so. Keys from `--key-file` and `--key` combine, and the command line as a whole wins over `ORC_ENCRYPTION_KEY`.
- Restored permission bits are masked to `0o777`: **setuid, setgid and the sticky bit are dropped**, both in the materialized tree and in the `--archive` tar. A restore point is bytes from another machine and pull runs as whoever invoked it, often root; recreating a setuid binary from it would grant a privilege the operator never did. The same masking applies to a node's own restore.
- Symlink targets are restored verbatim but validated when the index is parsed: a target that is absolute, that climbs out of the tree from where the link sits, that holds a `NUL`, a backslash or a colon (a drive letter, a UNC or device path, an NTFS stream), or that is over 4096 bytes, is refused before anything is created.
- Without `--archive`, pull materializes the point as the tree a restore would have written (files, directories, symlinks, permission bits, mtimes) into `-o DIR`, defaulting to `./<point-tag>` in the current directory. The tree is built under a sibling `.restoring` directory and renamed into place, so a failed pull leaves nothing. An existing output is refused unless `--force`. There is no per-layer resume: a point is materialized whole or not at all.
- With `--archive FILE`, pull writes the same `tar.zst` the pool page's download link produces, via a `.partial` name renamed only once the archive ends cleanly.
- Layers are fetched once each, in index-header order, digest-verified, and authenticated frame by frame; any integrity failure exits non-zero and leaves no output. Progress (layer *n*/*m* and bytes) goes to stderr; stdout carries `<reference>@<manifest digest>` as for an app pull.

`orc push <ref[:tag[,tag…]]> [PATH…]`

- Without `PATH`, push looks up `ref` in the local cache, uploads the referenced manifest or index and all missing config/payload blobs, then publishes the requested tag or tags.
- With `PATH` arguments, push packages and uploads those files directly for `ref`. This lower-level mode exists for direct file publishing; `orc build` is the preferred authoring path for `artifact.yaml` packages.
- Push fails with `not found` when the requested cached reference or a referenced blob is missing.

### Output and flags

- Progress → stderr; machine output → stdout.
- `--format json` on read commands (`list`, `search`, `versions`, `info`, `status`). Default format is human-readable text/table output.
- `-o, --output DIR` is reserved for commands that write artifacts/files to a destination, such as `orc build`.
- Global: `--insecure`, `--platform`, `--registry`, `--quiet`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | runtime/operational failure |
| 2 | invalid arguments |
| 3 | auth failure |
| 4 | not found |
| 5 | conflict (e.g. overwrite without `--force`) |

### Sensitive parameters

Literal values for `sensitive: true` params are forbidden. Accept `@file`, secret URIs (`vault://`, `bw://`, `op://`), or masked TTY prompt. Install records store URIs, never resolved values.

### Lifecycle semantics

- `install`/`start` resolve local refs before registry access and reuse cached blobs; idempotent install for same digest+params.
- `stop`: drain → stop → kill → finish; `--now` skips drain.
- `start` cold path: local-cache install when present, otherwise registry pull + install + start in one command.
- Service mode: install creates unit/plist/SCM; CLI only starts/stops named service.

---

## Requirements checklist

- MUST produce and consume packages per Part 1, including `artifact.yaml` builds, chunked layers, and index platform resolution.
- MUST support source round-trip: `orc build` embeds the recipe as an `application/vnd.orc8r.recipe.v1` referrer and `orc clone` recovers `artifact.yaml` verbatim, discovering it via the referrers API with referrers-tag-schema fallback.
- MUST implement command surface, reference resolution, output model, and exit codes in Part 2.
- MUST keep `orc list` local-only and use `orc search` for registry discovery.
- MUST keep blob cache content-addressed and shared across registries.
- MUST never echo secrets; prefer stdin/file for credentials.
- MUST support linux, darwin, and windows on amd64 and arm64 (linux/amd64 primary CI target).

## Open items

- GUI session provisioning for `"gui": true` apps.
- Additional registry-specific search providers beyond `ghcr.io`.
- Digest references such as `app@sha256:<digest>`.
- Whether `status` should expose health beyond running/stopped.
