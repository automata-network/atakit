# Workload Repositories CLI

How the atakit CLI enables workload providers and operators to manage workloads locally and interact with remote workload repositories. Covers the full lifecycle: build, import, list, push/pull, add from chain, export, and remove.

A **workload repository** is a remote source of `.atawl` archives keyed by their on-chain workload ID. Two backends are supported:

- **`http`** -- the in-house workload registry service. See [workload-registry-spec.md](workload-registry-spec.md) for the wire protocol.
- **`github`** -- a GitHub repository whose releases hold workload archives.

The on-chain [WorkloadRegistry](cvm-registry/) contract is the authority for workload specs (name, version, PCR specs, owner). A workload repository is just a content store for the actual `.atawl` archive blobs, with cached metadata for efficient queries.

## Configuration

Workload repositories are declared under `[workload.repositories]` in `~/.config/atakit/config.toml`. Each entry is a tagged TOML table with a `type` discriminator. Declaration order matters: the first entry is the implicit default for single-target commands like `workload push`.

```toml
[workload.repositories]
main       = { type = "http",   url  = "https://registry.example.com" }
staging    = { type = "http",   url  = "https://staging-registry.example.com" }
gh-public  = { type = "github", repo = "automata-network/workload-archives",  credential = "public" }
gh-private = { type = "github", repo = "myorg/private-workloads",             credential = "private" }
```

Section form is also valid if an entry wants inline comments:

```toml
[workload.repositories.main]
type = "http"
url  = "https://registry.example.com"
```

The `--repository` CLI flag accepts:

- a configured repository name (e.g. `main`, `gh-public`),
- a raw `http(s)://...` URL (treated as an anonymous HTTP repository),
- a bare `owner/repo` path (treated as an anonymous GitHub repository).

### How `--repository` interacts with declaration order

Declaration order in `[workload.repositories]` determines the implicit default for single-target commands and the visit order for multi-target commands:

| Command | When `--repository` set | When `--repository` omitted |
|---|---|---|
| `workload push` | Push to that one repository | Push to the **first declared** entry in `[workload.repositories]` |
| `workload pull` | Probe only that repository | **Probe every configured repository** in declaration order |
| `workload ls --remote` | Query only that repository | **Query every configured repository** in parallel and merge |

Pull and remote listing are inherently multi-source: they fan out across every configured entry so a workload can be found and compared wherever it lives. Reorder entries in `[workload.repositories]` if the implicit default for `workload push` should change.

### GitHub authentication

GitHub-backed repositories access the API through **named credentials** defined under `[github.credentials]`. Each credential sets exactly one token source:

```toml
[github.credentials]
public  = { file    = "~/.config/atakit/tokens/public" }
private = { command = ["pass", "show", "github/atakit-private"] }
ci      = { env     = "GH_CI_TOKEN" }
```

- `file` -- path to a `chmod 600` file containing the token. `~/` is expanded. Whitespace is trimmed.
- `command` -- exec the given argv (no shell), read stdout as the token. 30-second default timeout; override per-credential via `timeout_secs` for slow helpers (biometric prompts, remote HSMs).
- `env` -- read from a named environment variable.

A workload repository references its credential by name via `credential = "<name>"`. Entries without a `credential` field make anonymous GitHub requests (public reads only; `workload push` against such an entry errors with a clear "requires credential" message). A credential with `contents: write` scope is required for `workload push` against a GitHub repository.

## GitHub Repository Layout

Each workload version is published as one GitHub release.

| Field | Value |
|---|---|
| Tag | `<name>/<version>` -- e.g. `secure-signer/v0.0.1` (git refs forbid `:`, so `/` is used) |
| Release name | `<name>:<version>` -- the human-readable heading |
| Body | Newline-delimited `key: value` lines: `Workload ID`, `Manifest SHA256`, `PCR23`, `Archive size` |
| Assets | `<name>-<version>.atawl` (the archive) and `<name>-<version>.meta.json` (sidecar) |

The sidecar `meta.json` mirrors the HTTP service's response shape (camelCase). When listing or pulling, the sidecar is the source of truth for `workload_id`, `sha256`, `archive_hash`. If the sidecar is missing (hand-curated repo), values are derived from the release body and asset metadata, with unknown fields shown as `-`.

### Resolving by hex workload ID

`atakit workload pull 0xabc...` against a GitHub repo lists the most recent 100 releases and matches the `Workload ID:` field in each release body. The list endpoint already returns release bodies, so this requires no per-release follow-up. For repos with more than ~100 versions, prefer `name:version` lookups.

## Local Store

Workload archives and metadata are stored at `~/.local/share/atakit/workloads/`:

```
workloads/
  <name>/
    <version>/
      meta.json       # WorkloadMeta: workload_id, sha256, owner, on_chain_spec, etc.
      archive.atawl   # The .atawl archive blob (optional - metadata-only entries allowed)
```

`WorkloadStore` in `atakit-workload/src/store.rs` manages this layout. Follows the same pattern as `ImageStore` for base images.

`WorkloadMeta.repositories` (formerly `registries`, retained as a serde alias for old files) tracks the URIs this archive has been pulled from or pushed to. HTTP repos appear as `https://...`; GitHub repos appear as `github://owner/repo`.

### Status symbols

- `◉` local+tracked - present in the local store (metadata and archive) and tracked in a repository
- `◔` local - present in the local store only (metadata and archive), not tracked in a repository
- `◌` tracked - tracked in a repository with local metadata only (e.g. from `workload add`)
- `◊` remote - only exists in a remote repository, not present in the local store
- `✗` revoked - present locally or remotely but marked as revoked

## Workload Reference Format

Two forms for identifying workloads:

| Form | Example | Used by |
|------|---------|---------|
| `name:version` | `secure-signer:v0.0.1` | All commands |
| `0x<workload_id>` | `0xabcd...` (66 chars) | `pull`, `add` |

The `name:version` form mirrors the existing `ImageRef` pattern. The CLI resolves it to a workload ID using `keccak256(abi.encode_params(keccak256("CVM_WORKLOAD_V1"), name, version))`.

## Commands

### `atakit workload ls`

List local and/or remote workloads.

| Flag | Description |
|------|-------------|
| `--remote` | Query every configured repository |
| `--all` | Show both local and remote |
| `--name <filter>` | Filter by name substring |
| `--owner <fingerprint>` | Filter by owner fingerprint (remote only) |
| `--limit N` | Max results for remote queries |
| `--repository <name\|url\|owner/repo>` | Pin to a single repository (skips fan-out) |
| `-w`, `--wide` | Show the full source repository list without truncation |

Default: local only (like `image ls`).

When the same `(name, version)` workload appears in more than one repository, the entries are merged into a single row. The `REPOSITORIES` column lists every repository that advertises the workload. Two divergence checks run after the merge:

1. **Inter-repository sha256 disagreement** -- if two repositories serve different `sha256` values for the same `(name, version)`, the table keeps the first value seen, emits a `warning:` line on stderr, and renders the row in red.
2. **Repository vs on-chain disagreement** -- if `[publish] rpc_url` and `[publish] session_registry` are configured, every entry's advertised sha256 is converted to a final PCR23 (via `SHA-256(zeros_32 || event_hash)`) and compared to the on-chain `WorkloadRegistry` spec's PCR23 entry. A mismatch warns to stderr and renders the row in red. Workloads not yet registered on-chain (or repos without PCR23 entries) are silently skipped.

Both checks set the same "divergent" flag, so the row is rendered in red regardless of which check triggered. Use the stderr warnings to find out which one fired.

Display: name-grouped table with blank-on-repeat names, status symbols, truncated SHA256, and a REPOSITORIES column when remote results are present.

### `atakit workload import <archive>`

Import a local `.atawl` file into the store.

| Flag | Description |
|------|-------------|
| `--force` | Overwrite if already exists |

Inspects the archive to extract name, version, and SHA256. Copies the blob and writes metadata.

### `atakit workload export <name:version>`

Export an archive from the store to a file.

| Flag | Description |
|------|-------------|
| `-o <dir>` | Output directory (default: cwd) |

Copies `archive.atawl` from the store as `{name}-{version}.atawl`.

### `atakit workload pull <ref>`

Download a workload from a repository into the local store.

| Flag | Description |
|------|-------------|
| `--repository <name\|url\|owner/repo>` | Pin the source repository (skips discovery) |
| `--verify` | Verify SHA256 against on-chain spec (requires RPC config) |
| `--force` | Force overwrite if already in store |

By default `pull` queries every configured repository to find which one(s) hold the requested workload, then:

* **0 hits** -- error (`workload <ref> was not found in any configured repository`).
* **1 hit** -- pull from that repository, no prompt.
* **N hits** -- show a numbered list and prompt the user to pick. In a non-interactive session (no TTY on stdin) the prompt is replaced with an error suggesting `--repository`.

`--repository` bypasses discovery entirely: only the chosen repository is queried, and any error there is final.

Probe failures (e.g. 502 from a flaky HTTP service) emit a `warning:` line on stderr and the repository is skipped; other repositories can still serve the pull.

After download, four integrity checks run automatically:

1. **Manifest identity** -- the archive's manifest `name`/`version` are hashed via `keccak256` and compared to the requested workload ID. Catches "wrong workload served".
2. **Manifest sha256** -- the manifest event hash is compared against `RepositoryArchiveMeta.sha256` from the probe. Catches "manifest tampered after the repository indexed it".
3. **Archive sha256** -- the full downloaded file is SHA-256 hashed and compared to `RepositoryArchiveMeta.archive_hash`. Catches "archive corrupted or tampered in transit".
4. **On-chain PCR23** -- if `[publish] rpc_url` and `[publish] session_registry` are configured, the archive's final PCR23 is compared to the on-chain `WorkloadRegistry` spec. Catches "repository compromise" -- the on-chain registry is the canonical source of truth.

Check (1) always runs. Checks (2) and (3) are skipped when the repository didn't advertise that field (hand-curated GitHub repo without sidecar `.meta.json`). Check (4) is best-effort:

* `[publish]` not configured -- silent skip (the user hasn't opted in to chain verification).
* RPC connection fails, or the on-chain spec has no PCR23 entry -- the pull still succeeds, but a `warning:` is emitted on stderr so transient or configuration problems are visible instead of silently ignored.
* Workload not yet registered on-chain -- silent skip (valid during a mirror pull before publish).
* PCR23 mismatch -- **always** a hard error regardless of mode. If both the repo and the chain claim to have the workload but they disagree on PCR23, something is seriously wrong and the pull aborts.

Pass `--verify` to make check (4) strict: it then errors instead of silently skipping when any of the conditions above hold. Use this in CI or anywhere you need a guarantee that the on-chain attestation actually happened.

The source repository's URI is appended to `WorkloadMeta.repositories` in the local store on success.

### `atakit workload push [source]`

Upload a workload to a repository.

| Flag | Description |
|------|-------------|
| `-d <dir>` | Workload directory (for auto-detect) |
| `--repository <name\|url\|owner/repo>` | Override the repository |

Source can be: `name:version` (from store), a file path, or auto-detected via `find_versioned_archive()`.

For HTTP repositories the upload is a single `PUT /v1/workloads/{id}` request. For GitHub repositories push (a) refuses if a release with the canonical tag already exists, (b) creates a new release with tag `<name>/<version>`, name `<name>:<version>`, and body containing the workload ID and PCRs, then (c) uploads both the `.atawl` archive and the sidecar `.meta.json`. A `GITHUB_TOKEN` with `contents: write` is required.

### `atakit workload add <ref>`

Add a workload from on-chain spec to the local store (metadata only, no blob).

| Flag | Description |
|------|-------------|
| `--rpc-url <url>` | Ethereum RPC URL |
| `--session-registry <addr>` | Session registry contract address |

Queries on-chain spec and owner, creates or merges metadata entry.

### `atakit workload rm <name:version>`

Remove a workload from the local store.

| Flag | Description |
|------|-------------|
| `--blob-only` | Remove only the archive blob, keep metadata |

### `atakit workload build`

Build always imports the archive into the local store by default. Use `--no-store` to skip the import step.

### Store refs in existing commands

`workload info`, `workload publish`, and `workload deactivate` accept `name:version` store references in addition to file paths. If the positional argument looks like `name:version`, the CLI resolves it from the store's blob path.

## Typical Workflows

### Provider workflow (HTTP repository)

```
# 1. Build (automatically imports to store)
atakit workload build

# 2. Register on-chain
atakit workload publish secure-signer:v0.0.1 --owner-key ... --relay-key ...

# 3. Upload to default repository
atakit workload push secure-signer:v0.0.1

# 4. Verify listing
atakit workload ls --all
```

### Provider workflow (GitHub repository)

```
# 1. Build, register on-chain (as above)
atakit workload build
atakit workload publish secure-signer:v0.0.1 --owner-key ... --relay-key ...

# 2. Push to a github repository (creates release + uploads assets)
GITHUB_TOKEN=ghp_... atakit workload push secure-signer:v0.0.1 \
    --repository owner/workload-archives
```

### Operator workflow

```
# 1. Browse available workloads (uses default repository)
atakit workload ls --remote --name secure-signer

# 2. Download to local store
atakit workload pull secure-signer:v0.0.1 --verify

# 3. Inspect locally
atakit workload info secure-signer:v0.0.1

# 4. Deploy to CVM
atakit cloud deploy secure-signer:v0.0.1 --target my-gcp --image automata-linux:v0.1.6
```

### Tracking on-chain workloads

```
# Add metadata from chain (no blob download)
atakit workload add secure-signer:v0.0.1

# Later, pull the actual archive
atakit workload pull secure-signer:v0.0.1
```

## Implementation

| File | Purpose |
|------|---------|
| `crates/atakit-workload/src/store.rs` | `WorkloadStore`, `WorkloadMeta`, `WorkloadEntry` |
| `crates/atakit-workload/src/repository/mod.rs` | `WorkloadRepository` enum, `RepositoryArchiveMeta`, `RepositoryFilters`, `WorkloadCoords`, `UploadContext` |
| `crates/atakit-workload/src/repository/http.rs` | `HttpWorkloadRepository` (the in-house registry service) |
| `crates/atakit-workload/src/repository/github.rs` | `GithubWorkloadRepository` (GitHub releases) |
| `crates/atakit-github/src/` | Generic GitHub Releases client + asset I/O shared with atakit-image |
| `crates/atakit-cli/src/commands/workload/ls.rs` | List command handler |
| `crates/atakit-cli/src/commands/workload/pull.rs` | Pull command handler |
| `crates/atakit-cli/src/commands/workload/push.rs` | Push command handler |
| `crates/atakit-cli/src/commands/workload/import.rs` | Import command handler |
| `crates/atakit-cli/src/commands/workload/export.rs` | Export command handler |
| `crates/atakit-cli/src/commands/workload/add.rs` | Add command handler |
| `crates/atakit-cli/src/commands/workload/rm.rs` | Remove command handler |
| `crates/atakit-cli/src/config.rs` | `WorkloadConfig`, `WorkloadRepositorySpec` |
