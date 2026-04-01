# Workload Management CLI

How the atakit CLI enables workload providers and operators to manage workloads locally and interact with remote registries. Covers the full lifecycle: build, import, list, push/pull, add from chain, export, and remove.

See [workload-registry-spec.md](workload-registry-spec.md) for the registry service specification.

## Configuration

### Registry remotes

Git-style named remotes in `config.toml`:

```toml
[registry]
default = "main"

[registry.remotes.main]
url = "https://registry.example.com"

[registry.remotes.staging]
url = "https://staging-registry.example.com"
```

Env override: `ATAKIT_REGISTRY_URL` sets the URL for the default remote (creates a "default" remote if none configured).

Resolution: `--registry` CLI arg > default remote > error. The `--registry` flag accepts either a remote name or a raw URL.

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

### Status symbols

- `◉` local+tracked - present in the local store (metadata and archive) and tracked in a registry
- `◔` local - present in the local store only (metadata and archive), not tracked in a registry
- `◌` tracked - tracked in a registry with local metadata only (e.g. from `workload add`)
- `◊` remote - only exists on a remote registry, not present in the local store
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
| `--remote` | Show remote workloads from registry |
| `--all` | Show both local and remote |
| `--name <filter>` | Filter by name substring |
| `--owner <fingerprint>` | Filter by owner fingerprint (remote only) |
| `--limit N` | Max results for remote queries |
| `--registry <name\|url>` | Override registry |

Default: local only (like `image ls`).

Display: name-grouped table with blank-on-repeat names, status symbols, truncated SHA256.

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

Download a workload from a registry into the local store.

| Flag | Description |
|------|-------------|
| `--registry <name\|url>` | Override registry |
| `--verify` | Verify SHA256 against on-chain spec (requires RPC config) |
| `--force` | Force overwrite if already in store |

Downloads the archive, inspects it, and saves both blob and metadata.

### `atakit workload push [source]`

Upload a workload to a registry.

| Flag | Description |
|------|-------------|
| `-d <dir>` | Workload directory (for auto-detect) |
| `--registry <name\|url>` | Override registry |

Source can be: `name:version` (from store), a file path, or auto-detected via `find_versioned_archive()`.

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

`workload info`, `workload publish`, and `workload deactivate` now accept `name:version` store references in addition to file paths. If the positional argument looks like `name:version`, the CLI resolves it from the store's blob path.

## Typical Workflows

### Provider workflow

```
# 1. Build (automatically imports to store)
atakit workload build

# 2. Register on-chain
atakit workload publish secure-signer:v0.0.1 --owner-key ... --relay-key ...

# 3. Upload to registry
atakit workload push secure-signer:v0.0.1

# 4. Verify listing
atakit workload ls --all
```

### Operator workflow

```
# 1. Browse available workloads
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
| `crates/atakit-workload/src/registry.rs` | `RegistryClient`, `RegistryMeta`, API types |
| `crates/atakit-cli/src/commands/workload/ls.rs` | List command handler |
| `crates/atakit-cli/src/commands/workload/pull.rs` | Pull command handler |
| `crates/atakit-cli/src/commands/workload/push.rs` | Push command handler |
| `crates/atakit-cli/src/commands/workload/import.rs` | Import command handler |
| `crates/atakit-cli/src/commands/workload/export.rs` | Export command handler |
| `crates/atakit-cli/src/commands/workload/add.rs` | Add command handler |
| `crates/atakit-cli/src/commands/workload/rm.rs` | Remove command handler |
| `crates/atakit-cli/src/config.rs` | `RegistryConfig`, `RemoteConfig` |
