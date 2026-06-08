# atakit-ng Architecture

## Overview

atakit-ng is a complete Rust rewrite of the original [atakit](https://github.com/user/atakit) CVM (Confidential Virtual Machine) base image deployment toolkit. It uses a modular workspace where each subcommand is its own library crate, enabling both CLI and future TUI (`atakit-tui`) frontends to share the same logic.

## Workspace Structure

```
atakit-ng/
  Cargo.toml                    # workspace root
  crates/
    atakit-core/                # shared types (Env, ProgressReporter trait)
    atakit-github/              # generic GitHub Releases client (reused by image+workload)
    atakit-image/               # image subcommand library
    atakit-workload/            # workload subcommand library
    atakit-cloud/               # cloud deployment library
    atakit-cli/                 # main binary
```

## Crate Responsibilities

### atakit-core

Minimal shared crate with no heavy dependencies. Provides:

- **`Env`** -- runtime context holding XDG-compliant paths (`data_dir`, `config_dir`, `cache_dir`, `image_dir`, `workload_dir`). Only global state, no project-scoped config. Resolution: `ATAKIT_*_DIR` > `XDG_*_HOME/atakit` > `$HOME/<default>/atakit`.
- **`ProgressReporter` + `ProgressHandle`** -- traits for pluggable progress reporting. Includes `NullReporter` no-op impl. This is the key abstraction that lets CLI use indicatif while TUI can use ratatui gauges.

### atakit-github

Generic, domain-free client for the GitHub Releases REST API. Used by both `atakit-image` (base image distribution) and `atakit-workload` (the github workload repository backend). Knows about releases, tags, assets, and asset upload/download; knows nothing about `.atabi` or `.atawl` archive layouts.

- **`ReleasesClient`** -- token auth, `list_releases`, `get_release_by_tag`, `try_get_release_by_tag`, `get_latest_release`, `create_release`, `delete_release`, `build_asset_upload_url`.
- **Asset I/O** -- `download_asset` (writes asset using its name as filename), `download_asset_to_path` (caller controls dest), `download_asset_bytes` (in-memory, for small sidecars), `upload_release_asset` (streams a file), `upload_release_asset_bytes`.
- **Types** -- `Release`, `Asset`, `CreateReleaseRequest`.
- **Errors** -- `GithubError`.

### atakit-image

Domain logic for public image management (ls, pull, rm). Core API is always available; clap structs are behind a `cli` feature flag. Internal image-build tooling (scaffolding, config parsing, platform profiles) lives in the separate `atakit-imgbuild` crate.

- **Error types** -- `ImageError` enum via `thiserror`. Wraps `atakit_github::GithubError`.
- **Domain types** -- `ImageRef`, `Platform`, `AssetKind`, `Release`, `Asset`, `VersionSelector`. Local `Release`/`Asset` are thin wrappers around the generic `atakit_github` types with image-specific helpers (`archive_for_platform`, `available_platforms`, `kind`).
- **GitHub client** -- `ReleasesClient` is a thin wrapper around `atakit_github::ReleasesClient` with image-specific helpers (`find_latest_image_release`, `find_latest_release_for`, `list_image_releases`, `resolve`).
- **Download logic** -- delegates to `atakit_github::download_asset` after type conversion.
- **Local store** -- `ImageStore` for local disk management (does NOT own a `ReleasesClient`). `list()` takes both `github_repo` (for API) and `local_name` (for store lookups). `download()` takes `github_repo` for API calls.
- **Archive functions** -- `create_image_archive`, `import_image_archive`, `read_manifest`. Import compresses Azure VHD files to zstd for local storage.
- **CLI arg structs** -- (behind `cli` feature) `ImageCommand`, `LsArgs`, `PullArgs`, `RmArgs`, `ExportArgs`, `ImportArgs`

### atakit-workload

All domain logic for workload management. Clap structs behind a `cli` feature flag.

- **Error types** -- `WorkloadError` enum via `thiserror`
- **Config parsing** -- `WorkloadConfig`, `ImageSource` deserialization of `atakit-workload.toml`
- **Validation** -- cross-field validation (paths, names, disk refs, signing prefixes, disk sizes, mount constraints, firewall ports)
- **Container images** -- `ContainerEngine` enum (`Docker`, `Podman`) with detect/build/pull/save via CLI shelling
- **Hashing** -- SHA-256 hashing of files and directories for integrity verification
- **Manifest generation** -- `Manifest`, `ManifestMeta` serialization types for deterministic `manifest.json`
- **Archive creation** -- `StagingDir` assembly + tar.zst `.atawl` archive output (gzip via `--gz`)
- **Build pipeline** -- `build_workload()` async orchestrator, `BuildOptions` input, `BuildResult` output
- **Scaffolding** -- `create_workload()` for creating new workload directories with starter config
- **Local store** -- `WorkloadStore` for local workload archive and metadata management (`workload_dir/<name>/<version>/meta.json` + `archive.atawl`)
- **Repository abstraction** -- `WorkloadRepository` enum dispatching between `HttpWorkloadRepository` (the in-house registry service) and `GithubWorkloadRepository` (GitHub releases). Common surface: `resolve`, `get_meta`, `download_to_file`, `list`, `upload`, `display_uri`, `supports_upload`. Wire types: `RepositoryArchiveMeta`, `RepositoryFilters`, `WorkloadCoords`, `UploadContext`.
- **CLI arg structs** -- (behind `cli` feature) `WorkloadCommand`, `CreateArgs`, `BuildArgs`, `InfoArgs`, `PublishArgs`, `DeactivateArgs`, `SpecArgs`, `LsArgs`, `PullArgs`, `PushArgs`, `ImportArgs`, `ExportArgs`, `AddArgs`, `RmArgs`

### atakit-cloud

Cloud deployment logic. Clap structs behind a `cli` feature flag.

- **Error types** -- `CloudError` enum via `thiserror`
- **Config types** -- `PlatformKind` (Gcp, Azure), `CcType` (SevSnp, Tdx), `CloudConfig`, `CloudTarget`
- **Provider trait** -- `CloudProvider` async trait with `plan_deploy`, `execute_step`, `plan_destroy`, `execute_destroy_step`, `get_instance_ip`, `get_serial_output`, `ssh_command`, `serial_command`
- **GCP provider** -- `GcpProvider` implementing `CloudProvider`. Modules: `deps`, `image` (bucket + GCE image), `firewall`, `disk`, `instance`
- **Azure provider** -- `AzureProvider` implementing `CloudProvider`. Modules: `deps`, `image` (storage account + Compute Gallery), `firewall` (NSG), `disk` (managed disks), `instance` (CVM with `--security-type ConfidentialVM`)
- **Plan types** -- `DeployStep` with GCP variants (CheckDeps, UploadImage, OpenPorts, CreateDisks, CreateInstance, WaitForAgent, InitializeWorkload) and Azure variants (CreateResourceGroup, UploadImageAzure, CreateInstanceAzure). `DestroyStep` with GCP variants (DeleteInstance, DeleteDisks, DeleteFirewall, DeleteImage, DeleteBucket) and Azure variants (DeleteResourceGroup, DeleteImageVersion).
- **State management** -- `DeployState` persisted as JSON at `<data_dir>/deployments/<target>/<instance>.state.json`. `ResourceSet` contains `gcp: Option<GcpResources>` and `azure: Option<AzureResources>`. Lifecycle: Deploying, Deployed, Failed, Destroying, Destroyed. State file deleted on destroy completion.
- **Resource naming** -- `ResourceNames::for_gcp(instance, image_ref)` for GCP; `AzureResourceNames::for_azure(instance, image_ref, region)` for Azure. All deterministic.
- **Command execution** -- `CommandRunner` trait + `ProcessRunner` for real subprocess execution via tokio. `ProcessRunner::new(verbose)` enables printing each cloud command to stderr before execution.
- **CVM agent client** -- `wait_for_agent` (polling with backoff), `post_init` (multipart POST with archive + agent config)
- **CLI arg structs** -- (behind `cli` feature) `CloudCommand`, `DeployArgs`, `DestroyArgs`, `StatusArgs`, `ListArgs`, `SshArgs`, `SerialArgs`, `UploadImageArgs`, `InitArgs`

### atakit-cli

Binary crate. Owns all presentation: output formatting, progress bars, error display.

- **`IndicatifReporter`** -- implements `ProgressReporter` using indicatif
- **Config** -- `Config` loads optional `config.toml`. `ImageConfig` holds `repositories: IndexMap<String, ImageRepositorySpec>` (each entry has `repo` + optional `credential` + optional per-repo `list_limit` override); declaration order is preserved and the first entry is the implicit default for `image pull`. `repo_local_name()` extracts local store name from `owner/repo`. `WorkloadConfig` (the `[workload]` section) holds `repositories: IndexMap<String, WorkloadRepositorySpec>` (`type = "http"` with `url`, or `type = "github"` with `repo` + optional `credential`); the first entry is the implicit default for `workload push`. `Config::workload.resolve()` accepts a config name, raw URL, or bare `owner/repo` and returns the matching spec. `Config::workload.build_repository()` takes an already-resolved `Option<String>` token (the CLI resolves it via `Config::resolve_credential` beforehand) and constructs a runtime `WorkloadRepository`. GitHub auth lives under `[github.credentials.<name>]` -- xor of `file` / `command` / `env` (+ optional `timeout_secs` for `command`), validated eagerly and resolved lazily via `Config::resolve_credential` / `Config::resolve_credentials_for`.
- **Command handlers** -- `commands/<domain>/<action>.rs` modules bridging clap args to library API. Image: `ls`, `pull`, `rm`, `export`, `import`. Workload: `create`, `build`, `info`, `publish`, `deactivate`, `spec`, `ls`, `pull`, `push`, `import`, `export`, `add`, `rm`. Cloud: `deploy`, `destroy`, `status`, `list`, `ssh`, `serial`, `upload_image`, `init`.
- **External subcommand delegation** -- unknown subcommands are delegated to `atakit-<name>` binaries on PATH (e.g. `atakit imgbuild` runs `atakit-imgbuild`).
- **On-chain integration** -- `publish`, `deactivate`, and `spec` commands interact with the on-chain WorkloadRegistry via `automata-tee-workload-measurement` contract bindings and `alloy-ext` for transaction management.
- **Entry point** -- CLI struct, dispatch

## Dependency Graph

```
atakit-cli ──> atakit-image (cli feature) ──> atakit-github ──> atakit-core
    │                ^                              ^                ^
    │                │                              │                │
    ├──> atakit-workload (cli feature) ─────────────┘                │
    │                                                                │
    ├──> atakit-cloud (cli feature) ─────────────────────────────────┘
    │
    └────────────────────────────────────────────────────────────────┘
```

### Library dependencies
- reqwest, serde, tokio, futures-util, tracing, thiserror, toml, sha2, tar, zstd, flate2
- atakit-cloud additionally: serde_json, chrono, async-trait

### CLI-only dependencies
- clap, anyhow, indicatif, tracing-subscriber, owo-colors, shell-escape, reqwest, serde_json, alloy-ext, automata-tee-workload-measurement, hex, sha2

## Key Design Decisions

1. **Decoupled `ImageStore` from `ReleasesClient`** -- local ops (list, delete) don't need HTTP setup; client is passed as parameter to methods needing network access.

2. **Pluggable progress** -- trait-based `ProgressReporter`, no indicatif dependency in library crates. CLI implements it with indicatif, TUI can implement with ratatui gauges.

3. **Typed errors** -- `thiserror` enum in library, `anyhow` only in CLI binary for top-level error reporting.

4. **Clean library/CLI split** -- run/presentation logic lives in the CLI binary, not in library crates. Library crates are pure logic that can be consumed by any frontend.

5. **Feature-gated CLI types** -- clap arg structs in `atakit-image` are behind a `cli` feature so the library can be used without pulling in clap.

6. **On-chain integration** -- workload publish/deactivate use signature-based ownership (owner key signs, relay key pays gas). The `automata-tee-workload-measurement` crate provides alloy-based contract bindings for `WorkloadRegistry`. The CLI handles key loading, signature construction, and transaction submission; library crates remain chain-unaware.
