# atakit-ng Architecture

## Overview

atakit-ng is a complete Rust rewrite of the original [atakit](https://github.com/user/atakit) CVM (Confidential Virtual Machine) base image deployment toolkit. It uses a modular workspace where each subcommand is its own library crate, enabling both CLI and future TUI (`atakit-tui`) frontends to share the same logic.

## Workspace Structure

```
atakit-ng/
  Cargo.toml                    # workspace root
  crates/
    atakit-core/                # shared types (Env, ProgressReporter trait)
    atakit-image/               # image subcommand library
    atakit-cli/                 # main binary
```

## Crate Responsibilities

### atakit-core

Minimal shared crate with no heavy dependencies. Provides:

- **`Env`** -- runtime context holding `~/.atakit` paths (`atakit_dir`, `image_dir`). Only global state, no project-scoped config.
- **`ProgressReporter` + `ProgressHandle`** -- traits for pluggable progress reporting. Includes `NullReporter` no-op impl. This is the key abstraction that lets CLI use indicatif while TUI can use ratatui gauges.

### atakit-image

All domain logic for image management. Core API is always available; clap structs are behind a `cli` feature flag.

- **Error types** -- `ImageError` enum via `thiserror`
- **Domain types** -- `ImageRef`, `Platform`, `AssetKind`, `Release`, `Asset`, `VersionSelector`
- **GitHub client** -- `ReleasesClient` for GitHub Releases API (with optional token auth)
- **Download logic** -- download + decompress using `&dyn ProgressReporter`
- **Local store** -- `ImageStore` for local disk management (does NOT own a `ReleasesClient`)
- **CLI arg structs** -- (behind `cli` feature) `ImageCommand`, `LsArgs`, `PullArgs`, `RmArgs`

### atakit-cli

Binary crate. Owns all presentation: output formatting, progress bars, error display.

- **`IndicatifReporter`** -- implements `ProgressReporter` using indicatif
- **Command handlers** -- `run_ls`, `run_pull`, `run_rm` bridging clap args to library API
- **Entry point** -- CLI struct, dispatch

## Dependency Graph

```
atakit-cli ──> atakit-image (cli feature) ──> atakit-core
    │                                              │
    └──────────────────────────────────────────────┘
```

### Library dependencies
- reqwest, serde, tokio, futures-util, tracing, thiserror

### CLI-only dependencies
- clap, anyhow, indicatif, tracing-subscriber

## Key Design Decisions

1. **Decoupled `ImageStore` from `ReleasesClient`** -- local ops (list, delete) don't need HTTP setup; client is passed as parameter to methods needing network access.

2. **Pluggable progress** -- trait-based `ProgressReporter`, no indicatif dependency in library crates. CLI implements it with indicatif, TUI can implement with ratatui gauges.

3. **Typed errors** -- `thiserror` enum in library, `anyhow` only in CLI binary for top-level error reporting.

4. **Clean library/CLI split** -- run/presentation logic lives in the CLI binary, not in library crates. Library crates are pure logic that can be consumed by any frontend.

5. **Feature-gated CLI types** -- clap arg structs in `atakit-image` are behind a `cli` feature so the library can be used without pulling in clap.
