# atakit

All-in-one CLI for creation, provisioning, and management of Confidential Virtual Machines (CVMs) and the workloads running within them.

## Features

- **Image management** -- list, pull, and remove CVM base images from GitHub Releases
- **Workload scaffolding** -- create new workload projects with starter config
- **Workload builds** -- compile `atakit-workload.toml` into deterministic, deployable `.atawl` archives with integrity verification (PCR23)

## Install

Requires Rust 1.70+.

```sh
cargo install --path crates/atakit-cli
```

Or build from source:

```sh
cargo build --release -p atakit-cli
```

## Usage

```
atakit <command> [options]
```

### Image management

```sh
# List locally cached images
atakit image ls

# Include remote (GitHub Releases) images
atakit image ls --remote

# Pull an image for a specific platform
atakit image pull automata-linux:v0.1.6 --platform gcp

# Remove a local image
atakit image rm automata-linux:v0.1.6 --platform gcp
```

### Workload management

```sh
# Scaffold a new workload
atakit workload create my-workload

# Build a workload into a .atawl archive
atakit workload build -d ./my-workload
```

## Workload configuration

Each workload is defined by a single `atakit-workload.toml` file:

```toml
format = 1

[workload]
name = "my-service"
version = "v0.0.1"

image = { build = ".", containerfile = "Containerfile" }
ports = ["3000:3000"]
measured-data = ["./config/cert.pem"]

[workload.environment]
RUST_LOG = "info"
```

See [`docs/atakit-workload-toml-spec.md`](docs/atakit-workload-toml-spec.md) for the full specification.

## Project structure

```
crates/
  atakit-core/       # Shared types (Env, ProgressReporter trait)
  atakit-image/      # Image domain logic
  atakit-workload/   # Workload domain logic
  atakit-cli/        # Binary crate (presentation, progress bars, error display)
```

Library crates are frontend-agnostic -- the CLI binary owns all terminal presentation. See [`docs/architecture.md`](docs/architecture.md) for details.

## License

TODO
