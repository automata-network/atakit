# atakit

All-in-one CLI for creation, provisioning, and management of Confidential Virtual Machines (CVMs) and the workloads running within them.

## Features

- **Image management** -- list, pull, import/export CVM base images from GitHub Releases
- **Workload lifecycle** -- scaffold, build, publish, and manage workload archives (`.atawl`) with deterministic integrity verification (PCR23)
- **Workload registry** -- push/pull workload archives to/from an HTTP registry
- **On-chain integration** -- publish and deactivate workload specs on the on-chain WorkloadRegistry; query specs by workload ID
- **Cloud deployment** -- deploy workloads to CVM instances on GCP (Azure planned), with full orchestration of images, firewall rules, disks, and instances
- **Deployment management** -- status, SSH, serial console, destroy with selective resource preservation

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
atakit image pull automata-linux:v0.1.6 gcp

# Remove a local image
atakit image rm automata-linux:v0.1.6

# Export/import portable .atabi archives
atakit image export automata-linux:v0.1.6 gcp -o image.atabi
atakit image import image.atabi
```

### Workload management

```sh
# Scaffold a new workload
atakit workload create my-workload

# Build a workload into a .atawl archive
atakit workload build -d ./my-workload

# Inspect a built workload (shows PCR23 measurement)
atakit workload info my-service v0.0.1

# Push/pull workloads to a registry
atakit workload push my-service v0.0.1
atakit workload pull my-service v0.0.1

# Publish workload spec on-chain
atakit workload publish my-service v0.0.1

# Query on-chain workload spec
atakit workload spec <workload-id>
```

### Cloud deployment

Requires a configured target in `config.toml` (see [Configuration](#configuration)).

```sh
# Deploy a workload to a cloud CVM
atakit cloud deploy my-instance my-service:v0.0.1 --target my-gcp

# Upload a base image to the cloud without deploying
atakit cloud upload-image automata-linux:v0.1.6 --target my-gcp

# Initialize an already-deployed instance with a workload
atakit cloud init my-instance my-service:v0.0.1 --target my-gcp

# Check deployment status
atakit cloud status my-instance --target my-gcp

# List all deployments
atakit cloud ls

# SSH into a running instance
atakit cloud ssh my-instance --target my-gcp

# View serial console output
atakit cloud serial my-instance --target my-gcp

# Tear down a deployment
atakit cloud destroy my-instance --target my-gcp
```

## Configuration

### Operator config (`config.toml`)

Located at `$XDG_CONFIG_HOME/atakit/config.toml`:

```toml
[cloud]
rpc_url = "https://..."
session_registry = "0x..."

[cloud.targets.my-gcp]
platform = "gcp"
cc_type = "sev-snp"
project = "my-project"
region = "us-central1"
vmtype = "n2d-standard-2"
```

### Workload config (`atakit-workload.toml`)

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
  atakit-image/      # Image domain logic (GitHub Releases, local store)
  atakit-workload/   # Workload domain logic (build, registry, on-chain)
  atakit-cloud/      # Cloud deployment logic (GCP provider, state management)
  atakit-cli/        # Binary crate (presentation, progress bars, error display)
```

Library crates are frontend-agnostic -- the CLI binary owns all terminal presentation. See [`docs/architecture.md`](docs/architecture.md) for details.

## License

TODO
