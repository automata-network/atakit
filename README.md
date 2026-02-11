<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Atakit
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/automata-network/atakit)](https://github.com/automata-network/atakit/releases)

CVM base image deployment toolkit - Build, package, and deploy secure workloads to Confidential Virtual Machines.

## Overview

Atakit is a command-line tool for deploying containerized workloads to [Automata Linux](https://github.com/automata-network/automata-linux) CVMs across major cloud providers. It handles:

- Building workload packages from Docker Compose definitions
- Managing CVM base images
- Deploying to GCP, Azure, or local QEMU
- Registering workloads on-chain via smart contracts

## Installation

### From Source

```bash
git clone https://github.com/automata-network/atakit
cd atakit
cargo build --release
```

The binary will be available at `target/release/atakit`.

### Prerequisites

- **Rust**: 2024 edition or later
- **Cloud CLI tools**: `gcloud`, `az`, or `aws` depending on target platform
- **QEMU**: For local development (optional)

Cloud account permissions required:
- Create/delete VMs and disks
- Manage network and firewall rules
- Access cloud storage (for disk images)

## Quick Start

### 1. Pull a CVM Base Image

```bash
# List available images
atakit image ls

# Download an image
atakit image pull automata-linux:v0.1.0
```

### 2. Create a Workload

Create an `atakit.json` configuration file in your project directory:

```json
{
    "workloads": [
        {
            "name": "my-workload",
            "version": "v0.0.1",
            "image": "automata-linux:v0.1.0",
            "docker_compose": "./docker-compose.yml"
        }
    ],
    "disks": [
        {
            "name": "my-data",
            "size": "10GB"
        }
    ],
    "deployment": {
        "my-deployment": {
            "workload": "my-workload",
            "platforms": {
                "gcp": { "vmtype": "c3-standard-4" }
            }
        }
    }
}
```

Create a `docker-compose.yml` for your workload:

```yaml
services:
  app:
    build: .
    image: my-app:v0.0.1
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config:ro
      - app-data:/data

volumes:
  app-data:
```

Create a `Dockerfile`:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

> 💡 See [`workload_examples/`](./workload_examples) for complete working examples.

### 3. Build the Workload Package

```bash
atakit workload build my-deployment
```

This creates a `.tar.gz` package containing:
- Docker Compose definitions
- Measured files for attestation
- Docker images (if using bundle mode)

### 4. Publish the Workload

```bash
atakit workload publish my-workload \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --session-registry $REGISTRY_ADDRESS
```

### 5. Deploy

```bash
# Deploy to GCP
atakit deploy my-deployment --platform gcp

# Or deploy locally with QEMU
atakit deploy my-deployment --qemu
```

## Commands

### `atakit image`

Manage CVM base images.

```bash
atakit image ls              # List available releases
atakit image pull <image>  # Download a base image
atakit image rm <image>    # Remove a downloaded image
```

### `atakit workload build`

Build a workload package from Docker Compose definitions.

```bash
atakit workload build [DEPLOYMENTS...] [OPTIONS]

Options:
  --image-mode <MODE>  Image handling: bundle (include images) or pull (fetch at runtime)
```

### `atakit deploy`

Deploy a CVM instance.

```bash
atakit deploy <deployment-name> [OPTIONS]

Options:
  --platform <PLATFORM>  Target platform (gcp, azure)
  --qemu                 Deploy locally using QEMU
  --image <VERSION>      Override base image version
  --workload <PATH>      Path to workload package
  --private-key <KEY>    Operator private key for signing
  --quiet                Skip confirmation prompts
```

### `atakit registry`

Manage smart contract registry information.

```bash
atakit registry ls       # List contract addresses
atakit registry pull     # Pull deployment files from remote
atakit registry switch   # Switch between registry branches
```

### `atakit workload measure`

Measure a workload package and output event logs for PCR23 extension.

```bash
atakit workload measure <package.tar.gz> [OPTIONS]

Options:
  --format <FORMAT>  Output format: text or json
```

### `atakit workload publish`

Register a workload on-chain.

```bash
atakit workload publish <workload-name> [OPTIONS]

Options:
  --ttl <SECONDS>           Session time-to-live
  --private-key <KEY>       Signing key
  --rpc-url <URL>           Blockchain RPC endpoint
  --session-registry <ADDR> WorkloadRegistry contract address
  --dry-run                 Simulate without submitting
```

## Configuration

### atakit.json

The main project configuration file.

```json
{
    "workloads": [
        {
            "name": "string",           // Workload identifier
            "version": "v0.0.1",        // Version (must start with 'v')
            "image": "automata-linux:v0.1.0",  // Base image reference
            "docker_compose": "./path/to/docker-compose.yml"
        }
    ],
    "disks": [
        {
            "name": "disk-name",
            "size": "10GB",
            "encrypted": false          // Optional
        }
    ],
    "deployment": {
        "deployment-name": {
            "workload": "workload-name",
            "platforms": {
                "gcp": {
                    "vmtype": "c3-standard-4",
                    "zone": "us-central1-a"    // Optional
                },
                "azure": {
                    "vmtype": "Standard_DC4s_v3",
                    "region": "eastus"         // Optional
                }
            }
        }
    }
}
```

### Docker Compose Requirements

Atakit analyzes your `docker-compose.yml` to extract services, volumes, and configurations. Key requirements:

- **Image references**: Use full registry paths (e.g., `docker.io/library/nginx`)
- **Bind mounts**: Must be read-only (`:ro`) except for the CVM agent socket
- **Named volumes**: Each volume must be owned by exactly one service

Example:

```yaml
services:
  app:
    image: my-app:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config:ro           # Measured config
      - ./additional-data/key:/app/key:ro # Runtime data
      - app-data:/data                    # Persistent volume
      - ./cvm-agent.sock:/app/cvm-agent.sock  # Agent socket

volumes:
  app-data:
```

### Directory Structure

Workloads use a standard directory layout:

```
my-workload/
├── docker-compose.yml       # Service definitions
├── config/                  # Measured files (included in attestation)
│   └── app.conf
└── additional-data/         # Runtime data (not measured)
    └── secrets.json
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Logging level (e.g., `info`, `debug`) |
| `ATAKIT_HOME` | Override default data directory |

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# With internal commands
cargo build --features internal
```

### Running Tests

```bash
cargo test
```

### Local QEMU Testing

For local development without cloud resources:

```bash
# Deploy with QEMU
atakit deploy my-deployment --qemu

# Instance files are stored in ~/.atakit/qemu/<instance-name>/
```

## License

Apache-2.0
