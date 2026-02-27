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
just install
```

The binary will be available at `atakit`.

### Prerequisites

- **Rust**: 2024 edition or later
- **just**: Command runner ([installation](https://github.com/casey/just#installation))
- **Cloud CLI tools**: `gcloud` depending on target platform
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
            "image": "automata-linux:v0.1.1",
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
            "workload": "my-workload-tdx",
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
    image: my-workload:v0.0.1
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config:ro
      - ./cvm-agent.sock:/app/cvm-agent.sock
      - my-data:/data

volumes:
  my-data:
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
atakit workload build my-workload
```

This creates a `.tar.gz` package containing:
- Docker Compose definitions
- Measured files for attestation
- Docker images (if using bundle mode)

### 4. Publish the Workload

```bash
atakit workload publish my-workload \
  --rpc-url $RPC_URL \
  --owner-private-key $PRIVATE_KEY
```

### 5. Deploy

```bash
# Deploy to GCP
atakit deploy my-deployment --platform gcp

# Or deploy locally with QEMU
atakit deploy my-deployment --qemu
```

### 6. Check log

```bash
gcloud compute instances get-serial-port-output ${instance_name} --zone=${zone}
```

## Configuration

### atakit.json

The main project configuration file.

```json
{
    "workloads": [
        {
            "name": "workload-name",    // Workload identifier
            "version": "v0.0.1",        // Version (must start with 'v')
            "image": "automata-linux:v0.1.1",  // Base image reference
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
    image: my-app:v0.0.1
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

### CVM Agent API

Inside the CVM, workloads can access the CVM agent via a Unix socket at `/app/cvm-agent.sock`. The agent provides cryptographic signing and key management APIs.

**Socket Access with curl:**

```bash
curl --unix-socket /app/cvm-agent.sock http://localhost/<endpoint>
```

#### POST /sign-message

Sign an arbitrary message using the session key. Returns a secp256k1 signature along with session metadata.

**Request:**

```json
{
  "message": "0x48656c6c6f"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `message` | hex string | Message bytes to sign (hex-encoded with `0x` prefix) |

**Response:**

```json
{
  "signature": "0x...",
  "sessionId": "0x...",
  "sessionKeyPublic": {
    "typeId": 3,
    "key": "0x..."
  },
  "sessionKeyFingerprint": "0x...",
  "ownerKeyPublic": {
    "typeId": 3,
    "key": "0x..."
  },
  "ownerFingerprint": "0x...",
  "workloadId": "0x...",
  "baseImageId": "0x..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `signature` | hex string | secp256k1 signature (65 bytes: r \|\| s \|\| v) |
| `sessionId` | bytes32 | Current session ID |
| `sessionKeyPublic.typeId` | uint8 | Key type: 2=P-256, 3=secp256k1 |
| `sessionKeyPublic.key` | hex string | Public key bytes |
| `sessionKeyFingerprint` | bytes32 | Session key fingerprint |
| `ownerKeyPublic` | object | Owner key public identity |
| `ownerFingerprint` | bytes32 | Owner identity fingerprint |
| `workloadId` | bytes32 | Workload ID |
| `baseImageId` | bytes32 | Base image ID |

**Example:**

```bash
# Sign a message (hex-encoded "Hello")
curl --unix-socket /app/cvm-agent.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"message": "0x48656c6c6f"}' \
  http://localhost/sign-message
```

#### POST /rotate-key

Rotate the session key and register the new key on-chain. This generates a new session keypair and submits a transaction to update the session registry.

**Request:**

```json
{}
```

**Response:**

```json
{
  "sessionId": "0x...",
  "sessionKeyFingerprint": "0x...",
  "sessionKeyPublic": {
    "typeId": 3,
    "key": "0x..."
  },
  "txHash": "0x..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sessionId` | bytes32 | New session ID after rotation |
| `sessionKeyFingerprint` | bytes32 | New session key fingerprint |
| `sessionKeyPublic` | object | New session key public identity |
| `txHash` | bytes32 | On-chain transaction hash |

**Example:**

```bash
# Rotate the session key
curl --unix-socket /app/cvm-agent.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost/rotate-key
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

## Local Development with sim-agent

The `sim-agent` command provides a complete local development environment by simulating the CVM agent. It:

- Starts an embedded [Anvil](https://book.getfoundry.sh/reference/anvil/) node that forks from a remote chain
- Registers a **temporary workload** with a dev version (default: `dev-YYYYMMDD`) to the on-chain WorkloadRegistry
- Serves mock `/sign-message` and `/rotate-key` endpoints over Unix sockets

### Workflow

#### 1. Start a local Anvil node

We recommend forking from a remote chain so that the Automata contracts (SessionRegistry, BaseImageRegistry, etc.) are already available:

```bash
anvil --fork-url https://rpc.example.com --hardfork osaka
```

This gives you a local chain at `http://localhost:8545` with pre-funded test accounts.

The sim-agent requires a `SessionRegistryMock` contract on chain. You can check available contract addresses with:

```bash
atakit registry ls
```

#### 2. First run: get the dev workload ID

```bash
atakit sim-agent --rpc-url http://localhost:8545 my-workload
```

The output will show the temporary workload reference and its ID:

```
Workload: my-workload:dev-20260226 (workload_id: 0xabcd...)
```

The `--rpc-url` points to your local Anvil. The sim-agent starts a **second** embedded Anvil (default port `14345`, configurable with `--anvil-port`) that forks from it. This second Anvil is accessible at `http://0.0.0.0:14345` for external tools like `cast` or your own scripts.

> By default the dev version changes once per day (`dev-YYYYMMDD`). You can pin it with `--dev-version dev`, but make sure that version is not already registered in the WorkloadRegistry.

#### 3. Deploy contracts and whitelist the workload ID

With the first Anvil running at `localhost:8545`, you can deploy your contracts and add the dev `workload_id` from step 2 to your contract's whitelist:

```bash
# Deploy your contract to the local Anvil
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast

# Whitelist the dev workload ID
cast send <YOUR_CONTRACT> "addWorkload(bytes32)" 0xabcd... --rpc-url http://localhost:8545
```

#### 4. Build the workload package

```bash
atakit workload build my-workload
```

#### 5. Restart sim-agent

```bash
atakit sim-agent --rpc-url http://localhost:8545 my-workload
```

The sim-agent will register the temporary workload on its embedded Anvil (which forks from `localhost:8545`, inheriting your deployed contracts and whitelist) and start serving the CVM agent API on Unix sockets.

#### 6. Start your services

```bash
docker compose -f docker-compose.yml up
```

Your services can now call the simulated CVM agent via the Unix socket (e.g., `./cvm-agent.sock`) just like they would in a real CVM.

### sim-agent CLI Reference

```
atakit sim-agent [OPTIONS] --rpc-url <RPC_URL> [WORKLOAD]...
```

| Option | Description |
|--------|-------------|
| `[WORKLOAD]...` | Workload names from `atakit.json`. If omitted, all workloads are started |
| `--rpc-url <URL>` | Remote RPC endpoint (used as Anvil fork URL) |
| `--dev-version <VER>` | Dev workload version (default: `dev-YYYYMMDD`) |
| `--anvil-port <PORT>` | Anvil listen port (default: 14345) |
| `--session-registry <ADDR>` | SessionRegistry address (auto-detected if omitted) |

## Registry Query Commands

Query on-chain registry data.

### Query base image info

```bash
atakit registry query image automata-linux:v0.1.0 --rpc-url <RPC_URL>
```

Shows the full base image hierarchy: spec, platform profiles, invariant PCRs, and measurement variants.

### Query workload spec

```bash
atakit registry query workload guardian:v0.1.0 --rpc-url <RPC_URL>
```

Queries the WorkloadRegistry contract and prints the workload spec.

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
