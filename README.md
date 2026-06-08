# atakit

All-in-one CLI for creation, provisioning, and management of Confidential Virtual Machines (CVMs) and the workloads running within them.

## Features

- **Image management** -- list, pull, import/export CVM base images from GitHub Releases
- **Workload lifecycle** -- scaffold, build, publish, and manage workload archives (`.atawl`) with deterministic integrity verification (PCR23)
- **Workload registry** -- push/pull workload archives to/from an HTTP registry
- **On-chain integration** -- publish and deactivate workload specs on the on-chain WorkloadRegistry; query specs by workload ID
- **Cloud deployment** -- deploy workloads to CVM instances on GCP and Azure, with full orchestration of images, firewall rules, disks, and instances
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

## Quickstart (GCP)

The minimal path to deploy a workload to a Confidential VM on GCP. You'll need
the [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) authenticated
(`gcloud auth login`) and a container engine (Docker or Podman) for building
workloads.

### 1. Generate keys

Deployments register on-chain, which needs two secp256k1 (Ethereum-style)
private keys:

- **owner** -- signs the on-chain CVM registration.
- **gas** -- pays for that transaction; its address must hold funds on the
  target chain.

Any standard web3 key works (MetaMask "export private key", `openssl`, etc.).
With [Foundry's `cast`](https://book.getfoundry.sh/):

```sh
mkdir -p ~/.config/atakit
cast wallet new            # prints an address + a 0x... private key
```

Save each private key into its own file, then lock down permissions:

```sh
printf '0xYOUR_OWNER_KEY' > ~/.config/atakit/owner.key
printf '0xYOUR_GAS_KEY'   > ~/.config/atakit/gas.key
chmod 600 ~/.config/atakit/*.key
```

Fund the **gas** key's address on your target chain so the
registration transaction(s) can land.

### 2. Write a minimal config

Create `~/.config/atakit/config.toml`. (`atakit` also writes a fully-commented
template here on first run -- this is the minimal subset needed for a GCP
deploy.)

```toml
# Where to pull CVM base images from (GitHub Releases).
[image.repositories]
automata = { repo = "automata-network/automata-linux" }

# On-chain registries the CVM registers against. Values below are the
# Hoodi testnet deployment.
[chains.hoodi]
rpc_url             = "https://1rpc.io/hoodi"
session_registry    = "0xB247950fBBFCE245641e433AFd7d8884328CE5A1"
workload_registry   = "0xda6430E06385F7516963f8A3B4e87beBb89860F8"
base_image_registry = "0xCbe56f9B73c822679Cf36DcF8D99434E0f1588Ca"
expire_offset       = 3600

# secp256k1 private keys, read from the files created in step 1.
[keys.owner]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/owner.key"

[keys.gas]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/gas.key"

# Your GCP account + deployment zone.
[cloud.providers.gcp]
platform = "gcp"
project  = "my-gcp-project"
region   = "asia-southeast1-b"

# Defaults shared by every target, so targets stay terse.
[cloud.defaults]
chain        = "hoodi"
registration = "optional"
owner_key    = "owner"
gas_wallet   = "gas"

# A deploy target: a machine type on the provider above.
[cloud.targets.gcp-tdx]
provider = "gcp"
vmtype   = "c3-standard-4"
```

### 3. Build and deploy

```sh
# Search for images on remote
atakit image ls --remote

# Pull the base image for GCP into the local store
atakit image pull <image_name>:<version> gcp

# Scaffold + build a workload (or point -d at your own).
atakit workload create my-service
atakit workload build -d ./my-service

# Deploy it. The base image is uploaded to your GCP project automatically.
atakit cloud deploy my-service:v0.0.1 --target gcp-tdx --image <image_name>:<version>
```

The instance is named `<workload>-<target>` by default, so:
`atakit cloud status my-service-gcp-tdx` shows progress and
`atakit cloud destroy my-service-gcp-tdx` tears it down.

See [Configuration](#configuration) for the full set of options.

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

# Query a specific GitHub repository
atakit image ls --remote --repo automata-network/debug-linux

# Pull an image for a specific platform
atakit image pull automata-linux:v0.1.6 gcp

# Remove a local image
atakit image rm automata-linux:v0.1.6

# Export/import portable .atabi archives
atakit image export automata-linux:v0.1.6
atakit image import automata-linux-v0.1.6-gcp.atabi
```

### Workload management

```sh
# Scaffold a new workload
atakit workload create my-workload

# Build a workload into a .atawl archive
atakit workload build -d ./my-workload

# Inspect a built workload (shows PCR23 measurement)
atakit workload info my-service:v0.0.1

# Push/pull workloads to a repository
atakit workload push my-service:v0.0.1
atakit workload pull my-service:v0.0.1

# Publish workload spec on-chain
atakit workload publish my-service:v0.0.1

# Query on-chain workload spec
atakit workload spec <workload-id>
```

### Cloud deployment

Requires a configured target in `config.toml` (see [Configuration](#configuration)).

```sh
# Deploy a workload to a cloud CVM
atakit cloud deploy my-service:v0.0.1 --target my-gcp --image automata-linux:v0.1.6

# Deploy with a custom instance name
atakit cloud deploy my-service:v0.0.1 --target my-gcp --image automata-linux:v0.1.6 --name my-instance

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

### Local (QEMU) deploy

For offline iteration, `atakit cloud deploy` can target a local QEMU VM via
the `qemu` platform. This is a **functional harness**, not a real TEE: boot
is measured into a software TPM (swtpm) and the portal `/init` → workload
flow runs end-to-end against `localhost`, but there is no genuine TDX/SEV
quote — so on-chain registration defaults to `off` when the qemu target has
no chain configured.

Requirements on the host:

- `qemu-system-x86_64`, `qemu-img`, `swtpm` on `PATH`
- `/dev/kvm` accessible
- A TPM-enabled OVMF (ie, compiled with `TPM2_ENABLE=TRUE` and `TPM2_CONFIG_ENABLE=TRUE`)
- `socat` (only needed for `atakit cloud ssh` to attach to the serial console)

Minimal config:

```toml
[cloud.providers.qemu]
platform = "qemu"
uefi     = "~/.local/share/atakit/firmware/ovmf.fd"

[cloud.targets.qemu-local]
provider = "qemu"
image    = "automata-linux:v0.1.6"   # uses qemu_disk.qcow2 from the image store
```

Then:

```sh
atakit image pull automata-linux:v0.1.6 qemu
atakit cloud deploy my-service:v0.0.1 --target qemu-local

atakit cloud ls                              # qemu deployments listed alongside cloud
atakit cloud serial my-service-qemu-local    # tails serial.log (read-only)
atakit cloud ssh    my-service-qemu-local    # interactive serial console (Ctrl-] to detach)
atakit cloud destroy my-service-qemu-local   # stops qemu, removes overlays
```

`vmtype` is ignored for qemu (fixed 2 vCPU / 4 GiB). Data disks declared in
the workload manifest become per-instance qcow2 overlays attached via virtio
with `serial=<device_name>`, matching the cloud agent's discovery convention.
Workload ports are forwarded guest→same host port (so `curl localhost:<port>`
just works); the portal status/init ports are forwarded to ephemeral host
ports to avoid collisions between instances.

`cloud ssh` on qemu doesn't run a real ssh client — there's no sshd in the
guest — it `socat`s into a unix socket wired to the VM's serial chardev for
an interactive console.

## Configuration

### Operator config (`config.toml`)

Located at `$XDG_CONFIG_HOME/atakit/config.toml` (default
`~/.config/atakit/config.toml`). `atakit` writes a fully-commented template
there on first run. Precedence: CLI args > env vars > this file > defaults.

Targets reference a provider, chain, and keys *by name*, so those are declared
once and shared. The example below covers the common sections:

```toml
# ─── Chains ───────────────────────────────────────────────────────────
# Named on-chain configs. Cloud targets and publish commands reference a
# chain by name. workload_registry / base_image_registry are derived from
# session_registry on-chain when omitted.
[chains.hoodi]
rpc_url             = "https://1rpc.io/hoodi"
session_registry    = "0xB247950fBBFCE245641e433AFd7d8884328CE5A1"
workload_registry   = "0xda6430E06385F7516963f8A3B4e87beBb89860F8"
base_image_registry = "0xCbe56f9B73c822679Cf36DcF8D99434E0f1588Ca"
expire_offset       = 3600

# ─── Keys ─────────────────────────────────────────────────────────────
# `provisioned` keys supply the private key via exactly one of
# file / command / env. `self_generated` keys are created by the portal
# at init time (no source). type: es256k | es256 | rs256.
[keys.owner]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/owner.key"

[keys.gas]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/gas.key"
# command = ["pass", "show", "atakit/gas"]   # alternative source
# env     = "ATAKIT_GAS_KEY"                  # alternative source

# ─── GitHub credentials ───────────────────────────────────────────────
# Token sources for private repos. Each sets exactly one of
# file / command / env. Public repos need no credential.
# [github.credentials]
# private = { command = ["pass", "show", "github/atakit"] }

# ─── Image repositories ───────────────────────────────────────────────
# GitHub repos holding .atabi base-image archives. First entry is the
# implicit default for `image pull`.
[image.repositories]
automata = { repo = "automata-network/automata-linux" }
# private  = { repo = "myorg/private-images", credential = "private" }

# ─── Workload repositories ────────────────────────────────────────────
# `type = "http"` (registry service) or `type = "github"` (releases).
# First entry is the implicit default for `workload push`.
# [workload.repositories]
# main = { type = "http",   url  = "https://registry.example.com" }
# gh   = { type = "github", repo = "myorg/workloads", credential = "private" }

# ─── Publish ──────────────────────────────────────────────────────────
# References for `workload publish` (overridable with --chain / --owner-key).
[publish]
chain     = "hoodi"
owner_key = "owner"

# ─── Cloud ────────────────────────────────────────────────────────────
# Providers hold the account + region; targets reference a provider, chain,
# and keys by name. [cloud.defaults] fills in fields a target omits.
# Active registration requires owner_key, but it may be provisioned or
# self_generated when an ephemeral owner is acceptable. gas_wallet and
# sp1_payer identify keys the CVM uses for relay/prover submissions: they may
# be provisioned keys supplied by the relay owner, or self_generated keys whose
# public keys are accepted or registered by the relay. registration = "off"
# can omit chain and keys entirely.
[cloud.providers.gcp]
platform = "gcp"
project  = "my-gcp-project"
region   = "us-central1-a"

[cloud.providers.azure]
platform     = "azure"
subscription = "your-subscription-id"
region       = "eastus"

[cloud.defaults]
chain        = "hoodi"
registration = "optional"           # "required" | "optional" | "off"
owner_key    = "owner"
gas_wallet   = "gas"

[cloud.targets.gcp-tdx]
provider = "gcp"
vmtype   = "c3-standard-4"          # c3-standard-* → TDX, n2d-standard-* → SEV-SNP
image    = "automata-linux:v0.1.6"

[cloud.targets.azure-snp]
provider = "azure"
vmtype   = "Standard_DC4as_v5"      # *as_v5/v6 → SEV-SNP, *es_v6 → TDX
image    = "automata-linux:v0.1.6"
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
  atakit-cloud/      # Cloud deployment logic (GCP + Azure providers, state management)
  atakit-cli/        # Binary crate (presentation, progress bars, error display)
```

Library crates are frontend-agnostic -- the CLI binary owns all terminal presentation. See [`docs/architecture.md`](docs/architecture.md) for details.

## License

TODO
