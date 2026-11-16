# atakit

All-in-one CLI for creation, provisioning, and management of Confidential Virtual Machines (CVMs) and the workloads running within them.

## Features

- **Image management** -- list, pull, import/export CVM base images from GitHub Releases
- **Workload lifecycle** -- scaffold, build, publish, and manage workload archives (`.atawl`) with deterministic integrity verification (PCR23)
- **Workload registry** -- push/pull workload archives to/from an HTTP registry
- **On-chain integration** -- publish and deactivate workload specs on the on-chain WorkloadRegistry; query specs by workload ID
- **Cloud deployment** -- deploy workloads to CVM instances on GCP, AWS, and Azure, with full orchestration of images, firewall rules, disks, and instances
- **Deployment management** -- status, SSH, serial console, destroy with selective resource preservation

## Install

Use **Atakit CLI 0.7.8** with **Automata Linux v0.3.8** or
**v0.3.8-debug**. Both images require workload manifest **format 16** at initial
startup and after reboot. New workload templates use format 16. The workload
library also reads older formats; that does not make them deployable on v0.3.8.

Download `atakit-v0.7.8-linux-amd64` or `atakit-v0.7.8-macos-arm64` from the
[v0.7.8 release](https://github.com/automata-network/atakit/releases/tag/v0.7.8).
Verify the matching `.sha256` file before putting
the binary on your `PATH`. `atakit --version` must print `atakit 0.7.8`.

To build from the signed release tag:

```sh
git checkout v0.7.8
cargo install --locked --path crates/atakit-cli
```

The checkout includes the `atakit-portal-chain` verifier in
`crates/atakit-portal-chain`.

For disk profiles, Local SSD, encryption queues, THP and CPU controls, see the
[runtime configuration guide](docs/runtime-configuration.md).
For owner-signed file and environment replacements, see
[unmeasured-data updates](docs/unmeasured-data-update-spec.md).

## Quickstart (GCP)

The minimal path to deploy a workload to a Confidential VM on GCP. You'll need
the [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) authenticated
(`gcloud auth login`) and a container engine (Docker or Podman) for building
workloads.

GCP C4 deployment requires CLI v0.7.5 or later. Set the target's `vmtype` to
`c4-standard-N`, where `N` is 2, 4, 8, 16, 24, 32, 48, 96, 144, or 192.
Atakit selects Intel TDX and validates the provider's zone against the
[C4 TDX supported zones](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations#c4-standard-).
Local SSD and bare-metal C4 types are not supported. Confirm that the selected
image’s signed measurement pack includes the target machine type.
Atakit creates C4 workload disks as Hyperdisk Balanced volumes.

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
session_registry    = "0x7575BceC155b272077C87aD3Ae5Ef54Cf9DC6601"
# workload_registry and base_image_registry are resolved from session_registry.
tee_backend         = "auto"       # SNP -> ZK, TDX -> Solidity

[owner_operations]
op_expiry_seconds   = 3600

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

The example sets `owner_operations.op_expiry_seconds` to 3600 seconds. If
omitted, it defaults to 300 seconds. Initial session registration uses this
window for both proof generation and transaction submission; slow network
proving can exhaust the default. This is the validity period of an owner-signed
operation, not the lifetime of the registered session. A longer window keeps
that signed operation valid for longer.

### 3. Build and deploy

```sh
# Search for images on remote
atakit image ls --remote

# Pull the base image for GCP into the local store
atakit image pull <image_name>:<version> gcp

# Scaffold + build a workload (or point -d at your own).
atakit workload create my-service
atakit workload build -d ./my-service

# If the workload declares package data paths, measured files default to
# ./my-service/measured-data. Unmeasured declarations default to
# ./my-service/unmeasured-data for path expansion/validation, but their
# contents are supplied later during deploy/init.
atakit workload build -d ./my-service \
  --measured-data-root ./public-inputs \
  --unmeasured-data-root ./unmeasured-data

# Deploy it. The base image is uploaded to your GCP project automatically.
atakit cloud deploy my-service:v0.0.1 --target gcp-tdx --image <image_name>:<version> \
  --unmeasured-data-root ./operator-secrets
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
atakit image pull automata-linux:v0.3.8-debug gcp

# Remove a local image
atakit image rm automata-linux:v0.3.8-debug

# Export/import portable .atabi archives
atakit image export automata-linux:v0.3.8-debug
atakit image import automata-linux-v0.3.8-debug-gcp.atabi
```

### Workload management

```sh
# Scaffold a new workload
atakit workload create my-workload

# Build a workload into a .atawl archive
atakit workload build -d ./my-workload

# Package paths are logical absolute paths. By default, measured files are read
# from ./my-workload/measured-data. The unmeasured root is used to expand or
# validate unmeasured declarations; contents are not embedded in the archive.
atakit workload build -d ./my-workload \
  --measured-data-root ./measured-data \
  --unmeasured-data-root ./unmeasured-data

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
atakit cloud deploy my-service:v0.0.1 --target my-gcp --image automata-linux:v0.3.8-debug

# Check the same deployment without creating cloud resources or initialization credentials
atakit cloud deploy my-service:v0.0.1 --target my-gcp --image automata-linux:v0.3.8-debug --check-only

# Deploy with a custom instance name
atakit cloud deploy my-service:v0.0.1 --target my-gcp --image automata-linux:v0.3.8-debug --name my-instance

# Upload a base image to the cloud without deploying
atakit cloud image upload automata-linux:v0.3.8-debug --provider gcp

# Initialize an already-deployed instance with a workload
atakit cloud init my-instance my-service:v0.0.1 --target my-gcp

# Supply unmeasured data at deploy/init time when the workload declares it.
atakit cloud deploy my-service:v0.0.1 --target my-gcp \
  --image automata-linux:v0.3.8-debug \
  --unmeasured-data-root ./unmeasured-data
atakit cloud init my-instance my-service:v0.0.1 --target my-gcp \
  --unmeasured-data-root ./unmeasured-data

# Check deployment status
atakit cloud status my-instance --target my-gcp

# Verify live portal and session status once, or refresh until Ctrl+C
atakit cloud status my-instance --target my-gcp --live --verify
atakit cloud status my-instance --target my-gcp --live --verify --watch --interval 5

# Save public diagnostic results, including when checks fail
atakit cloud diagnose my-instance --target my-gcp --report diagnostics.json

# Optionally export already-collected local logs to a separate, unredacted file
atakit cloud diagnose my-instance --target my-gcp --report diagnostics-with-logs.json \
  --workload-log web.log --log-report workload-logs.json

# List all deployments
atakit cloud ls

# SSH into a running instance
atakit cloud ssh my-instance --target my-gcp

# View serial console output
atakit cloud serial my-instance --target my-gcp

# Tear down a deployment
atakit cloud destroy my-instance --target my-gcp
```

`cloud deploy` checks the resolved archive, image policy, initialization keys and
prover configuration before creating cloud resources. It also makes read-only
cloud requests to check authentication and the selected VM type. With active
registration, it checks that `SessionRegistry.workloadRegistry()` and
`SessionRegistry.baseImageRegistry()` match the configured addresses. At one
block number, it checks revocation and authenticates `getSignedWorkload` and
`getSignedVariant` responses against the requested publisher-qualified IDs.
It checks the signed workload's base-image permission and ordinary attribute
requirements for the target platform and machine when both policies have valid
signatures. A missing signature, or a signed-policy getter that reverts or returns
no data, produces a warning and a `Continue? [y/N]` prompt before VM creation:

> Publisher policy signatures are missing or unavailable. Deployment may fail if
> the selected image requires signed policies.

Accepting the warning allows deployment with older unsigned records; it does not
bypass Portal's startup requirements. `--yes` accepts the warning automatically.
`--check-only` reports it without prompting. Multi-target deployments ask during
serial checks, before shared image uploads. Invalid signatures, malformed
responses, RPC failures, revoked records, denied base-image permissions, and
incompatible signed policies still stop deployment. No image capability field
or version-based decision is used.

For Azure SEV-SNP, it checks all published `@firmware-` variants for the target
machine (up to 128 profile variants). The exact firmware variant remains
`NOT CHECKED` until Portal reads PCR0/PCR2 after boot. A provider-native image
without a canonical identity reports its base-image policy, variant and workload
permission as `NOT CHECKED`; `--base-image` supplies that identity. Workload
signature and registry-address checks still apply.

These checks do not verify live measurements, hardware evidence, or secret
provisioning eligibility. `cloud status --live` also displays Portal's
`startup_checks` report: policy IDs, publisher fingerprints, signature outcomes,
and failed PCR comparisons. These are Portal-local diagnostics. The CLI keeps
its independent attestation result separate. Older Portals without this field
show `NOT REPORTED`.

`cloud status --live` also shows Portal storage capacity, usage, available space,
and mounted baby-root quota counters. Available space below 10% shows `LOW SPACE`.
Locked or unmounted disks show `UNAVAILABLE`; old images show `NOT REPORTED`.
Cached readings include their sample time and stale state. Shared filesystems
are identified; capacities are not additive, including loop-backed storage.
These warnings do not delete files, resize disks, or stop workloads.

`cloud diagnose --report diagnostics.json` includes startup signature results,
policy IDs and digests, PCR comparisons, per-service startup readiness, and
storage readings. Independent TLS/session verification outcomes remain separate.
Exports include fixed failure codes and the failed startup stage instead of raw
error strings or readiness command output, which could contain secrets. Missing
fields on older images remain null. No credentials, passphrases, or workload
logs are added; explicit workload-log export remains separate. Status readers
accept up to 256 KiB to accommodate these bounded diagnostic sections.
After reboot, a running Portal may no longer report the original initialization
identity. Diagnosis marks that history `NOT CHECKED` and still independently
verifies the current session. A reported identity mismatch remains a failure.

`--check-only` runs the same checks without prompting, creating a deployment
record, generating initialization credentials, or uploading an image to a cloud.
It can import a supplied archive into the local image store and resolve configured
key sources, just as deployment does. Multi-target deployment checks every target
before shared image uploads. Image-only and `--skip-init` skip initialization
checks; registration-off skips registry checks and prover credentials.

CPU quota checks cover AWS Standard On-Demand instances using recent CloudWatch
usage, supported GCP regional CPU families and the all-regions CPU quota, and
Azure regional and VM-family CPU quotas. Insufficient quota stops deployment.
Unavailable usage, permissions, or quota mappings show `NOT CHECKED`. These
checks cover each target separately; they do not reserve quota, combine the CPU
needs of multiple targets, or check disk/network quotas and current host capacity.
Cloud queries time out after 30 seconds each; chain resolution and registry checks
have separate 60-second limits. Passing these checks does not replace portal
attestation or on-chain verification during initialization.

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

The portal currently requires a provisioned owner key even when registration is
off. Create a development-only key (keep it outside the repository), then use
this minimal config:

```sh
umask 077
openssl rand -hex 32 > ~/.config/atakit/qemu-owner.key
```

```toml
[keys.qemu-owner]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/qemu-owner.key"

[cloud.providers.qemu]
platform = "qemu"
uefi     = "~/.local/share/atakit/firmware/ovmf.fd"

[cloud.targets.qemu-local]
provider  = "qemu"
image     = "automata-linux:v0.3.8-debug"   # uses qemu_disk.qcow2 from the image store
owner_key = "qemu-owner"
```

Without `owner_key`, the CLI currently sends a self-generated owner descriptor
that the portal rejects because it has no private key. This is a known
producer/consumer mismatch; the explicit development key above is the working
path.

Then:

```sh
atakit image pull automata-linux:v0.3.8-debug qemu
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
session_registry    = "0x7575BceC155b272077C87aD3Ae5Ef54Cf9DC6601"
# workload_registry and base_image_registry are resolved from session_registry.
tee_backend         = "auto"       # "auto" | "solidity" | "zk"
# prover             = "sp1-network" # required when selecting ZK explicitly

[owner_operations]
op_expiry_seconds   = 3600

# ─── Keys ─────────────────────────────────────────────────────────────
# `provisioned` keys supply the private key via exactly one of
# file / command / env. `self_generated` keys are created by the portal
# at init time (no source), but the owner key must currently be provisioned.
# type: es256k | es256 | rs256.
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

# Prover profiles are deployment policy, separate from workload manifests.
# Reference this profile from a chain that uses ZK.
[provers.sp1-network]
backend    = "sp1"
execution  = "network"
credential = "gas"                 # may reference a dedicated key instead

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
# Every current /init request requires a provisioned owner_key. gas_wallet
# identifies the chain relayer and may be self_generated. ZK prover credentials
# are selected by a named [provers] profile referenced from [chains]. With
# registration = "off", chain, gas_wallet, and prover credentials may be
# omitted, but the owner-key producer/consumer mismatch described above still
# requires an owner_key until the implementation is fixed.
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
image    = "automata-linux:v0.3.8-debug"

[cloud.targets.azure-snp]
provider = "azure"
vmtype   = "Standard_DC2as_v5"      # *as_v5/v6 → SEV-SNP, *es_v6 → TDX
image    = "automata-linux:v0.3.8-debug"
```

### CPU choices and open-file limits

The workload publisher controls which CPU settings an operator may change.
Omitted permissions deny operator tuning. Publisher-fixed settings remain fixed.
Use `--runtime-config runtime.toml` on `cloud deploy` or `cloud init` for initial
choices. To inspect or stage later choices:

```sh
atakit cloud status my-instance --live --json
atakit cloud configure my-instance --runtime-config runtime.toml --check
atakit cloud configure my-instance --runtime-config runtime.toml
```

`configure` saves choices for the next full workload startup. It does not change
running containers. Flags override the standalone file, which overrides target
configuration and then shared defaults. Platform support is checked at startup.
See the [complete runtime.toml grammar](docs/runtime-configuration.md#standalone-runtimetoml-grammar)
for all accepted fields, types, value limits and omission rules. See the
[CPU control specification](docs/workload-cpu-controls.md)
for permissions and status fields.

A workload developer can set `nofile` on the main workload, a dependency or a
baby slot. This sets both the soft and hard per-process open-file limit; sockets
count toward it. Omission emits JSON `null` and uses the base-image default.
For v0.3.8, both the default and ceiling are 1,048,576. These are signed workload
settings, not operator overrides. See the
[workload specification](docs/atakit-workload-toml-spec.md).

### Workload config (`atakit-workload.toml`)

Each workload is defined by a single `atakit-workload.toml` file:

```toml
format = 16

[package]
measured-data = ["/config/cert.pem"]
unmeasured-data = ["/runtime.env"]

[workload]
name = "my-service"
version = "v0.0.1"

image = { build = ".", containerfile = "Containerfile" }
ports = ["3000:3000"]
measured-data = ["/config/cert.pem"]
unmeasured-data = ["/runtime.env"]
unmeasured-env-file = "/runtime.env"

[workload.environment]
RUST_LOG = "info"

[workload.attributes]
"atakit.attestation.v1.tee.intel-tdx.debug.enabled" = [false]
"atakit.attestation.v1.tee.amd-sev-snp.debug.enabled" = [false]
```

Package data paths are logical absolute paths. `/config/cert.pem` is read from
`<workload-dir>/measured-data/config/cert.pem` by default and included in the
archive. `/runtime.env` is declared in the archive, but its contents are
supplied from `<workload-dir>/unmeasured-data/runtime.env` at deploy/init time.
Use `--measured-data-root` on `workload build` or `workload info --dir` to read
measured data from another root. Use `--unmeasured-data-root` on
`workload build` / `workload info --dir` to expand and validate unmeasured
declarations from another root, and on `cloud deploy`, `cloud init`, or
`workload init` to supply an operator-specific allowlisted subset.
`--unmeasured-data-dir` remains as a deprecated alias for the deploy/init
commands.

Format 16 always emits the measured `manifest.json` `config.attributes` map,
even when `[workload.attributes]` is absent. Custom attribute names accept
string arrays. An empty custom array requires the base image to declare the
attribute and accepts any declared value; it does not deny every value. The six
reserved verified TEE names use Boolean arrays, Intel TDX TCB status names, or
one packed AMD SEV-SNP bytes32 value as defined by the full specification.

See [`docs/atakit-workload-toml-spec.md`](docs/atakit-workload-toml-spec.md) for the full specification.

## Project structure

```
crates/
  atakit-cvm-types/     # Chain-independent CVM protocol types
  atakit-cvm-encoding/  # Canonical identifier and PCR-policy encodings
  atakit-core/         # Shared types and progress-reporting abstractions
  atakit-config/       # Shared operator-config schema and secret resolution
  atakit-github/       # GitHub Releases client
  atakit-image/        # Base-image download, cache, and metadata
  atakit-workload/     # Workload build, registry, and on-chain operations
  atakit-attestation/  # Network-free attestation verification
  atakit-attestation-client/ # Read-only RPC and portal verification client
  atakit-cloud/        # GCP, Azure, AWS, and QEMU deployment backends
  atakit-cli/          # CLI parsing, presentation, and external subcommands
```

Library crates are frontend-agnostic -- the CLI binary owns all terminal presentation. See [`docs/architecture.md`](docs/architecture.md) for details.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

### Optional application readiness

Add `[workload.readiness]` or `[dependencies.<name>.readiness]` to wait for a
program inside that service's container before startup continues:

```toml
[dependencies.db.readiness]
command = ["/app/check-ready", "--database"]
interval-seconds = 2
attempt-timeout-seconds = 5
deadline-seconds = 60
```

Omit the table to keep existing startup behavior. All four fields are required.
The program must exist in the image. Exit 0 succeeds; completed failed attempts
retry until the deadline. Podman errors, container exits/restarts, or cancellation
fail startup and trigger cleanup. HTTP and TCP checks use programs in the
container, with its existing permissions.

Readiness runs before session registration and counts toward the existing
initialization timeout. `/status` exposes startup readiness progress without
command output. Readiness stops after success; it does not add ongoing health
monitoring.
