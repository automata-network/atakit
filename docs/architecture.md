# atakit-ng Architecture

## Overview

`atakit-ng` is the Rust operator CLI for base-image distribution, workload
build and publication, attestation verification, and deployment to GCP, Azure,
AWS, or the local QEMU functional harness.

The workspace separates reusable domain logic from terminal presentation:

```text
crates/
  atakit-core/          XDG paths and progress abstractions
  atakit-github/        generic GitHub Releases client
  atakit-image/         base-image distribution and local image store
  atakit-workload/      workload schema, build, stores, and repositories
  atakit-attestation/   verifier-side TLS and TEE attestation logic
  atakit-cloud/         provider plans, execution, state, and portal client
  atakit-cli/           clap surface, config resolution, and presentation
```

Library crates expose their clap types only behind a `cli` feature. The binary
owns prompts, progress bars, output formatting, and top-level error context.

## Command routing

The built-in command families are `image`, `workload`, and `cloud`. Clap's
external-subcommand handler also delegates unknown first-level commands to an
`atakit-<name>` executable on `PATH`; for example, `atakit imgbuild ...`
executes `atakit-imgbuild ...` when that binary is installed.

The standalone `atakit-imgbuild` spelling remains the canonical form in suite
documentation because it works without relying on delegation or installation
layout.

## Shared runtime context

`atakit-core::Env` resolves XDG-compliant configuration, data, cache, image,
and workload directories. Environment overrides take precedence over XDG
variables, which take precedence over home-directory defaults.

The operator config lives at `$XDG_CONFIG_HOME/atakit/config.toml` (normally
`~/.config/atakit/config.toml`). It names image and workload repositories,
credential sources, chains, prover profiles, keys, cloud providers, defaults,
and targets. Secret values are resolved lazily from a file, an argv-only
command, or an environment variable; deployment state stores only the selected
entry names.

## Domain boundaries

### Images

`atakit-image` owns public image discovery, pull/remove, `.atabi`
import/export, and the local image store. Image construction and on-chain base
image publication belong to the separate `atakit-imgbuild` repository.

### Workloads

`atakit-workload` owns `atakit-workload.toml` parsing and validation,
container-image build/save, deterministic manifest generation, `.atawl`
creation, local store operations, HTTP/GitHub repository backends, and
on-chain workload metadata helpers. Operator-provided unmeasured data is not
included in the archive; the manifest commits only to its allowlisted paths.

### Attestation

`atakit-attestation` verifies the portal's attested TLS bootstrap evidence and
measurement policy. Cloud deployment resolves this policy before provisioning
unless the operator explicitly selects the unsafe bypass.

### Cloud

`atakit-cloud` contains typed config, provider-independent plan/state types,
the provider implementations, and the portal HTTPS client. Supported platforms
are:

- GCP: image, firewall, disk, instance, and static-IP attachment;
- Azure: storage/gallery image, resource group, NSG, disk, instance, and
  static-IP attachment;
- AWS: snapshot/AMI, security group, disk, and instance;
- QEMU: local qcow2 overlays, swtpm, serial socket, and host port forwarding.

The provider implementations execute external cloud CLIs through a command
runner abstraction. QEMU invokes `qemu-system-x86_64`, `qemu-img`, and `swtpm`
instead.

Deployment state is stored below:

```text
$XDG_DATA_HOME/atakit/cloud/deployments/<target>/<instance>.state.json
```

State records provider resource identifiers so destroy does not reconstruct
them from mutable config. It includes `gcp`, `azure`, `aws`, and `qemu`
resource variants and lifecycle states `deploying`, `deployed`, `failed`,
`destroying`, and `destroyed`.

See [cloud-deploy-design.md](cloud-deploy-design.md) for the detailed current
flow and safety invariants.

## Dependency direction

```text
atakit-cli
  ├── atakit-image ──────┐
  ├── atakit-workload ───┼── atakit-github ── atakit-core
  ├── atakit-cloud ──────┤
  └── atakit-attestation ┘
```

Domain crates use typed errors; `anyhow` is reserved for the CLI boundary.
Progress reporting is trait-based so library code does not depend on terminal
rendering.

## On-chain boundary

Workload publish/deactivate and cloud session initialization use the registry
contract types supplied by `automata-tee-workload-measurement`. Operator
configuration keeps the owner identity, gas payer, and prover credential as
separate named keys. The workload manifest does not select a prover backend or
chain submission policy; those remain deployment policy.
