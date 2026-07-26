# Cloud Deployment Architecture

## Status and source of truth

This document describes the current `atakit cloud` implementation. The CLI
argument definitions in `crates/atakit-cloud/src/cli.rs`, configuration types in
`crates/atakit-{cli,cloud}/src/config.rs`, provider implementations under
`crates/atakit-cloud/src/{gcp,azure,aws,qemu}/`, and init serializer in
`crates/atakit-cloud/src/init.rs` are authoritative when this document and code
disagree.

Cloud deployment is a stateful, plan-based wrapper around provider CLIs:

- GCP uses `gcloud`.
- Azure uses `az`.
- AWS uses `aws`.
- QEMU uses local `qemu-system-x86_64`, `qemu-img`, and `swtpm` processes.

The workload archive defines portable workload policy: services, dependencies,
ports, data, storage, and disks. Operator `config.toml` defines provider account
selection, region, machine type, chain registration, keys, prover policy, and
deployment-specific overrides.

## Configuration model

Providers, targets, and defaults are separate named objects. Targets reference
providers and inherit selected fields from `[cloud.defaults]`.

```toml
[chains.example]
rpc_url = "https://rpc.example.com"
session_registry = "0x0000000000000000000000000000000000000001"
tee_backend = "auto"                 # auto | solidity | zk
prover = "sp1-network"

[keys.owner]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/owner.key"

[keys.gas]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/gas.key"

[keys.prover]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/prover.key"

[provers.sp1-network]
backend = "sp1"
execution = "network"
credential = "prover"

[cloud.providers.gcp-example]
platform = "gcp"
project = "example-project"
region = "us-central1-a"

[cloud.defaults]
chain = "example"
registration = "optional"
owner_key = "owner"
gas_wallet = "gas"

[cloud.targets.gcp-tdx]
provider = "gcp-example"
vmtype = "c3-standard-4"
image = "example-linux:v1.0.0"
```

### Providers

`[cloud.providers.<name>]` accepts:

| Field | Use |
|---|---|
| `platform` | Required: `gcp`, `azure`, `aws`, or `qemu`. |
| `project` | Required for GCP. |
| `subscription` | Required for Azure. |
| `region` | GCP zone, Azure region, or AWS region; unused by QEMU. |
| `uefi` | Optional QEMU OVMF path. |

Provider names are local aliases and do not have to match cloud account names.
Do not put credentials in this table; provider CLIs supply authentication.

### Targets and defaults

`[cloud.targets.<name>]` accepts:

| Field | Use |
|---|---|
| `provider` | Required provider reference. |
| `vmtype` | Cloud machine type; optional and ignored for QEMU. |
| `image` | Base-image reference; may come from `[cloud.defaults]` or `--image`. |
| `cc_type` | Optional `SEV_SNP` or `TDX`; normally inferred from `vmtype`. |
| `name` | Optional instance-name prefix. |
| `metadata` | Additional provider metadata. |
| `boot_disk_size` | Optional boot-disk size override. |
| `static_ip` | Existing operator-managed public-IP resource. |
| `static_ip_resource_group` | Azure resource group containing `static_ip`. |
| `chain` | Named `[chains]` entry. |
| `registration` | `required`, `optional`, or `off`. |
| `owner_key` | Named owner key. |
| `gas_wallet` | Named transaction payer. |
| `prover_credential` | Optional fallback prover key. |
| `uefi` | Per-target QEMU firmware override. |

`[cloud.defaults]` can provide `chain`, `registration`, `owner_key`,
`gas_wallet`, `prover_credential`, and `image`. A target value wins over the
default. Supported CLI overrides are documented by `atakit cloud <command>
--help`; notably `--chain`, `--owner-key`, and `--gas-wallet` refer to config
entry names, not file paths.

The effective configuration of `[cloud.targets.<name>]` is immutable while a
saved deployment references that target name. The effective configuration
includes inherited `[cloud.defaults]` values and every referenced provider,
chain, key, and prover entry. Later verification, session lifecycle, status,
and destruction commands resolve the same named configuration. An operator who
needs different configuration must create `[cloud.targets.<new-name>]` and a
new instance. Editing or reusing the old target name while its deployment
remains is unsupported.

`[cloud.images]` optionally declares the CC types used when registering a cloud
image:

```toml
[cloud.images]
"example-linux:v1.0.0" = ["SEV_SNP", "TDX"]
```

## Modular prover policy

Prover selection is deployment policy and never changes the workload manifest
or workload ID. A chain may reference one `[provers.<name>]` profile:

```toml
[provers.sp1-network]
backend = "sp1"
execution = "network"
credential = "prover"
# endpoint = "https://prover.example.com"
# [provers.sp1-network.options]
# dcap_rpc_url = "https://collateral.example.com"
```

The CLI validates backend/profile references, execution-mode spelling,
credential type, and `tee_backend` before provider operations. It resolves the
profile into the portal's top-level `prover` object. Format-2 requests emit the
credential as `prover_credential`.

`tee_backend = "auto"` selects ZK for AMD SEV-SNP and Solidity/DCAP for Intel
TDX. `zk` forces a prover program for either TEE. `solidity` is invalid for SNP.
The strict operator schema rejects the removed `chain.proving_strategy` field.

Effective prover credential precedence is profile credential, then
persisted/target fallback. The gas wallet is never a prover credential. A
selected network prover requires a separately named credential. With
`registration = "off"`, no prover is launched and no configured prover
credential is resolved.

The portal currently requires `owner_key.private_key` on every `/init`, so the
effective owner key must be a provisioned key even though the CLI schema and
some producer paths accept or synthesize `self_generated`. This mismatch
affects cloud and direct `workload init` flows as well as QEMU. Gas-wallet and
prover credentials may still be self-generated where their role permits it.

## CLI surface

The current command families are:

```text
atakit cloud deploy [SOURCE] --target <name> [--target <name> ...]
atakit cloud init <instance> [SOURCE] [--target <name>]
atakit cloud session new|rotate-key|renew <instance> [--target <name>]
atakit cloud session recover <instance> --old-session-id <bytes32> [--target <name>]
atakit cloud session status <instance> [--request-hash <bytes32>] [--wait]
atakit cloud destroy <instance>... [--target <name>]
atakit cloud status <instance> [--target <name>] [--live]
atakit cloud ls [--target <name>]
atakit cloud ssh <instance> [--target <name>]
atakit cloud serial <instance> [--target <name>]
atakit cloud image ls [--live]
atakit cloud image upload <image> --provider <name>
atakit cloud image rm <image> --provider <name>
atakit cloud image gc
atakit cloud provider ls
```

`cloud deploy` accepts a workload store reference, `.atawl` path, or `-d`
directory mode. `--image-only` provisions a VM without workload init. Repeating
`--target` performs image pre-upload serially per unique provider/image pair,
then deploys targets concurrently; `--name` is rejected in multi-target mode.

Deployment-management session commands derive their required binding from the
deployment target's `registration` value. `required` and an omitted policy
require a chain-bound session. `off` requires a local-bound session. `optional`
accepts either verified binding because a failed optional registration may
validly install a local-bound session. Lifecycle completion uses the verified
successor binding to decide whether to call `isSessionActive`. Rotate-key,
renew, and recover still require a chain-bound predecessor; new may start from
a local-bound predecessor.

`atakit cloud verify-session` is different. The verifier may be on another
computer. The verifier supplies the canonical base-image reference, canonical
workload reference, and portal address. A matching local deployment may fill
only those subject fields. The verifier selects `--chain` or supplies explicit
collateral. The command never takes a chain, registration policy, registry,
measurement policy, workload policy, or platform trust root from the local
deployment or deployment target.

For a chain-bound session, the authenticated chain ID and `SessionRegistry`
address must match the chain ID returned by the verifier-selected RPC endpoint
and the `SessionRegistry` address in the verifier-selected chain configuration.
The portal evidence never selects those trusted values. Selecting `--chain`
does not by itself require a chain-bound session; it may supply collateral for
a local-bound session when the caller's binding policy permits that session.

The default lifecycle `op_expires_at` window is the portal's 900-second proof
timeout plus `owner_operations.op_expiry_seconds`. The configured owner-
operation interval therefore remains available for portal transaction
submission after the longest supported proof. `--op-expiry-seconds` replaces
the complete calculated window. The default command wait adds a further
60-second completion buffer.

Verifier-selected registry-backed session verification reads the exact
`WorkloadSpec`, checks
that it allows the TLS-selected base image, and supplies all workload PCR and
attribute requirements to the offline verifier. These workload PCR rules are
appended to the effective base-image profile and variant rules, including when
both policies constrain the same PCR. Deployment-management verification with
`registration = "off"` and no `WorkloadRegistry` hashes and inspects the saved
`.atawl` and uses its PCR23. For `atakit cloud verify-session`,
`--trusted-workload-pcr23` is an explicit verifier-owned alternative to
`WorkloadRegistry`; the command never reads a saved `.atawl` as trusted
collateral.

TLS bootstrap applies the same verified TEE attribute policy before any
`POST /init` data is sent. The verifier extracts the Intel TDX debug state and
DCAP TCB status, or the AMD SEV-SNP debug, `MIGRATE_MA`, TCB,
`PLATFORM_INFO`, and CPUID state, from the signed report. It compares that
state with the effective signed platform profile and measurement variant. When
a workload manifest is selected, it also applies
`manifest.config.attributes`. When no workload is selected, missing workload
requirements do not create a workload-side AMD SEV-SNP policy; TLS verification
applies only the resolved base-image policy. Missing Boolean base-image values
mean disabled, and a missing Intel TDX base-image TCB status means `ok` only.
For AMD SEV-SNP, the verifier either receives the exact-CPUID registry default
as an explicit trust input or reads it
from the `AmdSnpSecurityPolicyRegistry` derived from the selected
`SessionRegistry`. Custom attributes and all six reserved TEE attributes use
measurement-variant-first lookup. The variant value replaces the matching
profile value. With a workload, an explicit workload packed value replaces its
registry default; without a workload, the resolved base-image value applies by
itself.

`atakit cloud session status` resolves only the deployment and verified portal
TLS connection before reading portal request state. It displays `idle`,
`waiting`, `running`, and `failed` without loading `WorkloadRegistry` policy.
When the portal reports `completed`, the command then resolves the trusted
workload policy, verifies the exact successor as the current session, and calls
`isSessionActive` for a chain-bound successor. A failure in that second stage
does not hide the portal's completed state. Session mutation commands retain
full current-session verification before owner authorization.

Azure TLS bootstrap and committed-session verification resolve MAA trust
separately. TLS bootstrap verifies the fresh `/tls-attestation` JWT with its
exact `kid` and `iss`. After the committed session evidence bundle is fetched,
session verification resolves that bundle's exact MAA key and verifies its JWT
with that key. A fresh TLS MAA key is not a fallback for the committed session
MAA key. Every manual `--azure-maa-key` value remains available until both JWTs
have been checked, so valid key rotation between session creation and a later
command does not make the committed session unverifiable.

Portal status and init ports default to `2024` and `1024` and can be overridden
per invocation with `--status-port` and `--init-port`. The selected ports are
used consistently for provider firewall rules, readiness, init, and persisted
state. Workload-declared ports are added only for workload deploys.

## Deploy flow

A single-target deploy performs these logical stages:

1. Resolve and validate the workload archive, manifest policy, image, target,
   provider, CC type, disk secrets, registration policy, keys, and prover.
2. Resolve the TLS measurement policy before provisioning unless
   `--unsafe-skip-tls-attestation` is explicitly set.
3. Create and persist a provider-specific deployment plan and resource state.
4. Upload/register the image when it is not already present.
5. Create firewall/security-group rules, data disks, and the VM.
6. Wait for `GET /status` on the configured status port.
7. Verify the portal TLS certificate against fresh attestation and the selected
   measurement policy.
8. Unless `--skip-init` or `--image-only` is set, require `GET /status` to
   report `init_schema_version = 2`, send the one-shot multipart `POST /init`
   request, and poll portal state.

The init upload timeout is controlled by `--init-upload-timeout`. Portal
readiness keeps a separate 300-second timeout. After `POST /init`,
`atakit workload init <host> --init-timeout`,
`atakit cloud init <instance> --init-timeout`, and
`atakit cloud deploy <workload> --init-timeout` use the same completion-timeout
calculation. The calculated default is the 900-second portal proof timeout plus
`owner_operations.op_expiry_seconds` plus a 60-second completion buffer. The
unsafe TLS bypass accepts a self-signed certificate without attestation and
always prints a warning.

The init JSON schema is defined in the suite's
[init-config specification](../../docs/specs/init-config-spec.md). It contains
`chain`, unified `owner_key` and
`gas_wallet` objects, optional resolved `prover`, `prover_credential`, platform
declaration, network values, and disk passphrases.
Legacy `agent_env`, `owner_private_key`, and `relay_private_key` objects are not
part of the current producer.

Unmeasured data is selected from the manifest allowlist. The CLI uploads only
declared paths present below `--unmeasured-data-root` (or the directory-mode
default); the portal rejects undeclared paths, while missing declared paths are
allowed.

## State and recovery

Deployment state is stored below the atakit XDG data directory:

```text
~/.local/share/atakit/cloud/deployments/<target>/<instance>.state.json
```

Deployment-state format 2 records the provider alias in `image_ref` and the
canonical verification subject identity in `base_image_ref`. `image_ref`
remains necessary for provider resource management. `base_image_ref` is only
an optional subject-input shortcut for `atakit cloud verify-session`; it is not
a policy or collateral source. Format 2 also records the platform, workload
identity, archive hash, selected config entry names, portal ports, lifecycle
status, and provider resource identifiers. It stores references to named keys,
not private key bytes.

When the loader reads format 1, it renames only `init_env.sp1_payer` to
`init_env.prover_credential`, preserves string and `null` values, rejects a
document containing both names, adds `base_image_ref = null`, and atomically
rewrites the state as format 2. The migration does not assume that the old
`image_ref` was a canonical base-image identity. Format 2 rejects `sp1_payer`.
This compatibility is limited to local deployment state; operator configuration
and portal `/init` remain strict current schemas. The loader also migrates the
older top-level `deployments/` directory when possible.

Lifecycle states are `deploying`, `deployed`, `failed`, `destroying`, and
`destroyed`. Each provider uses check-before-create behavior so a failed
provider step can resume before `POST /init`. `POST /init` is one-shot. If a
new deployment fails after `POST /init`, remove it with `atakit cloud destroy`
and create a new deployment with `atakit cloud deploy`. `cloud status --live`
queries the provider in addition to local state.

`cloud init` resolves config with CLI overrides first, persisted state second,
and the target/default config last. The selected chain profile still wins for
its prover credential, so a recovery init cannot silently use a different
proving identity.

If `cloud init` observes portal `Failed` or `CleanHalt` after the one-shot
`POST /init`, it saves deployment status `failed` with step `Wait for portal
Running` before returning an error. It keeps the updated workload identity,
configuration references, and provider resource identifiers so `cloud
destroy` can remove the deployment. A later `cloud init` rejects that failed
deployment.

## Resource ownership and destroy

Atakit records only resources created or attached for the deployment. Destroy
uses those identifiers rather than reconstructing names from current config.
Images are preserved by default and deleted only with `--clean-image`; they are
automatically preserved while another active deployment references them.
`--preserve disks,firewall` keeps the named resource classes.

Static public IPs are operator-managed attachments:

- GCP accepts a regional reserved address name.
- Azure accepts a Public IP name and requires
  `static_ip_resource_group`; that group must differ from the deployment group
  deleted by destroy.
- AWS static-IP attachment is rejected until Elastic IP support is implemented.

Destroy must never delete an operator-managed static IP merely because it was
attached to a deployment.

## Provider-specific resource sets

The persisted state tracks:

- GCP: project, zone, staging bucket, image, firewall rule, disks, instance,
  and external IP.
- Azure: subscription, region, deployment resource group, storage/gallery
  resources, image version, NSG, disks, instance, and external IP.
- AWS: region, staging bucket, snapshot, AMI, security group, instance, and
  external IP.
- QEMU: instance directory, process ID, base disk and overlays, swtpm state,
  serial socket/log, host port mappings, and loopback address.

Provider resource names are sanitized from the deployment name and tagged or
labeled where the provider supports it. Documentation examples intentionally
use placeholders and reserved domains rather than real account, host, or IP
values.

## QEMU functional harness

QEMU is for local workload-init iteration, not confidential-computing security.
It uses a software TPM and has no genuine TDX or SEV-SNP quote. A target with no
chain configuration synthesizes `registration = "off"`. Because of the
owner-key mismatch described above, a QEMU target must still reference a
provisioned ES256K owner key. Missing `gas_wallet` and prover credentials may
remain self-generated because they are unused in this mode.

The local provider uses a qcow2 overlay over the image-store QEMU disk, creates
per-instance qcow2 data disks, forwards portal ports to ephemeral loopback host
ports, and forwards workload TCP ports to the same host port. `cloud serial`
reads the serial log; `cloud ssh` attaches interactively to the serial socket.
Destroy terminates QEMU and removes the per-instance directory.

OVMF resolution precedence is `ATAKIT_QEMU_UEFI`, target `uefi`, then provider
`uefi`. The firmware must include TPM measurement support.

## Invariants

- Provider or network actions never begin before config and workload validation
  completes.
- Private key bytes are resolved only for the init request and are not written
  to deployment state.
- A workload's manifest, not operator config, controls workload ports, data
  allowlists, and disks.
- TLS attestation is the default before `/init`; bypass is explicit and noisy.
- Registration policy and TLS collateral resolution are independent.
- Prover/backend choice remains outside workload identity.
- Operator-managed static IP resources survive destroy.
- Current CLI help and typed config structures outrank examples in this file.
