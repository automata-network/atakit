# baseimage.toml Specification

Configuration file baked into the immutable rootfs of a CVM base image. Read by the portal at every boot before any other state is loaded.

## Overview

`baseimage.toml` defines runtime configuration for the portal daemon running
inside a CVM. The current implementation consumes RW-partition encryption,
container UID/GID ranges, baby-container policy, logging, system binary paths,
and base-image attributes. It also requires several compatibility fields that
are parsed but not yet enforced; those are called out below.

The image project supplies this file at `input/rootfs/etc/atakit-portal/baseimage.toml`. `atakit-imgbuild build` validates it and injects the image reference into `[meta].base-image-ref` before the root filesystem is assembled. Once baked into the disk image, it is protected by dm-verity as part of the immutable EROFS rootfs and cannot be modified post-build.

## Location

| Context | Path |
|---------|------|
| Inside CVM rootfs | `/etc/atakit-portal/baseimage.toml` |
| Dev-mode fallback | Compiled-in defaults (no file required) |

When the file is absent at boot, the portal logs a warning and uses compiled-in defaults. Encryption is disabled. Initialization authentication depends on a public bootstrap supplied through launch metadata or `--init-auth-file`, not this file.

## Precedence

There are no per-field CLI or environment overrides in the current portal.
When the file exists, it is deserialized as the complete configuration. When it
does not exist, the portal uses its compiled development default as a whole.

## Relation to image-config.toml

`image-config.toml` controls **how** the base image is built (disk layout,
kernel, platforms, secure boot). `baseimage.toml` is supplied by the image
project and controls the portal inside that image. The build pipeline does not
generate this file. It requires format 2, validates the attribute declarations,
updates `base-image-ref`, and copies the file into both the root filesystem and
the local image store.

| File | Written by | Read by | Mutability |
|------|-----------|---------|------------|
| `image-config.toml` | User | `atakit-imgbuild build` | Editable (project source) |
| `baseimage.toml` | Image-project author; `[meta].base-image-ref` updated by `atakit-imgbuild build` | `atakit-portal` | Immutable after build (dm-verity protected) |

## Relation to legacy platform.toml

`baseimage.toml` replaces the legacy `/etc/cvm-agent/platform.toml`. Fields dropped, renamed, or relocated:

| Legacy field | Disposition |
|---|---|
| `container-engine` | Kept as `[container] engine` |
| `container-owner` | Dropped. Worker is always `atakit-worker`. |
| `workload-owner-uid` | Dropped. Replaced by userns UID/GID mapping. |
| `enable-tls` | Kept as `[tls] enable` |
| `enable-auth`, `operator-auth-max-drift` | Kept as parsed compatibility fields under `[auth]`; not enforced yet. |
| `external-port`, `init-port` | Dropped. Hardcoded :1024 / :2024 (protocol contract). See [portal-api-spec.md](portal-api-spec.md). |
| `max-upload-size` | Dropped. No body size cap; disk-limited. |
| `workload-startup-retries`, `workload-startup-retry-delay` | Dropped. No retry; failure reflected in `/status`. |
| `baby-container-tmpfs-size` | Kept as `[baby-containers] tmpfs-size` |
| `nft-path`, `dockerd-path` | Kept as `[paths] nft`. Added `[paths] podman`. `dockerd-path` dropped (no docker). |
| `disk-debug-level` | Dropped. Replaced by `[logging] level` (tracing-based). |
| `emulation-*` fields | Dropped. TEE emulation is a compile-time feature flag, not runtime config. |
| `base-image-ref` | Kept as `[meta] base-image-ref` |

## Schema Reference

The runtime sections are **required**. A missing runtime section is a parse
error and the portal refuses to start. The attribute tables described below
are optional and default to empty.

### `[meta]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format` | integer | yes | Schema version. The current and only supported value is `2`. Rebuild a format 1 base image before use. |
| `base-image-ref` | string | yes | Canonical image reference injected by imgbuild at build time, `"<publisher>/<name>:<version>"` (e.g. `"0x11111111.../my-image:v1.0.0"`). Composed from the build signing key's fingerprint plus `image-config.toml`'s `[image] name` and `version`. |

`base-image-ref` is used by the portal to identify itself in API responses and on-chain registration. It must match the `<publisher>/<name>:<version>` of the image project and signing key that produced it.

The publisher is part of the reference because the base-image identifier is
`keccak256(abi.encode(domain, publisher, name, version))`. Since this file is
inside the dm-verity-protected rootfs, the publisher is measured along with it,
and the portal derives the identifier it reports rather than being told one. A
two-part `name:version` reference is rejected: choosing a publisher for it would
claim an identity the image does not have.

### `[attributes.all]`, `[attributes.profiles."<profile-name>"]`, and `[attributes.variants."<profile-name>"."<variant-name>"]`

These optional tables declare attributes for generated platform profiles and
measurement variants.
`[attributes.all]` applies to every profile. A matching
`[attributes.profiles."<profile-name>"]` entry replaces values from
`[attributes.all]` for that profile. A matching
`[attributes.variants."<profile-name>"."<variant-name>"]` entry records
machine-specific values that replace the effective profile values when that
variant is selected. Profiles and variants do not need to contain the same
attribute set.

Custom attribute names and values are strings:

```toml
[attributes.all]
"example.environment" = "production"
```

Publication encodes the key as `keccak256(bytes(name))` and the value as
`keccak256(bytes(value))`.

The following names are reserved:

| Name | TEE platform | Source value |
|---|---|---|
| `atakit.attestation.v1.tee.intel-tdx.debug.enabled` | Intel TDX | Boolean |
| `atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed` | Intel TDX | Array of Intel DCAP TCB status names |
| `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled` | AMD SEV-SNP | Boolean |
| `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled` | AMD SEV-SNP | Boolean |
| `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum` | AMD SEV-SNP | `0x`-prefixed packed bytes32 string |
| `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum.by-cpuid` | AMD SEV-SNP | Opt-in marker; only `true` is valid |
| `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum.cpuid.<six lowercase hex digits>` | AMD SEV-SNP | Packed bytes32 minimum for that exact CPUID |
| `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy` | AMD SEV-SNP | `0x`-prefixed packed bytes32 string |

Omit `tcb.minimum.by-cpuid` when using one global `tcb.minimum`, or the
registry's default minimum. Do not set the marker to `false`. When the marker
is `true`, omit the global minimum and provide a CPUID-specific minimum for
each supported CPU. Verification fails if the signed report's exact CPUID has
no entry. Profile generation must not add a default value for this marker.

`atakit-imgbuild generate-platform-profile` reads the measured TEE type. It
copies custom attributes from `[attributes.all]` to every selected profile and
applies entries from a named profile table only to that profile. It applies
entries from a named variant table only to that exact profile and variant. It
copies a reserved entry from `[attributes.all]` only to profiles for that
reserved attribute's TEE platform. It rejects a named profile or variant that
contains a reserved attribute for the wrong TEE type. It also rejects unknown
profile and variant targets. A single base image can therefore declare both
Intel TDX and AMD SEV-SNP policy. The tool adds safe defaults to a profile when
an applicable reserved attribute is absent: `false` for debug and migration
Booleans and `["ok"]` for the Intel TDX TCB status attribute. It does not add
an AMD SEV-SNP packed policy because absence selects the active exact-CPUID
registry default. It does not add defaults to a variant. Regeneration preserves
an existing explicit profile or variant value unless the matching current
`baseimage.toml` table supplies that key.

Example:

```toml
[attributes.all]
"example.environment" = "production"

[attributes.profiles."gcp-sev-snp"]
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004"

[attributes.variants."gcp-sev-snp"."n2d-standard-4"]
"example.environment" = "hardware-specific"
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = "0x00000000df1e000500000000de1d000400000000de1d000400000000de1d0004"
"atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy" = "0x0000000000000000000000000000000000000000000000010000000000000020"
```

The supported Intel DCAP TCB status names and their one-hot bits are:

| Status name | Bit |
|---|---:|
| `ok` | `0x001` |
| `sw-hardening-needed` | `0x002` |
| `configuration-and-sw-hardening-needed` | `0x004` |
| `configuration-needed` | `0x008` |
| `out-of-date` | `0x010` |
| `out-of-date-configuration-needed` | `0x020` |
| `relaunch-advised` | `0x100` |
| `relaunch-advised-configuration-needed` | `0x200` |

The array must be non-empty, contain unique names, and include `ok`. The
generated on-chain value is the bitwise OR of the listed bits. Intel DCAP
statuses with raw values 6, 7, or any unknown value remain hard failures and
cannot be allowed by this policy.

The generated and regenerated JSON shape is defined in
[platform-profile-json-spec.md](platform-profile-json-spec.md).

The AMD SEV-SNP `migrate-ma.enabled` declaration covers only the signed
`POLICY.MIGRATE_MA` bit. An all-zero or all-`0xff` `REPORT_ID_MA` means that
no migration agent is associated. Every other `REPORT_ID_MA` represents an
active or unknown migration-agent association and remains unsupported. Both
the contract and the offline verifier reject it even when
`migrate-ma.enabled = true`.

The packed AMD SEV-SNP values and their validation rules are defined in
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).
They may be declared in a platform profile or measurement variant.

### `[rw-partition.encryption]`

Controls how the LUKS key for the `/atakit-portal/` RW partition is sealed and unsealed at boot.

First boot creates, formats and mounts the writable partition without an extra
reboot. Existing partitions automatically expand when the boot disk grows,
including the LUKS mapping and ext4 filesystem. Partition changes can invalidate
TPM keys bound to those measurements on a later boot. Selecting measurements
that remain valid across resizing is unresolved; PCR bindings are unchanged.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `unlock_method` | string[] | yes | - | Unlock methods for the RW partition. |
| `bind` | string[] | no | `[]` | PCR bindings applied when `unlock_method` includes `"tpm"`. |

#### `unlock_method`

List of methods for unlocking the LUKS-encrypted RW partition. For the RW partition, the only permitted values are:

| Value | Description |
|-------|-------------|
| `["tpm"]` | TPM2 PCR seal. Production default. |
| `[]` | No encryption. Dev/test only. |

Other methods (`"passphrase"`, `"keyfile"`, `"kms"`) exist in the encryption framework for data partitions but are **not permitted** for the RW partition.

#### `bind`

List of PCR bindings applied when `unlock_method` includes `"tpm"`. Each entry adds PCR registers to the TPM seal policy:

| Value | PCR Range | Description |
|-------|-----------|-------------|
| `"platform"` | 0-7 | Preboot/firmware measurements. Detects firmware tampering. |
| `"baseimage"` | 11 | Base image measurement. Detects rootfs tampering. |

`"workload"` (PCR 23) is **not permitted** for the RW partition because the workload has not been loaded yet when the partition is mounted.

**Boot lifecycle:**

- **First boot:** Supervisor creates the partition, generates a random key, LUKS2-formats it, seals the key to the TPM under a transient SRK with the PCR policy declared by `bind`, stores the sealed blob as a LUKS2 token in the partition's own header, formats with ext4, and mounts.
- **Subsequent boots:** Supervisor reads the LUKS2 token, unseals the key from the TPM (fails if any bound PCR values changed), activates the keyslot, and mounts.

### `[container]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `engine` | string | yes | Compatibility declaration. Current runtime always invokes the binary at `[paths].podman` and does not validate this value. Use `"podman"`. |
| `subuid-start` | integer (u64) | yes | Start of subordinate UID/GID range for user namespace isolation. |
| `subuid-size` | integer (u64) | yes | Total size of subordinate UID/GID range. |
| `nofile-default` | positive integer | no | Default soft and hard open-file limit for each container; default `1048576`. |
| `nofile-max` | positive integer | no | Maximum requested container limit and worker soft/hard limit; default `1048576`. |

`nofile-default` must not exceed `nofile-max`. Before dropping worker privileges,
Portal sets and reads back the worker's `RLIMIT_NOFILE` soft/hard limit. The
ceiling must fit the kernel's `fs.nr_open`; inability to establish it stops the
worker. Containers receive no `SYS_RESOURCE` capability. Portal checks requested
limits against this image policy and passes explicit Podman limits. See
[workload nofile](atakit-workload-toml-spec.md#open-file-and-socket-limits).

The portal uses manual user namespace mapping for container isolation. Each
parent service gets a 2,000-UID slice; each baby gets 100,000 UIDs (0–99,999). GID ranges come from the same
pool. The image project's rootfs must supply matching `/etc/subuid` and
`/etc/subgid` entries for `atakit-worker`; `atakit-imgbuild` preserves those
files but does not create them.

With the default range `100000:11000000`, workload service UID slots and workload GID-group slots must stay below host UID/GID `1,000,000`. Baby-container slots are reserved separately starting at host UID/GID `1,100,000`.

### `[baby-containers]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enable` | boolean | yes | Enable workload-facing baby container support. |
| `max-image-upload-mib` | positive integer | no | Per-upload archive body limit. Default 1024 MiB. Checked for byte conversion and address-space overflow. |
| `max-image-unpacked-mib` | positive integer | no | Combined decoded layer-stream limit per uploaded image. Default 4096 MiB. Checked for byte conversion overflow. Independent of writable-root capacity. |
| `image-store-size-mib` | positive integer | for writable roots | Hard filesystem capacity shared by all Podman images, container metadata and image import staging. Minimum 32 MiB. Physically reserved separately from writable roots. Existing populated storage is never hidden or resized automatically. |
| `rootfs-encryption` | string | no | Experimental `"tpm-integrity"` encrypts each writable generation with LUKS2 and keyed integrity, using a TPM-sealed key. Omit for the existing plain backend. Requires cryptsetup and built-in dm-integrity. Same-VM recovery only; no rollback or sealed-platform guarantee. |
| `tmpfs-size` | string | yes | Reserved compatibility field. It is parsed but not passed to the current baby-container runtime. |
| `max-concurrent` | integer (u32) | yes | Platform cap for simultaneous baby containers. The effective per-workload capacity is `min(max-concurrent, manifest.config.baby-container.max_instances)`. |

When `enable = false`, all workload-facing `/baby-container/*` requests are
rejected even if the workload manifest declares slots. `tmpfs-size` and
`max-concurrent` must still be present because all baseimage sections are
required.

### `[tls]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enable` | boolean | yes | Reserved compatibility field. The current portal does not branch on it. |

The current portal always loads or generates a self-signed ECDSA P-256
certificate and always serves HTTPS, regardless of `enable`. The certificate
and key are stored in the RW partition at `/atakit-portal/tls/`.

### `[auth]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enable` | boolean | yes | Reserved compatibility field; not enforced. |
| `max-clock-drift` | string | yes | Reserved compatibility string; not parsed as a duration or enforced. |

The operator selects [authenticated initialization](init-auth-spec.md) by
provisioning a public bootstrap through launch metadata, not through this file.
The legacy `enable` field does not control initialization authentication.

### `[logging]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `level` | string | yes | Tracing filter level. |

The value is passed to `tracing-subscriber`'s `EnvFilter`; ordinary values are
`"error"`, `"warn"`, `"info"`, `"debug"`, and `"trace"`.

### `[paths]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nft` | string | yes | Absolute path to the nftables binary. |
| `podman` | string | yes | Absolute path to the podman binary. |

These paths are baked in at build time because the rootfs is immutable. They must match the actual file locations in `input/rootfs/`.

The supervisor seeds Podman configuration into `$HOME/.config/containers/` each boot. The normal/debug image startup scripts explicitly select the immutable `/etc/containers/containers.conf` through `CONTAINERS_CONF`. Portal passes each container’s resolved `--ulimit=nofile=N:N` explicitly, overriding configuration defaults. See `state-layout.md` in the portal repo for the worker home layout.

## TEE Emulation

TEE emulation is **not** configured in `baseimage.toml`. It is a compile-time feature flag on the portal binary:

- `cargo build` -- production binary, real TEE backends
- `cargo build --features tee-emulation` -- dev binary, mock TEE backends

Emulation code does not ship in production builds.
Production packaging MUST execute the built binary with `--build-profile` and
require the exact output `production` before installing it into an image. An
emulation artifact reports `tee_emulation` and must be rejected.

`atakit-imgbuild` enforces this inside its architecture-matched worker
container. The rootfs MUST contain an executable portal at
`/bin/atakit-portal` or `/usr/bin/atakit-portal`; every portal present at those
supported paths is executed inside the target rootfs and must report
`production` before disk assembly begins.

## Example: Production

```toml
[meta]
format = 2
base-image-ref = "0x1111111111111111111111111111111111111111111111111111111111111111/example-linux:v1.0.0"

[attributes.all]
"example.environment" = "production"
"atakit.attestation.v1.tee.intel-tdx.debug.enabled" = false
"atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed" = ["ok"]
"atakit.attestation.v1.tee.amd-sev-snp.debug.enabled" = false
"atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled" = false
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004"
"atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy" = "0x0000000000000000000000000000000000000000000000000000000000000020"

[attributes.profiles."gcp-tdx"]
"atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed" = [
  "ok",
  "sw-hardening-needed",
]

[attributes.variants."gcp-tdx"."c3-standard-4"]
"atakit.attestation.v1.tee.intel-tdx.debug.enabled" = true
"atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed" = [
  "ok",
  "configuration-needed",
]

[rw-partition.encryption]
unlock_method = ["tpm"]
bind = ["platform", "baseimage"]

[container]
engine = "podman"
subuid-start = 100000
subuid-size = 11000000

[baby-containers]
enable = false
tmpfs-size = "64m"
max-concurrent = 100

[tls]
enable = true

[auth]
enable = false
max-clock-drift = "5m"

[logging]
level = "info"

[paths]
nft = "/usr/sbin/nft"
podman = "/usr/bin/podman"
```

## Example: Dev/Test (no encryption)

```toml
[meta]
format = 2
base-image-ref = "dev-mode"

[attributes.all]

[attributes.profiles]

[attributes.variants]

[rw-partition.encryption]
unlock_method = []
bind = []

[container]
engine = "podman"
subuid-start = 100000
subuid-size = 11000000

[baby-containers]
enable = false
tmpfs-size = "64m"
max-concurrent = 100

[tls]
enable = true

[auth]
enable = false
max-clock-drift = "5m"

[logging]
level = "info"

[paths]
nft = "/usr/sbin/nft"
podman = "/usr/bin/podman"
```

## Validation Rules

The following are the intended constraints:

1. **Runtime sections required.** Every runtime section (`[meta]`, `[rw-partition.encryption]`, `[container]`, `[baby-containers]`, `[tls]`, `[auth]`, `[logging]`, `[paths]`) must be present. The two attribute tables are optional and default to empty.
2. **`unlock_method` must be `["tpm"]` or `[]`.** Other values (`"passphrase"`, `"keyfile"`, `"kms"`) are not valid for the RW partition.
3. **`bind` entries must be `"platform"` or `"baseimage"`.** `"workload"` is not permitted (workload hasn't loaded when the RW partition mounts).
4. **`bind` is only meaningful when `unlock_method` includes `"tpm"`.** When `unlock_method = []`, `bind` should be `[]`.
5. **`engine` should be `"podman"`.** No other container engine is implemented.
6. **Paths must be absolute.** `nft` and `podman` paths must start with `/`.
7. **`format` must be `2`.** Format 1 is rejected with a rebuild message.
8. **Attribute names are unique inside each TOML table.** TOML parsing enforces this.
9. **Custom values are strings.** Unknown names under `atakit.attestation.v1.tee.` are rejected.
10. **Reserved values use their exact type.** Debug and `MIGRATE_MA` use Booleans. Intel TDX TCB policy uses a unique supported string array that includes `ok`.

At load time the portal enforces format 2 and typed TOML deserialization.
Unknown fields are accepted. `atakit-imgbuild build` performs the attribute
validation before disk assembly. RW-encryption and UID-range constraints are
checked later at their use sites, but `container.engine`, `tls.enable`,
`auth.*`, `baby-containers.tmpfs-size`, and path absoluteness are not currently
validated or enforced.

## Build Pipeline Production

During `atakit-imgbuild build`, the build pipeline:

1. Reads `image-config.toml` from the project directory.
2. Requires `input/rootfs/etc/atakit-portal/baseimage.toml`, requires format 2, validates its attribute declarations, and sets `[meta].base-image-ref` to `<publisher>/<name>:<version>`, where the publisher is the fingerprint of the build signing key (`--signing-key`, defaulting to `[publish] owner_key`) and the name and version come from `[image]`.
3. Copies the normalized source file to the image-store staging directory so platform-profile generation can apply its attributes.
4. Uses the existing `input/rootfs/` tree as the rootfs build input.
5. The file is included in the EROFS image and protected by dm-verity.

The image project remains responsible for the complete runtime configuration.
Platform-profile generation supplies missing safe reserved-attribute defaults;
it does not rewrite the source file.

Writable baby roots allocate physical backing files per instance on first
creation. The manifest selects the disk and byte quota. There is no aggregate
root pool setting. Boot-disk allocation preserves 1 GiB of free space; a
declared data disk preserves 16 MiB. These checks constrain supervisor storage
allocations, not unrelated future disk writes.

The image store remains separately bounded by `image-store-size-mib`. Its
filesystem is created on the first workload image load and restored on later
boots. Starting an unused VM does not allocate the image store or any baby root.
