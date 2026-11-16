# `atakit-workload.toml` Specification

One file per workload per directory. Defines everything: workload metadata, its container, dependencies, and storage.

**automata-linux v0.3.7 requires `format = 16` for every workload. Use CLI 0.7.7.** Formats
14 and 15 are rejected at initial startup and after reboot, even without CPU
settings. New workload templates use format 16. Changing a published workload
changes its measured manifest and requires a new workload version and policy.
The older v0.3.5 image requires format 15.

## Storage access lists (format 16; introduced in format 14)

Format 16 uses explicit access lists instead of `read-only` / `read_only`,
`executable`, and baby `permissions`. These lists were introduced in format 14.
Use format 16 for the current image; the historical format rules below do not
widen v0.3.7 startup support.

```toml
format = 16

[workload.storage.app]
disk = "data"
base-path = "/app"
mount-path = "/root/app"
access = ["read", "write", "execute"]

[baby-container.slots.dev.storage.app]
disk = "baby-data"
base-path = "/app"
mount-path = "/root/app"
scope = "instance"
retention = "disk"
access = ["read", "write", "execute"]
parent-access = []
```

`access` is required for every workload, dependency and baby storage mount.
Only `read`, `write`, and `execute` are accepted. `read` is required; unknown,
duplicate, empty or write-only/execute-only lists are rejected. `write` permits
writes through this mount; its absence makes the mount read-only. `execute`
permits executable mappings through this mount; its absence applies `noexec`.
Unix ownership and file modes still apply. `nosuid` and `nodev` always remain.
Reading a script and passing its contents to an interpreter is not prevented by
`noexec`; these are mount rights, not a guarantee that mutable code cannot run.

Baby `parent-access` defaults to `[]` (no parent access). A nonempty list must
include `read`. It limits separately declared overlapping storage mounts of the
owning parent service; it does not create a parent mount. Such mounts must not
exceed the grant in read, write or execute rights. Baby creation requests cannot
override either list. Storage scope, retention, paths, quotas, encryption and
lifecycle policies are unchanged.

Format 14 rejects the old fields even if explicitly set to false. Earlier
formats reject the new fields. The builder sorts both lists in read/write/execute
order before measuring the manifest, so list ordering does not alter PCR23.
Compiled JSON uses `access` and `parent_access`; it omits the old fields.
An omitted source `parent-access` becomes an explicit empty compiled list.

## Design Principles

1. **Security allowlist.** The schema defines what a workload *can* do on the CVM. If a field doesn't exist in this spec, it's not supported. The default is deny.
2. **No ambiguity.** Measured data, unmeasured data, and persistent disks are separate fields - not overloaded into a single `volumes` list.
3. **Auto-derivable fields are omitted.** Image tags for built services are auto-generated. Users don't manage derived artifacts.

---

## Full example

```toml
format = 16

# -- package data ------------------------------------------------

[package]
measured-data = ["/config/hello", "/config/cert.pem"]
unmeasured-data = ["/additional-data/signer_key", "/additional-data/signer_key.env"]

# -- workload container ------------------------------------------

[workload]
name = "secure-signer"
version = "v0.0.1"
base-image-mode = "blacklist"
base-image = ["mola-linux:v0.1.0-debug", "automata-linux:v0.1.5-debug"]

image = { build = ".", containerfile = "Containerfile" }
ports = ["3000:3000"]
depends_on = ["redis", "model-server"]
restart = "unless-stopped"
atakit-portal = true
boot-disk-size = "50GB"
measured-data = true
unmeasured-data = ["/additional-data/signer_key.env"]
gid-group = "shared"
cap-add = ["NET_ADMIN"]
cap-drop = ["NET_BIND_SERVICE"]
env-file = "./defaults.env"
unmeasured-env-file = "/additional-data/signer_key.env"

[workload.attributes]
"example.environment" = ["production"]
"atakit.attestation.v1.tee.intel-tdx.debug.enabled" = [false]
"atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed" = [
  "ok",
  "sw-hardening-needed",
]
"atakit.attestation.v1.tee.amd-sev-snp.debug.enabled" = [false, true]
"atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled" = [false]
"atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum" = [
  "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",
]
"atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy" = [
  "0x0000000000000000000000000000000000000000000000000000000000000020",
]

[workload.environment]
RUST_LOG = "info"
LISTEN_ADDR = "0.0.0.0:3000"

[workload.storage.data]
disk = "secure-signer-data"
base-path = "/"
mount-path = "/data"
access = ["read", "write"]

[workload.storage.data2]
disk = "secure-signer-data2"
base-path = "/"
mount-path = "/data2"
access = ["read", "write"]

[workload.logging]
driver = "k8s-file"
options = { max-size = "50m", max-file = "5" }
log-readers = ["log-shipper"]

# -- dependencies ------------------------------------------------

[dependencies.redis]
image = "redis:7"

[dependencies.model-server]
image = { file = "./images/model-server.tar" }
ports = ["8080:8080"]
measured-data = true

[dependencies.log-shipper]
image = "fluent/fluent-bit:3.0"
workload-logs = true
[dependencies.log-shipper.logging]
driver = "k8s-file"
options = { max-size = "20m", max-file = "3" }

# -- firewall ----------------------------------------------------

[firewall]
allow = ["4000/tcp"]

# -- baby containers ---------------------------------------------

[baby-container]
enabled = true
max-instances = 2

[baby-container.slots.analysis-job]
parent-service = "secure-signer"
gid-group = "shared"
image-selection = "multiple"
max-instances = 1
trust-policy = "user-helper-image"

[baby-container.slots.analysis-job.lifecycle]
image-retention = "disk"
instance-retention = "ephemeral"
restart = "manual"
rootfs = "read-only"

[baby-container.slots.analysis-job.storage.workspace]
disk = "secure-signer-data"
base-path = "/analysis-job/instances"
mount-path = "/workspace"
retention = "disk"
scope = "instance"
access = ["read", "write"]
parent-access = ["read"]

# -- persistent disks --------------------------------------------

[disks.secure-signer-data]
index = 10
size = "10GB"
encryption = { unlock_method = [], bind = [] }

[disks.secure-signer-data2]
index = 11
size = "11GB"
encryption = { unlock_method = ["tpm"], bind = ["workload"] }

```

---

## Minimal Example

```toml
format = 16

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
```

Five required fields. Everything else defaults: no ports, no mounts, no dependencies, no firewall overrides, no baby containers. With `base-image-mode = "blacklist"` and `base-image` defaulting to `[]`, this workload can deploy on any CVM image.

---

## Schema Reference

### `format` - Schema Version

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Source schema version. Use `16` for automata-linux v0.3.7. Format 16 retains storage access lists and signed baby logging access, and adds CPU policies and open-file limits. Older source formats are for older images only. |

Top-level field, not inside any table. Incremented on breaking schema changes.

### `[package]` - Package Data

Declares which files are bundled into the archive and what operators are expected to provide at deploy time. These are workload-level concerns; individual containers opt into all or selected entries via per-container `measured-data` and `unmeasured-data`.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `measured-data` | array of strings | no | `[]` | Files/directories included in the package and integrity-verified (PCR23). Logical absolute paths under the measured-data root. Files or directories. |
| `unmeasured-data` | array of strings | no | `[]` | Files/directories operators are permitted to provide at deploy time. Contents and presence are not integrity-verified, but the declared **allowlist path set** is committed to the manifest (PCR23). Logical absolute paths under the unmeasured-data root. |

**`measured-data`** — integrity-verified files (read-only). Included in the `.atawl` archive under `measured-data/`, hashed in the manifest's `[hashes]` section, and transitively covered by PCR23. The portal verifies their integrity at every boot. Directory structure is preserved (e.g., `/config/hello` is read from `<workload-dir>/measured-data/config/hello` by default and becomes `measured-data/config/hello` in the archive). Use `--measured-data-root` to read measured data from another root.

**`unmeasured-data`** — operator-provided files (read-only). The *contents* are not shipped in the archive or included in the workload measurement. Operators supply them at deployment or through an owner-authorized [v0.3.7 unmeasured-data update](unmeasured-data-update-spec.md). Both paths share file and env validation; updates replace the whole declared-file set on the next VM boot. Logical paths are read from `<workload-dir>/unmeasured-data` by default in directory mode, or from `--unmeasured-data-root` when supplied. The declared **paths** are recorded in the manifest's top-level `unmeasured-data` array (each entry prefixed `unmeasured-data/`, e.g. `unmeasured-data/config/cert.pem`) and are therefore covered by PCR23 as an allowlist: a verifier knows exactly which paths the deployer was permitted to upload, even though it cannot know their contents.

For unmeasured data, a trailing `/` explicitly declares a directory: `/config/` must exist at build time and expands into sorted member file paths. A path without `/` at the end declares one file and can be absent at build time, unless it is referenced by `unmeasured-env-file`. An existing directory declared without `/`, or a file declared with `/`, is an error. Declaring `/` enumerates the whole source directory. Enumeration rejects links and special files and reports read errors instead of silently omitting entries. The manifest still contains only exact file paths, sorted and deduplicated. Exact file declarations alone need no local source directory and never trigger a build-time prompt.

During `cloud deploy`, `cloud init`, and `workload init`, an explicit `--unmeasured-data-root DIR` (or its deprecated alias `--unmeasured-data-dir`) must identify an existing directory. Otherwise, directory input uses `<workload-dir>/unmeasured-data` when present. If paths are declared but no source is available, an interactive terminal prompts for a directory, continuation without data, or cancellation (the default). The choice occurs before creating a VM or sending initialization; multi-target deployment asks once. Without an interactive terminal, supply a source or `--no-unmeasured-data`. The skip flag also overrides an existing default directory and conflicts with either source flag. The CLI lists supplied and missing paths, never file contents. Missing individual files remain allowed. Archive and stored-workload inputs have no implicit source directory. No paths declared means no source and no prompt are needed.

At deploy time the portal verifies that the operator-supplied tar extracts to a **subset** of this allowlist before the workload runs. It accepts regular files and directories only. It rejects links, devices, FIFOs, sockets, traversal, duplicate paths, and undeclared files. Uploaded paths not declared in the manifest fail `/init` with `unmeasured_data_mismatch`. Missing declared paths are allowed: the allowlist is not a requirement that every listed file exists. Contents remain unverified, so every workload must validate each unmeasured file it consumes and fail closed on missing, empty, malformed, or otherwise invalid data.

Containers can set `measured-data = true` or `unmeasured-data = true` to receive all declared package data read-only at `/atakit-portal/measured-data/` or `/atakit-portal/unmeasured-data/`. They can instead provide a path array, such as `measured-data = ["/config/public.json"]`, to receive only selected package entries at their same relative container paths. `true`, `["/"]`, directory selectors, and explicit lists are authoring shortcuts. The builder always expands them to exact file paths in the manifest.

For each service, the supervisor creates one private unmeasured-data view containing only that service's exact selected files that are present. It uses filesystem reflinks when available and otherwise makes independent copies. It never uses hard links. The portal mounts that one view at `/atakit-portal/unmeasured-data/` with `readonly`, `noexec`, `nosuid`, and `nodev`. The root-owned canonical upload tree is frozen read-only and is never mounted into a container.

### `[workload]` - Workload Definition

The workload section defines both the metadata and the workload's own container.

#### Metadata

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | yes | - | Workload name. Alphanumeric + hyphens. |
| `version` | string | yes | - | Semver prefixed with `v` (e.g. `v0.0.1`). |
| `base-image-mode` | string | yes | - | `"whitelist"` or `"blacklist"`. Controls whether `base-image` is an allow-list or deny-list of CVM images. |
| `base-image` | array of strings | no | `[]` | List of base CVM image references (`name:version`). Interpreted according to `base-image-mode`. |
| `session-ttl` | integer | no | `0` | Session TTL in seconds. Determines how long a CVM session remains valid after attestation. `0` = contract default (30 days). |

#### `[workload.attributes]` - Attribute Policy

This optional table controls the base-image attribute values that a workload
permits. The builder always emits it as `config.attributes` in `manifest.json`,
including the empty `{}` map. PCR23 therefore binds both an explicit policy and
the empty default.

Custom names use arrays of string values. The builder encodes each custom name
and value with `keccak256(bytes(...))`. An empty custom array keeps the existing
registry meaning: the attribute must exist, but any value is accepted.

The following names have reserved verification rules:

| Name | Verified report field |
|---|---|
| `atakit.attestation.v1.tee.intel-tdx.debug.enabled` | Intel TDX `DEBUG` attribute |
| `atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed` | Intel DCAP TCB status |
| `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled` | AMD SEV-SNP `POLICY.DEBUG` |
| `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled` | AMD SEV-SNP `POLICY.MIGRATE_MA` |
| `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum` | AMD SEV-SNP current, reported, committed, and launch TCB minimums |
| `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy` | AMD SEV-SNP required-set and required-clear `PLATFORM_INFO` masks |

Each reserved Boolean value must be exactly `[false]` or `[false, true]`.
`[false]` permits only the disabled state. `[false, true]` permits either
verified state. A missing reserved Boolean entry has the same policy as
`[false]`. The builder rejects `[]`, `[true]`, duplicates, reversed values, and
other values.

The Intel TDX TCB status value is an array of supported status names. It must
contain unique names and include `"ok"`. The supported names, in canonical
order, are `"ok"`, `"sw-hardening-needed"`,
`"configuration-and-sw-hardening-needed"`, `"configuration-needed"`,
`"out-of-date"`, `"out-of-date-configuration-needed"`,
`"relaunch-advised"`, and
`"relaunch-advised-configuration-needed"`. The builder turns this array into
one on-chain bit mask. A missing entry permits only `"ok"`.

Each packed AMD SEV-SNP requirement must contain exactly one `0x`-prefixed
bytes32 string. The builder decodes that string into the exact on-chain value;
it does not hash the value string. During verification, a missing packed
requirement resolves to the active exact-CPUID
`AmdSnpSecurityPolicyRegistry` default. An explicit packed requirement
replaces that workload-side default. The layouts and resolution rules are
defined in
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).

The builder rejects unknown names under `atakit.attestation.v1.tee.`. Reserved
attributes for another TEE platform remain in the measured manifest. Session
verification evaluates only the reserved attributes for the verified TEE
platform.

Allowing `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled = [false,
true]` permits either value of the signed `POLICY.MIGRATE_MA` bit. It does not
permit an active migration-agent association. An all-zero or all-`0xff`
`REPORT_ID_MA` means that no migration agent is associated. Every other
`REPORT_ID_MA` remains unsupported and is always rejected.

`atakit workload info` and the `atakit workload publish` confirmation print
the source names and typed values. `atakit workload spec` recognizes the six
reserved on-chain hashes and prints their readable names and values. It keeps
ordinary on-chain keys and values as hexadecimal because their source strings
cannot be recovered from a hash.

**`base-image-mode`:**
- `"whitelist"` - the workload may **only** be deployed on the listed base images. Use when the workload is validated against specific CVM versions.
- `"blacklist"` - the workload may be deployed on **any** base image **except** the listed ones. Use to exclude known-incompatible or deprecated images.

#### Image Source

The `image` field specifies where the workload's container image comes from. Its type determines the source:

| Form | Type | Description |
|---|---|---|
| `image = "name:tag"` | string | Pull a pre-built image from a registry. |
| `image = { build = "." }` | table | Build from source. `build` is the context directory. |
| `image = { file = "./path.tar" }` | table | Load from a local OCI archive. |

**Build table fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `build` | string | yes | Build context directory (relative to `atakit-workload.toml`). |
| `containerfile` | string | no | Containerfile path relative to context. Default: `"Containerfile"`. |
| `args` | table | no | Build arguments. `{ KEY = "value" }` |

Built images are auto-tagged as `{workload.name}:{workload.version}`.

#### Container Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `ports` | array of strings | `[]` | Exposed ports. Format: `"host:container[/protocol]"`. No protocol suffix means both TCP and UDP. Use `/tcp` or `/udp` to restrict. No port ranges. |
| `depends_on` | array of strings | `[]` | Service names that must start first. A service name is the exact `[workload] name` or a `[dependencies.<name>]` key. |
| `restart` | string | `"no"` | Restart policy: `"no"`, `"always"`, `"on-failure"`, `"unless-stopped"`. |
| `command` | string or array | - | Override container CMD. Strings run through `/bin/sh -c` inside the container; arrays are literal arguments. |
| `entrypoint` | string or array | - | Override container ENTRYPOINT. Strings run through `/bin/sh -c` inside the container; arrays are literal arguments. |
| `environment` | table | `{}` | Environment variables. `{ KEY = "value" }` |
| `env-file` | string or array | `[]` | Measured build-time `.env` file path(s). Resolved relative to `atakit-workload.toml`, parsed during build, and inlined into `environment`. Legacy alias: `env_file`. |
| `unmeasured-env-file` | string or array | `[]` | Ordered runtime operator-supplied `.env` file path(s). Each normalized path must be declared in `[package] unmeasured-data`. The developer-side file must exist at build time. Its variable names are measured; its values are not. |
| `ip-env` | bool | `false` | Opt in to runtime injection of `ATAKIT_PUBLIC_IP` and `ATAKIT_INTERNAL_IP`. Unavailable values are injected as empty strings. These reserved variables override matching user-provided environment variables. |
| `atakit-portal` | bool | `false` | Mount a portal UDS socket at `/run/atakit-portal.sock` for this service. |
| `gid-group` | string | workload name | GID sharing group. Services with the same `gid-group` share a host GID. Defaults to the workload name when omitted. |
| `measured-data` | bool or array of strings | `false` | `true` mounts all measured data; an array mounts only selected `[package].measured-data` entries. |
| `unmeasured-data` | bool or array of strings | `false` | `true` mounts all unmeasured data; an array mounts only selected `[package].unmeasured-data` entries. |
| `boot-disk-size` | string | - | Minimum boot/OS disk size (e.g. `"50GB"`). Cloud provider default if omitted. Valid units: MB, GB, TB. The actual disk may be larger if the base image requires more. |
| `cap-add` | array of strings | `[]` | Linux capabilities to grant on top of the default cap set. Allowlisted to a small reviewed set (currently `"NET_ADMIN"`, `"NET_RAW"`). See [Capabilities](#capabilities). |
| `cap-drop` | array of strings | `[]` | Linux capabilities to remove from the default cap set as a hardening commitment. Entries must be members of the default cap set. See [Capabilities](#capabilities). |

#### Optional startup readiness

Source format 9 adds `[workload.readiness]` and
`[dependencies.<name>.readiness]`. Omitting the table keeps startup based on
container start order. The complete table is copied into the measured manifest;
changing any field changes the workload measurement.

```toml
[dependencies.db.readiness]
command = ["/app/check-ready", "--database"]
interval-seconds = 2
attempt-timeout-seconds = 5
deadline-seconds = 60
```

| Field | Required | Meaning |
|---|---|---|
| `command` | yes | Executable and literal arguments inside that service's container. The executable must be present in its image. |
| `interval-seconds` | yes | Wait after a completed failed attempt before trying again. |
| `attempt-timeout-seconds` | yes | Podman's time limit for each check command. |
| `deadline-seconds` | yes | Total time allowed for this service's startup check. |

Durations must be positive integers. The interval and attempt timeout must not
exceed the deadline; the deadline is capped at 86400 seconds. Commands allow up
to 128 entries and 16384 bytes in total; the executable must be nonempty and must
not begin with `-`; NUL bytes are rejected. Unknown table fields are rejected by
both the builder and portal.

The portal keeps serial startup order. After starting a service with readiness,
it waits for a successful check before starting the next service, including any
unrelated service later in that order. The first exit code 0 completes the check.
A completed nonzero exit code retries. Container exit/restart, Podman errors,
watchdog expiry, initialization cancellation, or the service deadline fail
startup and trigger existing container/PCR/disk cleanup. Readiness commands and
HTTP/TCP clients execute inside the service's container with its existing
permissions; the portal does not interpret their arguments as a shell command.

Readiness runs during `InitializingWorkload`, before session registration.
Commands must work without waiting for that registration. The overall `/init`
timeout still applies and may expire before a service deadline. `cloud resume`
does not restart attempts or reset timers. Checks stop after startup success;
this is not ongoing health monitoring or an application restart policy.

The public `/status` response includes `readiness`, keyed by service name, with
`state` (`not_configured`, `waiting`, `checking`, `ready`, `failed`), `attempts`,
`elapsed_ms`, `last_exit_code`, and `error`. It does not include command output.
`ready` records startup success; current container state remains a separate
observation.

#### Capabilities

`cap-add` and `cap-drop` declare the workload's Linux capability surface relative to a fixed default set. Both fields are per-container — declared independently on `[workload]` and on each `[dependencies.<name>]`. Both default to `[]`.

**Default cap set.** The runtime grants the following capabilities to every container by default (this is podman's compiled-in non-rootless-modified default; the runtime pins it explicitly so a container engine upgrade does not silently drift the attestation surface):

```
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_FOWNER
CAP_FSETID
CAP_KILL
CAP_NET_BIND_SERVICE
CAP_SETFCAP
CAP_SETGID
CAP_SETPCAP
CAP_SETUID
CAP_SYS_CHROOT
```

In `cap-add` and `cap-drop`, capability names are written in the canonical uppercase form **without** the `CAP_` prefix (matching `--cap-add` / `--cap-drop` argv shape). For example, drop `CAP_NET_BIND_SERVICE` by writing `cap-drop = ["NET_BIND_SERVICE"]`.

**`cap-add` allowlist.** Only `"NET_ADMIN"` and `"NET_RAW"` are accepted. Each capability widens the workload's attestation surface, so the allowlist is intentionally narrow; expanding it is a deliberate spec change with a per-cap review of operator-side reasoning impact.

**`cap-drop` allowlist.** Any member of the default cap set above. Dropping a cap is a monotonically-narrowing hardening claim, so this list is not separately curated — workloads may commit to relinquishing any default cap. An entry that names a cap not in the default set is rejected (otherwise it would be a silent no-op that misleads operator reasoning).

**No overlap.** A capability cannot appear in both `cap-add` and `cap-drop` for the same container. The two declarations would contradict each other.

**Empty as commitment.** Both fields are *always* serialized into `manifest.json`, including when empty. An empty `cap-add` is a positive commitment that the workload runs without `NET_ADMIN` and `NET_RAW`. An empty `cap-drop` is a positive commitment that the workload retains the full default cap set. PCR23 binds either declaration into attestation.

**Mutual-distrust framing.** Capabilities matter most when a baby container shares a network namespace with the workload. Two stances must be expressible:

- *Workload owner controls baby-container network policy.* `cap-add = ["NET_ADMIN"]` lets the workload install nftables in its own netns; baby containers placed into that netns inherit the rules and cannot escape them. The `/baby-container` API does not grant `NET_ADMIN` or `NET_RAW` to baby containers placed into the workload's netns, so the workload's policy cannot be subsequently undone by an operator-launched container.
- *Workload owner commits to **not** controlling baby-container network policy.* `cap-add = []` is a measured commitment that the workload does not have `NET_ADMIN` and therefore cannot post-hoc firewall shared-netns peers. An operator inspecting the manifest can rely on this commitment when deciding whether to drop a baby container into the workload's netns.

Without `cap-add` in the manifest, neither stance is expressible — every workload would run identically and the manifest could not commit to either property.

**Capability semantics.**

- **`NET_ADMIN`** — policy-control axis. Holder dictates netns-wide nftables rules. In the mutual-distrust setting above, peers in shared netns are subject to the holder's egress/ingress policy.
- **`NET_RAW`** — visibility / packet-injection axis. Holder can open raw sockets to sniff peer traffic in shared netns, inject forged packets, or run RST attacks. Does not grant control over peers' rules but does grant a different coercive vector. Operators reading the manifest must consider both axes before joining a baby container.

**Containment.** Capabilities granted via `cap-add` are scoped to the workload's user namespace and (where relevant) the workload's network namespace. They cannot reach the host's namespaces, the supervisor, or any other workload. `NET_ADMIN` in a userns-owned netns affects only that netns. The pod-level isolation guarantees of rootless podman are unchanged.

#### Data Mounts

Portal-managed directories are exposed through fixed mount targets; workloads do not choose arbitrary container paths. `measured-data` and `unmeasured-data` control data delivered via `[package]`, and `workload-logs` controls log subdirectories granted by `logging.log-readers`.

**`measured-data`** - when `true`, bind-mount all measured package entries read-only under `/atakit-portal/measured-data/`. When an array is supplied, bind-mount only selected package entries at the same relative paths.

**`unmeasured-data`** - when `true`, bind-mount all operator-provided unmeasured entries read-only under `/atakit-portal/unmeasured-data/`. When an array is supplied, bind-mount only selected package entries at the same relative paths.

**`workload-logs`** - when `true`, bind-mount `/atakit-portal/workload/logs/` read-only into this container at `/atakit-portal/workload-logs/`. The reader sees only the subdirectories of producing services that grant access via their `logging.log-readers` list; producers not granting access do not appear in the mount. Access also requires the reader to run with container-GID 0 in its process credentials (logs are mode 0640, group-owned by the gid-group host GID) and to share `gid-group` with each producer it reads from. See `#### Container Logging` below.

All three default to `false`. `workload-logs` remains a boolean opt-in.

**`[workload.storage.<label>]`** - Persistent storage mounts

For format 14, use the required `access` field described above. The following fields describe formats through 13.

Mounts a declared disk, or a subpath of a declared disk, into the workload container. The label is local to the service and must be a stable identifier.

```toml
[workload.storage.data]
disk = "secure-signer-data"
base-path = "/"
mount-path = "/data"
read-only = false
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `disk` | string | yes | - | Disk name; must match a `[disks.<name>]` entry. |
| `base-path` | string | yes | - | Absolute path under the mounted disk root. Created if missing. |
| `mount-path` | string | yes | - | Absolute container mount path. Must be unique within the service. |
| `read-only` | bool | no | `false` | Mount this storage entry read-only. |
| `executable` | bool | no | `false` | Allow binaries, scripts, and native libraries to execute from this mount. Keeps `nosuid,nodev`; independent of `read-only`. |

#### Container Logging

`[<service>.logging]` configures the podman log driver, its options, and the manifest-level allowlist of services that may read this service's logs. The same shape applies to `[workload.logging]` and each `[dependencies.<name>.logging]`.

| Field         | Type                  | Default                                                                  | Description                                                                                       |
|---------------|-----------------------|--------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `driver`      | string                | `"k8s-file"`                                                             | Podman log driver. Allowlist: `{"k8s-file", "none"}`.                                             |
| `options`     | table<string,string>  | `{max-size = "50m", max-file = "5"}` for `k8s-file`; `{}` for `none`     | Driver options. Per-driver key allowlist below.                                                   |
| `log-readers` | array of strings      | `[]` (default deny)                                                      | Service names in this workload that may receive a bind-mount of this service's log directory.     |

**Per-driver option allowlist:**

| Driver     | Allowed keys           | Bounds                                                                                |
|------------|------------------------|---------------------------------------------------------------------------------------|
| `k8s-file` | `max-size`, `max-file` | `max-size`: `<n>{k\|m\|g}` or bare bytes, ≤ 500m. `max-file`: positive integer ≤ 20. |
| `none`     | (none)                 | Must be empty.                                                                        |

`options.path` is never user-settable. The portal injects the canonical path (`/atakit-portal/workload/logs/<service>/<service>.log`) so all services' logs land in the per-producer subdirectory layout that supports access control. Setting `path` in the manifest is a build-time error.

**Defaults are materialised in `manifest.json`.** Omitting `[<service>.logging]` is equivalent to writing `driver = "k8s-file"` with the k8s-file default options and `log-readers = []`. Every service in every workload has a concrete `logging` table in the canonical JSON; PCR23 binds the actual driver, options, and log-readers list.

**Why no remote drivers.** Podman does not natively accept `fluentd`, `syslog`, `gelf`, `splunk`, or `awslogs` as log drivers; those are Docker drivers, and podman rejects them at container-create time with `Error: running container create option: invalid log driver: invalid argument`. Remote log delivery is therefore implemented as a shipper dependency that tails the local log files and ships them; the shipper's outbound traffic is declared in `[firewall]` / `ports` and measured into PCR23 like any other service's egress. See `dependency-runtime-spec.md` → "Per-Container Log Mounting".

**Access control.** A producer's logs are readable by a reader R only if all of the following hold:
1. R appears in the producer's `logging.log-readers` list.
2. R has `workload-logs = true`.
3. R and the producer are in the same `gid-group` (or both use the default).
4. R's process credentials include container-GID 0.

(1) and (2) are enforced as hard errors at build time and at portal `/init`. (3) and (4) are documented requirements; misconfigurations surface as `Permission denied` from the reader process at startup.

### `[dependencies.<name>]` - Dependency Containers

Supporting containers the workload needs (databases, caches, sidecars, etc.). Same container configuration fields as `[workload]`, same `image` field with the same three forms (registry string, build table, file table).

Dependencies also support:

| Field | Type | Default | Description |
|---|---|---|---|
| `depends_on` | array of strings | `[]` | Service names that must start first. This can include the main workload's exact `name`. |
| `atakit-portal` | bool | `false` | Mount a portal UDS socket for this dependency. |
| `gid-group` | string | workload name | GID sharing group for this dependency. |
| `measured-data` | bool or array of strings | `false` | `true` mounts all measured data; an array mounts only selected `[package].measured-data` entries. |
| `unmeasured-data` | bool or array of strings | `false` | `true` mounts all unmeasured data; an array mounts only selected `[package].unmeasured-data` entries. |
| `cap-add` | array of strings | `[]` | Linux capabilities to grant. Allowlisted to `"NET_ADMIN"`, `"NET_RAW"`. Per-container — independent of the workload's `cap-add`. See [Capabilities](#capabilities). |
| `cap-drop` | array of strings | `[]` | Linux capabilities to drop from the default cap set. Per-container. See [Capabilities](#capabilities). |
| `logging` | table | `{driver = "k8s-file", options = {max-size = "50m", max-file = "5"}, log-readers = []}` | Per-container log driver + options + log-readers allowlist. Same shape as `[workload.logging]`. See [Container Logging](#container-logging). |
| `workload-logs` | bool | `false` | Receive a read-only bind-mount of `/atakit-portal/workload/logs/` containing only the producer subdirs that grant access via their `logging.log-readers`. See [Container Logging](#container-logging). |
| `ip-env` | bool | `false` | Same semantics as `[workload] ip-env`, scoped to this dependency container. |

Dependencies can have their own `storage` sections:

```toml
[dependencies.redis]
image = "redis:7"

[dependencies.model-server]
image = { file = "./images/model-server.tar" }
ports = ["8080:8080"]
gid-group = "backend"
measured-data = true

[dependencies.model-server.storage.cache]
disk = "model-cache"
base-path = "/"
mount-path = "/data/cache"
read-only = false
```

Built dependency images are auto-tagged as `{dependency_name}:{workload.version}`.

### `[disks.<name>]` - Persistent Storage

Defines persistent disk volumes attached to the CVM. Referenced by `[workload.storage.<label>]` or `[dependencies.<name>.storage.<label>]`. A disk can be shared between multiple containers, and each service controls its own `base-path`, `mount-path`, and `read-only` setting.

| Field | Type | Required | Description |
|---|---|---|---|
| `index` | integer | no | LUN / device index for cloud disk attachment. Must be >= 10 and unique across all disks. Auto-assigned from 10 in alphabetical disk name order if omitted. |
| `size` | string | yes | Disk size (e.g. `"10GB"`). Minimum is `"10GB"`. |

#### `[disks.<name>.encryption]` - Disk Encryption

Uses the unified encryption schema (same structure as [baseimage.toml](baseimage-toml-spec.md) RW partition encryption).

| Field | Type | Required | Description |
|---|---|---|---|
| `unlock_method` | string[] | yes | Unlock methods. Supported values: `"tpm"`, `"passphrase"`. Reserved values (not yet supported, rejected at build time): `"keyfile"`, `"kms"`. May be empty (no encryption). Entries must be unique. |
| `bind` | string[] | yes (may be `[]`) | PCR bindings when `unlock_method` includes `"tpm"`: `"platform"` (0-7), `"baseimage"` (11), `"workload"` (23). |

```toml
[disks.secure-data]
size = "10GB"
encryption = { unlock_method = ["tpm"], bind = ["workload"] }
```

**`unlock_method` semantics:**

| Value | Description |
|---|---|
| `"tpm"` | TPM2 PCR-sealed key. Instance-bound; bind list controls which PCRs are in the seal policy. |
| `"passphrase"` | Operator-supplied secret. Delivered out-of-band via `init-config.disks.<name>.passphrase` at `/init` — the workload TOML names the disk; the operator owns the secret. Never embed the passphrase value in this TOML; the archive is measured into PCR23 and any secret here is leaked to anyone with the archive. |

When both `"tpm"` and `"passphrase"` are listed, TPM is attempted first on every mount; passphrase is the fallback (break-glass / migration). Passphrase-only disks have no fallback — a missing or wrong passphrase fails the workload.

**Always-emit invariant.** The `encryption` block is always serialised into `manifest.json`, even when both arrays are empty. An empty `unlock_method` is itself a positive commitment that the disk runs without encryption. PCR23 binds the declaration into attestation, so omitting the section and writing an empty section must produce the same measurement.

**Constraints:**
- `index` >= 10 to avoid collision with boot disk (LUN 0) and system devices.
- `index` must be unique across all `[disks.*]` entries.

### `[firewall]` - VM Firewall Overrides

By default, the CVM firewall auto-derives allow rules from `ports` across all services. A port without a protocol suffix opens both TCP and UDP; `/tcp` or `/udp` restricts to one protocol. The `[firewall]` section is optional and only needed to deviate from the auto-derived rules.

| Field | Type | Default | Description |
|---|---|---|---|
| `allow` | array | `[]` | Additional ports to allow beyond auto-derived rules. |
| `deny` | array | `[]` | Suppress auto-derived rules for specific port/protocol pairs. |

**Entry format (same for both allow and deny):**

Three forms are accepted:
- String: `"3000/tcp"`, `"5353/udp"`, or `"4000"` (both protocols). Same format as `ports` but without the container port.
- Integer: `3000` (both protocols).
- Object: `{ port = 3000, protocol = "tcp" }`.

Port must be 1025-65535. Protocol, if specified, must be `"tcp"` or `"udp"`.

```toml
[firewall]
# Extra port for a baby container that will bind here
allow = ["4000/tcp"]

# metrics-proxy exposes 9091 in compose but should be CVM-internal only
deny = [9091]

# Deny only UDP for port 3000 (keep TCP open)
# deny = ["3000/udp"]
```

If no `[firewall]` section exists, the workload gets exactly the auto-derived rules from `ports`. Ports 1024/tcp and 2024/tcp (portal HTTPS API) are always included in the manifest's `firewall-ports` by the build pipeline, regardless of this config. These are TCP-only since the portal serves HTTPS. User `deny` entries cannot remove them.

### `[baby-container]` - Baby Container Runtime

Controls whether the workload can create runtime baby containers through the
portal API. Disabled by default. Baby containers are workload-declared extension
points: the workload designer defines slots, and a baby-container user supplies
or authorizes images for those slots at runtime.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable baby container slots. |
| `max-instances` | integer | `0` when disabled, `1` when enabled and omitted | Maximum concurrent baby containers across all slots. |

```toml
[baby-container]
enabled = true
max-instances = 2
```

When `enabled = false` or `[baby-container]` is absent, the compiled manifest
materialises `enabled = false`, `max_instances = 0`, and `slots = {}`.

#### `[baby-container.slots.<name>]`

Defines a named baby-container extension point. Slot names are stable map keys
and are committed into `manifest.json`.

| Field | Type | Default | Description |
|---|---|---|---|
| `parent-service` | string | required | Workload service that owns this slot and whose portal UDS may operate it. |
| `gid-group` | string | parent service `gid-group` | Shared GID group used for baby storage permissions. |
| `image-selection` | string | `"single"` | `"single"` means at most one active image can be staged and `create` may omit `image_id`; `"multiple"` means many images can be staged and `create` must name `image_id`. |
| `max-instances` | integer | `1` | Maximum concurrent baby containers in this slot. Writable roots also count retained stopped/failed instances against this limit. |
| `trust-policy` | string | none | Unsupported: any supplied reference is rejected. |
| `allowed-capabilities` | string array | `[]` | Measured capability additions this slot permits. Restricted to CHOWN, SETUID, SETGID, SYS_CHROOT, FOWNER, DAC_OVERRIDE. |
| `ip-env` | bool | `false` | Opt in baby containers created from this slot to `ATAKIT_PUBLIC_IP` and `ATAKIT_INTERNAL_IP` injection. |

#### `[baby-container.slots.<slot>.lifecycle]`

Controls whether uploaded images or container instances survive workload/CVM
restart. Persistence is explicit because it changes the boot reconciliation
contract.

| Field | Type | Default | Description |
|---|---|---|---|
| `image-retention` | string | `"session"` | `"session"` means uploaded images are usable only for the current workload session and are pruned from the workload-scoped Podman image namespace on startup. `"disk"` means loaded images are retained in portal Podman graphroot, indexed by the portal, and reconciled on boot. |
| `instance-retention` | string | `"ephemeral"` | `"ephemeral"` removes instances at teardown/reconciliation. `"session"` keeps stopped instances only within the current workload session. `"disk"` preserves the instance record and, for writable roots, its private writable layer across workload and VM restarts on retained backing storage. |
| `restart` | string | `"manual"` | `"manual"` never auto-starts a retained instance. `"on-workload-start"` restarts eligible retained instances after the parent service starts. An explicit stop remains stopped until `/baby-container/start`. |
| `rootfs` | string | `"read-only"` | `"writable"` enables a private layer independent of the Podman container. Requires source format 10 and a configured storage backend. |
| `rootfs-size-mib` | integer | none | Required positive per-instance writable-root byte limit in MiB. Rejected with `read-only`. Separate declared volumes and the immutable image are not charged to this limit. |
| `rootfs-disk` | string | omitted | Source format 11. Selects a declared disk for private per-instance backing files. Omitted uses the boot disk writable partition. Requires `rootfs = "writable"` and an explicit `rootfs-size-mib`. The selected disk must not also appear in any service or baby storage mount. Multiple slots may select the same disk. |

Runtime image uploads are not part of the `.atawl` archive and do not change
PCR23. The portal loads the uploaded tar into Podman, then tags it under the
workload-scoped local namespace:

```text
localhost/atakit-baby/<workload-id>/<service>/<slot>:<image-id-hex>
```

The tag is a cleanup/reconciliation marker only. Baby-container creates still
run by canonical image ID.

#### `[baby-container.slots.<slot>.storage.<name>]`

Declares persistent or session storage mounted into baby containers. Storage is
backed by `[disks.<name>]` entries; callers never provide host paths.

| Field | Type | Default | Description |
|---|---|---|---|
| `disk` | string | required | Backing workload disk name. Must match `[disks.<name>]`. |
| `base-path` | string | required | Directory under the backing disk used as the storage root. |
| `mount-path` | string | required | Absolute path inside the baby container. |
| `retention` | string | `"session"` | `"session"` or `"disk"`. `"disk"` survives according to the backing workload disk policy. |
| `scope` | string | `"instance"` | Storage namespace: `"slot"`, `"image"`, `"instance"`, or future `"key:<name>"`. |
| `read-only` | bool | `false` | Mount storage read-only for the baby. |
| `executable` | bool | `false` | Allow execution from this baby mount. Keeps `nosuid,nodev`; the baby operator cannot override this manifest grant. |

Permissions are explicit:

```toml
[baby-container.slots.analysis-job.storage.workspace.permissions]
baby = "rw"
parent = "ro"
```

Permission values are `"none"`, `"ro"`, or `"rw"`.

Storage scope behavior:

- `slot`: all instances/images in the slot share the same directory.
- `image`: instances using the same image ID share a directory.
- `instance`: each create request uses `instance-id` to select a directory.
- `key:<name>`: future extension using create-request `storage-keys.<name>` to
  select a directory under `base-path`.

`instance-id` and `storage-keys` values are identifiers, not paths. The portal
validates them and resolves them under the declared `base-path`.

`trust-policy`, when present, is only a reference. The policy namespace and
key-store syntax are specified separately from baby containers so the portal can
reuse the same trust material for future features. Persistent cache, storage,
and other externally mutable data are not trusted authority merely because they
survived on disk.

---

## Explicitly Unsupported (Security Boundary)

These compose features are intentionally excluded. The CVM runtime controls these:

| Feature | Reason |
|---|---|
| `networks` | CVM controls network topology |
| `privileged` | No privilege escalation |
| `devices` | No host device passthrough |
| `pid` / `ipc` / `uts` | No namespace sharing |
| `security_opt` | CVM manages security policies |
| `user` | CVM controls container user |
| `read_only` | Controlled via mount sections above |
| `shm_size` / `tmpfs` | CVM manages memory mounts |
| `sysctls` | No kernel parameter tuning |
| `ulimits` | Generic limits are unsupported; use the format-16 `nofile` field below |

---

## Validation Rules

### Format

- The source parser supports formats `2` through `16`; `16` is current. Use `format = 16` for v0.3.7. The generic compiled-manifest parser reads formats 11–16, but the v0.3.7 Portal startup gate accepts only 16. Format 1 is rejected.
- Legacy fields (`cvm_agent`, `[signing]`, old encryption `{enable, key_security}`) are detected and rejected with specific migration hints.

### Workload

- `version` must start with `v`
- `name` must be alphanumeric + hyphens
- `base-image-mode` must be `"whitelist"` or `"blacklist"`
- `base-image`, if present, must be an array of `name:version` strings (may be empty)
- `image` must be present (string, build table, or file table)

### Image

- String form: must not be empty
- Build table: `build` (context path) is required, `containerfile` and `args` are optional
- File table: `file` path must end in `.tar` or `.tar.gz` and exist at build time
- Build and file tables are mutually exclusive (cannot have both `build` and `file` keys)

### Dependencies

- Same image and container validation rules as workload
- `[workload] depends_on` and each dependency's `depends_on` entries must name the exact workload name or a dependency defined in the file
- A service cannot depend on itself, repeat a name in `depends_on`, or form a dependency cycle
- A dependency name cannot equal the workload name
- `env-file` paths must exist relative to `atakit-workload.toml`; `env_file` is accepted only as a legacy alias, and using both spellings in one service is rejected
- Every `unmeasured-env-file` path must exist under the unmeasured-data root at build time and must also be present in `[package] unmeasured-data`.
- The builder parses each developer-side unmeasured env file as a template. It records the sorted variable names in the manifest and ignores their values. Names must use shell identifier syntax: the first character is an ASCII letter or `_`, and later characters are ASCII letters, digits, or `_`.
- Env files use one `NAME=VALUE` entry per line. Blank lines and lines whose first non-space character is `#` are ignored. The parser splits at the first `=`, trims surrounding space from the name and value, and does not expand quotes, escapes, variables, or shell commands.
- Duplicate names within one env file and names beginning with reserved prefix `ATAKIT_` or `VERIFIERD_` are rejected. `VERIFIERD_*` values configure `atakit-verifierd` trust and optional portal destination policy, so they must be supplied through measured `environment` or measured `env-file` input.
- Host ports must be unique across all containers (workload + dependencies)

### Disks

- Each disk referenced in `[workload.storage.*]` or `[dependencies.*.storage.*]` must have a corresponding `[disks.<name>]` entry
- `size` must be a valid size string (e.g. `"10GB"`, `"500MB"`)
- `encryption.unlock_method` values must be from `"tpm"` or `"passphrase"`. `"keyfile"` and `"kms"` are reserved; the build pipeline rejects them with a "not yet supported" message listing the supported set.
- `encryption.unlock_method` entries must be unique (no `["tpm", "tpm"]`).
- `encryption.bind` values must be from: `"platform"`, `"baseimage"`, `"workload"`

### Firewall

- Port must be 1025-65535 (both allow and deny)
- Protocol, if specified, must be `"tcp"` or `"udp"`
- No protocol (bare integer or string without `/proto`) means both tcp and udp
- `deny` entries that don't match any auto-derived port/protocol are warnings (no-op)
- `allow` entries that duplicate an auto-derived port/protocol are warnings (redundant)
- String entries must not include a container port (e.g. `"3000:80/tcp"` is rejected)

### Baby Container

- If `[baby-container]` is absent or `enabled = false`, compiled
  `max_instances` is `0` and `slots` is `{}`.
- If `enabled = true`, `max-instances` must be a positive integer.
- Slot names and storage names must be stable identifiers.
- `parent-service` must name the workload service or one dependency with
  `atakit-portal = true`.
- `image-selection` must be `"single"` or `"multiple"`.
- `trust-policy`, when present, must name a declared portal trust policy once
  the trust/key-store schema is implemented.
- `image-retention` must be `"session"` or `"disk"`.
- `instance-retention` must be `"ephemeral"`, `"session"`, or `"disk"`.
- `restart` must be `"manual"` or `"on-workload-start"`.
- `rootfs` must be `"read-only"` or `"writable"`. Writable roots require a positive, overflow-safe `rootfs-size-mib`. Disk-retained writable instances require disk-retained images.
- `allowed-capabilities` requires format 10 and must be a unique subset of `CHOWN`, `SETUID`, `SETGID`, `SYS_CHROOT`, `FOWNER`, and `DAC_OVERRIDE`. The default is empty. API `cap_add` must also fit this grant.
- Named `trust-policy` references are rejected until their enforcement exists.
- Parent storage mounts must not contradict baby `permissions.parent`. Baby and relevant parent storage source paths cannot contain symbolic links at runtime.
- `retention` must be `"session"` or `"disk"`.
- `scope` must be `"slot"`, `"image"`, `"instance"`, or `"key:<identifier>"`.
- `disk` must reference a declared `[disks.<name>]`.
- `base-path` and `mount-path` must be absolute paths without `..`, NUL, `:`,
  or `,`.
- `permissions.baby` and `permissions.parent` must be `"none"`, `"ro"`, or
  `"rw"`.

### Capabilities

- `cap-add` and `cap-drop` apply per-container (workload and each dependency, independently).
- Capability names use the canonical uppercase form **without** the `CAP_` prefix (e.g., `"NET_ADMIN"`, not `"CAP_NET_ADMIN"` or `"net_admin"`).
- `cap-add` entries must be one of `"NET_ADMIN"`, `"NET_RAW"`. Out-of-allowlist entries are rejected with the offending value and the allowed set in the error.
- `cap-drop` entries must be members of the default cap set (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `NET_BIND_SERVICE`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`). Dropping a cap that is not in the default set is rejected (it would be a silent no-op).
- A capability name cannot appear in both `cap-add` and `cap-drop` for the same container.

### Logging

Per-service rules (applied independently to `[workload.logging]` and each `[dependencies.<name>.logging]`):

1. `driver` must be in the allowlist `{"k8s-file", "none"}`.
2. `options` must not contain the key `"path"` — portal-injected, never user-settable.
3. If `driver == "none"`, `options` must be empty.
4. Every key in `options` must be in that driver's option allowlist (`k8s-file → {max-size, max-file}`; `none → {}`).
5. `options.max-size`, if present, must parse as a size suffix (`<n>{k|m|g}` or bare bytes) and must not exceed 500m.
6. `options.max-file`, if present, must be a positive integer not exceeding 20.
7. If `driver == "none"`, `log-readers` must be empty (no logs are produced, no grants are meaningful).
8. `log-readers` must not contain duplicates.
9. Every name in `log-readers` must resolve to a service in the same workload (the workload's own `name`, or a `[dependencies.<name>]` key). Self-grant is allowed.

Cross-service consistency (applied after per-service validation):

10. If producer P's `logging.log-readers` includes reader R, then R must have `workload-logs = true`. Both sides must land in the same manifest; partial grants are rejected.
11. If service R has `workload-logs = true`, at least one producer must include R in its `logging.log-readers`. An opt-in without grants is rejected.

All eleven rules are hard errors at build time AND at portal `/init`. The build pipeline and the portal share an identical allowlist + validation implementation; a constants mismatch between the two is a CI failure.

Baby slots also accept `[baby-container.slots.<slot>.logging]`. Its `driver`,
`options`, and `log-readers` follow the same rules. `access` is either `parent`
(the default) or `none`; it controls only the parent's
`GET /baby-container/logs` endpoint. `access` is not valid on workload or
dependency logging. The build writes the concrete baby `access` value into
`manifest.json`, so PCR23 binds it. Unknown logging fields are rejected.

A baby `log-readers` grant requires the reader's `workload-logs = true` and
the same `gid-group` as the baby slot. Portal prepares one stable log directory
per slot and mounts it read-only at `/atakit-portal/baby-logs/<slot>` inside
each granted reader. The reader process must use container GID 0 to read the
group-owned files. It sees new baby instance files in that directory
and can run its own remote log shipper. Portal removes an instance's log files
on explicit removal and removes orphan files on the next workload start.
Set `format = 16` for every workload deployed to automata-linux v0.3.7.
The older v0.3.5 release requires `format = 15`,
including workloads without baby containers. An older Portal rejects manifest
format 15. Format 14 remains available when building for an older image; it
does not carry signed baby logging access or activate baby `log-readers`.

### Package

- All `[package] measured-data` and `unmeasured-data` entries must be logical absolute paths beginning with `/`
- All `[package] measured-data` entries must exist at build time (files or directories)
- `[package] unmeasured-data` file declarations need not exist at build time unless used as an `unmeasured-env-file`. Directory declarations must end in `/` and must exist for enumeration. Exact files alone need no source directory. The resulting exact path set is measured in the manifest; file contents are supplied at deployment or by an owner-authorized full replacement on the next VM boot.
- Every `unmeasured-env-file` entry must normalize to one of the manifest's top-level `unmeasured-data` paths. The manifest also records its sorted variable-name allowlist.
- Per-container `measured-data` and `unmeasured-data` must be booleans or arrays of logical absolute package paths.
- A path-array entry must start with `/`, must not contain traversal, and must match at least one normalized package data path. Unmeasured directory selectors must end in `/` and expand only to declared member files; unmeasured selectors without `/` match exact files.

---

## Container Runtime Mapping

The portal uses direct podman calls (not compose) to run containers. The manifest (`manifest.json` inside the `.atawl` archive - see [archive spec](atawl-archive-spec.md)) is the compiled form of this source TOML.

The mapping below shows the conceptual correspondence between source TOML fields and container runtime configuration:

| atakit-workload.toml | Container runtime |
|---|---|
| `[workload]` | Main workload container (named `{workload.name}`) |
| `[dependencies.<name>]` | Dependency container (named `<name>`) |
| `image` (resolved to `name:tag`) | Container image |
| `ports` | Port mappings |
| `restart` | Restart policy |
| `command` | CMD override |
| `entrypoint` | ENTRYPOINT override |
| `environment` + `env-file` | Measured environment variables (merged, inlined) |
| `unmeasured-env-file` | Portal parses each file, rejects undeclared keys, and passes merged explicit values to Podman. Later files override earlier files. |
| `ip-env = true` | Inject `ATAKIT_PUBLIC_IP` and `ATAKIT_INTERNAL_IP` as explicit environment variables after measured env resolution, overriding user values |
| `depends_on` | Startup ordering |
| `measured-data = true` | Bind mount entire `measured-data/` directory to `/atakit-portal/measured-data/` (read-only) |
| `measured-data = ["/config/a"]` | Bind mount only selected measured entries to `/atakit-portal/measured-data/config/a` (read-only) |
| `unmeasured-data = true` | Expand to all exact declared files, build one private service view, and mount it at `/atakit-portal/unmeasured-data/` with `readonly,noexec,nosuid,nodev` |
| `unmeasured-data = ["/runtime/key"]` | Put only the exact selected present files in that service view |
| `[*.disks]` | Volume mounts |
| `atakit-portal = true` | Portal UDS socket at `/run/atakit-portal.sock` |
| `cap-add` | One `--cap-add NAME` per entry |
| `cap-drop` | One `--cap-drop NAME` per entry |
| `logging.driver` | `--log-driver=<driver>` |
| `logging.options` (k8s-file) | One `--log-opt=KEY=VALUE` per entry, sorted by key, plus portal-injected `--log-opt=path=/atakit-portal/workload/logs/<service>/<service>.log` |
| `log-readers` (producer side) | Drives `--volume` emission on grantees; not a direct argv flag |
| `workload-logs = true` | One `--volume=/atakit-portal/workload/logs/<P>:/atakit-portal/workload-logs/<P>:ro` per producer P that grants this reader, sorted by P |
| `[disks.*]` | Block device setup |

The `build` / `file` sections are build-time only - images are pre-built and saved as tars in the archive.

The `firewall-ports` and `[baby-container]` sections are not part of container configuration. The portal reads them directly from the manifest for firewall setup and baby container policy.

For unmeasured env files, a runtime file may provide any subset of its measured names and the file itself may be absent. The portal rejects extra names, duplicate names within one file, and reserved `ATAKIT_*` and `VERIFIERD_*` names. It merges later unmeasured files over earlier files, then measured `environment` and `env-file` values over the unmeasured values, then portal-reserved `ATAKIT_*` values over all user values.

### Log Directory Layout

The supervisor creates, during `/init`, one subdirectory per producing service:

```
/atakit-portal/workload/logs/<service>/
  mode  02775                # owner+group rwx, others r-x, plus setgid bit
  owner atakit-worker
  group <service's gid-group host GID>
```

The setgid bit on the directory makes conmon-created log files inherit the directory's group (the shared gid-group's host GID), not conmon's primary group (which is `atakit-worker` and lies outside every container's gidmap, so files written without setgid would appear as overflow GID inside any container). Conmon writes log files at mode 0640, group-readable inside any container running in the same gid-group.

**Cross-gid-group log access is not supported.** A reader in a different `gid-group` than a producer sees the producer's log files with overflow GID (the producer's gid-group is outside the reader's gidmap) and cannot read them, regardless of any `log-readers` grant or `workload-logs = true` flag. Operators who need a shipper to read multiple producers' logs must place the shipper in the same gid-group as those producers.

---

## Local Development

`atakit-workload.toml` is not directly usable by container compose tools. Two options for local dev:

### Option A: `atakit dev up`

```
$ atakit dev up          # generates temp compose, runs containers
$ atakit dev down        # tears down
$ atakit dev logs -f     # follows logs
```

Thin wrapper that generates a compose file in memory (or `.atakit/compose.yml`) and delegates to the detected container engine's compose.

### Option B: Maintain a separate `compose.yml` for dev

For complex local dev setups (extra services, debug tools, different env vars), developers can keep a handwritten `compose.yml` alongside `atakit-workload.toml`. This is not the "single config" for atakit - it's a developer convenience that atakit doesn't manage.

Both options can coexist. `atakit dev up` handles simple cases; a separate compose file handles complex local dev.

---

## Migration

### From format 7 to format 8

Format 8 lets the main workload take part in startup ordering. Older source
files remain accepted when they do not use the new workload-wide graph. Every
new source format 13 build emits compiled manifest format 13. Older supported source formats retain compiled format 11 or 12.

| Format 7 | Format 8 |
|---|---|
| `depends_on` is valid only on dependencies | `depends_on` is valid on `[workload]` and dependencies |
| A dependency can name only another dependency | A dependency can also name the main workload's exact `name` |
| No main-workload startup list in `manifest.json` | `config.depends_on` is required and always emitted, including `[]` |

### From format 6 to format 7

Format 7 added publisher-qualified workload identity. The builder derives
`meta.publisher` from the publishing key. The source file does not contain a
publisher field.

| Format 6 | Format 7 |
|---|---|
| Workload identity uses name and version | Workload identity uses publisher, name, and version |
| Compiled manifest has no `meta.publisher` | Compiled manifest requires measured `meta.publisher` |

### From format 2 to format 3

Format 3 adds per-service `unmeasured-env-file` and emits `unmeasured-env-files` in `manifest.json`. Format 2 source TOML remains accepted by the CLI; newly built archives emit manifest format 3.

| Format 2 | Format 3 |
|---|---|
| `env_file = "./defaults.env"` | `env-file = "./defaults.env"` (`env_file` remains a legacy alias) |
| `[workload.disks] data = "/data"` / `[dependencies.<name>.disks] data = "/data"` | `[workload.storage.data]` / `[dependencies.<name>.storage.data]` with `disk = "data"`, `base-path = "/"`, `mount-path = "/data"`, and optional `read-only` |
| Runtime secrets via mounted `unmeasured-data` only | `unmeasured-env-file = "/secrets/runtime.env"` with the same path declared in `[package] unmeasured-data` |

### From format 3 to format 4

Format 4 makes per-service measured and unmeasured data selective. Existing boolean source fields remain accepted: `true` compiles to all declared package data paths and `false` compiles to an empty array. New builds emit manifest format 4 with `config.measured-data` and `config.unmeasured-data` as arrays of normalized paths.

| Format 3 | Format 4 |
|---|---|
| `measured-data = true` | unchanged in source; emitted as all `measured-data/...` paths in `manifest.json` |
| `unmeasured-data = true` | unchanged in source; emitted as all `unmeasured-data/...` paths in `manifest.json` |
| no per-service data subset | `measured-data = ["/config/public.json"]` or `unmeasured-data = ["/runtime/service.env"]` |

### From format 4 to format 5

Format 5 measures the allowed variable names for every unmeasured env file and hardens delivery of unmeasured data. Older manifests are not accepted by the portal.

| Format 4 | Format 5 |
|---|---|
| `unmeasured-env-file` path only; file may be absent at build | Developer template must exist; path and sorted variable names are measured |
| Raw operator env file passed to Podman | Portal checks and merges values, then passes explicit environment entries |
| Selected unmeasured files mounted separately | One copied or reflinked service view mounted `readonly,noexec,nosuid,nodev` |

### From format 5 to format 6

Format 6 adds workload attribute policy. Older archives do not contain the
measured `config.attributes` field and are not accepted by the portal.

| Format 5 | Format 6 |
|---|---|
| No workload-level attribute policy | Optional `[workload.attributes]` table |
| No `config.attributes` field | Always emits `config.attributes`, using `{}` when empty |
| Debug, migration, and TCB states used fixed acceptance rules | Verified states are checked against base-image declarations and workload requirements |

### From format 1 to format 2

| Format 1 | Format 2 |
|---|---|
| `format = 1` | `format = 2` |
| `cvm_agent = true` | `atakit-portal = true` |
| `measured-data = [...]` on container | Move file list to `[package] measured-data`, set `measured-data = true` on container |
| `unmeasured-data = [...]` on container | Move file list to `[package] unmeasured-data`, set `unmeasured-data = true` on container |
| `encryption = { enable = true }` | `encryption = { unlock_method = ["tpm"], bind = ["workload"] }` |
| `encryption = { enable = true, key_security = "strong" }` | `encryption = { unlock_method = ["tpm"], bind = ["platform", "workload"] }` |
| `[signing]` section | Remove entirely |

The CLI detects format 1 fields and provides specific migration hints.

### From legacy format (atakit.json + compose.yml)

```
$ atakit migrate
Reading atakit.json...
Reading ./container/compose.yml...
Writing atakit-workload.toml...
Done. You can delete atakit.json and ./container/compose.yml.
```

| Legacy | atakit-workload.toml |
|---|---|
| `atakit.json` -> `workloads[0].name/version` | `[workload]` `name`, `version` |
| `atakit.json` -> `workloads[0].image` | `[workload]` `base-image` (now a list with mode) |
| `atakit.json` -> `disks[]` | `[disks.*]` |
| `atakit.json` -> `deployment` | *(moved to operator `config.toml` `[cloud.targets.*]`)* |
| `compose.yml` -> main service | `[workload]` container fields |
| `compose.yml` -> other services | `[dependencies.*]` |
| `compose.yml` -> `build` / `image` | `image` field (string, build table, or file table) |
| `compose.yml` -> bind mounts | `[package] measured-data` / `unmeasured-data` + per-container booleans or path lists |
| `compose.yml` -> named volumes | `[workload.storage.*]` plus `[disks.*]` |
| `./cvm-agent.sock` mount detection | `atakit-portal = true` |
| `.env` files | `env-file` or inlined `[workload.environment]` |
| `policy` -> `firewall.allowed_ports` | `[firewall]` (minus auto-derived ports) |
| `policy` -> `baby_container` | `[baby-container]` |
| `policy` -> `disk_config.disks[].bind_fs` | Removed. Manual `--uidmap`/`--gidmap` + shared GID scheme makes bindfs redundant. |
| `policy` -> `disk_config.disks[].disk_encryption` | `[disks.*]` `encryption` |

### Executable storage mounts

`executable = true` applies only to its own workload, dependency, or baby storage
mount. Other mounts of the same disk keep their own execution settings. Omitted
or false keeps `noexec,nosuid,nodev`; true uses `exec,nosuid,nodev`. Read-only
remains independent. Measured-data, unmeasured-data, `/tmp`, and `/run` are unchanged.
Source `format = 13` is required for `executable = true` and emits measured
manifest format 13, even when execution is not enabled. Older Portal images reject that format. False is omitted from the
measured manifest to preserve existing workload measurements. Format 13 also
supports disk integrity. Use the updated CLI and a rebuilt Portal base image;
the already-published v0.3.2-debug image does not implement this option.

```toml
format = 13

[workload.storage.app]
disk = "data"
base-path = "/app"
mount-path = "/root/app"
executable = true

[baby-container.slots.dev.storage.app]
disk = "data"
base-path = "/baby-app"
mount-path = "/root/app"
executable = true
```

Executable disk content is mutable and is not made part of the measured image
by this setting. A workload that loads it must account for who can write it.

## CPU controls (format 16, v0.3.6 and later)

Optional `[workload.cpu-idle]` sets the VM-wide CPU idle policy.
`[workload.cpu-frequency]` selects the VM-wide CPU frequency governor. Optional
`cpuset` on `[workload]`, each dependency, and each baby slot sets guest CPU
placement. `cpuset-policy` can explicitly delegate placement within a signed
allowance. `allow-operator-cpu-tuning` under `[workload]` expands into individual
permissions before explicit field overrides. Omission never grants operator
control. The publisher's rules are measured; operator choices are separate. v0.3.7 accepts only
format 16. See the complete
[CPU control specification](workload-cpu-controls.md) for syntax, failure
behavior, baby selection, and image requirements.

## Open-file and socket limits

Format 16 accepts optional `nofile` on `[workload]`, each `[dependencies.<name>]`,
and each `[baby-container.slots.<name>]`. This positive integer sets **both**
soft and hard `RLIMIT_NOFILE` for that container's processes, including sockets.
Each scope is independent. Babies use their signed slot's setting; the baby
create API cannot override it. It is a per-process limit, not a VM-wide quota.

```toml
[workload]
nofile = 262144

[dependencies.logger]
nofile = 65536

[baby-container.slots.tools]
nofile = 131072
```

Omit the field to use the base-image `container.nofile-default` (`1048576` in the
v0.3.7 normal/debug images). The image developer sets `container.nofile-max`
(`1048576` by default). Portal rejects a request above that ceiling before any
workload container starts. It never clamps or ignores the request. Podman must
apply the resolved limit before the entrypoint runs. Stop/start and reboot
recovery reapply the signed slot policy to babies, including writable roots.

Generated JSON always includes `config.nofile`, every declared dependency's
`nofile`, and every declared baby slot's `nofile`: integer or explicit `null`
for the image default. Accepted values range from 1 through 2147483647, subject
to the tighter image ceiling. Zero, negatives, fractions and strings such as
`"unlimited"` are rejected. Equivalent TOML integers such as `262144`, `262_144`
and `0x40000` produce the same canonical JSON and measurement.

This uses the existing manifest signature and measurement rules; it does not
alter CPU policy. It requires a Portal with format-16 nofile support, as included in v0.3.7.
Earlier development images may ignore unknown fields; trust the updated image's
measurements. Generic `ulimits` and `SYS_RESOURCE` remain unsupported.

If an existing image already provides a sufficient hard limit, an entrypoint
can raise only its soft limit before executing the application:

```sh
#!/bin/sh
set -e
ulimit -Sn 65536
exec /app/p2p "$@"
```

Check the affected process's `/proc/<pid>/limits`; a later diagnostic shell may
have different limits. This workaround cannot raise an insufficient hard limit.
