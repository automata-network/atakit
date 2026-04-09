# `atakit-workload.toml` Specification

One file per workload per directory. Defines everything: workload metadata, its container, dependencies, and storage.

## Design Principles

1. **Security allowlist.** The schema defines what a workload *can* do on the CVM. If a field doesn't exist in this spec, it's not supported. The default is deny.
2. **No ambiguity.** Measured data, unmeasured data, and persistent disks are separate fields — not overloaded into a single `volumes` list.
3. **Auto-derivable fields are omitted.** Image tags for built services are auto-generated. Compose YAML is generated for the package. Users don't manage derived artifacts.

---

## Full Example

```toml
format = 1

[workload]
name = "secure-signer"
version = "v0.0.1"
base-image-mode = "blacklist"
base-image = ["mola-linux:v0.1.0-debug", "automata-linux:v0.1.5-debug"]

# ── workload container ──────────────────────────────────

image = { build = ".", containerfile = "Containerfile" }
ports = ["3000:3000"]
restart = "unless-stopped"
cvm_agent = true
boot-disk-size = "50GB"
measured-data = ["./config/hello", "./config/cert.pem"]
unmeasured-data = ["./additional-data/signer_key"]

[workload.environment]
RUST_LOG = "info"
LISTEN_ADDR = "0.0.0.0:3000"

[workload.disks]
secure-signer-data = "/data"
secure-signer-data2 = "/data2"

# ── dependencies ────────────────────────────────────────

[dependencies.redis]
image = "redis:7"

[dependencies.model-server]
image = { file = "./images/model-server.tar" }
ports = ["8080:8080"]

# ── firewall ──────────────────────────────────────────

[firewall]
allow = ["4000/tcp"]

# ── baby containers ───────────────────────────────────

[baby-container]
allow = true
max_count = 2

# ── image signing ─────────────────────────────────────

[signing]
enable = true
auth_info = "./secrets/auth_info.json"
policy = "./config/cosign_policy.json"

# ── persistent disks ───────────────────────────────────

[disks.secure-signer-data]
index = 10
size = "10GB"

[disks.secure-signer-data2]
index = 11
size = "11GB"
bind_fs = true
encryption = { enable = true }

```

---

## Minimal Example

```toml
format = 1

[workload]
name = "my-app"
version = "v0.0.1"
base-image-mode = "blacklist"
image = "my-app:latest"
```

Five required fields. Everything else defaults: no ports, no mounts, no dependencies, no firewall overrides, no baby containers, no signing. With `base-image-mode = "blacklist"` and `base-image` defaulting to `[]`, this workload can deploy on any CVM image.

---

## Schema Reference

### `format` — Schema Version

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Schema version. Current: `1`. The CLI rejects configs with a `format` higher than it supports. |

Top-level field, not inside any table. Incremented on breaking schema changes.

### `[workload]` — Workload Definition

The workload section defines both the metadata and the workload's own container.

#### Metadata

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | yes | — | Workload name. Alphanumeric + hyphens. |
| `version` | string | yes | — | Semver prefixed with `v` (e.g. `v0.0.1`). |
| `base-image-mode` | string | yes | — | `"whitelist"` or `"blacklist"`. Controls whether `base-image` is an allow-list or deny-list of CVM images. |
| `base-image` | array of strings | no | `[]` | List of base CVM image references (`name:version`). Interpreted according to `base-image-mode`. |

**`base-image-mode`:**
- `"whitelist"` — the workload may **only** be deployed on the listed base images. Use when the workload is validated against specific CVM versions.
- `"blacklist"` — the workload may be deployed on **any** base image **except** the listed ones. Use to exclude known-incompatible or deprecated images.

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
| `restart` | string | `"no"` | Restart policy: `"no"`, `"always"`, `"on-failure"`, `"unless-stopped"`. |
| `command` | string or array | — | Override container CMD. String = shell form, array = exec form. |
| `entrypoint` | string or array | — | Override container ENTRYPOINT. |
| `environment` | table | `{}` | Environment variables. `{ KEY = "value" }` |
| `env_file` | string or array | `[]` | Path(s) to `.env` files. Resolved relative to `atakit-workload.toml`. |
| `cvm_agent` | bool | `false` | Enable CVM agent socket for this service. |
| `measured-data` | array of strings | `[]` | Files/directories included in the package and integrity-verified (PCR23). See below. |
| `unmeasured-data` | array of strings | `[]` | Files/directories provided by operators at deploy time. Not integrity-verified. See below. |
| `boot-disk-size` | string | — | Minimum boot/OS disk size (e.g. `"50GB"`). Cloud provider default if omitted. Valid units: MB, GB, TB. The actual disk may be larger if the base image requires more. |

#### Data Sections

Two arrays for shipping files or directories into the container. Mount targets are fixed — no user-specified container paths.

**`measured-data`** — Integrity-verified files (read-only)

Files or directories included in the package and in the PCR23 measurement. The CVM agent verifies their integrity during workload loading. Immutable at runtime.

```toml
measured-data = ["./config/hello", "./config/cert.pem"]
```

- Paths: relative to `atakit-workload.toml` (must start with `./`). Files or directories.
- Mounted at: `/app/measured-data/` (directory structure preserved)
- Always read-only (enforced)

**`unmeasured-data`** — Operator-provided files (read-only, not verified)

Listed in the manifest but not included in the package. Operators provide these at deployment time. Not integrity-verified by the CVM agent.

```toml
unmeasured-data = ["./additional-data/signer_key"]
```

- Paths: relative to `atakit-workload.toml` (must start with `./`). Files or directories.
- Mounted at: `/app/unmeasured-data/` (directory structure preserved)
- Always read-only

**`[workload.disks]`** — Persistent disk mounts (read-write)

Maps `[disks.*]` entries to container mount points.

```toml
[workload.disks]
secure-signer-data = "/data"
```

- Key: disk name (must match a `[disks.<name>]` entry)
- Value: absolute container mount path
- Always read-write

### `[dependencies.<name>]` — Dependency Containers

Supporting containers the workload needs (databases, caches, sidecars, etc.). Same container configuration fields as `[workload]`, same `image` field with the same three forms (registry string, build table, file table).

Dependencies also support:

| Field | Type | Default | Description |
|---|---|---|---|
| `depends_on` | array of strings | `[]` | Other dependencies that must start first. |

Dependencies can have their own `measured-data`, `unmeasured-data`, and `disks` sections:

```toml
[dependencies.redis]
image = "redis:7"

[dependencies.model-server]
image = { file = "./images/model-server.tar" }
ports = ["8080:8080"]

[dependencies.model-server.disks]
model-cache = "/data/cache"
```

Built dependency images are auto-tagged as `{dependency_name}:{workload.version}`.

### `[disks.<name>]` — Persistent Storage

Defines persistent disk volumes attached to the CVM. Referenced by `[workload.disks]` or `[dependencies.<name>.disks]`. A disk can be shared between multiple containers.

| Field | Type | Required | Description |
|---|---|---|---|
| `index` | integer | no | LUN / device index for cloud disk attachment. Must be >= 10 and unique across all disks. Auto-assigned from 10 in alphabetical disk name order if omitted. |
| `size` | string | yes | Disk size (e.g. `"10GB"`). |
| `bind_fs` | bool | no | Enable UID translation via bindfs for this disk. Default: `false`. |
| `encryption.enable` | bool | no | Enable disk encryption. Default: `false`. |
| `encryption.key_security` | string | no | Encryption key security level: `"standard"` (PCR 11 only) or `"strong"` (PCR 10+11). Default: `"standard"`. |

**Constraints:**
- `index` >= 10 to avoid collision with boot disk (LUN 0) and system devices.
- `index` must be unique across all `[disks.*]` entries.

### `[firewall]` — VM Firewall Overrides

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

If no `[firewall]` section exists, the workload gets exactly the auto-derived rules from `ports`. Port 1024 (CVM agent API) is always allowed by the CVM runtime regardless of this config.

### `[baby-container]` — Sidecar Container Runtime

Controls whether the workload can create ephemeral sidecar containers via the agent's `/baby-container/*` API. Disabled by default.

| Field | Type | Default | Description |
|---|---|---|---|
| `allow` | bool | `false` | Enable baby container creation. If `false`, all `/baby-container/*` endpoints return 403. |
| `max_count` | integer | `1` | Maximum concurrent baby containers. |

```toml
[baby-container]
allow = true
max_count = 2
```

### `[signing]` — Image Signature Verification

> **Legacy -- do not rely on this section.** The signing mechanism is being redesigned. The current `[signing]` fields (`enable`, `auth_info`, `policy`) and the cosign-based verification flow described below will be replaced. Leave `[signing]` absent or `enable = false` in new workloads until the redesign lands.

Enables cosign-based image signature verification for all container images (workload and dependencies) before startup. Disabled by default.

| Field | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | `false` | Enable image signature verification. |
| `auth_info` | string | — | Path to registry auth credentials file. Relative to `atakit-workload.toml`. Required when `enable = true`. |
| `policy` | string | — | Path to cosign signature verification policy file. Relative to `atakit-workload.toml`. Required when `enable = true`. |

```toml
[signing]
enable = true
auth_info = "./secrets/auth_info.json"
policy = "./config/cosign_policy.json"
```

Both files are included in the package under `measured-data/signing/` and shipped to the CVM. They **are** part of the PCR23 measurement.

---

## Explicitly Unsupported (Security Boundary)

These compose features are intentionally excluded. The CVM runtime controls these:

| Feature | Reason |
|---|---|
| `networks` | CVM controls network topology |
| `privileged` | No privilege escalation |
| `cap_add` / `cap_drop` | CVM manages capabilities |
| `devices` | No host device passthrough |
| `pid` / `ipc` / `uts` | No namespace sharing |
| `security_opt` | CVM manages security policies |
| `user` | CVM controls container user |
| `read_only` | Controlled via mount sections above |
| `shm_size` / `tmpfs` | CVM manages memory mounts |
| `sysctls` | No kernel parameter tuning |
| `ulimits` | CVM manages resource limits |

---

## Validation Rules

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
- `depends_on` entries must reference other dependencies defined in the file
- `env_file` paths must exist relative to `atakit-workload.toml`
- Host ports must be unique across all containers (workload + dependencies)

### Disks

- Each disk referenced in `[workload.disks]` or `[dependencies.*.disks]` must have a corresponding `[disks.<name>]` entry
- `size` must be a valid size string (e.g. `"10GB"`, `"500MB"`)
- `encryption.key_security` must be `"standard"` or `"strong"` if present

### Firewall

- Port must be 1025-65535 (both allow and deny)
- Protocol, if specified, must be `"tcp"` or `"udp"`
- No protocol (bare integer or string without `/proto`) means both tcp and udp
- `deny` entries that don't match any auto-derived port/protocol are warnings (no-op)
- `allow` entries that duplicate an auto-derived port/protocol are warnings (redundant)
- String entries must not include a container port (e.g. `"3000:80/tcp"` is rejected)

### Baby Container

- `max_count` must be a positive integer (defaults to `1`)

### Signing (legacy, being redesigned)

- `auth_info` and `policy` are required when `enable = true`
- Both paths must start with `./` (relative to `atakit-workload.toml`)
- Both files must exist at build time

### Data Paths

- All `measured-data` and `unmeasured-data` entries must start with `./` (relative to `atakit-workload.toml`)
- All `measured-data` entries must exist at build time (files or directories)
- `unmeasured-data` entries are listed in the manifest but not required to exist at build time

---

## Compose Generation

The CVM agent generates `compose.yml` at runtime from the workload manifest (`manifest.toml` inside the `.atawl` archive — see [archive spec](atawl-archive-spec.md)). Compose is an internal implementation detail — it is not included in the workload package and never authored by the user.

The mapping below shows the conceptual correspondence between source TOML fields and generated compose. At runtime, the agent reads the equivalent fields from `manifest.toml`.

### Mapping

| atakit-workload.toml | Generated compose |
|---|---|
| `[workload]` | `services.{workload.name}` |
| `[dependencies.<name>]` | `services.<name>` |
| `image` (string, or auto-tag from build/file) | `services.*.image` (fully qualified) |
| `ports` | `services.*.ports` |
| `restart` | `services.*.restart` |
| `command` | `services.*.command` |
| `entrypoint` | `services.*.entrypoint` |
| `environment` + `env_file` | `services.*.environment` (merged, inlined) |
| `depends_on` | `services.*.depends_on` |
| `measured-data` | `services.*.volumes` (bind mount to `/app/measured-data/`, `:ro`) |
| `unmeasured-data` | `services.*.volumes` (bind mount to `/app/unmeasured-data/`, `:ro`) |
| `[*.disks]` | `services.*.volumes` (named volume) |
| `cvm_agent = true` | `services.*.volumes` adds `./cvm-agent.sock` mount |
| `[disks.*]` | top-level `volumes:` declarations |

The `build` / `file` sections are **not** included in the generated compose — images are pre-built and saved as tars.

The `firewall-ports`, `[baby-container]`, and `[signing]` sections are **not** part of compose. The agent reads them directly from `manifest.toml`.

### Example Generated Compose

From the full example above:

```yaml
services:
  secure-signer:
    image: docker.io/library/secure-signer:v0.0.1
    ports:
      - "3000:3000"
    restart: unless-stopped
    environment:
      RUST_LOG: info
      LISTEN_ADDR: 0.0.0.0:3000
    volumes:
      - ./config/hello:/app/measured-data/config/hello:ro
      - ./config/cert.pem:/app/measured-data/config/cert.pem:ro
      - ./additional-data/signer_key:/app/unmeasured-data/additional-data/signer_key:ro
      - secure-signer-data:/data
      - secure-signer-data2:/data2
      - ./cvm-agent.sock:/app/cvm-agent.sock

  redis:
    image: docker.io/library/redis:7

  model-server:
    image: model-server:v0.0.1
    ports:
      - "8080:8080"

volumes:
  secure-signer-data:
  secure-signer-data2:
```

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

For complex local dev setups (extra services, debug tools, different env vars), developers can keep a handwritten `compose.yml` alongside `atakit-workload.toml`. This is not the "single config" for atakit — it's a developer convenience that atakit doesn't manage.

Both options can coexist. `atakit dev up` handles simple cases; a separate compose file handles complex local dev.

---

## Migration from Current Format

### Automated: `atakit migrate`

```
$ atakit migrate
Reading atakit.json...
Reading ./container/compose.yml...
Reading cvm_agent_policy.json...
Writing atakit-workload.toml...
Done. You can delete atakit.json, ./container/compose.yml, and cvm_agent_policy.json.
```

### Mapping

| Current | atakit-workload.toml |
|---|---|
| `atakit.json` → `workloads[0].name/version` | `[workload]` `name`, `version` |
| `atakit.json` → `workloads[0].image` | `[workload]` `base-image` (now a list with mode) |
| `atakit.json` → `disks[]` | `[disks.*]` |
| `atakit.json` → `deployment` | *(moved to operator `config.toml` `[cloud.targets.*]`)* |
| `compose.yml` → main service | `[workload]` container fields |
| `compose.yml` → other services | `[dependencies.*]` |
| `compose.yml` → `build` / `image` | `image` field (string, build table, or file table) |
| `compose.yml` → bind mounts | `measured-data` or `unmeasured-data` |
| `compose.yml` → named volumes | `[workload.disks]` |
| `./cvm-agent.sock` mount detection | `cvm_agent = true` |
| `.env` files | `env_file` or inlined `[workload.environment]` |
| `policy` → `firewall.allowed_ports` | `[firewall]` (minus auto-derived ports) |
| `policy` → `baby_container` | `[baby-container]` |
| `policy` → `image_signature_verification` | `[signing]` |
| `policy` → `disk_config.disks[].bind_fs` | `[disks.*]` `bind_fs` |
| `policy` → `disk_config.disks[].disk_encryption` | `[disks.*]` `encryption` |
