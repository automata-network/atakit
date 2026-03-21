# `.atawl` Archive Format Specification

A `.atawl` file is the deployable unit for CVM workloads. It packages everything the CVM agent needs to load and run a workload: a manifest, integrity-verified data, and pre-built container images. The file is a tar.gz with a custom extension — inspectable with standard tools (`tar tzf`).

## Design Principles

1. **Self-contained.** The archive contains everything needed to deploy. No registry pulls, no external dependencies at load time. Registry images are pre-pulled and bundled.
2. **Deterministic measurement.** Same runtime config + same content = same PCR23, regardless of how or where images were built. Build-time metadata is stripped.
3. **Source/compiled separation.** `atakit-workload.toml` is source (lives in repo, authored by developers). `manifest.toml` is the compiled artifact (lives in archive, read by CVM agent). The raw TOML is not in the archive.
4. **Transitive integrity.** PCR23 = hash of `manifest.toml`. The manifest contains SHA-256 hashes of all bundled content. Changing any file changes the manifest, which changes PCR23.

---

## Full Example

### Archive Layout

```
secure-signer/
  manifest.toml
  measured-data/
    config/
      hello
      cert.pem
    signing/
      auth_info.json
      cosign_policy.json
  images/
    secure-signer.tar
    redis.tar              # dependencies not yet implemented
    model-server.tar       # dependencies not yet implemented
```

The top-level directory is always the workload name. Three entries:

| Path | Contents |
|---|---|
| `manifest.toml` | Compiled workload definition + content hashes |
| `measured-data/` | Integrity-verified files (PCR23). Directory structure preserved from source |
| `images/` | OCI tar archives for every container (workload + all dependencies*) |

Not in the archive:
- `atakit-workload.toml` — source format, not needed at deploy time
- `unmeasured-data/` — operator-provided at deploy time, not developer-shipped

### Full Manifest

Built from the full example in the [workload TOML spec](atakit-workload-toml-spec.md):

```toml
[meta]
format = 1
name = "secure-signer"
version = "v0.0.1"

# ── runtime config (canonical) ────────────────────────

[config]
image = "secure-signer:v0.0.1"
base-image-mode = "blacklist"
base-image = ["mola-linux:v0.1.0-debug", "automata-linux:v0.1.5-debug"]
ports = ["3000:3000"]
restart = "unless-stopped"
cvm_agent = true
measured-data = ["config/hello", "config/cert.pem"]
unmeasured-data = ["additional-data/signer_key"]

[config.environment]
RUST_LOG = "info"
LISTEN_ADDR = "0.0.0.0:3000"

[config.disks]
secure-signer-data = "/data"
secure-signer-data2 = "/data2"

# ── dependencies (not yet implemented) ────────────────

[config.dependencies.redis]
image = "redis:7"

[config.dependencies.model-server]
image = "model-server:v0.0.1"
ports = ["8080:8080"]

# ── firewall ──────────────────────────────────────────

[config.firewall]
allow = [{ port = 4000, protocol = "tcp" }]

# ── baby containers ───────────────────────────────────

[config.baby-container]
allow = true
max_count = 2

# ── image signing ─────────────────────────────────────

[config.signing]
enable = true
auth_info = "signing/auth_info.json"
policy = "signing/cosign_policy.json"

# ── persistent disks ──────────────────────────────────

[disks.secure-signer-data]
size = "10GB"

[disks.secure-signer-data2]
size = "11GB"
bind_fs = true
encryption = { enable = true }

# ── content hashes ────────────────────────────────────

[hashes]
"measured-data/config/hello" = "sha256:cd34..."
"measured-data/config/cert.pem" = "sha256:ef56..."
"measured-data/signing/auth_info.json" = "sha256:1a2b..."
"measured-data/signing/cosign_policy.json" = "sha256:3c4d..."
"images/secure-signer.tar" = "sha256:78ab..."
"images/redis.tar" = "sha256:9cde..."
"images/model-server.tar" = "sha256:f012..."
```

---

## Minimal Example

### Archive Layout

```
my-app/
  manifest.toml
  images/
    my-app.tar
```

No `measured-data/` directory (nothing to measure beyond the image itself).

### Minimal Manifest

```toml
[meta]
format = 1
name = "my-app"
version = "v0.0.1"

[config]
image = "my-app:latest"
base-image-mode = "blacklist"

[hashes]
"images/my-app.tar" = "sha256:ab12..."
```

Five fields in `[meta]` + `[config]`, plus a hash for the single image. Everything else defaults: no ports, no dependencies, no firewall overrides, no measured-data.

---

## Schema Reference

### `[meta]` — Archive Metadata

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Schema version. Current: `1`. The CVM agent rejects manifests with a `format` higher than it supports. |
| `name` | string | yes | Workload name. Matches `[workload] name` from source TOML. |
| `version` | string | yes | Workload version. Matches `[workload] version` from source TOML. |

### `[config]` — Canonical Runtime Configuration

The resolved, canonicalized runtime config extracted from `atakit-workload.toml`. Build-time metadata is stripped. Image references are normalized to `name:tag` strings (the actual tars live under `images/`).

#### Workload Fields

| Field | Type | Default | Source in TOML |
|---|---|---|---|
| `image` | string | — | `[workload] image` (resolved to `name:tag`) |
| `base-image-mode` | string | — | `[workload] base-image-mode` |
| `base-image` | array of strings | `[]` | `[workload] base-image` |
| `ports` | array of strings | `[]` | `[workload] ports` |
| `restart` | string | `"no"` | `[workload] restart` |
| `command` | string or array | — | `[workload] command` |
| `entrypoint` | string or array | — | `[workload] entrypoint` |
| `cvm_agent` | bool | `false` | `[workload] cvm_agent` |
| `measured-data` | array of strings | `[]` | `[workload] measured-data` (paths rewritten, see below) |
| `unmeasured-data` | array of strings | `[]` | `[workload] unmeasured-data` (paths rewritten, see below) |

**Path rewriting:** Source paths are relative to `atakit-workload.toml` (e.g. `"./config/hello"`). Manifest paths are archive-relative with the `./` prefix stripped (e.g. `"config/hello"`). The actual files live under `measured-data/` in the archive.

**`unmeasured-data` in the manifest:** Paths are listed so the CVM agent knows what mounts to expect, but the files are not in the archive. Operators provide them at deploy time.

#### `[config.environment]`

Key-value table of environment variables. Identical to `[workload.environment]` in source TOML. Values from `env_file` are resolved and inlined at build time.

```toml
[config.environment]
RUST_LOG = "info"
LISTEN_ADDR = "0.0.0.0:3000"
```

#### `[config.disks]`

Maps disk names to container mount paths. Identical to `[workload.disks]` in source TOML.

```toml
[config.disks]
secure-signer-data = "/data"
```

### `[config.dependencies.<name>]` — Dependency Containers

> **Not yet implemented.** Dependencies are defined in the [workload TOML spec](atakit-workload-toml-spec.md) but not yet supported by the CLI or build pipeline.

Same fields as the workload's `[config]` section (minus `base-image-mode` and `base-image`, which are workload-level). Each dependency gets its own sub-table.

| Field | Type | Default | Description |
|---|---|---|---|
| `image` | string | — | Resolved image reference (`name:tag`). |
| `ports` | array of strings | `[]` | Exposed ports. |
| `restart` | string | `"no"` | Restart policy. |
| `command` | string or array | — | Override CMD. |
| `entrypoint` | string or array | — | Override ENTRYPOINT. |
| `environment` | table | `{}` | Environment variables. |
| `depends_on` | array of strings | `[]` | Dependencies that must start first. |
| `measured-data` | array of strings | `[]` | Archive-relative paths. |
| `unmeasured-data` | array of strings | `[]` | Mount paths for operator-provided files. |
| `disks` | table | `{}` | Disk name to mount path mapping. |

```toml
[config.dependencies.redis]
image = "redis:7"

[config.dependencies.model-server]
image = "model-server:v0.0.1"
ports = ["8080:8080"]
```

### `[config.firewall]` — VM Firewall Overrides

| Field | Type | Default | Source in TOML |
|---|---|---|---|
| `allow` | array of tables | `[]` | `[firewall] allow` |
| `deny` | array of integers | `[]` | `[firewall] deny` |

Each `allow` entry has `port` (integer) and `protocol` (string: `"tcp"` or `"udp"`).

### `[config.baby-container]` — Sidecar Container Runtime

| Field | Type | Default | Source in TOML |
|---|---|---|---|
| `allow` | bool | `false` | `[baby-container] allow` |
| `max_count` | integer | `1` | `[baby-container] max_count` |

### `[config.signing]` — Image Signature Verification

| Field | Type | Default | Source in TOML |
|---|---|---|---|
| `enable` | bool | `false` | `[signing] enable` |
| `auth_info` | string | — | `[signing] auth_info` (path rewritten to archive-relative) |
| `policy` | string | — | `[signing] policy` (path rewritten to archive-relative) |

When enabled, the referenced files are placed under `measured-data/signing/` in the archive. Their hashes appear in `[hashes]` and are covered by PCR23.

### `[disks.<name>]` — Persistent Storage

Top-level section (not under `[config]`). Defines persistent disk volumes attached to the CVM. Structure mirrors the source TOML.

| Field | Type | Required | Description |
|---|---|---|---|
| `size` | string | yes | Disk size (e.g. `"10GB"`). |
| `bind_fs` | bool | no | Enable UID translation via bindfs. Default: `false`. |
| `encryption.enable` | bool | no | Enable disk encryption. Default: `false`. |
| `encryption.key_security` | string | no | `"standard"` (PCR 11) or `"strong"` (PCR 10+11). Default: `"standard"`. |

### `[hashes]` — Content Integrity

Flat key-value table. Keys are archive-relative paths. Values are `"sha256:<hex>"` strings.

Every file in the archive (except `manifest.toml` itself) gets an entry:

| Key pattern | Source |
|---|---|
| `"measured-data/..."` | Files under `measured-data/` |
| `"images/<name>.tar"` | OCI tar archives under `images/` |

```toml
[hashes]
"measured-data/config/hello" = "sha256:cd34..."
"measured-data/signing/auth_info.json" = "sha256:1a2b..."
"images/secure-signer.tar" = "sha256:78ab..."
"images/redis.tar" = "sha256:9cde..."
```

### Fields NOT in the Manifest

| Source TOML section | Reason excluded |
|---|---|
| `[workload] image` build/file metadata (`build`, `containerfile`, `args`, `file`) | Build-time metadata stripped. Resolved `name:tag` kept in `[config] image`. |
| `[workload] env_file` | Inlined into `[config.environment]` at build time. |
| (deployment targets) | Deployment targets live in operator config (`config.toml`), not in the workload definition. |

---

## Image Resolution Rules

All container images — regardless of source — are resolved to OCI tar archives under `images/` at build time.

| Source form | Build behavior | Tar filename |
|---|---|---|
| `image = { build = "." }` | Build image, export as OCI tar. Auto-tagged `{name}:{version}`. | `<service>.tar` |
| `image = { file = "./path.tar" }` | Copy the tar into the archive. | `<service>.tar` |
| `image = "redis:7"` | Pull from registry, export as OCI tar. | `<service>.tar` |

**Service name mapping:** The workload's tar is named after `[workload] name`. When dependencies are implemented, dependency tars will be named after the dependency key (e.g. `[dependencies.redis]` produces `redis.tar`).

**Why bundle registry images?** Three reasons:

1. **Reproducibility** — the archive is fully self-contained. No risk of upstream tag overwrites or registry outages at deploy time.
2. **Integrity** — when signing is enabled, images are verified at build time (when registry auth is available). The verified tars ship in the archive.
3. **Simplicity** — the CVM agent loads all tars uniformly. No conditional pull logic.

The tradeoff is archive size. For CVM workloads where integrity and determinism are requirements, this is worth it.

---

## Measurement Model

### What Gets Measured

PCR23 is a single hash that transitively covers all workload content and configuration.

```
PCR23 = SHA-256(manifest.toml)
         |
         +-- [config]  -- canonical runtime config (ports, env, firewall, ...)
         +-- [hashes]  -- SHA-256 of every bundled file:
              +-- measured-data/config/hello              = sha256:cd34...
              +-- measured-data/config/cert.pem           = sha256:ef56...
              +-- measured-data/signing/auth_info.json    = sha256:1a2b...
              +-- measured-data/signing/cosign_policy.json = sha256:3c4d...
              +-- images/secure-signer.tar               = sha256:78ab...
              +-- images/redis.tar                       = sha256:9cde...
```

Changing any of the following changes PCR23:
- Any file under `measured-data/`
- Any container image
- Any runtime config field (ports, environment, restart policy, firewall rules, etc.)

### What Is NOT Measured

- `unmeasured-data/` — not in the archive; operator-provided at deploy time
- Deployment targets -- not in the manifest; live in operator config

### Why Hash the Manifest, Not the Raw TOML

Hashing `atakit-workload.toml` directly would be non-deterministic. The raw TOML mixes runtime config with build-time metadata:

```toml
# Developer A (builds from source)
image = { build = ".", containerfile = "Containerfile" }
measured-data = ["./config/hello"]

# Developer B (uses pre-built tar)
image = { file = "./images/secure-signer.tar" }
measured-data = ["./config/hello"]
```

Both produce identical runtime behavior and identical images, but different TOML files. The manifest solves this by canonicalizing runtime config and hashing content separately. Same intent = same manifest = same PCR23.

### CVM Agent Verification

At workload load time, the CVM agent:

1. Extracts the archive
2. Reads `manifest.toml`
3. Verifies every `[hashes]` entry against the actual file on disk
4. Extends PCR23 with the SHA-256 of `manifest.toml`
5. Proceeds with compose generation and container startup

If any hash mismatch is detected, the agent rejects the workload.

---

## Build Workflow

`atakit workload build` compiles `atakit-workload.toml` into a `.atawl` archive. Conceptual steps:

```
atakit-workload.toml  ──[atakit workload build]──>  secure-signer.atawl
     (source)                                (compiled)
```

### Step by Step

1. **Read** `atakit-workload.toml` and validate against the [workload TOML spec](atakit-workload-toml-spec.md).

2. **Resolve images.** For the workload container (and dependencies, when implemented):
   - `build` — run the container build, export result as OCI tar. Auto-tag as `{name}:{version}`.
   - `file` — verify the tar exists, copy it.
   - Registry string — pull from registry, export as OCI tar.

3. **Collect measured-data.** Copy all `measured-data` files/directories into the archive, preserving directory structure. If signing is enabled, copy `auth_info` and `policy` files under `measured-data/signing/`.

4. **Canonicalize runtime config.** Extract runtime-relevant fields from the TOML into the manifest's `[config]` section:
   - Strip build-time metadata (`build`, `containerfile`, `args`, `file`, source paths).
   - Normalize image references to `name:tag` strings.
   - Rewrite `measured-data` and `unmeasured-data` paths from `./`-relative to archive-relative.
   - Inline `env_file` contents into `[config.environment]`.

5. **Hash all content.** Compute SHA-256 for every file under `measured-data/` and every tar under `images/`.

6. **Generate `manifest.toml`.** Assemble `[meta]`, `[config]`, `[disks]`, and `[hashes]` sections.

7. **Create archive.** Package into `<name>.atawl` (tar.gz):
   ```
   <name>/manifest.toml
   <name>/measured-data/...
   <name>/images/...
   ```

### Output

```
$ atakit workload build
Reading atakit-workload.toml...
Building secure-signer:v0.0.1...
Pulling redis:7...
Loading model-server from ./images/model-server.tar...
Collecting measured-data (4 files)...
Generating manifest.toml...
Writing secure-signer.atawl (3 images, 4 measured files)
Done. SHA-256: ab12cd34...
```

---

## Source Format vs. Compiled Format

`atakit-workload.toml` and `manifest.toml` serve different audiences and different lifecycle stages.

| | `atakit-workload.toml` (source) | `manifest.toml` (compiled) |
|---|---|---|
| **Authored by** | Developer | `atakit workload build` |
| **Read by** | Developer, `atakit` CLI | CVM agent |
| **Lives in** | Git repo | `.atawl` archive |
| **Image refs** | Three forms: string, build table, file table | Resolved `name:tag` strings |
| **Data paths** | Relative to TOML (`./config/hello`) | Archive-relative (`config/hello`) |
| **Build metadata** | Present (`build`, `containerfile`, `args`) | Stripped |
| **env_file** | External file references | Inlined into `[config.environment]` |
| **Content hashes** | Not present | `[hashes]` with SHA-256 |
| **Deployments** | Optional `[deployments]` section | Not present |
| **unmeasured-data** | Files listed, must describe what operators provide | Paths listed for mount setup, files not bundled |

The relationship is analogous to source code and a compiled binary. The source is human-friendly and flexible; the compiled form is machine-friendly and deterministic.

### Field Mapping

| Source (`atakit-workload.toml`) | Manifest (`manifest.toml`) |
|---|---|
| `format` | `[meta] format` |
| `[workload] name` | `[meta] name` |
| `[workload] version` | `[meta] version` |
| `[workload] base-image-mode` | `[config] base-image-mode` |
| `[workload] base-image` | `[config] base-image` |
| `[workload] image` (any form) | `[config] image` (resolved `name:tag`) + tar under `images/` |
| `[workload] ports` | `[config] ports` |
| `[workload] restart` | `[config] restart` |
| `[workload] command` | `[config] command` |
| `[workload] entrypoint` | `[config] entrypoint` |
| `[workload] cvm_agent` | `[config] cvm_agent` |
| `[workload] measured-data` | `[config] measured-data` (paths rewritten) |
| `[workload] unmeasured-data` | `[config] unmeasured-data` (paths rewritten) |
| `[workload.environment]` + `env_file` | `[config.environment]` (merged, inlined) |
| `[workload.disks]` | `[config.disks]` |
| `[dependencies.<name>]` | `[config.dependencies.<name>]` *(not yet implemented)* |
| `[firewall]` | `[config.firewall]` |
| `[baby-container]` | `[config.baby-container]` |
| `[signing]` | `[config.signing]` (paths rewritten) |
| `[disks.<name>]` | `[disks.<name>]` |
| (deployment targets) | *(not in workload config or manifest; lives in operator config.toml)* |
