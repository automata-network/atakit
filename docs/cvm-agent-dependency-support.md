# CVM Agent: Dependency Container Support

## Background

The atakit build pipeline now supports dependency containers. A workload can define multiple containers in `atakit-workload.toml` using `[dependencies.<name>]` sections. The `.atawl` archive bundles all container images (workload + dependencies) and the `manifest.toml` describes how to run them.

The CVM agent currently supports only a single workload container. This document describes the changes required to support dependency containers.

## What changes in the archive

### Archive layout

Previously, `images/` contained a single tar. Now it contains one tar per container:

```
my-workload/
  manifest.toml
  measured-data/
    config/cert.pem
  images/
    my-workload.tar      # main workload
    redis.tar            # dependency "redis"
    model-server.tar     # dependency "model-server"
```

**Tar naming:** The workload's tar is named `{workload_name}.tar`. Each dependency's tar is named `{dependency_key}.tar` (matching the key in `[config.dependencies.<name>]`).

### New manifest fields

`manifest.toml` now includes a `[config.dependencies.<name>]` section for each dependency:

```toml
[meta]
format = 1
name = "my-workload"
version = "v0.1.0"

[config]
image = "my-workload:v0.1.0"
base-image-mode = "blacklist"
ports = ["3000:3000"]
restart = "unless-stopped"
cvm_agent = true
measured-data = ["config/cert.pem"]

[config.environment]
RUST_LOG = "info"

[config.disks]
app-data = "/data"

# NEW: dependency containers
[config.dependencies.redis]
image = "redis:7"
ports = ["6379:6379"]
restart = "unless-stopped"
measured-data = ["config/cert.pem"]

[config.dependencies.redis.environment]
REDIS_MAX_MEMORY = "256mb"

[config.dependencies.redis.disks]
app-data = "/cache"

[config.dependencies.model-server]
image = "model-server:v0.1.0"
ports = ["8080:8080"]
depends_on = ["redis"]

# ... [disks.*], [hashes], etc. unchanged
```

### Dependency fields

Each `[config.dependencies.<name>]` has these fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `image` | string | required | Image reference (`name:tag`). Corresponding tar is at `images/<name>.tar`. |
| `ports` | array of strings | `[]` | Port mappings in `"host:container[/protocol]"` format. Host ports are guaranteed unique across all containers by the build pipeline. |
| `restart` | string | `"no"` | Restart policy: `"no"`, `"always"`, `"on-failure"`, `"unless-stopped"`. |
| `command` | string or array | none | Override container CMD. |
| `entrypoint` | string or array | none | Override container ENTRYPOINT. |
| `environment` | table | `{}` | Environment variables (already resolved, no env_file references). |
| `depends_on` | array of strings | `[]` | Other dependency names that must start first. Only references other dependencies, never the main workload. |
| `measured-data` | array of strings | `[]` | Archive-relative paths of measured-data files to mount into this container at `/app/measured-data/`. Read-only. |
| `unmeasured-data` | array of strings | `[]` | Paths of unmeasured-data files to mount into this container at `/app/unmeasured-data/`. Read-only. |
| `disks` | table | `{}` | Disk name to container mount path mapping. Disk names reference `[disks.<name>]` entries. Multiple containers can share the same disk. |

## Required agent changes

### 1. Load all container images

Currently the agent loads a single image tar from `images/`. It must now load ALL tars under `images/`:

- `images/{workload_name}.tar` - main workload
- `images/{dep_name}.tar` - one per dependency

Each tar should be loaded via the container engine (`podman load` / `docker load`).

### 2. Start dependency containers

The agent must start a container for each entry in `[config.dependencies.<name>]`, in addition to the main workload container. Each container is configured from its manifest section:

**Main workload container** (unchanged):
- Container name: `{meta.name}` (e.g., `my-workload`)
- Configured from `[config]`: image, ports, restart, command, entrypoint, environment, cvm_agent

**Dependency containers** (new):
- Container name: the dependency key (e.g., `redis`, `model-server`)
- Configured from `[config.dependencies.<name>]`: image, ports, restart, command, entrypoint, environment
- `depends_on` defines startup ordering: listed dependencies must be started and running before this container starts

### 3. Mount measured-data per container

Each container (workload and dependency) specifies which measured-data files it needs via its `measured-data` array. The agent must mount only the listed files into each container.

- Workload's `[config] measured-data = ["config/cert.pem"]` means mount `config/cert.pem` into the workload container at `/app/measured-data/config/cert.pem` (read-only)
- Dependency's `measured-data = ["config/cert.pem"]` means mount the SAME file into that dependency container at `/app/measured-data/config/cert.pem` (read-only)

The actual files are always under the archive's `measured-data/` directory. The paths in the manifest are archive-relative (no `./` prefix).

### 4. Mount unmeasured-data per container

Same pattern as measured-data, but for operator-provided files. Each container's `unmeasured-data` array specifies which unmeasured-data files to mount.

Mount point: `/app/unmeasured-data/<path>` (read-only)

### 5. Mount disks per container

Disks can be shared between containers. A disk defined in `[disks.app-data]` might appear in both:
- `[config.disks] app-data = "/data"` (workload mounts at /data)
- `[config.dependencies.redis.disks] app-data = "/cache"` (redis mounts at /cache)

The same underlying disk volume is mounted at different paths in different containers.

### 6. cvm_agent socket

Only the main workload has the `cvm_agent` flag. Dependencies do NOT get the agent socket mounted. The `cvm_agent` field only exists on `[config]`, not on `[config.dependencies.*]`.

### 7. Firewall ports

The `[config.firewall-ports]` list already includes ports from all containers (workload + dependencies). No change needed here -- the agent already reads this flat list.

### 8. Startup order

The main workload container starts first (or in parallel with dependencies that have no `depends_on`). Dependencies with `depends_on` entries wait for the listed containers to be running before starting. The `depends_on` graph is acyclic (guaranteed by the build pipeline referencing only defined dependency names; cycle detection is the agent's responsibility if needed).

## Invariants the build pipeline guarantees

- Host ports are unique across all containers (no conflicts)
- `depends_on` entries only reference defined dependency names
- All referenced disk names have corresponding `[disks.<name>]` entries
- All image tars exist in `images/` with matching names
- `[hashes]` includes SHA-256 hashes for all image tars (workload + dependencies)
- Manifest is deterministic: same config produces same manifest produces same PCR23

## What does NOT change

- Archive format: tar.zst with `.atawl` extension (reads both zstd and gzip)
- PCR23 computation: still SHA-256 of `manifest.toml` bytes
- Hash verification: all files in `[hashes]` verified as before (now includes dependency image tars)
- `[meta]` section: unchanged
- `[disks.*]` section: unchanged (disk definitions are top-level, not per-container)
- `[config.firewall-ports]`: unchanged (already includes dependency ports)
- `[config.baby-container]`: unchanged
- `[config.signing]`: unchanged
- `/init` endpoint: unchanged (same multipart form)
