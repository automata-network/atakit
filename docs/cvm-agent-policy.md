# cvm-agent Policy File Reference

> **DEPRECATED.** `cvm_agent_policy.json` is being removed from cvm-agent. It is superseded by `manifest.toml`, which the agent reads directly from the `.atawl` archive. Workload authors define the workload in `atakit-workload.toml`, which the atakit build pipeline compiles into `manifest.toml`; the agent consumes the manifest natively -- no JSON policy file is written or read.
>
> This document remains as a historical reference for the legacy JSON format while the migration is in progress. Do not use it as a guide for new workloads or new cvm-agent code paths. See [`atakit-workload-toml-spec.md`](atakit-workload-toml-spec.md) and [`atawl-archive-spec.md`](atawl-archive-spec.md) for the current source of truth.

The `cvm_agent_policy.json` file is the central configuration authority for cvm-agent. Nearly every subsystem reads from it: container engine selection, firewall rules, disk setup, baby container limits, UID isolation, socket injection, and image verification.

## File Location

The agent searches for the policy file in this order:

1. Path provided via `--policy` CLI flag
2. `/data/workload/config/cvm_agent/cvm_agent_policy.json`
3. `./cvm_agent_policy.json` (fallback)

The file is loaded once at startup by `security_monitor.Load()`, which parses the JSON, validates all fields, and stores the result in a global struct protected by a read-write mutex.

---

## Top-Level Structure

```json
{
    "cvm_config": { ... },
    "workload_config": { ... }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cvm_config` | object | Yes | Infrastructure and platform configuration |
| `workload_config` | object | No | Workload lifecycle and service permissions |

---

## `cvm_config`

### `emulation_mode`

Controls whether the agent fakes TEE hardware using files on disk instead of real hardware attestation. Used for development and testing.

```json
"emulation_mode": {
    "enable": false,
    "cloud_provider": "azure",
    "tee_type": "snp",
    "emulation_data_path": "./emulation_mode_data",
    "enable_emulation_data_update": true
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `enable` | bool | Yes | — | Enable emulation mode (no real TEE hardware needed) |
| `cloud_provider` | string | If `enable: true` | Must be `"azure"`, `"google"`, or `"amazon"` | Simulated cloud provider for attestation flow selection |
| `tee_type` | string | If `enable: true` | Must be `"tdx"` or `"snp"` | Simulated TEE type |
| `emulation_data_path` | string | If `enable: true` | — | Directory containing fake attestation data files |
| `enable_emulation_data_update` | bool | No | — | Allow the agent to update emulation data files at runtime |

**Validation**: When `enable: true`, both `cloud_provider` and `tee_type` are validated against their allowed values. Invalid values cause a fatal load error.

---

### `firewall`

Configures network firewall rules applied at startup via nftables. The system assumes a default-deny policy is already in place; these rules punch holes for allowed traffic.

```json
"firewall": {
    "allowed_ports": [
        {
            "name": "allow_https",
            "protocol": "tcp",
            "port": "443"
        }
    ]
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `allowed_ports` | array | No | — | List of port rules to allow |
| `allowed_ports[].name` | string | Yes | Non-empty | Human-readable rule name |
| `allowed_ports[].protocol` | string | Yes | Must be `"tcp"` or `"udp"` | Transport protocol |
| `allowed_ports[].port` | string | Yes | Integer between 1 and 65535 | Port number (as string) |

**Validation**:
- Each rule must have a non-empty `name`
- `protocol` must be exactly `"tcp"` or `"udp"` (case-sensitive)
- `port` must parse as an integer in range 1-65535
- No duplicate rules allowed (uniqueness checked by `name-protocol-port` tuple)

**Behavior**: Each entry generates an `nft add rule ... {protocol} dport {port} accept` command inserted at the top of the INPUT chain.

---

### `container_api`

Selects the container runtime and the Unix user account used to execute container commands.

```json
"container_api": {
    "container_engine": "podman",
    "container_owner": "automata"
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `container_engine` | string | Yes | Must be `"podman"` or `"docker"` | Container runtime |
| `container_owner` | string | No | — | Unix user for running container commands via `su -`. Also determines which `/etc/subuid` range is used for UID isolation |

**Behavior**: Per-service UID isolation via `--uidmap`/`--gidmap` with 65536-wide UID slots allocated from the `container_owner`'s subuid range.

---

### `baby_container`

Controls the sandboxed sidecar container feature accessible via `/baby-container/*` internal API endpoints.

```json
"baby_container": {
    "allow": true,
    "max_count": 2
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `allow` | bool | Yes | — | Master gate for all baby container endpoints. When `false`, all `/baby-container/*` requests return HTTP 403 |
| `max_count` | int | If `allow: true` | Must be a positive integer (> 0) | Maximum number of concurrent baby containers. Exceeding the limit returns HTTP 429 |

**Additional hardcoded restrictions** (not configurable via policy):
- Forbidden mount paths: `/proc`, `/sys`, `/dev`, `/etc/shadow`, `/etc/passwd`, `/run`, `/var/run`, `/root`
- Allowed capabilities: only `SETUID` and `SETGID` (all others rejected)
- Network: must share network namespace with parent workload container (`--network=container:<workload>`)
- Security: `--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges`, tmpfs `/tmp` with noexec/nosuid/64MB limit
- Images must already be pre-loaded in the runtime (no pull at create time)

---

### `disk_config`

Configures additional data disks attached to the VM.

```json
"disk_config": {
    "enable": true,
    "disks": [
        {
            "serial": "data-vol-001",
            "disk_mount_point": "/data/data-disk",
            "service": "metrics-proxy",
            "bind_fs": false,
            "disk_encryption": {
                "enable": false,
                "encryption_key_security": "standard"
            }
        }
    ]
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `enable` | bool | Yes | — | Master gate. If `false`, disk setup is skipped entirely |
| `disks` | array | No | — | Disk entries |
| `disks[].serial` | string | Yes | Non-empty, unique across entries | Disk serial number. Resolved to `/dev/` path via a 5-phase lookup: symlinks, lsblk, sysfs, GCP metadata, Azure IMDS |
| `disks[].disk_mount_point` | string | Yes | Non-empty, unique across entries | Filesystem mount point |
| `disks[].service` | string | Yes | Non-empty | Owning compose service name. Enforces that only this service can use the disk's named volume |
| `disks[].bind_fs` | bool | No | — | Enable bindfs UID translation. When true, disk is mounted via bindfs at `/data/bindfs/{volumeName}` with forced UID/GID matching the container's assigned UID |
| `disks[].disk_encryption.enable` | bool | No | — | Enable LUKS encryption for this disk |
| `disks[].disk_encryption.encryption_key_security` | string | If encryption enabled | Must be `"standard"` or `"strong"` | TPM PCR binding level for the encryption key. `"standard"` = PCR 11 (kernel). `"strong"` = PCR 10 + 11 (firmware + kernel) |

**Validation**:
- Each entry must have non-empty `serial`, `disk_mount_point`, and `service`
- No duplicate `serial` values
- No duplicate `disk_mount_point` values
- If encryption enabled, `encryption_key_security` must be `"standard"` or `"strong"`

**Volume ownership enforcement**: When a compose service uses a named volume, the system looks up the volume name via `GetServiceByDiskSerial()`. If the requesting service doesn't match the disk entry's `service` field, the volume mount is rejected.

---

## `workload_config`

### `services`

Configures which workload services receive access to the agent's internal API.

```json
"services": {
    "agent_socket_targets": ["my-service"]
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `agent_socket_targets` | string[] | No | — | Services that receive an injected Unix socket at `/var/run/cvm-agent.sock` (inside the container) for accessing the internal agent API. Socket ownership is set to the service's UID slot |

---

### `image_signature_verification`

Controls cosign-based image signature verification before workload startup.

```json
"image_signature_verification": {
    "enable": false,
    "auth_info_file_path": "/data/workload/secrets/auth_info.json",
    "signature_verification_policy_path": "/data/workload/config/cvm_agent/sample_image_verify_policy.json"
}
```

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `enable` | bool | Yes | — | Enable cosign image signature verification for all compose images |
| `auth_info_file_path` | string | If `enable: true` | — | Path to JSON file with registry credentials (`{"user_name": "...", "password": "..."}`) |
| `signature_verification_policy_path` | string | If `enable: true` | — | Path to cosign signature verification policy JSON file |

The signature verification policy file follows the `containers/image` policy format:

```json
{
    "default": [{"type": "reject"}],
    "transports": {
        "docker": {
            "docker.io/example/image": [
                {
                    "type": "sigstoreSigned",
                    "keyPath": "/data/workload/config/cvm_agent/cosign.pub",
                    "signedIdentity": {"type": "matchRepository"}
                }
            ]
        }
    }
}
```

---

## Complete Example

A full-featured policy file covering all sections:

```json
{
    "cvm_config": {
        "emulation_mode": {
            "enable": false,
            "cloud_provider": "azure",
            "tee_type": "snp",
            "emulation_data_path": "./emulation_mode_data",
            "enable_emulation_data_update": true
        },
        "firewall": {
            "allowed_ports": [
                {
                    "name": "allow_https",
                    "protocol": "tcp",
                    "port": "443"
                }
            ]
        },
        "container_api": {
            "container_engine": "podman",
            "container_owner": "automata"
        },
        "baby_container": {
            "allow": true,
            "max_count": 2
        },
        "disk_config": {
            "enable": true,
            "disks": [
                {
                    "serial": "data-vol-001",
                    "disk_mount_point": "/data/data-disk",
                    "service": "metrics-proxy",
                    "bind_fs": false,
                    "disk_encryption": {
                        "enable": false,
                        "encryption_key_security": "standard"
                    }
                }
            ]
        }
    },
    "workload_config": {
        "services": {
            "agent_socket_targets": ["nginx-socket-test"]
        },
        "image_signature_verification": {
            "enable": false,
            "auth_info_file_path": "/data/workload/secrets/auth_info.json",
            "signature_verification_policy_path": "/data/workload/config/cvm_agent/sample_image_verify_policy.json"
        }
    }
}
```

---

## Minimal Valid Policy

The absolute minimum required to pass validation:

```json
{
    "cvm_config": {
        "emulation_mode": {
            "enable": false
        },
        "container_api": {
            "container_engine": "podman"
        }
    }
}
```

Only `container_engine` has a strict validation requirement (must be `"podman"` or `"docker"`). All other fields default to their zero values (false, empty string, empty array, 0).

**Note**: A minimal policy disables most features: no firewall rules, no disk setup, no baby containers, no image verification.

---

## Subsystem-to-Policy Field Map

| Subsystem | Package | Policy Fields Read |
|-----------|---------|-------------------|
| TEE emulation | `security_monitor` | `cvm_config.emulation_mode.*` |
| Firewall | `firewall` | `cvm_config.firewall.allowed_ports[]` |
| Container runtime | `container_api` | `cvm_config.container_api.container_engine`, `.container_owner` |
| UID isolation | `container_api` | `cvm_config.container_api.container_owner` (for subuid lookup) |
| Socket injection | `container_api` | `workload_config.services.agent_socket_targets[]` |
| Volume restrictions | `container_api` | `cvm_config.disk_config.disks[].serial`, `.service`, `.bind_fs` |
| Disk setup | `disk` | `cvm_config.disk_config.*` |
| Baby containers | `baby_container` | `cvm_config.baby_container.allow`, `.max_count` |
| Workload startup | `workload_op` | `workload_config.services.agent_socket_targets[]`, image sig verification fields |
| Image verification | `workload_op`, `container_api` | `workload_config.image_signature_verification.*` |

---

## Validation Summary

Errors during `security_monitor.Load()` are fatal — the agent will not start with an invalid policy.

| Rule | Error Condition |
|------|-----------------|
| Emulation cloud provider | `enable: true` and `cloud_provider` not in `{"azure", "google", "amazon"}` |
| Emulation TEE type | `enable: true` and `tee_type` not in `{"tdx", "snp"}` |
| Container engine | `container_engine` not in `{"podman", "docker"}` |
| Firewall rule name | Empty `name` in any port entry |
| Firewall protocol | `protocol` not in `{"tcp", "udp"}` |
| Firewall port | `port` not parseable as integer, or outside 1-65535 |
| Firewall duplicates | Two rules with same `name-protocol-port` tuple |
| Disk serial | Empty `serial` in any disk entry |
| Disk mount point | Empty `disk_mount_point` in any disk entry |
| Disk service | Empty `service` in any disk entry |
| Disk serial uniqueness | Duplicate `serial` values across disk entries |
| Disk mount uniqueness | Duplicate `disk_mount_point` values across disk entries |
| Disk encryption level | Encryption enabled but `encryption_key_security` not in `{"standard", "strong"}` |
| Baby container max count | `allow: true` but `max_count <= 0` |
