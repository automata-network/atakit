# `.atawl` Archive Format Specification

A `.atawl` file is the deployable unit for CVM workloads. It packages everything the runtime needs to load and run a workload: a manifest, integrity-verified data, and pre-built container images. The file is a tar.zst (tar + zstandard) with a custom extension - inspectable with standard tools (`tar --zstd -tf`). Workload builds always write zstd, including when the deprecated `--gz` flag is supplied. CLI inspection can still read legacy tar.gz archives, but portal initialization requires zstd; rebuild legacy gzip workloads before deployment.

## Design Principles

1. **Self-contained.** The archive contains everything needed to deploy. No registry pulls, no external dependencies at load time. Registry images are pre-pulled and bundled.
2. **Deterministic measurement.** Same runtime config + same content = same PCR23, regardless of how or where images were built. Build-time metadata is stripped.
3. **Source/compiled separation.** `atakit-workload.toml` is source (lives in repo, authored by developers). `manifest.json` is the compiled artifact (lives in archive, read by runtime). The source TOML is not in the archive.
4. **Transitive integrity.** PCR23 = hash of `manifest.json`. The manifest contains SHA-256 hashes of all bundled content **and** the image config digest ("image-id") of every container. Changing any file or any container's image content changes the manifest, which changes PCR23.
5. **Immutable runtime identity.** The manifest commits to each service's image-id (`sha256(<image-config-blob>)`), the same value `podman images --no-trunc` reports as IMAGE ID. The runtime runs containers by image-id, not by tag, so a malicious `podman load` cannot rebind a tag and substitute a different image between load and run.

---

## Manifest Format

The manifest is serialized as [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON (JCS - JSON Canonicalization Scheme). This guarantees byte-for-byte determinism: object keys are sorted by Unicode code point, no unnecessary whitespace, numbers normalized. The canonical form is what gets hashed for PCR23.

Every field applicable to the selected manifest format is always present in
the generated JSON. Optional source settings receive explicit defaults:
`null`, `false`, an empty array/object, or the field's defined value. This rule
covers the main workload, dependencies, baby slots/lifecycle and disks.
Fields that do not belong to that format are absent; a removed field is not a
missing default. A shared Rust type is not the schema for every format.

### Equivalent input values

The builder normalizes runtime settings before generating JSON. JSON key
sorting alone does not make different spellings or unordered lists equivalent.

| Input field | Generated representation |
| --- | --- |
| Main/dependency/baby `cpuset` | Sorted unique decimal CPU IDs: `"0-3"` and `"3,1,0,2,2"` both become `"0,1,2,3"` |
| `cpu-idle.disabled-states` and CPU allowlists | Sorted unique names; wildcard state allowance reduces to `["*"]` |
| `cpuset-policy.allowed-cpus` | Sorted unique decimal IDs, or the explicit `"online"` allowance |
| `base-image`, `depends_on`, `cap-add`, `cap-drop`, baby `allowed_capabilities`, logging `log-readers` | Sorted unique strings |
| Custom attribute allowed values | Sorted unique strings; reserved hardware attributes retain their dedicated rules |
| Disk `encryption.bind` | Sorted unique bindings |
| Disk `size` and `boot-disk-size` | Largest exact `TB`, `GB` or `MB` unit, using the project's 1024-based conversions; `10240MB` becomes `10GB` |
| Logging `max-size` | Largest exact lowercase `g`, `m` or `k` unit, or decimal bytes; `52428800` becomes `50m` |
| Logging `max-file` | Decimal integer without leading zeros; `05` becomes `5` |

Sizes are never rounded by normalization. Zero log size is `"0"`. Validation
still rejects invalid input, including duplicate entries in fields that require
unique source entries. Normalization does not make an invalid policy valid.

Command arguments, entrypoint arguments and environment-file lists keep their
order because it affects execution or override precedence. This is not a rule
to sort every array or rewrite arbitrary paths and image references.

Normalization applies to newly built manifests, including supported older
formats. It does not rewrite existing archives or replace their measured bytes.

### Supported formats

The CLI and generic Portal manifest reader accept compiled formats 11–16.
Image startup has a narrower gate: v0.3.5 requires format 15; v0.3.6 and v0.3.7 accept
only format 16, including after reboot. Formats 14 and 15 cannot start on
v0.3.6 and v0.3.7, even without CPU settings. Formats below 11 are rejected by
current archive inspection; formats above 16 require an updated toolchain.

| Format | Added behavior |
| --- | --- |
| 11 | Baseline, including readiness and baby lifecycle/disk selection |
| 12 | Authenticated disk `encryption.integrity` |
| 13 | Per-mount `executable` |
| 14 | Storage `access` and baby `parent_access`; removes `read_only`, `executable` and baby `permissions` |
| 15 | Signed baby logging `access` and reader grants |
| 16 | Main/dependency/baby `cpuset` and `nofile`, VM-wide `cpu-idle` and `cpu-frequency` |

### Explicit generated defaults

| Generated location | Default when not set in source | Applicable formats |
| --- | --- | --- |
| `config.readiness`, `config.dependencies.<name>.readiness` | `null` | 11–16 |
| `config.baby-container.slots.<name>.lifecycle.rootfs_size_mib` | `null` | 11–16 |
| `config.baby-container.slots.<name>.lifecycle.rootfs_disk` | `null` | 11–16 |
| `disks.<name>.encryption.integrity` | `null` | 12–16 |
| Main/dependency/baby storage `executable` | `false` | 13 only |
| Baby storage `parent_access` | `[]` | 14–16 |
| Baby `logging.access` | `"parent"` | 15–16; not a main/dependency field |
| Main/dependency/baby `cpuset` and `cpuset-policy` | `null` | 16 |
| Main/dependency/baby `nofile` | `null` (base-image default) | 16 |
| `config.cpu-idle`, `config.cpu-frequency` | `null` | 16 |

A null CPU policy means no requested change. A null CPU set means no requested
placement restriction. Inside a present CPU policy, `required` defaults to
`true`; an omitted idle governor is `null` and omitted `disabled-states` is
`[]`. See [CPU controls](workload-cpu-controls.md) for the runtime rules.

Generated output uses these explicit fields even when a reader tolerates
older archives missing optional keys. Readers measure the archive's original
manifest bytes, not a rewritten copy. Correcting defaults in a newly built
archive changes its bytes and measurement; it does not rewrite old archives.

---

## Full Example

### Archive Layout

```
secure-signer/
  manifest.json
  measured-data/
    config/
      hello
      cert.pem
  images/
    secure-signer.tar
    redis.tar
    model-server.tar
```

The top-level directory is always the workload name. Three entries:

Readers require exactly one top-level directory and exactly one
`<workload-name>/manifest.json`. The directory name must equal
`meta.name`. Readers accept regular files and directories only. They reject
links, special files, duplicate paths, and unsafe paths.

| Path | Contents |
|---|---|
| `manifest.json` | Compiled workload definition + content hashes + per-service image identity (RFC 8785 canonical JSON) |
| `measured-data/` | Integrity-verified files (PCR23). Directory structure preserved from source |
| `images/` | Container image tar archives for every container (workload + all dependencies). Either docker-archive or oci-archive; both are accepted. |

Not in the archive:
- `atakit-workload.toml` - source format, not needed at deploy time
- `unmeasured-data/` - contents are operator-provided at deploy time, not developer-shipped. The declared *path set* is still committed to the manifest's top-level `unmeasured-data` array (and thus PCR23); only the bytes are absent.

### Full Manifest

Built from the full example in the [workload TOML spec](atakit-workload-toml-spec.md). Shown pretty-printed for readability; the actual on-disk form is canonical minified JSON with sorted keys.

```json
{
  "config": {
    "atakit-portal": true,
    "attributes": {
      "atakit.attestation.v1.tee.amd-sev-snp.debug.enabled": [
        false,
        true
      ],
      "atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled": [
        false
      ],
      "atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy": [
        "0x0000000000000000000000000000000000000000000000000000000000000020"
      ],
      "atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum": [
        "0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004"
      ],
      "example.environment": [
        "production"
      ]
    },
    "baby-container": {
      "enabled": true,
      "max_instances": 2,
      "slots": {
        "analysis-job": {
          "allowed_capabilities": [],
          "cpuset": null,
          "cpuset-policy": null,
          "nofile": null,
          "gid_group": "shared",
          "image_selection": "multiple",
          "ip_env": false,
          "lifecycle": {
            "image_retention": "disk",
            "instance_retention": "ephemeral",
            "restart": "manual",
            "rootfs": "read_only",
            "rootfs_disk": null,
            "rootfs_size_mib": null
          },
          "logging": {
            "access": "parent",
            "driver": "k8s-file",
            "log-readers": [],
            "options": {
              "max-file": "3",
              "max-size": "10m"
            }
          },
          "max_instances": 1,
          "parent_service": "secure-signer",
          "storage": {
            "workspace": {
              "access": [
                "read",
                "write"
              ],
              "base_path": "/analysis-job/instances",
              "disk": "secure-signer-data",
              "mount_path": "/workspace",
              "parent_access": [
                "read"
              ],
              "retention": "disk",
              "scope": "instance"
            }
          },
          "trust_policy": "user-helper-image"
        }
      }
    },
    "base-image": [
      "automata-linux:v0.1.5-debug",
      "mola-linux:v0.1.0-debug"
    ],
    "base-image-mode": "blacklist",
    "boot-disk-size": "50GB",
    "cap-add": [
      "NET_ADMIN"
    ],
    "cap-drop": [
      "NET_BIND_SERVICE"
    ],
    "command": null,
    "cpu-frequency": null,
    "cpu-idle": null,
    "cpuset": null,
    "cpuset-policy": null,
    "nofile": null,
    "dependencies": {
      "model-server": {
        "atakit-portal": false,
        "cap-add": [],
        "cap-drop": [],
        "command": null,
        "cpuset": null,
        "cpuset-policy": null,
        "nofile": null,
        "depends_on": [],
        "entrypoint": null,
        "environment": {},
        "gid-group": "secure-signer",
        "image": "model-server:v0.0.1",
        "ip_env": false,
        "logging": {
          "driver": "k8s-file",
          "log-readers": [],
          "options": {
            "max-file": "5",
            "max-size": "50m"
          }
        },
        "measured-data": [
          "measured-data/config/cert.pem",
          "measured-data/config/hello"
        ],
        "ports": [
          "8080:8080"
        ],
        "readiness": null,
        "restart": "no",
        "storage": {},
        "unmeasured-data": [],
        "unmeasured-env-files": [],
        "workload-logs": false
      },
      "redis": {
        "atakit-portal": false,
        "cap-add": [],
        "cap-drop": [],
        "command": null,
        "cpuset": null,
        "cpuset-policy": null,
        "nofile": null,
        "depends_on": [],
        "entrypoint": null,
        "environment": {},
        "gid-group": "secure-signer",
        "image": "redis:7",
        "ip_env": false,
        "logging": {
          "driver": "k8s-file",
          "log-readers": [],
          "options": {
            "max-file": "5",
            "max-size": "50m"
          }
        },
        "measured-data": [],
        "ports": [],
        "readiness": null,
        "restart": "no",
        "storage": {},
        "unmeasured-data": [],
        "unmeasured-env-files": [],
        "workload-logs": false
      }
    },
    "depends_on": [
      "model-server",
      "redis"
    ],
    "entrypoint": null,
    "environment": {
      "LISTEN_ADDR": "0.0.0.0:3000",
      "RUST_LOG": "info"
    },
    "firewall-ports": [
      {
        "port": 1024,
        "protocol": "tcp"
      },
      {
        "port": 2024,
        "protocol": "tcp"
      },
      {
        "port": 3000,
        "protocol": "tcp"
      },
      {
        "port": 3000,
        "protocol": "udp"
      },
      {
        "port": 4000,
        "protocol": "tcp"
      },
      {
        "port": 8080,
        "protocol": "tcp"
      },
      {
        "port": 8080,
        "protocol": "udp"
      }
    ],
    "gid-group": "shared",
    "image": "secure-signer:v0.0.1",
    "ip_env": false,
    "logging": {
      "driver": "k8s-file",
      "log-readers": [],
      "options": {
        "max-file": "5",
        "max-size": "50m"
      }
    },
    "measured-data": [
      "measured-data/config/cert.pem",
      "measured-data/config/hello"
    ],
    "ports": [
      "3000:3000"
    ],
    "readiness": null,
    "restart": "unless-stopped",
    "session-ttl": 0,
    "storage": {
      "data": {
        "access": [
          "read",
          "write"
        ],
        "base_path": "/",
        "disk": "secure-signer-data",
        "mount_path": "/data"
      },
      "data2": {
        "access": [
          "read",
          "write"
        ],
        "base_path": "/",
        "disk": "secure-signer-data2",
        "mount_path": "/data2"
      }
    },
    "unmeasured-data": [
      "unmeasured-data/additional-data/signer_key.env"
    ],
    "unmeasured-env-files": [
      "unmeasured-data/additional-data/signer_key.env"
    ],
    "workload-logs": false
  },
  "disks": {
    "secure-signer-data": {
      "encryption": {
        "bind": [],
        "integrity": null,
        "unlock_method": []
      },
      "index": 10,
      "size": "10GB"
    },
    "secure-signer-data2": {
      "encryption": {
        "bind": [
          "workload"
        ],
        "integrity": null,
        "unlock_method": [
          "tpm"
        ]
      },
      "index": 11,
      "size": "11GB"
    }
  },
  "hashes": {
    "images/model-server.tar": "sha256:f012...",
    "images/redis.tar": "sha256:9cde...",
    "images/secure-signer.tar": "sha256:78ab...",
    "measured-data/config/cert.pem": "sha256:ef56...",
    "measured-data/config/hello": "sha256:cd34..."
  },
  "images": {
    "model-server": {
      "archive": "images/model-server.tar",
      "image-id": "sha256:1111..."
    },
    "redis": {
      "archive": "images/redis.tar",
      "image-id": "sha256:2222..."
    },
    "secure-signer": {
      "archive": "images/secure-signer.tar",
      "image-id": "sha256:3333..."
    }
  },
  "meta": {
    "format": 16,
    "name": "secure-signer",
    "publisher": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "version": "v0.0.1"
  },
  "unmeasured-data": [
    "unmeasured-data/additional-data/signer_key",
    "unmeasured-data/additional-data/signer_key.env"
  ],
  "unmeasured-env-files": {
    "unmeasured-data/additional-data/signer_key.env": [
      "SIGNER_KEY_PATH"
    ]
  }
}
```

The top-level `unmeasured-data` array lists the allowed operator-provided paths
(see `[package] unmeasured-data` in the source TOML). Unlike `measured-data`,
these carry no entry in `hashes` — the files are not in the archive — but the
path allowlist is committed to PCR23, and the portal verifies the operator's
`/init` upload extracts to a subset of this set.

---

## Minimal Example

### Archive Layout

```
my-app/
  manifest.json
  images/
    my-app.tar
```

No `measured-data/` directory (nothing to measure beyond the image itself).

### Minimal Manifest

All fields are present even in the minimal case (no conditional omission). Default values are filled in by the build pipeline.

```json
{
  "config": {
    "atakit-portal": false,
    "attributes": {},
    "baby-container": {
      "enabled": false,
      "max_instances": 0,
      "slots": {}
    },
    "base-image": [],
    "base-image-mode": "blacklist",
    "boot-disk-size": null,
    "cap-add": [],
    "cap-drop": [],
    "command": null,
    "cpu-frequency": null,
    "cpu-idle": null,
    "cpuset": null,
    "cpuset-policy": null,
    "nofile": null,
    "dependencies": null,
    "depends_on": [],
    "entrypoint": null,
    "environment": {},
    "firewall-ports": [
      {
        "port": 1024,
        "protocol": "tcp"
      },
      {
        "port": 2024,
        "protocol": "tcp"
      }
    ],
    "gid-group": "my-app",
    "image": "my-app:latest",
    "ip_env": false,
    "logging": {
      "driver": "k8s-file",
      "log-readers": [],
      "options": {
        "max-file": "5",
        "max-size": "50m"
      }
    },
    "measured-data": [],
    "ports": [],
    "readiness": null,
    "restart": "no",
    "session-ttl": 0,
    "storage": {},
    "unmeasured-data": [],
    "unmeasured-env-files": [],
    "workload-logs": false
  },
  "disks": {},
  "hashes": {
    "images/my-app.tar": "sha256:ab12..."
  },
  "images": {
    "my-app": {
      "archive": "images/my-app.tar",
      "image-id": "sha256:cd34..."
    }
  },
  "meta": {
    "format": 16,
    "name": "my-app",
    "publisher": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "version": "v0.0.1"
  },
  "unmeasured-data": [],
  "unmeasured-env-files": {}
}
```

---

## Schema Reference

JSON keys shown in dot notation (e.g. `meta.format` means `{"meta": {"format": ...}}`).

### `meta` - Archive Metadata

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Compiled schema version, `11`–`16`; see the image startup gates above. |
| `publisher` | string | yes | Fingerprint of the publishing key: `0x` followed by 64 lowercase hexadecimal characters. Comes from the build's signing key, never from the source TOML. |
| `name` | string | yes | Workload name. Matches `[workload] name` from source TOML. |
| `version` | string | yes | Workload version. Matches `[workload] version` from source TOML. |

`publisher` is inside the measured manifest, so it is covered by PCR23. This is
deliberate: the workload identifier is
`keccak256(abi.encode(domain, publisher, name, version))`, so a portal that read
its publisher from an unmeasured source could attest one publisher's identity
while running another's workload. Because it is measured, two publishers
building identical sources produce different PCR23 values.

### `config` - Canonical Runtime Configuration

The resolved, canonicalized runtime config extracted from `atakit-workload.toml`. Build-time metadata is stripped. Image references are normalized to `name:tag` strings (the actual tars live under `images/`).

#### Workload Fields

| Field | Type | Always present | Default | Source in TOML |
|---|---|---|---|---|
| `image` | string | yes | - | `[workload] image` (resolved to `name:tag`) |
| `base-image-mode` | string | yes | - | `[workload] base-image-mode` |
| `base-image` | array of strings | yes | `[]` | `[workload] base-image` |
| `ports` | array of strings | yes | `[]` | `[workload] ports` |
| `depends_on` | array of strings | yes | `[]` | `[workload] depends_on`. Service names that must start first. |
| `restart` | string | yes | `"no"` | `[workload] restart` |
| `command` | string or array | no | null | `[workload] command` |
| `entrypoint` | string or array | no | null | `[workload] entrypoint` |
| `atakit-portal` | bool | yes | `false` | `[workload] atakit-portal` |
| `ip_env` | bool | yes | `false` | `[workload] ip-env` |
| `measured-data` | array of strings | yes | `[]` | `[workload] measured-data`, expanded to selected `measured-data/...` paths |
| `unmeasured-data` | array of strings | yes | `[]` | `[workload] unmeasured-data`, expanded to selected `unmeasured-data/...` paths |
| `session-ttl` | integer | yes | `0` | `[workload] session-ttl` |
| `attributes` | object | yes | `{}` | `[workload.attributes]`. Custom values are string arrays. An empty custom array requires the attribute to exist and accepts any value. Reserved Boolean values are `[false]` or `[false, true]`. The Intel TDX TCB status value is a supported status-name array that includes `ok`. Each packed AMD SEV-SNP policy is a one-element array containing a `0x`-prefixed bytes32 string. Always serialized and measured by PCR23. |
| `boot-disk-size` | string | no | null | `[workload] boot-disk-size` |
| `gid-group` | string | yes | workload name | `[workload] gid-group` |
| `cap-add` | array of strings | yes | `[]` | `[workload] cap-add`. Always serialized; empty list is a positive commitment. See [`atakit-workload.toml` Capabilities section](atakit-workload-toml-spec.md#capabilities). |
| `cap-drop` | array of strings | yes | `[]` | `[workload] cap-drop`. Always serialized; empty list is a positive commitment. |

For
`atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled`,
`[false, true]` permits either signed `POLICY.MIGRATE_MA` bit. It does not
permit active migration-agent association. An all-zero or all-`0xff`
`REPORT_ID_MA` means that no migration agent is associated. Every other
`REPORT_ID_MA` remains a hard verification failure.

The AMD SEV-SNP packed attribute layouts and registry-default resolution are
defined in
[AMD SEV-SNP Security Policy Specification](amd-sev-snp-security-policy-spec.md).

**`atakit-portal`:** When `true`, the portal mounts a per-service UDS socket into the container at `/run/atakit-portal.sock`. The socket is owned by the service's host UID (mode 0600). The portal identifies callers by which socket accepted the connection.

**`gid-group`:** Controls GID sharing between containers. Services with the same `gid-group` value share a host GID; services with different values get isolated GIDs. In `atakit-workload.toml` this field is optional (defaults to the workload name). In `manifest.json` it is always present with the resolved value.

**`measured-data` / `unmeasured-data`:** Arrays of normalized paths that this service receives. Source TOML booleans are syntax sugar: `true` expands to all declared package paths and `false` expands to `[]`. Directory selectors also expand to exact file paths. `measured-data` entries must appear in the manifest's `hashes` map, while `unmeasured-data` entries must appear in the manifest's top-level `unmeasured-data` array. Both exact path sets are committed to PCR23.

#### `config.environment`

Key-value object of measured environment variables. Values from source `env-file` are resolved and inlined at build time. Legacy source spelling `env_file` is accepted by the builder but never appears in the manifest.

```json
"environment": {
  "LISTEN_ADDR": "0.0.0.0:3000",
  "RUST_LOG": "info"
}
```

#### `config.unmeasured-env-files`

Ordered array of normalized paths to runtime operator-supplied env files. Each entry must also appear in the top-level `unmeasured-data` array and in the top-level `unmeasured-env-files` object. The array order is measured because later files override earlier files.

```json
"unmeasured-env-files": [
  "unmeasured-data/secrets/runtime.env"
]
```

At runtime the portal reads and parses each file itself. Every key must appear in the measured allowlist for that file. Missing files and missing keys are allowed. Undeclared keys, duplicate keys within one file, invalid names, and reserved `ATAKIT_*` and `VERIFIERD_*` names are rejected. `VERIFIERD_*` values configure `atakit-verifierd` trust and optional portal destination policy and MUST come from measured manifest environment. The portal never passes an operator-controlled env file to Podman.

Each non-empty, non-comment line has the form `NAME=VALUE`. A comment line is one whose first non-space character is `#`. The parser splits at the first `=`, trims surrounding space from the name and value, and treats all remaining value bytes as literal UTF-8. It does not expand quotes, escapes, variables, or shell commands.

The portal merges values in this order: later unmeasured env files override earlier files; measured `config.environment` values override all unmeasured values; portal-injected `ATAKIT_*` values override everything else. It then passes only the merged key-value pairs to Podman.

#### `config.ip_env`

Boolean opt-in for portal-injected VM network identity. When `true`, the runtime injects `ATAKIT_PUBLIC_IP` and `ATAKIT_INTERNAL_IP` into the container environment. Missing values are injected as empty strings. These reserved variables are emitted after env-files and measured environment, so they override matching user-provided values.

#### `config.storage`

Maps service-local storage labels to disk subpath mounts.

```json
"storage": {
  "data": {
    "base_path": "/",
    "disk": "secure-signer-data",
    "mount_path": "/data",
    "read_only": false
  }
}
```

`disk` references a top-level `disks.<name>` declaration. `base_path` is resolved under that disk's mounted root and is created if missing. `mount_path` is the absolute container path. `base_path` and `mount_path` must not contain `..`, NUL, `:`, or `,`. `read_only` controls the container mount mode.

### `config.dependencies.<name>` - Dependency Containers

Same fields as the workload's `config` section (minus `base-image-mode` and `base-image`, which are workload-level). Each dependency is a key in the `dependencies` object.

| Field | Type | Always present | Default | Description |
|---|---|---|---|---|
| `image` | string | yes | - | Resolved image reference (`name:tag`). |
| `ports` | array of strings | yes | `[]` | Exposed ports. |
| `restart` | string | yes | `"no"` | Restart policy. |
| `command` | string or array | no | null | Override CMD. |
| `entrypoint` | string or array | no | null | Override ENTRYPOINT. |
| `environment` | object | yes | `{}` | Environment variables. |
| `ip_env` | bool | yes | `false` | Runtime injection of `ATAKIT_PUBLIC_IP` and `ATAKIT_INTERNAL_IP`. |
| `unmeasured-env-files` | array of strings | yes | `[]` | Runtime env files resolved under top-level `unmeasured-data`. |
| `depends_on` | array of strings | yes | `[]` | Services that must start first. May include the main workload's exact `meta.name`. |
| `measured-data` | array of strings | yes | `[]` | Selected measured paths mounted into this container. |
| `unmeasured-data` | array of strings | yes | `[]` | Selected unmeasured paths mounted into this container. |
| `storage` | object | yes | `{}` | Service-local storage labels to disk subpath mounts. |
| `atakit-portal` | bool | yes | `false` | Enable portal UDS socket for this service. |
| `gid-group` | string | yes | workload name | GID sharing group. |
| `cap-add` | array of strings | yes | `[]` | Linux capabilities to grant. Allowlisted; per-container. |
| `cap-drop` | array of strings | yes | `[]` | Linux capabilities to drop from the default cap set. Per-container. |

### `config.firewall-ports` - Resolved Firewall Ports

A flat array of port/protocol objects to open. This is the compiled result of: always-allowed portal ports (1024, 2024) + auto-derived ports from `ports` fields + `[firewall] allow` entries - `[firewall] deny` entries. Portal ports cannot be denied. Sorted by port number, then protocol, for deterministic output.

| Field | Type | Description |
|---|---|---|
| `port` | integer | Port number. |
| `protocol` | string | `"tcp"` or `"udp"`. |

Ports without a protocol suffix in the source config are expanded to two entries (tcp + udp).

### `config.baby-container` - Baby Container Runtime

| Field | Type | Default | Source in TOML |
|---|---|---|---|
| `enabled` | bool | `false` | `[baby-container] enabled` |
| `max_instances` | integer | `0` when disabled | `[baby-container] max-instances` |
| `slots` | object | `{}` | `[baby-container.slots.*]` |

When disabled, `config.baby-container` is always materialized as:

```json
{"enabled":false,"max_instances":0,"slots":{}}
```

`slots` is an object keyed by slot name. Each slot object contains:

| Field | Type | Description |
|---|---|---|
| `parent_service` | string | Service that owns the slot and whose portal UDS may operate it. |
| `gid_group` | string | Stable GID group used for baby storage sharing. |
| `image_selection` | string | `"single"` or `"multiple"`. |
| `max_instances` | integer | Slot-local concurrent instance limit. |
| `ip_env` | bool | Opt baby instances in this slot into `ATAKIT_PUBLIC_IP` and `ATAKIT_INTERNAL_IP`. |
| `lifecycle` | object | Image/container retention and restart policy. |
| `storage` | object | Storage scopes keyed by storage name. |
| `logging` | object | Baby-container log driver/options/access, same canonicalization style as service logging. |
| `trust_policy` | string or null | Optional reference to a portal trust/key-store policy. |

`lifecycle` uses compiled snake_case names: `image_retention`,
`instance_retention`, `restart`, and `rootfs`. The v1 `rootfs` value is
`"read_only"`.

Baby-container images are uploaded at runtime and are not packaged in the
archive. The manifest commits only to the slot contract. The portal tags loaded
baby images under:

```text
localhost/atakit-baby/<workload-id>/<service>/<slot>:<image-id-hex>
```

Those tags are cleanup/reconciliation markers, not create handles. Creates use
canonical image IDs. `image_retention = "session"` images are removed from that
workload-scoped namespace on startup; `image_retention = "disk"` images are kept
only when a current portal image index validates them. `instance_retention =
"disk"` persists instance intent in portal indexes and reconstructs containers
after the parent workload service starts; it does not preserve old Podman
container objects across reboot.

Storage entries use compiled snake_case names: `base_path`, `mount_path`,
`read_only`, `retention`, `scope`, and `permissions`.

Runtime create requests may provide `instance_id` for `scope = "instance"` and
may provide `storage_keys` for future `scope = "key:<name>"` storage. These
request values are identifiers resolved under manifest-declared base paths, not
paths.

`trust_policy` is a measured reference only. The trust/key-store namespace is
specified separately from baby containers so future features can reuse the same
policy objects without changing baby-container slot shape.

### `disks.<name>` - Persistent Storage

Top-level object (not under `config`). Defines persistent disk volumes attached to the CVM.

| Field | Type | Required | Description |
|---|---|---|---|
| `index` | integer | yes | LUN / device index for cloud disk attachment. Must be >= 10 and unique across all disks. |
| `size` | string | yes | Disk size (e.g. `"10GB"`). |

#### `disks.<name>.encryption` - Disk Encryption

Uses the unified encryption schema (same structure as [baseimage.toml](baseimage-toml-spec.md) RW partition encryption).

The encryption block is **always present** in `manifest.json`. For an unencrypted disk, format 11 emits `{"bind": [], "unlock_method": []}`; formats 12–16 also emit `"integrity": null`. Source disk declarations require an explicit `encryption` block. Empty arrays explicitly declare no encryption.

| Field | Type | Required | Description |
|---|---|---|---|
| `unlock_method` | string[] | yes (may be `[]`) | Unlock methods for this disk. Supported values listed below. |
| `bind` | string[] | yes (may be `[]`) | PCR bindings when `unlock_method` includes `"tpm"`. |

**`unlock_method`** values:

| Value | Description |
|---|---|
| `"tpm"` | TPM2 PCR seal. |
| `"passphrase"` | Operator-supplied secret delivered via `init-config.disks.<name>.passphrase` at `/init`. |
| `"keyfile"` | *Reserved — not yet supported.* The build pipeline rejects manifests using this method. |
| `"kms"` | *Reserved — not yet supported.* The build pipeline rejects manifests using this method. |

**`bind`** values:

| Value | PCR Range | Description |
|---|---|---|
| `"platform"` | 0-7 | Preboot/firmware measurements. |
| `"baseimage"` | 11 | Base image measurement. |
| `"workload"` | 23 | Workload measurement. Permitted for data disks (unlike the RW partition). |

### `hashes` - Content Integrity

Flat key-value object. Keys are archive-relative paths. Values are `"sha256:<hex>"` strings.

Every file in the archive (except `manifest.json` itself) gets an entry:

| Key pattern | Source |
|---|---|
| `"measured-data/..."` | Files under `measured-data/` |
| `"images/<name>.tar"` | Container image tar archives under `images/` |

### `images` - Per-Service Image Identity

Object keyed by service name (the workload's own name plus each entry under `config.dependencies`). Each value is an object with two fields:

| Field | Type | Description |
|---|---|---|
| `archive` | string | Archive-relative path to the image tar. Matches the corresponding key in `hashes`. |
| `image-id` | string | `"sha256:<hex>"`. The image config digest (a.k.a. "image ID"), `sha256(<image-config-blob>)`. The same value `podman images --no-trunc` reports as IMAGE ID. |

The image-id is the immutable runtime identity of a container image. It is computed at build time from inside each image tar (read directly from oci-archive `index.json`, or extracted from the Config field of docker-archive `manifest.json` and verified by hashing the actual config blob). It transitively covers env, cmd, entrypoint, and rootfs (via `rootfs.diff_ids` in the config blob), so it commits to what the container will actually execute.

The runtime uses image-id to address containers (`podman run sha256:<hex>`) instead of mutable tags, closing the gap where a malicious `podman load` could rebind a tag between load and run. See "Runtime Verification" below.

Always present (may be an empty object only when reading legacy v1 archives via the compatibility shim).

### `unmeasured-data` - Declared Operator-Provided Paths

Top-level array of strings, each an `unmeasured-data/`-prefixed archive-relative path (e.g. `"unmeasured-data/config/cert.pem"`). These are the files the workload declares the operator may provide at deploy time, sourced from logical absolute `[package] unmeasured-data` paths under the unmeasured-data root in the source TOML.

Unlike `hashes` entries, there is **no content hash**: the files are not in the archive. Only the declared **path allowlist** is recorded — and because it is part of `manifest.json`, it is committed to PCR23. A source declaration ending in `/` is a directory: it must exist at build time and is enumerated into sorted member files. A declaration without a trailing `/` is an exact file and may be absent at build time unless used as an env-file template. Existing directories without the trailing `/` are rejected. The array is sorted, deduplicated, and always present (empty `[]` is a positive commitment that the workload permits no operator-provided files).

At `/init` the operator may upload contents as a tar.gz (see [portal API spec](portal-api-spec.md)). The portal accepts regular files and directories only. It rejects symlinks, hard links, devices, FIFOs, sockets, absolute paths, traversal, duplicate paths, and undeclared files. Missing declared paths are allowed. The contents are not part of the workload measurement. Env syntax and declared names are validated; workloads must still validate the meaning of every unmeasured file they consume. v0.3.7 also authenticates complete owner-authorized replacements and protects stored data with a private keyed hash; see [unmeasured-data updates](unmeasured-data-update-spec.md).

Before containers start, the supervisor freezes the canonical source tree as root-owned read-only files and directories. It creates one private view directory per service containing only that service's exact selected files that are present. It uses filesystem reflinks when available and otherwise makes independent byte copies. It never uses hard links. The view is built in a temporary directory and renamed into place only after it is complete.

The runtime mounts that single view directory at `/atakit-portal/unmeasured-data/` with `readonly`, `noexec`, `nosuid`, and `nodev`. The canonical source tree is never mounted into a container. The views are derived state and are rebuilt during initialization and reboot recovery.

### `unmeasured-env-files` - Measured Environment-Key Allowlists

Top-level object keyed by normalized `unmeasured-data/...` env-file path. Each value is a sorted array of allowed environment variable names. The object is always present; `{}` means no unmeasured env file is allowed.

```json
"unmeasured-env-files": {
  "unmeasured-data/secrets/runtime.env": ["API_TOKEN", "REGION"]
}
```

The builder reads each referenced developer-side env file. It measures the file path and its variable names, but ignores its values. Changing an allowed name changes PCR23. Changing only a template value does not. A runtime file may define any subset of the measured names.

### Fields NOT in the Manifest

| Source TOML section | Reason excluded |
|---|---|
| `[workload] image` build/file metadata (`build`, `containerfile`, `args`, `file`) | Build-time metadata stripped. Resolved `name:tag` kept in `config.image`. |
| `[workload] env-file` | Inlined into `config.environment` at build time. Legacy source spelling `env_file` is accepted but not emitted. |
| `[workload] unmeasured-env-file` | Emitted as `config.unmeasured-env-files`; must reference top-level `unmeasured-data` paths. |
| `[package] measured-data` (file paths) | Files bundled into `measured-data/` and covered by `hashes`. The raw path list is not a separate field — the `hashes` keys enumerate it. |
| `[signing]` | Removed in format 2. |
| (deployment targets) | Live in operator config (`config.toml`), not in the workload definition. |

---

## Image Resolution Rules

All container images - regardless of source - are resolved to container image tar archives (docker-archive or oci-archive) under `images/` at build time.

| Source form | Build behavior | Tar filename |
|---|---|---|
| `image = { build = "." }` | Build image, export as a container image tar (docker-archive). Auto-tagged `{name}:{version}`. | `<service>.tar` |
| `image = { file = "./path.tar" }` | Copy the tar into the archive (must be docker-archive or oci-archive). | `<service>.tar` |
| `image = "redis:7"` | Pull from registry, export as a container image tar (docker-archive). | `<service>.tar` |

**Service name mapping:** The workload's tar is named after `[workload] name`. Dependency tars are named after the dependency key (e.g. `[dependencies.redis]` produces `redis.tar`).

**Why bundle registry images?** Three reasons:

1. **Reproducibility** - the archive is fully self-contained. No risk of upstream tag overwrites or registry outages at deploy time.
2. **Integrity** - images are verified at build time (when registry auth is available). The verified tars ship in the archive.
3. **Simplicity** - the runtime loads all tars uniformly. No conditional pull logic.

The tradeoff is archive size. For CVM workloads where integrity and determinism are requirements, this is worth it.

---

## Measurement Model

### What Gets Measured

PCR23 is a single hash that transitively covers all workload content and configuration. It is computed in two steps:

1. **Event hash** = `SHA-256(manifest.json)` -- SHA-256 of the canonical JSON manifest bytes
2. **Final PCR23** = `SHA-256(zeros_32 || event_hash)` -- a TPM-style PCR extend starting from an all-zeros register

The event hash is what gets extended into PCR23 at workload load time. The final PCR23 register value is what gets registered on-chain in a STATIC `comparison` via `workload publish`.

```
event_hash = SHA-256(manifest.json)      # canonical JSON bytes
                      |
                      +-- config    -- canonical runtime config (ports, env, firewall, ...)
                      +-- hashes    -- SHA-256 of every bundled file:
                      |    +-- measured-data/config/hello              = sha256:cd34...
                      |    +-- measured-data/config/cert.pem           = sha256:ef56...
                      |    +-- images/secure-signer.tar               = sha256:78ab...
                      |    +-- images/redis.tar                       = sha256:9cde...
                      +-- images   -- per-service archive path + image config digest:
                           +-- secure-signer  archive: images/secure-signer.tar  image-id: sha256:3333...
                           +-- redis          archive: images/redis.tar          image-id: sha256:2222...

final_pcr23 = SHA-256(zeros_32 || event_hash)
```

`workload info` displays both values: `SHA256` (event hash) and `PCR23` (final register value).

PCR23 is computed from the original manifest bytes for any compiled format
accepted by the reader (currently 11–16). A valid measurement does not imply
that every image supports starting that format; startup gates remain separate.

Changing any of the following changes both the event hash and PCR23:
- Any file under `measured-data/`
- Any container image (its tar bytes, and its image-id)
- Any runtime config field (ports, environment, restart policy, firewall rules, etc.)
- Any `config.attributes` requirement
- Any unmeasured env-file path or allowed variable name

### What Is NOT Measured

- `unmeasured-data/` *contents* - not in the archive; operator-provided at deploy time. (The declared *path set* in the top-level `unmeasured-data` array **is** measured — only the file bytes are not.)
- Deployment targets -- not in the manifest; live in operator config

### Why Canonical JSON

Two properties make RFC 8785 canonical JSON ideal for deterministic hashing:

1. **Byte-for-byte reproducibility.** JCS defines a single canonical form: sorted keys, no whitespace, normalized numbers. Same logical manifest always produces the same bytes.
2. **No ambiguity.** Unlike TOML (where key ordering and whitespace are flexible), canonical JSON has exactly one valid representation per value.

Hashing `atakit-workload.toml` directly would be non-deterministic. The raw TOML mixes runtime config with build-time metadata:

```toml
# Developer A (builds from source)
image = { build = ".", containerfile = "Containerfile" }
```

```toml
# Developer B (uses pre-built tar)
image = { file = "./images/secure-signer.tar" }
```

Both produce identical runtime behavior and identical images, but different TOML files. The manifest solves this by canonicalizing runtime config and hashing content separately. Same intent = same manifest = same PCR23.

### Runtime Verification

At workload load time, the runtime:

1. Extracts the archive
2. Reads `manifest.json`
3. Verifies every `hashes` entry against the actual file on disk
4. Computes event hash = `SHA-256(manifest.json bytes)`, extends into PCR23
5. For each service: `podman load` the image tar, then query the loaded image's ID and verify it matches `images[svc].image-id` from the manifest. Mismatch is fatal.
6. For each service: run the container with `podman run sha256:<image-id>` (digest reference, not a tag). This binds the running container to the manifest's claimed identity, immune to tag rebinding.

If any hash or image-id mismatch is detected, the runtime rejects the workload. The resulting PCR23 register value can be verified against the on-chain STATIC `comparison`.

**Why image-id, not tag?** Tags in podman are mutable: any `podman load` of a tar declaring the same `name:tag` rebinds the tag. Verifying tar bytes pre-load covers file integrity but does not bind what gets executed. Running by image-id closes that gap, since image-ids are content-addressed.

---

## Build Workflow

`atakit workload build` compiles `atakit-workload.toml` into a `.atawl` archive. Conceptual steps:

```
atakit-workload.toml  --[atakit workload build]-->  secure-signer-v0.0.1.atawl
     (source TOML)                                       (compiled JSON + assets)
```

### Step by Step

1. **Read** `atakit-workload.toml` and validate against the [workload TOML spec](atakit-workload-toml-spec.md).

2. **Resolve images.** For the workload container and all dependencies:
   - `build` - run the container build, export result as a container image tar (docker-archive). Auto-tag as `{name}:{version}`.
   - `file` - verify the tar exists, copy it.
   - Registry string - pull from registry, export as a container image tar (docker-archive).

3. **Collect measured-data.** Copy all `measured-data` files/directories into the archive, preserving directory structure.

4. **Canonicalize runtime config.** Extract runtime-relevant fields from the TOML into the manifest's `config` object:
   - Strip build-time metadata (`build`, `containerfile`, `args`, `file`, source paths).
   - Normalize image references to `name:tag` strings.
   - Convert per-container `measured-data` and `unmeasured-data` to normalized path arrays. Boolean `true` expands to all declared package data paths; boolean `false` expands to `[]`. `[package] measured-data` files are hashed into `hashes`; `[package] unmeasured-data` paths are normalized (trailing-slash directory declarations require build-time enumeration; exact file declarations may be absent) into the top-level `unmeasured-data` array.
   - Inline `env-file` contents into `config.environment`.
   - Normalize `unmeasured-env-file` paths into ordered per-service `unmeasured-env-files`. Read each referenced developer-side file and emit its sorted variable-name allowlist in the top-level `unmeasured-env-files` object. Do not commit its values.
   - Fill default values for omitted optional fields (e.g. `gid-group` defaults to workload name).

5. **Hash all content.** Compute SHA-256 for every file under `measured-data/` and every tar under `images/`.

6. **Extract image-ids.** For each staged image tar, read the image config digest from inside the tar (oci-archive: `index.json` -> manifest blob -> `config.digest`; docker-archive: top-level `manifest.json`'s `Config` field, with the named blob hash-verified). One entry per service in `images`.

7. **Generate `manifest.json`.** Assemble `meta`, `config`, `disks`, `hashes`, and `images` as RFC 8785 canonical JSON via `serde_json_canonicalizer`.

8. **Create archive.** Package into `<name>-<version>.atawl` (tar.zst):
   ```
   <name>/manifest.json
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
Collecting measured-data (2 files)...
Generating manifest.json...
Writing secure-signer.atawl (3 images, 2 measured files)
Done. SHA-256: ab12cd34...
```

---

## Source Format vs. Compiled Format

`atakit-workload.toml` and `manifest.json` serve different audiences and different lifecycle stages.

| | `atakit-workload.toml` (source) | `manifest.json` (compiled) |
|---|---|---|
| **Format** | TOML | RFC 8785 canonical JSON |
| **Authored by** | Developer | `atakit workload build` |
| **Read by** | Developer, `atakit` CLI | Runtime (portal) |
| **Lives in** | Git repo | `.atawl` archive |
| **Image refs** | Three forms: string, build table, file table | Resolved `name:tag` strings |
| **Data paths** | Logical absolute file lists in `[package]` under measured/unmeasured data roots | Not in manifest as raw source lists (integrity via `hashes` and top-level `unmeasured-data`) |
| **Data mounts** | Per-container booleans or path lists | Per-container normalized path arrays |
| **Build metadata** | Present (`build`, `containerfile`, `args`) | Stripped |
| **env-file** | External measured file references | Inlined into `config.environment` |
| **unmeasured-env-file** | Developer template plus runtime operator values | Ordered paths in `config.unmeasured-env-files`; measured names in top-level `unmeasured-env-files` |
| **Content hashes** | Not present | `hashes` with SHA-256 |
| **Optional fields** | Many fields optional, defaults implicit | All fields present, defaults explicit |
| **Deployment targets** | Not present (lives in operator `config.toml`) | Not present |

The relationship is analogous to source code and a compiled binary. The source is human-friendly and flexible; the compiled form is machine-friendly and deterministic.

### Field Mapping

| Source (`atakit-workload.toml`) | Manifest (`manifest.json`) |
|---|---|
| `format` | `meta.format` |
| `[workload] name` | `meta.name` |
| `[workload] version` | `meta.version` |
| `[workload] base-image-mode` | `config.base-image-mode` |
| `[workload] base-image` | `config.base-image` |
| `[workload] image` (any form) | `config.image` (resolved `name:tag`) + tar under `images/` |
| `[workload] ports` | `config.ports` |
| `[workload] depends_on` | `config.depends_on` (always present; `[]` when omitted) |
| `[workload] restart` | `config.restart` |
| `[workload] command` | `config.command` |
| `[workload] entrypoint` | `config.entrypoint` |
| `[workload] atakit-portal` | `config.atakit-portal` |
| `[workload] gid-group` (optional, default: workload name) | `config.gid-group` (always present) |
| `[package] measured-data` (file list) | `hashes` entries under `measured-data/` |
| `[package] unmeasured-data` (file list) | top-level `unmeasured-data` array (paths only, no hashes; operator provides contents at deploy time) |
| `[workload] measured-data` (bool or path list) | `config.measured-data` (normalized path array) |
| `[workload] unmeasured-data` (bool or path list) | `config.unmeasured-data` (normalized path array) |
| `[workload] session-ttl` | `config.session-ttl` |
| `[workload.attributes]` | `config.attributes` (always present; `{}` when omitted in source) |
| `[workload] boot-disk-size` | `config.boot-disk-size` |
| `[workload] cap-add` | `config.cap-add` (always present; `[]` when omitted in source) |
| `[workload] cap-drop` | `config.cap-drop` (always present; `[]` when omitted in source) |
| `[workload.environment]` + `env-file` | `config.environment` (merged, inlined) |
| `[workload] unmeasured-env-file` | `config.unmeasured-env-files` |
| `[workload.storage.<label>]` | `config.storage.<label>` |
| `[dependencies.<name>]` | `config.dependencies.<name>` |
| `[firewall]` + `ports` | `config.firewall-ports` (resolved flat list) |
| `[baby-container]` | `config.baby-container.enabled`, `config.baby-container.max_instances`, `config.baby-container.slots` |
| `[baby-container.slots.<name>]` | `config.baby-container.slots.<name>` |
| `[disks.<name>]` | `disks.<name>` |
| (deployment targets) | *(not in workload config or manifest; lives in operator config.toml)* |
| *(no source field)* | `images.<service>` -- archive path + image-id, auto-extracted at build time from the staged image tar. |

### Changes from Earlier Formats

Format 8 is the current version. Earlier formats are not accepted anywhere. Rebuild an old archive; it cannot be converted.

Key changes from format 7:

| Format 7 | Format 8 |
|---|---|
| The main workload has no `config.depends_on` field | `config.depends_on` is required and always materialized, including `[]` |
| Only dependencies take part in dependency ordering | The main workload and dependencies form one validated startup graph |
| A dependency cannot name the main workload | A dependency can name `meta.name`; cycles, including cycles through the main workload, are rejected |

Key changes from format 6:

| Format 6 | Format 7 |
|---|---|
| Identity is `name:version`; a manifest records no publisher | `meta.publisher` is always present and measured by PCR23 |
| The workload identifier derives from name and version | The identifier derives from publisher, name, and version, so it cannot be computed from an older manifest |
| A reader for older archives was retained for local inspection | Removed: converting an older archive would mean inventing a publisher and measuring it |

Key changes from format 5:

| Format 5 | Format 6 |
|---|---|
| No workload attribute policy in the manifest | `config.attributes` is always present and measured by PCR23 |
| Portal accepts format 5 only | Portal accepts format 6 only |

Key changes from format 4:

| Format 4 | Format 5 |
|---|---|
| Unmeasured env files commit only to their paths | Top-level `unmeasured-env-files` also commits to the allowed variable names for each file |
| Portal passes operator files to Podman with `--env-file` | Portal parses, checks, merges, and passes explicit values only |
| Selected unmeasured files are individual bind mounts | One per-service copied/reflinked view is mounted with `readonly,noexec,nosuid,nodev` |
| Portal accepts formats 2, 3, and 4 | Portal accepts format 5 only |

Key changes from format 3:

| Format 3 | Format 4 |
|---|---|
| `config.measured-data` / `config.unmeasured-data` booleans | normalized path arrays |
| `meta.format = 3` | `meta.format = 4` |

Key changes from format 2:

| Format 2 | Format 3 |
|---|---|
| No per-service runtime env-file field | `unmeasured-env-files` is emitted for workload and dependencies, always present and defaulting to `[]` |
| `config.disks` per-service whole-disk mount maps | `config.storage` per-service mount objects with `disk`, `base_path`, `mount_path`, and `read_only` |
| `meta.format = 2` | `meta.format = 3` |

Key changes from format 1 to format 2:

| Format 1 | Format 2 |
|---|---|
| `manifest.toml` (TOML) | `manifest.json` (RFC 8785 canonical JSON) |
| `cvm_agent` (bool) | `atakit-portal` (bool) |
| Socket path `/app/cvm-agent.sock` | `/run/atakit-portal.sock` |
| `disks.*.encryption = { enable, key_security }` | `disks.*.encryption = { unlock_method, bind }` (unified schema) |
| `config.signing` present | Removed entirely |
| No `gid-group` field | `gid-group` always present (defaults to workload name) |
| `measured-data` / `unmeasured-data` as path arrays | `measured-data` / `unmeasured-data` as booleans (file lists moved to `[package]` in source TOML) |
| Optional fields omitted from output | All fields always present |
| No per-service image identity | `images.<service>.image-id` always present; runtime runs containers by image-id, not by tag |
