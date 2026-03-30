# `.atabi` Archive Format Specification

A `.atabi` file is a portable package for CVM base images. It bundles the disk images for one or more cloud platforms along with secure boot certificates into a single file that can be imported into the local image store. The file is a tar.zst (tar + zstandard) with a custom extension - inspectable with standard tools (`tar --zstd -tf`). Legacy tar.gz archives are also supported for reading.

## Design Principles

1. **Portable.** A single `.atabi` file contains everything needed to deploy a base image on any supported platform. No GitHub API calls or network access required for import.
2. **Store-aligned.** The archive layout mirrors the image store directory structure. Import is a direct extraction.
3. **Multi-platform.** One archive can contain disk images for GCP, AWS, and Azure. Only platforms present locally are included.
4. **Inspectable.** A TOML manifest at the root describes the contents without extracting the full archive.

---

## Archive Layout

```
automata-linux/
  manifest.toml
  disk_images/
    gcp_disk.tar.gz
    aws_disk.vmdk
    azure_disk.vhd
  secure_boot_certs/
    PK.crt
    KEK.crt
    db.crt
    kernel.crt
```

The top-level directory is the repository name. This matches the image store layout under `<store_base>/<repository>/<tag>/`.

| Path | Contents |
|---|---|
| `manifest.toml` | Archive metadata: name, version, included platforms |
| `disk_images/` | Platform-specific disk image files |
| `secure_boot_certs/` | Secure boot certificate files (optional) |

### Naming Convention

Archive files are named `{repository}-{tag}.atabi`. Examples:

- `automata-linux-v0.1.6.atabi`
- `automata-linux-v0.5.0-debug.atabi`

---

## Manifest

The manifest is a TOML file at `<repository>/manifest.toml` inside the archive.

### Full Example

```toml
[meta]
format = 1
name = "automata-linux"
version = "v0.1.6"
platforms = ["gcp", "aws", "azure"]
```

### Minimal Example

```toml
[meta]
format = 1
name = "automata-linux"
version = "v0.1.6"
platforms = ["gcp"]
```

### Schema Reference

#### `[meta]` - Archive Metadata

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Schema version. Current: `1`. |
| `name` | string | yes | Repository name (e.g. `automata-linux`). |
| `version` | string | yes | Release tag (e.g. `v0.1.6`). |
| `platforms` | array of strings | yes | Platforms with disk images in this archive. Values: `gcp`, `aws`, `azure`. |

---

## Disk Image Files

Each platform has a fixed filename:

| Platform | Filename | Format |
|---|---|---|
| GCP | `gcp_disk.tar.gz` | Compressed raw disk |
| AWS | `aws_disk.vmdk` | VMDK disk image |
| Azure | `azure_disk.vhd` | VHD disk image |

Only platforms listed in `manifest.toml`'s `platforms` field have corresponding files in `disk_images/`. The `platforms` field reflects what is actually present in the archive.

---

## Secure Boot Certificates

The `secure_boot_certs/` directory is optional. When present, it contains DER/PEM certificate files used for UEFI Secure Boot on the target platform. The exact filenames depend on the release but typically include:

- `PK.crt` - Platform Key
- `KEK.crt` - Key Exchange Key
- `db.crt` - Signature Database
- `kernel.crt` - Kernel signing certificate

---

## Relationship to Image Store

The image store organizes files under `<base_dir>/<repository>/<tag>/`:

```
~/.local/share/atakit/images/
  automata-linux/
    v0.1.6/
      disk_images/
        gcp_disk.tar.gz
      secure_boot_certs/
        PK.crt
        KEK.crt
```

### Export

`atakit image export automata-linux:v0.1.6` reads the store entry and creates:

```
automata-linux-v0.1.6.atabi (tar.zst)
  automata-linux/
    manifest.toml          <-- generated from store contents
    disk_images/            <-- copied from store
      gcp_disk.tar.gz
    secure_boot_certs/      <-- copied from store (if present)
      PK.crt
      KEK.crt
```

### Import

`atakit image import automata-linux-v0.1.6.atabi` extracts into the store:

1. Read `manifest.toml` from the archive to get `name` and `version`.
2. Extract `disk_images/` to `<store>/<name>/<version>/disk_images/`.
3. Extract `secure_boot_certs/` to `<store>/<name>/<version>/secure_boot_certs/` (if present).
4. The `manifest.toml` itself is not stored - it is only used during import.

---

## Cloud Deploy Integration

`atakit cloud deploy --image <ref>` resolves the base image through the image store:

| `--image` value | Behavior |
|---|---|
| `automata-linux:v0.1.6` | Look up in image store. Pick platform-appropriate disk image based on target. Upload to cloud, register. GCE image name derived from sanitized ref. |
| `/path/to/image.atabi` | Import into store first, then resolve as above. |
| `my-existing-gce-image` | Assume already registered in cloud provider. Skip upload. |

The target's platform determines which disk image file is selected from the store:

- Target `platform = "gcp"` selects `disk_images/gcp_disk.tar.gz`
- Target `platform = "azure"` selects `disk_images/azure_disk.vhd`

---

## Deterministic Archives

Archives are created with deterministic metadata for reproducibility:

- All tar entries have `mtime = 0`, `uid = 0`, `gid = 0`
- Directory permissions: `0755`, file permissions: `0644`
- Entries are sorted: files before directories, alphabetical within each group
- `manifest.toml` appears first (before `disk_images/` and `secure_boot_certs/`)
- Zstd compression (default); `--gz` flag produces gzip for backwards compatibility
