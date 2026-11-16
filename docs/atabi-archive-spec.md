# `.atabi` Archive Format Specification

A `.atabi` file is a portable package for CVM base images. It bundles the disk images for one or more cloud platforms along with secure boot certificates into a single file that can be imported into the local image store. The file is a tar.zst (tar + zstandard) with a custom extension - inspectable with standard tools (`tar --zstd -tf`). Legacy tar.gz archives are also supported for reading.

`.atabi` archives do not carry the canonical verifier measurement policy for
TLS attestation. Measurements are distributed as standalone signed measurement
packs so they can be updated independently of disk-image archives. See
[measurement-pack-spec.md](measurement-pack-spec.md).

## Design Principles

1. **Portable.** A single `.atabi` file contains everything needed to deploy a base image on any supported platform. No GitHub API calls or network access required for import.
2. **Store-aligned.** The archive layout mirrors the image store directory structure. Import is a direct extraction.
3. **Multi-platform.** One archive can contain disk images for GCP, AWS, Azure, and QEMU. Only platforms present locally are included.
4. **Inspectable.** A TOML manifest at the root describes the contents without extracting the full archive.

---

## Archive Layout

```
automata-linux/
  manifest.toml
  baseimage.toml
  disk_images/
    gcp_disk.tar.gz
    aws_disk.vmdk
    azure_disk.vhd.zst
    qemu_disk.qcow2
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
| `baseimage.toml` | Format 2 base-image runtime configuration and attribute source |
| `disk_images/` | Platform-specific disk image files |
| `secure_boot_certs/` | Secure boot certificate files (optional) |

### Naming Convention

Archive files are named `{repository}-{tag}-{platforms}.atabi` where `{platforms}` is `all` (when all platforms are included) or dash-joined platform names sorted alphabetically. Examples:

- `automata-linux-v0.2.6-debug-all.atabi` -- contains all four platforms
- `automata-linux-v0.2.6-debug-gcp.atabi` -- contains only GCP
- `automata-linux-v0.2.6-debug-aws-azure.atabi` -- contains AWS and Azure

---

## Manifest

The manifest is a TOML file at `<repository>/manifest.toml` inside the archive.

### Full Example

```toml
[meta]
format = 2
name = "automata-linux"
version = "v0.2.6-debug"
platforms = ["gcp", "aws", "azure", "qemu"]
```

### Minimal Example

```toml
[meta]
format = 2
name = "automata-linux"
version = "v0.2.6-debug"
platforms = ["gcp"]
```

### Schema Reference

#### `[meta]` - Archive Metadata

| Field | Type | Required | Description |
|---|---|---|---|
| `format` | integer | yes | Schema version. Current: `2`. Format 1 archives must be rebuilt. |
| `name` | string | yes | Repository name (e.g. `automata-linux`). |
| `version` | string | yes | Release tag (e.g. `v0.2.6-debug`). |
| `platforms` | array of strings | yes | Platforms with disk images in this archive. Values: `gcp`, `aws`, `azure`, `qemu`. |

---

## Disk Image Files

Each platform has a fixed filename:

| Platform | Filename (in archive) | Filename (in store) | Format |
|---|---|---|---|
| GCP | `gcp_disk.tar.gz` | `gcp_disk.tar.gz` | Compressed raw disk |
| AWS | `aws_disk.vmdk` | `aws_disk.vmdk` | VMDK disk image |
| Azure | `azure_disk.vhd.zst` | `azure_disk.vhd.zst` | Zstandard-compressed VHD disk image |
| QEMU | `qemu_disk.qcow2` | `qemu_disk.qcow2` | QCOW2 disk image |

Only platforms listed in `manifest.toml`'s `platforms` field have corresponding files in `disk_images/`. The `platforms` field reflects what is actually present in the archive.

The archive copies the selected files from the local store without changing their inner representation. Azure deploy decompresses `azure_disk.vhd.zst` to a temporary VHD before upload.

> **Known producer nonconformance:** the current `atakit-imgbuild build` path
> stages `output/images/azure_disk.vhd` without compressing or renaming it before
> archive creation. The shared `ImageStore` discovers Azure only as
> `azure_disk.vhd.zst`, so an Azure archive made by that path is not usable after
> import. Release archives and `atakit image export` must follow the
> `azure_disk.vhd.zst` contract above until the producer is fixed.

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
    v0.2.6-debug/
      baseimage.toml
      disk_images/
        gcp_disk.tar.gz
        azure_disk.vhd.zst
      secure_boot_certs/
        PK.crt
        KEK.crt
```

### Export

`atakit image export automata-linux:v0.2.6-debug` reads the store entry and creates:

```
automata-linux-v0.2.6-debug-gcp.atabi (tar.zst)
  automata-linux/
    manifest.toml          <-- generated from store contents
    baseimage.toml         <-- copied from the image build
    disk_images/            <-- copied from store
      gcp_disk.tar.gz
    secure_boot_certs/      <-- copied from store (if present)
      PK.crt
      KEK.crt
```

### Import

`atakit image import automata-linux-v0.2.6-debug-gcp.atabi` extracts into the store:

1. Read `manifest.toml` from the archive to get `name`, `version`, and format.
2. Require archive format 2 and a root-level `baseimage.toml`.
3. Extract `baseimage.toml` to `<store>/<name>/<version>/baseimage.toml`.
4. Extract `disk_images/` to `<store>/<name>/<version>/disk_images/`.
5. Extract `secure_boot_certs/` to `<store>/<name>/<version>/secure_boot_certs/` (if present).
6. The `manifest.toml` itself is not stored - it is only used during import.

---

## Cloud Deploy Integration

`atakit cloud deploy --image <ref>` resolves the base image through the image store:

| `--image` value | Behavior |
|---|---|
| `automata-linux:v0.2.6-debug` | Look up in image store. Pick the target platform's disk image. Cloud targets upload/register it; QEMU runs its local QCOW2 copy. |
| `/path/to/image.atabi` | Import into store first, then resolve as above. |
| `my-existing-gce-image` | Assume already registered in cloud provider. Skip upload. |

The target's platform determines which disk image file is selected from the store:

- Target `platform = "gcp"` selects `disk_images/gcp_disk.tar.gz`
- Target `platform = "aws"` selects `disk_images/aws_disk.vmdk`
- Target `platform = "azure"` selects `disk_images/azure_disk.vhd.zst` from the local store (decompressed to temp file before upload)
- Target `platform = "qemu"` selects `disk_images/qemu_disk.qcow2`

---

## Deterministic Archives

Archives are created with deterministic metadata for reproducibility:

- All tar entries have `mtime = 0`, `uid = 0`, `gid = 0`
- Directory permissions: `0755`, file permissions: `0644`
- Entries are sorted: files before directories, alphabetical within each group
- `manifest.toml` appears first. `baseimage.toml`, `disk_images/`, and
  `secure_boot_certs/` follow in deterministic path order.
- Zstd compression (default); `--gz` flag produces gzip for backwards compatibility
