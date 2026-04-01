# Image Subcommand Design

## Overview

The `image` subcommand manages CVM (Confidential Virtual Machine) base images from GitHub Releases. It provides five public commands: `ls`, `pull`, `rm`, `export`, and `import`.

## CLI Interface

```
atakit image ls [--limit N] [--all] [--tag REF] [--repo OWNER/REPO] [--remote]
atakit image pull [IMAGE] [PLATFORMS]
atakit image rm <IMAGE>
atakit image export <IMAGE> [-o DIR] [--gz]
atakit image import <ARCHIVE> [--force]
```

### `image ls`

List available CVM base image releases.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | 10 | Maximum releases to show |
| `--all` | false | Show all releases (not just those with disk images) |
| `--tag REF` | - | Show a specific release by tag (e.g. `automata-linux:v0.5.0`) |
| `--repo OWNER/REPO` | - | GitHub repository in `owner/repo` format. If omitted, queries all configured repositories. |
| `--remote` | false | Query remote releases (GitHub API). Default is local-only. |

Default mode (no `--remote` or `--all`) scans the local filesystem only. When multiple repositories are configured, `--remote` queries all of them and groups output by repository name.

### `image pull`

Pull CVM base images for a specific release.

| Argument | Required | Description |
|----------|----------|-------------|
| `IMAGE` | no | Release tag (e.g. `automata-linux:v0.5.0`). If omitted, uses latest. |
| `PLATFORMS` | no | Comma-separated platforms: `gcp,aws,azure`. If omitted, pulls all. |

### `image rm`

Remove locally downloaded CVM base images.

| Argument | Required | Description |
|----------|----------|-------------|
| `IMAGE` | yes | Release tag to remove (e.g. `automata-linux:v0.5.0`) |

### `image export`

Export an image from the local store as a portable `.atabi` archive.

| Argument/Flag | Required | Description |
|---------------|----------|-------------|
| `IMAGE` | yes | Image reference to export (e.g. `automata-linux:v0.1.6`) |
| `-o DIR` | no | Output directory (default: current directory) |
| `--gz` | no | Use gzip compression instead of zstd |

Exports all locally available platforms for the given image. The archive is named `{repository}-{tag}-{platforms}.atabi` (e.g. `automata-linux-v0.1.6-gcp.atabi`, `automata-linux-v0.1.6-all.atabi`).

### `image import`

Import a `.atabi` archive into the image store.

| Argument/Flag | Required | Description |
|---------------|----------|-------------|
| `ARCHIVE` | yes | Path to `.atabi` archive file |
| `--force` | no | Overwrite existing files in the store |

## Types

### ImageRef

Reference to a specific image: `repository:tag` (e.g. `automata-linux:v0.5.0`). The `repository` part must not contain `/` (this is the local store name, not the GitHub owner/repo path).

### Platform

Target cloud platform: `Gcp`, `Aws`, `Azure`.

### AssetKind

Classification of a release asset by filename:
- `ImageArchive(Vec<Platform>)` -- `.atabi` archive containing images for listed platforms
- `Unknown` -- unrecognised asset

Filenames are parsed as `{repo}-{tag}-{suffix}.atabi` where suffix is `all` or dash-joined platform names (e.g. `gcp`, `aws-azure`).

### Release / Asset

GitHub release metadata and individual asset metadata, deserialized from the API. Key methods: `has_archives()`, `archives()`, `archive_for_platform(platform)`, `available_platforms()`.

### VersionSelector

Specifies which release version to resolve:
- `Latest` -- GitHub "latest" release
- `LatestImage` -- most recent release containing any `.atabi` archive
- `LatestImageFor(Platform)` -- most recent release with archive for a specific platform
- `Tag(ImageRef)` -- specific release by tag

## API Surface

### ReleasesClient

All methods take the full GitHub `owner/repo` path as the `repo` parameter.

```rust
impl ReleasesClient {
    fn new() -> Self;
    fn with_token(self, token: impl Into<String>) -> Self;
    fn with_token_from_env(self) -> Self;

    // Low-level
    async fn list_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>>;
    async fn get_release(&self, repo: &str, tag: &str) -> Result<Release>;
    async fn get_latest_release(&self, repo: &str) -> Result<Release>;

    // High-level
    async fn resolve(&self, repo: &str, selector: &VersionSelector) -> Result<Release>;
    async fn list_image_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>>;
    async fn find_latest_image_release(&self, repo: &str) -> Result<Release>;
    async fn find_latest_release_for(&self, repo: &str, platform: Platform) -> Result<Release>;
}
```

### ImageStore

```rust
impl ImageStore {
    fn new(base_dir: impl Into<PathBuf>) -> Self;

    // Paths
    fn base_dir(&self) -> &Path;
    fn tag_dir(&self, image_ref: &ImageRef) -> PathBuf;
    fn disk_images_dir(&self, image_ref: &ImageRef) -> PathBuf;
    fn image_path(&self, image_ref: &ImageRef, platform: Platform) -> PathBuf;
    fn certs_dir(&self, image_ref: &ImageRef) -> PathBuf;

    // Query
    fn local_platforms(&self, image_ref: &ImageRef) -> Vec<Platform>;
    fn has_certs(&self, image_ref: &ImageRef) -> bool;
    fn exists(&self, image_ref: &ImageRef) -> bool;

    // List (local ops need no client)
    fn list_local(&self) -> Result<Vec<ImageRef>>;
    async fn list(
        &self,
        client: &ReleasesClient,
        github_repo: &str,
        local_name: &str,
        per_page: u32,
    ) -> Result<Vec<ReleaseStatus>>;

    // Download (client passed as parameter)
    async fn download(
        &self,
        client: &ReleasesClient,
        github_repo: &str,
        image_ref: &ImageRef,
        platforms: &[Platform],
        progress: &dyn ProgressReporter,
    ) -> Result<Vec<PathBuf>>;

    // Delete (local ops)
    async fn delete(&self, image_ref: &ImageRef) -> Result<()>;
    async fn delete_platform(&self, image_ref: &ImageRef, platform: Platform) -> Result<()>;
}
```

Note: `list()` and `download()` take both `github_repo` (full `owner/repo` for API calls) and either `local_name` or `image_ref` (plain repository name for local store lookups). The `repo_local_name()` helper in `atakit-cli/src/config.rs` extracts the local name from an `owner/repo` string.

### Download (free functions)

```rust
async fn download_asset(client: &ReleasesClient, asset: &Asset, opts: &DownloadOptions, progress: &dyn ProgressReporter) -> Result<PathBuf>;
```

### Archive (free functions)

```rust
fn create_image_archive(
    tag_dir: &Path,
    image_ref: &ImageRef,
    platforms: &[Platform],
    output_dir: &Path,
    progress: &dyn ProgressReporter,
    compression: ArchiveCompression,
) -> Result<PathBuf>;

fn import_image_archive(archive_path: &Path, store_base_dir: &Path) -> Result<ImageRef>;
fn read_manifest(archive_path: &Path) -> Result<ImageManifest>;
```

## Data Flow

### `image ls` (default, local-only)
```
CLI -> ImageStore::list_local() -> scan filesystem -> group by repository -> format & print
```

### `image ls --remote`
```
CLI -> for each configured repo:
         ImageStore::list(client, github_repo, local_name, ...) ->
           ReleasesClient::list_image_releases() -> annotate with local status
       -> merge with local-only images not in remote -> group by repository -> format & print
```

### `image ls --all`
```
CLI -> for each configured repo:
         ReleasesClient::list_releases() -> annotate with local status
       -> merge with local-only images -> group by repository -> format & print
```

### `image pull`
```
CLI -> ReleasesClient::resolve() -> ImageStore::download(client, github_repo, ...) -> download .atabi -> import_image_archive() -> print paths
```

### `image rm`
```
CLI -> ImageStore::delete() -> remove_dir_all -> print confirmation
```

### `image export`
```
CLI -> ImageStore::local_platforms() -> create_image_archive(tag_dir, image_ref, platforms, output_dir, progress, compression) -> print path
```

### `image import`
```
CLI -> import_image_archive(archive_path, store_base_dir) -> print imported ImageRef
```

## Local Storage Layout

```
~/.local/share/atakit/images/        # default ($XDG_DATA_HOME/atakit/images)
  <repository>/
    <tag>/
      disk_images/
        gcp_disk.tar.gz
        aws_disk.vmdk
        azure_disk.vhd.zst           # compressed on import
      secure_boot_certs/
        PK.crt
        KEK.crt
        db.crt
        kernel.crt
```

Override with `ATAKIT_DATA_DIR` or `XDG_DATA_HOME`.

Note: Azure VHD files are stored compressed as `azure_disk.vhd.zst`. The `.atabi` archive contains the uncompressed `azure_disk.vhd`; `import_image_archive()` compresses it to zstd after extraction. Azure deploy decompresses to a temp file before upload.

## Configuration

Image repositories are configured in `config.toml` under `[image]`:

```toml
[image]
# Single repository (string)
repository = "automata-network/automata-linux"

# Or multiple repositories (array)
repositories = ["automata-network/automata-linux", "automata-network/debug-linux"]
```

Both `repository` (singular) and `repositories` (plural) are accepted. The first entry is the default for `image pull`. The `--repo` CLI flag overrides with a single repository.

`repo_local_name(repo)` in `atakit-cli/src/config.rs` extracts the local store name from an `owner/repo` string (e.g. `"automata-network/debug-linux"` -> `"debug-linux"`). This is used for local store directory names and `ImageRef` construction.
