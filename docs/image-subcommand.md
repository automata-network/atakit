# Image Subcommand Design

## Overview

The `image` subcommand manages CVM (Confidential Virtual Machine) base images from GitHub Releases. It provides three public commands: `ls`, `pull`, and `rm`.

## CLI Interface

```
atakit image ls [--limit N] [--all] [--tag REF] [--repo NAME] [--remote]
atakit image pull [IMAGE] [PLATFORMS]
atakit image rm <IMAGE>
```

### `image ls`

List available CVM base image releases.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | 10 | Maximum releases to show |
| `--all` | false | Show all releases (not just those with disk images) |
| `--tag REF` | - | Show a specific release by tag (e.g. `automata-linux:v0.5.0`) |
| `--repo NAME` | `automata-linux` | Repository name |
| `--remote` | false | Query remote releases (GitHub API). Default is local-only. |

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

## Types

### ImageRef

Reference to a specific image: `repository:tag` (e.g. `automata-linux:v0.5.0`).

### Platform

Target cloud platform: `Gcp`, `Aws`, `Azure`.

### AssetKind

Classification of a release asset by filename:
- `DiskImage(Platform)` -- disk image for a platform
- `SecureBootCerts` -- secure-boot certificate bundle
- `Unknown` -- unrecognised asset

### Release / Asset

GitHub release metadata and individual asset metadata, deserialized from the API.

### VersionSelector

Specifies which release version to resolve:
- `Latest` -- GitHub "latest" release
- `LatestImage` -- most recent release containing any disk image
- `LatestImageFor(Platform)` -- most recent release with image for a specific platform
- `Tag(ImageRef)` -- specific release by tag

## API Surface

### ReleasesClient

```rust
impl ReleasesClient {
    fn new() -> Self;
    fn with_token(self, token: impl Into<String>) -> Self;
    fn with_token_from_env(self) -> Self;

    // Low-level
    async fn list_releases(&self, repo: &str, per_page: u32) -> Result<Vec<Release>>;
    async fn get_release(&self, image_ref: &ImageRef) -> Result<Release>;
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
    fn image_path(&self, image_ref: &ImageRef, platform: Platform) -> PathBuf;
    fn certs_dir(&self, image_ref: &ImageRef) -> PathBuf;

    // List (local ops need no client)
    fn list_local(&self) -> Result<Vec<ImageRef>>;
    async fn list(&self, client: &ReleasesClient, repo: &str, per_page: u32) -> Result<Vec<ReleaseStatus>>;

    // Download (client passed as parameter)
    async fn download(&self, client: &ReleasesClient, image_ref: &ImageRef, platforms: &[Platform], progress: &dyn ProgressReporter) -> Result<Vec<PathBuf>>;

    // Delete (local op)
    async fn delete(&self, image_ref: &ImageRef) -> Result<()>;
}
```

### Download (free functions)

```rust
async fn download_asset(client: &ReleasesClient, asset: &Asset, opts: &DownloadOptions, progress: &dyn ProgressReporter) -> Result<PathBuf>;
```

## Data Flow

### `image ls` (default, local-only)
```
CLI -> ImageStore::list_local() -> scan filesystem -> format & print
```

### `image ls --remote` / `image ls --all`
```
CLI -> ImageStore::list(client, ...) -> ReleasesClient::list_image_releases() -> annotate with local status -> format & print
```

### `image pull`
```
CLI -> ReleasesClient::resolve() -> ImageStore::download(client, ...) -> download_asset() -> decompress -> print paths
```

### `image rm`
```
CLI -> ImageStore::delete() -> remove_dir_all -> print confirmation
```

## Local Storage Layout

```
~/.local/share/atakit/images/        # default ($XDG_DATA_HOME/atakit/images)
  <repository>/
    <tag>/
      gcp_disk.tar.gz
      aws_disk.vmdk
      azure_disk.vhd
      secure_boot/
        PK.crt
        KEK.crt
        db.crt
        kernel.crt
```

Override with `ATAKIT_DATA_DIR` or `XDG_DATA_HOME`.
