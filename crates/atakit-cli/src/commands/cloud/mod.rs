pub mod deploy;
pub mod destroy;
pub mod image;
pub mod init;
pub mod list;
pub mod provider;
pub mod serial;
pub mod ssh;
pub mod status;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cloud_images::{CloudImage, CloudImages};
use atakit_cloud::config::CloudProviderConfig;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::plan::DeployStep;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::{
    AzureResourceNames, CloudTarget, PersistedInitEnv, PlatformKind, ProcessRunner,
};
use atakit_core::Env;
use atakit_image::{import_image_archive, ImageRef, ImageStore, Platform as ImagePlatform};
use atakit_workload::WorkloadStore;

/// Resolve init env references with precedence: CLI > target config.
pub struct InitEnvResolver<'a> {
    pub cli_chain: Option<&'a str>,
    pub cli_owner_key: Option<&'a str>,
    pub cli_gas_wallet: Option<&'a str>,
    pub target: &'a CloudTarget,
}

impl<'a> InitEnvResolver<'a> {
    pub fn chain(&self) -> String {
        self.cli_chain
            .map(String::from)
            .or_else(|| self.target.chain.clone())
            .expect("chain must be set on target or via --chain")
    }

    pub fn owner_key(&self) -> String {
        self.cli_owner_key
            .map(String::from)
            .or_else(|| self.target.owner_key.clone())
            .expect("owner_key must be set on target or via --owner-key")
    }

    pub fn gas_wallet(&self) -> String {
        self.cli_gas_wallet
            .map(String::from)
            .or_else(|| self.target.gas_wallet.clone())
            .expect("gas_wallet must be set on target or via --gas-wallet")
    }

    pub fn build(&self) -> PersistedInitEnv {
        PersistedInitEnv {
            chain: self.chain(),
            owner_key: self.owner_key(),
            gas_wallet: self.gas_wallet(),
        }
    }
}

/// Parse instance reference: "target/instance" or just "instance".
pub fn parse_instance_ref(s: &str) -> (Option<&str>, &str) {
    if let Some((target, instance)) = s.split_once('/') {
        (Some(target), instance)
    } else {
        (None, s)
    }
}

/// Resolve an instance reference to (target_name, instance_name) using the state store.
pub fn resolve_instance(
    data_dir: &std::path::Path,
    instance: &str,
    target_filter: Option<&str>,
) -> Result<(String, String)> {
    let (embedded_target, instance_name) = parse_instance_ref(instance);
    let target = target_filter.or(embedded_target);
    atakit_cloud::state::find_instance(data_dir, instance_name, target)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Resolved base image: display name for the plan + optional local file path.
pub(super) struct ResolvedImage {
    /// Human-readable name (image ref or GCE image name).
    pub display_name: String,
    /// Local disk image file path for upload. `None` means the image is
    /// assumed to already exist in GCE.
    pub source_path: Option<String>,
    /// Local secure-boot cert directory from the image store, if available.
    pub certs_dir: Option<String>,
}

/// Resolve the `--image` argument into a display name and optional source path.
///
/// Three cases:
/// 1. Ends with `.atabi` - import into store, then resolve from store.
/// 2. Contains `:` (ImageRef) - look up in ImageStore for the target
///    platform's disk image. If found locally, use as source_path.
///    If not found, treat as existing GCE image name.
/// 3. Otherwise - bare GCE image name, no upload needed.
pub(super) fn resolve_image(
    image_arg: &str,
    platform: &PlatformKind,
    env: &Env,
) -> Result<ResolvedImage> {
    let store = ImageStore::new(&env.image_dir);

    if image_arg.ends_with(".atabi") {
        // Import .atabi archive, then resolve from store.
        let archive_path = PathBuf::from(image_arg);
        if !archive_path.exists() {
            bail!("archive not found: {image_arg}");
        }
        let image_ref = import_image_archive(&archive_path, store.base_dir())
            .with_context(|| format!("failed to import {image_arg}"))?;
        eprintln!("  Imported {} from .atabi archive", image_ref);
        return resolve_store_image(&store, &image_ref, platform);
    }

    if image_arg.contains(':') {
        // Parse as ImageRef (repository:tag).
        let image_ref: ImageRef = image_arg
            .parse()
            .with_context(|| format!("invalid image reference: {image_arg}"))?;
        if store.exists(&image_ref) {
            return resolve_store_image(&store, &image_ref, platform);
        }
        bail!(
            "image {} not found in store (run 'atakit image pull {}' first, \
             or 'atakit image ls --remote' to check available releases)",
            image_ref,
            image_ref,
        );
    }

    // Bare name - existing GCE image.
    Ok(ResolvedImage {
        display_name: image_arg.to_string(),
        source_path: None,
        certs_dir: None,
    })
}

/// Look up a disk image file in the store for the target platform.
fn resolve_store_image(
    store: &ImageStore,
    image_ref: &ImageRef,
    platform: &PlatformKind,
) -> Result<ResolvedImage> {
    let image_platform = match platform {
        PlatformKind::Gcp => ImagePlatform::Gcp,
        PlatformKind::Azure => ImagePlatform::Azure,
        PlatformKind::Aws => ImagePlatform::Aws,
    };

    let disk_path = store.image_path(image_ref, image_platform);
    if !disk_path.exists() {
        let available = store.local_platforms(image_ref);
        let names: Vec<_> = available.iter().map(|p| p.to_string()).collect();
        bail!(
            "no {} disk image for {} in store (available: {})",
            image_platform,
            image_ref,
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            },
        );
    }

    Ok(ResolvedImage {
        display_name: image_ref.to_string(),
        source_path: Some(disk_path.display().to_string()),
        certs_dir: Some(store.certs_dir(image_ref).display().to_string()),
    })
}

/// Resolved workload source: archive path + name/version + declared ports + disks.
pub(crate) struct ResolvedWorkload {
    pub archive_path: PathBuf,
    pub name: String,
    pub version: String,
    pub ports: Vec<String>,
    /// Disk name -> (index, size string e.g. "10GB", declared unlock_method).
    /// The unlock_method list is carried so deploy/init can validate
    /// `--disk-passphrase` against what each disk actually requires.
    pub disks: BTreeMap<String, (u32, String, Vec<String>)>,
    /// Minimum boot/OS disk size (e.g. "50GB"). None = cloud default.
    pub boot_disk_size: Option<String>,
    /// Base image access control mode: "any", "whitelist", or "blacklist".
    pub base_image_mode: String,
    /// Base image references for whitelist/blacklist filtering.
    pub base_image: Vec<String>,
    /// Declared unmeasured-data file paths from the manifest, as deploy-relative
    /// paths (the `unmeasured-data/` prefix stripped). The operator must supply
    /// exactly this set at `/init`.
    pub unmeasured_data_paths: Vec<String>,
    /// Workload source directory (available in dir mode, None for store-ref/file modes).
    pub workload_dir: Option<PathBuf>,
}

/// Resolve workload from source arg, falling back to dir mode.
pub(crate) fn resolve_workload(
    source: &Option<String>,
    dir: &Option<PathBuf>,
    env: &Env,
    skip_freshness_check: bool,
) -> Result<ResolvedWorkload> {
    if let Some(ref src) = source {
        // Store reference: name:version
        if crate::commands::workload::looks_like_store_ref(src) {
            let (name, version) = src
                .split_once(':')
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap();
            let store = WorkloadStore::new(&env.workload_dir);
            let blob = store.blob_path(&name, &version)?;
            if !blob.exists() {
                bail!("no archive blob for {name}:{version} in store");
            }
            let inspect_opts = atakit_workload::InspectOptions {
                archive: Some(blob.clone()),
                workload_dir: None,
                engine: None,
                verbose: false,
            };
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(atakit_workload::inspect_workload(&inspect_opts))
            })
            .context("failed to inspect store archive")?;
            let disks = result
                .manifest
                .disks
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        (v.index, v.size.clone(), v.encryption.unlock_method.clone()),
                    )
                })
                .collect();
            let ports = collect_firewall_ports(&result.manifest);
            let unmeasured_paths = manifest_unmeasured_paths(&result.manifest);
            return Ok(ResolvedWorkload {
                archive_path: blob,
                name,
                version,
                ports,
                disks,
                boot_disk_size: result.manifest.config.boot_disk_size,
                base_image_mode: result.manifest.config.base_image_mode,
                base_image: result.manifest.config.base_image,
                unmeasured_data_paths: unmeasured_paths,
                workload_dir: None,
            });
        }

        // File path: something.atawl
        let path = PathBuf::from(src);
        if !path.exists() {
            bail!("archive not found: {src}");
        }
        let opts = atakit_workload::InspectOptions {
            archive: Some(path.clone()),
            workload_dir: None,
            engine: None,
            verbose: false,
        };
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(atakit_workload::inspect_workload(&opts))
        })
        .context("failed to inspect archive")?;
        let disks = result
            .manifest
            .disks
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (v.index, v.size.clone(), v.encryption.unlock_method.clone()),
                )
            })
            .collect();
        let ports = collect_firewall_ports(&result.manifest);
        let unmeasured_paths = manifest_unmeasured_paths(&result.manifest);
        return Ok(ResolvedWorkload {
            archive_path: path,
            name: result.manifest.meta.name,
            version: result.manifest.meta.version,
            ports,
            disks,
            boot_disk_size: result.manifest.config.boot_disk_size,
            base_image_mode: result.manifest.config.base_image_mode,
            base_image: result.manifest.config.base_image,
            unmeasured_data_paths: unmeasured_paths,
            workload_dir: None,
        });
    }

    // Dir mode: read atakit-workload.toml, find versioned archive.
    let workload_dir = dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    if !workload_dir.join("atakit-workload.toml").exists() {
        bail!(
            "no workload source specified and no atakit-workload.toml found in {}",
            workload_dir.display(),
        );
    }
    let archive_path = crate::commands::workload::find_versioned_archive(&workload_dir)?;

    // Check if any source file is newer than the archive.
    if !skip_freshness_check {
        if let Ok(archive_meta) = std::fs::metadata(&archive_path) {
            if let Ok(archive_mtime) = archive_meta.modified() {
                if let Some(stale_file) = find_newer_source(&workload_dir, &archive_mtime) {
                    bail!(
                        "'{}' is newer than {} - run 'atakit workload build' first, or pass --skip-freshness-check to skip this check",
                        stale_file.display(),
                        archive_path.display(),
                    );
                }
            }
        }
    }

    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(archive_path.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
    };
    let result = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(atakit_workload::inspect_workload(&inspect_opts))
    })
    .context("failed to inspect archive")?;
    let ports = collect_firewall_ports(&result.manifest);
    let disks = result
        .manifest
        .disks
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                (v.index, v.size.clone(), v.encryption.unlock_method.clone()),
            )
        })
        .collect();
    // The declared unmeasured-data set comes from the manifest (committed to
    // PCR23), not the source TOML, so every deploy mode resolves the same set.
    let unmeasured_paths = manifest_unmeasured_paths(&result.manifest);
    Ok(ResolvedWorkload {
        archive_path,
        name: result.manifest.meta.name,
        version: result.manifest.meta.version,
        ports,
        disks,
        boot_disk_size: result.manifest.config.boot_disk_size,
        base_image_mode: result.manifest.config.base_image_mode,
        base_image: result.manifest.config.base_image,
        unmeasured_data_paths: unmeasured_paths,
        workload_dir: Some(workload_dir),
    })
}

/// The declared unmeasured-data file paths from the manifest, as deploy-relative
/// paths (the `unmeasured-data/` prefix stripped). This is the authoritative set
/// the operator must supply at `/init`; reading it from the manifest (rather than
/// the source TOML) means it works for archive/store deploys, not just dir mode.
fn manifest_unmeasured_paths(m: &atakit_workload::manifest::Manifest) -> Vec<String> {
    m.unmeasured_data
        .iter()
        .map(|p| p.strip_prefix("unmeasured-data/").unwrap_or(p).to_string())
        .collect()
}

/// Walk a workload directory and return the first file newer than `threshold`.
/// Skips `.git`, `target`, and `.atawl` files. Only compares file mtimes,
/// not directory mtimes (directories update on unrelated changes like new files).
fn find_newer_source(
    dir: &std::path::Path,
    threshold: &std::time::SystemTime,
) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".git"
            || name_str == "target"
            || name_str == ".claude"
            || name_str == ".codex"
        {
            continue;
        }
        if name_str.ends_with(".atawl") {
            continue;
        }
        let path = entry.path();
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_dir() {
                if let Some(found) = find_newer_source(&path, threshold) {
                    return Some(found);
                }
            } else if let Ok(mtime) = meta.modified() {
                if mtime > *threshold {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Collect resolved firewall ports from a manifest as `"port/proto"` strings.
///
/// Uses the manifest's `firewall_ports` which is the authoritative resolved list:
/// auto-derived from container port mappings + firewall allow - deny.
fn collect_firewall_ports(m: &atakit_workload::manifest::Manifest) -> Vec<String> {
    m.config
        .firewall_ports
        .iter()
        .map(|fp| format!("{}/{}", fp.port, fp.protocol))
        .collect()
}

/// Validate that the given image ref is allowed by the workload's base-image policy.
pub(super) fn validate_base_image(
    image_display_name: &str,
    base_image_mode: &str,
    base_image: &[String],
) -> Result<()> {
    if base_image_mode == "any" {
        return Ok(());
    }

    // Every entry must parse as a valid ImageRef (repository:tag).
    for entry in base_image {
        if entry.parse::<ImageRef>().is_err() {
            bail!(
                "invalid base-image entry '{}': must be repository:tag format \
                 (e.g. 'automata-linux:v0.1.6')",
                entry,
            );
        }
    }

    match base_image_mode {
        "whitelist" => {
            // Empty whitelist = nothing allowed.
            if !base_image.iter().any(|b| b == image_display_name) {
                if base_image.is_empty() {
                    bail!(
                        "image '{}' rejected: base-image-mode is 'whitelist' but \
                         base-image list is empty (no images are allowed)",
                        image_display_name,
                    );
                }
                bail!(
                    "image '{}' is not in the workload's base-image whitelist: [{}]",
                    image_display_name,
                    base_image.join(", "),
                );
            }
        }
        "blacklist" => {
            if base_image.iter().any(|b| b == image_display_name) {
                bail!(
                    "image '{}' is blacklisted by the workload",
                    image_display_name,
                );
            }
        }
        other => {
            bail!(
                "invalid base-image-mode '{}': expected 'any', 'whitelist', or 'blacklist'",
                other,
            );
        }
    }
    Ok(())
}

/// Resolve the operator-supplied unmeasured-data into a tar.gz for `/init`,
/// given the manifest's declared path set.
///
/// Gated on the **declared path set** (not the per-container mount boolean),
/// because the portal verifies the uploaded set against the manifest's
/// `unmeasured-data` array unconditionally. When the manifest declares paths but
/// no `--unmeasured-data-dir` (and no workload source dir) is available, this is
/// a hard **error**, not a warning: the portal would reject `/init` for the
/// missing set, and failing here avoids provisioning a VM that can never init.
pub(crate) fn resolve_unmeasured_tar(
    declared_paths: &[String],
    unmeasured_data_dir: Option<&PathBuf>,
    workload_dir: Option<&PathBuf>,
) -> Result<Option<Vec<u8>>> {
    if declared_paths.is_empty() {
        return Ok(None);
    }
    let Some(dir) = unmeasured_data_dir.or(workload_dir) else {
        bail!(
            "workload declares {} unmeasured-data file(s) but no source directory is available; \
             pass --unmeasured-data-dir with the declared files (the portal requires exactly the \
             declared set at /init)",
            declared_paths.len(),
        );
    };
    collect_unmeasured_tar(declared_paths, dir)
}

/// Collect the operator-provided unmeasured-data files into a gzipped tar,
/// after verifying the directory contains *exactly* the set the manifest
/// declares.
///
/// `declared` are deploy-relative file paths (no `./` prefix, e.g.
/// `"secrets/api_key"`) — the manifest's `unmeasured-data` list with the
/// `unmeasured-data/` prefix stripped. `data_dir` is the operator's
/// `--unmeasured-data-dir`. Bails if any declared file is missing, or if the
/// directory holds files the manifest does not declare: the set is committed to
/// PCR23, so it must match exactly. Returns `None` only when nothing is declared.
pub(crate) fn collect_unmeasured_tar(
    declared: &[String],
    data_dir: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    if declared.is_empty() {
        return Ok(None);
    }

    let canon_base = data_dir
        .canonicalize()
        .with_context(|| format!("--unmeasured-data-dir not found: {}", data_dir.display()))?;

    // Enumerate what's actually present, then diff against the declared set.
    let mut actual: BTreeSet<String> = BTreeSet::new();
    enumerate_files(&canon_base, &canon_base, &mut actual)?;
    let declared_set: BTreeSet<String> = declared.iter().cloned().collect();

    let missing: Vec<&str> = declared_set
        .difference(&actual)
        .map(String::as_str)
        .collect();
    let extra: Vec<&str> = actual
        .difference(&declared_set)
        .map(String::as_str)
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        let mut msg = format!(
            "unmeasured-data in {} does not match the manifest's declared set",
            data_dir.display()
        );
        if !missing.is_empty() {
            msg.push_str(&format!(
                "\n  missing (declared in manifest, not found): {}",
                missing.join(", ")
            ));
        }
        if !extra.is_empty() {
            msg.push_str(&format!(
                "\n  extra (present but not declared in manifest): {}",
                extra.join(", ")
            ));
        }
        bail!(msg);
    }

    // Set matches: build the tar from exactly the declared files.
    let buf = Vec::new();
    let encoder = flate2::write::GzEncoder::new(buf, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    for rel_path in declared {
        let src = canon_base.join(rel_path);
        let metadata = std::fs::metadata(&src)
            .with_context(|| format!("read unmeasured-data file {rel_path}"))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_cksum();
        let file = std::fs::File::open(&src)?;
        tar.append_data(&mut header, rel_path, file)?;
    }

    let encoder = tar.into_inner()?;
    let bytes = encoder.finish()?;
    Ok(Some(bytes))
}

/// Recursively collect file paths under `dir`, relative to `base`, joined with
/// `/`. Symlinked files are resolved and verified to stay within `base`.
fn enumerate_files(
    dir: &std::path::Path,
    base: &std::path::Path,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            enumerate_files(&path, base, out)?;
        } else if path.is_file() {
            let canon = path.canonicalize()?;
            if !canon.starts_with(base) {
                bail!(
                    "unmeasured-data file resolves outside the data directory: {}",
                    path.display(),
                );
            }
            let rel = path
                .strip_prefix(base)
                .expect("path is under base")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.insert(rel);
        }
    }
    Ok(())
}

/// Build a `CloudImage` record for the given platform.
pub(super) fn build_cloud_image_record(
    provider_config: &CloudProviderConfig,
    image_ref: &str,
    instance_name: &str,
    cc_types: &[atakit_cloud::CcType],
) -> CloudImage {
    match provider_config.platform {
        PlatformKind::Gcp => {
            let names = atakit_cloud::naming::ResourceNames::for_gcp(instance_name, image_ref);
            CloudImage {
                platform: PlatformKind::Gcp,
                cloud_name: names.image,
                bucket: Some(names.bucket),
                gallery_rg: None,
                gallery: None,
                image_version: None,
                cc_types: cc_types.to_vec(),
                uploaded_at: chrono::Utc::now(),
            }
        }
        PlatformKind::Azure => {
            // Only gallery/image fields are used here; storage_account isn't.
            let names =
                AzureResourceNames::for_azure(instance_name, image_ref, &provider_config.region);
            CloudImage {
                platform: PlatformKind::Azure,
                cloud_name: names.image_definition,
                bucket: None,
                gallery_rg: Some(names.gallery_rg),
                gallery: Some(names.gallery),
                image_version: Some(names.image_version),
                cc_types: cc_types.to_vec(),
                uploaded_at: chrono::Utc::now(),
            }
        }
        PlatformKind::Aws => {
            let names = atakit_cloud::naming::ResourceNames::for_aws(instance_name, image_ref);
            CloudImage {
                platform: PlatformKind::Aws,
                cloud_name: names.image,
                bucket: Some(names.bucket),
                gallery_rg: None,
                gallery: None,
                image_version: None,
                cc_types: cc_types.to_vec(),
                uploaded_at: chrono::Utc::now(),
            }
        }
    }
}

/// Result of a cloud image upload attempt.
pub(super) struct UploadResult {
    /// Whether an upload actually happened (false = already existed).
    pub uploaded: bool,
}

/// Ensure a cloud image is uploaded to the given provider. Checks the local
/// `CloudImages` state first to avoid redundant cloud API calls.
///
/// Records the upload in `CloudImages` on success.
/// Returns `uploaded: false` if the image already exists (in local state or cloud).
#[allow(clippy::too_many_arguments)]
pub(super) async fn ensure_cloud_image(
    image_ref: &str,
    provider_name: &str,
    provider_config: &CloudProviderConfig,
    source_path: &str,
    certs_dir: Option<&str>,
    cc_types: &[atakit_cloud::CcType],
    force: bool,
    env: &Env,
    verbose: bool,
) -> Result<UploadResult> {
    let mut cloud_imgs = CloudImages::load(&env.data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

    let cloud_provider: Box<dyn CloudProvider> = match provider_config.platform {
        PlatformKind::Gcp => {
            let project = provider_config.project.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "provider '{provider_name}' is missing 'project' in \
                     [cloud.providers.{provider_name}]"
                )
            })?;
            Box::new(GcpProvider::new(project, provider_config.region.clone()))
        }
        PlatformKind::Azure => {
            let subscription = provider_config.subscription.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "provider '{provider_name}' is missing 'subscription' in \
                     [cloud.providers.{provider_name}] — set it to the Azure \
                     subscription ID you intend to deploy into (atakit will pass \
                     --subscription to every az call)"
                )
            })?;
            Box::new(AzureProvider::new(
                subscription,
                provider_config.region.clone(),
            ))
        }
        PlatformKind::Aws => Box::new(AwsProvider::new(provider_config.region.clone())),
    };

    let runner = ProcessRunner::new(verbose);

    // Check deps.
    cloud_provider
        .execute_step(&DeployStep::CheckDeps, &runner, verbose)
        .await?;

    // Check existence before uploading so we can report accurately.
    let already_exists = match provider_config.platform {
        PlatformKind::Gcp => {
            let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", image_ref);
            let exists = atakit_cloud::gcp::image::check_image_exists(
                provider_config.project.as_deref().unwrap(),
                &names.image,
                &runner,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to check image existence: {e}"))?;
            exists && !force
        }
        PlatformKind::Azure => {
            let subscription = provider_config.subscription.as_deref().unwrap();
            // Image-existence check; storage_account isn't used.
            let names = AzureResourceNames::for_azure("upload", image_ref, &provider_config.region);
            let exists = atakit_cloud::azure::image::check_image_version_exists(
                subscription,
                &names.gallery_rg,
                &names.gallery,
                &names.image_definition,
                &names.image_version,
                &runner,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to check image existence: {e}"))?;
            exists && !force
        }
        PlatformKind::Aws => {
            let names = atakit_cloud::naming::ResourceNames::for_aws("upload", image_ref);
            let exists =
                atakit_cloud::aws::image::find_ami(&provider_config.region, &names.image, &runner)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to check image existence: {e}"))?
                    .is_some();
            exists && !force
        }
    };

    if already_exists {
        // Record in tracking (may be missing if uploaded before tracking existed).
        let record = build_cloud_image_record(provider_config, image_ref, "upload", cc_types);
        cloud_imgs.record(image_ref, provider_name, record);
        cloud_imgs
            .save(&env.data_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        return Ok(UploadResult { uploaded: false });
    }

    // Upload.
    match provider_config.platform {
        PlatformKind::Gcp => {
            let names = atakit_cloud::naming::ResourceNames::for_gcp("upload", image_ref);
            let step = DeployStep::UploadImage {
                bucket: names.bucket.clone(),
                image_name: names.image.clone(),
                source_path: Some(source_path.to_string()),
                certs_dir: certs_dir.map(str::to_string),
                cc_types: cc_types.to_vec(),
                force,
            };
            cloud_provider.execute_step(&step, &runner, verbose).await?;
        }
        PlatformKind::Azure => {
            // Image-upload path: shared `atakitupload` storage account (no
            // hash) so a follow-up `cloud image upload` of the same image
            // reuses rather than duplicates. This is a different lifecycle
            // from per-deploy storage accounts.
            let names = AzureResourceNames::for_azure("upload", image_ref, &provider_config.region);
            cloud_provider
                .execute_step(
                    &DeployStep::CreateResourceGroup {
                        name: names.resource_group.clone(),
                        region: provider_config.region.clone(),
                    },
                    &runner,
                    verbose,
                )
                .await?;
            let step = DeployStep::UploadImageAzure {
                resource_group: names.resource_group,
                storage_account: names.storage_account,
                gallery_rg: names.gallery_rg,
                gallery: names.gallery,
                image_definition: names.image_definition,
                image_version: names.image_version,
                source_path: Some(source_path.to_string()),
                certs_dir: certs_dir.map(str::to_string),
                cc_types: cc_types.to_vec(),
                force,
            };
            cloud_provider.execute_step(&step, &runner, verbose).await?;
        }
        PlatformKind::Aws => {
            let names = atakit_cloud::naming::ResourceNames::for_aws("upload", image_ref);
            let step = DeployStep::UploadImageAws {
                bucket: names.bucket,
                image_name: names.image,
                source_path: Some(source_path.to_string()),
                certs_dir: certs_dir.map(str::to_string),
                force,
            };
            cloud_provider.execute_step(&step, &runner, verbose).await?;
        }
    };

    let record = build_cloud_image_record(provider_config, image_ref, "upload", cc_types);
    cloud_imgs.record(image_ref, provider_name, record);
    cloud_imgs
        .save(&env.data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(UploadResult { uploaded: true })
}

/// Parse metadata key=value strings into a map.
pub fn parse_metadata(items: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut map = std::collections::BTreeMap::new();
    for item in items {
        let (key, value) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid metadata format: expected KEY=VALUE, got '{item}'")
        })?;
        if key.is_empty() {
            bail!("metadata key cannot be empty in '{item}'");
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}
