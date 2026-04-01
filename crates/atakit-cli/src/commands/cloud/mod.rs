pub mod deploy;
pub mod destroy;
pub mod init;
pub mod list;
pub mod serial;
pub mod ssh;
pub mod status;
pub mod upload_image;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use atakit_cloud::{CloudConfig, CloudTarget, PlatformKind, PersistedAgentEnv};
use atakit_core::Env;
use atakit_image::{ImageRef, ImageStore, Platform as ImagePlatform, import_image_archive};
use atakit_workload::WorkloadStore;

use owo_colors::OwoColorize;

use crate::config::PublishConfig;

/// Resolve agent env fields with precedence: CLI > target > [cloud] > [publish].
pub struct AgentEnvBuilder<'a> {
	pub cli_rpc_url: Option<&'a str>,
	pub cli_session_registry: Option<&'a str>,
	pub cli_owner_key: Option<&'a str>,
	pub cli_relay_key: Option<&'a str>,
	pub target: &'a CloudTarget,
	pub cloud: &'a CloudConfig,
	pub publish: &'a PublishConfig,
}

impl<'a> AgentEnvBuilder<'a> {
	pub fn rpc_url(&self) -> Option<String> {
		self.cli_rpc_url
			.map(String::from)
			.or_else(|| self.target.rpc_url.clone())
			.or_else(|| self.cloud.rpc_url.clone())
			.or_else(|| self.publish.rpc_url.clone())
	}

	pub fn session_registry(&self) -> Option<String> {
		self.cli_session_registry
			.map(String::from)
			.or_else(|| self.target.session_registry.clone())
			.or_else(|| self.cloud.session_registry.clone())
			.or_else(|| self.publish.session_registry.clone())
	}

	pub fn owner_key_file(&self) -> Option<String> {
		self.cli_owner_key
			.map(String::from)
			.or_else(|| self.target.owner_key_file.clone())
			.or_else(|| self.cloud.owner_key_file.clone())
			.or_else(|| self.publish.owner_key_file.clone())
	}

	pub fn relay_key_file(&self) -> Option<String> {
		self.cli_relay_key
			.map(String::from)
			.or_else(|| self.target.relay_key_file.clone())
			.or_else(|| self.cloud.relay_key_file.clone())
			.or_else(|| self.publish.relay_key_file.clone())
	}

	pub fn expire_offset(&self) -> Option<u64> {
		self.cloud.expire_offset
	}

	pub fn build(&self) -> PersistedAgentEnv {
		PersistedAgentEnv {
			rpc_url: self.rpc_url(),
			session_registry: self.session_registry(),
			owner_key_file: self.owner_key_file(),
			relay_key_file: self.relay_key_file(),
			expire_offset: self.expire_offset(),
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
        let image_ref: ImageRef = image_arg.parse()
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
    })
}

/// Resolved workload source: archive path + name/version + declared ports + disks.
pub(super) struct ResolvedWorkload {
    pub archive_path: PathBuf,
    pub name: String,
    pub version: String,
    pub ports: Vec<String>,
    /// Disk name -> (index, size string e.g. "10GB").
    pub disks: BTreeMap<String, (u32, String)>,
    /// Minimum boot/OS disk size (e.g. "50GB"). None = cloud default.
    pub boot_disk_size: Option<String>,
    /// Base image access control mode: "any", "whitelist", or "blacklist".
    pub base_image_mode: String,
    /// Base image references for whitelist/blacklist filtering.
    pub base_image: Vec<String>,
    /// All unmeasured-data paths from the manifest (workload + dependencies, deduplicated).
    /// Archive-relative, no ./ prefix.
    pub unmeasured_data: Vec<String>,
    /// Workload source directory (available in dir mode, None for store-ref/file modes).
    pub workload_dir: Option<PathBuf>,
}

/// Resolve workload from source arg, falling back to dir mode.
pub(super) fn resolve_workload(source: &Option<String>, dir: &Option<PathBuf>, env: &Env) -> Result<ResolvedWorkload> {
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
                tokio::runtime::Handle::current().block_on(atakit_workload::inspect_workload(&inspect_opts))
            }).context("failed to inspect store archive")?;
            let disks = result.manifest.disks.iter()
                .map(|(k, v)| (k.clone(), (v.index, v.size.clone())))
                .collect();
            let ports = collect_firewall_ports(&result.manifest);
            let unmeasured = collect_unmeasured_paths(&result.manifest);
            return Ok(ResolvedWorkload {
                archive_path: blob,
                name,
                version,
                ports,
                disks,
                boot_disk_size: result.manifest.config.boot_disk_size,
                base_image_mode: result.manifest.config.base_image_mode,
                base_image: result.manifest.config.base_image,
                unmeasured_data: unmeasured,
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
        }).context("failed to inspect archive")?;
        let disks = result.manifest.disks.iter()
            .map(|(k, v)| (k.clone(), (v.index, v.size.clone())))
            .collect();
        let ports = collect_firewall_ports(&result.manifest);
        let unmeasured = collect_unmeasured_paths(&result.manifest);
        return Ok(ResolvedWorkload {
            archive_path: path,
            name: result.manifest.meta.name,
            version: result.manifest.meta.version,
            ports,
            disks,
            boot_disk_size: result.manifest.config.boot_disk_size,
            base_image_mode: result.manifest.config.base_image_mode,
            base_image: result.manifest.config.base_image,
            unmeasured_data: unmeasured,
            workload_dir: None,
        });
    }

    // Dir mode: read atakit-workload.toml, find versioned archive.
    let workload_dir = dir.clone().unwrap_or_else(|| std::env::current_dir().unwrap());
    if !workload_dir.join("atakit-workload.toml").exists() {
        bail!(
            "no workload source specified and no atakit-workload.toml found in {}",
            workload_dir.display(),
        );
    }
    let archive_path = crate::commands::workload::find_versioned_archive(&workload_dir)?;
    let inspect_opts = atakit_workload::InspectOptions {
        archive: Some(archive_path.clone()),
        workload_dir: None,
        engine: None,
        verbose: false,
    };
    let result = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(atakit_workload::inspect_workload(&inspect_opts))
    }).context("failed to inspect archive")?;
    let ports = collect_firewall_ports(&result.manifest);
    let disks = result.manifest.disks.iter()
        .map(|(k, v)| (k.clone(), (v.index, v.size.clone())))
        .collect();
    let unmeasured = collect_unmeasured_paths(&result.manifest);
    Ok(ResolvedWorkload {
        archive_path,
        name: result.manifest.meta.name,
        version: result.manifest.meta.version,
        ports,
        disks,
        boot_disk_size: result.manifest.config.boot_disk_size,
        base_image_mode: result.manifest.config.base_image_mode,
        base_image: result.manifest.config.base_image,
        unmeasured_data: unmeasured,
        workload_dir: Some(workload_dir),
    })
}

/// Collect all unmeasured-data paths from a manifest (workload + dependencies, deduplicated).
fn collect_unmeasured_paths(m: &atakit_workload::manifest::Manifest) -> Vec<String> {
    let mut paths: Vec<String> = m.config.unmeasured_data.clone();
    if let Some(ref deps) = m.config.dependencies {
        for dep in deps.values() {
            for p in &dep.unmeasured_data {
                if !paths.contains(p) {
                    paths.push(p.clone());
                }
            }
        }
    }
    paths
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
        _ => {}
    }
    Ok(())
}

/// Collect unmeasured-data files from a workload directory into a gzipped tar.
///
/// `paths` are archive-relative (no `./` prefix, e.g. `"runtime-data/key.pem"`).
/// Files are resolved under `workload_dir` with a `./` prefix re-added.
/// Returns `None` if no files are found. Warns about missing files.
pub(super) fn collect_unmeasured_tar(
    paths: &[String],
    workload_dir: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    if paths.is_empty() {
        return Ok(None);
    }

    let mut found_any = false;
    let buf = Vec::new();
    let encoder = flate2::write::GzEncoder::new(buf, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);

    let canon_base = workload_dir.canonicalize()?;

    for rel_path in paths {
        // Manifest stores paths without ./ prefix. The source files live at
        // workload_dir/./path (the original config used ./ relative paths).
        let src = workload_dir.join(rel_path);
        if !src.exists() {
            eprintln!(
                "  {}: unmeasured-data file not found: {}",
                "warning".yellow(),
                src.display(),
            );
            continue;
        }

        // Resolve symlinks and verify the real path stays within the workload dir.
        let canon_src = src.canonicalize()?;
        if !canon_src.starts_with(&canon_base) {
            bail!(
                "unmeasured-data path '{}' resolves outside workload directory: {}",
                rel_path,
                canon_src.display(),
            );
        }

        if src.is_file() {
            let metadata = std::fs::metadata(&src)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(metadata.len());
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_cksum();
            let file = std::fs::File::open(&src)?;
            tar.append_data(&mut header, rel_path, file)?;
            found_any = true;
        } else if src.is_dir() {
            append_dir_recursive(&mut tar, &src, rel_path)?;
            found_any = true;
        }
    }

    if !found_any {
        return Ok(None);
    }

    let encoder = tar.into_inner()?;
    let bytes = encoder.finish()?;
    Ok(Some(bytes))
}

/// Recursively append a directory to a tar archive.
fn append_dir_recursive<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    src_dir: &std::path::Path,
    archive_prefix: &str,
) -> Result<()> {
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let child_src = entry.path();
        let child_name = child_src
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let child_archive = format!("{archive_prefix}/{child_name}");
        let ft = entry.file_type()?;

        if ft.is_file() {
            let metadata = std::fs::metadata(&child_src)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(metadata.len());
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_cksum();
            let file = std::fs::File::open(&child_src)?;
            tar.append_data(&mut header, &child_archive, file)?;
        } else if ft.is_dir() {
            append_dir_recursive(tar, &child_src, &child_archive)?;
        }
    }
    Ok(())
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
