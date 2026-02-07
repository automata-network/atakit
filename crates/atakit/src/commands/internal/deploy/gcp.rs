use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::info;

use super::CloudPlatform;
use crate::config::{self, Config};
use crate::types::{DiskDef, PlatformConfig};

struct GcpDataDisk {
    name: String,
    size: String,
    /// Resolved GCP disk name after `ensure_data_disk` runs (may differ after
    /// conversion, e.g. `"disk-ssd"`).
    attached_name: Option<String>,
}

pub(crate) struct Gcp {
    vm_name: String,
    vm_type: String,
    zone: String,
    region: String,
    project_id: String,
    bucket_name: String,
    bucket_url: String,
    image_name: String,
    artifact_dir: PathBuf,
    quiet: bool,
    /// GCP firewall `--allow` value, e.g. `"tcp:8000,tcp:8080"`.
    firewall_allow: String,
    /// Data disks derived from DiskDef entries.
    data_disks: Vec<GcpDataDisk>,
    /// GCP disk name for the additional-data image.
    additional_data_disk: Option<String>,
}

/// Derive region from zone by stripping the trailing `-<letter>` suffix.
/// e.g. "asia-southeast1-b" -> "asia-southeast1"
fn zone_to_region(zone: &str) -> String {
    match zone.rsplit_once('-') {
        Some((prefix, _)) => prefix.to_string(),
        None => zone.to_string(),
    }
}

impl Gcp {
    pub(crate) fn new(
        deployment_name: &str,
        platform_config: &PlatformConfig,
        cfg: &Config,
        quiet: bool,
        compose_ports: &[(String, String)],
        disk_defs: &[&DiskDef],
    ) -> Result<Self> {
        let vm_type = platform_config
            .vmtype
            .as_deref()
            .unwrap_or("c3-standard-4")
            .to_string();
        let zone = platform_config
            .region
            .as_deref()
            .unwrap_or("asia-southeast1-b")
            .to_string();
        let region = zone_to_region(&zone);

        let project_id = match &platform_config.project {
            Some(p) => p.clone(),
            None => config::try_capture("gcloud", &["config", "get-value", "project"]).ok_or_else(
                || {
                    anyhow::anyhow!(
                        "GCP project not set. Specify 'project' in atakit.json or run: gcloud init"
                    )
                },
            )?,
        };

        // Reuse saved bucket name from previous deployment, or generate a new one.
        let artifact_dir = cfg.artifact_dir.clone();
        let bucket_artifact = artifact_dir.join(format!("gcp_{}_bucket", deployment_name));
        let bucket_name = if let Ok(saved) = std::fs::read_to_string(&bucket_artifact) {
            let saved = saved.trim().to_string();
            info!(bucket = %saved, "Reusing bucket from previous deployment");
            saved
        } else {
            let name = config::generate_name(deployment_name, 6);
            info!(bucket = %name, "Generated new bucket name");
            name
        };

        let bucket_url = format!("gs://{}", bucket_name);
        let image_name = format!("{}-image", deployment_name);
        let firewall_allow = build_firewall_allow(compose_ports);

        info!(
            platform = "GCP",
            vm_name = deployment_name,
            vm_type = %vm_type,
            zone = %zone,
            project_id = %project_id,
            bucket = %bucket_name,
            "Deployment configuration"
        );

        let data_disks: Vec<GcpDataDisk> = disk_defs
            .iter()
            .map(|d| GcpDataDisk {
                name: d.name.clone(),
                size: d.size.clone(),
                attached_name: None,
            })
            .collect();

        Ok(Self {
            vm_name: deployment_name.to_string(),
            vm_type,
            zone,
            region,
            project_id,
            bucket_name,
            bucket_url,
            image_name,
            artifact_dir,
            quiet,
            firewall_allow,
            data_disks,
            additional_data_disk: None,
        })
    }

    fn save_artifact(&self, suffix: &str, value: &str) {
        let path = self
            .artifact_dir
            .join(format!("gcp_{}_{}", self.vm_name, suffix));
        if let Err(e) = std::fs::write(&path, value) {
            tracing::warn!(path = %path.display(), error = %e, "Failed to save artifact");
        }
    }

    /// Save deployment artifacts for reuse in subsequent deployments.
    fn save_artifacts(&self, public_ip: Option<&str>, disk_name: Option<&str>) {
        self.save_artifact("bucket", &self.bucket_name);
        self.save_artifact("region", &self.zone);
        self.save_artifact("project", &self.project_id);
        if let Some(ip) = public_ip {
            self.save_artifact("ip", ip);
        }
        if let Some(disk) = disk_name {
            self.save_artifact("disk", disk);
        }
    }

    /// Resolve all data disks: create or convert as needed.
    fn resolve_data_disks(&mut self) -> Result<()> {
        let zone_flag = format!("--zone={}", self.zone);
        let project_flag = format!("--project={}", self.project_id);
        let vm_type = self.vm_type.clone();
        let quiet = self.quiet;

        for disk in &mut self.data_disks {
            let disk_name = disk.name.clone();

            // Check if disk already exists.
            let exists = super::run_cmd_silent(
                "gcloud",
                &[
                    "compute",
                    "disks",
                    "describe",
                    &disk_name,
                    &zone_flag,
                    &project_flag,
                ],
            );

            if exists {
                // Check if we need to convert pd-standard → pd-balanced for c3-* VMs.
                if let Some(converted) = maybe_convert_disk_type(
                    &disk_name,
                    &vm_type,
                    quiet,
                    &zone_flag,
                    &project_flag,
                )? {
                    disk.attached_name = Some(converted);
                } else {
                    info!(disk = %disk_name, "Attaching existing data disk");
                    disk.attached_name = Some(disk_name);
                }
            } else {
                // Create a new disk.
                info!(disk = %disk_name, size = %disk.size, "Creating new data disk");
                let size_flag = format!("--size={}", disk.size);
                super::run_cmd(
                    "gcloud",
                    &[
                        "compute",
                        "disks",
                        "create",
                        &disk_name,
                        &size_flag,
                        "--type=pd-balanced",
                        &zone_flag,
                        &project_flag,
                    ],
                    quiet,
                )?;
                disk.attached_name = Some(disk_name);
            }
        }
        Ok(())
    }
}

/// If the existing disk is pd-standard and the VM type is c3-*, snapshot
/// and recreate as pd-balanced.  Returns `Some(new_disk_name)` on
/// conversion, `None` when no conversion is needed.
fn maybe_convert_disk_type(
    disk_name: &str,
    vm_type: &str,
    quiet: bool,
    zone_flag: &str,
    project_flag: &str,
) -> Result<Option<String>> {
    if !vm_type.starts_with("c3-") {
        return Ok(None);
    }

    // Query current disk type.
    let disk_type = config::try_capture(
        "gcloud",
        &[
            "compute",
            "disks",
            "describe",
            disk_name,
            zone_flag,
            project_flag,
            "--format=value(type)",
        ],
    )
    .unwrap_or_default();

    if !disk_type.contains("pd-standard") {
        return Ok(None);
    }

    info!(disk = %disk_name, "Disk is pd-standard, converting to pd-balanced for c3-* VM");

    let snap_name = format!(
        "{}-snap-{}",
        disk_name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let new_disk = format!("{}-ssd", disk_name);

    // Create snapshot.
    super::run_cmd(
        "gcloud",
        &[
            "compute",
            "disks",
            "snapshot",
            disk_name,
            &format!("--snapshot-names={}", snap_name),
            zone_flag,
            project_flag,
        ],
        quiet,
    )?;

    // Create pd-balanced disk from snapshot.
    super::run_cmd(
        "gcloud",
        &[
            "compute",
            "disks",
            "create",
            &new_disk,
            &format!("--source-snapshot={}", snap_name),
            "--type=pd-balanced",
            zone_flag,
            project_flag,
        ],
        quiet,
    )?;

    // Clean up snapshot.
    let _ = super::run_cmd(
        "gcloud",
        &[
            "compute",
            "snapshots",
            "delete",
            &snap_name,
            project_flag,
            "--quiet",
        ],
        quiet,
    );

    Ok(Some(new_disk))
}

impl CloudPlatform for Gcp {
    fn name(&self) -> &str {
        "gcp"
    }

    fn disk_filename(&self) -> &str {
        "gcp_disk.tar.gz"
    }

    fn attach_additional_data_disk(&mut self, img_path: Option<&Path>) -> Result<()> {
        let raw_path = match img_path {
            Some(p) => p,
            None => return Ok(()),
        };

        let project_flag = format!("--project={}", self.project_id);
        let zone_flag = format!("--zone={}", self.zone);
        let disk_name = format!("{}-additional-data", self.vm_name);
        let image_name = format!("{}-additional-data-img", self.vm_name);

        // 1. Package raw image as tar.gz for GCP.
        let tar_gz_path = raw_path.with_extension("img.tar.gz");
        super::fat_image::package_as_tar_gz(raw_path, &tar_gz_path)?;

        // 2. Upload tar.gz to GCS bucket.
        let dest_uri = format!("{}/additional-data.tar.gz", self.bucket_url);
        info!("Uploading additional-data image to GCS");
        super::run_cmd(
            "gsutil",
            &["cp", &tar_gz_path.to_string_lossy(), &dest_uri],
            self.quiet,
        )?;

        // 3. Delete old GCP image if exists.
        if super::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "images",
                "describe",
                &image_name,
                &project_flag,
            ],
        ) {
            info!("Deleting existing additional-data image");
            super::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "images",
                    "delete",
                    &image_name,
                    &project_flag,
                    "--quiet",
                ],
                self.quiet,
            )?;
        }

        // 4. Create GCP image from uploaded tar.gz.
        info!("Creating additional-data GCP image");
        super::run_cmd(
            "gcloud",
            &[
                "compute",
                "images",
                "create",
                &image_name,
                "--source-uri",
                &dest_uri,
                &project_flag,
            ],
            self.quiet,
        )?;

        // 5. Delete old disk if exists.
        if super::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "disks",
                "describe",
                &disk_name,
                &zone_flag,
                &project_flag,
            ],
        ) {
            info!("Deleting existing additional-data disk");
            super::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "disks",
                    "delete",
                    &disk_name,
                    &zone_flag,
                    &project_flag,
                    "--quiet",
                ],
                self.quiet,
            )?;
        }

        // 6. Create disk from image.
        info!("Creating additional-data disk");
        super::run_cmd(
            "gcloud",
            &[
                "compute",
                "disks",
                "create",
                &disk_name,
                &format!("--image={}", image_name),
                "--type=pd-balanced",
                &zone_flag,
                &project_flag,
            ],
            self.quiet,
        )?;

        self.additional_data_disk = Some(disk_name);
        Ok(())
    }

    fn check_deps(&self, cfg: &Config) -> Result<()> {
        cfg.run_script_default("check_csp_deps.sh", &["gcp"])
            .context("check deps")
    }

    fn prepare_image(&mut self, cfg: &Config) -> Result<()> {
        // 1. Create bucket if it doesn't exist.
        if !super::run_cmd_silent("gsutil", &["ls", "-b", &self.bucket_url]) {
            info!("Creating GCS bucket");
            super::run_cmd(
                "gcloud",
                &[
                    "storage",
                    "buckets",
                    "create",
                    &self.bucket_url,
                    &format!("--location={}", self.region),
                ],
                self.quiet,
            )?;
        }
        // Persist bucket name immediately so it can be reused if later steps fail.
        self.save_artifact("bucket", &self.bucket_name);

        // 2. Upload disk image to bucket.
        info!("Uploading disk image to GCS");
        let disk_path = cfg.disk_dir.join(self.disk_filename());
        if !disk_path.exists() {
            bail!("Disk image not found: {}", disk_path.display());
        }
        let uploaded_name = format!("{}.tar.gz", self.vm_name);
        let dest_uri = format!("{}/{}", self.bucket_url, uploaded_name);
        super::run_cmd(
            "gsutil",
            &["cp", &disk_path.to_string_lossy(), &dest_uri],
            self.quiet,
        )?;

        // 3. Delete old image if it exists.
        if super::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "images",
                "describe",
                &self.image_name,
                &format!("--project={}", self.project_id),
            ],
        ) {
            info!("Deleting existing image");
            super::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "images",
                    "delete",
                    &self.image_name,
                    &format!("--project={}", self.project_id),
                    "--quiet",
                ],
                self.quiet,
            )?;
        }

        // 4. Create GCP image from uploaded disk.
        info!("Creating GCP image");
        let location = if self.zone.contains("eu") {
            "eu"
        } else if self.zone.contains("us") {
            "us"
        } else {
            "asia"
        };

        let sb_dir = cfg.disk_dir.join("secure_boot");
        let mut sig_files = format!(
            "{},{}",
            sb_dir.join("db.crt").display(),
            sb_dir.join("kernel.crt").display()
        );
        let livepatch = sb_dir.join("livepatch.crt");
        if livepatch.exists() {
            sig_files.push_str(&format!(",{}", livepatch.display()));
        }

        let pk_flag = format!("--platform-key-file={}", sb_dir.join("PK.crt").display());
        let kek_flag = format!(
            "--key-exchange-key-file={}",
            sb_dir.join("KEK.crt").display()
        );
        let sig_flag = format!("--signature-database-file={}", sig_files);

        super::run_cmd(
            "gcloud",
            &[
                "compute",
                "images",
                "create",
                &self.image_name,
                "--source-uri",
                &dest_uri,
                &format!("--project={}", self.project_id),
                "--guest-os-features",
                "TDX_CAPABLE,SEV_SNP_CAPABLE,GVNIC,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE",
                &format!("--storage-location={}", location),
                &pk_flag,
                &kek_flag,
                &sig_flag,
            ],
            self.quiet,
        )?;

        Ok(())
    }

    fn setup_network(&mut self) -> Result<()> {
        let rule_name = format!("{}-ingress", self.vm_name);
        let allow_ports = &self.firewall_allow;

        if super::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "describe",
                &rule_name,
                &format!("--project={}", self.project_id),
            ],
        ) {
            info!("Deleting existing firewall rule");
            super::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "firewall-rules",
                    "delete",
                    &rule_name,
                    &format!("--project={}", self.project_id),
                    "--quiet",
                ],
                self.quiet,
            )?;
        }

        info!("Creating firewall rule");
        super::run_cmd(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "create",
                &rule_name,
                &format!("--project={}", self.project_id),
                "--allow",
                allow_ports,
                "--target-tags",
                &rule_name,
                "--description",
                "Allow cvm workload traffic",
                "--direction",
                "INGRESS",
                "--priority",
                "1000",
                "--network",
                "default",
            ],
            self.quiet,
        )?;

        Ok(())
    }

    fn ensure_data_disk(&mut self) -> Result<()> {
        self.resolve_data_disks()
    }

    fn launch(&self) -> Result<()> {
        let cc_type = if self.vm_type.starts_with("n2d-") {
            "SEV_SNP"
        } else {
            "TDX"
        };

        let machine_type = format!("--machine-type={}", self.vm_type);
        let zone_flag = format!("--zone={}", self.zone);
        let cc_flag = format!("--confidential-compute-type={}", cc_type);
        let image_project = format!("--image-project={}", self.project_id);
        let image_flag = format!("--image={}", self.image_name);
        let project_flag = format!("--project={}", self.project_id);
        let rule_name = format!("{}-ingress", self.vm_name);

        let mut args: Vec<String> = vec![
            "compute".into(),
            "instances".into(),
            "create".into(),
            self.vm_name.clone(),
            machine_type,
            zone_flag,
            cc_flag,
            "--maintenance-policy=TERMINATE".into(),
            image_project,
            image_flag,
            "--shielded-secure-boot".into(),
            "--shielded-vtpm".into(),
            "--shielded-integrity-monitoring".into(),
            project_flag,
            "--tags".into(),
            rule_name,
            "--metadata".into(),
            "serial-port-enable=1,serial-port-logging-enable=1".into(),
        ];

        for disk in &self.data_disks {
            if let Some(ref attached) = disk.attached_name {
                args.push(format!(
                    "--disk=name={},device-name={},auto-delete=no,boot=no",
                    attached, disk.name
                ));
            }
        }

        if let Some(ref disk) = self.additional_data_disk {
            args.push(format!(
                "--disk=name={},auto-delete=yes,boot=no,mode=ro",
                disk
            ));
        }

        info!("Creating CVM instance");
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        super::run_cmd("gcloud", &arg_refs, self.quiet)?;

        Ok(())
    }

    fn post_launch(&self) -> Result<()> {
        let public_ip = config::try_capture(
            "gcloud",
            &[
                "compute",
                "instances",
                "describe",
                &self.vm_name,
                &format!("--zone={}", self.zone),
                &format!("--project={}", self.project_id),
                "--format=get(networkInterfaces[0].accessConfigs[0].natIP)",
            ],
        );

        let first_disk = self
            .data_disks
            .first()
            .and_then(|d| d.attached_name.as_deref());
        self.save_artifacts(public_ip.as_deref(), first_disk);

        if let Some(ip) = &public_ip {
            info!(public_ip = %ip, vm_name = %self.vm_name, "GCP deployment complete");
        } else {
            info!(vm_name = %self.vm_name, "GCP deployment complete");
        }

        Ok(())
    }
}

/// Build the GCP firewall `--allow` value from compose port mappings.
///
/// Always includes the default agent port (`tcp:8000`). Compose ports
/// in the format `HOST:CONTAINER[/proto]` or `IP:HOST:CONTAINER[/proto]`
/// are appended. Entries without an explicit host mapping are skipped.
fn build_firewall_allow(compose_ports: &[(String, String)]) -> String {
    let mut entries: Vec<String> = vec!["tcp:8000".to_string()];

    for (_service, raw) in compose_ports {
        let (port_part, protocol) = if let Some((p, proto)) = raw.rsplit_once('/') {
            if matches!(proto, "tcp" | "udp" | "sctp") {
                (p, proto)
            } else {
                (raw.as_str(), "tcp")
            }
        } else {
            (raw.as_str(), "tcp")
        };

        let parts: Vec<&str> = port_part.split(':').collect();
        let host_port = match parts.len() {
            1 => continue,
            2 => parts[0],
            3 => parts[1],
            _ => continue,
        };

        let entry = format!("{}:{}", protocol, host_port);
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }

    entries.join(",")
}
