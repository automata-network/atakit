use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use async_trait::async_trait;
use tracing::info;

use crate::cmd;
use crate::{
    BlockStorage, CloudProvider, Compute, DiskFormat, ImageManager, InstanceInfo, Logs, Metadata,
    Networking, PortRule, Protocol,
};

// ── Configuration ─────────────────────────────────────────────────

/// Configuration for creating a [`Gcp`] provider instance.
pub struct GcpConfig {
    pub vm_name: String,
    pub vm_type: Option<String>,
    pub zone: Option<String>,
    pub project_id: Option<String>,
    pub bucket_name: Option<String>,
    pub image_name: Option<String>,
    /// Directory containing secure boot certificates (PK.crt, KEK.crt, db.crt, kernel.crt).
    pub secure_boot_dir: Option<PathBuf>,
    /// Run without confirmation prompts.
    pub quiet: bool,
    /// Port rules for firewall configuration.
    pub port_rules: Vec<PortRule>,
    /// Data disks to attach to the instance.
    pub data_disks: Vec<DataDiskConfig>,
}

/// Configuration for a data disk to attach to an instance.
#[derive(Clone, Debug)]
pub struct DataDiskConfig {
    /// Disk name (used for both GCP disk name and device-name).
    pub name: String,
    /// Disk size (e.g., "100GB").
    pub size: String,
}

/// Internal state for a data disk to attach during instance creation.
struct GcpDataDisk {
    /// Device name exposed to the guest.
    name: String,
    /// Actual GCP disk name (may differ after conversion, e.g., `"disk-ssd"`).
    attached_name: String,
}

// ── Provider ──────────────────────────────────────────────────────

pub struct Gcp {
    vm_name: String,
    vm_type: String,
    zone: String,
    region: String,
    project_id: String,
    bucket_name: String,
    bucket_url: String,
    image_name: String,
    secure_boot_dir: Option<PathBuf>,
    quiet: bool,
    firewall_rule_name: String,
    firewall_allow: String,
    /// Data disks to attach during instance creation.
    data_disks: Vec<GcpDataDisk>,
}

impl Gcp {
    pub async fn new(config: GcpConfig) -> Result<Self> {
        let vm_type = config.vm_type.unwrap_or_else(|| "c3-standard-4".into());
        let zone = config.zone.unwrap_or_else(|| "asia-southeast1-b".into());
        let region = zone_to_region(&zone);

        let project_id = match config.project_id {
            Some(p) => p,
            None => cmd::try_capture("gcloud", &["config", "get-value", "project"])
                .await
                .ok_or_else(|| {
                    anyhow::anyhow!("GCP project not set. Specify project_id or run: gcloud init")
                })?,
        };

        let bucket_name = config
            .bucket_name
            .unwrap_or_else(|| cmd::generate_name(&config.vm_name, 6));
        let bucket_url = format!("gs://{bucket_name}");
        let image_name = config
            .image_name
            .unwrap_or_else(|| format!("{}-image", config.vm_name));

        let firewall_rule_name = format!("{}-ingress", config.vm_name);
        let firewall_allow = build_firewall_allow(&config.port_rules);

        let data_disks: Vec<GcpDataDisk> = config
            .data_disks
            .into_iter()
            .map(|d| GcpDataDisk {
                name: d.name.clone(),
                attached_name: d.name,
            })
            .collect();

        info!(
            platform = "GCP",
            vm_name = %config.vm_name,
            vm_type = %vm_type,
            zone = %zone,
            project_id = %project_id,
            bucket = %bucket_name,
            "Configuration"
        );

        Ok(Self {
            vm_name: config.vm_name,
            vm_type,
            zone,
            region,
            project_id,
            bucket_name,
            bucket_url,
            image_name,
            secure_boot_dir: config.secure_boot_dir,
            quiet: config.quiet,
            firewall_rule_name,
            firewall_allow,
            data_disks,
        })
    }

    pub fn bucket_name(&self) -> &str {
        &self.bucket_name
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }
}

// ── CloudProvider ─────────────────────────────────────────────────

#[async_trait]
impl CloudProvider for Gcp {
    fn name(&self) -> &str {
        "gcp"
    }

    fn disk_format(&self) -> DiskFormat {
        DiskFormat::TarGz
    }

    async fn check_deps(&self) -> Result<()> {
        let required = [
            ("gcloud", "Google Cloud SDK"),
            ("gsutil", "Google Cloud SDK"),
        ];
        let mut missing: Vec<&str> = Vec::new();

        for (cmd_name, _pkg) in &required {
            if !cmd::command_exists(cmd_name).await {
                missing.push(cmd_name);
            }
        }

        if !missing.is_empty() {
            bail!(
                "Missing required tools: {}. Install Google Cloud SDK.",
                missing.join(", ")
            );
        }

        Ok(())
    }
}

// ── ImageManager ──────────────────────────────────────────────────

#[async_trait]
impl ImageManager for Gcp {
    async fn upload_image(
        &mut self,
        disk_path: &Path,
        version: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let version = version.map(|n| n.replace(":", "-").replace(".", "-"));
        let version = version.as_deref();
        // Use versioned image name if version provided.
        let image_name = match version {
            Some(v) => format!("{}", v),
            None => self.image_name.clone(),
        };

        let project_flag = format!("--project={}", self.project_id);

        // Check if image already exists with this version.
        if version.is_some() && self.image_exists(version).await {
            if force {
                info!(image = %image_name, "Force flag set, deleting existing image");
                cmd::run_cmd(
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
                )
                .await?;
            } else {
                info!(image = %image_name, "Image already exists, skipping upload");
                self.image_name = image_name;
                return Ok(());
            }
        }

        // 1. Create bucket if it doesn't exist.
        if !cmd::run_cmd_silent("gsutil", &["ls", "-b", &self.bucket_url]).await {
            info!("Creating GCS bucket");
            cmd::run_cmd(
                "gcloud",
                &[
                    "storage",
                    "buckets",
                    "create",
                    &self.bucket_url,
                    &format!("--location={}", self.region),
                ],
                self.quiet,
            )
            .await?;
        }

        // 2. Upload disk image to bucket.
        info!("Uploading disk image to GCS");
        if !disk_path.exists() {
            bail!("Disk image not found: {}", disk_path.display());
        }
        let uploaded_name = match version {
            Some(v) => format!("{}.tar.gz", v),
            None => format!("{}.tar.gz", self.vm_name),
        };
        let dest_uri = format!("{}/{}", self.bucket_url, uploaded_name);
        cmd::run_cmd(
            "gsutil",
            &["cp", &disk_path.to_string_lossy(), &dest_uri],
            self.quiet,
        )
        .await?;

        // 3. Delete old image if it exists (only for non-versioned deploys).
        if version.is_none() {
            if cmd::run_cmd_silent(
                "gcloud",
                &["compute", "images", "describe", &image_name, &project_flag],
            )
            .await
            {
                info!("Deleting existing image");
                cmd::run_cmd(
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
                )
                .await?;
            }
        }

        // 4. Create GCP image from uploaded disk.
        info!(image = %image_name, "Creating GCP image");
        let location = if self.zone.contains("eu") {
            "eu"
        } else if self.zone.contains("us") {
            "us"
        } else {
            "asia"
        };

        let mut create_args: Vec<String> = vec![
            "compute".into(),
            "images".into(),
            "create".into(),
            image_name.clone(),
            "--source-uri".into(),
            dest_uri.clone(),
            project_flag,
            "--guest-os-features".into(),
            "TDX_CAPABLE,SEV_SNP_CAPABLE,GVNIC,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE".into(),
            format!("--storage-location={}", location),
        ];

        // Add secure boot certificate flags if directory is provided.
        if let Some(ref sb_dir) = self.secure_boot_dir {
            let mut sig_files = format!(
                "{},{}",
                sb_dir.join("db.crt").display(),
                sb_dir.join("kernel.crt").display()
            );
            let livepatch = sb_dir.join("livepatch.crt");
            if livepatch.exists() {
                sig_files.push_str(&format!(",{}", livepatch.display()));
            }

            create_args.push(format!(
                "--platform-key-file={}",
                sb_dir.join("PK.crt").display()
            ));
            create_args.push(format!(
                "--key-exchange-key-file={}",
                sb_dir.join("KEK.crt").display()
            ));
            create_args.push(format!("--signature-database-file={sig_files}"));
        }

        let arg_refs: Vec<&str> = create_args.iter().map(|s| s.as_str()).collect();
        cmd::run_cmd("gcloud", &arg_refs, self.quiet).await?;

        // 5. Clean up uploaded tar.gz from bucket.
        info!("Removing uploaded disk image from GCS");
        let _ = cmd::run_cmd("gsutil", &["rm", &dest_uri], self.quiet).await;

        // Update image_name to the versioned name for subsequent use.
        self.image_name = image_name;

        Ok(())
    }

    async fn image_exists(&self, version: Option<&str>) -> bool {
        let version = version.map(|n| n.replace(":", "-").replace(".", "-"));
        let image_name = match version {
            Some(v) => format!("{}", v),
            None => self.image_name.clone(),
        };
        let project_flag = format!("--project={}", self.project_id);

        cmd::run_cmd_silent(
            "gcloud",
            &["compute", "images", "describe", &image_name, &project_flag],
        )
        .await
    }

    async fn delete_image(&mut self, version: Option<&str>) -> Result<()> {
        let version = version.map(|n| n.replace(":", "-").replace(".", "-"));
        let image_name = match version {
            Some(v) => format!("{}", v),
            None => self.image_name.clone(),
        };
        let project_flag = format!("--project={}", self.project_id);

        if cmd::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "images",
                "describe",
                &image_name,
                &project_flag,
            ],
        )
        .await
        {
            cmd::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "images",
                    "delete",
                    &self.image_name,
                    &project_flag,
                    "--quiet",
                ],
                self.quiet,
            )
            .await?;
        }
        Ok(())
    }
}

// ── Compute ───────────────────────────────────────────────────────

#[async_trait]
impl Compute for Gcp {
    async fn create_instance(&mut self, metadata: &Metadata) -> Result<InstanceInfo> {
        let cc_type = if self.vm_type.starts_with("n2d-") {
            "SEV_SNP"
        } else {
            "TDX"
        };

        let project_flag = format!("--project={}", self.project_id);
        let zone_flag = format!("--zone={}", self.zone);

        // Build --metadata value: serial-port-enable=1 + user-supplied metadata.
        let mut meta_pairs: Vec<String> = vec![
            "serial-port-enable=1".into(),
            "serial-port-logging-enable=1".into(),
        ];
        for (key, value) in metadata {
            meta_pairs.push(format!("{key}={value}"));
        }
        let metadata_value = meta_pairs.join(",");

        let mut args: Vec<String> = vec![
            "compute".into(),
            "instances".into(),
            "create".into(),
            self.vm_name.clone(),
            format!("--machine-type={}", self.vm_type),
            zone_flag,
            format!("--confidential-compute-type={}", cc_type),
            "--maintenance-policy=TERMINATE".into(),
            format!("--image-project={}", self.project_id),
            format!("--image={}", self.image_name),
            "--shielded-secure-boot".into(),
            "--shielded-vtpm".into(),
            "--shielded-integrity-monitoring".into(),
            project_flag,
            "--tags".into(),
            self.firewall_rule_name.clone(),
            "--metadata".into(),
            metadata_value,
        ];

        // Attach data disks.
        for disk in &self.data_disks {
            args.push(format!(
                "--disk=name={},device-name={},auto-delete=no,boot=no",
                disk.attached_name, disk.name
            ));
        }

        info!("Creating CVM instance");
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        cmd::run_cmd("gcloud", &arg_refs, self.quiet).await?;

        self.instance_info(&self.vm_name.clone()).await
    }

    async fn destroy_instance(&mut self, name: &str) -> Result<()> {
        let project_flag = format!("--project={}", self.project_id);
        let zone_flag = format!("--zone={}", self.zone);

        cmd::run_cmd(
            "gcloud",
            &[
                "compute",
                "instances",
                "delete",
                name,
                &zone_flag,
                &project_flag,
                "--quiet",
            ],
            self.quiet,
        )
        .await?;

        Ok(())
    }

    async fn instance_info(&self, name: &str) -> Result<InstanceInfo> {
        let ip = cmd::try_capture(
            "gcloud",
            &[
                "compute",
                "instances",
                "describe",
                name,
                &format!("--zone={}", self.zone),
                &format!("--project={}", self.project_id),
                "--format=get(networkInterfaces[0].accessConfigs[0].natIP)",
            ],
        )
        .await;

        Ok(InstanceInfo {
            name: name.to_string(),
            public_ip: ip,
        })
    }
}

// ── Networking ────────────────────────────────────────────────────

#[async_trait]
impl Networking for Gcp {
    async fn open_ports(&mut self, _ports: &[PortRule]) -> Result<()> {
        let project_flag = format!("--project={}", self.project_id);

        // Delete existing rule if present.
        if cmd::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "describe",
                &self.firewall_rule_name,
                &project_flag,
            ],
        )
        .await
        {
            info!("Deleting existing firewall rule");
            cmd::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "firewall-rules",
                    "delete",
                    &self.firewall_rule_name,
                    &project_flag,
                    "--quiet",
                ],
                self.quiet,
            )
            .await?;
        }

        info!("Creating firewall rule");
        cmd::run_cmd(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "create",
                &self.firewall_rule_name,
                &project_flag,
                "--allow",
                &self.firewall_allow,
                "--target-tags",
                &self.firewall_rule_name,
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
        )
        .await?;

        Ok(())
    }

    async fn close_ports(&mut self) -> Result<()> {
        let project_flag = format!("--project={}", self.project_id);

        if cmd::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "firewall-rules",
                "describe",
                &self.firewall_rule_name,
                &project_flag,
            ],
        )
        .await
        {
            cmd::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "firewall-rules",
                    "delete",
                    &self.firewall_rule_name,
                    &project_flag,
                    "--quiet",
                ],
                self.quiet,
            )
            .await?;
        }

        Ok(())
    }
}

// ── BlockStorage ──────────────────────────────────────────────────

#[async_trait]
impl BlockStorage for Gcp {
    async fn create_disk(&mut self, name: &str, size: &str) -> Result<()> {
        let zone_flag = format!("--zone={}", self.zone);
        let project_flag = format!("--project={}", self.project_id);

        // Check if disk already exists.
        let exists = cmd::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "disks",
                "describe",
                name,
                &zone_flag,
                &project_flag,
            ],
        )
        .await;

        if exists {
            info!(disk = %name, "Disk already exists");
        } else {
            info!(disk = %name, size = %size, "Creating new data disk");
            let size_flag = format!("--size={size}");
            cmd::run_cmd(
                "gcloud",
                &[
                    "compute",
                    "disks",
                    "create",
                    name,
                    &size_flag,
                    "--type=pd-balanced",
                    &zone_flag,
                    &project_flag,
                ],
                self.quiet,
            )
            .await?;
        }

        // Track disk for attachment during instance creation.
        self.data_disks.push(GcpDataDisk {
            name: name.to_string(),
            attached_name: name.to_string(),
        });

        Ok(())
    }

    async fn delete_disk(&mut self, name: &str) -> Result<()> {
        let zone_flag = format!("--zone={}", self.zone);
        let project_flag = format!("--project={}", self.project_id);

        cmd::run_cmd(
            "gcloud",
            &[
                "compute",
                "disks",
                "delete",
                name,
                &zone_flag,
                &project_flag,
                "--quiet",
            ],
            self.quiet,
        )
        .await?;

        Ok(())
    }

    async fn disk_exists(&self, name: &str) -> Result<bool> {
        let zone_flag = format!("--zone={}", self.zone);
        let project_flag = format!("--project={}", self.project_id);

        Ok(cmd::run_cmd_silent(
            "gcloud",
            &[
                "compute",
                "disks",
                "describe",
                name,
                &zone_flag,
                &project_flag,
            ],
        )
        .await)
    }
}

// ── Logs ──────────────────────────────────────────────────────────

#[async_trait]
impl Logs for Gcp {
    async fn serial_logs(&self, name: &str) -> Result<String> {
        let output = cmd::try_capture(
            "gcloud",
            &[
                "compute",
                "instances",
                "get-serial-port-output",
                name,
                &format!("--zone={}", self.zone),
                &format!("--project={}", self.project_id),
            ],
        )
        .await;

        match output {
            Some(logs) => Ok(logs),
            None => bail!("Failed to retrieve serial logs for VM '{name}'"),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Derive region from zone by stripping the trailing `-<letter>` suffix.
/// e.g. `"asia-southeast1-b"` -> `"asia-southeast1"`
fn zone_to_region(zone: &str) -> String {
    match zone.rsplit_once('-') {
        Some((prefix, _)) => prefix.to_string(),
        None => zone.to_string(),
    }
}

/// Build the GCP firewall `--allow` value from port rules.
///
/// Always includes the default agent port (`tcp:8000`).
fn build_firewall_allow(port_rules: &[PortRule]) -> String {
    let mut entries: Vec<String> = vec!["tcp:8000".to_string()];

    for rule in port_rules {
        let proto = match rule.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        let entry = format!("{}:{}", proto, rule.port);
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }

    entries.join(",")
}

