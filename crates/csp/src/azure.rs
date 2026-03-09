use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tracing::info;

use crate::cmd;
use crate::{
    BlockStorage, CloudProvider, Compute, DataDiskConfig, DiskFormat, ImageManager, InstanceInfo,
    Logs, Metadata, Networking, PortRule, Protocol,
};

// ── Configuration ─────────────────────────────────────────────────

/// Configuration for creating an [`Azure`] provider instance.
pub struct AzureConfig {
    pub vm_name: String,
    pub vm_type: Option<String>,
    pub region: Option<String>,
    pub resource_group: Option<String>,
    pub storage_account: Option<String>,
    pub container_name: Option<String>,
    /// Directory containing secure boot certificates (PK.crt, KEK.crt, db.crt, kernel.crt).
    pub secure_boot_dir: Option<PathBuf>,
    /// Port rules for firewall configuration.
    pub port_rules: Vec<PortRule>,
    /// Data disks to attach to the instance.
    pub data_disks: Vec<DataDiskConfig>,
    /// Optional gallery name override (defaults to "{vm_name}Gallery" with hyphens removed).
    pub gallery_name: Option<String>,
    /// Run without confirmation prompts.
    pub quiet: bool,
}

// ── Provider ──────────────────────────────────────────────────────

/// Internal state for a data disk to attach during instance creation.
struct AzureDataDisk {
    /// Disk resource name.
    name: String,
}

pub struct Azure {
    vm_name: String,
    vm_type: String,
    region: String,
    resource_group: String,
    storage_account: String,
    container_name: String,
    secure_boot_dir: Option<PathBuf>,
    gallery_name: String,
    nsg_name: String,
    firewall_allow: Vec<PortRule>,
    data_disks: Vec<AzureDataDisk>,
    /// SIG image version (e.g., "0.1.4"), set during upload_image.
    image_version: String,
    /// Set after upload_image completes the SIG flow.
    gallery_image_id: Option<String>,
    quiet: bool,
}

impl Azure {
    pub async fn new(config: AzureConfig) -> Result<Self> {
        let vm_type = config.vm_type.unwrap_or_else(|| "Standard_DC2es_v6".into());
        let region = config.region.unwrap_or_else(|| "East US".into());
        let resource_group = config
            .resource_group
            .unwrap_or_else(|| format!("{}_Rg", config.vm_name));

        // Storage account names are globally unique (lowercase + digits, 3-24 chars).
        // Include a short region code so the same project in different regions won't
        // collide. Format: {name}0{region_code}.
        let storage_account = config.storage_account.unwrap_or_else(|| {
            let region_code = short_region_code(&region);
            let prefix_limit = 23 - region_code.len();
            let mut name: String = cmd::sanitize_name(&config.vm_name)
                .chars()
                .take(prefix_limit)
                .collect();
            name.push('0');
            name.push_str(&region_code);
            while name.len() < 3 {
                name.push('0');
            }
            name
        });

        let container_name = config.container_name.unwrap_or_else(|| "workloads".into());

        // Gallery name: no hyphens allowed, alphanumeric + dots + underscores only.
        let gallery_name = config.gallery_name.unwrap_or_else(|| {
            let sanitized: String = config
                .vm_name
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
                .collect();
            format!("{}Gallery", sanitized)
        });

        let nsg_name = format!("{}-{}", config.vm_name, short_region_code(&region));

        info!(
            platform = "Azure",
            vm_name = %config.vm_name,
            vm_type = %vm_type,
            region = %region,
            resource_group = %resource_group,
            storage_account = %storage_account,
            gallery_name = %gallery_name,
            "Configuration"
        );

        Ok(Self {
            vm_name: config.vm_name,
            vm_type,
            region,
            resource_group,
            storage_account,
            container_name,
            secure_boot_dir: config.secure_boot_dir,
            gallery_name,
            nsg_name,
            firewall_allow: config.port_rules,
            data_disks: config
                .data_disks
                .into_iter()
                .map(|d| AzureDataDisk { name: d.name })
                .collect(),
            image_version: DEFAULT_IMAGE_VERSION.to_string(),
            gallery_image_id: None,
            quiet: config.quiet,
        })
    }
}

// ── CloudProvider ─────────────────────────────────────────────────

#[async_trait]
impl CloudProvider for Azure {
    fn name(&self) -> &str {
        "azure"
    }

    fn disk_format(&self) -> DiskFormat {
        DiskFormat::Vhd
    }

    async fn check_deps(&self) -> Result<()> {
        if !cmd::command_exists("az").await {
            bail!(
                "Azure CLI (az) not found. Install it from https://aka.ms/InstallAzureCLIDeb"
            );
        }
        Ok(())
    }
}

// ── ImageManager ──────────────────────────────────────────────────

/// Sanitize a version string for Azure resource names.
///
/// Same transformation as GCP: `"automata-linux:v0.1.4-debug"` → `"automata-linux-v0-1-4-debug"`.
fn sanitize_version(version: &str) -> String {
    version.replace([':', '.'], "-")
}

/// Derive the SIG image definition name from a version string (or fall back to vm_name).
///
/// Each base-image version gets its own image definition so existing images can be reused.
fn image_def_name(version: Option<&str>, vm_name: &str) -> String {
    match version {
        Some(v) => sanitize_version(v),
        None => format!("{}-def", vm_name),
    }
}

/// Default SIG image version when no version can be extracted.
const DEFAULT_IMAGE_VERSION: &str = "1.0.0";

/// Extract a SIG-compatible image version (x.y.z) from a base-image version string.
///
/// Examples:
/// - `"automata-linux:v0.1.4-debug"` → `"0.1.4"`
/// - `"v0.1.4"`                      → `"0.1.4"`
/// - `"0.2.0"`                       → `"0.2.0"`
/// - `None` / unparseable            → `"1.0.0"`
fn extract_image_version(version: Option<&str>) -> String {
    let Some(v) = version else {
        return DEFAULT_IMAGE_VERSION.to_string();
    };
    // Find a pattern like "v?MAJOR.MINOR.PATCH" anywhere in the string.
    // Scan for the first digit sequence followed by `.digit.digit`.
    for (i, c) in v.char_indices() {
        if !c.is_ascii_digit() {
            continue;
        }
        // Try to parse x.y.z starting at position i.
        let rest = &v[i..];
        let parts: Vec<&str> = rest.splitn(4, '.').collect();
        if parts.len() >= 3 {
            // Strip any non-digit suffix from the patch part (e.g., "4-debug" → "4").
            let major = parts[0];
            let minor = parts[1];
            let patch: String = parts[2].chars().take_while(|c| c.is_ascii_digit()).collect();
            if !major.is_empty() && !minor.is_empty() && !patch.is_empty() {
                return format!("{}.{}.{}", major, minor, patch);
            }
        }
    }
    DEFAULT_IMAGE_VERSION.to_string()
}

#[async_trait]
impl ImageManager for Azure {
    async fn upload_image(
        &mut self,
        disk_path: &Path,
        version: Option<&str>,
        force: bool,
    ) -> Result<()> {
        self.image_version = extract_image_version(version);
        let def_name = image_def_name(version, &self.vm_name);

        // Use version-based blob name (like GCP) so each base-image has its own blob.
        let blob_name = match version {
            Some(v) => format!("{}.vhd", sanitize_version(v)),
            None => disk_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "disk.vhd".into()),
        };

        // Check if SIG image already exists for this version — if so, reuse it.
        if !force && self.image_exists(version).await {
            info!(image = %def_name, "SIG image already exists, skipping upload");
            self.gallery_image_id = Some(self.fetch_gallery_image_id(&def_name).await?);
            return Ok(());
        }

        // Force: delete existing image first.
        if force && self.image_exists(version).await {
            info!(image = %def_name, "Force flag set, deleting existing SIG image");
            self.delete_sig_image(&def_name).await?;
        }

        // 1. Create resource group.
        info!("Creating resource group");
        cmd::run_cmd(
            "az",
            &[
                "group",
                "create",
                "--name",
                &self.resource_group,
                "--location",
                &self.region,
            ],
            self.quiet,
        )
        .await?;

        // 2. Ensure storage account exists in our resource group.
        self.ensure_storage_account().await?;

        // 3. Create blob container.
        cmd::run_cmd(
            "az",
            &[
                "storage",
                "container",
                "create",
                "--name",
                &self.container_name,
                "--account-name",
                &self.storage_account,
            ],
            self.quiet,
        )
        .await?;

        // 4. Upload VHD as page blob (skip if blob already exists).
        let blob_exists = cmd::run_cmd_silent(
            "az",
            &[
                "storage",
                "blob",
                "show",
                "--account-name",
                &self.storage_account,
                "--container-name",
                &self.container_name,
                "--name",
                &blob_name,
            ],
        )
        .await;

        if blob_exists {
            info!(blob = %blob_name, "VHD blob already exists, skipping upload");
        } else {
            info!(blob = %blob_name, "Uploading VHD as page blob");
            self.upload_vhd_blob(disk_path, &blob_name).await?;
        }

        // 5. Create Shared Image Gallery (if not exists).
        let gallery_exists = cmd::run_cmd_silent(
            "az",
            &[
                "sig",
                "show",
                "--gallery-name",
                &self.gallery_name,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await;

        if gallery_exists {
            info!(gallery = %self.gallery_name, "Shared Image Gallery already exists");
        } else {
            info!(gallery = %self.gallery_name, "Creating Shared Image Gallery");
            cmd::run_cmd(
                "az",
                &[
                    "sig",
                    "create",
                    "--gallery-name",
                    &self.gallery_name,
                    "--resource-group",
                    &self.resource_group,
                    "--location",
                    &self.region,
                ],
                self.quiet,
            )
            .await?;
        }

        // 7. Create image definition (if not exists).
        let def_exists = cmd::run_cmd_silent(
            "az",
            &[
                "sig",
                "image-definition",
                "show",
                "--gallery-name",
                &self.gallery_name,
                "--gallery-image-definition",
                &def_name,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await;

        if def_exists {
            info!(image_def = %def_name, "SIG image definition already exists");
        } else {
            info!(image_def = %def_name, "Creating SIG image definition");
            cmd::run_cmd(
                "az",
                &[
                    "sig",
                    "image-definition",
                    "create",
                    "--gallery-name",
                    &self.gallery_name,
                    "--gallery-image-definition",
                    &def_name,
                    "--resource-group",
                    &self.resource_group,
                    "--location",
                    &self.region,
                    "--os-type",
                    "Linux",
                    "--os-state",
                    "specialized",
                    "--hyper-v-generation",
                    "V2",
                    "--publisher",
                    "atakit",
                    "--offer",
                    &self.vm_name,
                    "--sku",
                    &self.vm_name,
                    "--features",
                    "SecurityType=TrustedLaunchAndConfidentialVmSupported",
                ],
                self.quiet,
            )
            .await?;
        }

        // 9. Create image version — with or without secure boot certs.
        let blob_url = format!(
            "https://{}.blob.core.windows.net/{}/{}",
            self.storage_account, self.container_name, blob_name
        );

        // Get storage account ID — must be in same resource group as gallery.
        let sa_id = cmd::capture(
            "az",
            &[
                "storage",
                "account",
                "show",
                "--name",
                &self.storage_account,
                "--resource-group",
                &self.resource_group,
                "--query",
                "id",
                "--output",
                "tsv",
            ],
        )
        .await?;

        if let Some(ref sb_dir) = self.secure_boot_dir {
            self.create_image_version_with_secureboot(&blob_url, &sa_id, sb_dir, &def_name)
                .await?;
        } else {
            self.create_image_version_simple(&blob_url, &sa_id, &def_name)
                .await?;
        }

        // 10. Poll provisioning state until Succeeded or Failed.
        info!("Waiting for image version provisioning");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let state = cmd::try_capture(
                "az",
                &[
                    "sig",
                    "image-version",
                    "show",
                    "--gallery-name",
                    &self.gallery_name,
                    "--gallery-image-definition",
                    &def_name,
                    "--gallery-image-version",
                    &self.image_version,
                    "--resource-group",
                    &self.resource_group,
                    "--query",
                    "provisioningState",
                    "--output",
                    "tsv",
                ],
            )
            .await;
            match state.as_deref() {
                Some("Succeeded") => {
                    info!("Image version provisioning succeeded");
                    break;
                }
                Some("Failed") => {
                    // Use --expand ReplicationStatus to get the actual error message.
                    let detail = cmd::try_capture(
                        "az",
                        &[
                            "sig",
                            "image-version",
                            "show",
                            "--gallery-name",
                            &self.gallery_name,
                            "--gallery-image-definition",
                            &def_name,
                            "--gallery-image-version",
                            &self.image_version,
                            "--resource-group",
                            &self.resource_group,
                            "--expand",
                            "ReplicationStatus",
                        ],
                    )
                    .await;
                    bail!(
                        "SIG image version provisioning failed.\n{}",
                        detail.unwrap_or_default()
                    );
                }
                other => {
                    info!(state = ?other, "Still provisioning...");
                }
            }
        }

        // 11. Clean up the intermediate VHD blob from storage.
        info!(blob = %blob_name, "Removing uploaded VHD blob");
        let _ = cmd::run_cmd(
            "az",
            &[
                "storage",
                "blob",
                "delete",
                "--account-name",
                &self.storage_account,
                "--container-name",
                &self.container_name,
                "--name",
                &blob_name,
            ],
            self.quiet,
        )
        .await;

        // 12. Get gallery image ID.
        self.gallery_image_id = Some(self.fetch_gallery_image_id(&def_name).await?);
        info!(gallery_image_id = ?self.gallery_image_id, "SIG image ready");

        Ok(())
    }

    async fn image_exists(&self, version: Option<&str>) -> bool {
        let def_name = image_def_name(version, &self.vm_name);
        cmd::run_cmd_silent(
            "az",
            &[
                "sig",
                "image-version",
                "show",
                "--gallery-name",
                &self.gallery_name,
                "--gallery-image-definition",
                &def_name,
                "--gallery-image-version",
                &self.image_version,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await
    }

    async fn delete_image(&mut self, version: Option<&str>) -> Result<()> {
        // Ensure image_version matches the actual SIG version.
        // Without this, image_version stays at the default "1.0.0" when
        // delete_image is called without a prior upload_image (e.g., destroy).
        self.image_version = extract_image_version(version);
        let def_name = image_def_name(version, &self.vm_name);
        self.delete_sig_image(&def_name).await?;
        self.gallery_image_id = None;
        Ok(())
    }
}

impl Azure {
    /// Ensure the storage account exists in our resource group; create if needed.
    async fn ensure_storage_account(&self) -> Result<()> {
        let exists = cmd::run_cmd_silent(
            "az",
            &[
                "storage",
                "account",
                "show",
                "--name",
                &self.storage_account,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await;

        if exists {
            info!(storage_account = %self.storage_account, "Storage account already exists");
        } else {
            info!(storage_account = %self.storage_account, "Creating storage account");
            cmd::run_cmd(
                "az",
                &[
                    "storage",
                    "account",
                    "create",
                    "--name",
                    &self.storage_account,
                    "--resource-group",
                    &self.resource_group,
                    "--location",
                    &self.region,
                    "--sku",
                    "Standard_LRS",
                ],
                self.quiet,
            )
            .await?;
        }
        Ok(())
    }

    /// Upload a VHD file as a page blob. Uses `azcopy` for parallel transfer
    /// if available, otherwise falls back to `az storage blob upload`.
    async fn upload_vhd_blob(&self, disk_path: &Path, blob_name: &str) -> Result<()> {
        if cmd::command_exists("azcopy").await {
            self.upload_vhd_azcopy(disk_path, blob_name).await
        } else {
            info!("azcopy not found, falling back to az storage blob upload");
            self.upload_vhd_az_cli(disk_path, blob_name).await
        }
    }

    /// Upload via `azcopy copy ... --blob-type PageBlob` (fast, parallel).
    async fn upload_vhd_azcopy(&self, disk_path: &Path, blob_name: &str) -> Result<()> {
        // SAS expiry: 1 hour from now.
        let expiry = sas_expiry_utc();

        let sas_token = cmd::capture(
            "az",
            &[
                "storage",
                "account",
                "generate-sas",
                "--account-name",
                &self.storage_account,
                "--permissions",
                "rwdlacup",
                "--services",
                "b",
                "--resource-types",
                "sco",
                "--expiry",
                &expiry,
                "--output",
                "tsv",
            ],
        )
        .await?;

        let blob_url_with_sas = format!(
            "https://{}.blob.core.windows.net/{}/{}?{}",
            self.storage_account, self.container_name, blob_name, sas_token
        );

        info!("Uploading VHD via azcopy (parallel transfer)");
        cmd::run_cmd(
            "azcopy",
            &[
                "copy",
                &disk_path.to_string_lossy(),
                &blob_url_with_sas,
                "--blob-type",
                "PageBlob",
                "--overwrite",
                "true",
            ],
            self.quiet,
        )
        .await
    }

    /// Upload via `az storage blob upload --type page` (slower fallback).
    async fn upload_vhd_az_cli(&self, disk_path: &Path, blob_name: &str) -> Result<()> {
        let account_key = cmd::capture(
            "az",
            &[
                "storage",
                "account",
                "keys",
                "list",
                "--account-name",
                &self.storage_account,
                "--resource-group",
                &self.resource_group,
                "--query",
                "[0].value",
                "--output",
                "tsv",
            ],
        )
        .await?;

        cmd::run_cmd(
            "az",
            &[
                "storage",
                "blob",
                "upload",
                "--account-name",
                &self.storage_account,
                "--account-key",
                &account_key,
                "--container-name",
                &self.container_name,
                "--name",
                blob_name,
                "--file",
                &disk_path.to_string_lossy(),
                "--type",
                "page",
                "--overwrite",
            ],
            self.quiet,
        )
        .await
    }

    /// Create SIG image version without secure boot certificates.
    /// Create SIG image version without custom secure boot certs via `az rest`.
    ///
    /// Uses `MicrosoftUefiCertificateAuthorityTemplate` so the image version
    /// has a `securityProfile`, which Azure requires for ConfidentialVM (TDX/SNP).
    async fn create_image_version_simple(
        &self,
        blob_url: &str,
        sa_id: &str,
        def_name: &str,
    ) -> Result<()> {
        info!("Creating SIG image version (MicrosoftUefiCertificateAuthorityTemplate)");

        let subscription_id = cmd::capture(
            "az",
            &["account", "show", "--query", "id", "--output", "tsv"],
        )
        .await?;

        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/galleries/{}/images/{}/versions/{}?api-version=2024-03-03",
            subscription_id, self.resource_group, self.gallery_name, def_name, self.image_version
        );

        let body = format!(
            r#"{{
  "location": "{}",
  "properties": {{
    "publishingProfile": {{
      "targetRegions": [{{ "name": "{}", "regionalReplicaCount": 1 }}]
    }},
    "storageProfile": {{
      "osDiskImage": {{
        "source": {{
          "uri": "{}",
          "storageAccountId": "{}"
        }},
        "hostCaching": "ReadOnly"
      }}
    }},
    "securityProfile": {{
      "uefiSettings": {{
        "signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"]
      }}
    }}
  }}
}}"#,
            self.region, self.region, blob_url, sa_id
        );

        cmd::run_cmd(
            "az",
            &["rest", "--method", "PUT", "--url", &api_url, "--body", &body],
            self.quiet,
        )
        .await
    }

    /// Create SIG image version with secure boot certificates via `az rest`.
    async fn create_image_version_with_secureboot(
        &self,
        blob_url: &str,
        sa_id: &str,
        sb_dir: &Path,
        def_name: &str,
    ) -> Result<()> {
        info!("Creating SIG image version (with secure boot certificates)");

        // Read and base64-encode certificate files.
        let pk_b64 = read_cert_base64(&sb_dir.join("PK.crt"))?;
        let kek_b64 = read_cert_base64(&sb_dir.join("KEK.crt"))?;
        let db_b64 = read_cert_base64(&sb_dir.join("db.crt"))?;
        let kernel_b64 = read_cert_base64(&sb_dir.join("kernel.crt"))?;

        // Collect db values: db.crt + kernel.crt (+ livepatch.crt if present).
        let mut db_values = format!(r#""{}", "{}""#, db_b64, kernel_b64);
        let livepatch = sb_dir.join("livepatch.crt");
        if livepatch.exists() {
            let lp_b64 = read_cert_base64(&livepatch)?;
            db_values.push_str(&format!(r#", "{}""#, lp_b64));
        }

        // Build the JSON body for az rest.
        let subscription_id = cmd::capture(
            "az",
            &["account", "show", "--query", "id", "--output", "tsv"],
        )
        .await?;

        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/galleries/{}/images/{}/versions/{}?api-version=2024-03-03",
            subscription_id, self.resource_group, self.gallery_name, def_name, self.image_version
        );

        let body = format!(
            r#"{{
  "location": "{}",
  "properties": {{
    "publishingProfile": {{
      "targetRegions": [{{ "name": "{}", "regionalReplicaCount": 1 }}]
    }},
    "storageProfile": {{
      "osDiskImage": {{
        "source": {{
          "uri": "{}",
          "storageAccountId": "{}"
        }},
        "hostCaching": "ReadOnly"
      }}
    }},
    "securityProfile": {{
      "uefiSettings": {{
        "signatureTemplateNames": ["NoSignatureTemplate"],
        "additionalSignatures": {{
          "pk": {{
            "type": "x509",
            "value": ["{}"]
          }},
          "kek": [{{
            "type": "x509",
            "value": ["{}"]
          }}],
          "db": [{{
            "type": "x509",
            "value": [{}]
          }}]
        }}
      }}
    }}
  }}
}}"#,
            self.region, self.region, blob_url, sa_id, pk_b64, kek_b64, db_values
        );

        cmd::run_cmd(
            "az",
            &["rest", "--method", "PUT", "--url", &api_url, "--body", &body],
            self.quiet,
        )
        .await
    }

    /// Fetch the gallery image ID from a completed SIG image version.
    async fn fetch_gallery_image_id(&self, def_name: &str) -> Result<String> {
        cmd::capture(
            "az",
            &[
                "sig",
                "image-version",
                "show",
                "--gallery-name",
                &self.gallery_name,
                "--gallery-image-definition",
                def_name,
                "--gallery-image-version",
                &self.image_version,
                "--resource-group",
                &self.resource_group,
                "--query",
                "id",
                "--output",
                "tsv",
            ],
        )
        .await
    }

    /// Delete a SIG image version + definition by name.
    async fn delete_sig_image(&self, def_name: &str) -> Result<()> {
        // Delete image version first.
        if cmd::run_cmd_silent(
            "az",
            &[
                "sig",
                "image-version",
                "show",
                "--gallery-name",
                &self.gallery_name,
                "--gallery-image-definition",
                def_name,
                "--gallery-image-version",
                &self.image_version,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await
        {
            info!("Deleting SIG image version");
            cmd::run_cmd(
                "az",
                &[
                    "sig",
                    "image-version",
                    "delete",
                    "--gallery-name",
                    &self.gallery_name,
                    "--gallery-image-definition",
                    def_name,
                    "--gallery-image-version",
                    &self.image_version,
                    "--resource-group",
                    &self.resource_group,
                ],
                self.quiet,
            )
            .await?;

            info!("Waiting for image version deletion");
            cmd::run_cmd(
                "az",
                &[
                    "sig",
                    "image-version",
                    "wait",
                    "--deleted",
                    "--gallery-name",
                    &self.gallery_name,
                    "--gallery-image-definition",
                    def_name,
                    "--gallery-image-version",
                    &self.image_version,
                    "--resource-group",
                    &self.resource_group,
                ],
                self.quiet,
            )
            .await?;
        }

        // Then delete image definition.
        if cmd::run_cmd_silent(
            "az",
            &[
                "sig",
                "image-definition",
                "show",
                "--gallery-name",
                &self.gallery_name,
                "--gallery-image-definition",
                def_name,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await
        {
            info!("Deleting SIG image definition");
            cmd::run_cmd(
                "az",
                &[
                    "sig",
                    "image-definition",
                    "delete",
                    "--gallery-name",
                    &self.gallery_name,
                    "--gallery-image-definition",
                    def_name,
                    "--resource-group",
                    &self.resource_group,
                ],
                self.quiet,
            )
            .await?;
        }

        Ok(())
    }
}

/// Derive a short region code for storage account naming.
///
/// Takes the first letter of each word (lowercase).
/// `"Southeast Asia"` → `"sa"`, `"East US"` → `"eu"`, `"West Europe"` → `"we"`.
fn short_region_code(region: &str) -> String {
    let code: String = region
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if code.is_empty() {
        "x".to_string()
    } else {
        code
    }
}

/// Read a certificate file and return its base64-encoded contents.
fn read_cert_base64(path: &Path) -> Result<String> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read certificate {}: {}", path.display(), e))?;
    Ok(BASE64.encode(&data))
}

/// Return a UTC timestamp 1 hour from now, formatted for `az storage account generate-sas --expiry`.
fn sas_expiry_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    // Convert epoch seconds to "YYYY-MM-DDTHH:MMZ".
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    // Calculate year/month/day from days since 1970-01-01.
    let (year, month, day) = epoch_days_to_ymd(days_since_epoch);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}Z", year, month, day, hours, minutes)
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Shift epoch from 1970-01-01 to 2000-03-01 for easier leap-year math.
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ── Compute ───────────────────────────────────────────────────────

#[async_trait]
impl Compute for Azure {
    async fn create_instance(&mut self, metadata: &Metadata) -> Result<InstanceInfo> {
        let gallery_image_id = self
            .gallery_image_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No gallery image ID — upload_image must run first"))?
            .clone();

        let mut args: Vec<String> = vec![
            "vm".into(),
            "create".into(),
            "--resource-group".into(),
            self.resource_group.clone(),
            "--name".into(),
            self.vm_name.clone(),
            "--size".into(),
            self.vm_type.clone(),
            "--location".into(),
            self.region.clone(),
            "--security-type".into(),
            "ConfidentialVM".into(),
            "--os-disk-security-encryption-type".into(),
            "VMGuestStateOnly".into(),
            "--enable-vtpm".into(),
            "true".into(),
            "--enable-secure-boot".into(),
            "true".into(),
            "--image".into(),
            gallery_image_id,
            "--specialized".into(),
            "--public-ip-sku".into(),
            "Standard".into(),
            "--nsg".into(),
            self.nsg_name.clone(),
            "--boot-diagnostics-storage".into(),
            format!("https://{}.blob.core.windows.net/", self.storage_account),
            "--admin-username".into(),
            "dummyuser".into(),
            "--admin-password".into(),
            "DummyPassword123!".into(),
        ];

        // Attach data disks.
        if !self.data_disks.is_empty() {
            args.push("--attach-data-disks".into());
            for disk in &self.data_disks {
                args.push(disk.name.clone());
            }
        }

        // Metadata as --tags key=value.
        if !metadata.is_empty() {
            args.push("--tags".into());
            for (key, value) in metadata {
                args.push(format!("{key}={value}"));
            }
        }

        info!("Creating CVM instance");
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        cmd::run_cmd("az", &arg_refs, self.quiet).await?;

        self.instance_info(&self.vm_name.clone()).await
    }

    async fn destroy_instance(&mut self, name: &str) -> Result<()> {
        info!("Deleting VM");
        cmd::run_cmd(
            "az",
            &[
                "vm", "delete",
                "--resource-group", &self.resource_group,
                "--name", name,
                "--yes",
            ],
            self.quiet,
        )
        .await
    }

    async fn instance_info(&self, name: &str) -> Result<InstanceInfo> {
        let ip = cmd::try_capture(
            "az",
            &[
                "vm",
                "show",
                "--resource-group",
                &self.resource_group,
                "--name",
                name,
                "--show-details",
                "--query",
                "publicIps",
                "--output",
                "tsv",
            ],
        )
        .await;

        Ok(InstanceInfo {
            name: name.to_string(),
            public_ip: ip,
        })
    }
}

// ── VM resource cleanup ───────────────────────────────────────────

/// Resources associated with an Azure VM, captured before deletion.
pub struct VmResources {
    pub os_disk: Option<String>,
    pub nic_ids: Vec<String>,
    pub public_ip_ids: Vec<String>,
    pub vnet_ids: Vec<String>,
}

impl Azure {
    /// Query the resources associated with a VM (OS disk, NICs, public IPs, VNETs).
    ///
    /// Must be called **before** `destroy_instance` — the VM must still exist.
    pub async fn query_vm_resources(&self, name: &str) -> VmResources {
        let os_disk = cmd::try_capture(
            "az",
            &[
                "vm", "show",
                "--resource-group", &self.resource_group,
                "--name", name,
                "--query", "storageProfile.osDisk.name",
                "--output", "tsv",
            ],
        )
        .await;

        let nic_ids: Vec<String> = cmd::try_capture(
            "az",
            &[
                "vm", "show",
                "--resource-group", &self.resource_group,
                "--name", name,
                "--query", "networkProfile.networkInterfaces[].id",
                "--output", "tsv",
            ],
        )
        .await
        .map(|s| parse_tsv_lines(&s))
        .unwrap_or_default();

        let mut public_ip_ids: Vec<String> = Vec::new();
        let mut vnet_ids: Vec<String> = Vec::new();

        for nic_id in &nic_ids {
            // Public IPs — filter out ipConfigurations where publicIpAddress is null.
            if let Some(pip_output) = cmd::try_capture(
                "az",
                &[
                    "network", "nic", "show",
                    "--ids", nic_id,
                    "--query", "ipConfigurations[?publicIpAddress].publicIpAddress.id",
                    "--output", "tsv",
                ],
            )
            .await
            {
                for id in parse_tsv_lines(&pip_output) {
                    if !public_ip_ids.contains(&id) {
                        public_ip_ids.push(id);
                    }
                }
            }

            // VNETs — extract from subnet resource IDs.
            // Subnet ID format: .../virtualNetworks/{vnet}/subnets/{subnet}
            if let Some(subnet_output) = cmd::try_capture(
                "az",
                &[
                    "network", "nic", "show",
                    "--ids", nic_id,
                    "--query", "ipConfigurations[].subnet.id",
                    "--output", "tsv",
                ],
            )
            .await
            {
                for subnet_id in parse_tsv_lines(&subnet_output) {
                    if let Some(vnet_id) = subnet_id.rsplit_once("/subnets/").map(|(v, _)| v.to_string()) {
                        if !vnet_ids.contains(&vnet_id) {
                            vnet_ids.push(vnet_id);
                        }
                    }
                }
            }
        }

        VmResources { os_disk, nic_ids, public_ip_ids, vnet_ids }
    }

    /// Delete resources that were associated with a (now-deleted) VM.
    pub async fn cleanup_vm_resources(
        &self,
        resources: &VmResources,
        preserve_public_ip: bool,
    ) -> Result<()> {
        if let Some(ref disk_name) = resources.os_disk {
            info!(disk = %disk_name, "Deleting OS disk");
            let _ = cmd::run_cmd(
                "az",
                &[
                    "disk", "delete",
                    "--resource-group", &self.resource_group,
                    "--name", disk_name,
                    "--yes", "--no-wait",
                ],
                self.quiet,
            )
            .await;
        }

        for nic_id in &resources.nic_ids {
            info!("Deleting NIC");
            let _ = cmd::run_cmd(
                "az",
                &["network", "nic", "delete", "--ids", nic_id],
                self.quiet,
            )
            .await;
        }

        if !preserve_public_ip {
            for pip_id in &resources.public_ip_ids {
                info!("Deleting public IP");
                let _ = cmd::run_cmd(
                    "az",
                    &["network", "public-ip", "delete", "--ids", pip_id],
                    self.quiet,
                )
                .await;
            }
        }

        for vnet_id in &resources.vnet_ids {
            info!("Deleting virtual network");
            let _ = cmd::run_cmd(
                "az",
                &["network", "vnet", "delete", "--ids", vnet_id],
                self.quiet,
            )
            .await;
        }

        Ok(())
    }
}

/// Parse TSV output lines, filtering empty lines and `None` literals.
fn parse_tsv_lines(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && l != "None")
        .collect()
}

// ── Networking (NSG) ──────────────────────────────────────────────

#[async_trait]
impl Networking for Azure {
    async fn open_ports(&mut self, _ports: &[PortRule]) -> Result<()> {
        // 1. Create NSG.
        info!(nsg = %self.nsg_name, "Creating network security group");
        cmd::run_cmd(
            "az",
            &[
                "network",
                "nsg",
                "create",
                "--name",
                &self.nsg_name,
                "--resource-group",
                &self.resource_group,
                "--location",
                &self.region,
            ],
            self.quiet,
        )
        .await?;

        // 2. Default rule: attestation agent on port 8000.
        info!("Adding NSG rule for attestation agent (port 8000)");
        cmd::run_cmd(
            "az",
            &[
                "network",
                "nsg",
                "rule",
                "create",
                "--nsg-name",
                &self.nsg_name,
                "--resource-group",
                &self.resource_group,
                "--name",
                "attestation_agent",
                "--priority",
                "100",
                "--destination-port-ranges",
                "8000",
                "--access",
                "Allow",
                "--protocol",
                "Tcp",
                "--direction",
                "Inbound",
            ],
            self.quiet,
        )
        .await?;

        // 3. Additional port rules.
        let mut priority = 200u16;
        for rule in &self.firewall_allow {
            let proto = match rule.protocol {
                Protocol::Tcp => "Tcp",
                Protocol::Udp => "Udp",
            };
            let port_str = rule.port.to_string();
            let rule_name = format!("Workload_{}", rule.port);

            info!(port = rule.port, protocol = proto, "Adding NSG rule");
            cmd::run_cmd(
                "az",
                &[
                    "network",
                    "nsg",
                    "rule",
                    "create",
                    "--nsg-name",
                    &self.nsg_name,
                    "--resource-group",
                    &self.resource_group,
                    "--name",
                    &rule_name,
                    "--priority",
                    &priority.to_string(),
                    "--destination-port-ranges",
                    &port_str,
                    "--access",
                    "Allow",
                    "--protocol",
                    proto,
                    "--direction",
                    "Inbound",
                ],
                self.quiet,
            )
            .await?;

            priority += 10;
        }

        Ok(())
    }

    async fn close_ports(&mut self) -> Result<()> {
        info!(nsg = %self.nsg_name, "Deleting network security group");
        cmd::run_cmd(
            "az",
            &[
                "network",
                "nsg",
                "delete",
                "--name",
                &self.nsg_name,
                "--resource-group",
                &self.resource_group,
            ],
            self.quiet,
        )
        .await?;
        Ok(())
    }
}

// ── BlockStorage ──────────────────────────────────────────────────

#[async_trait]
impl BlockStorage for Azure {
    async fn create_disk(&mut self, name: &str, size: &str) -> Result<()> {
        // --size-gb expects a plain integer; strip any unit suffix like "GB".
        let size_gb: String = size.chars().take_while(|c| c.is_ascii_digit()).collect();

        // Check if disk already exists.
        if self.disk_exists(name).await? {
            info!(disk = %name, "Disk already exists");
        } else {
            info!(disk = %name, size = %size_gb, "Creating managed data disk");
            cmd::run_cmd(
                "az",
                &[
                    "disk",
                    "create",
                    "--name",
                    name,
                    "--resource-group",
                    &self.resource_group,
                    "--location",
                    &self.region,
                    "--size-gb",
                    &size_gb,
                    "--sku",
                    "Premium_LRS",
                    "--encryption-type",
                    "EncryptionAtRestWithPlatformKey",
                ],
                self.quiet,
            )
            .await?;
        }

        // Track for attachment during instance creation.
        self.data_disks.push(AzureDataDisk {
            name: name.to_string(),
        });

        Ok(())
    }

    async fn delete_disk(&mut self, name: &str) -> Result<()> {
        cmd::run_cmd(
            "az",
            &[
                "disk",
                "delete",
                "--name",
                name,
                "--resource-group",
                &self.resource_group,
                "--yes",
            ],
            self.quiet,
        )
        .await
    }

    async fn disk_exists(&self, name: &str) -> Result<bool> {
        Ok(cmd::run_cmd_silent(
            "az",
            &[
                "disk",
                "show",
                "--name",
                name,
                "--resource-group",
                &self.resource_group,
            ],
        )
        .await)
    }
}

// ── Logs ──────────────────────────────────────────────────────────

#[async_trait]
impl Logs for Azure {
    async fn serial_logs(&self, name: &str) -> Result<String> {
        let output = cmd::try_capture(
            "az",
            &[
                "vm",
                "boot-diagnostics",
                "get-boot-log",
                "--resource-group",
                &self.resource_group,
                "--name",
                name,
            ],
        )
        .await;

        match output {
            Some(logs) => Ok(logs),
            None => bail!("Failed to retrieve boot diagnostics for VM '{name}'"),
        }
    }
}
