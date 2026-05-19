use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::CloudError;

/// Cloud platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformKind {
    Gcp,
    Azure,
    Aws,
}

impl std::fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformKind::Gcp => write!(f, "gcp"),
            PlatformKind::Azure => write!(f, "azure"),
            PlatformKind::Aws => write!(f, "aws"),
        }
    }
}

/// Confidential computing type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CcType {
    #[default]
    SevSnp,
    Tdx,
}

impl std::fmt::Display for CcType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CcType::SevSnp => write!(f, "SEV_SNP"),
            CcType::Tdx => write!(f, "TDX"),
        }
    }
}

impl std::str::FromStr for CcType {
    type Err = CloudError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SEV_SNP" => Ok(CcType::SevSnp),
            "TDX" => Ok(CcType::Tdx),
            other => Err(CloudError::Config {
                message: format!("unknown CC type '{other}', expected SEV_SNP or TDX"),
            }),
        }
    }
}

impl CcType {
    /// Minimum CPU platform for instance creation, if required.
    pub fn min_cpu_platform(&self) -> Option<&str> {
        match self {
            CcType::SevSnp => Some("AMD Milan"),
            CcType::Tdx => None,
        }
    }
}

/// GCE `--guest-os-features` flag for image registration.
///
/// For now every image is registered as dual-capable (SEV-SNP + TDX)
/// regardless of the configured CC types — GCP accepts both capability
/// flags on a single image. `SEV_CAPABLE` (plain SEV) is intentionally
/// omitted: only SEV-SNP is supported.
pub fn guest_os_features_for(_cc_types: &[CcType]) -> String {
    "--guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE"
        .to_string()
}

/// Per-image registration config in `[cloud.images]`.
///
/// Supports two TOML forms:
/// ```toml
/// "img:v1" = ["SEV_SNP", "TDX"]
/// "img:v2" = { cc_types = ["SEV_SNP", "TDX"] }
/// ```
#[derive(Debug, Clone)]
pub struct CloudImageEntry {
    pub cc_types: Vec<CcType>,
}

impl<'de> Deserialize<'de> for CloudImageEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Simple(Vec<CcType>),
            Extended { cc_types: Vec<CcType> },
        }
        let cc_types = match Raw::deserialize(deserializer)? {
            Raw::Simple(cc_types) => cc_types,
            Raw::Extended { cc_types } => cc_types,
        };
        if cc_types.is_empty() {
            return Err(serde::de::Error::custom("cc_types must not be empty"));
        }
        Ok(CloudImageEntry { cc_types })
    }
}

/// A named cloud provider (e.g. `[cloud.providers.gcp-sea]`).
#[derive(Debug, Clone, Deserialize)]
pub struct CloudProviderConfig {
    /// Cloud platform.
    pub platform: PlatformKind,
    /// GCP project ID.
    pub project: Option<String>,
    /// Azure subscription ID.
    pub subscription: Option<String>,
    /// Cloud region or zone.
    pub region: String,
}

/// Top-level `[cloud]` configuration section.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CloudConfig {
    /// Default values inherited by targets that omit a field.
    #[serde(default)]
    pub defaults: CloudTargetDefaults,
    /// Named cloud providers: `[cloud.providers]`.
    #[serde(default)]
    pub providers: BTreeMap<String, CloudProviderConfig>,
    /// Image library: `[cloud.images]`.
    #[serde(default)]
    pub images: BTreeMap<String, CloudImageEntry>,
    /// Named cloud targets.
    #[serde(default)]
    pub targets: BTreeMap<String, CloudTarget>,
}

impl CloudConfig {
    /// Fill target fields from `[cloud.defaults]` where the target omits them.
    pub fn apply_defaults(&mut self) {
        let defaults = self.defaults.clone();
        for target in self.targets.values_mut() {
            if target.chain.is_none() {
                target.chain = defaults.chain.clone();
            }
            if target.owner_key.is_none() {
                target.owner_key = defaults.owner_key.clone();
            }
            if target.gas_wallet.is_none() {
                target.gas_wallet = defaults.gas_wallet.clone();
            }
            if target.image.is_none() {
                target.image = defaults.image.clone();
            }
        }
    }
}

/// Default values for cloud targets: `[cloud.defaults]`.
///
/// Any field set here is inherited by targets that omit it.
/// Target-level values always take precedence.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CloudTargetDefaults {
    pub chain: Option<String>,
    pub owner_key: Option<String>,
    pub gas_wallet: Option<String>,
    pub image: Option<String>,
}

/// A named cloud deployment target (e.g. `[cloud.targets.c3-standard-4]`).
#[derive(Debug, Clone, Deserialize)]
pub struct CloudTarget {
    /// Provider name (references a key in `[cloud.providers]`).
    pub provider: String,
    /// VM machine type.
    pub vmtype: String,
    /// Base image reference. Falls back to `[cloud.defaults] image`.
    /// `cloud deploy` enforces that either this, the default, or
    /// the `--image` flag is set.
    #[serde(default)]
    pub image: Option<String>,
    /// Confidential computing type. Optional; inferred from vmtype if absent.
    #[serde(default)]
    pub cc_type: Option<CcType>,
    /// Custom instance name prefix.
    pub name: Option<String>,
    /// Extra metadata key-value pairs.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Override OS boot disk size for this target (e.g. "100GB"). Falls
    /// back to the workload manifest's boot-disk-size if absent. The CLI
    /// `--boot-disk-size` flag overrides this.
    #[serde(default)]
    pub boot_disk_size: Option<String>,
    /// Chain config name (references a key in `[chains]`).
    /// Falls back to `[cloud.defaults] chain`.
    #[serde(default)]
    pub chain: Option<String>,
    /// Owner key name (references a key in `[keys]`, must be provisioned).
    /// Falls back to `[cloud.defaults] owner_key`.
    #[serde(default)]
    pub owner_key: Option<String>,
    /// Gas wallet key name (references a key in `[keys]`).
    /// Falls back to `[cloud.defaults] gas_wallet`.
    #[serde(default)]
    pub gas_wallet: Option<String>,
}

impl CloudTarget {
    /// Returns the CC type, either explicit or inferred from vmtype.
    pub fn resolved_cc_type(&self, platform: PlatformKind) -> Result<CcType, CloudError> {
        if let Some(cc) = self.cc_type {
            return Ok(cc);
        }
        infer_cc_type(platform, &self.vmtype)
    }
}

/// Infer the confidential computing type from the machine type.
pub fn infer_cc_type(platform: PlatformKind, vmtype: &str) -> Result<CcType, CloudError> {
    match platform {
        PlatformKind::Gcp => {
            if vmtype.starts_with("n2d-standard-") {
                Ok(CcType::SevSnp)
            } else if vmtype.starts_with("c3-standard-") {
                Ok(CcType::Tdx)
            } else {
                Err(CloudError::Config {
                    message: format!(
                        "cannot infer CC type from machine type '{vmtype}'. \
                         Use 'n2d-standard-*' (SEV-SNP) or 'c3-standard-*' (TDX), \
                         or set cc_type explicitly."
                    ),
                })
            }
        }
        PlatformKind::Azure => {
            if is_azure_dces_v6(vmtype) {
                Ok(CcType::Tdx)
            } else if is_azure_dcas_v5v6(vmtype) {
                Ok(CcType::SevSnp)
            } else {
                Err(CloudError::Config {
                    message: format!(
                        "cannot infer CC type from VM size '{vmtype}'. \
                         Use 'Standard_DC*es_v6' (TDX) or 'Standard_DC*as_v5/v6' (SEV-SNP), \
                         or set cc_type explicitly."
                    ),
                })
            }
        }
        PlatformKind::Aws => {
            if is_aws_snp_instance(vmtype) {
                // AWS confidential computing is AMD SEV-SNP only; there is
                // no TDX offering.
                Ok(CcType::SevSnp)
            } else {
                Err(CloudError::Config {
                    message: format!(
                        "cannot infer CC type from instance type '{vmtype}'. \
                         AWS confidential VMs require an AMD SEV-SNP instance type \
                         (e.g. 'm6a.large', 'c6a.xlarge', 'r6a.2xlarge'), \
                         or set cc_type explicitly."
                    ),
                })
            }
        }
    }
}

// ── Cloud target validation ─────────────────────────────────────────

const GCP_SNP_ZONES: &[&str] = &[
    "asia-southeast1-a",
    "asia-southeast1-b",
    "asia-southeast1-c",
    "europe-west3-a",
    "europe-west3-b",
    "europe-west3-c",
    "europe-west4-a",
    "europe-west4-b",
    "europe-west4-c",
    "us-central1-a",
    "us-central1-b",
    "us-central1-c",
];

const GCP_TDX_ZONES: &[&str] = &[
    "asia-southeast1-a",
    "asia-southeast1-b",
    "asia-southeast1-c",
    "europe-west4-a",
    "europe-west4-b",
    "europe-west4-c",
    "us-central1-a",
    "us-central1-b",
    "us-central1-c",
];

const AWS_SNP_REGIONS: &[&str] = &["us-east-2", "eu-west-1"];

/// AWS instance type families supporting AMD SEV-SNP.
const AWS_SNP_INSTANCE_FAMILIES: &[&str] = &["m6a", "c6a", "r6a", "m7a", "c7a", "r7a"];

const AZURE_TDX_V6_REGIONS: &[&str] = &["West Europe", "East US", "West US", "West US 3"];

const AZURE_SNP_REGIONS: &[&str] = &[
    "East US",
    "West US",
    "Switzerland North",
    "Italy North",
    "North Europe",
    "West Europe",
    "Germany West Central",
    "UAE North",
    "Japan East",
    "Central India",
    "East Asia",
    "Southeast Asia",
];

/// Valid GCP C3 standard sizes for TDX.
const GCP_C3_SIZES: &[&str] = &["4", "8", "22", "44", "88", "176"];

/// Valid GCP N2D standard sizes for SEV-SNP.
const GCP_N2D_SIZES: &[&str] = &[
    "2", "4", "8", "16", "32", "48", "64", "80", "96", "128", "224",
];

/// Valid Azure DC vCPU counts.
const AZURE_DC_VCPUS: &[&str] = &["2", "4", "8", "16", "32", "48", "64", "96"];

/// Validate that the target's machine type, zone/region form a supported
/// combination. If `cc_type` is set explicitly, validate it matches the
/// inferred type from vmtype.
pub fn validate_target(
    target: &CloudTarget,
    provider: &CloudProviderConfig,
    target_name: &str,
) -> Result<(), CloudError> {
    let err = |msg: String| CloudError::Config {
        message: format!("target '{target_name}': {msg}"),
    };

    // Validate explicit cc_type matches inferred.
    let inferred =
        infer_cc_type(provider.platform, &target.vmtype).map_err(|e| err(e.to_string()))?;
    if let Some(explicit) = target.cc_type {
        if explicit != inferred {
            return Err(err(format!(
                "cc_type '{}' does not match machine type '{}' (which implies {})",
                explicit, target.vmtype, inferred
            )));
        }
    }

    match provider.platform {
        PlatformKind::Gcp => {
            if let Some(size) = target.vmtype.strip_prefix("n2d-standard-") {
                if !GCP_N2D_SIZES.contains(&size) {
                    return Err(err(format!(
                        "unsupported GCP machine type '{}'. \
                         Valid n2d-standard sizes: {}. \
                         Reference: https://cloud.google.com/compute/docs/general-purpose-machines#n2d_machine_types",
                        target.vmtype, GCP_N2D_SIZES.join(", ")
                    )));
                }
                if !GCP_SNP_ZONES.contains(&provider.region.as_str()) {
                    return Err(err(format!(
                        "zone '{}' does not support SEV-SNP VMs. Supported zones: {}",
                        provider.region,
                        GCP_SNP_ZONES.join(", ")
                    )));
                }
            } else if let Some(size) = target.vmtype.strip_prefix("c3-standard-") {
                if !GCP_C3_SIZES.contains(&size) {
                    return Err(err(format!(
                        "unsupported GCP machine type '{}'. \
                         Valid c3-standard sizes: {}. \
                         Reference: https://cloud.google.com/compute/docs/general-purpose-machines#c3_machine_types",
                        target.vmtype, GCP_C3_SIZES.join(", ")
                    )));
                }
                if !GCP_TDX_ZONES.contains(&provider.region.as_str()) {
                    return Err(err(format!(
                        "zone '{}' does not support TDX VMs. Supported zones: {}",
                        provider.region,
                        GCP_TDX_ZONES.join(", ")
                    )));
                }
            } else {
                return Err(err(format!(
                    "unsupported GCP machine type '{}'. \
                     Use 'n2d-standard-*' (SEV-SNP) or 'c3-standard-*' (TDX). \
                     Reference: https://cloud.google.com/compute/docs/general-purpose-machines#n2d_machine_types \
                     Reference: https://cloud.google.com/compute/docs/general-purpose-machines#c3_machine_types",
                    target.vmtype
                )));
            }
        }
        PlatformKind::Azure => {
            let is_tdx_v6 = is_azure_dces_v6(&target.vmtype);
            let is_snp = is_azure_dcas_v5v6(&target.vmtype);

            if is_tdx_v6 {
                if !AZURE_TDX_V6_REGIONS.contains(&provider.region.as_str()) {
                    return Err(err(format!(
                        "region '{}' does not support TDX DCesv6 VMs. Supported regions: {}",
                        provider.region,
                        AZURE_TDX_V6_REGIONS.join(", ")
                    )));
                }
            } else if is_snp {
                if !AZURE_SNP_REGIONS.contains(&provider.region.as_str()) {
                    return Err(err(format!(
                        "region '{}' does not support SEV-SNP VMs. Supported regions: {}",
                        provider.region,
                        AZURE_SNP_REGIONS.join(", ")
                    )));
                }
            } else {
                return Err(err(format!(
                    "unsupported Azure VM size '{}'. \
                     Use 'Standard_DC*as_v5' or 'Standard_DC*as_v6' (SEV-SNP) \
                     or 'Standard_DC*es_v6' (TDX). \
                     Reference: https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasv5-series \
                     Reference: https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasv6-series \
                     Reference: https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcesv6-series",
                    target.vmtype
                )));
            }
        }
        PlatformKind::Aws => {
            if !is_aws_snp_instance(&target.vmtype) {
                return Err(err(format!(
                    "unsupported AWS instance type '{}'. \
                     Use an AMD SEV-SNP instance family: {}. \
                     Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html",
                    target.vmtype,
                    AWS_SNP_INSTANCE_FAMILIES.join(", ")
                )));
            }
            if !AWS_SNP_REGIONS.contains(&provider.region.as_str()) {
                return Err(err(format!(
                    "region '{}' does not support SEV-SNP VMs. Supported regions: {}",
                    provider.region,
                    AWS_SNP_REGIONS.join(", ")
                )));
            }
        }
    }
    Ok(())
}

/// Match an AWS SEV-SNP-capable instance type (e.g. `m6a.large`).
fn is_aws_snp_instance(vmtype: &str) -> bool {
    match vmtype.split_once('.') {
        Some((family, size)) => {
            !size.is_empty() && AWS_SNP_INSTANCE_FAMILIES.contains(&family)
        }
        None => false,
    }
}

/// Match `Standard_DC{2,4,8,16,32,64,96,128}es_v6`.
fn is_azure_dces_v6(vmtype: &str) -> bool {
    let Some(rest) = vmtype.strip_prefix("Standard_DC") else {
        return false;
    };
    let Some(rest) = rest.strip_suffix("es_v6") else {
        return false;
    };
    AZURE_DC_VCPUS.contains(&rest)
}

/// Match `Standard_DC{2,4,8,16,32,64,96,128}as_v{5,6}`.
fn is_azure_dcas_v5v6(vmtype: &str) -> bool {
    let Some(rest) = vmtype.strip_prefix("Standard_DC") else {
        return false;
    };
    let Some(rest) = rest
        .strip_suffix("as_v5")
        .or_else(|| rest.strip_suffix("as_v6"))
    else {
        return false;
    };
    AZURE_DC_VCPUS.contains(&rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider(platform: PlatformKind, region: &str) -> CloudProviderConfig {
        CloudProviderConfig {
            platform,
            project: None,
            subscription: None,
            region: region.to_string(),
        }
    }

    fn make_target(vmtype: &str) -> CloudTarget {
        CloudTarget {
            provider: "test-provider".to_string(),
            vmtype: vmtype.to_string(),
            image: Some("test-image:v1".to_string()),
            cc_type: None,
            name: None,
            metadata: BTreeMap::new(),
            boot_disk_size: None,
            chain: Some("test-chain".to_string()),
            owner_key: Some("test-owner".to_string()),
            gas_wallet: Some("test-gas".to_string()),
        }
    }

    fn make_target_with_cc(vmtype: &str, cc: CcType) -> CloudTarget {
        let mut t = make_target(vmtype);
        t.cc_type = Some(cc);
        t
    }

    // ── GCP SEV-SNP (n2d-standard) ──────────────────────

    #[test]
    fn gcp_snp_valid() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target("n2d-standard-2");
        assert!(validate_target(&t, &p, "test").is_ok());
    }

    #[test]
    fn gcp_snp_all_sizes() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        for size in GCP_N2D_SIZES {
            let vmtype = format!("n2d-standard-{size}");
            let t = make_target(&vmtype);
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected {vmtype} to be valid"
            );
        }
    }

    #[test]
    fn gcp_snp_invalid_size() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target("n2d-standard-7");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported GCP machine type"), "{err}");
        assert!(err.contains("n2d_machine_types"), "{err}");
    }

    #[test]
    fn gcp_snp_all_zones() {
        for zone in GCP_SNP_ZONES {
            let p = make_provider(PlatformKind::Gcp, zone);
            let t = make_target("n2d-standard-8");
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected zone {zone} to be valid"
            );
        }
    }

    #[test]
    fn gcp_snp_bad_zone() {
        let p = make_provider(PlatformKind::Gcp, "us-west1-a");
        let t = make_target("n2d-standard-2");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not support SEV-SNP"), "{err}");
    }

    #[test]
    fn gcp_snp_wrong_cc_type() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target_with_cc("n2d-standard-4", CcType::Tdx);
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    // ── GCP TDX (c3-standard) ───────────────────────────

    #[test]
    fn gcp_tdx_valid() {
        let p = make_provider(PlatformKind::Gcp, "europe-west4-b");
        let t = make_target("c3-standard-4");
        assert!(validate_target(&t, &p, "test").is_ok());
    }

    #[test]
    fn gcp_tdx_all_sizes() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        for size in GCP_C3_SIZES {
            let vmtype = format!("c3-standard-{size}");
            let t = make_target(&vmtype);
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected {vmtype} to be valid"
            );
        }
    }

    #[test]
    fn gcp_tdx_invalid_size() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target("c3-standard-5");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported GCP machine type"), "{err}");
        assert!(err.contains("c3_machine_types"), "{err}");
    }

    #[test]
    fn gcp_tdx_all_zones() {
        for zone in GCP_TDX_ZONES {
            let p = make_provider(PlatformKind::Gcp, zone);
            let t = make_target("c3-standard-4");
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected zone {zone} to be valid"
            );
        }
    }

    #[test]
    fn gcp_tdx_bad_zone() {
        let p = make_provider(PlatformKind::Gcp, "europe-west3-a");
        let t = make_target("c3-standard-4");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not support TDX"), "{err}");
    }

    #[test]
    fn gcp_tdx_wrong_cc_type() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target_with_cc("c3-standard-4", CcType::SevSnp);
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    // ── GCP unsupported machine type ────────────────────

    #[test]
    fn gcp_unsupported_machine_type() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target("e2-standard-4");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("cannot infer CC type"), "{err}");
    }

    // ── Azure TDX (DCes_v6) ─────────────────────────────

    #[test]
    fn azure_tdx_valid() {
        let p = make_provider(PlatformKind::Azure, "East US");
        let t = make_target("Standard_DC4es_v6");
        assert!(validate_target(&t, &p, "test").is_ok());
    }

    #[test]
    fn azure_tdx_all_sizes() {
        let p = make_provider(PlatformKind::Azure, "West Europe");
        for size in AZURE_DC_VCPUS {
            let vmtype = format!("Standard_DC{size}es_v6");
            let t = make_target(&vmtype);
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected {vmtype} to be valid"
            );
        }
    }

    #[test]
    fn azure_tdx_all_regions() {
        for region in AZURE_TDX_V6_REGIONS {
            let p = make_provider(PlatformKind::Azure, region);
            let t = make_target("Standard_DC4es_v6");
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected region {region} to be valid"
            );
        }
    }

    #[test]
    fn azure_tdx_bad_region() {
        let p = make_provider(PlatformKind::Azure, "Japan East");
        let t = make_target("Standard_DC4es_v6");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not support TDX DCesv6"), "{err}");
    }

    #[test]
    fn azure_tdx_wrong_cc_type() {
        let p = make_provider(PlatformKind::Azure, "East US");
        let t = make_target_with_cc("Standard_DC4es_v6", CcType::SevSnp);
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    // ── Azure SEV-SNP (DCas_v5/v6) ──────────────────────

    #[test]
    fn azure_snp_v5_valid() {
        let p = make_provider(PlatformKind::Azure, "East US");
        let t = make_target("Standard_DC4as_v5");
        assert!(validate_target(&t, &p, "test").is_ok());
    }

    #[test]
    fn azure_snp_v6_valid() {
        let p = make_provider(PlatformKind::Azure, "West Europe");
        let t = make_target("Standard_DC8as_v6");
        assert!(validate_target(&t, &p, "test").is_ok());
    }

    #[test]
    fn azure_snp_all_regions() {
        for region in AZURE_SNP_REGIONS {
            let p = make_provider(PlatformKind::Azure, region);
            let t = make_target("Standard_DC2as_v5");
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected region {region} to be valid"
            );
        }
    }

    #[test]
    fn azure_snp_bad_region() {
        let p = make_provider(PlatformKind::Azure, "Brazil South");
        let t = make_target("Standard_DC4as_v5");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not support SEV-SNP"), "{err}");
    }

    #[test]
    fn azure_snp_wrong_cc_type() {
        let p = make_provider(PlatformKind::Azure, "East US");
        let t = make_target_with_cc("Standard_DC4as_v5", CcType::Tdx);
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    // ── Azure unsupported VM size ────────────────────────

    #[test]
    fn azure_unsupported_vm_size() {
        let p = make_provider(PlatformKind::Azure, "East US");
        let t = make_target("Standard_D4s_v5");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("cannot infer CC type"), "{err}");
    }

    #[test]
    fn azure_bad_dc_size_number() {
        let p = make_provider(PlatformKind::Azure, "East US");
        let t = make_target("Standard_DC3es_v6");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("cannot infer CC type"), "{err}");
    }

    // ── AWS SEV-SNP ─────────────────────────────────────

    #[test]
    fn aws_snp_valid() {
        let p = make_provider(PlatformKind::Aws, "us-east-2");
        let t = make_target("m6a.large");
        assert!(validate_target(&t, &p, "test").is_ok());
    }

    #[test]
    fn aws_snp_all_families() {
        let p = make_provider(PlatformKind::Aws, "eu-west-1");
        for fam in AWS_SNP_INSTANCE_FAMILIES {
            let vmtype = format!("{fam}.xlarge");
            let t = make_target(&vmtype);
            assert!(
                validate_target(&t, &p, "test").is_ok(),
                "expected {vmtype} to be valid"
            );
        }
    }

    #[test]
    fn aws_snp_bad_region() {
        let p = make_provider(PlatformKind::Aws, "us-west-2");
        let t = make_target("c6a.xlarge");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not support SEV-SNP"), "{err}");
    }

    #[test]
    fn aws_unsupported_instance_type() {
        let p = make_provider(PlatformKind::Aws, "us-east-2");
        let t = make_target("m5.large");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("cannot infer CC type"), "{err}");
    }

    #[test]
    fn aws_tdx_rejected() {
        let p = make_provider(PlatformKind::Aws, "us-east-2");
        let t = make_target_with_cc("m6a.large", CcType::Tdx);
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn infer_aws_snp() {
        assert_eq!(
            infer_cc_type(PlatformKind::Aws, "r6a.2xlarge").unwrap(),
            CcType::SevSnp
        );
    }

    #[test]
    fn infer_aws_unknown() {
        assert!(infer_cc_type(PlatformKind::Aws, "t3.micro").is_err());
        assert!(infer_cc_type(PlatformKind::Aws, "m6a").is_err());
    }

    // ── Error messages ──────────────────────────────────

    #[test]
    fn gcp_bad_zone_mentions_sev_snp() {
        let p = make_provider(PlatformKind::Gcp, "us-west1-a");
        let t = make_target("n2d-standard-2");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("SEV-SNP"), "{err}");
    }

    #[test]
    fn gcp_invalid_size_includes_doc_link() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target("c3-standard-5");
        let err = validate_target(&t, &p, "test").unwrap_err().to_string();
        assert!(err.contains("c3_machine_types"), "{err}");
    }

    #[test]
    fn error_includes_target_name() {
        let p = make_provider(PlatformKind::Gcp, "us-central1-a");
        let t = make_target("e2-standard-4");
        let err = validate_target(&t, &p, "my-prod").unwrap_err().to_string();
        assert!(err.contains("target 'my-prod'"), "{err}");
    }

    // ── infer_cc_type ───────────────────────────────────

    #[test]
    fn infer_gcp_n2d() {
        assert_eq!(
            infer_cc_type(PlatformKind::Gcp, "n2d-standard-8").unwrap(),
            CcType::SevSnp
        );
    }

    #[test]
    fn infer_gcp_c3() {
        assert_eq!(
            infer_cc_type(PlatformKind::Gcp, "c3-standard-4").unwrap(),
            CcType::Tdx
        );
    }

    #[test]
    fn infer_gcp_unknown() {
        assert!(infer_cc_type(PlatformKind::Gcp, "e2-standard-4").is_err());
    }

    #[test]
    fn infer_azure_dces() {
        assert_eq!(
            infer_cc_type(PlatformKind::Azure, "Standard_DC4es_v6").unwrap(),
            CcType::Tdx
        );
    }

    #[test]
    fn infer_azure_dcas() {
        assert_eq!(
            infer_cc_type(PlatformKind::Azure, "Standard_DC4as_v5").unwrap(),
            CcType::SevSnp
        );
    }

    // ── resolved_cc_type ────────────────────────────────

    #[test]
    fn resolved_cc_type_inferred() {
        let t = make_target("c3-standard-4");
        assert_eq!(t.resolved_cc_type(PlatformKind::Gcp).unwrap(), CcType::Tdx);
    }

    #[test]
    fn resolved_cc_type_explicit() {
        let t = make_target_with_cc("n2d-standard-2", CcType::SevSnp);
        assert_eq!(
            t.resolved_cc_type(PlatformKind::Gcp).unwrap(),
            CcType::SevSnp
        );
    }

    // ── CloudImageEntry deserialization ──────────────────

    #[test]
    fn image_entry_simple_form() {
        let toml = r#"
            [images]
            "img:v1" = ["SEV_SNP", "TDX"]
        "#;
        #[derive(Deserialize)]
        struct W {
            images: BTreeMap<String, CloudImageEntry>,
        }
        let w: W = toml::from_str(toml).unwrap();
        let entry = &w.images["img:v1"];
        assert_eq!(entry.cc_types, vec![CcType::SevSnp, CcType::Tdx]);
    }

    #[test]
    fn image_entry_extended_form() {
        let toml = r#"
            [images."img:v2"]
            cc_types = ["TDX"]
        "#;
        #[derive(Deserialize)]
        struct W {
            images: BTreeMap<String, CloudImageEntry>,
        }
        let w: W = toml::from_str(toml).unwrap();
        let entry = &w.images["img:v2"];
        assert_eq!(entry.cc_types, vec![CcType::Tdx]);
    }

    #[test]
    fn image_entry_empty_cc_types_rejected() {
        let toml = r#"
            [images]
            "img:v1" = []
        "#;
        #[derive(Deserialize)]
        struct W {
            images: BTreeMap<String, CloudImageEntry>,
        }
        assert!(toml::from_str::<W>(toml).is_err());
    }

    #[test]
    fn image_entry_both_forms_in_one() {
        let toml = r#"
            [images]
            "a:v1" = ["SEV_SNP"]
            [images."b:v1"]
            cc_types = ["SEV_SNP", "TDX"]
        "#;
        #[derive(Deserialize)]
        struct W {
            images: BTreeMap<String, CloudImageEntry>,
        }
        let w: W = toml::from_str(toml).unwrap();
        assert_eq!(w.images["a:v1"].cc_types, vec![CcType::SevSnp]);
        assert_eq!(w.images["b:v1"].cc_types, vec![CcType::SevSnp, CcType::Tdx]);
    }

    // ── guest_os_features_for ───────────────────────────

    const EXPECTED_FEATURES: &str =
        "--guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE";

    #[test]
    fn guest_os_features_always_dual_capable() {
        // Every image is dual-capable regardless of configured CC types.
        assert_eq!(guest_os_features_for(&[CcType::SevSnp]), EXPECTED_FEATURES);
        assert_eq!(guest_os_features_for(&[CcType::Tdx]), EXPECTED_FEATURES);
        assert_eq!(
            guest_os_features_for(&[CcType::SevSnp, CcType::Tdx]),
            EXPECTED_FEATURES
        );
    }

    #[test]
    fn guest_os_features_omits_plain_sev() {
        // Only SEV-SNP is supported; plain SEV must not be advertised.
        assert!(!guest_os_features_for(&[CcType::SevSnp]).contains("SEV_CAPABLE"));
    }

    // ── CcType FromStr ──────────────────────────────────

    #[test]
    fn cc_type_from_str_valid() {
        assert_eq!("SEV_SNP".parse::<CcType>().unwrap(), CcType::SevSnp);
        assert_eq!("TDX".parse::<CcType>().unwrap(), CcType::Tdx);
    }

    #[test]
    fn cc_type_from_str_invalid() {
        assert!("snp".parse::<CcType>().is_err());
        assert!("".parse::<CcType>().is_err());
    }

    #[test]
    fn cc_type_display_roundtrip() {
        for cc in [CcType::SevSnp, CcType::Tdx] {
            assert_eq!(cc.to_string().parse::<CcType>().unwrap(), cc);
        }
    }

    // ── CloudTarget deserialization ─────────────────────

    #[test]
    fn cloud_target_boot_disk_size_parses() {
        let toml = r#"
            [targets.my-tdx]
            provider = "my-gcp"
            vmtype = "c3-standard-4"
            boot_disk_size = "100GB"
        "#;
        #[derive(Deserialize)]
        struct W {
            targets: BTreeMap<String, CloudTarget>,
        }
        let w: W = toml::from_str(toml).unwrap();
        assert_eq!(w.targets["my-tdx"].boot_disk_size.as_deref(), Some("100GB"));
    }

    #[test]
    fn cloud_target_boot_disk_size_defaults_none() {
        let toml = r#"
            [targets.my-tdx]
            provider = "my-gcp"
            vmtype = "c3-standard-4"
        "#;
        #[derive(Deserialize)]
        struct W {
            targets: BTreeMap<String, CloudTarget>,
        }
        let w: W = toml::from_str(toml).unwrap();
        assert!(w.targets["my-tdx"].boot_disk_size.is_none());
    }
}
