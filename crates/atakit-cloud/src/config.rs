use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::CloudError;

/// Cloud platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformKind {
    Gcp,
    Azure,
}

impl std::fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformKind::Gcp => write!(f, "gcp"),
            PlatformKind::Azure => write!(f, "azure"),
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

impl CcType {
    /// GCE guest OS features for image registration.
    pub fn guest_os_features(&self) -> &str {
        match self {
            CcType::SevSnp => "--guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,SEV_CAPABLE,GVNIC",
            CcType::Tdx => "--guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC",
        }
    }

    /// Minimum CPU platform for instance creation, if required.
    pub fn min_cpu_platform(&self) -> Option<&str> {
        match self {
            CcType::SevSnp => Some("AMD Milan"),
            CcType::Tdx => None,
        }
    }
}

/// Top-level `[cloud]` configuration section.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CloudConfig {
    /// Default expire offset for CVM agent sessions (seconds).
    pub expire_offset: Option<u64>,
    /// RPC URL (falls back to `[publish]` if not set).
    pub rpc_url: Option<String>,
    /// Session registry contract address.
    pub session_registry: Option<String>,
    /// Path to owner private key file.
    pub owner_key_file: Option<String>,
    /// Path to relay private key file.
    pub relay_key_file: Option<String>,
    /// Named cloud targets.
    #[serde(default)]
    pub targets: BTreeMap<String, CloudTarget>,
}

/// A named cloud deployment target (e.g. `[cloud.targets.prod-gcp]`).
#[derive(Debug, Clone, Deserialize)]
pub struct CloudTarget {
    /// Cloud platform.
    pub platform: PlatformKind,
    /// Confidential computing type (SEV_SNP or TDX). Default: SEV_SNP.
    #[serde(default)]
    pub cc_type: CcType,
    /// GCP project ID.
    pub project: Option<String>,
    /// Azure subscription ID (future).
    pub subscription: Option<String>,
    /// Cloud region or zone.
    pub region: String,
    /// VM machine type.
    pub vmtype: String,
    /// Custom instance name prefix.
    pub name: Option<String>,
    /// Extra metadata key-value pairs.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    // Per-target agent env overrides.
    pub rpc_url: Option<String>,
    pub session_registry: Option<String>,
    pub owner_key_file: Option<String>,
    pub relay_key_file: Option<String>,
}

// ── Cloud target validation ─────────────────────────────────────────

const GCP_SNP_ZONES: &[&str] = &[
    "asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c",
    "europe-west3-a", "europe-west3-b", "europe-west3-c",
    "europe-west4-a", "europe-west4-b", "europe-west4-c",
    "us-central1-a", "us-central1-b", "us-central1-c",
];

const GCP_TDX_ZONES: &[&str] = &[
    "asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c",
    "europe-west4-a", "europe-west4-b", "europe-west4-c",
    "us-central1-a", "us-central1-b", "us-central1-c",
];

#[allow(dead_code)] // AWS platform not yet implemented
const AWS_SNP_REGIONS: &[&str] = &["us-east-2", "eu-west-1"];

const AZURE_TDX_V6_REGIONS: &[&str] = &[
    "West Europe", "East US", "West US", "West US 3",
];

const AZURE_SNP_REGIONS: &[&str] = &[
    "East US", "West US", "Switzerland North", "Italy North",
    "North Europe", "West Europe", "Germany West Central",
    "UAE North", "Japan East", "Central India", "East Asia",
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

/// Validate that the target's machine type, zone/region and CC type form a
/// supported combination. Returns a descriptive error if not.
pub fn validate_target(target: &CloudTarget, target_name: &str) -> Result<(), CloudError> {
    let err = |msg: String| CloudError::Config { message: format!("target '{target_name}': {msg}") };

    match target.platform {
        PlatformKind::Gcp => {
            // Machine type determines CC type:
            //   n2d-standard-* → SEV_SNP
            //   c3-standard-*  → TDX
            if let Some(size) = target.vmtype.strip_prefix("n2d-standard-") {
                if !GCP_N2D_SIZES.contains(&size) {
                    return Err(err(format!(
                        "unsupported GCP machine type '{}'. \
                         Valid n2d-standard sizes: {}. \
                         Reference: https://cloud.google.com/compute/docs/general-purpose-machines#n2d_machine_types",
                        target.vmtype, GCP_N2D_SIZES.join(", ")
                    )));
                }
                if target.cc_type != CcType::SevSnp {
                    return Err(err(format!(
                        "machine type '{}' requires cc_type SEV_SNP, got {}",
                        target.vmtype, target.cc_type
                    )));
                }
                if !GCP_SNP_ZONES.contains(&target.region.as_str()) {
                    return Err(err(format!(
                        "zone '{}' does not support SEV-SNP VMs. Supported zones: {}",
                        target.region, GCP_SNP_ZONES.join(", ")
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
                if target.cc_type != CcType::Tdx {
                    return Err(err(format!(
                        "machine type '{}' requires cc_type TDX, got {}",
                        target.vmtype, target.cc_type
                    )));
                }
                if !GCP_TDX_ZONES.contains(&target.region.as_str()) {
                    return Err(err(format!(
                        "zone '{}' does not support TDX VMs. Supported zones: {}",
                        target.region, GCP_TDX_ZONES.join(", ")
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
            // Standard_DC*es_v6  → TDX
            // Standard_DC*as_v5/v6 → SEV-SNP
            let is_tdx_v6 = is_azure_dces_v6(&target.vmtype);
            let is_snp = is_azure_dcas_v5v6(&target.vmtype);

            if is_tdx_v6 {
                if target.cc_type != CcType::Tdx {
                    return Err(err(format!(
                        "VM size '{}' requires cc_type TDX, got {}",
                        target.vmtype, target.cc_type
                    )));
                }
                if !AZURE_TDX_V6_REGIONS.contains(&target.region.as_str()) {
                    return Err(err(format!(
                        "region '{}' does not support TDX DCesv6 VMs. Supported regions: {}",
                        target.region, AZURE_TDX_V6_REGIONS.join(", ")
                    )));
                }
            } else if is_snp {
                if target.cc_type != CcType::SevSnp {
                    return Err(err(format!(
                        "VM size '{}' requires cc_type SEV_SNP, got {}",
                        target.vmtype, target.cc_type
                    )));
                }
                if !AZURE_SNP_REGIONS.contains(&target.region.as_str()) {
                    return Err(err(format!(
                        "region '{}' does not support SEV-SNP VMs. Supported regions: {}",
                        target.region, AZURE_SNP_REGIONS.join(", ")
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
    }
    Ok(())
}

/// Match `Standard_DC{2,4,8,16,32,64,96,128}es_v6`.
fn is_azure_dces_v6(vmtype: &str) -> bool {
    let Some(rest) = vmtype.strip_prefix("Standard_DC") else { return false };
    let Some(rest) = rest.strip_suffix("es_v6") else { return false };
    AZURE_DC_VCPUS.contains(&rest)
}

/// Match `Standard_DC{2,4,8,16,32,64,96,128}as_v{5,6}`.
fn is_azure_dcas_v5v6(vmtype: &str) -> bool {
    let Some(rest) = vmtype.strip_prefix("Standard_DC") else { return false };
    let Some(rest) = rest.strip_suffix("as_v5").or_else(|| rest.strip_suffix("as_v6")) else {
        return false;
    };
    AZURE_DC_VCPUS.contains(&rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a minimal CloudTarget for testing.
    fn make_target(platform: PlatformKind, vmtype: &str, region: &str, cc_type: CcType) -> CloudTarget {
        CloudTarget {
            platform,
            cc_type,
            project: None,
            subscription: None,
            region: region.to_string(),
            vmtype: vmtype.to_string(),
            name: None,
            metadata: BTreeMap::new(),
            rpc_url: None,
            session_registry: None,
            owner_key_file: None,
            relay_key_file: None,
        }
    }

    // ── GCP SEV-SNP (n2d-standard) ──────────────────────

    #[test]
    fn gcp_snp_valid() {
        let t = make_target(PlatformKind::Gcp, "n2d-standard-2", "us-central1-a", CcType::SevSnp);
        assert!(validate_target(&t, "test").is_ok());
    }

    #[test]
    fn gcp_snp_all_sizes() {
        for size in GCP_N2D_SIZES {
            let vmtype = format!("n2d-standard-{size}");
            let t = make_target(PlatformKind::Gcp, &vmtype, "us-central1-a", CcType::SevSnp);
            assert!(validate_target(&t, "test").is_ok(), "expected {vmtype} to be valid");
        }
    }

    #[test]
    fn gcp_snp_invalid_size() {
        let t = make_target(PlatformKind::Gcp, "n2d-standard-7", "us-central1-a", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported GCP machine type"), "{err}");
        assert!(err.contains("n2d_machine_types"), "{err}");
    }

    #[test]
    fn gcp_snp_all_zones() {
        for zone in GCP_SNP_ZONES {
            let t = make_target(PlatformKind::Gcp, "n2d-standard-8", zone, CcType::SevSnp);
            assert!(validate_target(&t, "test").is_ok(), "expected zone {zone} to be valid");
        }
    }

    #[test]
    fn gcp_snp_bad_zone() {
        let t = make_target(PlatformKind::Gcp, "n2d-standard-2", "us-west1-a", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("does not support SEV-SNP"), "{err}");
        assert!(err.contains("us-west1-a"), "{err}");
    }

    #[test]
    fn gcp_snp_wrong_cc_type() {
        let t = make_target(PlatformKind::Gcp, "n2d-standard-4", "us-central1-a", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("requires cc_type SEV_SNP"), "{err}");
    }

    // ── GCP TDX (c3-standard) ───────────────────────────

    #[test]
    fn gcp_tdx_valid() {
        let t = make_target(PlatformKind::Gcp, "c3-standard-4", "europe-west4-b", CcType::Tdx);
        assert!(validate_target(&t, "test").is_ok());
    }

    #[test]
    fn gcp_tdx_all_sizes() {
        for size in GCP_C3_SIZES {
            let vmtype = format!("c3-standard-{size}");
            let t = make_target(PlatformKind::Gcp, &vmtype, "us-central1-a", CcType::Tdx);
            assert!(validate_target(&t, "test").is_ok(), "expected {vmtype} to be valid");
        }
    }

    #[test]
    fn gcp_tdx_invalid_size() {
        let t = make_target(PlatformKind::Gcp, "c3-standard-5", "us-central1-a", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported GCP machine type"), "{err}");
        assert!(err.contains("c3_machine_types"), "{err}");
    }

    #[test]
    fn gcp_tdx_all_zones() {
        for zone in GCP_TDX_ZONES {
            let t = make_target(PlatformKind::Gcp, "c3-standard-4", zone, CcType::Tdx);
            assert!(validate_target(&t, "test").is_ok(), "expected zone {zone} to be valid");
        }
    }

    #[test]
    fn gcp_tdx_bad_zone() {
        // europe-west3 supports SNP but not TDX
        let t = make_target(PlatformKind::Gcp, "c3-standard-4", "europe-west3-a", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("does not support TDX"), "{err}");
    }

    #[test]
    fn gcp_tdx_wrong_cc_type() {
        let t = make_target(PlatformKind::Gcp, "c3-standard-4", "us-central1-a", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("requires cc_type TDX"), "{err}");
    }

    // ── GCP unsupported machine type ────────────────────

    #[test]
    fn gcp_unsupported_machine_type() {
        let t = make_target(PlatformKind::Gcp, "e2-standard-4", "us-central1-a", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported GCP machine type"), "{err}");
        assert!(err.contains("n2d-standard-*"), "{err}");
        assert!(err.contains("c3-standard-*"), "{err}");
    }

    // ── Azure TDX (DCes_v6) ─────────────────────────────

    #[test]
    fn azure_tdx_valid() {
        let t = make_target(PlatformKind::Azure, "Standard_DC4es_v6", "East US", CcType::Tdx);
        assert!(validate_target(&t, "test").is_ok());
    }

    #[test]
    fn azure_tdx_all_sizes() {
        for size in AZURE_DC_VCPUS {
            let vmtype = format!("Standard_DC{size}es_v6");
            let t = make_target(PlatformKind::Azure, &vmtype, "West Europe", CcType::Tdx);
            assert!(validate_target(&t, "test").is_ok(), "expected {vmtype} to be valid");
        }
    }

    #[test]
    fn azure_tdx_all_regions() {
        for region in AZURE_TDX_V6_REGIONS {
            let t = make_target(PlatformKind::Azure, "Standard_DC4es_v6", region, CcType::Tdx);
            assert!(validate_target(&t, "test").is_ok(), "expected region {region} to be valid");
        }
    }

    #[test]
    fn azure_tdx_bad_region() {
        let t = make_target(PlatformKind::Azure, "Standard_DC4es_v6", "Japan East", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("does not support TDX DCesv6"), "{err}");
    }

    #[test]
    fn azure_tdx_wrong_cc_type() {
        let t = make_target(PlatformKind::Azure, "Standard_DC4es_v6", "East US", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("requires cc_type TDX"), "{err}");
    }

    // ── Azure SEV-SNP (DCas_v5/v6) ──────────────────────

    #[test]
    fn azure_snp_v5_valid() {
        let t = make_target(PlatformKind::Azure, "Standard_DC4as_v5", "East US", CcType::SevSnp);
        assert!(validate_target(&t, "test").is_ok());
    }

    #[test]
    fn azure_snp_v6_valid() {
        let t = make_target(PlatformKind::Azure, "Standard_DC8as_v6", "West Europe", CcType::SevSnp);
        assert!(validate_target(&t, "test").is_ok());
    }

    #[test]
    fn azure_snp_all_regions() {
        for region in AZURE_SNP_REGIONS {
            let t = make_target(PlatformKind::Azure, "Standard_DC2as_v5", region, CcType::SevSnp);
            assert!(validate_target(&t, "test").is_ok(), "expected region {region} to be valid");
        }
    }

    #[test]
    fn azure_snp_bad_region() {
        let t = make_target(PlatformKind::Azure, "Standard_DC4as_v5", "Brazil South", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("does not support SEV-SNP"), "{err}");
    }

    #[test]
    fn azure_snp_wrong_cc_type() {
        let t = make_target(PlatformKind::Azure, "Standard_DC4as_v5", "East US", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("requires cc_type SEV_SNP"), "{err}");
    }

    // ── Azure unsupported VM size ────────────────────────

    #[test]
    fn azure_unsupported_vm_size() {
        let t = make_target(PlatformKind::Azure, "Standard_D4s_v5", "East US", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported Azure VM size"), "{err}");
    }

    #[test]
    fn azure_bad_dc_size_number() {
        // 3 is not in the valid set {2,4,8,16,32,64,96,128}
        let t = make_target(PlatformKind::Azure, "Standard_DC3es_v6", "East US", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("unsupported Azure VM size"), "{err}");
    }

    // ── Error messages include doc links ─────────────────

    #[test]
    fn gcp_error_includes_doc_link() {
        let t = make_target(PlatformKind::Gcp, "e2-micro", "us-central1-a", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("cloud.google.com/compute/docs"), "{err}");
    }

    #[test]
    fn gcp_invalid_size_includes_doc_link() {
        let t = make_target(PlatformKind::Gcp, "c3-standard-5", "us-central1-a", CcType::Tdx);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("c3_machine_types"), "{err}");
    }

    #[test]
    fn azure_error_includes_doc_link() {
        let t = make_target(PlatformKind::Azure, "Standard_D4s_v5", "East US", CcType::SevSnp);
        let err = validate_target(&t, "test").unwrap_err().to_string();
        assert!(err.contains("learn.microsoft.com"), "{err}");
    }

    // ── Error message includes target name ───────────────

    #[test]
    fn error_includes_target_name() {
        let t = make_target(PlatformKind::Gcp, "e2-micro", "us-central1-a", CcType::SevSnp);
        let err = validate_target(&t, "my-prod").unwrap_err().to_string();
        assert!(err.contains("target 'my-prod'"), "{err}");
    }
}
