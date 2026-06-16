/// Deterministic resource names for cloud deployments.
pub struct ResourceNames {
    /// GCS bucket name: `atakit-{instance}`.
    pub bucket: String,
    /// GCE image name: sanitized image ref (shared across instances).
    pub image: String,
    /// Firewall rule name: `{instance}-ingress`.
    pub firewall: String,
    /// VM instance name: `{instance}`.
    pub instance: String,
}

impl ResourceNames {
    /// Derive GCP resource names from instance name and image reference.
    pub fn for_gcp(instance_name: &str, image_ref: &str) -> Self {
        Self {
            bucket: format!("atakit-{}", sanitize(instance_name, 63)),
            image: sanitize_image_ref(image_ref),
            firewall: format!("{}-ingress", sanitize(instance_name, 58)),
            instance: sanitize(instance_name, 63),
        }
    }

    /// Derive AWS resource names from instance name and image reference.
    ///
    /// `bucket` is the S3 bucket, `image` is the AMI name, `firewall` is the
    /// security group name.
    pub fn for_aws(instance_name: &str, image_ref: &str) -> Self {
        Self {
            bucket: format!("atakit-{}", sanitize(instance_name, 56)),
            image: sanitize_image_ref(image_ref),
            firewall: format!("{}-secgrp", sanitize(instance_name, 56)),
            instance: sanitize(instance_name, 63),
        }
    }
}

/// Azure resource names for cloud deployments.
///
/// Storage account, gallery, image definition, and image version are scoped to
/// `(region, image_ref)` so concurrent deploys of the same image share the same
/// uploaded VHD and gallery image. Only `resource_group`, `nsg`, and `instance`
/// are per-instance.
pub struct AzureResourceNames {
    /// Resource group: `{instance}-rg`.
    pub resource_group: String,
    /// Storage account holding the uploaded VHD. Shared across all deploys of
    /// the same `(region, image_ref)`. Format: `atakit{18-hex}` (24 chars).
    pub storage_account: String,
    /// Gallery resource group: `atakit-images-{region}` (shared across deployments).
    pub gallery_rg: String,
    /// Compute Gallery: `atakit_{region}_gallery` — one per region, shared
    /// across all image refs.
    pub gallery: String,
    /// Image definition: sanitized image ref.
    pub image_definition: String,
    /// Image version: always "1.0.0".
    pub image_version: String,
    /// Network security group: `{instance}-nsg`.
    pub nsg: String,
    /// VM instance name.
    pub instance: String,
}

impl AzureResourceNames {
    /// Derive Azure resource names from instance name, image reference, and
    /// region.
    ///
    /// The storage account is deterministically derived from `(region,
    /// image_ref)`. Subsequent deploys of the same image discover and reuse
    /// the same storage account and gallery image version — avoiding redundant
    /// VHD uploads across instances.
    pub fn for_azure(instance_name: &str, image_ref: &str, region: &str) -> Self {
        Self {
            resource_group: format!("{}-rg", sanitize(instance_name, 87)),
            storage_account: azure_shared_storage_account(region, image_ref),
            gallery_rg: format!("atakit-images-{}", sanitize(region, 73)),
            gallery: format!("atakit_{}_gallery", sanitize_azure_gallery(region, 55)),
            image_definition: sanitize(image_ref, 80),
            image_version: "1.0.0".to_string(),
            nsg: format!("{}-nsg", sanitize(instance_name, 76)),
            instance: sanitize(instance_name, 64),
        }
    }
}

/// Deterministic storage account name shared across deploys of the same
/// `(region, image_ref)`. Format: `atakit{6-hex-of-image-hash}{region}`.
/// Lowercase alphanum, 24-char max. The hash is over `image_ref` only — so
/// every region uses the same prefix for the same image and the trailing
/// region disambiguates regional resources. Region is truncated if needed to
/// fit the 24-char Azure limit.
fn azure_shared_storage_account(region: &str, image_ref: &str) -> String {
    use sha2::{Digest, Sha256};
    const PREFIX: &str = "atakit";
    const MAX: usize = 24;
    let d = Sha256::digest(image_ref.as_bytes());
    let hash6: String = d.iter().take(3).map(|b| format!("{b:02x}")).collect();
    let region_san: String = region
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let budget = MAX.saturating_sub(PREFIX.len() + hash6.len());
    let region_trunc: String = region_san.chars().take(budget).collect();
    format!("{PREFIX}{hash6}{region_trunc}")
}

/// Sanitize for Azure gallery name: alphanum + underscores.
fn sanitize_azure_gallery(s: &str, max_len: usize) -> String {
    let mut result = String::with_capacity(s.len());
    let mut last_was_underscore = true;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch.to_ascii_lowercase());
            last_was_underscore = false;
        } else if !last_was_underscore {
            result.push('_');
            last_was_underscore = true;
        }
    }
    while result.ends_with('_') {
        result.pop();
    }
    if result.len() > max_len {
        result.truncate(max_len);
        while result.ends_with('_') {
            result.pop();
        }
    }
    result
}

/// Standard labels applied to all GCP resources.
pub fn resource_labels(
    instance: &str,
    workload_name: &str,
    workload_version: &str,
    image_ref: &str,
) -> Vec<(String, String)> {
    vec![
        ("managed-by".into(), "atakit".into()),
        ("atakit-instance".into(), sanitize(instance, 63)),
        ("atakit-workload".into(), sanitize(workload_name, 63)),
        ("atakit-version".into(), sanitize(workload_version, 63)),
        ("atakit-image".into(), sanitize(image_ref, 63)),
    ]
}

/// Sanitize a string for use as a GCP resource name or label value.
/// Lowercase, replace non-alphanumeric with hyphens, collapse, trim, max length.
fn sanitize(s: &str, max_len: usize) -> String {
    let mut result = String::with_capacity(s.len());
    let mut last_was_hyphen = true; // prevent leading hyphen
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch.to_ascii_lowercase());
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            result.push('-');
            last_was_hyphen = true;
        }
    }
    // Trim trailing hyphen.
    while result.ends_with('-') {
        result.pop();
    }
    if result.len() > max_len {
        result.truncate(max_len);
        while result.ends_with('-') {
            result.pop();
        }
    }
    result
}

/// Sanitize an image ref like "automata-linux:v0.1.6-debug" for use as a GCE image name.
fn sanitize_image_ref(image_ref: &str) -> String {
    sanitize(image_ref, 63)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_sanitize() {
        assert_eq!(sanitize("hello-world", 63), "hello-world");
        assert_eq!(sanitize("Hello_World!", 63), "hello-world");
        assert_eq!(sanitize("--leading--", 63), "leading");
    }

    #[test]
    fn truncate_with_hyphen_trim() {
        let long = "abcdefghij-";
        assert_eq!(sanitize(long, 10), "abcdefghij");
    }

    #[test]
    fn image_ref_sanitize() {
        assert_eq!(
            sanitize_image_ref("automata-linux:v0.1.6-debug"),
            "automata-linux-v0-1-6-debug"
        );
    }

    #[test]
    fn resource_names() {
        let names = ResourceNames::for_gcp("my-instance", "automata-linux:v0.1.6");
        assert_eq!(names.bucket, "atakit-my-instance");
        assert_eq!(names.image, "automata-linux-v0-1-6");
        assert_eq!(names.firewall, "my-instance-ingress");
        assert_eq!(names.instance, "my-instance");
    }

    #[test]
    fn aws_resource_names() {
        let names = ResourceNames::for_aws("my-instance", "automata-linux:v0.1.6");
        assert_eq!(names.bucket, "atakit-my-instance");
        assert_eq!(names.image, "automata-linux-v0-1-6");
        assert_eq!(names.firewall, "my-instance-secgrp");
        assert_eq!(names.instance, "my-instance");
    }

    #[test]
    fn azure_storage_account_is_image_scoped() {
        // Same image + same region → same storage account (shared across
        // every instance of that image). Different instance names must NOT
        // change the storage account name.
        let a = AzureResourceNames::for_azure("inst-a", "dev-baseimage:v0.0.2", "eastus");
        let b = AzureResourceNames::for_azure("inst-b", "dev-baseimage:v0.0.2", "eastus");
        assert_eq!(a.storage_account, b.storage_account);
        // Different image_ref → different storage account.
        let c = AzureResourceNames::for_azure("inst-a", "dev-baseimage:v0.0.3", "eastus");
        assert_ne!(a.storage_account, c.storage_account);
        // Different region → different storage account (regional resource).
        let d = AzureResourceNames::for_azure("inst-a", "dev-baseimage:v0.0.2", "westus");
        assert_ne!(a.storage_account, d.storage_account);
        assert!(a.storage_account.starts_with("atakit"));
        assert!(a.storage_account.ends_with("eastus"));
        assert!(a.storage_account.len() <= 24);
    }

    #[test]
    fn azure_storage_account_length_for_long_region() {
        // Region truncates to fit 24-char Azure limit; trailing chars dropped.
        let n = AzureResourceNames::for_azure("inst", "img:v1", "southeastasia");
        assert!(n.storage_account.len() <= 24);
        assert!(n.storage_account.starts_with("atakit"));
    }

    #[test]
    fn azure_gallery_sanitize() {
        assert_eq!(sanitize_azure_gallery("my-instance", 55), "my_instance");
        assert_eq!(sanitize_azure_gallery("--leading--", 55), "leading");
    }

    #[test]
    fn azure_resource_names() {
        let names = AzureResourceNames::for_azure("my-instance", "automata-linux:v0.1.6", "eastus");
        // Per-instance fields.
        assert_eq!(names.resource_group, "my-instance-rg");
        assert_eq!(names.nsg, "my-instance-nsg");
        assert_eq!(names.instance, "my-instance");
        // Per-image / per-region fields (shared).
        assert_eq!(names.gallery_rg, "atakit-images-eastus");
        assert_eq!(names.gallery, "atakit_eastus_gallery");
        assert_eq!(names.image_definition, "automata-linux-v0-1-6");
        assert_eq!(names.image_version, "1.0.0");
        assert!(names.storage_account.starts_with("atakit"));
        assert!(names.storage_account.ends_with("eastus"));
        assert!(names.storage_account.len() <= 24);
    }
}
