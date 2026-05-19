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
pub struct AzureResourceNames {
    /// Resource group: `{instance}-rg`.
    pub resource_group: String,
    /// Storage account: `atakit{alphanum}` (max 24, lowercase alphanum only).
    pub storage_account: String,
    /// Gallery resource group: `atakit-images-{region}` (shared across deployments).
    pub gallery_rg: String,
    /// Compute Gallery: `atakit_{alphanum}_gallery` (alphanum + underscores).
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
    /// Derive Azure resource names from instance name, image reference, region,
    /// and a storage-account hash.
    ///
    /// `storage_hash` is inserted immediately after the `atakit` prefix in the
    /// storage account name to break global-uniqueness collisions (Azure
    /// storage account names are globally unique across all tenants). Pass
    /// `""` when the caller doesn't care about the storage account (e.g.
    /// when only using resource_group / gallery fields) — this preserves the
    /// pre-hash naming. For deploy flows, generate a fresh value via
    /// [`random_storage_hash`].
    pub fn for_azure(
        instance_name: &str,
        image_ref: &str,
        region: &str,
        storage_hash: &str,
    ) -> Self {
        let inst = sanitize(instance_name, 64);
        Self {
            resource_group: format!("{}-rg", sanitize(instance_name, 87)),
            storage_account: azure_storage_account(instance_name, storage_hash),
            gallery_rg: format!("atakit-images-{}", sanitize(region, 73)),
            gallery: format!(
                "atakit_{}_gallery",
                sanitize_azure_gallery(instance_name, 55)
            ),
            image_definition: sanitize(image_ref, 80),
            image_version: "1.0.0".to_string(),
            nsg: format!("{}-nsg", sanitize(instance_name, 76)),
            instance: inst,
        }
    }
}

/// Generate a 6-char lowercase-hex token suitable for use as a storage account
/// disambiguation hash. Uses SHA-256 over time + pid + a monotonic counter so
/// repeated calls within the same process never collide.
pub fn random_storage_hash() -> String {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    let d = hasher.finalize();
    format!("{:02x}{:02x}{:02x}", d[0], d[1], d[2])
}

/// Build an Azure storage account name: `atakit{hash}{instance}`, truncated
/// from the back of the instance-name portion to fit the 24-char limit.
/// Lowercase alphanum only (Azure storage account name constraints).
fn azure_storage_account(instance: &str, hash: &str) -> String {
    const MAX: usize = 24;
    const PREFIX: &str = "atakit";
    let hash_budget = MAX.saturating_sub(PREFIX.len());
    let hash_san: String = lowercase_alphanum(hash).chars().take(hash_budget).collect();
    let prefix = format!("{PREFIX}{hash_san}");
    let inst_san = lowercase_alphanum(instance);
    let remaining = MAX.saturating_sub(prefix.len());
    let inst_trunc: String = inst_san.chars().take(remaining).collect();
    format!("{prefix}{inst_trunc}")
}

/// Lowercase alphanumerics only — strips everything else.
fn lowercase_alphanum(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
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
    fn azure_storage_no_hash() {
        // Empty hash → atakit + truncated instance (legacy behavior preserved).
        assert_eq!(azure_storage_account("my-instance", ""), "atakitmyinstance");
        // 21-char sanitized instance, 18-char budget after "atakit" prefix.
        assert_eq!(
            azure_storage_account("aVeryLongInstanceName", ""),
            "atakitaverylonginstancen",
        );
        assert!(azure_storage_account("aVeryLongInstanceName", "").len() <= 24);
    }

    #[test]
    fn azure_storage_with_hash() {
        // 6-char hash: atakit(6) + hash(6) + up to 12 of instance.
        assert_eq!(
            azure_storage_account("my-instance", "abc123"),
            "atakitabc123myinstance",
        );
        // Long instance truncated to 12 chars.
        assert_eq!(
            azure_storage_account("aVeryLongInstanceName", "abc123"),
            "atakitabc123averylongins",
        );
        assert!(azure_storage_account("aVeryLongInstanceName", "abc123").len() <= 24);
    }

    #[test]
    fn azure_storage_oversized_hash() {
        // A hash longer than the 24-char budget must still yield a legal name:
        // hash_san is clamped so prefix never exceeds MAX, instance is dropped.
        let out = azure_storage_account("my-instance", "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(out, "atakitabcdefghijklmnopqr");
        assert_eq!(out.len(), 24);
    }

    #[test]
    fn azure_gallery_sanitize() {
        assert_eq!(sanitize_azure_gallery("my-instance", 55), "my_instance");
        assert_eq!(sanitize_azure_gallery("--leading--", 55), "leading");
    }

    #[test]
    fn azure_resource_names() {
        let names = AzureResourceNames::for_azure(
            "my-instance",
            "automata-linux:v0.1.6",
            "eastus",
            "abc123",
        );
        assert_eq!(names.resource_group, "my-instance-rg");
        assert_eq!(names.storage_account, "atakitabc123myinstance");
        assert_eq!(names.gallery_rg, "atakit-images-eastus");
        assert_eq!(names.gallery, "atakit_my_instance_gallery");
        assert_eq!(names.image_definition, "automata-linux-v0-1-6");
        assert_eq!(names.image_version, "1.0.0");
        assert_eq!(names.nsg, "my-instance-nsg");
        assert_eq!(names.instance, "my-instance");
    }

    #[test]
    fn random_hash_shape() {
        let h = random_storage_hash();
        assert_eq!(h.len(), 6);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Monotonic counter ⇒ consecutive calls differ.
        assert_ne!(h, random_storage_hash());
    }
}
