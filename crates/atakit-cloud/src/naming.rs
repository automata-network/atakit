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
}
