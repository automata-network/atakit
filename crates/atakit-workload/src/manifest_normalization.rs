//! Normalize equivalent settings at the build boundary, before measurement.
//! Never apply this to archives being read: their original bytes are measured.

use atakit_core::{
    cpu::canonical_cpuset,
    tee_attributes::{AttributeValue, VerifiedTeeAttribute},
};

use crate::{
    manifest::{Manifest, ManifestLogging},
    WorkloadError,
};

fn sort_unique(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
}

fn normalize_cpuset(value: &mut Option<String>) -> Result<(), WorkloadError> {
    *value = value
        .as_deref()
        .map(canonical_cpuset)
        .transpose()
        .map_err(WorkloadError::Validation)?;
    Ok(())
}

/// Use the largest exact unit. Never round a requested size.
fn format_exact_size(value: u64, units: &[(u64, &str)]) -> String {
    for &(factor, suffix) in units {
        if value >= factor && value.is_multiple_of(factor) {
            return format!("{}{suffix}", value / factor);
        }
    }
    unreachable!("unit table must end in factor 1")
}

fn normalize_disk_size(value: &mut String) -> Result<(), WorkloadError> {
    let mb = crate::validate::parse_size_mb(value).ok_or_else(|| {
        WorkloadError::Validation(format!("invalid or overflowing disk size {value:?}"))
    })?;
    *value = if mb == 0 {
        "0MB".into()
    } else {
        format_exact_size(mb, &[(1024 * 1024, "TB"), (1024, "GB"), (1, "MB")])
    };
    Ok(())
}

fn normalize_logging(value: &mut ManifestLogging) -> Result<(), WorkloadError> {
    sort_unique(&mut value.log_readers);
    if let Some(value) = value.options.get_mut("max-size") {
        let bytes = crate::validate::parse_size_suffix(value).map_err(WorkloadError::Validation)?;
        *value = if bytes == 0 {
            "0".into()
        } else {
            format_exact_size(
                bytes,
                &[
                    (1024 * 1024 * 1024, "g"),
                    (1024 * 1024, "m"),
                    (1024, "k"),
                    (1, ""),
                ],
            )
        };
    }
    if let Some(value) = value.options.get_mut("max-file") {
        *value = value
            .parse::<u32>()
            .map_err(|_| WorkloadError::Validation(format!("invalid log max-file {value:?}")))?
            .to_string();
    }
    Ok(())
}

pub(crate) fn normalize(manifest: &mut Manifest) -> Result<(), WorkloadError> {
    let config = &mut manifest.config;
    normalize_cpuset(&mut config.cpuset)?;
    if let Some(policy) = &mut config.cpu_idle {
        policy.normalize();
    }
    if let Some(policy) = &mut config.cpu_frequency {
        if let Some(values) = &mut policy.allowed_governors {
            sort_unique(values);
        }
    }
    for policy in config
        .cpuset_policy
        .iter_mut()
        .chain(
            config
                .dependencies
                .iter_mut()
                .flat_map(|d| d.values_mut())
                .filter_map(|d| d.cpuset_policy.as_mut()),
        )
        .chain(
            config
                .baby_container
                .slots
                .values_mut()
                .filter_map(|s| s.cpuset_policy.as_mut()),
        )
    {
        policy.normalize().map_err(WorkloadError::Validation)?;
    }
    sort_unique(&mut config.base_image);
    sort_unique(&mut config.depends_on);
    sort_unique(&mut config.cap_add);
    sort_unique(&mut config.cap_drop);
    normalize_logging(&mut config.logging)?;
    if let Some(value) = &mut config.boot_disk_size {
        normalize_disk_size(value)?;
    }
    for (name, values) in &mut config.attributes {
        // Reserved attributes have their own validation and normalization.
        // Custom attributes are unordered sets of allowed string values.
        if VerifiedTeeAttribute::from_name(name).is_none() {
            let mut strings = values
                .iter()
                .map(|value| match value {
                    AttributeValue::String(value) => Ok(value.clone()),
                    _ => Err(WorkloadError::Validation(format!(
                        "custom attribute {name:?} must contain strings"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?;
            sort_unique(&mut strings);
            *values = strings.into_iter().map(AttributeValue::String).collect();
        }
    }
    if let Some(dependencies) = &mut config.dependencies {
        for dependency in dependencies.values_mut() {
            normalize_cpuset(&mut dependency.cpuset)?;
            sort_unique(&mut dependency.depends_on);
            sort_unique(&mut dependency.cap_add);
            sort_unique(&mut dependency.cap_drop);
            normalize_logging(&mut dependency.logging)?;
        }
    }
    for slot in config.baby_container.slots.values_mut() {
        normalize_cpuset(&mut slot.cpuset)?;
        sort_unique(&mut slot.allowed_capabilities);
        normalize_logging(&mut slot.logging)?;
    }
    for disk in manifest.disks.values_mut() {
        normalize_disk_size(&mut disk.size)?;
        sort_unique(&mut disk.encryption.bind);
    }
    // Commands, entrypoints and environment-file lists are ordered. Do not sort.
    Ok(())
}
