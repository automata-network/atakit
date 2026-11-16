//! Creation-only disk profiles. Provider identity comes from the provider config.
use crate::{
    config::{CloudTarget, PlatformKind},
    error::CloudError,
    plan::DiskSpec,
};
use atakit_core::disk_config::{EncryptionWorkqueues, RuntimeDiskConfig, RuntimeDiskOptions};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskProfile {
    pub disk_type: String,
    pub iops: Option<u64>,
    pub throughput_mibps: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootDiskConfig {
    pub profile: Option<String>,
    pub size: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadDiskConfig {
    pub profile: Option<String>,
    pub encryption_workqueues: Option<EncryptionWorkqueues>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskPerformance {
    pub profile: Option<String>,
    pub disk_type: String,
    pub iops: Option<u64>,
    pub throughput_mibps: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResolvedDiskConfiguration {
    pub vmtype: String,
    pub boot_size_gb: Option<u64>,
    pub boot: Option<DiskPerformance>,
    pub disks: BTreeMap<String, DiskPerformance>,
}

fn error(message: impl Into<String>) -> CloudError {
    CloudError::Config {
        message: message.into(),
    }
}

impl CloudTarget {
    pub fn selected_boot_disk_size(&self) -> Result<Option<&str>, CloudError> {
        if self.boot_disk.size.is_some() && self.boot_disk_size.is_some() {
            return Err(error(
                "set only boot_disk.size, not both boot_disk.size and boot_disk_size",
            ));
        }
        Ok(self
            .boot_disk
            .size
            .as_deref()
            .or(self.boot_disk_size.as_deref()))
    }

    pub fn runtime_disks(&self) -> RuntimeDiskConfig {
        RuntimeDiskConfig(
            self.disks
                .iter()
                .map(|(name, disk)| {
                    (
                        name.clone(),
                        RuntimeDiskOptions {
                            encryption_workqueues: disk.encryption_workqueues.unwrap_or_default(),
                        },
                    )
                })
                .collect(),
        )
    }
}

impl ResolvedDiskConfiguration {
    pub fn resolve(
        profiles: &BTreeMap<String, DiskProfile>,
        target: &CloudTarget,
        platform: PlatformKind,
        declared: &[(String, u32, u64)],
        boot_size_gb: u64,
    ) -> Result<Self, CloudError> {
        target.selected_boot_disk_size()?;
        if target.availability_zone.is_some() && platform != PlatformKind::Azure {
            return Err(error(
                "availability_zone is supported only for Azure targets",
            ));
        }
        if target
            .availability_zone
            .as_deref()
            .is_some_and(|zone| !matches!(zone, "1" | "2" | "3"))
        {
            return Err(error(
                "Azure availability_zone must be \"1\", \"2\" or \"3\"",
            ));
        }
        let mut result = Self {
            vmtype: target.vmtype.clone(),
            boot_size_gb: Some(boot_size_gb),
            ..Default::default()
        };
        let resolve = |name: &str, size: u64, boot: bool| -> Result<DiskPerformance, CloudError> {
            let p = profiles
                .get(name)
                .ok_or_else(|| error(format!("unknown disk profile {name:?}")))?;
            let (required, disk_type) = match p.disk_type.split_once('-') {
                Some(("aws", kind)) => (PlatformKind::Aws, kind),
                Some(("gcp", kind)) => (PlatformKind::Gcp, kind),
                Some(("azure", kind)) => (PlatformKind::Azure, match kind {
                    "premium-ssd" => "Premium_LRS",
                    "premium-ssd-v2" => "PremiumV2_LRS",
                    "ultra-disk" => "UltraSSD_LRS",
                    "local-ssd" => "local-ssd",
                    _ => return Err(error("unknown Azure disk type")),
                }),
                _ => {
                    return Err(error(
                        "disk_type must identify its cloud, such as aws-gp3, azure-premium-ssd-v2 or gcp-local-ssd",
                    ))
                }
            };
            if required != platform {
                return Err(error(format!(
                    "disk profile {name:?} requires {}, but the provider uses {platform}",
                    required
                )));
            }
            let resolved = DiskPerformance {
                profile: Some(name.into()),
                disk_type: disk_type.into(),
                iops: p.iops,
                throughput_mibps: p.throughput_mibps,
            };
            resolved.validate(platform, &target.vmtype, size, boot)?;
            Ok(resolved)
        };
        if let Some(profile) = &target.boot_disk.profile {
            result.boot = Some(resolve(profile, boot_size_gb, true)?);
        }
        for (name, choice) in &target.disks {
            let (_, _, size) = declared.iter().find(|(n, _, _)| n == name).ok_or_else(|| {
                error(format!(
                    "unknown workload disk {name:?}; declared disks: {}",
                    declared
                        .iter()
                        .map(|(n, _, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            if let Some(profile) = &choice.profile {
                result
                    .disks
                    .insert(name.clone(), resolve(profile, *size, false)?);
            }
        }
        result.local_ssd()?;
        if result
            .disks
            .values()
            .any(|p| matches!(p.disk_type.as_str(), "PremiumV2_LRS" | "UltraSSD_LRS"))
            && target.availability_zone.is_none()
        {
            return Err(error(
                "Azure Premium SSD v2 and Ultra Disk require availability_zone on the target",
            ));
        }
        Ok(result)
    }

    pub fn local_ssd(
        &self,
    ) -> Result<Option<atakit_core::disk_config::LocalSsdConfig>, CloudError> {
        let names: Vec<_> = self
            .disks
            .iter()
            .filter(|(_, p)| p.disk_type == "local-ssd")
            .map(|(name, _)| name)
            .collect();
        if names.len() > 1 {
            return Err(error(
                "only one workload disk can select local SSD; it uses all included local disks",
            ));
        }
        names
            .first()
            .map(|name| {
                Ok(atakit_core::disk_config::LocalSsdConfig {
                    disk: (*name).clone(),
                    count: local_ssd_layout(&self.vmtype)
                        .map(|(count, _)| count)
                        .ok_or_else(|| {
                            error("local SSD requires a supported VM with local disks")
                        })?,
                })
            })
            .transpose()
    }

    pub fn apply(&self, disk: &mut DiskSpec) {
        if let Some(performance) = self.disks.get(&disk.device_name) {
            disk.disk_type = performance.disk_type.clone();
            disk.performance = Some(performance.clone());
        }
    }
}

pub fn gcp_local_ssd_count(vm: &str) -> Option<u32> {
    match vm.strip_prefix("c3-standard-")?.strip_suffix("-lssd")? {
        "4" => Some(1),
        "8" => Some(2),
        "22" => Some(4),
        "44" => Some(8),
        "88" => Some(16),
        "176" => Some(32),
        _ => None,
    }
}

/// Member count and capacity in GiB per member, derived from the VM type.
pub fn local_ssd_layout(vm: &str) -> Option<(u32, u64)> {
    if let Some(count) = gcp_local_ssd_count(vm) {
        return Some((count, 375));
    }
    let rest = vm.strip_prefix("Standard_DC")?;
    if let Some(size) = rest.strip_suffix("eds_v6") {
        return match size {
            "2" => Some((1, 110)),
            "4" => Some((1, 220)),
            "8" => Some((1, 440)),
            "16" => Some((2, 440)),
            "32" => Some((4, 440)),
            "48" => Some((6, 440)),
            "64" => Some((4, 880)),
            "96" => Some((6, 880)),
            "128" => Some((4, 1760)),
            _ => None,
        };
    }
    let size = rest
        .strip_suffix("ads_v5")
        .or_else(|| rest.strip_suffix("ads_v6"))?;
    let cpus = size.parse::<u64>().ok()?;
    [2, 4, 8, 16, 32, 48, 64, 96]
        .contains(&cpus)
        .then_some((1, cpus * 75 / 2))
}

/// Azure accepts whole decimal MB/s. Round up to supply at least the requested
/// binary MiB/s; inventory converts back by rounding down.
pub fn azure_mbps(mibps: u64) -> Result<u64, CloudError> {
    mibps
        .checked_mul(1_048_576)
        .map(|v| v.div_ceil(1_000_000))
        .ok_or_else(|| error("Azure throughput is too large"))
}

impl DiskPerformance {
    pub fn validate(
        &self,
        platform: PlatformKind,
        vm: &str,
        size: u64,
        boot: bool,
    ) -> Result<(), CloudError> {
        let fail = |message: &str| error(format!("disk profile {:?}: {message}", self.profile));
        if size == 0 || size > 65536 {
            return Err(fail("disk size must be between 1 and 65536 GB"));
        }
        match (platform, self.disk_type.as_str()) {
            (PlatformKind::Gcp | PlatformKind::Azure, "local-ssd") => {
                let (count, capacity) = local_ssd_layout(vm)
                    .filter(|_| match platform {
                        PlatformKind::Gcp => vm.starts_with("c3-"),
                        _ => vm.starts_with("Standard_DC"),
                    })
                    .ok_or_else(|| fail("local SSD requires a supported VM with local disks"))?;
                if boot || self.iops.is_some() || self.throughput_mibps.is_some() {
                    return Err(fail("local SSD is a workload disk and accepts no provisioned performance settings"));
                }
                // Leave room for RAID metadata when combining multiple members.
                if size * 1024 * 1024 * 1024
                    > u64::from(count)
                        * (capacity * 1024 * 1024 * 1024
                            - if count > 1 { 16 * 1024 * 1024 } else { 0 })
                {
                    return Err(fail(
                        "included Local SSD capacity is smaller than the workload disk requirement",
                    ));
                }
            }
            (PlatformKind::Aws, "gp3") => {
                let iops = self.iops.unwrap_or(3000);
                let throughput = self.throughput_mibps.unwrap_or(125);
                if !(3000..=80000.min((size * 500).max(3000))).contains(&iops) {
                    return Err(fail(
                        "gp3 IOPS must be 3000..80000 and at most 500 per GB above the baseline",
                    ));
                }
                if !(125..=2000.min(iops / 4)).contains(&throughput) {
                    return Err(fail(
                        "gp3 throughput must be 125..2000 MiB/s and at most IOPS/4",
                    ));
                }
            }
            (PlatformKind::Aws, "io2") => {
                let iops = self.iops.ok_or_else(|| fail("io2 requires iops"))?;
                if size < 4 || !(100..=256000.min(size * 1000)).contains(&iops) {
                    return Err(fail(
                        "io2 requires at least 4 GB and 100..256000 IOPS, at most 1000 per GB",
                    ));
                }
                if self.throughput_mibps.is_some() {
                    return Err(fail(
                        "io2 throughput follows IOPS; do not set throughput_mibps",
                    ));
                }
            }
            (PlatformKind::Azure, "Premium_LRS") => {
                if size > 32767 || self.iops.is_some() || self.throughput_mibps.is_some() {
                    return Err(fail(
                        "Azure Premium SSD supports up to 32767 GB; performance follows its size",
                    ));
                }
            }
            (PlatformKind::Azure, "PremiumV2_LRS" | "UltraSSD_LRS") => {
                if boot {
                    return Err(fail(
                        "Azure Premium SSD v2 and Ultra Disk support workload data disks only",
                    ));
                }
                let ultra = self.disk_type == "UltraSSD_LRS";
                if crate::infer_cc_type(PlatformKind::Azure, vm).is_err() {
                    return Err(fail(
                        "this Azure disk type requires a supported confidential VM",
                    ));
                }
                let (minimum, maximum, ratio, max_mbps) = if ultra {
                    (100, 400000, 1000, 10000)
                } else {
                    (3000, 80000, 500, 2000)
                };
                let iops = self
                    .iops
                    .unwrap_or(if ultra { 100.max(size) } else { 3000 });
                if (ultra && size < 4)
                    || !(minimum..=maximum.min((size * ratio).max(minimum))).contains(&iops)
                {
                    return Err(fail(
                        "Azure provisioned IOPS exceed the disk type or size limits",
                    ));
                }
                let mbps = self
                    .throughput_mibps
                    .map(azure_mbps)
                    .transpose()?
                    .unwrap_or(if ultra { 1 } else { 125 });
                if !(if ultra { 1 } else { 125 }..=max_mbps.min(iops / 4)).contains(&mbps) {
                    return Err(fail("Azure throughput exceeds the disk type or IOPS limit (converted to decimal MB/s)"));
                }
            }
            (PlatformKind::Gcp, "hyperdisk-balanced") => {
                if !(vm.starts_with("c3-standard-") || vm.starts_with("c4-standard-")) {
                    return Err(fail("Hyperdisk Balanced is supported here only on C3/C4; other families may need provider enrollment"));
                }
                if boot && !vm.starts_with("c4-standard-") {
                    return Err(fail("use Persistent Disk for this VM's boot disk; Hyperdisk boot selection is supported on C4"));
                }
                if size < 4 {
                    return Err(fail("Hyperdisk Balanced requires at least 4 GB"));
                }
                let minimum = (size * 500).min(3000);
                let iops = self.iops.unwrap_or(if size <= 6 {
                    size * 500
                } else {
                    (size * 6 + 3000).min(160000)
                });
                let throughput = self.throughput_mibps.unwrap_or(if size <= 6 {
                    140
                } else {
                    (size * 3 / 2 + 140).min(2400)
                });
                if !(minimum..=(size * 500).min(160000)).contains(&iops) {
                    return Err(fail(
                        "Hyperdisk Balanced IOPS exceed the size-dependent limits",
                    ));
                }
                if !(140.max(iops.div_ceil(256))..=2400.min(iops / 4)).contains(&throughput) {
                    return Err(fail("Hyperdisk Balanced throughput must be max(140, IOPS/256)..min(2400, IOPS/4) MiB/s"));
                }
                if let Some((max_iops, max_throughput)) = gcp_hyperdisk_vm_limits(vm) {
                    if iops > max_iops || throughput > max_throughput {
                        return Err(fail(
                            "provisioned performance exceeds this VM's shared Hyperdisk limit",
                        ));
                    }
                }
            }
            (PlatformKind::Gcp, "pd-balanced" | "pd-ssd") => {
                if vm.starts_with("c4-") {
                    return Err(fail(
                        "C4 requires Hyperdisk; Persistent Disk is unsupported",
                    ));
                }
                if size < 10 {
                    return Err(fail("Persistent Disk requires at least 10 GB"));
                }
                if self.iops.is_some() || self.throughput_mibps.is_some() {
                    return Err(fail(
                        "Persistent Disk does not accept provisioned IOPS or throughput",
                    ));
                }
            }
            _ => return Err(fail("unsupported platform/disk type combination")),
        }
        Ok(())
    }
}

/// Provider-documented shared VM budgets, not a per-disk performance promise.
pub fn gcp_hyperdisk_vm_limits(vm: &str) -> Option<(u64, u64)> {
    let size = vm.rsplit('-').next()?.parse::<u64>().ok()?;
    if vm.starts_with("c4-standard-") {
        match size {
            2 | 4 => Some((50000, 400)),
            8 => Some((50000, 800)),
            16 | 24 | 32 => Some((100000, 1600)),
            48 => Some((160000, 2400)),
            96 => Some((240000, 4800)),
            144 => Some((240000, 6250)),
            192 => Some((320000, 10000)),
            288 => Some((320000, 12500)),
            _ => None,
        }
    } else if vm.starts_with("c3-standard-") {
        match size {
            4 => Some((25000, 400)),
            8 => Some((50000, 800)),
            22 => Some((120000, 1800)),
            44 => Some((160000, 2400)),
            88 => Some((160000, 4800)),
            176 => Some((160000, 10000)),
            _ => None,
        }
    } else {
        None
    }
}

pub fn describe(p: Option<&DiskPerformance>) -> String {
    match p {
        None => "existing provider defaults (no profile)".into(),
        Some(p) => {
            format!(
                "profile={}, type={}, IOPS={}, throughput={} MiB/s",
                p.profile.as_deref().unwrap_or("none"),
                p.disk_type,
                p.iops
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "provider default".into()),
                p.throughput_mibps
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "provider default".into())
            ) + &if matches!(p.disk_type.as_str(), "PremiumV2_LRS" | "UltraSSD_LRS") {
                p.throughput_mibps
                    .and_then(|v| azure_mbps(v).ok())
                    .map(|v| format!(" (Azure request: {v} MB/s)"))
                    .unwrap_or_default()
            } else {
                String::new()
            }
        }
    }
}

pub fn validate_shared_limits(
    configuration: &ResolvedDiskConfiguration,
    iops: u64,
    mibps: f64,
) -> Result<String, CloudError> {
    let mut total_iops = 0;
    let mut total_mibps = 0.0;
    for p in configuration
        .boot
        .iter()
        .chain(configuration.disks.values())
    {
        let throughput = p
            .throughput_mibps
            .map(|v| {
                if matches!(p.disk_type.as_str(), "PremiumV2_LRS" | "UltraSSD_LRS") {
                    azure_mbps(v).map(|mbps| mbps as f64 * 1_000_000.0 / 1_048_576.0)
                } else {
                    Ok(v as f64)
                }
            })
            .transpose()?;
        if p.iops.is_some_and(|v| v > iops) || throughput.is_some_and(|v| v > mibps) {
            return Err(error(format!(
                "profile {:?} exceeds the VM's shared disk limit ({iops} IOPS, {mibps:.1} MiB/s)",
                p.profile
            )));
        }
        total_iops += p.iops.unwrap_or(0);
        total_mibps += throughput.unwrap_or(0.0);
    }
    Ok(format!("VM disk limit shared by all volumes: {iops} IOPS, {mibps:.1} MiB/s; explicit selections total {total_iops} IOPS, {total_mibps:.1} MiB/s{}",
        if total_iops > iops || total_mibps > mibps { "; aggregate provisioned performance is limited by the VM" } else { "" }))
}

/// Read provider capability data before any create operation. This reserves no quota.
pub async fn check_capabilities(
    provider: &crate::CloudProviderConfig,
    target: &CloudTarget,
    configuration: &ResolvedDiskConfiguration,
    runner: &dyn crate::CommandRunner,
) -> Result<Vec<String>, CloudError> {
    if configuration.boot.is_none()
        && configuration.disks.is_empty()
        && target.availability_zone.is_none()
        && !(provider.platform == PlatformKind::Azure && local_ssd_layout(&target.vmtype).is_some())
    {
        return Ok(vec!["No disk profiles selected; existing provider defaults apply. Disk quota and capacity are checked at creation.".into()]);
    }
    let mut checks = Vec::new();
    match provider.platform {
        PlatformKind::Aws => {
            let out = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                runner.run_capture(
                    "aws",
                    &[
                        "ec2",
                        "describe-instance-types",
                        "--instance-types",
                        &target.vmtype,
                        "--region",
                        &provider.region,
                        "--output",
                        "json",
                    ],
                ),
            )
            .await
            .map_err(|_| error("AWS disk capability check timed out"))??;
            let json: serde_json::Value = serde_json::from_str(&out.stdout)?;
            let vm = json["InstanceTypes"]
                .as_array()
                .and_then(|v| v.iter().find(|v| v["InstanceType"] == target.vmtype))
                .ok_or_else(|| {
                    error("AWS returned no matching instance type for disk validation")
                })?;
            let limits = &vm["EbsInfo"]["EbsOptimizedInfo"];
            if let (Some(iops), Some(mbps)) = (
                limits["MaximumIops"].as_u64(),
                limits["MaximumThroughputInMBps"].as_f64(),
            ) {
                // EC2 reports decimal MB/s, while the profile uses binary MiB/s.
                checks.push(format!(
                    "PASS: {} (AWS describe-instance-types)",
                    validate_shared_limits(configuration, iops, mbps * 1_000_000.0 / 1_048_576.0)?
                ));
                if vm["Hypervisor"] == "xen"
                    && configuration
                        .boot
                        .iter()
                        .chain(configuration.disks.values())
                        .any(|p| p.iops.is_some_and(|v| v > 32000))
                {
                    return Err(error("EBS IOPS above 32000 require an AWS Nitro instance"));
                }
            } else {
                checks.push("NOT CHECKED: AWS shared disk performance limit unavailable".into());
            }
        }
        PlatformKind::Gcp => {
            if let Some((iops, mibps)) = gcp_hyperdisk_vm_limits(&target.vmtype) {
                checks.push(format!(
                    "PASS: {} (GCP documented Hyperdisk limits)",
                    validate_shared_limits(configuration, iops, mibps as f64)?
                ));
            } else {
                checks.push(
                    "NOT CHECKED: GCP shared disk performance limit unavailable for this VM family"
                        .into(),
                );
            }
        }
        PlatformKind::Azure => {
            checks.extend(
                crate::azure::capabilities::check(provider, target, configuration, runner).await?,
            );
        }
        _ => (),
    }
    checks.push("NOT CHECKED: disk quota and current capacity; provider creation is the final admission check".into());
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONFIG: &str = r#"
[disk_profiles.fast]
disk_type = "aws-gp3"
iops = 6000
throughput_mibps = 250
[targets.my-gcp]
provider = "actually-aws"
vmtype = "m6a.xlarge"
boot_disk = { profile = "fast", size = "32GB" }
disks.database = { profile = "fast", encryption_workqueues = "bypass" }
"#;
    #[test]
    fn accepted_syntax_resolves_platform_and_manifest_names() {
        let config: crate::CloudConfig = toml::from_str(CONFIG).unwrap();
        let target = &config.targets["my-gcp"];
        let declared = vec![("database".into(), 0, 2000)];
        let resolved = ResolvedDiskConfiguration::resolve(
            &config.disk_profiles,
            target,
            PlatformKind::Aws,
            &declared,
            32,
        )
        .unwrap();
        assert_eq!(resolved.disks["database"].iops, Some(6000));
        assert_eq!(resolved.boot.as_ref().unwrap().throughput_mibps, Some(250));
        assert_eq!(target.selected_boot_disk_size().unwrap(), Some("32GB"));
        assert_eq!(
            target.runtime_disks().mode("database"),
            EncryptionWorkqueues::Bypass
        );
        assert!(ResolvedDiskConfiguration::resolve(
            &config.disk_profiles,
            target,
            PlatformKind::Gcp,
            &declared,
            32
        )
        .is_err());
        assert!(ResolvedDiskConfiguration::resolve(
            &config.disk_profiles,
            target,
            PlatformKind::Aws,
            &[],
            32
        )
        .is_err());
        let mut target = target.clone();
        target.boot_disk.profile = Some("typo".into());
        assert!(ResolvedDiskConfiguration::resolve(
            &config.disk_profiles,
            &target,
            PlatformKind::Aws,
            &declared,
            32
        )
        .is_err());
        target.boot_disk_size = Some("32GB".into());
        assert!(target.selected_boot_disk_size().is_err());
    }
    #[test]
    fn local_ssd_groups_all_members_for_only_one_workload_disk() {
        let text = r#"
[disk_profiles.local]
disk_type = "gcp-local-ssd"
[targets.node]
provider = "gcp"
vmtype = "c3-standard-8-lssd"
disks.database = { profile = "local" }
"#;
        let c: crate::CloudConfig = toml::from_str(text).unwrap();
        let target = &c.targets["node"];
        let declared = vec![("database".into(), 10, 700), ("logs".into(), 11, 10)];
        let resolve = |t: &CloudTarget, p| {
            ResolvedDiskConfiguration::resolve(&c.disk_profiles, t, p, &declared, 24)
        };
        let config = resolve(target, PlatformKind::Gcp).unwrap();
        let local = config.local_ssd().unwrap().unwrap();
        assert_eq!((local.disk.as_str(), local.count), ("database", 2));
        assert!(resolve(target, PlatformKind::Aws).is_err());
        let mut changed = target.clone();
        changed
            .disks
            .insert("logs".into(), changed.disks["database"].clone());
        assert!(resolve(&changed, PlatformKind::Gcp).is_err());
        changed = target.clone();
        changed.vmtype = "c3-standard-4-lssd".into();
        assert!(resolve(&changed, PlatformKind::Gcp).is_err());
        changed.vmtype = "c3-standard-8".into();
        assert!(resolve(&changed, PlatformKind::Gcp).is_err());
        changed = target.clone();
        changed.boot_disk.profile = Some("local".into());
        assert!(resolve(&changed, PlatformKind::Gcp).is_err());
    }

    #[test]
    fn strict_profile_fields_and_disk_modes() {
        for (old, new) in [
            ("iops = 6000", "iops = -1"),
            ("iops = 6000", "iop = 6000"),
            (
                "encryption_workqueues = \"bypass\"",
                "encryption_workqueues = \"fast\"",
            ),
            (
                "profile = \"fast\", encryption",
                "device = \"/dev/sda\", encryption",
            ),
        ] {
            assert!(
                toml::from_str::<crate::CloudConfig>(&CONFIG.replace(old, new)).is_err(),
                "{new}"
            );
        }
    }
    #[test]
    fn size_type_vm_and_performance_limits() {
        let mut p = DiskPerformance {
            disk_type: "gp3".into(),
            iops: Some(6000),
            throughput_mibps: Some(250),
            ..Default::default()
        };
        assert!(p
            .validate(PlatformKind::Aws, "m6a.xlarge", 32, false)
            .is_ok());
        assert!(p
            .validate(PlatformKind::Aws, "m6a.xlarge", 8, false)
            .is_err());
        p.throughput_mibps = Some(1600);
        assert!(p
            .validate(PlatformKind::Aws, "m6a.xlarge", 2000, false)
            .is_err());
        p.disk_type = "pd-balanced".into();
        assert!(p
            .validate(PlatformKind::Gcp, "n2d-standard-4", 2000, false)
            .is_err());
        p.iops = None;
        p.throughput_mibps = None;
        assert!(p
            .validate(PlatformKind::Gcp, "n2d-standard-4", 2000, false)
            .is_ok());
        assert!(p
            .validate(PlatformKind::Gcp, "c4-standard-4", 2000, false)
            .is_err());
        p.disk_type = "hyperdisk-balanced".into();
        p.iops = Some(6000);
        p.throughput_mibps = Some(250);
        assert!(p
            .validate(PlatformKind::Gcp, "c4-standard-4", 2000, false)
            .is_ok());
        assert!(p
            .validate(PlatformKind::Gcp, "n2d-standard-4", 2000, false)
            .is_err());
        assert!(p
            .validate(PlatformKind::Gcp, "c3-standard-4", 2000, true)
            .is_err());
        p.throughput_mibps = Some(500);
        assert!(p
            .validate(PlatformKind::Gcp, "c3-standard-4", 2000, false)
            .is_err());
    }
    #[test]
    fn vm_limit_is_shared_and_saved_configuration_does_not_follow_profile_edits() {
        let mut config: crate::CloudConfig = toml::from_str(CONFIG).unwrap();
        let resolved = ResolvedDiskConfiguration::resolve(
            &config.disk_profiles,
            &config.targets["my-gcp"],
            PlatformKind::Aws,
            &[("database".into(), 0, 2000)],
            32,
        )
        .unwrap();
        assert!(validate_shared_limits(&resolved, 5000, 500.0).is_err());
        assert!(validate_shared_limits(&resolved, 10000, 500.0)
            .unwrap()
            .contains("aggregate"));
        let saved = serde_json::to_vec(&resolved).unwrap();
        config.disk_profiles.get_mut("fast").unwrap().iops = Some(9000);
        let restored: ResolvedDiskConfiguration = serde_json::from_slice(&saved).unwrap();
        assert_eq!(restored.disks["database"].iops, Some(6000));
    }
}
