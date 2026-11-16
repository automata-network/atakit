use crate::{disk_profiles::*, *};
use serde_json::json;

fn config(kind: &str, vm: &str, performance: &str) -> CloudConfig {
    toml::from_str(&format!(
        r#"
[disk_profiles.fast]
disk_type = "{kind}"
{performance}
[targets.node]
provider = "test"
vmtype = "{vm}"
disks.database = {{ profile = "fast" }}
"#
    ))
    .unwrap()
}

fn resolve(
    config: &CloudConfig,
    platform: PlatformKind,
    size: u64,
) -> Result<ResolvedDiskConfiguration, CloudError> {
    ResolvedDiskConfiguration::resolve(
        &config.disk_profiles,
        &config.targets["node"],
        platform,
        &[("database".into(), 0, size)],
        32,
    )
}

#[test]
fn io2_requires_iops_and_rejects_throughput_or_impossible_sizes() {
    let valid = config("aws-io2", "c6a.16xlarge", "iops = 80000");
    let selected = resolve(&valid, PlatformKind::Aws, 80).unwrap();
    assert_eq!(selected.disks["database"].disk_type, "io2");
    assert!(resolve(&valid, PlatformKind::Aws, 79).is_err());
    for perf in [
        "",
        "iops=99",
        "iops=256001",
        "iops=80000\nthroughput_mibps=1000",
    ] {
        assert!(resolve(
            &config("aws-io2", "c6a.16xlarge", perf),
            PlatformKind::Aws,
            1000
        )
        .is_err());
    }
    let small = config("aws-io2", "m6a.large", "iops=100");
    assert!(resolve(&small, PlatformKind::Aws, 3).is_err());
    assert!(resolve(&small, PlatformKind::Aws, 4).is_ok());
}

#[test]
fn azure_profiles_require_zone_and_enforce_data_disk_and_performance_limits() {
    for (kind, sku, iops, throughput, size) in [
        ("azure-premium-ssd-v2", "PremiumV2_LRS", 80000, 1907, 160),
        ("azure-ultra-disk", "UltraSSD_LRS", 400000, 9536, 400),
    ] {
        let mut c = config(
            kind,
            "Standard_DC128es_v6",
            &format!("iops={iops}\nthroughput_mibps={throughput}"),
        );
        assert!(resolve(&c, PlatformKind::Azure, size).is_err());
        c.targets.get_mut("node").unwrap().availability_zone = Some("1".into());
        let resolved = resolve(&c, PlatformKind::Azure, size).unwrap();
        assert_eq!(resolved.disks["database"].disk_type, sku);
        assert!(resolve(&c, PlatformKind::Azure, size - 1).is_err());
        assert!(resolve(&c, PlatformKind::Aws, size).is_err());
        c.disk_profiles.get_mut("fast").unwrap().throughput_mibps = Some(throughput + 1);
        assert!(resolve(&c, PlatformKind::Azure, size).is_err());
        c.disk_profiles.get_mut("fast").unwrap().throughput_mibps = None;
        c.targets.get_mut("node").unwrap().boot_disk.profile = Some("fast".into());
        assert!(resolve(&c, PlatformKind::Azure, size).is_err());
    }
    let mut c = config("azure-ultra-disk", "Standard_DC32as_v6", "iops=1000");
    c.targets.get_mut("node").unwrap().availability_zone = Some("1".into());
    assert!(resolve(&c, PlatformKind::Azure, 32).is_ok()); // Live SKU/zone support is checked separately.
    let c = config("azure-premium-ssd", "Standard_DC4as_v5", "");
    assert!(resolve(&c, PlatformKind::Azure, 32).is_ok());
    assert!(resolve(&c, PlatformKind::Azure, 32768).is_err());
}

#[test]
fn local_azure_sizes_group_only_their_included_devices() {
    for (vm, count, member_size) in [
        ("Standard_DC2eds_v6", 1, 110),
        ("Standard_DC16eds_v6", 2, 440),
        ("Standard_DC32eds_v6", 4, 440),
        ("Standard_DC48eds_v6", 6, 440),
        ("Standard_DC96eds_v6", 6, 880),
        ("Standard_DC128eds_v6", 4, 1760),
        ("Standard_DC32ads_v5", 1, 1200),
        ("Standard_DC32ads_v6", 1, 1200),
    ] {
        assert_eq!(local_ssd_layout(vm), Some((count, member_size)));
        let c = config("azure-local-ssd", vm, "");
        let resolved = resolve(&c, PlatformKind::Azure, 100).unwrap();
        let local = resolved.local_ssd().unwrap().unwrap();
        assert_eq!(local.count, count);
        local.validate().unwrap();
        assert!(resolve(&c, PlatformKind::Azure, u64::from(count) * member_size + 1).is_err());
        assert_eq!(
            infer_cc_type(PlatformKind::Azure, vm).unwrap(),
            if vm.ends_with("eds_v6") {
                CcType::Tdx
            } else {
                CcType::SevSnp
            }
        );
    }
    for vm in [
        "Standard_DC32es_v6",
        "Standard_DC32as_v6",
        "Standard_DC128ads_v6",
        "m6a.large",
    ] {
        assert!(resolve(&config("azure-local-ssd", vm, ""), PlatformKind::Azure, 10).is_err());
    }
    let mut c = config("azure-local-ssd", "Standard_DC32eds_v6", "");
    c.targets.get_mut("node").unwrap().boot_disk.profile = Some("fast".into());
    assert!(resolve(&c, PlatformKind::Azure, 10).is_err());
}

#[test]
fn azure_inventory_checks_exact_decimal_throughput() {
    let spec = DiskSpec {
        name: "vm-data".into(),
        device_name: "data".into(),
        index: 0,
        size_gb: 32,
        disk_type: "UltraSSD_LRS".into(),
        performance: Some(DiskPerformance {
            disk_type: "UltraSSD_LRS".into(),
            iops: Some(1000),
            throughput_mibps: Some(20),
            profile: None,
        }),
    };
    let mut value = json!({"sku":{"name":"UltraSSD_LRS"}, "properties":{
        "uniqueId":"disk-id", "diskSizeGB":32, "diskIOPSReadWrite":1000, "diskMBpsReadWrite":21, "provisioningState":"Succeeded"
    }});
    crate::disk_inventory::validate_azure(&spec, &value).unwrap();
    value["properties"]["diskMBpsReadWrite"] = 22.into();
    // Both values round down to 20 MiB/s. The exact MB/s check must still fail.
    assert_eq!(
        crate::disk_inventory::azure_observation(&value)
            .unwrap()
            .throughput_mibps,
        Some(20)
    );
    assert!(crate::disk_inventory::validate_azure(&spec, &value).is_err());
    assert!(azure_mbps(u64::MAX).is_err());
}

#[test]
fn azure_zone_checks_reject_unavailable_or_restricted_placement() {
    let mut sku = json!({"name":"test", "locationInfo":[{"location":"eastus", "zones":["1","2"]}], "restrictions":[]});
    crate::azure::capabilities::validate_location(&sku, "eastus", Some("1")).unwrap();
    assert!(crate::azure::capabilities::validate_location(&sku, "eastus", Some("3")).is_err());
    sku["restrictions"] =
        json!([{"type":"Zone", "restrictionInfo":{"locations":["eastus"],"zones":["1"]}}]);
    assert!(crate::azure::capabilities::validate_location(&sku, "eastus", Some("1")).is_err());
    crate::azure::capabilities::validate_location(&sku, "eastus", Some("2")).unwrap();
    sku["restrictions"] = json!([{"type":"Location", "values":["eastus"]}]);
    assert!(crate::azure::capabilities::validate_location(&sku, "eastus", None).is_err());
}

#[test]
fn azure_vm_budget_checks_include_decimal_rounding() {
    let mut configuration = ResolvedDiskConfiguration::default();
    configuration.disks.insert(
        "data".into(),
        DiskPerformance {
            disk_type: "PremiumV2_LRS".into(),
            throughput_mibps: Some(250),
            ..Default::default()
        },
    );
    assert!(validate_shared_limits(&configuration, 6000, 250.1).is_err());
    validate_shared_limits(&configuration, 6000, 251.0).unwrap();
}

struct AzureCatalogRunner {
    vm: serde_json::Value,
}

#[async_trait::async_trait]
impl CommandRunner for AzureCatalogRunner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CloudError> {
        assert_eq!(program, "az");
        assert!(args.starts_with(&["vm", "list-skus"]));
        let result = if args.contains(&"virtualMachines") {
            json!([self.vm])
        } else {
            assert!(args.contains(&"disks"));
            json!([{"name":"UltraSSD_LRS", "locationInfo":[{"location":"eastus", "zones":["1","2"]}]}])
        };
        Ok(CommandOutput {
            status: 0,
            stdout: result.to_string(),
            stderr: String::new(),
        })
    }

    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<CommandOutput, CloudError> {
        panic!("capability checks must only read the catalog")
    }
}

#[tokio::test]
async fn azure_preflight_checks_ultra_zone_and_local_vm_without_profiles() {
    let provider = CloudProviderConfig {
        platform: PlatformKind::Azure,
        subscription: Some("subscription".into()),
        region: "eastus".into(),
        project: None,
        uefi: None,
    };
    let runner = AzureCatalogRunner {
        vm: json!({"name":"Standard_DC32ads_v6",
        "locationInfo":[{"location":"eastus", "zones":["1","2"], "zoneDetails":[{
            "name":["1"], "capabilities":[{"name":"UltraSSDAvailable","value":"True"}]
        }]}],
        "capabilities":[
            {"name":"PremiumIO","value":"True"},
            {"name":"UncachedDiskIOPS","value":"57600"},
            {"name":"UncachedDiskBytesPerSecond","value":"1440000000"}
        ]}),
    };
    let mut c = config("azure-ultra-disk", "Standard_DC32ads_v6", "iops=1000");
    c.targets.get_mut("node").unwrap().availability_zone = Some("1".into());
    let resolved = resolve(&c, PlatformKind::Azure, 32).unwrap();
    check_capabilities(&provider, &c.targets["node"], &resolved, &runner)
        .await
        .unwrap();
    c.targets.get_mut("node").unwrap().availability_zone = Some("2".into());
    assert!(
        check_capabilities(&provider, &c.targets["node"], &resolved, &runner)
            .await
            .is_err()
    );

    let target = c.targets.get_mut("node").unwrap();
    target.availability_zone = None;
    target.disks.clear();
    let defaults = ResolvedDiskConfiguration::default();
    check_capabilities(&provider, target, &defaults, &runner)
        .await
        .unwrap();
    target.vmtype = "Standard_DC32eds_v6".into();
    assert!(check_capabilities(&provider, target, &defaults, &runner)
        .await
        .is_err());
}
