//! Check the selected VM, disk SKUs and zone before cloud writes.
use crate::{
    disk_profiles::{validate_shared_limits, ResolvedDiskConfiguration},
    CloudError, CloudProviderConfig, CloudTarget, CommandRunner,
};
use serde_json::Value;

fn error(message: impl Into<String>) -> CloudError {
    CloudError::Config {
        message: message.into(),
    }
}

pub(crate) fn capability<'a>(sku: &'a Value, name: &str) -> Option<&'a str> {
    sku["capabilities"].as_array()?.iter().find(|c| {
        c["name"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
    })?["value"]
        .as_str()
}

pub fn validate_location(sku: &Value, region: &str, zone: Option<&str>) -> Result<(), CloudError> {
    let name = sku["name"].as_str().unwrap_or("unknown SKU");
    let location = sku["locationInfo"].as_array().and_then(|locations| {
        locations.iter().find(|v| {
            v["location"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(region))
        })
    });
    if let Some(zone) = zone {
        if !location
            .and_then(|l| l["zones"].as_array())
            .is_some_and(|zones| zones.iter().any(|z| z == zone))
        {
            return Err(error(format!(
                "Azure {name} is unavailable in {region} zone {zone}"
            )));
        }
    }
    for restriction in sku["restrictions"].as_array().into_iter().flatten() {
        let locations = restriction["restrictionInfo"]["locations"]
            .as_array()
            .or_else(|| {
                (restriction["type"] == "Location")
                    .then(|| restriction["values"].as_array())
                    .flatten()
            });
        let here = locations.is_none_or(|locations| {
            locations.is_empty()
                || locations
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(region)))
        });
        if here
            && (restriction["type"] == "Location"
                || (restriction["type"] == "Zone"
                    && zone.is_some_and(|zone| {
                        restriction["restrictionInfo"]["zones"]
                            .as_array()
                            .is_none_or(|zones| zones.iter().any(|z| z == zone))
                    })))
        {
            return Err(error(format!(
                "Azure {name} is restricted in the selected region or zone"
            )));
        }
    }
    Ok(())
}

pub(crate) async fn catalog(
    provider: &CloudProviderConfig,
    kind: &str,
    runner: &dyn CommandRunner,
) -> Result<Value, CloudError> {
    let subscription = provider
        .subscription
        .as_deref()
        .ok_or_else(|| error("Azure subscription is required"))?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        runner.run_capture(
            "az",
            &[
                "vm",
                "list-skus",
                "--location",
                &provider.region,
                "--resource-type",
                kind,
                "--all",
                "--subscription",
                subscription,
                "--output",
                "json",
            ],
        ),
    )
    .await
    .map_err(|_| error("Azure disk capability query timed out"))??;
    Ok(serde_json::from_str(&output.stdout)?)
}

pub(crate) fn find<'a>(catalog: &'a Value, name: &str) -> Result<&'a Value, CloudError> {
    catalog
        .as_array()
        .and_then(|items| {
            items.iter().find(|item| {
                item["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
        })
        .ok_or_else(|| {
            error(format!(
                "Azure returned no capability information for {name}"
            ))
        })
}

pub async fn check(
    provider: &CloudProviderConfig,
    target: &CloudTarget,
    config: &ResolvedDiskConfiguration,
    runner: &dyn CommandRunner,
) -> Result<Vec<String>, CloudError> {
    let vms = catalog(provider, "virtualMachines", runner).await?;
    let vm = find(&vms, &target.vmtype)?;
    validate_location(vm, &provider.region, target.availability_zone.as_deref())?;
    let mut checks = vec![format!(
        "PASS: Azure VM {} in {} zone {}",
        target.vmtype,
        provider.region,
        target.availability_zone.as_deref().unwrap_or("regional")
    )];
    if let (Some(iops), Some(bytes)) = (
        capability(vm, "UncachedDiskIOPS").and_then(|v| v.parse::<u64>().ok()),
        capability(vm, "UncachedDiskBytesPerSecond").and_then(|v| v.parse::<u64>().ok()),
    ) {
        checks.push(validate_shared_limits(
            config,
            iops,
            bytes as f64 / 1_048_576.0,
        )?);
    } else {
        checks.push("NOT CHECKED: Azure shared disk performance limit unavailable".into());
    }
    let kinds: std::collections::BTreeSet<_> = config
        .boot
        .iter()
        .chain(config.disks.values())
        .map(|p| p.disk_type.as_str())
        .filter(|kind| *kind != "local-ssd")
        .collect();
    if !kinds.is_empty() {
        if capability(vm, "PremiumIO") != Some("True") {
            return Err(error("selected Azure VM does not report PremiumIO support"));
        }
        let disks = catalog(provider, "disks", runner).await?;
        for kind in kinds {
            validate_location(
                find(&disks, kind)?,
                &provider.region,
                target.availability_zone.as_deref(),
            )?;
            if kind == "UltraSSD_LRS" {
                let zone = target
                    .availability_zone
                    .as_deref()
                    .ok_or_else(|| error("Ultra Disk requires availability_zone"))?;
                let supported = capability(vm, "UltraSSDAvailable") == Some("True")
                    || vm["locationInfo"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|l| {
                            l["location"]
                                .as_str()
                                .is_some_and(|s| s.eq_ignore_ascii_case(&provider.region))
                        })
                        .flat_map(|l| l["zoneDetails"].as_array().into_iter().flatten())
                        .any(|detail| {
                            detail["name"]
                                .as_array()
                                .is_some_and(|zones| zones.iter().any(|z| z == zone))
                                && capability(detail, "UltraSSDAvailable") == Some("True")
                        });
                if !supported {
                    return Err(error(
                        "selected Azure VM and zone do not report Ultra Disk support",
                    ));
                }
            }
            checks.push(format!(
                "PASS: Azure {kind} is available in the selected location"
            ));
        }
    }
    Ok(checks)
}
