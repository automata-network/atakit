//! Read-only deployment checks. CPU quotas are observations, not reservations.
use std::time::Duration;

use serde_json::Value;

use crate::{CloudError, CloudProviderConfig, CloudTarget, CommandRunner, PlatformKind};

type Result<T> = std::result::Result<T, CloudError>;
fn error(message: impl Into<String>) -> CloudError {
    CloudError::Config {
        message: message.into(),
    }
}

async fn query(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<Value> {
    query_with_timeout(runner, program, args, Duration::from_secs(30)).await
}

async fn query_with_timeout(
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Value> {
    let output = tokio::time::timeout(timeout, runner.run_capture(program, args))
        .await
        .map_err(|_| {
            error(format!(
                "{program} {} deployment check timed out after {} seconds",
                args.iter().take(2).copied().collect::<Vec<_>>().join(" "),
                timeout.as_secs()
            ))
        })??;
    serde_json::from_str(&output.stdout)
        .map_err(|_| error(format!("{program} deployment check returned invalid JSON")))
}

fn number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|n| n.is_finite() && *n >= 0.0)
}

fn quota(label: &str, usage: Option<f64>, limit: Option<f64>, needed: f64) -> Result<String> {
    let (Some(usage), Some(limit)) = (usage, limit) else {
        return Ok(format!("NOT CHECKED: {label} (usage or limit unavailable)"));
    };
    if usage + needed > limit {
        return Err(error(format!(
            "insufficient {label}: {usage} used, {limit} limit, {needed} needed"
        )));
    }
    Ok(format!(
        "PASS: {label}: {usage} used, {limit} limit, {needed} needed"
    ))
}

/// Authentication/target failures and known quota shortages stop deployment.
/// Missing quota permissions/data remain visible without claiming a pass.
pub async fn check(
    config: &CloudProviderConfig,
    target: &CloudTarget,
    runner: &dyn CommandRunner,
) -> Result<Vec<String>> {
    let mut checks = match config.platform {
        PlatformKind::Aws => aws(config, target, runner).await?,
        PlatformKind::Gcp => gcp(config, target, runner).await?,
        PlatformKind::Azure => azure(config, target, runner).await?,
        PlatformKind::Qemu => {
            crate::qemu::deps::check_local_deps()?;
            return Ok(vec![
                "PASS: local QEMU dependencies".into(),
                "NOT APPLICABLE: cloud authentication and quotas (QEMU)".into(),
            ]);
        }
    };
    checks.push("NOT CHECKED: other resource quotas and current host capacity; CPU checks do not reserve capacity".into());
    Ok(checks)
}

async fn aws(
    c: &CloudProviderConfig,
    t: &CloudTarget,
    r: &dyn CommandRunner,
) -> Result<Vec<String>> {
    let identity = query(
        r,
        "aws",
        &[
            "sts",
            "get-caller-identity",
            "--region",
            &c.region,
            "--output",
            "json",
        ],
    )
    .await?;
    let account = identity["Account"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("AWS did not return an authenticated account"))?;
    let sizes = query(
        r,
        "aws",
        &[
            "ec2",
            "describe-instance-types",
            "--instance-types",
            &t.vmtype,
            "--region",
            &c.region,
            "--output",
            "json",
        ],
    )
    .await?;
    let size = sizes["InstanceTypes"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["InstanceType"] == t.vmtype))
        .ok_or_else(|| {
            error(format!(
                "AWS instance type {} is unavailable in {}",
                t.vmtype, c.region
            ))
        })?;
    let cpus = number(&size["VCpuInfo"]["DefaultVCpus"])
        .filter(|n| *n > 0.0)
        .ok_or_else(|| error("AWS instance type has no valid vCPU count"))?;
    let mut checks = vec![format!(
        "PASS: AWS authentication (account {account}) and instance type {} in {}",
        t.vmtype, c.region
    )];
    // This quota covers Standard On-Demand families only, not GPU/HPC/Spot pools.
    let family = t.vmtype.split('.').next().unwrap_or("");
    let standard = ["a", "c", "d", "h", "i", "m", "r", "t", "z"]
        .iter()
        .any(|prefix| {
            family
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        });
    if !standard {
        checks.push(
            "NOT CHECKED: AWS CPU quota (instance family has no supported quota mapping)".into(),
        );
        return Ok(checks);
    }
    let response = query(
        r,
        "aws",
        &[
            "service-quotas",
            "get-service-quota",
            "--service-code",
            "ec2",
            "--quota-code",
            "L-1216C47A",
            "--region",
            &c.region,
            "--output",
            "json",
        ],
    )
    .await;
    let Ok(response) = response else {
        checks.push(
            "NOT CHECKED: AWS Standard On-Demand vCPU quota (quota query unavailable)".into(),
        );
        return Ok(checks);
    };
    let q = &response["Quota"];
    // Get the usage metric from AWS, rather than infer usage from a partial VM list.
    let metric = &q["UsageMetric"];
    let (Some(namespace), Some(name), Some(dimensions)) = (
        metric["MetricNamespace"].as_str(),
        metric["MetricName"].as_str(),
        metric["MetricDimensions"].as_object(),
    ) else {
        checks.push(
            "NOT CHECKED: AWS Standard On-Demand vCPU quota (usage metric unavailable)".into(),
        );
        return Ok(checks);
    };
    let dimensions: Vec<Value> = dimensions
        .iter()
        .filter_map(|(name, value)| Some(serde_json::json!({"Name":name, "Value":value.as_str()?})))
        .collect();
    if dimensions.len() != metric["MetricDimensions"].as_object().unwrap().len() {
        checks.push(
            "NOT CHECKED: AWS Standard On-Demand vCPU quota (invalid usage dimensions)".into(),
        );
        return Ok(checks);
    }
    let dimensions = serde_json::to_string(&dimensions).map_err(|e| error(e.to_string()))?;
    let now = chrono::Utc::now();
    let start = (now - chrono::Duration::minutes(10)).to_rfc3339();
    let end = now.to_rfc3339();
    let data = query(
        r,
        "aws",
        &[
            "cloudwatch",
            "get-metric-statistics",
            "--namespace",
            namespace,
            "--metric-name",
            name,
            "--dimensions",
            &dimensions,
            "--start-time",
            &start,
            "--end-time",
            &end,
            "--period",
            "60",
            "--statistics",
            "Maximum",
            "--region",
            &c.region,
            "--output",
            "json",
        ],
    )
    .await;
    let usage = data.ok().and_then(|v| {
        v["Datapoints"]
            .as_array()?
            .iter()
            .filter_map(|p| {
                let at = chrono::DateTime::parse_from_rfc3339(p["Timestamp"].as_str()?)
                    .ok()?
                    .with_timezone(&chrono::Utc);
                (at <= now && at >= now - chrono::Duration::minutes(5))
                    .then_some((at, number(&p["Maximum"])?))
            })
            .max_by_key(|(at, _)| *at)
            .map(|(_, usage)| usage)
    });
    checks.push(quota(
        "AWS Standard On-Demand vCPU quota (recent CloudWatch usage)",
        usage,
        number(&q["Value"]),
        cpus,
    )?);
    Ok(checks)
}

async fn gcp(
    c: &CloudProviderConfig,
    t: &CloudTarget,
    r: &dyn CommandRunner,
) -> Result<Vec<String>> {
    let project = c
        .project
        .as_deref()
        .ok_or_else(|| error("GCP project is required"))?;
    // GCP deployment treats provider.region as the zone; obtain its region from the API.
    let zone = query(
        r,
        "gcloud",
        &[
            "compute",
            "zones",
            "describe",
            &c.region,
            "--project",
            project,
            "--format=json",
            "--quiet",
        ],
    )
    .await?;
    let region = zone["region"]
        .as_str()
        .and_then(|s| s.rsplit('/').next())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("GCP zone did not return its region"))?;
    let size = query(
        r,
        "gcloud",
        &[
            "compute",
            "machine-types",
            "describe",
            &t.vmtype,
            "--zone",
            &c.region,
            "--project",
            project,
            "--format=json",
            "--quiet",
        ],
    )
    .await?;
    let cpus = number(&size["guestCpus"])
        .filter(|n| *n > 0.0)
        .ok_or_else(|| error("GCP machine type has no valid vCPU count"))?;
    let mut checks = vec![format!(
        "PASS: GCP authentication and machine type {} in project {project}, zone {}",
        t.vmtype, c.region
    )];
    let metric = match t.vmtype.split('-').next().unwrap_or("") {
        "n1" | "e2" => Some("CPUS"),
        "n2" => Some("N2_CPUS"),
        "n2d" => Some("N2D_CPUS"),
        "c2" => Some("C2_CPUS"),
        "c2d" => Some("C2D_CPUS"),
        "c3" => Some("C3_CPUS"),
        "c3d" => Some("C3D_CPUS"),
        "t2d" => Some("T2D_CPUS"),
        _ => None,
    };
    if let Some(metric) = metric {
        let data = query(
            r,
            "gcloud",
            &[
                "compute",
                "regions",
                "describe",
                region,
                "--project",
                project,
                "--format=json",
                "--quiet",
            ],
        )
        .await;
        checks.push(gcp_quota(data.as_ref().ok(), metric, cpus)?);
    } else {
        checks.push(
            "NOT CHECKED: GCP regional CPU quota (machine family has no supported quota mapping)"
                .into(),
        );
    }
    let data = query(
        r,
        "gcloud",
        &[
            "compute",
            "project-info",
            "describe",
            "--project",
            project,
            "--format=json",
            "--quiet",
        ],
    )
    .await;
    checks.push(gcp_quota(data.as_ref().ok(), "CPUS_ALL_REGIONS", cpus)?);
    Ok(checks)
}

fn gcp_quota(data: Option<&Value>, metric: &str, cpus: f64) -> Result<String> {
    let q = data
        .and_then(|v| v["quotas"].as_array())
        .and_then(|a| a.iter().find(|q| q["metric"] == metric));
    quota(
        &format!("GCP {metric} quota"),
        q.and_then(|q| number(&q["usage"])),
        q.and_then(|q| number(&q["limit"])),
        cpus,
    )
}

async fn azure(
    c: &CloudProviderConfig,
    t: &CloudTarget,
    r: &dyn CommandRunner,
) -> Result<Vec<String>> {
    let subscription = c
        .subscription
        .as_deref()
        .ok_or_else(|| error("Azure subscription is required"))?;
    // list-skus enumerates the regional SKU catalog before filtering the size.
    // A successful live query can exceed one minute, so allow two minutes here.
    let data = query_with_timeout(
        r,
        "az",
        &[
            "vm",
            "list-skus",
            "--location",
            &c.region,
            "--size",
            &t.vmtype,
            "--resource-type",
            "virtualMachines",
            "--all",
            "--subscription",
            subscription,
            "--output",
            "json",
        ],
        Duration::from_secs(120),
    )
    .await?;
    let sku = data
        .as_array()
        .and_then(|a| {
            a.iter().find(|s| {
                s["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&t.vmtype))
            })
        })
        .ok_or_else(|| {
            error(format!(
                "Azure VM size {} is unavailable in {}",
                t.vmtype, c.region
            ))
        })?;
    if sku["restrictions"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v["type"] == "Location"))
    {
        return Err(error(format!(
            "Azure VM size {} is restricted in {} for subscription {subscription}",
            t.vmtype, c.region
        )));
    }
    let cpus = sku["capabilities"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["name"] == "vCPUs"))
        .and_then(|v| number(&v["value"]))
        .filter(|n| *n > 0.0)
        .ok_or_else(|| error("Azure VM size has no valid vCPU count"))?;
    let mut checks = vec![format!(
        "PASS: Azure authentication and VM size {} in subscription {subscription}, region {}",
        t.vmtype, c.region
    )];
    let usage = query(
        r,
        "az",
        &[
            "vm",
            "list-usage",
            "--location",
            &c.region,
            "--subscription",
            subscription,
            "--output",
            "json",
        ],
    )
    .await;
    for name in [Some("cores"), sku["family"].as_str()] {
        let Some(name) = name else {
            checks.push("NOT CHECKED: Azure VM family CPU quota (SKU family unavailable)".into());
            continue;
        };
        let q = usage
            .as_ref()
            .ok()
            .and_then(|v| v.as_array())
            .and_then(|a| {
                a.iter().find(|v| {
                    v["name"]["value"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(name))
                })
            });
        checks.push(quota(
            &format!("Azure {name} CPU quota"),
            q.and_then(|v| number(&v["currentValue"])),
            q.and_then(|v| number(&v["limit"])),
            cpus,
        )?);
    }
    Ok(checks)
}

#[cfg(test)]
mod tests;
