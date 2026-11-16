use super::*;
use serde_json::json;
use std::{collections::VecDeque, sync::Mutex};

struct Runner {
    replies: Mutex<VecDeque<Result<Value>>>,
    calls: Mutex<Vec<(String, Vec<String>)>>,
}
impl Runner {
    fn new(replies: Vec<Result<Value>>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(vec![]),
        }
    }
}
#[async_trait::async_trait]
impl CommandRunner for Runner {
    async fn run_capture(&self, program: &str, args: &[&str]) -> Result<crate::CommandOutput> {
        self.calls
            .lock()
            .unwrap()
            .push((program.into(), args.iter().map(|s| s.to_string()).collect()));
        let v = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected cloud command")?;
        Ok(crate::CommandOutput {
            status: 0,
            stdout: v.to_string(),
            stderr: String::new(),
        })
    }
    async fn run_stream(&self, _: &str, _: &[&str], _: bool) -> Result<crate::CommandOutput> {
        panic!("mutating command")
    }
}
fn config(platform: PlatformKind, vmtype: &str) -> (CloudProviderConfig, CloudTarget) {
    let c = CloudProviderConfig {
        platform,
        project: Some("selected-project".into()),
        subscription: Some("selected-subscription".into()),
        region: "selected-region".into(),
        uefi: None,
    };
    let t: CloudTarget =
        toml::from_str(&format!("provider = 'test'\nvmtype = '{vmtype}'")).unwrap();
    (c, t)
}
fn assert_scope(r: &Runner, flag: &str, expected: &str) {
    for (_, args) in r.calls.lock().unwrap().iter() {
        let index = args
            .iter()
            .position(|s| s == flag)
            .expect("missing explicit scope");
        assert_eq!(args[index + 1], expected);
    }
    assert!(r.replies.lock().unwrap().is_empty());
}
fn aws_identity() -> Result<Value> {
    Ok(json!({"Account":"123456789012"}))
}
fn aws_size() -> Result<Value> {
    Ok(json!({"InstanceTypes":[{"InstanceType":"m6a.large","VCpuInfo":{"DefaultVCpus":2}}]}))
}
fn aws_quota() -> Result<Value> {
    Ok(
        json!({"Quota":{"Value":8,"UsageMetric":{"MetricNamespace":"AWS/Usage","MetricName":"ResourceCount","MetricDimensions":{"Class":"Standard/OnDemand","Resource":"vCPU","Service":"EC2","Type":"Resource"}}}}),
    )
}
#[tokio::test]
async fn preflight_aws_uses_recent_usage_and_stops_at_shortage() {
    let (c, t) = config(PlatformKind::Aws, "m6a.large");
    for (used, valid, passes) in [(6, true, true), (7, true, false), (7, false, true)] {
        let at = if valid {
            chrono::Utc::now()
        } else {
            chrono::Utc::now() - chrono::Duration::minutes(20)
        };
        let r = Runner::new(vec![
            aws_identity(),
            aws_size(),
            aws_quota(),
            Ok(json!({"Datapoints":[{"Timestamp":at.to_rfc3339(),"Maximum":used}]})),
        ]);
        let result = check(&c, &t, &r).await;
        assert_eq!(result.is_ok(), passes);
        if !valid {
            assert!(result
                .unwrap()
                .iter()
                .any(|s| s.starts_with("NOT CHECKED: AWS Standard")));
        }
        assert_scope(&r, "--region", "selected-region");
    }
}
#[tokio::test]
async fn preflight_missing_quota_permissions_are_not_passes() {
    let (c, t) = config(PlatformKind::Aws, "m6a.large");
    let r = Runner::new(vec![
        aws_identity(),
        aws_size(),
        Err(error("access denied")),
    ]);
    let result = check(&c, &t, &r).await.unwrap();
    assert!(result
        .iter()
        .any(|s| s.starts_with("NOT CHECKED: AWS Standard")));
    assert_scope(&r, "--region", "selected-region");
}
#[tokio::test]
async fn preflight_authentication_failure_stops_each_provider() {
    for (p, vm) in [
        (PlatformKind::Aws, "m6a.large"),
        (PlatformKind::Azure, "Standard_DC2as_v5"),
        (PlatformKind::Gcp, "n2d-standard-2"),
    ] {
        let (c, t) = config(p, vm);
        let r = Runner::new(vec![Err(error("expired credentials"))]);
        assert!(check(&c, &t, &r)
            .await
            .unwrap_err()
            .to_string()
            .contains("expired credentials"));
        assert_eq!(r.calls.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn preflight_gcp_checks_zone_region_family_and_global_cpu_quotas() {
    let (c, t) = config(PlatformKind::Gcp, "n2d-standard-2");
    for (metric, used, passes) in [
        ("N2D_CPUS", 6, true),
        ("N2D_CPUS", 7, false),
        ("CPUS_ALL_REGIONS", 7, false),
        ("UNKNOWN", 7, true),
    ] {
        let mut replies = vec![
            Ok(json!({"region":"https://compute/regions/actual-region"})),
            Ok(json!({"guestCpus":2})),
            Ok(
                json!({"quotas":[{"metric":if metric=="N2D_CPUS" {metric} else {"UNKNOWN"},"usage":used,"limit":8}]}),
            ),
        ];
        if metric != "N2D_CPUS" || passes {
            replies.push(Ok(json!({"quotas":[{"metric":if metric=="CPUS_ALL_REGIONS" {metric} else {"UNKNOWN"},"usage":used,"limit":8}]})));
        }
        let r = Runner::new(replies);
        let result = check(&c, &t, &r).await;
        assert_eq!(result.is_ok(), passes, "{result:?}");
        assert_scope(&r, "--project", "selected-project");
        let calls = r.calls.lock().unwrap();
        assert_eq!(calls[0].1[3], "selected-region");
        assert_eq!(calls[2].1[3], "actual-region");
    }
}
fn azure_sku(restrictions: Value) -> Result<Value> {
    Ok(
        json!([{"name":"Standard_DC2as_v5","family":"standardDCASv5Family","capabilities":[{"name":"vCPUs","value":"2"}],"restrictions":restrictions}]),
    )
}
#[tokio::test]
async fn preflight_azure_checks_total_and_family_quotas() {
    let (c, t) = config(PlatformKind::Azure, "Standard_DC2as_v5");
    for (total, family, passes) in [(6, 6, true), (7, 0, false), (0, 7, false)] {
        let r = Runner::new(vec![
            azure_sku(json!([])),
            Ok(json!([
                {"name":{"value":"cores"},"currentValue":total,"limit":8},
                {"name":{"value":"standardDCASv5Family"},"currentValue":family,"limit":8}
            ])),
        ]);
        assert_eq!(check(&c, &t, &r).await.is_ok(), passes);
        assert_scope(&r, "--subscription", "selected-subscription");
        assert_scope(&r, "--location", "selected-region");
    }
}
#[tokio::test]
async fn preflight_azure_rejects_location_restrictions_but_not_unused_zone_restrictions() {
    let (c, t) = config(PlatformKind::Azure, "Standard_DC2as_v5");
    let r = Runner::new(vec![azure_sku(json!([{"type":"Location"}]))]);
    assert!(check(&c, &t, &r)
        .await
        .unwrap_err()
        .to_string()
        .contains("restricted"));
    let r = Runner::new(vec![
        azure_sku(json!([{"type":"Zone"}])),
        Err(error("quota access denied")),
    ]);
    let result = check(&c, &t, &r).await.unwrap();
    assert!(result
        .iter()
        .any(|s| s.starts_with("NOT CHECKED: Azure cores")));
}
#[test]
fn preflight_missing_invalid_numbers_never_become_zero_usage() {
    for v in [Value::Null, json!(-1), json!("NaN"), json!("inf")] {
        assert_eq!(number(&v), None);
    }
    assert!(quota("test", None, Some(8.0), 2.0)
        .unwrap()
        .starts_with("NOT CHECKED"));
    assert!(quota("test", Some(0.0), Some(0.0), 2.0).is_err());
}
