//! Recover cloud creation without adopting resources found by name.
use crate::{CloudError, CommandRunner, DeployState, DeployStep};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, time::Duration};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Provisioning {
    /// Only disk/instance steps. Image uploads and firewall edits are not replayed.
    pub steps: Vec<DeployStep>,
    pub next_step: usize,
    pub started: bool,
    pub creations: BTreeMap<String, Creation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CreateRequest {
    Aws {
        args: Vec<String>,
    },
    Gcp {
        project: String,
        zone: String,
        collection: String,
        body: Value,
    },
    Azure {
        subscription: String,
        group: String,
        template: Value,
    },
    AzureVm {
        subscription: String,
        group: String,
        name: String,
        body: Value,
    },
    AzureNetwork {
        id: String,
        api_version: String,
        body: Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creation {
    #[serde(default)]
    pub outcome: CreationOutcome,
    pub request: CreateRequest,
    pub token: String,
    pub sent: bool,
    pub receipt: Option<Value>,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationOutcome {
    #[default]
    NotSubmitted,
    Rejected,
    Unknown,
    Accepted,
    Succeeded,
    Failed,
}

impl Creation {
    pub fn unresolved(&self) -> bool {
        self.sent
            && self.result.is_none()
            && !matches!(
                self.outcome,
                CreationOutcome::Rejected | CreationOutcome::Failed
            )
    }
}

pub(crate) fn error(message: impl Into<String>) -> CloudError {
    CloudError::State {
        message: message.into(),
    }
}

pub fn is_step(step: &DeployStep) -> bool {
    matches!(
        step,
        DeployStep::CreateDisks { .. }
            | DeployStep::CreateInstance { .. }
            | DeployStep::CreateInstanceAws { .. }
            | DeployStep::CreateInstanceAzure { .. }
    )
}

pub fn ensure_before_init(state: &DeployState) -> Result<(), CloudError> {
    if state.cleanup.started {
        return Err(error(
            "cleanup has started; use cloud destroy to finish cleanup",
        ));
    }
    if state
        .initialization
        .as_ref()
        .is_some_and(|i| i.phase != crate::resume::InitializationPhase::Prepared)
    {
        return Err(error(
            "initialization may already have been sent; cloud provisioning cannot be replayed",
        ));
    }
    Ok(())
}

/// Execute just the saved provisioning sequence. Each provider rechecks known
/// identities before attaching, waiting, or reusing a completed create result.
pub async fn resume(
    data_dir: &Path,
    target: &str,
    instance: &str,
    provider: &dyn crate::CloudProvider,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let mut state = DeployState::load(data_dir, target, instance)?;
    ensure_before_init(&state)?;
    if !state.provisioning.started || state.provisioning.steps.is_empty() {
        return Err(error(
            "no saved cloud provisioning sequence; cannot replay earlier image or network setup",
        ));
    }
    let durable = crate::resume::DeploymentRunner {
        runner,
        data_dir,
        target,
        instance,
    };
    while state.provisioning.next_step < state.provisioning.steps.len() {
        let step = state.provisioning.steps[state.provisioning.next_step].clone();
        if !is_step(&step) {
            return Err(error("invalid saved provisioning step"));
        }
        let result = provider.execute_step(&step, &durable, false).await?;
        state = DeployState::load(data_dir, target, instance)?;
        state.apply_resource_updates(&result.resource_updates);
        state.provisioning.next_step += 1;
        state.save(data_dir)?;
    }
    crate::disk_inventory::status(&state, runner).await?;
    state.provisioning_complete = true;
    state.save(data_dir)
}

/// Execute a create using an already durable request. `sent` is set before
/// entering this function. Cached results are returned without another write.
pub async fn execute<R: CommandRunner + ?Sized>(
    runner: &R,
    key: &str,
    creation: &Creation,
    recovering: bool,
) -> Result<Value, CloudError> {
    execute_with_wait(runner, key, creation, recovering, true).await
}

pub async fn reconcile<R: CommandRunner + ?Sized>(
    runner: &R,
    key: &str,
    creation: &Creation,
) -> Result<Value, CloudError> {
    if let CreateRequest::Aws { args } = &creation.request {
        if key == "instance" && args.iter().any(|s| s == "run-instances") {
            let region = args
                .windows(2)
                .find(|pair| pair[0] == "--region")
                .map(|pair| pair[1].as_str())
                .ok_or_else(|| error("saved AWS region is missing"))?;
            let out = runner
                .run_capture(
                    "aws",
                    &[
                        "ec2",
                        "describe-instances",
                        "--region",
                        region,
                        "--filters",
                        &format!("Name=client-token,Values={}", creation.token),
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let value: Value = serde_json::from_str(&out.stdout)?;
            let instances: Vec<_> = value["Reservations"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|r| r["Instances"].as_array().into_iter().flatten())
                .collect();
            if instances.len() == 1 && instances[0]["ClientToken"] == creation.token {
                return Ok(json!({"Instances":[instances[0]]}));
            }
        }
        return Err(error(
            "AWS creation response is unknown; retained the saved request for recovery",
        ));
    }
    execute_with_wait(runner, key, creation, true, false).await
}

async fn execute_with_wait<R: CommandRunner + ?Sized>(
    runner: &R,
    key: &str,
    creation: &Creation,
    recovering: bool,
    wait: bool,
) -> Result<Value, CloudError> {
    if let Some(result) = &creation.result {
        return Ok(result.clone());
    }
    match &creation.request {
        CreateRequest::Aws { args } => {
            let mut args = args.clone();
            args.extend(["--client-token".into(), creation.token.clone()]);
            let out = runner
                .run_capture("aws", &args.iter().map(String::as_str).collect::<Vec<_>>())
                .await
                .map_err(|e| if recovering { e } else { rejected_command(e) })?;
            Ok(serde_json::from_str(&out.stdout)?)
        }
        CreateRequest::Gcp {
            project,
            zone,
            collection,
            body,
        } => {
            let base = format!(
                "https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}"
            );
            let mut operation = if let Some(receipt) = &creation.receipt {
                receipt.clone()
            } else if recovering {
                // The operation, not the current resource name, proves which
                // numeric incarnation was created by this exact request.
                let url = format!("{base}/operations?filter={}", url_filter(&creation.token));
                let list = runner.gcp_api("GET", &url, None).await?;
                let matches: Vec<_> = list["items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|o| {
                        o["clientOperationId"] == creation.token && o["operationType"] == "insert"
                    })
                    .collect();
                if matches.len() != 1 {
                    return Err(error("original GCP creation operation is unavailable; refusing to create or adopt another resource"));
                }
                matches[0].clone()
            } else {
                let url = format!("{base}/{collection}?requestId={}", creation.token);
                runner
                    .gcp_api("POST", &url, Some(body))
                    .await
                    .map_err(rejected_response)?
            };
            let resource_name = body["name"]
                .as_str()
                .ok_or_else(|| error("missing GCP resource name"))?;
            let expected_link =
                format!("/projects/{project}/zones/{zone}/{collection}/{resource_name}");
            let name = identity(&operation["name"])?;
            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(error("invalid GCP operation name"));
            }
            let validate = |operation: &Value| -> Result<(), CloudError> {
                if operation["name"] != name
                    || !operation["targetLink"]
                        .as_str()
                        .is_some_and(|s| s.ends_with(&expected_link))
                    || operation["clientOperationId"] != creation.token
                    || operation["operationType"] != "insert"
                {
                    return Err(error(
                        "GCP creation operation does not match the saved request",
                    ));
                }
                Ok(())
            };
            validate(&operation)?;
            runner.record_creation_receipt(key, &operation).await?;
            for _ in 0..if wait { 120 } else { 1 } {
                if operation["status"] == "DONE" {
                    break;
                }
                if wait {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                // Cleanup refreshes once without waiting or resubmitting creation.
                operation = runner
                    .gcp_api("GET", &format!("{base}/operations/{name}"), None)
                    .await?;
                validate(&operation)?;
                runner.record_creation_receipt(key, &operation).await?;
            }
            if operation["status"] != "DONE" {
                return Err(error(
                    "GCP creation is still pending; retry cloud resume or cloud destroy",
                ));
            }
            if operation.get("error").is_some_and(|e| !e.is_null()) {
                // A failed operation cannot establish ownership of a resource
                // found by name. Only retire this request once absence is known.
                match runner.gcp_api("GET", &format!("{base}/{collection}/{resource_name}"), None).await {
                    Err(CloudError::ProviderResponse { status: 404, .. }) => {
                        return Err(CloudError::CreationFailed {
                            message: format!("GCP creation failed; requested resource is absent: {}", operation["error"]),
                        });
                    }
                    Err(e) => return Err(e),
                    Ok(_) => return Err(error("GCP creation failed but a resource exists at the requested name; ownership is unresolved, resource retained")),
                }
            }
            let id = identity(&operation["targetId"])?;
            let resource = runner
                .gcp_api("GET", &format!("{base}/{collection}/{resource_name}"), None)
                .await?;
            if identity(&resource["id"])? != id {
                return Err(error("GCP resource was replaced after creation"));
            }
            Ok(resource)
        }
        CreateRequest::Azure {
            subscription,
            group,
            template,
        } => {
            let name = format!("atakit-{}", creation.token);
            if !recovering {
                // Azure deployments are kept as a provider-side creation
                // receipt. Never resubmit a deployment to recover a response.
                let body = json!({"properties":{"mode":"Incremental","template":template,
                    "debugSetting":{"detailLevel":"responseContent"}}})
                .to_string();
                let url = format!("https://management.azure.com/subscriptions/{subscription}/resourcegroups/{group}/providers/Microsoft.Resources/deployments/{name}?api-version=2022-09-01");
                let out = runner
                    .run_capture(
                        "az",
                        &[
                            "rest", "--method", "put", "--url", &url, "--body", &body, "--output",
                            "json",
                        ],
                    )
                    .await
                    .map_err(rejected_command)?;
                let receipt: Value = serde_json::from_str(&out.stdout)?;
                runner.record_creation_receipt(key, &receipt).await?;
            }
            for _ in 0..if wait { 120 } else { 1 } {
                let out = runner
                    .run_capture(
                        "az",
                        &[
                            "deployment",
                            "group",
                            "show",
                            "--subscription",
                            subscription,
                            "--resource-group",
                            group,
                            "--name",
                            &name,
                            "--output",
                            "json",
                        ],
                    )
                    .await?;
                let deployment: Value = serde_json::from_str(&out.stdout)?;
                match deployment["properties"]["provisioningState"].as_str() {
                    Some("Succeeded" | "Failed" | "Canceled") => {
                        let out = runner
                            .run_capture(
                                "az",
                                &[
                                    "deployment",
                                    "operation",
                                    "group",
                                    "list",
                                    "--subscription",
                                    subscription,
                                    "--resource-group",
                                    group,
                                    "--name",
                                    &name,
                                    "--output",
                                    "json",
                                ],
                            )
                            .await?;
                        let operations: Value = serde_json::from_str(&out.stdout)?;
                        record_azure_network(runner, template, &operations).await?;
                        if deployment["properties"]["provisioningState"] != "Succeeded" {
                            return Err(CloudError::CreationFailed { message: "Azure deployment failed; partial resources remain recorded for cleanup".into() });
                        }
                        let output = deployment
                            .pointer("/properties/outputs/resource/value")
                            .ok_or_else(|| {
                                error("Azure deployment has no resource identity output")
                            })?;
                        return azure_creation_response(&operations, output);
                    }
                    _ if wait => tokio::time::sleep(Duration::from_secs(2)).await,
                    _ => break,
                }
            }
            Err(error("Azure creation is still pending; use cloud resume"))
        }
        CreateRequest::AzureNetwork {
            id,
            api_version,
            body,
        } => {
            let url = format!("https://management.azure.com{id}?api-version={api_version}");
            let original = if let Some(receipt) = &creation.receipt {
                receipt.clone()
            } else if recovering {
                return Err(error("Azure network creation response was lost; refusing to adopt a resource by name"));
            } else {
                let value = runner
                    .azure_api("PUT", &url, Some(body), true)
                    .await
                    .map_err(rejected_response)?;
                runner.record_creation_receipt(key, &value).await?;
                value
            };
            let record = azure_network_record(id, api_version, &original)?;
            runner.record_azure_resource(&record).await?;
            for _ in 0..if wait { 120 } else { 1 } {
                let current = runner.azure_api("GET", &url, None, false).await?;
                if azure_network_record(id, api_version, &current)?.identity != record.identity {
                    return Err(error(
                        "Azure network resource differs from its creation response",
                    ));
                }
                match current["properties"]["provisioningState"].as_str() {
                    Some("Succeeded") => return Ok(original),
                    Some("Failed" | "Canceled") => return Err(CloudError::CreationFailed { message: "Azure network creation failed; its saved identity can still be used for cleanup".into() }),
                    _ if wait => tokio::time::sleep(Duration::from_secs(2)).await,
                    _ => break,
                }
            }
            Err(error(
                "Azure network creation is still pending; use cloud resume",
            ))
        }
        CreateRequest::AzureVm {
            subscription,
            group,
            name,
            body,
        } => {
            let url = format!("https://management.azure.com/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Compute/virtualMachines/{name}?api-version=2024-11-01");
            let original = if let Some(receipt) = &creation.receipt {
                receipt.clone()
            } else if recovering {
                return Err(error("Azure VM creation response was lost; refusing to adopt a VM by name. Its existence and charges require operator inspection"));
            } else {
                let value = runner
                    .azure_api("PUT", &url, Some(body), true)
                    .await
                    .map_err(rejected_response)?;
                runner.record_creation_receipt(key, &value).await?;
                value
            };
            let expected = identity(&original["properties"]["vmId"])?;
            for _ in 0..if wait { 120 } else { 1 } {
                let current = runner.azure_api("GET", &url, None, false).await?;
                if identity(&current["properties"]["vmId"])? != expected {
                    return Err(error("Azure VM differs from its creation response"));
                }
                match current["properties"]["provisioningState"].as_str() {
                    Some("Succeeded") => {
                        crate::azure::instance::record_vm_created_network(body, &original, &current, runner).await?;
                        return Ok(original);
                    }
                    Some("Failed" | "Canceled") => return Err(CloudError::CreationFailed { message: "Azure VM creation failed; its saved identity can still be used for cleanup".into() }),
                    _ if wait => tokio::time::sleep(Duration::from_secs(2)).await,
                    _ => break,
                }
            }
            Err(error(
                "Azure VM creation is still pending; use cloud resume",
            ))
        }
    }
}

pub(crate) fn azure_network_record(
    id: &str,
    api_version: &str,
    value: &Value,
) -> Result<crate::provisioning_cleanup::AzureResource, CloudError> {
    if !value["id"]
        .as_str()
        .is_some_and(|v| v.eq_ignore_ascii_case(id))
    {
        return Err(error("Azure network response has a different resource ID"));
    }
    Ok(crate::provisioning_cleanup::AzureResource {
        id: id.into(),
        api_version: api_version.into(),
        identity_field: "resourceGuid".into(),
        identity: identity(&value["properties"]["resourceGuid"])?,
    })
}

async fn record_azure_network<R: CommandRunner + ?Sized>(
    runner: &R,
    template: &Value,
    operations: &Value,
) -> Result<(), CloudError> {
    for op in operations.as_array().into_iter().flatten() {
        let props = &op["properties"];
        if props["provisioningState"] != "Succeeded"
            || props["provisioningOperation"] != "Create"
            || !(props["statusCode"] == "Created" || props["statusCode"] == "201")
        {
            continue;
        }
        let content = &props["response"]["content"];
        let value: Value = match content.as_str() {
            Some(s) => serde_json::from_str(s)?,
            None => content.clone(),
        };
        let Some(id) = value["id"].as_str() else {
            continue;
        };
        let Some(spec) = template["resources"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|spec| {
                let kind = spec["type"].as_str().unwrap_or("");
                let name = spec["name"].as_str().unwrap_or("");
                kind.starts_with("Microsoft.Network/")
                    && id
                        .to_lowercase()
                        .ends_with(&format!("/{kind}/{name}").to_lowercase())
            })
        else {
            continue;
        };
        let record = crate::provisioning_cleanup::AzureResource {
            id: id.into(),
            api_version: identity(&spec["apiVersion"])?,
            identity_field: "resourceGuid".into(),
            identity: identity(&value["properties"]["resourceGuid"])?,
        };
        runner.record_azure_resource(&record).await?;
    }
    Ok(())
}

/// A deployment output can describe a replacement resource. Only its original
/// resource-provider response establishes the identity created by this request.
fn azure_creation_response(operations: &Value, output: &Value) -> Result<Value, CloudError> {
    let id = output["id"]
        .as_str()
        .ok_or_else(|| error("missing Azure resource ID"))?;
    let matches: Vec<_> = operations
        .as_array()
        .into_iter()
        .flatten()
        .filter(|op| {
            let p = &op["properties"];
            p["targetResource"]["id"]
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case(id))
                && p["provisioningOperation"] == "Create"
                && p["provisioningState"] == "Succeeded"
        })
        .collect();
    if matches.len() != 1 {
        return Err(error("original Azure creation operation is unavailable; refusing to adopt the current resource"));
    }
    let content = &matches[0]["properties"]["response"]["content"];
    let response = if let Some(s) = content.as_str() {
        serde_json::from_str(s)?
    } else {
        content.clone()
    };
    let field = if id.to_ascii_lowercase().contains("/microsoft.network/") {
        "resourceGuid"
    } else if id.to_ascii_lowercase().contains("/virtualmachines/") {
        "vmId"
    } else {
        "uniqueId"
    };
    if !response["id"]
        .as_str()
        .is_some_and(|v| v.eq_ignore_ascii_case(id))
        || identity(&response["properties"][field])? != identity(&output["properties"][field])?
    {
        return Err(error(
            "Azure resource differs from its original creation response",
        ));
    }
    Ok(response)
}

fn url_filter(token: &str) -> String {
    format!("clientOperationId%20%3D%20%22{token}%22")
}

pub fn identity(value: &Value) -> Result<String, CloudError> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|v| v.to_string()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("provider response has no immutable resource ID"))
}

/// Token stays in memory and never enters saved requests, logs or argv.
pub async fn gcp_api<R: CommandRunner + ?Sized>(
    runner: &R,
    method: &str,
    url: &str,
    body: Option<&Value>,
) -> Result<Value, CloudError> {
    if !url.starts_with("https://compute.googleapis.com/compute/v1/projects/") {
        return Err(error("invalid GCP API endpoint"));
    }
    let token = runner
        .run_capture("gcloud", &["auth", "print-access-token", "--quiet"])
        .await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| error(e.to_string()))?;
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| error("invalid GCP method"))?;
    let mut request = client.request(method, url).bearer_auth(token.stdout.trim());
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|e| error(e.to_string()))?;
    let status = response.status();
    let value: Value = response.json().await.map_err(|e| error(e.to_string()))?;
    if !status.is_success() {
        return Err(CloudError::ProviderResponse {
            provider: "GCP",
            status: status.as_u16(),
            code: value["error"]["status"]
                .as_str()
                .unwrap_or("unknown")
                .into(),
            message: value["error"]["message"]
                .as_str()
                .unwrap_or("request failed")
                .into(),
        });
    }
    Ok(value)
}

/// Only endpoints with create-only semantics may create resources here.
/// Compute creates new public IPs and disks as part of the conditional VM PUT.
pub async fn azure_api<R: CommandRunner + ?Sized>(
    runner: &R,
    method: &str,
    url: &str,
    body: Option<&Value>,
    create_only: bool,
) -> Result<Value, CloudError> {
    let disk_endpoint = url.contains("/providers/Microsoft.Compute/disks/");
    if disk_endpoint && !matches!(method, "GET" | "PATCH") {
        return Err(error(
            "Azure disk API only permits reading or tuning a verified disk",
        ));
    }
    if disk_endpoint && method == "PATCH" {
        let valid = body.and_then(|b| b.as_object()).is_some_and(|b| {
            b.len() == 1
                && b.get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|p| {
                        !p.is_empty()
                            && p.iter().all(|(k, v)| {
                                matches!(k.as_str(), "diskIOPSReadWrite" | "diskMBpsReadWrite")
                                    && v.as_u64().is_some_and(|n| n > 0)
                            })
                    })
        });
        if !valid || create_only {
            return Err(error("invalid Azure disk performance update"));
        }
    }
    if method == "PUT" && url.contains("/providers/Microsoft.Network/publicIPAddresses/") {
        return Err(CloudError::CreationRejected {
            message:
                "standalone Azure public IP creation is unsafe; create the address with the VM"
                    .into(),
        });
    }
    let supported = disk_endpoint
        || [
            "Microsoft.Compute/virtualMachines",
            "Microsoft.Network/virtualNetworks",
            "Microsoft.Network/networkInterfaces",
            "Microsoft.Network/publicIPAddresses",
            "Microsoft.Network/networkSecurityGroups",
        ]
        .iter()
        .any(|kind| url.contains(&format!("/providers/{kind}/")));
    if !url.starts_with("https://management.azure.com/subscriptions/") || !supported {
        return Err(error("invalid Azure creation API endpoint"));
    }
    let token = runner
        .run_capture(
            "az",
            &[
                "account",
                "get-access-token",
                "--resource",
                "https://management.azure.com/",
                "--query",
                "accessToken",
                "--output",
                "tsv",
            ],
        )
        .await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| error(e.to_string()))?;
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| error("invalid Azure method"))?;
    if method == reqwest::Method::PUT && !create_only {
        return Err(error("Azure creation requires If-None-Match"));
    }
    let mut request = client.request(method, url).bearer_auth(token.stdout.trim());
    if create_only {
        request = request.header(reqwest::header::IF_NONE_MATCH, "*");
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|e| error(e.to_string()))?;
    let status = response.status();
    if create_only && url.contains("/providers/Microsoft.Network/") && status.is_success() {
        require_azure_network_created(status.as_u16())?;
    }
    let value: Value = response.json().await.map_err(|e| error(e.to_string()))?;
    if !status.is_success() {
        return Err(CloudError::ProviderResponse {
            provider: "Azure",
            status: status.as_u16(),
            code: value["error"]["code"].as_str().unwrap_or("unknown").into(),
            message: value["error"]["message"]
                .as_str()
                .unwrap_or("request failed")
                .into(),
        });
    }
    Ok(value)
}

fn require_azure_network_created(status: u16) -> Result<(), CloudError> {
    if status != 201 {
        return Err(error(format!("Azure network PUT returned HTTP {status}, not 201 Created; refusing ownership or retry. An existing resource may have been updated; inspect it before cleanup")));
    }
    Ok(())
}

/// Only initial insert responses enter here. A failed GET or a terminal failed
/// operation does not establish that no resources were created.
fn rejected_response(e: CloudError) -> CloudError {
    if matches!(
        &e,
        CloudError::ProviderResponse {
            status: 400 | 401 | 403 | 404 | 409 | 412 | 422 | 429,
            ..
        }
    ) {
        CloudError::CreationRejected {
            message: e.to_string(),
        }
    } else {
        rejected_command(e)
    }
}

fn rejected_command(e: CloudError) -> CloudError {
    let rejected = match &e {
        CloudError::CommandNotFound { .. } => true,
        CloudError::CommandFailed {
            program,
            args,
            stderr,
            ..
        } => {
            // Auth failed before the resource request. Do not classify a cloud
            // timeout, a deployment failure, or an ambiguous CLI error as safe.
            (program == "gcloud" && args.contains("print-access-token"))
                || (program == "az" && args.contains("get-access-token"))
                || (program == "aws"
                    && [
                        "(UnauthorizedOperation)",
                        "(AuthFailure)",
                        "(InvalidClientTokenId)",
                        "(RequestLimitExceeded)",
                        "(VolumeLimitExceeded)",
                        "(InstanceLimitExceeded)",
                        "(InsufficientInstanceCapacity)",
                    ]
                    .iter()
                    .any(|code| stderr.contains(code)))
                || (program == "az"
                    && [
                        "(AuthorizationFailed)",
                        "(InvalidAuthenticationToken)",
                        "(InvalidTemplate)",
                        "(InvalidTemplateDeployment)",
                    ]
                    .iter()
                    .any(|code| stderr.contains(code)))
        }
        _ => false,
    };
    if rejected {
        CloudError::CreationRejected {
            message: e.to_string(),
        }
    } else {
        e
    }
}

pub fn azure_template(resources: Value, resource_id: &str, api_version: &str) -> Value {
    json!({"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion":"1.0.0.0","resources":resources,
        "outputs":{"resource":{"type":"object","value":format!("[reference('{resource_id}', '{api_version}', 'Full')]" )}}})
}

#[cfg(test)]
mod tests;
