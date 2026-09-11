//! Explicit public output fields. Never serialize the full deployment record.
use atakit_cloud::{DeployState, DeployStatus};
use serde_json::{json, Value};

pub(super) fn saved_deployment(state: &DeployState) -> Value {
    let (status, ip) = match &state.status {
        DeployStatus::Deploying { .. } => ("deploying", None),
        DeployStatus::Deployed { ip } => ("deployed", Some(ip.as_str())),
        DeployStatus::Failed { .. } => ("failed", None),
        DeployStatus::Destroying => ("destroying", None),
        DeployStatus::Destroyed => ("destroyed", None),
    };
    let mode = match state.init_auth_mode() {
        "authenticated" => "authenticated",
        "unsigned" => "unsigned",
        _ => "unknown",
    };
    json!({
        "instance": state.instance_name,
        "target": state.target_name,
        "provider": state.provider_name,
        "platform": state.platform,
        "workload": {
            "publisher": state.workload_publisher,
            "name": state.workload_name,
            "version": state.workload_version,
        },
        "image": state.image_ref,
        "init_mode": mode,
        "status": status,
        "ip": ip,
        "created_at": state.created_at,
        "updated_at": state.updated_at,
    })
}
