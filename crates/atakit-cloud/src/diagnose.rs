//! Read-only cloud observations for deployment diagnostics.
use crate::{CloudError, CommandRunner, DeployState, PlatformKind};
use serde_json::Value;

/// Dropping a timed-out diagnostic query also stops its cloud CLI process.
pub struct DiagnosticRunner;

#[async_trait::async_trait]
impl CommandRunner for DiagnosticRunner {
    async fn run_capture(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<crate::CommandOutput, CloudError> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .env("AWS_PAGER", "")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CloudError::CommandNotFound {
                        program: program.into(),
                    }
                } else {
                    CloudError::Io(e)
                }
            })?;
        if !output.status.success() {
            return Err(CloudError::CommandFailed {
                program: program.into(),
                args: args.join(" "),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                code: output.status.code(),
            });
        }
        Ok(crate::CommandOutput {
            status: 0,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::new(),
        })
    }
    async fn run_stream(
        &self,
        program: &str,
        args: &[&str],
        _: bool,
    ) -> Result<crate::CommandOutput, CloudError> {
        self.run_capture(program, args).await
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VmObservation {
    pub id: String,
    pub power_state: String,
    pub address: Option<String>,
}

fn error(message: &str) -> CloudError {
    CloudError::State {
        message: message.into(),
    }
}

pub async fn observe_vm(
    state: &DeployState,
    runner: &dyn CommandRunner,
) -> Result<VmObservation, CloudError> {
    let (program, args) = match state.platform {
        PlatformKind::Aws => {
            let r = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("saved AWS resources are missing"))?;
            let id = r
                .instance
                .as_deref()
                .ok_or_else(|| error("saved AWS instance ID is missing"))?;
            (
                "aws",
                vec![
                    "ec2",
                    "describe-instances",
                    "--region",
                    &r.region,
                    "--instance-ids",
                    id,
                    "--output",
                    "json",
                ],
            )
        }
        PlatformKind::Azure => {
            let r = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("saved Azure resources are missing"))?;
            let name = r
                .instance
                .as_deref()
                .ok_or_else(|| error("saved Azure VM name is missing"))?;
            let group = r
                .resource_group
                .as_deref()
                .ok_or_else(|| error("saved Azure resource group is missing"))?;
            (
                "az",
                vec![
                    "vm",
                    "show",
                    "--subscription",
                    &r.subscription,
                    "--resource-group",
                    group,
                    "--name",
                    name,
                    "--show-details",
                    "--output",
                    "json",
                ],
            )
        }
        PlatformKind::Gcp => {
            let r = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("saved GCP resources are missing"))?;
            let name = r
                .instance
                .as_deref()
                .ok_or_else(|| error("saved GCP instance name is missing"))?;
            (
                "gcloud",
                vec![
                    "compute",
                    "instances",
                    "describe",
                    name,
                    "--project",
                    &r.project,
                    "--zone",
                    &r.zone,
                    "--format=json",
                ],
            )
        }
        PlatformKind::Qemu => return Err(error("live VM lookup supports AWS, Azure, and GCP")),
    };
    let response = runner.run_capture(program, &args).await?;
    let value = serde_json::from_str(&response.stdout)
        .map_err(|_| error("cloud CLI returned invalid JSON"))?;
    parse_observation(state.platform, &value)
}

fn parse_observation(platform: PlatformKind, value: &Value) -> Result<VmObservation, CloudError> {
    let (id, power, addresses) = match platform {
        PlatformKind::Aws => {
            let reservations = value["Reservations"]
                .as_array()
                .ok_or_else(|| error("AWS response omitted Reservations"))?;
            let instances: Vec<_> = reservations
                .iter()
                .filter_map(|r| r["Instances"].as_array())
                .flatten()
                .collect();
            let [vm] = instances.as_slice() else {
                return Err(error("AWS lookup did not return exactly one VM"));
            };
            (
                vm["InstanceId"].as_str().map(str::to_string),
                vm["State"]["Name"].as_str(),
                vm["PublicIpAddress"]
                    .as_str()
                    .into_iter()
                    .collect::<Vec<_>>(),
            )
        }
        PlatformKind::Azure => (
            value["vmId"].as_str().map(str::to_string),
            value["powerState"].as_str(),
            value["publicIps"]
                .as_str()
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .collect(),
        ),
        PlatformKind::Gcp => (
            value["id"]
                .as_str()
                .map(str::to_string)
                .or_else(|| value["id"].as_u64().map(|n| n.to_string())),
            value["status"].as_str(),
            value["networkInterfaces"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|nic| nic["accessConfigs"].as_array().into_iter().flatten())
                .filter_map(|config| config["natIP"].as_str())
                .collect(),
        ),
        PlatformKind::Qemu => return Err(error("cloud lookup does not support QEMU")),
    };
    let id = id
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("cloud response omitted VM identity"))?;
    let power_state = power
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("cloud response omitted power state"))?
        .to_string();
    let address = match addresses.as_slice() {
        [] => None,
        [ip] => Some(
            ip.trim()
                .parse::<std::net::IpAddr>()
                .map_err(|_| error("cloud response returned an invalid public IP"))?
                .to_string(),
        ),
        _ => {
            return Err(error(
                "VM has multiple public addresses; cannot select one for diagnostics",
            ))
        }
    };
    Ok(VmObservation {
        id,
        power_state,
        address,
    })
}

/// AWS already saves the immutable EC2 ID as its resource reference.
pub fn expected_vm_id(state: &DeployState) -> Option<&str> {
    state.cloud_instance_id.as_deref().or_else(|| {
        (state.platform == PlatformKind::Aws)
            .then(|| state.resources.aws.as_ref()?.instance.as_deref())
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn observes_all_three_providers_and_missing_addresses() {
        for (platform, value, id, power) in [
            (
                PlatformKind::Aws,
                json!({"Reservations":[{"Instances":[{"InstanceId":"i-saved","State":{"Name":"running"},"PublicIpAddress":"192.0.2.1"}]}]}),
                "i-saved",
                "running",
            ),
            (
                PlatformKind::Azure,
                json!({"vmId":"uuid", "powerState":"VM running", "publicIps":"192.0.2.1"}),
                "uuid",
                "VM running",
            ),
            (
                PlatformKind::Gcp,
                json!({"id":"123", "status":"RUNNING", "networkInterfaces":[{"accessConfigs":[{"natIP":"192.0.2.1"}]}]}),
                "123",
                "RUNNING",
            ),
        ] {
            assert_eq!(
                parse_observation(platform, &value).unwrap(),
                VmObservation {
                    id: id.into(),
                    power_state: power.into(),
                    address: Some("192.0.2.1".into())
                }
            );
        }
        let vm = parse_observation(
            PlatformKind::Azure,
            &json!({"vmId":"uuid", "powerState":"VM stopped", "publicIps":""}),
        )
        .unwrap();
        assert!(vm.address.is_none());
        assert_eq!(vm.power_state, "VM stopped");
    }

    #[test]
    fn rejects_missing_ambiguous_and_malformed_observations() {
        for platform in [PlatformKind::Aws, PlatformKind::Azure, PlatformKind::Gcp] {
            assert!(parse_observation(platform, &json!({})).is_err());
        }
        assert!(parse_observation(PlatformKind::Aws, &json!({"Reservations":[]})).is_err());
        for ips in ["not-an-ip", "192.0.2.1,192.0.2.2"] {
            assert!(parse_observation(
                PlatformKind::Azure,
                &json!({"vmId":"uuid","powerState":"VM running","publicIps":ips})
            )
            .is_err());
        }
    }
}
