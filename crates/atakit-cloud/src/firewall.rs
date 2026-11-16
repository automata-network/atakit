//! Workload initialization updates only the firewall saved with the deployment.
use crate::{CloudError, CommandRunner, DeployState, PlatformKind, PortalPorts};

pub(crate) fn error(message: impl Into<String>) -> CloudError {
    CloudError::FirewallError {
        message: message.into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Port {
    pub number: u16,
    pub protocol: String,
}

impl Port {
    pub fn entry(&self) -> String {
        format!("{}/{}", self.number, self.protocol)
    }
}

pub(crate) fn parse_ports(entries: &[String]) -> Result<Vec<Port>, CloudError> {
    let mut ports = Vec::new();
    for entry in entries {
        let (number, protocol) = entry.split_once('/').unwrap_or((entry, "tcp"));
        let number = number
            .parse::<u16>()
            .ok()
            .filter(|n| *n != 0)
            .ok_or_else(|| error(format!("invalid firewall port '{entry}'")))?;
        if !matches!(protocol, "tcp" | "udp") {
            return Err(error(format!("invalid firewall protocol in '{entry}'")));
        }
        let port = Port {
            number,
            protocol: protocol.into(),
        };
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    Ok(ports)
}

/// Update before recording or submitting the one-shot initialization request.
/// Existing AWS/Azure allows retain their sources; only missing ports get the
/// public source policy already used by cloud deploy.
pub async fn update_for_init(
    state: &DeployState,
    workload_ports: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let mut ports = state.portal_ports.firewall_entries();
    for port in workload_ports {
        if !PortalPorts::is_default_portal_entry(port) && !ports.contains(port) {
            ports.push(port.clone());
        }
    }
    match state.platform {
        PlatformKind::Gcp => {
            let resources = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("deployment has no saved GCP resources"))?;
            let rule = resources
                .firewall_rule
                .as_deref()
                .ok_or_else(|| error("deployment has no saved GCP firewall rule"))?;
            crate::gcp::firewall::update_firewall(&resources.project, rule, &ports, runner).await
        }
        PlatformKind::Aws => {
            let resources = state
                .resources
                .aws
                .as_ref()
                .ok_or_else(|| error("deployment has no saved AWS resources"))?;
            let group = resources
                .security_group
                .as_deref()
                .ok_or_else(|| error("deployment has no saved AWS security group"))?;
            crate::aws::firewall::update_ingress_rules(&resources.region, group, &ports, runner)
                .await
        }
        PlatformKind::Azure => {
            let resources = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("deployment has no saved Azure resources"))?;
            let rg = resources
                .resource_group
                .as_deref()
                .ok_or_else(|| error("deployment has no saved Azure resource group"))?;
            let nsg = resources
                .nsg
                .as_deref()
                .ok_or_else(|| error("deployment has no saved Azure network security group"))?;
            crate::azure::firewall::update_nsg_rules(
                &resources.subscription,
                rg,
                nsg,
                &ports,
                runner,
            )
            .await
        }
        PlatformKind::Qemu => Ok(()),
    }
}

#[cfg(test)]
mod tests;
