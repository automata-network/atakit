use crate::error::CloudError;
use crate::exec::CommandRunner;
use crate::firewall::{error, parse_ports};

/// Preserve custom rules and append missing allows after existing inbound rules.
pub async fn update_nsg_rules(
    subscription: &str,
    rg: &str,
    nsg: &str,
    ports: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Rule {
        name: String,
        priority: u16,
        direction: String,
        access: String,
        protocol: String,
        destination_port_range: Option<String>,
        destination_port_ranges: Option<Vec<String>>,
    }
    let ports = parse_ports(ports)?;
    // securityRules excludes Azure's default rules (including VirtualNetwork
    // allow-all); those must not hide missing public workload ports.
    let output = runner
        .run_capture(
            "az",
            &[
                "network",
                "nsg",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                nsg,
                "--query",
                "securityRules",
                "--output",
                "json",
            ],
        )
        .await?;
    let rules: Vec<Rule> = serde_json::from_str(&output.stdout).map_err(|e| {
        error(format!(
            "invalid Azure network security group response: {e}"
        ))
    })?;
    for rule in &rules {
        if !(100..=4096).contains(&rule.priority)
            || rule.name.is_empty()
            || rule.protocol.is_empty()
            || !matches!(rule.direction.as_str(), "Inbound" | "Outbound")
            || !matches!(rule.access.as_str(), "Allow" | "Deny")
        {
            return Err(error(
                "invalid Azure custom rule priority, direction, or access",
            ));
        }
        let ranges: Vec<_> = rule
            .destination_port_range
            .iter()
            .chain(rule.destination_port_ranges.iter().flatten())
            .filter(|range| !range.is_empty())
            .collect();
        if ranges.is_empty() || ranges.iter().any(|range| parse_port_range(range).is_none()) {
            return Err(error("invalid Azure custom rule destination port range"));
        }
    }
    let mut priority = rules
        .iter()
        .filter(|r| r.direction == "Inbound")
        .map(|r| r.priority)
        .max()
        .unwrap_or(99);
    let mut additions = Vec::new();
    for port in ports {
        let covered = rules.iter().any(|r| {
            r.direction == "Inbound"
                && r.access == "Allow"
                && (r.protocol == "*" || r.protocol.eq_ignore_ascii_case(&port.protocol))
                && r.destination_port_range
                    .iter()
                    .chain(r.destination_port_ranges.iter().flatten())
                    .any(|range| port_range_contains(range, port.number))
        });
        if covered {
            continue;
        }
        loop {
            priority += 1;
            if priority > 4096 {
                return Err(error(
                    "no Azure rule priority available after existing inbound rules",
                ));
            }
            if !rules.iter().any(|r| r.priority == priority) {
                break;
            }
        }
        let base = format!("allow-{}-{}", port.number, port.protocol);
        let mut name = base.clone();
        let mut suffix = 0;
        while rules.iter().any(|r| r.name.eq_ignore_ascii_case(&name)) {
            suffix += 1;
            name = format!("{base}-{suffix}");
        }
        additions.push((port, priority, name));
    }
    // Plan all additions first: priority exhaustion must not partially update.
    for (port, priority, name) in additions {
        runner
            .run_capture(
                "az",
                &[
                    "network",
                    "nsg",
                    "rule",
                    "create",
                    "--subscription",
                    subscription,
                    "--resource-group",
                    rg,
                    "--nsg-name",
                    nsg,
                    "--name",
                    &name,
                    "--priority",
                    &priority.to_string(),
                    "--protocol",
                    &capitalize_proto(&port.protocol),
                    "--destination-port-ranges",
                    &port.number.to_string(),
                    "--source-address-prefixes",
                    "*",
                    "--source-port-ranges",
                    "*",
                    "--destination-address-prefixes",
                    "*",
                    "--access",
                    "Allow",
                    "--direction",
                    "Inbound",
                ],
            )
            .await
            .map_err(|e| error(format!("failed to create NSG rule '{name}': {e}")))?;
    }
    Ok(())
}

fn port_range_contains(range: &str, port: u16) -> bool {
    matches!(parse_port_range(range), Some((start, end)) if start <= port && port <= end)
}

fn parse_port_range(range: &str) -> Option<(u16, u16)> {
    if range == "*" {
        return Some((0, u16::MAX));
    }
    let (start, end) = range.split_once('-').unwrap_or((range, range));
    let (start, end) = (start.parse::<u16>().ok()?, end.parse::<u16>().ok()?);
    (start <= end).then_some((start, end))
}

/// Create a Network Security Group.
pub async fn create_nsg(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let out = runner
        .run_capture(
            "az",
            &[
                "group",
                "show",
                "--subscription",
                subscription,
                "--name",
                rg,
                "--query",
                "location",
                "--output",
                "tsv",
            ],
        )
        .await?;
    let id = format!("/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{name}");
    let api = "2024-05-01";
    runner
        .create_resource(
            &format!("network:{name}"),
            &crate::provisioning::CreateRequest::AzureNetwork {
                id,
                api_version: api.into(),
                body: serde_json::json!({ "location":out.stdout.trim(), "properties":{"securityRules":[]} }),
            },
        )
        .await?;
    Ok(())
}

/// Add NSG rules for the given ports with incrementing priorities.
///
/// Each entry in `ports` is `"port/proto"` (e.g. `"1024/tcp"`, `"5353/udp"`).
pub async fn add_nsg_rules(
    subscription: &str,
    rg: &str,
    nsg: &str,
    ports: &[String],
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    for (i, entry) in ports.iter().enumerate() {
        let (port, proto) = entry.split_once('/').unwrap_or((entry, "tcp"));
        let priority = 100 + (i as u32) * 10;
        let rule_name = format!("allow-{port}-{proto}");

        runner
            .run_capture(
                "az",
                &[
                    "network",
                    "nsg",
                    "rule",
                    "create",
                    "--subscription",
                    subscription,
                    "--resource-group",
                    rg,
                    "--nsg-name",
                    nsg,
                    "--name",
                    &rule_name,
                    "--priority",
                    &priority.to_string(),
                    "--protocol",
                    &capitalize_proto(proto),
                    "--destination-port-ranges",
                    port,
                    "--access",
                    "Allow",
                    "--direction",
                    "Inbound",
                ],
            )
            .await
            .map_err(|e| CloudError::FirewallError {
                message: format!("failed to create NSG rule '{rule_name}': {e}"),
            })?;
    }
    Ok(())
}

/// Check if an NSG exists.
pub async fn check_nsg_exists(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "network",
                "nsg",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
            ],
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(CloudError::CommandFailed { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Capitalize protocol name for Azure CLI (e.g. "tcp" -> "Tcp").
fn capitalize_proto(proto: &str) -> String {
    let mut chars = proto.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
    }
}
