use anyhow::Result;
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::StatusArgs;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::qemu::QemuProvider;
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_cloud::ProcessRunner;
use atakit_core::Env;
use owo_colors::OwoColorize;
use serde_json::{json, Value};
use std::time::Duration;

use super::resolve_instance;
use crate::config::Config;

pub async fn run(args: StatusArgs, env: &Env, _config: &Config) -> Result<()> {
    let (target_name, instance_name) =
        resolve_instance(&env.data_dir, &args.instance, args.target.as_deref())?;

    let state = DeployState::load(&env.data_dir, &target_name, &instance_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut live_ip: Option<String> = None;
    let mut live = Value::Null;
    if args.live {
        let provider: Option<Box<dyn CloudProvider>> = match state.platform {
            atakit_cloud::PlatformKind::Gcp => GcpProvider::from_state(&state)
                .ok()
                .map(|p| Box::new(p) as _),
            atakit_cloud::PlatformKind::Azure => AzureProvider::from_state(&state)
                .ok()
                .map(|p| Box::new(p) as _),
            atakit_cloud::PlatformKind::Aws => AwsProvider::from_state(&state)
                .ok()
                .map(|p| Box::new(p) as _),
            atakit_cloud::PlatformKind::Qemu => QemuProvider::from_state(&state)
                .ok()
                .map(|p| Box::new(p) as _),
        };
        let mut provider_error = None;
        if let Some(provider) = provider {
            let runner = ProcessRunner::default();
            match tokio::time::timeout(
                Duration::from_secs(15),
                provider.get_instance_ip(&state, &runner),
            )
            .await
            {
                Ok(Ok(Some(ip))) if !ip.is_empty() => live_ip = Some(ip),
                _ => provider_error = Some("provider IP lookup failed or returned no IP"),
            }
        } else {
            provider_error = Some("saved provider resources are incomplete");
        }
        let endpoint = live_portal_endpoint(&state, live_ip.as_deref());
        let portal = match endpoint {
            Some((host, port)) => match read_portal_state(&host, port).await {
                Ok(portal_state) => {
                    json!({"state": portal_state, "verified": false, "error": null})
                }
                Err(error) => json!({"state": null, "verified": false, "error": error}),
            },
            None => {
                json!({"state": null, "verified": false, "error": "no portal address available"})
            }
        };
        live = json!({"ip": live_ip, "provider_error": provider_error, "portal": portal});
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "format": 1, "saved": super::output::saved_deployment(&state), "live": live,
            }))?
        );
        return Ok(());
    }

    // Display status.
    eprintln!(
        "  Instance:  {}",
        format!("{target_name}/{instance_name}").bold()
    );
    eprintln!(
        "  Workload:  {}:{}",
        state.workload_name,
        state.workload_version.dimmed()
    );
    eprintln!("  Platform:  {}", state.platform);
    eprintln!("  Image:     {}", state.image_ref);
    eprintln!("  Init mode: {} (saved)", state.init_auth_mode());
    if args.live {
        if let Some(ip) = &live_ip {
            eprintln!("  Live IP:   {ip}");
        }
        if let Some(error) = live["provider_error"].as_str() {
            eprintln!("  Live lookup: {error}");
        }
        if let Some(portal_state) = live["portal"]["state"].as_str() {
            eprintln!("  Portal:    {portal_state} (live, unverified)");
        } else {
            eprintln!(
                "  Portal:    unavailable ({})",
                live["portal"]["error"].as_str().unwrap_or("query failed")
            );
        }
    }
    eprintln!(
        "  Created:   {}",
        state.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    eprintln!(
        "  Updated:   {}",
        state.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    match &state.status {
        DeployStatus::Deploying { step, total } => {
            eprintln!(
                "  Status:    {} deploying ({}/{})",
                "~".yellow(),
                step,
                total
            );
        }
        DeployStatus::Deployed { ip } => {
            eprintln!("  Status:    {} deployed", "*".green());
            eprintln!("  Saved IP:  {ip}");
        }
        DeployStatus::Failed { step, message } => {
            eprintln!("  Status:    {} failed at: {step}", "x".red());
            eprintln!("  Error:     {message}");
        }
        DeployStatus::Destroying => {
            eprintln!("  Status:    {} destroying", "~".yellow());
        }
        DeployStatus::Destroyed => {
            eprintln!("  Status:    {} destroyed", "o".dimmed());
        }
    }

    // Show resources.
    if let Some(ref gcp) = state.resources.gcp {
        eprintln!();
        eprintln!("  {}", "Resources:".dimmed());
        if let Some(ref i) = gcp.instance {
            eprintln!("    Instance:  {i}");
        }
        if let Some(ref b) = gcp.bucket {
            eprintln!("    Bucket:    {b}");
        }
        if let Some(ref img) = gcp.image {
            eprintln!("    Image:     {img}");
        }
        if let Some(ref fw) = gcp.firewall_rule {
            eprintln!("    Firewall:  {fw}");
        }
        if !gcp.disks.is_empty() {
            eprintln!("    Disks:     {}", gcp.disks.join(", "));
        }
    }
    if let Some(ref az) = state.resources.azure {
        eprintln!();
        eprintln!("  {}", "Resources:".dimmed());
        if let Some(ref i) = az.instance {
            eprintln!("    Instance:  {i}");
        }
        if let Some(ref rg) = az.resource_group {
            eprintln!("    RG:        {rg}");
        }
        if let Some(ref nsg) = az.nsg {
            eprintln!("    NSG:       {nsg}");
        }
        if let Some(ref g) = az.gallery {
            eprintln!("    Gallery:   {g}");
        }
        if let Some(ref def) = az.image_definition {
            eprintln!("    Image def: {def}");
        }
        if let Some(ref sa) = az.storage_account {
            eprintln!("    Storage:   {sa}");
        }
        if !az.disks.is_empty() {
            eprintln!("    Disks:     {}", az.disks.join(", "));
        }
    }
    if let Some(ref aws) = state.resources.aws {
        eprintln!();
        eprintln!("  {}", "Resources:".dimmed());
        eprintln!("    Region:    {}", aws.region);
        if let Some(ref i) = aws.instance {
            eprintln!("    Instance:  {i}");
        }
        if let Some(ref b) = aws.bucket {
            eprintln!("    Bucket:    {b}");
        }
        if let Some(ref ami) = aws.ami {
            eprintln!("    AMI:       {ami}");
        }
        if let Some(ref snap) = aws.snapshot {
            eprintln!("    Snapshot:  {snap}");
        }
        if let Some(ref sg) = aws.security_group {
            eprintln!("    Sec group: {sg}");
        }
    }
    if let Some(ref q) = state.resources.qemu {
        eprintln!();
        eprintln!("  {}", "Resources:".dimmed());
        eprintln!("    Mode:      local (qemu)");
        eprintln!("    PID:       {}", q.pid);
        if !q.instance_dir.is_empty() {
            eprintln!("    Dir:       {}", q.instance_dir);
        }
        if q.host_status_port != 0 && q.host_init_port != 0 {
            eprintln!(
                "    Portal:    localhost:{} (status), localhost:{} (init)",
                q.host_status_port, q.host_init_port,
            );
        }
        if !q.serial_sock.is_empty() {
            eprintln!("    Console:   {}", q.serial_sock);
        }
        if !q.data_disks.is_empty() {
            eprintln!("    Disks:     {} data disk(s)", q.data_disks.len());
        }
    }

    Ok(())
}

fn live_portal_endpoint(state: &DeployState, live_ip: Option<&str>) -> Option<(String, u16)> {
    // QEMU uses forwarded host ports. Cloud VMs use the provider's current IP
    // when available, even when the saved address is absent or stale.
    if state.resources.qemu.is_none() {
        if let Some(ip) = live_ip {
            return Some((ip.into(), state.portal_ports.status));
        }
    }
    super::portal_endpoints(state)
        .ok()
        .map(|(host, port, _)| (host, port))
}

fn parse_portal_state(body: &[u8]) -> Result<String, &'static str> {
    let value: Value = serde_json::from_slice(body).map_err(|_| "invalid portal response")?;
    match value["state"].as_str() {
        Some(
            state @ ("AwaitingInit"
            | "Initializing"
            | "InitializingWorkload"
            | "AwaitingDiskUnlock"
            | "Registering"
            | "Running"
            | "Failed"
            | "CleanHalt"),
        ) => Ok(state.into()),
        _ => Err("unknown or missing portal state"),
    }
}

async fn read_portal_state(host: &str, port: u16) -> Result<String, &'static str> {
    // Advisory only: this does not establish workload identity or authorize actions.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "could not create portal client")?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.into()
    };
    read_portal_state_with_client(&client, &format!("https://{host}:{port}/status")).await
}

async fn read_portal_state_with_client(
    client: &reqwest::Client,
    url: &str,
) -> Result<String, &'static str> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "portal request failed")?
        .error_for_status()
        .map_err(|_| "portal returned an HTTP error")?;
    if !response.status().is_success() {
        return Err("portal returned an HTTP error");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "portal response read failed")?
    {
        if body.len() + chunk.len() > 64 * 1024 {
            return Err("portal response exceeds 64 KiB");
        }
        body.extend_from_slice(&chunk);
    }
    parse_portal_state(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn portal_queries_handle_http_errors_invalid_and_oversized_bodies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for (status, body, expected) in [
            (
                "200 OK",
                r#"{"state":"Running"}"#.into(),
                Ok("Running".into()),
            ),
            (
                "503 Service Unavailable",
                "SECRET".into(),
                Err("portal returned an HTTP error"),
            ),
            (
                "302 Found",
                "SECRET".into(),
                Err("portal returned an HTTP error"),
            ),
            ("200 OK", "SECRET".into(), Err("invalid portal response")),
            (
                "200 OK",
                "x".repeat(64 * 1024 + 1),
                Err("portal response exceeds 64 KiB"),
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                stream.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
            assert_eq!(
                read_portal_state_with_client(&client, &format!("http://{addr}/status")).await,
                expected
            );
            server.await.unwrap();
        }
    }

    #[test]
    fn portal_state_output_does_not_echo_arbitrary_response_fields() {
        for state in [
            "AwaitingInit",
            "Initializing",
            "InitializingWorkload",
            "AwaitingDiskUnlock",
            "Registering",
            "Running",
            "Failed",
            "CleanHalt",
        ] {
            let bytes = serde_json::to_vec(
                &json!({"state": state, "detail": "SECRET", "private_key": "SECRET"}),
            )
            .unwrap();
            assert_eq!(parse_portal_state(&bytes).unwrap(), state);
        }
        for bytes in [
            b"not json".as_slice(),
            b"{}",
            br#"{"state":"\u001bSECRET"}"#,
        ] {
            assert!(parse_portal_state(bytes).is_err());
        }
    }
}
