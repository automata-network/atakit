use anyhow::Result;
use atakit_cloud::aws::AwsProvider;
use atakit_cloud::azure::AzureProvider;
use atakit_cloud::cli::StatusArgs;
use atakit_cloud::diagnose::DiagnosticRunner;
use atakit_cloud::gcp::GcpProvider;
use atakit_cloud::provider::CloudProvider;
use atakit_cloud::qemu::QemuProvider;
use atakit_cloud::state::{DeployState, DeployStatus};
use atakit_core::Env;
use owo_colors::OwoColorize;
use serde_json::{json, Value};
use std::time::Duration;

mod live;

use super::diagnose::display_text;
use crate::config::Config;

pub async fn run(args: StatusArgs, env: &Env, config: &Config) -> Result<()> {
    if !args.watch {
        return run_once(&args, env, config).await;
    }
    // Keep a single signal future alive, including while a check is running.
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            signal = &mut stop => { signal?; return Ok(()); }
            result = run_once(&args, env, config) => {
                if let Err(error) = result {
                    eprintln!("Refresh failed: {}", display_text(&error.to_string()));
                }
            }
        }
        tokio::select! {
            signal = &mut stop => { signal?; return Ok(()); }
            _ = tokio::time::sleep(Duration::from_secs(args.interval)) => {}
        }
    }
}

async fn run_once(args: &StatusArgs, env: &Env, config: &Config) -> Result<()> {
    let started_at = chrono::Utc::now().to_rfc3339();
    if args.watch && !args.json {
        eprintln!("\nChecking at {started_at}; previous results are historical.");
    }
    let state =
        match DeployState::load_for_diagnose(&env.data_dir, &args.instance, args.target.as_deref())
        {
            Ok(state) => state,
            Err(error) => {
                if args.json {
                    emit_json(
                        &json!({"format": 1, "observed_at": started_at,
                    "saved": null, "live": null, "error": display_text(&error.to_string())}),
                        args.watch,
                    )?;
                }
                return Err(error.into());
            }
        };
    let target_name = &state.target_name;
    let instance_name = &state.instance_name;
    let mut live_ip: Option<String> = None;
    let mut live = Value::Null;
    if args.verify {
        live = live::verified(args, state.clone(), env, config).await;
        live_ip = live["ip"].as_str().map(str::to_string);
    } else if args.live {
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
            let runner = DiagnosticRunner;
            match tokio::time::timeout(
                Duration::from_secs(args.check_timeout.min(15)),
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
            Some((host, port)) => match read_portal_status(&host, port, args.check_timeout).await {
                Ok(status) => live::portal_summary(&status, false),
                Err(error) => json!({"state": null, "verified": false, "error": error}),
            },
            None => {
                json!({"state": null, "verified": false, "error": "no portal address available"})
            }
        };
        live = json!({"ip": live_ip, "provider_error": provider_error, "portal": portal});
    }

    if args.live || args.verify {
        live["cloud_disks"] = match tokio::time::timeout(
            Duration::from_secs(args.check_timeout),
            atakit_cloud::disk_inventory::status(&state, &DiagnosticRunner),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => json!({"error": display_text(&error.to_string())}),
            Err(_) => json!({"error": "provider disk observation timed out"}),
        };
    }
    let failed = live["failed"].as_bool().unwrap_or(false);
    if args.json {
        emit_json(
            &json!({
                "format": 1, "observed_at": chrono::Utc::now().to_rfc3339(),
                "checks_started_at": started_at,
                "saved": super::output::saved_deployment(&state), "live": live,
            }),
            args.watch,
        )?;
        return refresh_result(failed);
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
    eprintln!(
        "  Disk settings (saved): {}",
        serde_json::to_string(&state.disk_configuration)?
    );
    if args.live || args.verify {
        eprintln!(
            "  Cloud disks (live): {}",
            display_text(&live["cloud_disks"].to_string())
        );
        eprintln!(
            "  Guest disk modes (live): {}",
            display_text(&live["portal"]["runtime"]["observed"]["disks"].to_string())
        );
    }
    if args.live {
        if let Some(ip) = &live_ip {
            eprintln!("  Live IP:   {ip}");
        }
        if let Some(error) = live["provider_error"].as_str() {
            eprintln!("  Live lookup: {error}");
        }
        if let Some(portal_state) = live["portal"]["state"].as_str() {
            let trust = if live["portal"]["verified"] == true {
                "attestation verified"
            } else {
                "unverified"
            };
            eprintln!("  Portal:    {portal_state} (live, {trust})");
        } else {
            eprintln!(
                "  Portal:    unavailable ({})",
                live["portal"]["error"].as_str().unwrap_or("query failed")
            );
        }
    }
    if args.live {
        live::print_details(&live);
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

    if state.cleanup.started {
        eprintln!(
            "  Cleanup:   {} completed deletion(s)",
            state.cleanup.completed.len()
        );
        if let Some(power) = &state.cleanup.vm_power {
            eprintln!("  VM power (last cleanup check): {power}");
        }
        for (resource, reason) in &state.cleanup.remaining {
            eprintln!("    Retained: {resource}: {reason}");
        }
    }

    // Show saved resource references. Cleanup records above describe deletion.
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

    refresh_result(failed)
}

fn emit_json(value: &Value, watch: bool) -> Result<()> {
    if watch {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn refresh_result(failed: bool) -> Result<()> {
    if failed {
        anyhow::bail!("live status checks failed");
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

async fn read_portal_status(host: &str, port: u16, seconds: u64) -> Result<Value, &'static str> {
    // Advisory only: this does not establish workload identity or authorize actions.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(seconds))
        .build()
        .map_err(|_| "could not create portal client")?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.into()
    };
    read_portal_status_with_client(&client, &format!("https://{host}:{port}/status")).await
}

async fn read_portal_status_with_client(
    client: &reqwest::Client,
    url: &str,
) -> Result<Value, &'static str> {
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
        if body.len() + chunk.len() > 256 * 1024 {
            return Err("portal response exceeds 256 KiB");
        }
        body.extend_from_slice(&chunk);
    }
    parse_portal_state(&body)?;
    serde_json::from_slice(&body).map_err(|_| "invalid portal response")
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
                "x".repeat(256 * 1024 + 1),
                Err("portal response exceeds 256 KiB"),
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let _bytes_read = stream.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
            assert_eq!(
                read_portal_status_with_client(&client, &format!("http://{addr}/status"))
                    .await
                    .map(|v| v["state"].as_str().unwrap().to_string()),
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
