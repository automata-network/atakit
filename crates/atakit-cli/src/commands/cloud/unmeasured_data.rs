use crate::config::Config;
use anyhow::{bail, Context, Result};
use atakit_attestation_client::SessionAuthorityKind;
use atakit_cloud::cli::{SessionVerificationArgs, UnmeasuredDataCommand};
use atakit_core::{unmeasured_data as data, Env};
use sha2::{Digest, Sha256};
use std::time::Duration;

async fn response_bytes(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    // Never echo response errors or arbitrary fields: values and stored IDs must stay hidden.
    if !response.status().is_success() {
        bail!("Portal rejected the request (HTTP {}). Check owner authorization, workload and local input.",response.status());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            bail!("Portal response exceeds size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
async fn response_json(response: reqwest::Response) -> Result<serde_json::Value> {
    serde_json::from_slice(&response_bytes(response, 65536).await?)
        .context("invalid Portal operation response")
}

fn check_manifest_measurement_pins(
    verification: &SessionVerificationArgs,
    authority: SessionAuthorityKind,
    manifest_sha256: &str,
    manifest_sha384: &str,
) -> Result<()> {
    use super::session_access::{
        decode_hex_32, decode_hex_48, trusted_workload_pcr23, workload_policy_authority_conflict,
    };
    if let Some(message) = workload_policy_authority_conflict(authority, verification) {
        bail!(message);
    }
    if let Some((sha256, sha384)) = trusted_workload_pcr23(verification)? {
        if sha256 != decode_hex_32(manifest_sha256, "fetched manifest SHA-256 PCR23")? {
            bail!("Portal manifest does not match --trusted-workload-pcr23-sha256");
        }
        if sha384 != decode_hex_48(manifest_sha384, "fetched manifest SHA-384 PCR23")? {
            bail!("Portal manifest does not match --trusted-workload-pcr23-sha384");
        }
    }
    Ok(())
}

pub async fn run(command: UnmeasuredDataCommand, env: &Env, config: &Config) -> Result<()> {
    let (args, operation, update) = match &command {
        UnmeasuredDataCommand::Update(a) => (&a.instance, "update", Some(a)),
        UnmeasuredDataCommand::Status(a) => (a, "status", None),
        UnmeasuredDataCommand::Discard(a) => (a, "discard", None),
    };
    let access = super::session_access::resolve_disk_unlock_access(
        &args.instance,
        args.target.as_deref(),
        &args.verification,
        env,
        config,
    )
    .await?;
    if access.verified_tls.manual_override().is_some() {
        bail!("unmeasured-data requires verified Portal TLS without a manual override");
    }
    let client = access.verified_tls.client();
    let host = if access.host.contains(':') {
        format!("[{}]", access.host)
    } else {
        access.host.clone()
    };
    let base = format!("https://{host}:{}", access.status_port);
    let bytes = response_bytes(
        client
            .get(format!("{base}/workload/manifest"))
            .timeout(Duration::from_secs(30))
            .send()
            .await?,
        data::MAX_MANIFEST,
    )
    .await?;
    let inspected = atakit_workload::inspect::inspect_manifest_json(
        String::from_utf8(bytes.clone()).context("manifest is not UTF-8")?,
    )?;
    // Check the owner's expected manifest even if startup failed and PCR23 was reset.
    // This runs for --check/status/discard too, before collecting files or signing.
    check_manifest_measurement_pins(
        &args.verification,
        access
            .verified_tls
            .authority_kind()
            .context("verified Portal TLS has no verification authority")?,
        &inspected.pcr23_sha256,
        &inspected.pcr23_sha384,
    )?;
    let expected = crate::commands::workload::parse_workload_ref(
        &format!(
            "{}/{}:{}",
            access.state.workload_publisher,
            access.state.workload_name,
            access.state.workload_version
        ),
        &config.alias,
    )?;
    let actual = crate::commands::workload::measured_workload_ref(&inspected.manifest.meta)?;
    if !atakit_workload::hex_equal(
        &format!(
            "{:#x}",
            crate::commands::workload::compute_workload_id(&actual)
        ),
        &expected.workload_id(),
    ) {
        bail!("Portal manifest does not match the selected workload");
    }
    let workload_status = response_json(
        client
            .get(format!("{base}/status"))
            .timeout(Duration::from_secs(15))
            .send()
            .await?,
    )
    .await?;
    super::disk::validate_workload_identity(&workload_status, &expected.workload_id())?;
    // Failed startup resets PCR23. The attested supervisor verifies stored manifest integrity.
    if workload_status["state"] != "Failed" {
        super::disk::check_inspected_workload_measurement(client, &base, &inspected).await?;
    }
    let policy = data::Policy::from_manifest(&bytes).map_err(anyhow::Error::msg)?;
    let mut archive = None;
    let mut preview = None;
    if let Some(update) = update {
        let files = data::Tree::collect(&update.unmeasured_data_root, &policy)
            .map_err(anyhow::Error::msg)?;
        // Check archive limits before declaring validation successful, also for --check.
        archive =
            Some(data::prepare_archive_in(&files, &env.cache_dir).map_err(anyhow::Error::msg)?);
        let paths: Vec<_> = files.paths().cloned().collect();
        preview = Some(
            serde_json::json!({"instance":format!("{}/{}",access.target_name,access.instance_name),"source":update.unmeasured_data_root,
            "mode":"replace","files":paths,"file_count":files.len(),"clears_all":files.is_empty()}),
        );
        if !args.json {
            println!(
                "Instance: {}/{}\nSource: {}\nMode: replace entire unmeasured-data directory",
                access.target_name,
                access.instance_name,
                update.unmeasured_data_root.display()
            );
            println!("Only manifest-declared files are included. Other local files are ignored.\n\nFiles in replacement:");
            for path in files.paths() {
                println!("  {path}");
            }
            println!("\nDeclared files absent from this folder will be absent after restart.");
            if files.is_empty() {
                println!("All unmeasured-data files will be removed on restart.");
            }
            println!("Any existing pending update will be replaced.\nLocal validation passed. {} files in replacement.",files.len());
        }
        if update.check {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"preview":preview,"state":"validated","saved":false})
                );
            } else {
                println!("Nothing saved.");
            }
            return Ok(());
        }
    }
    let target = config
        .cloud
        .targets
        .get(&access.target_name)
        .context("target not found")?;
    let key_name = args
        .owner_key
        .as_deref()
        .or((!access.state.init_env.owner_key.is_empty())
            .then_some(access.state.init_env.owner_key.as_str()))
        .or(target.owner_key.as_deref())
        .context("configure the provisioned owner key or use --owner-key")?;
    let key = super::disk::resolve_owner_key(key_name, config)?;
    let challenge = response_json(
        client
            .get(format!("{base}/unmeasured-data/challenge"))
            .timeout(Duration::from_secs(30))
            .send()
            .await?,
    )
    .await?;
    let authorization = data::Authorization {
        manifest_hash: hex::encode(Sha256::digest(&bytes)),
        boot_id: challenge["boot_id"]
            .as_str()
            .context("missing boot identity")?
            .into(),
        challenge: challenge["challenge"]
            .as_str()
            .context("missing authorization challenge")?
            .into(),
        archive_length: archive.as_ref().map_or(0, |a| a.length),
        archive_sha256: archive.as_ref().map_or_else(
            || hex::encode(Sha256::digest([])),
            |a| hex::encode(a.sha256),
        ),
    };
    let authorization = serde_json::to_vec(&authorization)?;
    let fingerprint = hex::encode(access.verified_tls.identity().cert_sha256);
    let (signature, recovery) = key.sign_prehash_recoverable(&data::request_digest(
        &fingerprint,
        operation,
        &authorization,
    ))?;
    let mut signature = signature.to_bytes().to_vec();
    signature.push(recovery.to_byte());
    let mut authorization_header =
        reqwest::header::HeaderValue::from_str(&hex::encode(authorization))?;
    authorization_header.set_sensitive(true);
    let mut signature_header = reqwest::header::HeaderValue::from_str(&hex::encode(signature))?;
    signature_header.set_sensitive(true);
    let body = if let Some(archive) = &archive {
        reqwest::Body::from(tokio::fs::File::from_std(
            archive.open().map_err(anyhow::Error::msg)?,
        ))
    } else {
        reqwest::Body::from(Vec::<u8>::new())
    };
    // No automatic replay of mutating requests, even if the connection fails after acceptance.
    let response = client.post(format!("{base}/unmeasured-data/{operation}"))
        .header("atakit-data-authorization",authorization_header)
        .header("atakit-owner-signature",signature_header)
        .header("content-type","application/gzip").body(body).timeout(Duration::from_secs(300))
        .send().await.context("submission outcome is unconfirmed; use unmeasured-data status before explicitly submitting again")?;
    let result = response_json(response)
        .await
        .context("operation was not confirmed; use unmeasured-data status before explicitly submitting again")?;
    match operation {
        "update" => {
            if result["state"] != "pending" {
                bail!("unexpected update response; submission outcome is unconfirmed");
            }
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"preview":preview,"state":"pending"})
                );
            } else {
                println!("Replacement saved. Waiting for VM restart.\nApply with: atakit cloud reboot {}/{}",access.target_name,access.instance_name);
            }
        }
        "discard" => {
            if result["state"] != "discarded" {
                bail!("unexpected discard response; outcome is unconfirmed");
            }
            if args.json {
                println!("{}", serde_json::json!({"state":"discarded"}));
            } else {
                println!("Pending update cleared.");
            }
        }
        "status" => {
            let last = result["last_update"]
                .as_str()
                .filter(|s| matches!(*s, "none" | "applied" | "discarded"))
                .context("invalid update status")?;
            let pending = result["pending"]
                .as_bool()
                .context("invalid pending status")?;
            let startup = match workload_status["state"].as_str() {
                Some("Running") => "ready",
                Some("Failed") => "failed",
                _ => "starting",
            };
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"last_update":last,"pending":pending,"workload_startup":startup})
                );
            } else {
                println!(
                    "Last update: {last}\nPending update: {}\nWorkload startup: {startup}",
                    if pending {
                        "saved; waiting for VM restart"
                    } else {
                        "none"
                    }
                );
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> SessionVerificationArgs {
        SessionVerificationArgs {
            trusted_workload_pcr23_sha256: Some(format!("0x{}", "ab".repeat(32))),
            trusted_workload_pcr23_sha384: Some(format!("0x{}", "cd".repeat(48))),
            ..Default::default()
        }
    }

    fn check(verification: &SessionVerificationArgs) -> Result<()> {
        check_manifest_measurement_pins(
            verification,
            SessionAuthorityKind::Explicit,
            &"ab".repeat(32),
            &"cd".repeat(48),
        )
    }

    #[test]
    fn checks_both_manifest_measurements_without_a_running_session_or_archive() {
        let mut verification = pins();
        verification.trusted_workload_pcr23_sha256 = Some("AB".repeat(32));
        verification.trusted_workload_pcr23_sha384 = Some(format!("0x{}", "CD".repeat(48)));
        check(&verification).unwrap();
        for bank in ["sha256", "sha384"] {
            let mut verification = pins();
            match bank {
                "sha256" => verification.trusted_workload_pcr23_sha256 = Some("00".repeat(32)),
                _ => verification.trusted_workload_pcr23_sha384 = Some("00".repeat(48)),
            }
            let error = check(&verification).unwrap_err().to_string();
            assert!(error.contains(&format!("does not match --trusted-workload-pcr23-{bank}")));
        }
    }

    #[test]
    fn rejects_missing_malformed_and_wrong_length_pins() {
        for bank in ["sha256", "sha384"] {
            for value in [None, Some("zz".into()), Some("00".into())] {
                let mut verification = pins();
                match bank {
                    "sha256" => verification.trusted_workload_pcr23_sha256 = value,
                    _ => verification.trusted_workload_pcr23_sha384 = value,
                }
                assert!(check(&verification).is_err());
            }
        }
    }

    #[test]
    fn retains_the_existing_verification_authority_rules() {
        for authority in [
            SessionAuthorityKind::Explicit,
            SessionAuthorityKind::Chain,
            SessionAuthorityKind::Packs,
        ] {
            check_manifest_measurement_pins(
                &SessionVerificationArgs::default(),
                authority,
                &"ab".repeat(32),
                &"cd".repeat(48),
            )
            .unwrap();
            let result = check_manifest_measurement_pins(
                &pins(),
                authority,
                &"ab".repeat(32),
                &"cd".repeat(48),
            );
            if authority == SessionAuthorityKind::Explicit {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().to_string().contains(authority.name()));
            }
        }
    }
}
