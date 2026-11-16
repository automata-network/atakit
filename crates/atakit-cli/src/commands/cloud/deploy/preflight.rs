//! Read the exact records used by registration; never publish or select a firmware variant.
use std::time::Duration;

use alloy_ext::core::{
    primitives::B256,
    sol_types::{SolCall, SolValue},
};
use alloy_ext::{core::primitives::Address, ext::NetworkProvider, providers::Provider};
use anyhow::{ensure, Context, Result};
use atakit_cloud::{CcType, InitChainConfig, PlatformKind};
use atakit_portal_chain::publisher_policy as signed;
use automata_tee_workload_measurement::{
    stubs::{
        BaseImageRegistry::BaseImageRegistryInstance, SessionRegistry::SessionRegistryInstance,
        WorkloadRegistry::WorkloadRegistryInstance,
    },
    types::AppRef,
};

pub(super) async fn check_registries(
    chain: &InitChainConfig,
    workload: &AppRef,
    base_image: &str,
    platform: PlatformKind,
    cc_type: CcType,
    machine: &str,
) -> Result<Vec<String>> {
    tokio::time::timeout(
        Duration::from_secs(60),
        records(chain, workload, base_image, platform, cc_type, machine),
    )
    .await
    .context("registry checks timed out after 60 seconds")?
}

async fn records(
    chain: &InitChainConfig,
    workload: &AppRef,
    base_image: &str,
    platform: PlatformKind,
    cc_type: CcType,
    machine: &str,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let provider = NetworkProvider::with_http(
        &chain.rpc_url,
        Some(Duration::from_secs(5)),
        Some(Duration::from_secs(15)),
        0,
    )
    .await
    .context("connect to configured chain for registry checks")?;
    let chain_id = provider.get_chain_id().await.context("read chain ID")?;
    if let Some(expected) = chain.chain_id {
        ensure!(
            chain_id == expected,
            "configured chain ID {expected} differs from RPC chain ID {chain_id}"
        );
    }
    let block = provider
        .get_block_number()
        .await
        .context("read registry check block")?;
    let workload_address: Address = chain
        .workload_registry
        .parse()
        .context("invalid workload_registry")?;
    let image_address: Address = chain
        .base_image_registry
        .parse()
        .context("invalid base_image_registry")?;
    let session_address: Address = chain
        .session_registry
        .parse()
        .context("invalid session_registry")?;
    let sessions = SessionRegistryInstance::new(session_address, provider.clone());
    ensure!(sessions.workloadRegistry().block(block.into()).call().await.context("SessionRegistry.workloadRegistry unavailable; check the configured registry interface")? == workload_address,
        "SessionRegistry.workloadRegistry differs from configured workload_registry");
    ensure!(sessions.baseImageRegistry().block(block.into()).call().await.context("SessionRegistry.baseImageRegistry unavailable; check the configured registry interface")? == image_address,
        "SessionRegistry.baseImageRegistry differs from configured base_image_registry");
    let workloads = WorkloadRegistryInstance::new(workload_address, provider.clone());
    let workload_id = crate::commands::workload::compute_workload_id(workload);
    workloads.getWorkload(workload_id).block(block.into()).call().await
        .with_context(|| format!("workload {workload} is not readable from WorkloadRegistry; publish it on the selected chain before deploying"))?;
    ensure!(
        !workloads
            .isWorkloadRevoked(workload_id)
            .block(block.into())
            .call()
            .await?,
        "workload {workload} is revoked"
    );
    let workload_policy = match signed_response(
        workloads
            .getSignedWorkload(workload_id)
            .block(block.into())
            .call()
            .await,
        &format!("workload {workload}"),
        &mut warnings,
    )? {
        Some(result) => {
            let policy = signed::getSignedWorkloadCall::abi_decode_returns_validate(
                &(result,).abi_encode_params(),
            )
            .context("malformed signed workload response")?;
            if policy.workloadSignature.is_empty() {
                warnings.push(format!(
                    "Workload {workload} has no publisher policy signature."
                ));
                None
            } else {
                signed::verify_workload(workload_id, &policy)
                    .context("workload publisher signature or identity is invalid")?;
                Some(policy)
            }
        }
        None => None,
    };
    eprintln!("  PASS: registered, non-revoked workload {workload}");

    // A provider-native image name has no publisher-qualified identity before boot.
    // Preserve that supported path; the portal's claim is still checked during TLS attestation.
    let Ok(image) = base_image.parse::<AppRef>() else {
        eprintln!("  NOT CHECKED: base-image signed policy, target variant and workload permission (provider image has no canonical identity; supply --base-image)");
        return Ok(warnings);
    };
    let image_id = crate::commands::workload::compute_base_image_id(&image);
    let images = BaseImageRegistryInstance::new(image_address, provider);
    images.getBaseImage(image_id).block(block.into()).call().await
        .with_context(|| format!("base image {image} is not readable from BaseImageRegistry; publish it on the selected chain before deploying"))?;
    ensure!(
        !images
            .isBaseImageRevoked(image_id)
            .block(block.into())
            .call()
            .await?,
        "base image {image} is revoked"
    );
    ensure!(
        workloads
            .isBaseImageAllowed(workload_id, image_id)
            .block(block.into())
            .call()
            .await?,
        "WorkloadRegistry does not allow base image {image} for workload {workload}"
    );
    let tee = match cc_type {
        CcType::Tdx => "tdx",
        CcType::SevSnp => "sev-snp",
    };
    let profile_name = format!("{platform}-{tee}");
    let profile_id: B256 =
        atakit_cvm_encoding::platform_profile_id(image_id.0, &profile_name).into();
    let firmware_selected = platform == PlatformKind::Azure && cc_type == CcType::SevSnp;
    let variants = if firmware_selected {
        let ids = images.getMeasurementVariantIds(profile_id).block(block.into()).call().await
            .context("cannot enumerate Azure SNP firmware variants; check profile publication and registry interface")?;
        ensure!(
            ids.len() <= 128,
            "too many variants for bounded deployment preflight"
        );
        let mut candidates = Vec::new();
        for id in ids {
            let variant = images
                .getMeasurementVariant(id)
                .block(block.into())
                .call()
                .await?;
            if variant.name.contains("@firmware-")
                && atakit_core::measurement_variant_machine_type(&variant.name).ok()
                    == Some(machine)
            {
                candidates.push(id);
            }
        }
        ensure!(
            !candidates.is_empty(),
            "no published firmware variants for {profile_name}/{machine}"
        );
        candidates
    } else {
        vec![atakit_cvm_encoding::variant_id(profile_id.0, machine).into()]
    };
    for variant_id in variants {
        let Some(result) = signed_response(
            images
                .getSignedVariant(image_id, profile_id, variant_id)
                .block(block.into())
                .call()
                .await,
            &format!("base-image variant {profile_name}/{machine} ({variant_id})"),
            &mut warnings,
        )?
        else {
            continue;
        };
        let image_policy = signed::getSignedVariantCall::abi_decode_returns_validate(
            &(result,).abi_encode_params(),
        )
        .context("malformed signed variant response")?;
        if image_policy.variantSignature.is_empty() {
            warnings.push(format!(
                "Base-image variant {variant_id} has no publisher policy signature."
            ));
            continue;
        }
        signed::verify_variant(image_id, profile_id, variant_id, &image_policy)
            .context("base-image publisher signature or identity is invalid")?;
        if let Some(workload_policy) = &workload_policy {
            signed::verify_selected_policy(
                workload_id,
                image_id,
                profile_id,
                variant_id,
                workload_policy.clone(),
                image_policy,
            )
            .context("signed image/workload policies are incompatible")?;
        }
    }
    if warnings.is_empty() {
        eprintln!("  PASS: signed base-image policies for {profile_name}/{machine}; publisher identities, image permission and ordinary attributes checked");
    } else {
        eprintln!("  NOT CHECKED: complete publisher-signed policy compatibility");
    }
    if firmware_selected {
        eprintln!("  NOT CHECKED: exact Azure SNP firmware variant; Portal selects it from PCR0/PCR2 after boot");
    }
    eprintln!("  NOT CHECKED: live measurements and hardware security; deployment preflight does not authorize secret provisioning");
    Ok(warnings)
}

// A reverting or absent getter may belong to an older registry. Transport and
// malformed-response failures remain errors, rather than claims of legacy data.
fn signed_response<T>(
    result: Result<T, alloy_ext::contract::Error>,
    record: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<T>> {
    use alloy_ext::contract::Error;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            let unavailable = match &error {
                Error::ZeroData(..) => true,
                Error::TransportError(error) => error.as_error_resp().is_some_and(|response| {
                    response.code == 3 || response.message.contains("execution reverted")
                }),
                _ => false,
            };
            if !unavailable {
                return Err(error.into());
            }
            warnings.push(format!("Publisher policy signature unavailable for {record}: the signed getter reverted or returned no data."));
            Ok(None)
        }
    }
}

pub(super) fn confirm_policy_warnings(
    warnings: &[String],
    check_only: bool,
    yes: bool,
) -> Result<()> {
    confirm_policy_warnings_with(
        warnings,
        check_only,
        yes,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn confirm_policy_warnings_with(
    warnings: &[String],
    check_only: bool,
    yes: bool,
    input: &mut impl std::io::BufRead,
    output: &mut impl std::io::Write,
) -> Result<()> {
    if warnings.is_empty() {
        return Ok(());
    }
    for warning in warnings {
        writeln!(output, "  WARNING: {warning}")?;
    }
    writeln!(output, "Publisher policy signatures are missing or unavailable. Deployment may fail if the selected image requires signed policies.")?;
    if check_only {
        return Ok(());
    }
    if yes {
        writeln!(output, "Continuing because --yes was supplied.")?;
        return Ok(());
    }
    write!(output, "Continue? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    ensure!(
        matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        "deployment cancelled: publisher policy signature warning was not accepted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_ext::core::{primitives::keccak256, sol_types::SolValue};
    use automata_tee_workload_measurement::stubs::{
        BaseImageRegistry::BaseImageSpec,
        WorkloadRegistry::{PcrPolicyBlock, WorkloadSpec},
    };
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn missing_signature_prompt_requires_explicit_acceptance() {
        for (answer, accepted) in [
            ("y\n", true),
            ("YES\n", true),
            ("n\n", false),
            ("\n", false),
            ("", false),
        ] {
            let mut input = std::io::Cursor::new(answer.as_bytes());
            let mut output = Vec::new();
            let result = confirm_policy_warnings_with(
                &["Workload has no publisher signature.".into()],
                false,
                false,
                &mut input,
                &mut output,
            );
            assert_eq!(result.is_ok(), accepted, "{answer:?}");
            let output = String::from_utf8(output).unwrap();
            assert!(output
                .contains("Deployment may fail if the selected image requires signed policies."));
            assert!(output.contains("Continue? [y/N]"));
        }
        for (warnings, check_only, yes) in [
            (vec![], false, false),
            (vec!["missing signature".into()], true, false),
            (vec!["missing signature".into()], false, true),
        ] {
            let mut input = std::io::Cursor::new(b"n\n");
            let mut output = Vec::new();
            confirm_policy_warnings_with(&warnings, check_only, yes, &mut input, &mut output)
                .unwrap();
            assert_eq!(input.position(), 0);
            let output = String::from_utf8(output).unwrap();
            assert!(!output.contains("Continue?"));
            assert_eq!(output.contains("WARNING"), !warnings.is_empty());
        }
    }

    #[tokio::test]
    async fn preflight_registry_checks_exact_records_revocation_and_permission() {
        for scenario in [
            "pass",
            "missing workload",
            "revoked workload",
            "missing image",
            "revoked image",
            "denied image",
            "wrong chain",
            "native image",
            "wrong registry",
            "missing signed getter",
            "missing variant getter",
            "unsigned workload revoked image",
            "signed getter rpc error",
            "empty signed getter",
            "unsigned workload",
            "altered workload",
            "unsigned variant",
            "wrong variant",
            "azure no variants",
            "azure unrelated variants",
            "azure variant cap",
        ] {
            let fixture: Value = serde_json::from_str(include_str!(
                "../../../../../atakit-portal-chain/tests/fixtures/publisher-policies.json"
            ))
            .unwrap();
            let decode =
                |v: &Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
            let mut wp = signed::getSignedWorkloadCall::abi_decode_returns_validate(&decode(
                &fixture["workload"]["rawGetterResult"],
            ))
            .unwrap();
            let mut ip = signed::getSignedVariantCall::abi_decode_returns_validate(&decode(
                &fixture["variants"][0]["rawGetterResult"],
            ))
            .unwrap();
            let workload = AppRef::new(wp.ownerFingerprint, &wp.spec.name, &wp.spec.version);
            let image = AppRef::new(
                ip.ownerFingerprint,
                &ip.baseImage.name,
                &ip.baseImage.version,
            );
            if matches!(
                scenario,
                "unsigned workload" | "unsigned workload revoked image"
            ) {
                wp.workloadSignature = Default::default();
            }
            if scenario == "altered workload" {
                wp.spec.requirements.clear();
            }
            if scenario == "unsigned variant" {
                ip.variantSignature = Default::default();
            }
            let signed_workload = (wp,).abi_encode_params();
            let unsigned_variant = (ip.measurementVariant.clone(),).abi_encode_params();
            let signed_image = (ip,).abi_encode_params();
            let pid: B256 = fixture["variants"][0]["profileId"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let vid: B256 = fixture["variants"][0]["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let wid = crate::commands::workload::compute_workload_id(&workload);
            let bid = crate::commands::workload::compute_base_image_id(&image);
            let azure = scenario.starts_with("azure ");
            let pid = if azure {
                atakit_cvm_encoding::platform_profile_id(bid.0, "azure-sev-snp").into()
            } else {
                pid
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = calls.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let parsed: Value = loop {
                        let mut buf = [0; 4096];
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&buf[..n]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let length: usize = headers
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .map(|n| n.trim().parse().unwrap())
                                })
                                .unwrap();
                            if request.len() >= end + 4 + length {
                                break serde_json::from_slice(&request[end + 4..end + 4 + length])
                                    .unwrap();
                            }
                        }
                    };
                    recorded.lock().unwrap().push(parsed.clone());
                    let mut missing = false;
                    let result = match parsed["method"].as_str().unwrap() {
                        "eth_chainId" => {
                            if scenario == "wrong chain" {
                                "0x2".into()
                            } else {
                                "0x1".into()
                            }
                        }
                        "eth_blockNumber" => "0x2a".into(),
                        "eth_call" => {
                            assert_eq!(parsed["params"][1], "0x2a");
                            let input = parsed["params"][0]["input"]
                                .as_str()
                                .or_else(|| parsed["params"][0]["data"].as_str())
                                .unwrap();
                            let selector = &input[2..10];
                            let is = |sig: &str| {
                                selector == hex::encode(&keccak256(sig.as_bytes())[..4])
                            };
                            let graph_call = is("workloadRegistry()") || is("baseImageRegistry()");
                            let image_call = is("getBaseImage(bytes32)")
                                || is("isBaseImageRevoked(bytes32)")
                                || is("getSignedVariant(bytes32,bytes32,bytes32)")
                                || is("getMeasurementVariantIds(bytes32)")
                                || is("getMeasurementVariant(bytes32)");
                            assert_eq!(
                                parsed["params"][0]["to"],
                                format!(
                                    "0x{}",
                                    if graph_call {
                                        "33"
                                    } else if image_call {
                                        "22"
                                    } else {
                                        "11"
                                    }
                                    .repeat(20)
                                )
                            );
                            if !graph_call {
                                assert_eq!(
                                    &input[10..74],
                                    hex::encode(if is("getMeasurementVariantIds(bytes32)") {
                                        pid
                                    } else if is("getMeasurementVariant(bytes32)") {
                                        vid
                                    } else if image_call {
                                        bid
                                    } else {
                                        wid
                                    })
                                );
                            }
                            let bytes = if is("workloadRegistry()") {
                                (Address::repeat_byte(if scenario == "wrong registry" {
                                    0x44
                                } else {
                                    0x11
                                }),)
                                    .abi_encode_params()
                            } else if is("baseImageRegistry()") {
                                (Address::repeat_byte(0x22),).abi_encode_params()
                            } else if is("getSignedWorkload(bytes32)") {
                                missing = matches!(
                                    scenario,
                                    "missing signed getter" | "signed getter rpc error"
                                );
                                if scenario == "empty signed getter" {
                                    vec![]
                                } else {
                                    signed_workload.clone()
                                }
                            } else if is("getMeasurementVariantIds(bytes32)") {
                                let ids = match scenario {
                                    "azure no variants" => vec![],
                                    "azure variant cap" => vec![vid; 129],
                                    _ => vec![vid],
                                };
                                (ids,).abi_encode_params()
                            } else if is("getMeasurementVariant(bytes32)") {
                                unsigned_variant.clone()
                            } else if is("getSignedVariant(bytes32,bytes32,bytes32)") {
                                assert_eq!(&input[74..138], hex::encode(pid));
                                if scenario != "wrong variant" {
                                    assert_eq!(&input[138..], hex::encode(vid));
                                }
                                missing = scenario == "missing variant getter";
                                signed_image.clone()
                            } else if is("getWorkload(bytes32)") {
                                missing = scenario == "missing workload";
                                (WorkloadSpec {
                                    name: "workload".into(),
                                    version: "v1".into(),
                                    sessionTtl: 0,
                                    baseImageMode: 0,
                                    baseImageIds: vec![],
                                    requirements: vec![],
                                    workloadPcrPolicy: PcrPolicyBlock {
                                        pcrSpecs256: vec![],
                                        pcrSpecs384: vec![],
                                    },
                                },)
                                    .abi_encode_params()
                            } else if is("getBaseImage(bytes32)") {
                                missing = scenario == "missing image";
                                (BaseImageSpec {
                                    name: "image".into(),
                                    version: "v1".into(),
                                    uri: String::new(),
                                },)
                                    .abi_encode_params()
                            } else if is("isWorkloadRevoked(bytes32)") {
                                (scenario == "revoked workload",).abi_encode_params()
                            } else if is("isBaseImageRevoked(bytes32)") {
                                (matches!(
                                    scenario,
                                    "revoked image" | "unsigned workload revoked image"
                                ),)
                                    .abi_encode_params()
                            } else {
                                assert!(is("isBaseImageAllowed(bytes32,bytes32)"));
                                assert_eq!(&input[74..], hex::encode(bid));
                                (scenario != "denied image",).abi_encode_params()
                            };
                            format!("0x{}", hex::encode(bytes))
                        }
                        other => panic!("unexpected RPC: {other}"),
                    };
                    let response = if missing {
                        json!({"jsonrpc":"2.0","id":parsed["id"],"error":{"code":if scenario == "signed getter rpc error" {-32005} else {3},"message":if scenario == "signed getter rpc error" {"rate limited"} else {"execution reverted"}}})
                    } else {
                        json!({"jsonrpc":"2.0","id":parsed["id"],"result":result})
                    };
                    let body = response.to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
            });
            let chain = InitChainConfig {
                rpc_url: format!("http://{address}"),
                session_registry: format!("0x{}", "33".repeat(20)),
                workload_registry: format!("0x{}", "11".repeat(20)),
                base_image_registry: format!("0x{}", "22".repeat(20)),
                chain_id: Some(1),
                registration: Some("required".into()),
                tee_backend: "auto".into(),
                prover: None,
            };
            let image_ref = if scenario == "native image" {
                "cloud-image".into()
            } else {
                image.to_string()
            };
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                check_registries(
                    &chain,
                    &workload,
                    &image_ref,
                    if azure {
                        PlatformKind::Azure
                    } else {
                        PlatformKind::Aws
                    },
                    CcType::SevSnp,
                    if scenario == "wrong variant" {
                        "m6a.xlarge"
                    } else {
                        "m6a.large"
                    },
                ),
            )
            .await;
            server.abort();
            let server_result = server.await;
            assert!(!server_result.unwrap_err().is_panic(), "mock RPC failed");
            let result = result.expect("registry check hung");
            assert_eq!(
                result.is_ok(),
                matches!(
                    scenario,
                    "pass"
                        | "native image"
                        | "missing signed getter"
                        | "missing variant getter"
                        | "empty signed getter"
                        | "unsigned workload"
                        | "unsigned variant"
                ),
                "{scenario}: {result:?}"
            );
            if matches!(
                scenario,
                "missing signed getter"
                    | "missing variant getter"
                    | "empty signed getter"
                    | "unsigned workload"
                    | "unsigned variant"
            ) {
                assert_eq!(result.as_ref().unwrap().len(), 1, "{scenario}");
            } else if let Ok(warnings) = &result {
                assert!(warnings.is_empty(), "{scenario}");
            }
            if azure {
                let message = format!("{:#}", result.unwrap_err());
                assert!(
                    message.contains(if scenario == "azure variant cap" {
                        "too many variants"
                    } else {
                        "no published firmware variants"
                    }),
                    "{scenario}: {message}"
                );
            }
            let calls = calls.lock().unwrap();
            if scenario == "wrong chain" {
                assert!(!calls.iter().any(|c| c["method"] == "eth_call"));
            }
            if scenario == "pass" {
                assert_eq!(
                    calls.iter().filter(|c| c["method"] == "eth_call").count(),
                    9
                );
            }
            if scenario == "native image" {
                assert_eq!(
                    calls.iter().filter(|c| c["method"] == "eth_call").count(),
                    5
                );
            }
        }
    }
}
