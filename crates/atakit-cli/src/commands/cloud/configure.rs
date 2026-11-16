use crate::config::Config;
use anyhow::{bail, Context, Result};
use atakit_cloud::cli::{ConfigureArgs, RuntimeCpuArgs};
use atakit_core::{
    cpu_config::{FrequencySelection, IdleSelection, RuntimeCpuConfig, RuntimeCpuSelection},
    runtime_config::{RuntimeInputs, ThpMode},
    Env,
};
use std::{collections::BTreeMap, time::Duration};

fn record_sources(
    value: &serde_json::Value,
    path: &str,
    source: &str,
    out: &mut BTreeMap<String, String>,
) {
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            record_sources(
                value,
                &if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                },
                source,
                out,
            );
        }
    } else if !value.is_null() {
        out.insert(path.to_string(), source.to_string());
    }
}
/// One parsed snapshot shared by every scope in a request.
#[derive(Default)]
pub(super) struct RuntimeFile {
    inputs: RuntimeInputs,
    has_cpu: bool,
}

impl RuntimeFile {
    pub(super) fn read(args: &RuntimeCpuArgs) -> Result<Self> {
        let Some(path) = &args.runtime_config else {
            return Ok(Self::default());
        };
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() > 65536 {
            bail!("runtime configuration exceeds 64 KiB");
        }
        let value: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
        let has_cpu = value
            .as_table()
            .is_some_and(|table| table.keys().any(|key| key != "thp"));
        Ok(Self {
            inputs: value.try_into()?,
            has_cpu,
        })
    }

    pub(super) fn thp(&self, defaults: &RuntimeInputs, target: &RuntimeInputs) -> Option<ThpMode> {
        self.inputs.thp.or(target.thp).or(defaults.thp)
    }
}

pub(super) fn resolve(
    args: &RuntimeCpuArgs,
    defaults: &RuntimeCpuConfig,
    target: &RuntimeCpuConfig,
    file: &RuntimeFile,
) -> Result<RuntimeCpuSelection> {
    let mut result = RuntimeCpuSelection::default();
    let mut add = |value: &RuntimeCpuConfig, source: &str| -> Result<()> {
        result.config.overlay(value);
        record_sources(
            &serde_json::to_value(value)?,
            "",
            source,
            &mut result.sources,
        );
        Ok(())
    };
    add(defaults, "cloud.defaults.runtime")?;
    add(target, "cloud.targets.runtime")?;
    // Do not publish workstation paths in public status responses.
    add(&file.inputs.cpu, "runtime-config file")?;
    let mut flags = RuntimeCpuConfig {
        cpuset: args.cpuset.clone(),
        ..Default::default()
    };
    if args.cpu_idle_governor.is_some() || args.cpu_idle_disabled_states.is_some() {
        flags.cpu_idle = Some(IdleSelection {
            governor: args.cpu_idle_governor.clone(),
            disabled_states: args.cpu_idle_disabled_states.as_ref().map(|v| {
                if v.is_empty() {
                    vec![]
                } else {
                    v.split(',').map(str::to_string).collect()
                }
            }),
        });
    }
    if args.cpu_frequency_governor.is_some() {
        flags.cpu_frequency = Some(FrequencySelection {
            governor: args.cpu_frequency_governor.clone(),
        });
    }
    for (values, output) in [
        (&args.dependency_cpuset, &mut flags.dependencies),
        (&args.baby_cpuset, &mut flags.baby_containers),
    ] {
        for value in values {
            let (name, cpus) = value
                .split_once('=')
                .context("CPU selection must be NAME=CPUS")?;
            if name.is_empty() || output.insert(name.to_string(), cpus.to_string()).is_some() {
                bail!("empty or duplicate CPU scope {name:?}");
            }
        }
    }
    add(&flags, "command line")?;
    result.config.normalize().map_err(anyhow::Error::msg)?;
    Ok(result)
}

/// Validate choices against the exact archive policy before deployment or upload.
pub(super) fn resolve_disks(
    target: &atakit_cloud::CloudTarget,
    manifest: &atakit_workload::manifest::Manifest,
) -> Result<atakit_core::disk_config::RuntimeDiskConfig> {
    target
        .runtime_disks()
        .resolve(
            manifest
                .disks
                .iter()
                .map(|(name, disk)| (name.as_str(), !disk.encryption.unlock_method.is_empty())),
        )
        .map_err(anyhow::Error::msg)
}

/// Validate choices against the exact archive policy before deployment or upload.
/// Guest CPU availability remains a Portal startup check.
pub(super) fn resolve_for_manifest(
    args: &RuntimeCpuArgs,
    defaults: &RuntimeCpuConfig,
    target: &RuntimeCpuConfig,
    manifest: &atakit_workload::manifest::Manifest,
    file: &RuntimeFile,
) -> Result<RuntimeCpuSelection> {
    use atakit_core::cpu_config::{resolve_cpuset, resolve_frequency, resolve_idle};
    let selection = resolve(args, defaults, target, file)?;
    let request = &selection.config;
    let policy = &manifest.config;
    let validate = || -> std::result::Result<(), String> {
        resolve_idle(policy.cpu_idle.as_ref(), request.cpu_idle.as_ref())?;
        resolve_frequency(
            policy.cpu_frequency.as_ref(),
            request.cpu_frequency.as_ref(),
        )?;
        resolve_cpuset(
            policy.cpuset.as_deref(),
            policy.cpuset_policy.as_ref(),
            request.cpuset.as_deref(),
        )?;
        for name in request.dependencies.keys() {
            if !policy
                .dependencies
                .as_ref()
                .is_some_and(|d| d.contains_key(name))
            {
                return Err(format!("unknown CPU dependency {name:?}"));
            }
        }
        for (name, dep) in policy.dependencies.iter().flat_map(|d| d.iter()) {
            resolve_cpuset(
                dep.cpuset.as_deref(),
                dep.cpuset_policy.as_ref(),
                request.dependencies.get(name).map(String::as_str),
            )?;
        }
        for name in request.baby_containers.keys() {
            if !policy.baby_container.slots.contains_key(name) {
                return Err(format!("unknown CPU baby slot {name:?}"));
            }
        }
        for (name, slot) in &policy.baby_container.slots {
            resolve_cpuset(
                slot.cpuset.as_deref(),
                slot.cpuset_policy.as_ref(),
                request.baby_containers.get(name).map(String::as_str),
            )?;
        }
        Ok(())
    };
    validate()
        .map_err(anyhow::Error::msg)
        .context("CPU configuration violates workload policy")?;
    Ok(selection)
}

pub async fn run(args: ConfigureArgs, env: &Env, config: &Config) -> Result<()> {
    let access = super::session_access::resolve_disk_unlock_access(
        &args.instance,
        args.target.as_deref(),
        &args.verification,
        env,
        config,
    )
    .await?;
    if access.verified_tls.manual_override().is_some() {
        bail!("runtime configuration requires verified TLS without a manual override");
    }
    let target = config
        .cloud
        .targets
        .get(&access.target_name)
        .context("target not found")?;
    let file = RuntimeFile::read(&args.runtime)?;
    let selection = if args.reset {
        RuntimeCpuSelection::default()
    } else {
        resolve(
            &args.runtime,
            &config.cloud.defaults.runtime,
            &target.runtime,
            &file,
        )?
    };
    let thp = if args.reset {
        Some(atakit_core::runtime_config::ThpMode::Never)
    } else {
        file.thp(&config.cloud.defaults.runtime, &target.runtime)
    };
    let key_name = args
        .owner_key
        .as_deref()
        .or((!access.state.init_env.owner_key.is_empty())
            .then_some(access.state.init_env.owner_key.as_str()))
        .or(target.owner_key.as_deref())
        .context("configure a provisioned owner key or use --owner-key")?;
    let key = super::disk::resolve_owner_key(key_name, config)?;
    let archive = std::path::Path::new(&access.state.archive_path);
    let (inspected, archive_hash, _) = super::inspect_workload_archive_snapshot(archive)?;
    let actual = hex::encode(archive_hash);
    if access.state.archive_hash.is_empty()
        || !atakit_workload::hex_equal(&actual, &access.state.archive_hash)
    {
        bail!("local workload archive differs from saved deployment");
    }
    let manifest_hash = inspected
        .manifest_hash
        .strip_prefix("sha256:")
        .context("local workload inspection did not return a SHA-256 manifest hash")?;
    let expected = crate::commands::workload::parse_workload_ref(
        &format!(
            "{}/{}:{}",
            access.state.workload_publisher,
            access.state.workload_name,
            access.state.workload_version
        ),
        &config.alias,
    )?
    .workload_id();
    let host = if access.host.contains(':') {
        format!("[{}]", access.host)
    } else {
        access.host.clone()
    };
    let base = format!("https://{host}:{}", access.status_port);
    let client = access.verified_tls.client();
    let status = super::disk::read_json(
        client
            .get(format!("{base}/status"))
            .timeout(Duration::from_secs(15))
            .send()
            .await?,
    )
    .await?;
    super::disk::validate_workload_identity(&status, &expected)?;
    // Failed startup deliberately clears PCR23. A correction carries the exact
    // manifest hash in the owner-signed body; the attested base-image supervisor
    // checks that hash, manifest integrity and runtime permissions before staging it.
    // Startup verifies the publisher signature before applying the settings. This is
    // a runtime control operation; it does not unlock disks or provision secrets.
    if status["state"] != "Failed" {
        super::disk::check_inspected_workload_measurement(client, &base, &inspected).await?;
    }
    let challenge = read_cpu_response(
        client
            .get(format!("{base}/runtime-config/challenge"))
            .timeout(Duration::from_secs(15))
            .send()
            .await?,
    )
    .await?;
    let nonce = challenge["challenge"]
        .as_str()
        .context("Portal did not provide runtime configuration challenge")?;
    let has_cpu = args.reset || file.has_cpu || selection.config != RuntimeCpuConfig::default();
    let has_disks = args.reset
        || target
            .disks
            .values()
            .any(|d| d.encryption_workqueues.is_some());
    if has_disks && !args.reset {
        eprintln!("Staging encryption_workqueues from the target. Disk profiles and boot_disk apply only when creating disks.");
    }
    if !has_cpu && !has_disks && thp.is_none() {
        bail!("no runtime choices supplied; configure CPU, disk or THP choices, or use --reset");
    }
    let mut request = serde_json::json!({"manifest_hash": manifest_hash, "check": args.check});
    if has_cpu {
        request["selection"] = serde_json::to_value(selection)?;
    }
    if has_disks {
        request["runtime_disks"] = if args.reset {
            serde_json::to_value(atakit_core::disk_config::RuntimeDiskConfig::default())?
        } else {
            serde_json::to_value(resolve_disks(target, &inspected.manifest)?)?
        };
    }
    if let Some(thp) = thp {
        request["thp"] = serde_json::to_value(thp)?;
    }
    let body = serde_json::to_vec(&request)?;
    let tls = hex::encode(access.verified_tls.identity().cert_sha256);
    let (signature, recovery) =
        key.sign_prehash_recoverable(&atakit_core::cpu_config::request_digest(&tls, nonce, &body))?;
    let mut signature = signature.to_bytes().to_vec();
    signature.push(recovery.to_byte());
    let response = read_cpu_response(
        client
            .post(format!("{base}/runtime-config"))
            .header("atakit-runtime-challenge", nonce)
            .header(
                "atakit-owner-signature",
                format!("0x{}", hex::encode(signature)),
            )
            .header("content-type", "application/json")
            .body(body)
            .timeout(Duration::from_secs(30))
            .send()
            .await?,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    eprintln!(
        "{}",
        if args.check {
            "Runtime choices validated. No settings saved or applied; disk modes are verified when disks open."
        } else if response["state"] == "unchanged" {
            "Runtime choices already match. No reboot needed for these choices."
        } else {
            "Runtime choices saved. Reboot the VM to apply disk and THP choices; CPU choices apply at workload startup."
        }
    );
    Ok(())
}

async fn read_cpu_response(mut response: reqwest::Response) -> Result<serde_json::Value> {
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > 65536 {
            bail!("Runtime configuration response exceeds 64 KiB");
        }
        body.extend_from_slice(&chunk);
    }
    decode_cpu_response(status, &body)
}

fn decode_cpu_response(status: reqwest::StatusCode, body: &[u8]) -> Result<serde_json::Value> {
    let value = serde_json::from_slice::<serde_json::Value>(body);
    if !status.is_success() {
        let detail = value
            .as_ref()
            .ok()
            .and_then(|v| v.get("error"))
            .and_then(|v| v.as_str())
            .map(|s| {
                s.chars()
                    .filter(|c| !c.is_control())
                    .take(512)
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty());
        if let Some(detail) = detail {
            bail!("Runtime configuration rejected (HTTP {status}): {detail}");
        }
        bail!("Runtime configuration API returned HTTP {status}");
    }
    value.context("invalid Runtime configuration API response")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy_manifest() -> atakit_workload::manifest::Manifest {
        let config = atakit_workload::config::WorkloadConfig::load_from_str(
            r#"
format = 16
[workload]
name = "app"
version = "v1"
image = "app:latest"
base-image-mode = "blacklist"
allow-operator-cpu-tuning = true
atakit-portal = true
[dependencies.logger]
image = "logger:latest"
[baby-container]
enabled = true
[baby-container.slots.tools]
parent-service = "app"
"#,
        )
        .unwrap();
        atakit_workload::manifest::build_manifest(
            &config,
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "app:latest",
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap()
    }

    #[test]
    fn thp_layering_preserves_omission_and_does_not_select_cpu() {
        use atakit_core::runtime_config::{RuntimeInputs, ThpMode};
        let mut defaults = RuntimeInputs::default();
        let mut target = RuntimeInputs::default();
        let mut args = RuntimeCpuArgs::default();
        assert_eq!(
            RuntimeFile::read(&args).unwrap().thp(&defaults, &target),
            None
        );
        defaults.thp = Some(ThpMode::Madvise);
        target.thp = Some(ThpMode::Never);
        assert_eq!(
            RuntimeFile::read(&args).unwrap().thp(&defaults, &target),
            Some(ThpMode::Never)
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.toml");
        std::fs::write(&path, "thp = 'madvise'\n").unwrap();
        args.runtime_config = Some(path.clone());
        assert_eq!(
            RuntimeFile::read(&args).unwrap().thp(&defaults, &target),
            Some(ThpMode::Madvise)
        );
        assert!(!RuntimeFile::read(&args).unwrap().has_cpu);
        assert_eq!(
            resolve(
                &args,
                &defaults,
                &target,
                &RuntimeFile::read(&args).unwrap()
            )
            .unwrap()
            .config,
            RuntimeCpuConfig::default()
        );
        std::fs::write(&path, "").unwrap();
        assert!(!RuntimeFile::read(&args).unwrap().has_cpu);
        std::fs::write(&path, "thp = 'always'\n").unwrap();
        assert!(RuntimeFile::read(&args).is_err());
        std::fs::write(&path, "thp = 'madvise'\ndefrag = 'always'\n").unwrap();
        assert!(RuntimeFile::read(&args).is_err());
    }

    #[test]
    fn runtime_file_uses_one_snapshot_for_cpu_thp_and_omission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.toml");
        let args = RuntimeCpuArgs {
            runtime_config: Some(path.clone()),
            ..Default::default()
        };
        for (original, has_cpu, cpuset, thp) in [
            ("thp = 'madvise'\n", false, None, Some(ThpMode::Madvise)),
            (
                "cpuset = '0-1'\nthp = 'never'\n",
                true,
                Some("0,1"),
                Some(ThpMode::Never),
            ),
            ("[dependencies]\n", true, None, None),
            ("", false, None, None),
        ] {
            std::fs::write(&path, original).unwrap();
            let file = RuntimeFile::read(&args).unwrap();
            std::fs::write(&path, "invalid changed input").unwrap();
            let inputs = RuntimeInputs::default();
            let cpu = resolve(&args, &inputs, &inputs, &file).unwrap();
            assert_eq!(cpu.config.cpuset.as_deref(), cpuset);
            assert_eq!(file.has_cpu, has_cpu);
            assert_eq!(file.thp(&inputs, &inputs), thp);
        }
    }

    #[test]
    fn deployment_cpu_preflight_rejects_permissions_and_unknown_scopes() {
        let mut manifest = policy_manifest();
        manifest.config.cpuset_policy.as_mut().unwrap().allowed_cpus = Some("0-3".into());
        let empty = RuntimeCpuConfig::default();
        let check = |args: RuntimeCpuArgs, manifest: &atakit_workload::manifest::Manifest| {
            resolve_for_manifest(
                &args,
                &empty,
                &empty,
                manifest,
                &RuntimeFile::read(&args).unwrap(),
            )
        };
        for (args, expected) in [
            (
                RuntimeCpuArgs {
                    cpuset: Some("4".into()),
                    ..Default::default()
                },
                "outside publisher allowance",
            ),
            (
                RuntimeCpuArgs {
                    cpu_idle_governor: Some("ladder".into()),
                    ..Default::default()
                },
                "outside publisher allowance",
            ),
            (
                RuntimeCpuArgs {
                    cpu_frequency_governor: Some("performance".into()),
                    ..Default::default()
                },
                "forbids operator",
            ),
            (
                RuntimeCpuArgs {
                    dependency_cpuset: vec!["missing=0".into()],
                    ..Default::default()
                },
                "unknown CPU dependency",
            ),
            (
                RuntimeCpuArgs {
                    baby_cpuset: vec!["missing=0".into()],
                    ..Default::default()
                },
                "unknown CPU baby slot",
            ),
        ] {
            assert!(format!("{:#}", check(args, &manifest).unwrap_err()).contains(expected));
        }
        // Publisher-fixed settings cannot be overridden, even with an opt-in preset.
        manifest.config.cpuset = Some("0".into());
        assert!(format!(
            "{:#}",
            check(
                RuntimeCpuArgs {
                    cpuset: Some("0".into()),
                    ..Default::default()
                },
                &manifest
            )
            .unwrap_err()
        )
        .contains("publisher-fixed"));
        manifest.config.cpuset = None;
        // A valid request keeps normalization and defers hardware support to Portal.
        let selected = check(
            RuntimeCpuArgs {
                cpuset: Some("3,1-2".into()),
                dependency_cpuset: vec!["logger=99".into()],
                baby_cpuset: vec!["tools=4-5".into()],
                cpu_idle_governor: Some("teo".into()),
                ..Default::default()
            },
            &manifest,
        )
        .unwrap();
        assert_eq!(selected.config.cpuset.as_deref(), Some("1,2,3"));
        assert_eq!(selected.config.dependencies["logger"], "99");
        // Defaults and targets go through the same policy check as flags.
        let denied = RuntimeCpuConfig {
            cpuset: Some("4".into()),
            ..Default::default()
        };
        assert!(resolve_for_manifest(
            &RuntimeCpuArgs::default(),
            &denied,
            &empty,
            &manifest,
            &RuntimeFile::default()
        )
        .is_err());
        assert!(resolve_for_manifest(
            &RuntimeCpuArgs::default(),
            &empty,
            &denied,
            &manifest,
            &RuntimeFile::default()
        )
        .is_err());
    }

    #[test]
    fn deployment_cpu_preflight_requires_selections_for_every_declared_scope() {
        for scope in ["workload", "dependency", "baby", "idle", "frequency"] {
            let mut manifest = policy_manifest();
            match scope {
                "workload" => manifest.config.cpuset_policy.as_mut().unwrap().required = true,
                "dependency" => {
                    manifest
                        .config
                        .dependencies
                        .as_mut()
                        .unwrap()
                        .get_mut("logger")
                        .unwrap()
                        .cpuset_policy
                        .as_mut()
                        .unwrap()
                        .required = true
                }
                "baby" => {
                    manifest
                        .config
                        .baby_container
                        .slots
                        .get_mut("tools")
                        .unwrap()
                        .cpuset_policy
                        .as_mut()
                        .unwrap()
                        .required = true
                }
                "idle" => manifest.config.cpu_idle.as_mut().unwrap().required = true,
                _ => {
                    let rule = manifest.config.cpu_frequency.as_mut().unwrap();
                    rule.allow_operator = Some(true);
                    rule.allowed_governors = Some(vec!["performance".into()]);
                    rule.required = true;
                }
            }
            let error = resolve_for_manifest(
                &RuntimeCpuArgs::default(),
                &RuntimeCpuConfig::default(),
                &RuntimeCpuConfig::default(),
                &manifest,
                &RuntimeFile::default(),
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("requires an operator"),
                "{scope}: {error:#}"
            );
        }
    }

    #[test]
    fn cpu_rejection_reports_the_publisher_rule_without_disk_advice() {
        let error = decode_cpu_response(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"idle governor is outside publisher allowance"}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("idle governor is outside publisher allowance"));
        assert!(!error.contains("disk"));
        let error = decode_cpu_response(reqwest::StatusCode::BAD_GATEWAY, b"private proxy dump")
            .unwrap_err()
            .to_string();
        assert!(error.contains("502"));
        assert!(!error.contains("private proxy dump"));
    }

    #[test]
    fn flags_file_target_and_defaults_merge_per_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.toml");
        std::fs::write(
            &path,
            "cpuset = '3,1-2'\n[cpu-idle]\ndisabled-states = []\n[dependencies]\nlogger = '1'\n",
        )
        .unwrap();
        let defaults: RuntimeCpuConfig = toml::from_str(
            "cpuset = '0'\n[cpu-idle]\ngovernor = 'menu'\ndisabled-states = ['C6']\n",
        )
        .unwrap();
        let target: RuntimeCpuConfig = toml::from_str("[cpu-idle]\ngovernor = 'teo'\n").unwrap();
        let args = RuntimeCpuArgs {
            runtime_config: Some(path),
            cpuset: Some("1,0".into()),
            ..Default::default()
        };
        let selected = resolve(
            &args,
            &defaults,
            &target,
            &RuntimeFile::read(&args).unwrap(),
        )
        .unwrap();
        assert_eq!(selected.config.cpuset.as_deref(), Some("0,1"));
        assert_eq!(
            selected
                .config
                .cpu_idle
                .as_ref()
                .unwrap()
                .governor
                .as_deref(),
            Some("teo")
        );
        assert_eq!(
            selected.config.cpu_idle.unwrap().disabled_states,
            Some(vec![])
        );
        assert_eq!(
            selected.sources["cpu-idle.governor"],
            "cloud.targets.runtime"
        );
        assert_eq!(
            selected.sources["cpu-idle.disabled-states"],
            "runtime-config file"
        );
        assert_eq!(selected.sources["cpuset"], "command line");
        assert_eq!(selected.config.dependencies["logger"], "1");
    }
}
