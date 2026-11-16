use super::*;
use crate::{
    init::{InitChainConfig, InitKeyConfig},
    NewDeployParams, PlatformKind,
};
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> (tempfile::TempDir, DeployState, InitializationInputs) {
    let dir = tempfile::tempdir().unwrap();
    let (credential, _) = crate::init_auth::create(dir.path()).unwrap();
    let archive = dir.path().join("workload.atawl");
    fs::write(&archive, vec![42; 1024 * 1024]).unwrap();
    let archive_sha256 = sha2::Sha256::digest(fs::read(&archive).unwrap()).into();
    let mut state = DeployState::new(NewDeployParams {
        instance_name: "vm".into(),
        target_name: "target".into(),
        provider_name: "provider".into(),
        platform: PlatformKind::Aws,
        workload_publisher: format!("0x{}", "11".repeat(32)),
        workload_name: "workload".into(),
        workload_version: "v1".into(),
        image_ref: "image:v1".into(),
        base_image_ref: None,
        archive_path: archive.display().to_string(),
        archive_hash: hex::encode(archive_sha256),
        init_env: Default::default(),
        portal_ports: Default::default(),
        total_steps: 3,
    });
    state.resources.aws = Some(crate::AwsResources {
        region: "region".into(),
        ..Default::default()
    });
    state.init_auth_key_file = Some(credential.display().to_string());
    state.init_auth_required = Some(true);
    let config = InitConfig {
        runtime_cpu: Default::default(),
        runtime_disks: Default::default(),
        thp: None,
        local_ssd: None,
        disk_setup: Default::default(),
        init_auth: Some(crate::init_auth::ClientAuth {
            key_file: credential,
            workload_id: "11".repeat(32),
            tls_fingerprint: "22".repeat(32),
        }),
        submission: None,
        platform: "aws".into(),
        chain: InitChainConfig {
            rpc_url: "https://rpc.example".into(),
            session_registry: "registry".into(),
            workload_registry: "workloads".into(),
            base_image_registry: "images".into(),
            registration: None,
            chain_id: Some(31337),
            tee_backend: "auto".into(),
            prover: None,
        },
        owner_operations: Default::default(),
        owner_key: InitKeyConfig {
            mode: "provisioned".into(),
            key_type: "es256k".into(),
            private_key: Some("private-owner-key".into()),
        },
        gas_wallet: InitKeyConfig {
            mode: "self_generated".into(),
            key_type: "es256k".into(),
            private_key: None,
        },
        prover_credential: None,
        pcr_policy: None,
    };
    let inputs = InitializationInputs {
        config,
        config_sha256: String::new(),
        archive_path: archive.display().to_string(),
        archive_sha256,
        remote_source: None,
        unmeasured_tar: Some(
            atakit_core::unmeasured_data::Archive::from_reader(
                b"private-unmeasured-data".as_slice(),
            )
            .unwrap(),
        ),
        transfer_timeout: 300,
        init_timeout: 900,
        pcr_policy_path: None,
        pcr_policy_sha256: None,
        verification: json!({}),
    };
    prepare(&mut state, dir.path(), inputs.clone()).unwrap();
    (dir, state, inputs)
}
use sha2::Digest;

fn status(record: &Initialization, state: &str, accepted: bool) -> serde_json::Value {
    let bootstrap = record.bootstrap.as_ref().unwrap();
    json!({"state":state, "init_schema_version": crate::init::INIT_SCHEMA_VERSION,
        "init_timeout_mode":"portal-enforced-non-transfer-v1", "init_auth":{
        "deployment_id":bootstrap.deployment_id, "key_fingerprint":bootstrap.fingerprint().unwrap(),
        "accepted_transfer_id": if accepted { Some(record.transfer_id.as_str()) } else { None }
    }})
}

#[test]
fn interrupted_before_send_can_submit_but_uncertain_send_cannot() {
    let (dir, state, inputs) = fixture();
    let record = state.initialization.as_ref().unwrap();
    let awaiting = status(record, "AwaitingInit", false);
    assert_eq!(
        action(record, "tls", &awaiting).unwrap(),
        ResumeAction::Submit
    );
    let submission = Submission::for_state(&state, dir.path()).unwrap();
    submission.record_before_send(&inputs.config).unwrap();
    // This disk reload is what a new CLI process sees, even when no POST ran.
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert!(action(saved.initialization.as_ref().unwrap(), "tls", &awaiting).is_err());
    assert!(submission.record_before_send(&inputs.config).is_err());
    assert!(prepare(&mut saved.clone(), dir.path(), inputs).is_err());
}

#[tokio::test]
async fn planned_disk_names_are_not_freshness_proof_and_uncertain_sends_never_renew_permission() {
    let (dir, mut state, mut inputs) = fixture();
    state.automatic_disk_setup.insert("database".into());
    inputs
        .config
        .disk_setup
        .insert("database".into(), "create".into());
    state.save(dir.path()).unwrap();
    let submission = Submission::for_state(&state, dir.path()).unwrap();
    assert!(submission
        .verify_disks(&inputs.config, &FailedAwsWait)
        .await
        .unwrap_err()
        .to_string()
        .contains("no recorded fresh creation"));
    state.initialization.as_mut().unwrap().phase = InitializationPhase::MayHaveBeenSent;
    state.save(dir.path()).unwrap();
    assert!(submission
        .verify_disks(&inputs.config, &FailedAwsWait)
        .await
        .unwrap_err()
        .to_string()
        .contains("refusing to renew"));
    assert_eq!(
        DeployState::load(dir.path(), "target", "vm")
            .unwrap()
            .initialization
            .unwrap()
            .phase,
        InitializationPhase::MayHaveBeenSent
    );
}

#[test]
fn initialization_hash_includes_disk_queue_choices() {
    let (_, _, mut inputs) = fixture();
    let before = config_hash(&inputs.config);
    inputs.config.runtime_disks =
        serde_json::from_value(json!({"database":{"encryption_workqueues":"bypass"}})).unwrap();
    assert_ne!(before, config_hash(&inputs.config));
    assert_eq!(
        crate::init::build_portal_config_json(&inputs.config)["format"],
        4
    );
}

#[test]
fn resumed_request_requires_same_deployment_key_request_and_certificate() {
    let (dir, state, mut inputs) = fixture();
    inputs.config.init_auth = Some(crate::init_auth::ClientAuth {
        key_file: state.init_auth_key_file.as_ref().unwrap().into(),
        workload_id: "11".repeat(32),
        tls_fingerprint: "tls".into(),
    });
    Submission::for_state(&state, dir.path())
        .unwrap()
        .record_before_send(&inputs.config)
        .unwrap();
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    let record = saved.initialization.as_ref().unwrap();
    let running = status(record, "Running", true);
    assert_eq!(
        action(record, "tls", &running).unwrap(),
        ResumeAction::VerifyComplete
    );
    for field in ["deployment_id", "key_fingerprint", "accepted_transfer_id"] {
        let mut wrong = running.clone();
        wrong["init_auth"][field] = json!("other");
        assert!(action(record, "tls", &wrong).is_err(), "{field}");
    }
    assert!(action(record, "new-certificate", &running).is_err());
    assert!(action(record, "tls", &status(record, "AwaitingInit", false)).is_err());
    assert!(action(record, "tls", &status(record, "Running", false)).is_err());
    assert_eq!(
        action(record, "tls", &status(record, "AwaitingDiskUnlock", true)).unwrap(),
        ResumeAction::DiskUnlock
    );
    assert!(matches!(
        action(record, "tls", &status(record, "Failed", true)).unwrap(),
        ResumeAction::Failed(_)
    ));
}

#[test]
fn saved_inputs_exclude_private_keys_and_reject_changed_keys_or_disk_actions() {
    let (dir, state, inputs) = fixture();
    let record = state.initialization.as_ref().unwrap();
    let path = inputs_path(dir.path(), record).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("private-owner-key"));
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut saved = load_inputs(dir.path(), record).unwrap();
    assert!(saved.validate_restored_config().is_err());
    saved.config.owner_key = inputs.config.owner_key.clone();
    saved.validate_restored_config().unwrap();
    saved
        .config
        .disk_setup
        .insert("data".into(), "overwrite".into());
    assert!(saved.validate_restored_config().is_err());
    let submission = Submission::for_state(&state, dir.path()).unwrap();
    assert!(submission.record_before_send(&saved.config).is_err());
    let reloaded = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        reloaded.initialization.unwrap().phase,
        InitializationPhase::Prepared
    );
}

#[test]
fn completion_survives_interruption_before_and_after_credential_removal() {
    let (dir, mut state, inputs) = fixture();
    Submission::for_state(&state, dir.path())
        .unwrap()
        .record_before_send(&inputs.config)
        .unwrap();
    state = DeployState::load(dir.path(), "target", "vm").unwrap();
    let credential = state.init_auth_key_file.clone().unwrap();
    let original_path = inputs_path(dir.path(), state.initialization.as_ref().unwrap()).unwrap();
    record_complete(&mut state, dir.path(), "192.0.2.1").unwrap();
    let mut saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        saved.initialization.as_ref().unwrap().phase,
        InitializationPhase::VerifiedComplete
    );
    assert!(Path::new(&credential).exists());
    assert!(!original_path.exists());
    let complete_inputs = load_inputs(dir.path(), saved.initialization.as_ref().unwrap()).unwrap();
    assert!(complete_inputs.unmeasured_tar.is_none());
    // Simulate exit in retire after unlink, before the state path is cleared.
    fs::remove_file(&credential).unwrap();
    crate::init_auth::retire(&mut saved, dir.path()).unwrap();
    record_complete(&mut saved, dir.path(), "192.0.2.1").unwrap();
    assert!(DeployState::load(dir.path(), "target", "vm")
        .unwrap()
        .init_auth_key_file
        .is_none());
}

#[test]
fn deployment_lock_excludes_other_commands_and_releases_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let lock = DeploymentLock::acquire(dir.path(), "target", "vm").unwrap();
    assert!(DeploymentLock::acquire(dir.path(), "target", "vm").is_err());
    let other = DeploymentLock::acquire(dir.path(), "target", "other-vm").unwrap();
    drop(lock);
    DeploymentLock::acquire(dir.path(), "target", "vm").unwrap();
    drop(other);
}

#[test]
fn lock_child() {
    let Ok(dir) = std::env::var("ATAKIT_RESUME_LOCK_TEST_DIR") else {
        return;
    };
    let _lock = DeploymentLock::acquire(Path::new(&dir), "target", "vm").unwrap();
    fs::write(Path::new(&dir).join("ready"), b"ready").unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn killed_cli_process_does_not_leave_a_stale_deployment_lock() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resume::tests::lock_child"])
        .env("ATAKIT_RESUME_LOCK_TEST_DIR", dir.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !dir.path().join("ready").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let ready = dir.path().join("ready").exists();
    let blocked = DeploymentLock::acquire(dir.path(), "target", "vm").is_err();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready && blocked);
    DeploymentLock::acquire(dir.path(), "target", "vm").unwrap();
}

struct FailedAwsWait;

struct OtherCloudCreation;
#[async_trait::async_trait]
impl crate::CommandRunner for OtherCloudCreation {
    async fn azure_api(
        &self,
        _: &str,
        url: &str,
        _: Option<&serde_json::Value>,
        _: bool,
    ) -> Result<serde_json::Value, CloudError> {
        let prefix = "/subscriptions/subscription/resourceGroups/group/providers";
        let vm_id = format!("{prefix}/Microsoft.Compute/virtualMachines/created-vm");
        let nic_id = format!("{prefix}/Microsoft.Network/networkInterfaces/created-vm-nic-auto");
        let ip_id = format!("{prefix}/Microsoft.Network/publicIPAddresses/created-vm-ip-auto");
        let attachment = format!("{nic_id}/ipConfigurations/primary");
        if url.contains("/Microsoft.Network/networkInterfaces/") {
            return Ok(
                serde_json::json!({"id":nic_id,"properties":{"resourceGuid":"nic-guid","virtualMachine":{"id":vm_id},"ipConfigurations":[{"name":"primary","id":attachment,"properties":{"subnet":{"id":format!("{prefix}/Microsoft.Network/virtualNetworks/created-vm-vnet/subnets/default")},"publicIPAddress":{"id":ip_id,"properties":{"deleteOption":"Detach"}}}}]}}),
            );
        }
        if url.contains("/Microsoft.Network/publicIPAddresses/") {
            return Ok(
                serde_json::json!({"id":ip_id,"sku":{"name":"Standard"},"properties":{"resourceGuid":"ip-guid","ipConfiguration":{"id":attachment},"deleteOption":"Detach","publicIPAllocationMethod":"Static"}}),
            );
        }
        if url.contains("/providers/Microsoft.Network/") {
            let id = url
                .strip_prefix("https://management.azure.com")
                .unwrap()
                .split('?')
                .next()
                .unwrap();
            return Ok(
                serde_json::json!({"id":id,"properties":{"resourceGuid":format!("guid-{id}"),"provisioningState":"Succeeded"}}),
            );
        }
        Ok(
            serde_json::json!({"id":vm_id,"name":"created-vm","properties":{"vmId":"a1c08226-18b8-4d0e-b15a-917adfe51ed0","provisioningState":"Succeeded","networkProfile":{"networkInterfaces":[{"id":nic_id}]}}}),
        )
    }
    async fn gcp_api(
        &self,
        method: &str,
        url: &str,
        _: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, CloudError> {
        if method == "POST" {
            let token = url.split("requestId=").nth(1).unwrap();
            Ok(
                serde_json::json!({"name":"op","status":"DONE","operationType":"insert","clientOperationId":token,"targetId":"123456789","targetLink":"https://compute.googleapis.com/compute/v1/projects/project/zones/zone/instances/created-vm"}),
            )
        } else {
            Ok(
                serde_json::json!({"id":"123456789","name":"created-vm","disks":[{"boot":true,"source":"projects/project/zones/zone/disks/boot"}]}),
            )
        }
    }
    async fn run_capture(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<crate::CommandOutput, CloudError> {
        let vm = serde_json::json!({"id":"/subscriptions/subscription/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/created-vm","name":"created-vm","properties":{"vmId":"a1c08226-18b8-4d0e-b15a-917adfe51ed0"}});
        let stdout = if args.starts_with(&["compute", "disks", "describe"]) {
            r#"{"id":"boot-id","type":"pd-balanced","sizeGb":"32"}"#.into()
        } else if args.starts_with(&["disk", "show"]) {
            serde_json::json!({"id":args[3],"uniqueId":"boot-id","diskSizeGB":32,"sku":{"name":"Premium_LRS"}}).to_string()
        } else if program == "gcloud" {
            if args.contains(&"--format=value(id)") {
                "123456789".into()
            } else {
                r#"{"id":"123456789","networkInterfaces":[{"accessConfigs":[{"natIP":"192.0.2.2"}]}]}"#.into()
            }
        } else if args.starts_with(&["group", "show"]) {
            "region".into()
        } else if args.starts_with(&["resource", "show"]) {
            return Err(CloudError::CommandFailed {
                program: "az".into(),
                args: args.join(" "),
                stderr: "ResourceNotFound".into(),
                code: Some(3),
            });
        } else if args.starts_with(&["rest"]) {
            "{}".into()
        } else if args.starts_with(&["deployment", "group", "show"]) {
            serde_json::json!({"properties":{"provisioningState":"Succeeded","outputs":{"resource":{"value":vm}}}}).to_string()
        } else if args.starts_with(&["deployment", "operation"]) {
            serde_json::json!([{"properties":{"targetResource":{"id":vm["id"]},"provisioningOperation":"Create","provisioningState":"Succeeded","response":{"content":vm}}}]).to_string()
        } else if args.starts_with(&["vm", "show"]) {
            if args.contains(&"--query") {
                "a1c08226-18b8-4d0e-b15a-917adfe51ed0".into()
            } else {
                r#"{"vmId":"a1c08226-18b8-4d0e-b15a-917adfe51ed0","storageProfile":{"osDisk":{"managedDisk":{"id":"/subscriptions/subscription/resourceGroups/group/providers/Microsoft.Compute/disks/boot"}}}}"#.into()
            }
        } else if args.starts_with(&["vm", "list-ip-addresses"]) {
            "192.0.2.3".into()
        } else {
            return Err(error("simulated disk attachment failure"));
        };
        Ok(crate::CommandOutput {
            status: 0,
            stdout,
            stderr: String::new(),
        })
    }
    async fn run_stream(
        &self,
        _: &str,
        _: &[&str],
        _: bool,
    ) -> Result<crate::CommandOutput, CloudError> {
        unreachable!()
    }
}

#[tokio::test]
async fn gcp_creation_and_azure_attachment_failure_keep_the_vm_reference() {
    for platform in [PlatformKind::Gcp, PlatformKind::Azure] {
        let (dir, mut state, _) = fixture();
        state.platform = platform;
        state.resources = Default::default();
        if platform == PlatformKind::Gcp {
            state.resources.gcp = Some(Default::default());
        } else {
            state.resources.azure = Some(crate::AzureResources {
                resource_group: Some("group".into()),
                ..Default::default()
            });
        }
        state.save(dir.path()).unwrap();
        let runner = DeploymentRunner {
            runner: &OtherCloudCreation,
            data_dir: dir.path(),
            target: "target",
            instance: "vm",
        };
        if platform == PlatformKind::Gcp {
            crate::gcp::instance::create_instance(
                "project",
                "zone",
                "created-vm",
                "n2d-standard-2",
                "image",
                crate::CcType::SevSnp,
                &[],
                &[],
                None,
                None,
                None,
                &runner,
            )
            .await
            .unwrap();
            let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
            assert_eq!(
                saved.resources.gcp.unwrap().instance.as_deref(),
                Some("created-vm")
            );
            assert!(saved.provisioning_complete);
        } else {
            crate::azure::instance::create_instance(
                "subscription",
                "group",
                "created-vm",
                "Standard_DC2as_v5",
                "image",
                crate::CcType::SevSnp,
                "nsg",
                &[],
                None,
                None,
                &[],
                None,
                &runner,
            )
            .await
            .unwrap();
            assert!(crate::azure::instance::attach_disk(
                "subscription",
                "group",
                "created-vm",
                "disk",
                0,
                &runner
            )
            .await
            .is_err());
            let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
            assert_eq!(
                saved.resources.azure.unwrap().instance.as_deref(),
                Some("created-vm")
            );
            assert!(!saved.provisioning_complete);
        }
    }
}

#[async_trait::async_trait]
impl crate::CommandRunner for FailedAwsWait {
    async fn run_capture(
        &self,
        _: &str,
        args: &[&str],
    ) -> Result<crate::CommandOutput, CloudError> {
        if args.contains(&"run-instances") {
            Ok(crate::CommandOutput {
                status: 0,
                stdout: r#"{"Instances":[{"InstanceId":"i-created"}]}"#.into(),
                stderr: String::new(),
            })
        } else {
            Err(error("simulated interruption while waiting for boot"))
        }
    }
    async fn run_stream(
        &self,
        _: &str,
        _: &[&str],
        _: bool,
    ) -> Result<crate::CommandOutput, CloudError> {
        unreachable!()
    }
}

#[tokio::test]
async fn aws_creation_is_saved_even_when_boot_wait_fails() {
    let (dir, _, _) = fixture();
    let runner = DeploymentRunner {
        runner: &FailedAwsWait,
        data_dir: dir.path(),
        target: "target",
        instance: "vm",
    };
    assert!(crate::aws::instance::create_instance(
        "region",
        "vm",
        "m6a.large",
        "ami",
        "sg",
        "subnet",
        &[],
        &[],
        None,
        None,
        None,
        &runner
    )
    .await
    .is_err());
    let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
    assert_eq!(
        saved.resources.aws.unwrap().instance.as_deref(),
        Some("i-created")
    );
    assert!(!saved.provisioning_complete);
}

#[tokio::test]
async fn reused_cloud_vm_name_does_not_pass_resume_identity_check() {
    for platform in [PlatformKind::Gcp, PlatformKind::Azure] {
        let (_, mut state, _) = fixture();
        state.platform = platform;
        state.resources = Default::default();
        let expected = if platform == PlatformKind::Gcp {
            state.resources.gcp = Some(crate::GcpResources {
                instance: Some("vm".into()),
                ..Default::default()
            });
            "123456789"
        } else {
            state.resources.azure = Some(crate::AzureResources {
                instance: Some("vm".into()),
                resource_group: Some("group".into()),
                ..Default::default()
            });
            "a1c08226-18b8-4d0e-b15a-917adfe51ed0"
        };
        state.cloud_instance_id = Some(expected.into());
        verify_instance_identity(&state, &OtherCloudCreation)
            .await
            .unwrap();
        state.cloud_instance_id = Some("previous-vm-id".into());
        assert!(verify_instance_identity(&state, &OtherCloudCreation)
            .await
            .unwrap_err()
            .to_string()
            .contains("replaced"));
        state.cloud_instance_id = None;
        assert!(verify_instance_identity(&state, &OtherCloudCreation)
            .await
            .is_err());
    }
}

/// A real HTTPS endpoint lets the test abort the upload after receiving headers.
/// It models acceptance, failure, and delayed registration; it does not stand
/// in for a production portal end-to-end test.
async fn portal(
    record: Initialization,
    tls_fingerprint: String,
) -> (
    u16,
    reqwest::Client,
    Arc<Mutex<serde_json::Value>>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use tokio_rustls::{rustls, TlsAcceptor};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key.into())
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_der(cert.cert.der()).unwrap())
        .build()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let live = Arc::new(Mutex::new(status(&record, "AwaitingInit", false)));
    let requests = Arc::new(AtomicUsize::new(0));
    let (live_server, count) = (live.clone(), requests.clone());
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let live = live_server.clone();
            let count = count.clone();
            let record = record.clone();
            let tls_fingerprint = tls_fingerprint.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = acceptor.accept(socket).await else {
                    return;
                };
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    if headers.len() > 65536 {
                        return;
                    }
                    let Ok(byte) = socket.read_u8().await else {
                        return;
                    };
                    headers.push(byte);
                }
                let headers = String::from_utf8(headers).unwrap();
                let body = if headers.starts_with("GET /init/challenge ") {
                    let bootstrap = record.bootstrap.as_ref().unwrap();
                    serde_json::to_value(crate::init_auth::Challenge {
                        scheme: atakit_init_auth::SCHEME.into(),
                        deployment_id: bootstrap.deployment_id.clone(),
                        key_fingerprint: bootstrap.fingerprint().unwrap(),
                        tls_fingerprint,
                        challenge: "33".repeat(32),
                        expires_in_seconds: 120,
                    })
                    .unwrap()
                } else if headers.starts_with("POST /init ") {
                    count.fetch_add(1, Ordering::SeqCst);
                    assert!(headers
                        .to_ascii_lowercase()
                        .contains(&format!("atakit-transfer-id: {}", record.transfer_id)));
                    *live.lock().unwrap() = status(&record, "Initializing", true);
                    // Keep the body incomplete until the client is interrupted.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    return;
                } else {
                    live.lock().unwrap().clone()
                };
                let body = body.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, client, live, requests, task)
}

#[tokio::test]
async fn disconnected_upload_is_never_reposted_and_late_registration_is_observed() {
    for terminal in ["Failed", "Running"] {
        let (dir, state, mut inputs) = fixture();
        let record = state.initialization.as_ref().unwrap();
        let (port, client, live, requests, server) = portal(record.clone(), "22".repeat(32)).await;
        inputs.config.init_auth = Some(crate::init_auth::ClientAuth {
            key_file: state.init_auth_key_file.as_ref().unwrap().into(),
            workload_id: "11".repeat(32),
            tls_fingerprint: "22".repeat(32),
        });
        inputs.config.submission = Some(Submission::for_state(&state, dir.path()).unwrap());
        let mut posting = Box::pin(crate::init::post_portal_init_with_client(
            &client,
            "localhost",
            port,
            port,
            &inputs.archive_path,
            &inputs.archive_sha256,
            inputs.unmeasured_tar.as_ref(),
            &inputs.config,
            Duration::from_secs(inputs.transfer_timeout),
            Duration::from_secs(inputs.init_timeout),
            &atakit_core::NullReporter,
        ));
        let accepted = async {
            while requests.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! {
            result = &mut posting => panic!("POST completed before interruption: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), accepted) => { result.unwrap(); },
        }
        // Drop the HTTP future as when the CLI exits. Re-open only saved state.
        drop(posting);
        let saved = DeployState::load(dir.path(), "target", "vm").unwrap();
        let record = saved.initialization.as_ref().unwrap();
        let observed = crate::init::read_portal_status(&client, "localhost", port)
            .await
            .unwrap();
        assert_eq!(
            action(record, &"22".repeat(32), &observed).unwrap(),
            ResumeAction::Wait
        );
        assert!(Submission::for_state(&saved, dir.path())
            .unwrap()
            .record_before_send(&inputs.config)
            .is_err());
        // No saved timer changes when a second CLI invocation observes work.
        let reloaded = load_inputs(dir.path(), record).unwrap();
        assert_eq!(
            (reloaded.transfer_timeout, reloaded.init_timeout),
            (300, 900)
        );
        *live.lock().unwrap() = status(record, "Registering", true);
        assert_eq!(
            action(record, &"22".repeat(32), &live.lock().unwrap()).unwrap(),
            ResumeAction::Wait
        );
        *live.lock().unwrap() = status(record, terminal, true);
        let observed = crate::init::read_portal_status(&client, "localhost", port)
            .await
            .unwrap();
        let decision = action(record, &"22".repeat(32), &observed).unwrap();
        if terminal == "Running" {
            assert_eq!(decision, ResumeAction::VerifyComplete);
        } else {
            assert!(matches!(decision, ResumeAction::Failed(_)));
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
    }
}
