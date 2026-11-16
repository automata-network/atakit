//! Durable client state for an initialization request. No server timer lives here.
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    init::{InitConfig, RemoteAtawlSource},
    CloudError, DeployState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitializationPhase {
    Prepared,
    MayHaveBeenSent,
    VerifiedComplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Initialization {
    pub transfer_id: String,
    pub phase: InitializationPhase,
    pub bootstrap: Option<crate::init_auth::Bootstrap>,
    pub inputs_sha256: String,
    pub tls_sha256: Option<String>,
    pub submitted_config_sha256: Option<String>,
}

/// Kept in a private file because URLs and unmeasured data can contain secrets.
/// Provisioned private keys are removed; the CLI restores them from named keys
/// and checks the original configuration hash before a first submission.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitializationInputs {
    pub config: InitConfig,
    pub config_sha256: String,
    pub archive_path: String,
    pub archive_sha256: [u8; 32],
    pub remote_source: Option<RemoteAtawlSource>,
    pub unmeasured_tar: Option<atakit_core::unmeasured_data::Archive>,
    pub transfer_timeout: u64,
    pub init_timeout: u64,
    pub pcr_policy_path: Option<PathBuf>,
    pub pcr_policy_sha256: Option<String>,
    pub verification: serde_json::Value,
}

impl InitializationInputs {
    pub fn remove_private_keys(&mut self) {
        self.config_sha256 = config_hash(&self.config);
        self.config.owner_key.private_key = None;
        self.config.gas_wallet.private_key = None;
        if let Some(key) = &mut self.config.prover_credential {
            key.private_key = None;
        }
    }

    pub fn validate_restored_config(&self) -> Result<(), CloudError> {
        if config_hash(&self.config) != self.config_sha256 {
            return Err(error(
                "initialization configuration or named keys changed; original inputs are required",
            ));
        }
        if let Some(path) = &self.pcr_policy_path {
            if Some(atakit_init_auth::hash(&fs::read(path)?)) != self.pcr_policy_sha256 {
                return Err(error("original PCR collection policy changed"));
            }
        }
        Ok(())
    }
}

pub fn config_hash(config: &InitConfig) -> String {
    atakit_init_auth::hash(
        crate::init::build_portal_config_json(config)
            .to_string()
            .as_bytes(),
    )
}

pub fn prepare(
    state: &mut DeployState,
    data_dir: &Path,
    mut inputs: InitializationInputs,
) -> Result<(), CloudError> {
    if state.initialization.is_some() {
        return Err(error(
            "initialization is already recorded; use atakit cloud resume",
        ));
    }
    let bootstrap = state
        .init_auth_key_file
        .as_ref()
        .map(|path| {
            crate::init_auth::load(Path::new(path))
                .map(|(_, bootstrap)| bootstrap)
                .map_err(|message| error(&message))
        })
        .transpose()?;
    inputs.remove_private_keys();
    let mut record = Initialization {
        transfer_id: uuid::Uuid::new_v4().to_string(),
        phase: InitializationPhase::Prepared,
        bootstrap,
        inputs_sha256: String::new(),
        tls_sha256: None,
        submitted_config_sha256: None,
    };
    if let Some(archive) = &inputs.unmeasured_tar {
        inputs.unmeasured_tar = Some(
            archive
                .save(&archive_path(data_dir, &record)?)
                .map_err(|message| error(&message))?,
        );
    }
    let bytes = serde_json::to_vec(&inputs)?;
    record.inputs_sha256 = atakit_init_auth::hash(&bytes);
    write_private_file(&inputs_path(data_dir, &record)?, &bytes)?;
    state.initialization = Some(record);
    state.save(data_dir)
}

pub fn load_inputs(
    data_dir: &Path,
    record: &Initialization,
) -> Result<InitializationInputs, CloudError> {
    let bytes = fs::read(inputs_path(data_dir, record)?)?;
    if atakit_init_auth::hash(&bytes) != record.inputs_sha256 {
        return Err(error("saved initialization inputs changed"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn remove_inputs(data_dir: &Path, record: &Initialization) -> Result<(), CloudError> {
    // Also reclaim an archive left after a completed-record crash boundary.
    match fs::remove_file(archive_path(data_dir, record)?) {
        Ok(()) => File::open(inputs_path(data_dir, record)?.parent().unwrap())?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    for phase in [
        InitializationPhase::Prepared,
        InitializationPhase::VerifiedComplete,
    ] {
        let mut record = record.clone();
        record.phase = phase;
        let path = inputs_path(data_dir, &record)?;
        match fs::remove_file(&path) {
            Ok(()) => File::open(path.parent().unwrap())?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Write the small completion record before removing either the initialization
/// credential or private transfer inputs. Each crash boundary remains readable.
pub fn record_complete(
    state: &mut DeployState,
    data_dir: &Path,
    host: &str,
) -> Result<(), CloudError> {
    let previous = state
        .initialization
        .as_ref()
        .ok_or_else(|| error("initialization record is missing"))?
        .clone();
    let mut inputs = load_inputs(data_dir, &previous)?;
    let prepared_archive = inputs.unmeasured_tar.take();
    inputs.remote_source = None;
    let bytes = serde_json::to_vec(&inputs)?;
    let mut completed = previous.clone();
    completed.phase = InitializationPhase::VerifiedComplete;
    completed.inputs_sha256 = atakit_init_auth::hash(&bytes);
    write_private_file(&inputs_path(data_dir, &completed)?, &bytes)?;
    state.initialization = Some(completed);
    state.apply_resource_updates(&crate::ResourceUpdates {
        external_ip: Some(host.into()),
        ..Default::default()
    });
    state.set_status(crate::DeployStatus::Deployed { ip: host.into() }, data_dir)?;
    if let Some(archive) = prepared_archive {
        archive
            .remove_saved(&archive_path(data_dir, &previous)?)
            .map_err(|message| error(&message))?;
    }
    let mut original = previous;
    original.phase = InitializationPhase::Prepared;
    let path = inputs_path(data_dir, &original)?;
    match fs::remove_file(&path) {
        Ok(()) => File::open(path.parent().unwrap())?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn archive_path(data_dir: &Path, record: &Initialization) -> Result<PathBuf, CloudError> {
    let mut prepared = record.clone();
    prepared.phase = InitializationPhase::Prepared;
    Ok(inputs_path(data_dir, &prepared)?.with_extension("unmeasured.tar.gz"))
}

fn inputs_path(data_dir: &Path, record: &Initialization) -> Result<PathBuf, CloudError> {
    let id = uuid::Uuid::parse_str(&record.transfer_id)
        .map_err(|_| error("invalid saved transfer ID"))?;
    let suffix = if record.phase == InitializationPhase::VerifiedComplete {
        ".complete"
    } else {
        ""
    };
    Ok(data_dir
        .join("cloud/init-inputs")
        .join(format!("{id}{suffix}.json")))
}

#[derive(Debug, Clone)]
pub struct Submission {
    pub data_dir: PathBuf,
    pub target: String,
    pub instance: String,
    pub transfer_id: String,
}

impl Submission {
    /// Check cloud identities immediately before the first initialization send.
    /// The durable request still contains exactly the permissions saved at deploy.
    pub async fn verify_disks(
        &self,
        config: &InitConfig,
        runner: &dyn crate::CommandRunner,
    ) -> Result<(), CloudError> {
        let state = DeployState::load(&self.data_dir, &self.target, &self.instance)?;
        if state.automatic_disk_setup.is_empty() && state.created_boot_disk.is_none() {
            return Ok(());
        }
        if state
            .initialization
            .as_ref()
            .is_none_or(|r| r.phase != InitializationPhase::Prepared)
        {
            return Err(error("initialization may already have been sent; refusing to renew disk creation permission"));
        }
        if config.local_ssd != state.disk_configuration.local_ssd()? {
            return Err(error(
                "Local SSD binding differs from saved deployment settings",
            ));
        }
        for name in &state.automatic_disk_setup {
            if config
                .local_ssd
                .as_ref()
                .is_some_and(|local| local.disk == *name)
            {
                if config.disk_setup.get(name).map(String::as_str) != Some("create") {
                    return Err(error("Local SSD creation permission is missing"));
                }
                crate::disk_inventory::verify_local_ssd(&state, runner).await?;
                continue;
            }
            if !state
                .created_disks
                .get(name)
                .is_some_and(|record| record.creation_verified)
                || config.disk_setup.get(name).map(String::as_str) != Some("create")
            {
                return Err(error(&format!(
                    "disk {name:?} has no recorded fresh creation and one-time permission"
                )));
            }
        }
        crate::disk_inventory::verify_configuration(&state, runner).await?;
        Ok(())
    }

    pub fn for_state(state: &DeployState, data_dir: &Path) -> Result<Self, CloudError> {
        let record = state
            .initialization
            .as_ref()
            .ok_or_else(|| error("initialization inputs are not recorded"))?;
        Ok(Self {
            data_dir: data_dir.into(),
            target: state.target_name.clone(),
            instance: state.instance_name.clone(),
            transfer_id: record.transfer_id.clone(),
        })
    }

    /// Called immediately before `.send()`. A crash after this durable write
    /// is uncertain, even if no bytes actually reached the portal.
    pub fn record_before_send(&self, config: &InitConfig) -> Result<(), CloudError> {
        let mut state = DeployState::load(&self.data_dir, &self.target, &self.instance)?;
        let inputs = load_inputs(
            &self.data_dir,
            state
                .initialization
                .as_ref()
                .ok_or_else(|| error("initialization record is missing"))?,
        )?;
        let mut restored = inputs.clone();
        restored.config = config.clone();
        // Registry collection policy is resolved against fresh attestation.
        restored.config.pcr_policy = inputs.config.pcr_policy;
        restored.validate_restored_config()?;
        let record = state
            .initialization
            .as_mut()
            .ok_or_else(|| error("initialization record is missing"))?;
        if record.transfer_id != self.transfer_id || record.phase != InitializationPhase::Prepared {
            return Err(error(
                "initialization may already have been sent; refusing another POST /init",
            ));
        }
        if let Some(expected) = &record.bootstrap {
            let auth = config
                .init_auth
                .as_ref()
                .ok_or_else(|| error("saved initialization requires authentication"))?;
            let (_, actual) =
                crate::init_auth::load(&auth.key_file).map_err(|message| error(&message))?;
            if &actual != expected {
                return Err(error(
                    "initialization credential belongs to a different deployment",
                ));
            }
        }
        record.phase = InitializationPhase::MayHaveBeenSent;
        record.tls_sha256 = config
            .init_auth
            .as_ref()
            .map(|auth| auth.tls_fingerprint.clone());
        record.submitted_config_sha256 = Some(config_hash(config));
        state.save(&self.data_dir)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResumeAction {
    Submit,
    Wait,
    VerifyComplete,
    DiskUnlock,
    Failed(String),
}

/// Call only with status read through freshly attested, pinned portal TLS.
pub fn action(
    record: &Initialization,
    tls_sha256: &str,
    status: &serde_json::Value,
) -> Result<ResumeAction, CloudError> {
    let bootstrap = record
        .bootstrap
        .as_ref()
        .ok_or_else(|| error("resume requires the saved authenticated initialization identity"))?;
    let fingerprint = bootstrap.fingerprint().map_err(error)?;
    let auth = &status["init_auth"];
    if auth["deployment_id"].as_str() != Some(&bootstrap.deployment_id)
        || auth["key_fingerprint"].as_str() != Some(&fingerprint)
    {
        return Err(error(
            "portal initialization identity differs from the saved deployment",
        ));
    }
    if record
        .tls_sha256
        .as_deref()
        .is_some_and(|saved| saved != tls_sha256)
    {
        return Err(error("portal TLS certificate changed; automatic resume across a portal or VM restart is not supported"));
    }
    let accepted = auth["accepted_transfer_id"]
        .as_str()
        .filter(|s| !s.is_empty());
    if accepted.is_some_and(|id| id != record.transfer_id) {
        return Err(error("portal accepted a different initialization request"));
    }
    let state = status["state"]
        .as_str()
        .ok_or_else(|| error("portal status omitted state"))?;
    if matches!(state, "Failed" | "CleanHalt") {
        return Ok(ResumeAction::Failed(format!(
            "portal reached {state}: {}",
            status["detail"]
        )));
    }
    if record.phase == InitializationPhase::Prepared
        && accepted.is_none()
        && state == "AwaitingInit"
    {
        return Ok(ResumeAction::Submit);
    }
    if accepted != Some(record.transfer_id.as_str())
        || record.phase == InitializationPhase::Prepared
    {
        return Err(error(
            "initialization outcome is unknown; the saved request was not sent again",
        ));
    }
    if state == "Running" {
        return Ok(ResumeAction::VerifyComplete);
    }
    if state == "AwaitingDiskUnlock"
        || status["disks"]
            .as_object()
            .is_some_and(|disks| disks.values().any(|d| d["state"] == "awaiting_passphrase"))
    {
        return Ok(ResumeAction::DiskUnlock);
    }
    match state {
        "Initializing" | "InitializingWorkload" | "Registering" => Ok(ResumeAction::Wait),
        _ => Err(error("portal accepted the request but its current state does not establish progress; initialization was not sent again")),
    }
}

/// Locks live outside deployment directories and are never unlinked. The OS
/// releases the lock on process exit, including SIGKILL.
pub struct DeploymentLock(File);
impl DeploymentLock {
    pub fn acquire(data_dir: &Path, target: &str, instance: &str) -> Result<Self, CloudError> {
        let dir = data_dir.join("cloud/locks");
        fs::create_dir_all(&dir)?;
        let name = atakit_init_auth::hash(&serde_json::to_vec(&(target, instance))?);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join(format!("{name}.lock")))?;
        // SAFETY: file owns a valid fd; flock does not retain a Rust pointer.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(error(
                "another command is changing this deployment; wait for it to finish",
            ));
        }
        Ok(Self(file))
    }
}
impl Drop for DeploymentLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CloudError> {
    let dir = path
        .parent()
        .ok_or_else(|| error("state file has no parent directory"))?;
    fs::create_dir_all(dir)?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| CloudError::Io(e.error))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn error(message: &str) -> CloudError {
    CloudError::State {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;

pub struct DeploymentRunner<'a> {
    pub runner: &'a dyn crate::CommandRunner,
    pub data_dir: &'a Path,
    pub target: &'a str,
    pub instance: &'a str,
}

#[async_trait::async_trait]
impl crate::CommandRunner for DeploymentRunner<'_> {
    async fn azure_api(
        &self,
        method: &str,
        url: &str,
        body: Option<&serde_json::Value>,
        create_only: bool,
    ) -> Result<serde_json::Value, CloudError> {
        self.runner.azure_api(method, url, body, create_only).await
    }
    async fn create_resource(
        &self,
        key: &str,
        request: &crate::provisioning::CreateRequest,
    ) -> Result<serde_json::Value, CloudError> {
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        crate::provisioning::ensure_before_init(&state)?;
        let creation = state
            .provisioning
            .creations
            .entry(key.into())
            .or_insert_with(|| crate::provisioning::Creation {
                outcome: Default::default(),
                request: request.clone(),
                token: uuid::Uuid::new_v4().to_string(),
                sent: false,
                receipt: None,
                result: None,
            });
        if &creation.request != request {
            return Err(error(
                "cloud creation request changed; refusing to modify or recreate resources",
            ));
        }
        if let Some(result) = &creation.result {
            return Ok(result.clone());
        }
        if creation.outcome == crate::provisioning::CreationOutcome::Rejected {
            creation.sent = false;
            creation.receipt = None;
            creation.token = uuid::Uuid::new_v4().to_string();
        }
        let recovering = creation.sent;
        creation.sent = true;
        creation.outcome = crate::provisioning::CreationOutcome::Unknown;
        let creation = creation.clone();
        state.provisioning_complete = false;
        state.save(self.data_dir)?;
        let result = crate::provisioning::execute(self, key, &creation, recovering).await;
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        let saved = state
            .provisioning
            .creations
            .get_mut(key)
            .ok_or_else(|| error("creation record disappeared"))?;
        let result = match result {
            Ok(value) => value,
            Err(e) => {
                if matches!(e, CloudError::CreationRejected { .. }) && saved.receipt.is_none() {
                    saved.outcome = crate::provisioning::CreationOutcome::Rejected;
                    state.save(self.data_dir)?;
                } else if matches!(e, CloudError::CreationFailed { .. }) {
                    saved.outcome = crate::provisioning::CreationOutcome::Failed;
                    state.save(self.data_dir)?;
                }
                return Err(e);
            }
        };
        saved.result = Some(result.clone());
        saved.outcome = crate::provisioning::CreationOutcome::Succeeded;
        state.save(self.data_dir)?;
        Ok(result)
    }
    async fn creation_recorded(&self, key: &str) -> Result<bool, CloudError> {
        Ok(
            DeployState::load(self.data_dir, self.target, self.instance)?
                .provisioning
                .creations
                .contains_key(key),
        )
    }
    async fn recorded_creation(
        &self,
        key: &str,
    ) -> Result<Option<crate::provisioning::Creation>, CloudError> {
        Ok(
            DeployState::load(self.data_dir, self.target, self.instance)?
                .provisioning
                .creations
                .get(key)
                .cloned(),
        )
    }
    async fn record_creation_receipt(
        &self,
        key: &str,
        receipt: &serde_json::Value,
    ) -> Result<(), CloudError> {
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        let creation = state
            .provisioning
            .creations
            .get_mut(key)
            .ok_or_else(|| error("creation request was not saved"))?;
        creation.receipt = Some(receipt.clone());
        creation.outcome = crate::provisioning::CreationOutcome::Accepted;
        state.save(self.data_dir)
    }
    async fn gcp_api(
        &self,
        method: &str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, CloudError> {
        self.runner.gcp_api(method, url, body).await
    }
    async fn record_boot_disk(
        &self,
        disk: &crate::disk_inventory::ObservedDisk,
    ) -> Result<(), CloudError> {
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        if state
            .created_boot_disk
            .as_ref()
            .is_some_and(|old| old.id != disk.id)
        {
            return Err(error("boot disk identity changed during creation"));
        }
        state.created_boot_disk = Some(disk.clone());
        state.save(self.data_dir)?;
        // A settings mismatch must stop provisioning without losing the
        // original disk identity needed by cleanup.
        crate::disk_inventory::validate_boot(&state, disk)
    }
    async fn record_azure_resource(
        &self,
        resource: &crate::provisioning_cleanup::AzureResource,
    ) -> Result<(), CloudError> {
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        let azure = state
            .resources
            .azure
            .as_mut()
            .ok_or_else(|| error("missing Azure state"))?;
        if azure
            .owned_resources
            .get(&resource.id)
            .is_some_and(|old| old.identity != resource.identity)
        {
            return Err(error("Azure resource identity changed"));
        }
        azure
            .owned_resources
            .insert(resource.id.clone(), resource.clone());
        state.save(self.data_dir)
    }
    async fn recorded_disk(
        &self,
        name: &str,
    ) -> Result<Option<crate::disk_inventory::CreatedDisk>, CloudError> {
        let state = DeployState::load(self.data_dir, self.target, self.instance)?;
        Ok(state.created_disks.get(name).cloned())
    }
    async fn record_created_disk(
        &self,
        disk: &crate::disk_inventory::CreatedDisk,
    ) -> Result<(), CloudError> {
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        let name = &disk.specification.device_name;
        if state
            .created_disks
            .get(name)
            .is_some_and(|old| old.observed.id != disk.observed.id)
        {
            return Err(error("disk identity changed during creation"));
        }
        state.created_disks.insert(name.clone(), disk.clone());
        if state.platform == crate::PlatformKind::Gcp
            || state.platform == crate::PlatformKind::Azure
        {
            state.apply_resource_updates(&crate::ResourceUpdates {
                disks: vec![disk.specification.name.clone()],
                ..Default::default()
            });
        }
        if state.platform == crate::PlatformKind::Aws {
            let resources = state
                .resources
                .aws
                .as_mut()
                .ok_or_else(|| error("missing AWS resources"))?;
            if !resources.disks.contains(&disk.observed.id) {
                resources.disks.push(disk.observed.id.clone());
            }
        }
        state.save(self.data_dir)
    }
    async fn record_created_instance(
        &self,
        instance: &str,
        ip: &str,
        complete: bool,
        identity: Option<&str>,
    ) -> Result<(), CloudError> {
        let mut state = DeployState::load(self.data_dir, self.target, self.instance)?;
        state.apply_resource_updates(&crate::ResourceUpdates {
            instance: Some(instance.into()),
            external_ip: (!ip.is_empty()).then(|| ip.into()),
            ..Default::default()
        });
        state.provisioning_complete = false;
        state.save(self.data_dir)?;
        let identity = match identity {
            Some(id) => id.to_owned(),
            None => read_instance_identity(&state, self.runner).await?,
        };
        if state
            .cloud_instance_id
            .as_ref()
            .is_some_and(|saved| saved != &identity)
        {
            return Err(error("cloud VM changed during provisioning"));
        }
        state.cloud_instance_id = Some(identity);
        state.provisioning_complete = complete && !state.provisioning.started;
        state.save(self.data_dir)
    }
    async fn run_capture(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<crate::CommandOutput, CloudError> {
        self.runner.run_capture(program, args).await
    }
    async fn run_stream(
        &self,
        program: &str,
        args: &[&str],
        verbose: bool,
    ) -> Result<crate::CommandOutput, CloudError> {
        self.runner.run_stream(program, args, verbose).await
    }
}

pub async fn verify_instance_identity(
    state: &DeployState,
    runner: &dyn crate::CommandRunner,
) -> Result<(), CloudError> {
    let expected = state.cloud_instance_id.as_ref().ok_or_else(|| {
        error("cloud VM identity was not recorded; resume cannot identify this VM")
    })?;
    let actual = read_instance_identity(state, runner).await?;
    if expected != &actual {
        return Err(error(
            "cloud VM was replaced; its unique instance ID differs from the saved deployment",
        ));
    }
    Ok(())
}

async fn read_instance_identity(
    state: &DeployState,
    runner: &dyn crate::CommandRunner,
) -> Result<String, CloudError> {
    let output = match state.platform {
        crate::PlatformKind::Aws => {
            // The AWS resource reference already is the immutable instance ID.
            // get_instance_ip subsequently queries EC2 using this exact ID.
            return state
                .resources
                .aws
                .as_ref()
                .and_then(|aws| aws.instance.clone())
                .ok_or_else(|| error("AWS instance ID is missing"));
        }
        crate::PlatformKind::Gcp => {
            let gcp = state
                .resources
                .gcp
                .as_ref()
                .ok_or_else(|| error("GCP resources are missing"))?;
            let instance = gcp
                .instance
                .as_deref()
                .ok_or_else(|| error("GCP instance reference is missing"))?;
            runner
                .run_capture(
                    "gcloud",
                    &[
                        "compute",
                        "instances",
                        "describe",
                        instance,
                        "--project",
                        &gcp.project,
                        "--zone",
                        &gcp.zone,
                        "--format=value(id)",
                    ],
                )
                .await?
        }
        crate::PlatformKind::Azure => {
            let azure = state
                .resources
                .azure
                .as_ref()
                .ok_or_else(|| error("Azure resources are missing"))?;
            let instance = azure
                .instance
                .as_deref()
                .ok_or_else(|| error("Azure instance reference is missing"))?;
            let group = azure
                .resource_group
                .as_deref()
                .ok_or_else(|| error("Azure resource group is missing"))?;
            runner
                .run_capture(
                    "az",
                    &[
                        "vm",
                        "show",
                        "--subscription",
                        &azure.subscription,
                        "--resource-group",
                        group,
                        "--name",
                        instance,
                        "--query",
                        "vmId",
                        "--output",
                        "tsv",
                    ],
                )
                .await?
        }
        crate::PlatformKind::Qemu => return Err(error("cloud resume does not support QEMU")),
    };
    let identity = output.stdout.trim();
    if identity.is_empty() {
        return Err(error("cloud did not return a unique VM ID"));
    }
    Ok(identity.into())
}
