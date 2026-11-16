//! Removal of tracked cloud images. Never removes VMs or shared upload storage.
use crate::{
    cloud_images::{CloudImage, CloudImages},
    CloudError, CloudProviderConfig, CommandRunner, DeployState, DeployStatus, PlatformKind,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImageRemoval {
    Aws {
        region: String,
        images: Vec<AwsImage>,
    },
    Gcp {
        project: String,
        name: String,
    },
    Azure {
        subscription: String,
        resource_group: String,
        gallery: String,
        definition: String,
        version: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsImage {
    pub id: String,
    pub snapshots: Vec<String>,
}
fn invalid(message: impl Into<String>) -> CloudError {
    CloudError::State {
        message: message.into(),
    }
}
fn required(value: &Option<String>, name: &str) -> Result<String, CloudError> {
    value
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| invalid(format!("image removal requires {name}")))
}

/// Unlike the display-oriented deployment listing, never skip unreadable state.
pub fn ensure_unused(
    data_dir: &Path,
    image_ref: &str,
    provider: &str,
    record: &CloudImage,
    config: &CloudProviderConfig,
) -> Result<(), CloudError> {
    let base = data_dir.join("cloud/deployments");
    if !base.exists() {
        return Ok(());
    }
    for target in std::fs::read_dir(base)? {
        let target = target?;
        if !target.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(target.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(instance) = name.to_str().and_then(|s| s.strip_suffix(".state.json")) else {
                continue;
            };
            let target_name = target.file_name().to_string_lossy().into_owned();
            let state = DeployState::load(data_dir, &target_name, instance)?;
            if matches!(state.status, DeployStatus::Destroyed) {
                continue;
            }
            let physical_match = match record.platform {
                PlatformKind::Aws => state.resources.aws.as_ref().is_some_and(|r| {
                    r.region == config.region && r.ami.as_deref() == Some(&record.cloud_name)
                }),
                PlatformKind::Gcp => state.resources.gcp.as_ref().is_some_and(|r| {
                    Some(&r.project) == config.project.as_ref()
                        && r.image.as_deref() == Some(&record.cloud_name)
                }),
                PlatformKind::Azure => state.resources.azure.as_ref().is_some_and(|r| {
                    Some(&r.subscription) == config.subscription.as_ref()
                        && r.gallery_rg == record.gallery_rg
                        && r.gallery == record.gallery
                        && r.image_definition.as_deref() == Some(&record.cloud_name)
                        && r.image_version == record.image_version
                }),
                PlatformKind::Qemu => false,
            };
            if physical_match || (state.provider_name == provider && state.image_ref == image_ref) {
                return Err(invalid(format!("image is used by deployment '{target_name}/{instance}'; remove that deployment first")));
            }
        }
    }
    Ok(())
}

pub async fn prepare(
    record: &CloudImage,
    config: &CloudProviderConfig,
    runner: &dyn CommandRunner,
) -> Result<ImageRemoval, CloudError> {
    if record.platform != config.platform {
        return Err(invalid(
            "tracked image platform differs from provider configuration",
        ));
    }
    if let Some(plan) = &record.removal {
        let same_scope = match plan {
            ImageRemoval::Aws { region, .. } => {
                config.platform == PlatformKind::Aws && *region == config.region
            }
            ImageRemoval::Gcp { project, .. } => {
                config.platform == PlatformKind::Gcp && Some(project) == config.project.as_ref()
            }
            ImageRemoval::Azure { subscription, .. } => {
                config.platform == PlatformKind::Azure
                    && Some(subscription) == config.subscription.as_ref()
            }
        };
        if !same_scope {
            return Err(invalid("provider configuration differs from the saved image removal; restore its original scope before retrying"));
        }
        return Ok(plan.clone());
    }
    if record.cloud_name.is_empty() {
        return Err(invalid("tracked cloud image name is empty"));
    }
    Ok(match record.platform {
        PlatformKind::Aws => {
            let out = runner
                .run_capture(
                    "aws",
                    &[
                        "ec2",
                        "describe-images",
                        "--region",
                        &config.region,
                        "--owners",
                        "self",
                        "--filters",
                        &format!("Name=name,Values={}", record.cloud_name),
                        "--output",
                        "json",
                    ],
                )
                .await?;
            let value: serde_json::Value = serde_json::from_str(&out.stdout)?;
            let images = value
                .get("Images")
                .and_then(|v| v.as_array())
                .ok_or_else(|| invalid("AWS image response is missing Images"))?;
            if images.len() > 1 {
                return Err(invalid(
                    "multiple AWS images match the tracked name; refusing ambiguous removal",
                ));
            }
            let mut targets = Vec::new();
            for image in images {
                if image["Name"].as_str() != Some(&record.cloud_name) {
                    return Err(invalid("AWS image name does not match the tracked image"));
                }
                let id = image["ImageId"]
                    .as_str()
                    .filter(|s| s.starts_with("ami-"))
                    .ok_or_else(|| invalid("AWS image response is missing its AMI ID"))?
                    .to_owned();
                let mappings = image["BlockDeviceMappings"].as_array().ok_or_else(|| {
                    invalid("AWS image response is missing block device mappings")
                })?;
                let mut snapshots = Vec::new();
                for mapping in mappings {
                    if let Some(ebs) = mapping.get("Ebs") {
                        let id = ebs["SnapshotId"]
                            .as_str()
                            .filter(|s| s.starts_with("snap-"))
                            .ok_or_else(|| invalid("AWS image mapping is missing its snapshot ID"))?
                            .to_owned();
                        if !snapshots.contains(&id) {
                            snapshots.push(id);
                        }
                    }
                }
                targets.push(AwsImage { id, snapshots });
            }
            ImageRemoval::Aws {
                region: config.region.clone(),
                images: targets,
            }
        }
        PlatformKind::Gcp => ImageRemoval::Gcp {
            project: required(&config.project, "GCP project")?,
            name: record.cloud_name.clone(),
        },
        PlatformKind::Azure => ImageRemoval::Azure {
            subscription: required(&config.subscription, "Azure subscription")?,
            resource_group: required(&record.gallery_rg, "gallery resource group")?,
            gallery: required(&record.gallery, "gallery")?,
            definition: record.cloud_name.clone(),
            version: required(&record.image_version, "image version")?,
        },
        PlatformKind::Qemu => {
            return Err(invalid(
                "cloud image rm is not supported for qemu; use atakit image rm for local images",
            ))
        }
    })
}

async fn aws_delete(
    runner: &dyn CommandRunner,
    args: &[&str],
    absent_code: &str,
) -> Result<(), CloudError> {
    match runner.run_capture("aws", args).await {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. }) if stderr.contains(absent_code) => Ok(()),
        Err(e) => Err(e),
    }
}
impl std::fmt::Display for ImageRemoval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws { region, images } => {
                writeln!(f, "  AWS region: {region}")?;
                if images.is_empty() { writeln!(f, "  Image already absent; remove local upload record")?; }
                for image in images {
                    writeln!(f, "  Deregister AMI {}", image.id)?;
                    for snapshot in &image.snapshots { writeln!(f, "  Delete backing snapshot {snapshot}")?; }
                }
                Ok(())
            }
            Self::Gcp { project, name } => writeln!(f, "  Delete GCP image {project}/{name}"),
            Self::Azure { subscription, resource_group, gallery, definition, version } => writeln!(f, "  Delete Azure image version {subscription}/{resource_group}/{gallery}/{definition}/{version}"),
        }
    }
}

impl ImageRemoval {
    pub async fn execute(&self, runner: &dyn CommandRunner) -> Result<(), CloudError> {
        match self {
            Self::Aws { region, images } => {
                let mut failures = Vec::new();
                for image in images {
                    if let Err(e) = aws_delete(
                        runner,
                        &[
                            "ec2",
                            "deregister-image",
                            "--region",
                            region,
                            "--image-id",
                            &image.id,
                        ],
                        "InvalidAMIID.NotFound",
                    )
                    .await
                    {
                        failures.push(format!(
                            "AMI {}: {e}; backing snapshots retained: {}",
                            image.id,
                            image.snapshots.join(", ")
                        ));
                        continue;
                    }
                    for snapshot in &image.snapshots {
                        if let Err(e) = aws_delete(
                            runner,
                            &[
                                "ec2",
                                "delete-snapshot",
                                "--region",
                                region,
                                "--snapshot-id",
                                snapshot,
                            ],
                            "InvalidSnapshot.NotFound",
                        )
                        .await
                        {
                            failures.push(format!("snapshot {snapshot}: {e}"));
                        }
                    }
                }
                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(CloudError::DestroyFailed {
                        resource: "AWS image resources".into(),
                        message: failures.join("; "),
                    })
                }
            }
            Self::Gcp { project, name } => {
                crate::gcp::image::delete_image(project, name, runner).await
            }
            Self::Azure {
                subscription,
                resource_group,
                gallery,
                definition,
                version,
            } => {
                crate::azure::image::delete_image_version(
                    subscription,
                    resource_group,
                    gallery,
                    definition,
                    version,
                    runner,
                )
                .await
            }
        }
    }
}

/// Save exact targets before the first destructive call; forget tracking only
/// after every deletion succeeds. Rerunning resumes the same targets.
pub async fn remove(
    data_dir: &Path,
    image_ref: &str,
    provider: &str,
    plan: ImageRemoval,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let mut images = CloudImages::load(data_dir)?;
    let mut record = images
        .get(image_ref, provider)
        .cloned()
        .ok_or_else(|| invalid("image upload record disappeared before removal"))?;
    record.removal = Some(plan.clone());
    images.record(image_ref, provider, record);
    images.save(data_dir)?;
    plan.execute(runner).await?;
    let mut images = CloudImages::load(data_dir)?;
    images.remove(image_ref, provider);
    images.save(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandOutput;
    use std::{collections::VecDeque, sync::Mutex};
    struct Runner {
        outputs: Mutex<VecDeque<Result<String, CloudError>>>,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl Runner {
        fn new(outputs: Vec<Result<&str, CloudError>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().map(|r| r.map(str::to_owned)).collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }
    #[async_trait::async_trait]
    impl CommandRunner for Runner {
        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            self.calls.lock().unwrap().push(
                std::iter::once(program)
                    .chain(args.iter().copied())
                    .map(str::to_owned)
                    .collect(),
            );
            let stdout = self
                .outputs
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected cloud command")?;
            Ok(CommandOutput {
                status: 0,
                stdout,
                stderr: String::new(),
            })
        }
        async fn run_stream(
            &self,
            program: &str,
            args: &[&str],
            _: bool,
        ) -> Result<CommandOutput, CloudError> {
            self.run_capture(program, args).await
        }
    }
    fn failed(message: &str) -> CloudError {
        CloudError::CommandFailed {
            program: "aws".into(),
            args: String::new(),
            stderr: message.into(),
            code: Some(1),
        }
    }
    fn config(platform: PlatformKind) -> CloudProviderConfig {
        CloudProviderConfig {
            platform,
            region: "region".into(),
            project: Some("project".into()),
            subscription: Some("subscription".into()),
            uefi: None,
        }
    }
    fn record(platform: PlatformKind) -> CloudImage {
        CloudImage {
            platform,
            cloud_name: "image".into(),
            bucket: Some("keep-bucket".into()),
            gallery_rg: Some("gallery-rg".into()),
            gallery: Some("gallery".into()),
            image_version: Some("1.0.0".into()),
            cc_types: vec![crate::CcType::SevSnp],
            uploaded_at: chrono::Utc::now(),
            removal: None,
        }
    }
    const AWS: &str = r#"{"Images":[{"Name":"image","ImageId":"ami-test","BlockDeviceMappings":[{"Ebs":{"SnapshotId":"snap-test"}}]}]}"#;

    #[tokio::test]
    async fn aws_partial_failure_survives_reload_and_retries_exact_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut images = CloudImages::default();
        images.record("img:v1", "aws", record(PlatformKind::Aws));
        images.record("img:v1", "other", record(PlatformKind::Gcp));
        images.save(dir.path()).unwrap();
        let runner = Runner::new(vec![
            Ok(AWS),
            Ok("{}"),
            Err(failed("UnauthorizedOperation")),
        ]);
        let plan = prepare(
            images.get("img:v1", "aws").unwrap(),
            &config(PlatformKind::Aws),
            &runner,
        )
        .await
        .unwrap();
        assert!(remove(dir.path(), "img:v1", "aws", plan, &runner)
            .await
            .is_err());
        let saved = CloudImages::load(dir.path()).unwrap();
        assert!(saved.ensure_not_removing("img:v1", "aws").is_err());
        assert!(saved.ensure_not_removing("img:v1", "other").is_ok());
        let retry = Runner::new(vec![Err(failed("InvalidAMIID.NotFound")), Ok("{}")]);
        let plan = prepare(
            saved.get("img:v1", "aws").unwrap(),
            &config(PlatformKind::Aws),
            &retry,
        )
        .await
        .unwrap();
        assert!(
            retry.calls.lock().unwrap().is_empty(),
            "must not re-resolve a deleted AMI by name"
        );
        remove(dir.path(), "img:v1", "aws", plan, &retry)
            .await
            .unwrap();
        let saved = CloudImages::load(dir.path()).unwrap();
        assert!(saved.get("img:v1", "aws").is_none());
        assert!(saved.get("img:v1", "other").is_some());
        assert_eq!(
            retry.calls.lock().unwrap()[1],
            [
                "aws",
                "ec2",
                "delete-snapshot",
                "--region",
                "region",
                "--snapshot-id",
                "snap-test"
            ]
        );
    }

    #[tokio::test]
    async fn retry_rejects_changed_provider_scope() {
        let runner = Runner::new(vec![]);
        let mut saved = record(PlatformKind::Aws);
        saved.removal = Some(ImageRemoval::Aws {
            region: "original-region".into(),
            images: vec![],
        });
        assert!(prepare(&saved, &config(PlatformKind::Aws), &runner)
            .await
            .unwrap_err()
            .to_string()
            .contains("original scope"));
    }

    #[test]
    fn same_image_upload_and_removal_cannot_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let lock = CloudImages::lock(dir.path(), "img:v1", "aws").unwrap();
        assert!(CloudImages::lock(dir.path(), "img:v1", "aws").is_err());
        assert!(CloudImages::lock(dir.path(), "img:v2", "aws").is_ok());
        drop(lock);
        assert!(CloudImages::lock(dir.path(), "img:v1", "aws").is_ok());
    }

    #[tokio::test]
    async fn aws_missing_image_does_not_delete_anything() {
        let runner = Runner::new(vec![Ok(r#"{"Images":[]}"#)]);
        prepare(
            &record(PlatformKind::Aws),
            &config(PlatformKind::Aws),
            &runner,
        )
        .await
        .unwrap()
        .execute(&runner)
        .await
        .unwrap();
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn aws_rejects_wrong_name_or_missing_snapshot_identity() {
        for value in [
            AWS.replace("\"Name\":\"image\"", "\"Name\":\"other\""),
            AWS.replace("\"SnapshotId\":\"snap-test\"", "\"VolumeSize\":10"),
            "{}".into(),
        ] {
            let runner = Runner::new(vec![Ok(&value)]);
            assert!(prepare(
                &record(PlatformKind::Aws),
                &config(PlatformKind::Aws),
                &runner
            )
            .await
            .is_err());
            assert_eq!(runner.calls.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn gcp_deletes_only_selected_project_image() {
        let runner = Runner::new(vec![Ok("")]);
        prepare(
            &record(PlatformKind::Gcp),
            &config(PlatformKind::Gcp),
            &runner,
        )
        .await
        .unwrap()
        .execute(&runner)
        .await
        .unwrap();
        assert_eq!(
            runner.calls.lock().unwrap()[0],
            [
                "gcloud",
                "compute",
                "images",
                "delete",
                "image",
                "--project",
                "project",
                "--quiet"
            ]
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn azure_deletes_only_recorded_version_and_waits() {
        let runner = Runner::new(vec![Ok(""), Err(failed("ResourceNotFound"))]);
        prepare(
            &record(PlatformKind::Azure),
            &config(PlatformKind::Azure),
            &runner,
        )
        .await
        .unwrap()
        .execute(&runner)
        .await
        .unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            [
                "az",
                "sig",
                "image-version",
                "delete",
                "--subscription",
                "subscription",
                "--resource-group",
                "gallery-rg",
                "--gallery-name",
                "gallery",
                "--gallery-image-definition",
                "image",
                "--gallery-image-version",
                "1.0.0"
            ]
        );
        assert_eq!(calls.len(), 2);
        assert!(calls[1].contains(&"show".to_string()));
    }

    #[tokio::test]
    async fn rejects_incomplete_or_mismatched_configuration_without_cloud_calls() {
        let runner = Runner::new(vec![]);
        let mut r = record(PlatformKind::Azure);
        r.image_version = None;
        assert!(prepare(&r, &config(PlatformKind::Azure), &runner)
            .await
            .is_err());
        assert!(prepare(&r, &config(PlatformKind::Aws), &runner)
            .await
            .is_err());
        assert!(prepare(
            &record(PlatformKind::Qemu),
            &config(PlatformKind::Qemu),
            &runner
        )
        .await
        .is_err());
    }

    #[test]
    fn unreadable_deployment_state_blocks_removal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cloud/deployments/target")).unwrap();
        std::fs::write(
            dir.path().join("cloud/deployments/target/vm.state.json"),
            "not json",
        )
        .unwrap();
        assert!(ensure_unused(
            dir.path(),
            "img:v1",
            "aws",
            &record(PlatformKind::Aws),
            &config(PlatformKind::Aws)
        )
        .is_err());
    }

    #[test]
    fn deployment_blocks_removal_even_through_provider_alias() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = DeployState::new(crate::NewDeployParams {
            instance_name: "vm".into(),
            workload_name: "workload".into(),
            workload_publisher: "publisher".into(),
            workload_version: "v1".into(),
            target_name: "target".into(),
            provider_name: "alias".into(),
            platform: PlatformKind::Aws,
            image_ref: "another-reference".into(),
            base_image_ref: None,
            archive_path: "workload.atawl".into(),
            archive_hash: "hash".into(),
            init_env: Default::default(),
            portal_ports: Default::default(),
            total_steps: 1,
        });
        state.resources.aws = Some(crate::AwsResources {
            region: "region".into(),
            ami: Some("image".into()),
            ..Default::default()
        });
        state.save(dir.path()).unwrap();
        assert!(ensure_unused(
            dir.path(),
            "img:v1",
            "aws",
            &record(PlatformKind::Aws),
            &config(PlatformKind::Aws)
        )
        .unwrap_err()
        .to_string()
        .contains("target/vm"));
        state.status = DeployStatus::Destroyed;
        state.save(dir.path()).unwrap();
        ensure_unused(
            dir.path(),
            "img:v1",
            "aws",
            &record(PlatformKind::Aws),
            &config(PlatformKind::Aws),
        )
        .unwrap();
    }
}
