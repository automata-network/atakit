use super::packager;

use std::fs;

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use tracing::info;
use workload_compose::{ImageKind, extract_image_name_tag};

use crate::{
    commands::deploy::config::{build_from_deployment, to_json},
    env::Env,
    types::{AtakitConfig, DeploymentDef, WorkloadDef},
};

/// How to handle Docker images in the workload package.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ImageMode {
    /// Build and bundle images into the package (default)
    #[default]
    Bundle,
    /// Skip building; images will be pulled at runtime
    Pull,
}

/// Build a workload package from docker-compose definitions.
#[derive(Args)]
pub struct BuildWorkload {
    /// Names of deployments to build (builds all if omitted)
    pub deployments: Vec<String>,

    /// How to handle Docker images
    #[arg(long, value_enum, default_value_t = ImageMode::Bundle)]
    pub image_mode: ImageMode,
}

impl BuildWorkload {
    pub fn run(self, env: &Env) -> Result<()> {
        let atakit_config = env.config()?;
        let project_dir = env.config_dir()?.to_path_buf();
        std::fs::create_dir_all(&env.project_artifact_dir)?;

        // Resolve which deployments to build.
        let deployments = self.resolve_deployments(&atakit_config)?;

        for (deploy_name, deploy_def) in deployments {
            // Find the workload referenced by this deployment.
            let wl_def = self.find_workload(&atakit_config, deploy_def)?;

            // Create output directory: ata_artifacts/{workload_name}/
            let output_dir = env.project_artifact_dir.join(&wl_def.name);
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("Failed to create {}", output_dir.display()))?;

            // Analyze the workload's docker-compose.
            let analysis = workload_compose::analyze(&project_dir, &wl_def.docker_compose)
                .with_context(|| format!("Failed to analyze workload {:?}", wl_def.name))?;

            info!(
                deployment = %deploy_name,
                workload = %wl_def.name,
                measured = analysis.measured_files.len(),
                additional_data = analysis.additional_data_files.len(),
                images = analysis.summary.images.len(),
                "Compose analysis complete"
            );

            // Validate that all compose images match workload.name:workload.version
            let expected_image = format!("{}:{}", wl_def.name, wl_def.version);
            validate_compose_images(&analysis.summary.images, &expected_image)?;

            let image = deploy_def.image.as_ref().unwrap_or(&wl_def.image);

            // Build workload package: {workload_name}-{version}.tar.gz
            let package_name = format!("{}-{}", wl_def.name, wl_def.version);
            info!(
                deployment = %deploy_name,
                %image,
                "Building package"
            );

            packager::create_package(
                &package_name,
                wl_def,
                &analysis,
                &project_dir,
                &output_dir,
                &atakit_config,
                self.image_mode,
                deploy_def.image.clone(),
            )?;
            info!(output = %format!("ata_artifacts/{}/{}.tar.gz", wl_def.name, package_name), "Package created");

            // Generate deployment configs: {deploy_name}-{platform}-deployment.json
            let project_name = project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("atakit");
            for (platform_name, platform_config) in &deploy_def.platforms {
                let config = build_from_deployment(
                    &deploy_name,
                    deploy_def,
                    wl_def,
                    platform_name,
                    platform_config,
                    &analysis,
                    &atakit_config,
                    project_name,
                )?;
                let filename = format!("{}-{}-deployment.json", deploy_name, platform_name);
                let output_path = output_dir.join(&filename);
                let json = to_json(&config)?;
                fs::write(&output_path, json)
                    .with_context(|| format!("Failed to write {}", output_path.display()))?;
                info!(output = %format!("ata_artifacts/{}/{}", wl_def.name, filename), "Deployment config created");
            }
        }

        info!("Build complete");
        Ok(())
    }

    fn resolve_deployments<'a>(
        &self,
        config: &'a AtakitConfig,
    ) -> Result<Vec<(String, &'a DeploymentDef)>> {
        if self.deployments.is_empty() {
            if config.deployment.is_empty() {
                bail!("No deployments defined in atakit.json");
            }
            return Ok(config
                .deployment
                .iter()
                .map(|(k, v)| (k.clone(), v))
                .collect());
        }

        let mut result = Vec::new();
        for name in &self.deployments {
            match config.deployment.get(name) {
                Some(def) => result.push((name.clone(), def)),
                None => bail!(
                    "Deployment '{}' not found in atakit.json. Available: {}",
                    name,
                    config
                        .deployment
                        .keys()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        Ok(result)
    }

    fn find_workload<'a>(
        &self,
        config: &'a AtakitConfig,
        deploy_def: &DeploymentDef,
    ) -> Result<&'a WorkloadDef> {
        let workload_name = &deploy_def.workload;

        config
            .workloads
            .iter()
            .find(|w| &w.name == workload_name)
            .with_context(|| {
                format!(
                    "Workload '{}' not found in atakit.json. Available: {}",
                    workload_name,
                    config
                        .workloads
                        .iter()
                        .map(|w| w.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}

/// Validate that all docker-compose images match the expected workload name:version.
///
/// Images in docker-compose may include a registry prefix (e.g., `ghcr.io/org/myapp:v1`),
/// but the name:tag portion must match `expected` (e.g., `myapp:v1`).
fn validate_compose_images(
    images: &[workload_compose::ServiceImage],
    expected: &str,
) -> Result<()> {
    let mut errors = Vec::new();

    for img in images {
        let tag = match &img.kind {
            ImageKind::Build { tag } => tag,
            ImageKind::Pull { tag } => tag,
            ImageKind::BuildUntagged => {
                errors.push(format!(
                    "Service '{}': image tag is required (add `image: {}` to the service)",
                    img.service, expected
                ));
                continue;
            }
        };

        let actual = extract_image_name_tag(tag);
        if actual != expected {
            errors.push(format!(
                "Service '{}': image '{}' does not match expected '{}' (extracted: '{}')",
                img.service, tag, expected, actual
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "Docker compose image validation failed:\n  - {}",
            errors.join("\n  - ")
        )
    }
}
