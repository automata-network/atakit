use crate::error::CloudError;
use crate::exec::CommandRunner;
use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Ensure the resource group exists.
pub async fn ensure_resource_group(
    subscription: &str,
    name: &str,
    region: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &[
                "group",
                "create",
                "--subscription",
                subscription,
                "--name",
                name,
                "--location",
                region,
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create resource group: {e}"),
        })?;
    Ok(())
}

/// Ensure the storage account exists.
pub async fn ensure_storage_account(
    subscription: &str,
    rg: &str,
    name: &str,
    region: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    // Check if it exists first.
    match runner
        .run_capture(
            "az",
            &[
                "storage",
                "account",
                "show",
                "--subscription",
                subscription,
                "--name",
                name,
                "--resource-group",
                rg,
            ],
        )
        .await
    {
        Ok(_) => return Ok(()),
        Err(CloudError::CommandFailed { .. }) => {} // doesn't exist
        Err(e) => return Err(e),
    }

    runner
        .run_capture(
            "az",
            &[
                "storage",
                "account",
                "create",
                "--subscription",
                subscription,
                "--name",
                name,
                "--resource-group",
                rg,
                "--location",
                region,
                "--sku",
                "Standard_LRS",
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create storage account: {e}"),
        })?;
    Ok(())
}

/// Ensure the storage container exists.
pub async fn ensure_storage_container(
    subscription: &str,
    account: &str,
    container: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &[
                "storage",
                "container",
                "create",
                "--subscription",
                subscription,
                "--name",
                container,
                "--account-name",
                account,
                "--auth-mode",
                "login",
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create storage container: {e}"),
        })?;
    Ok(())
}

/// Upload a VHD file to blob storage as a page blob.
///
/// Consumers (like the Shared Image Gallery) read the blob via the plain
/// `https://{account}.blob.core.windows.net/{container}/{name}` URL; the
/// gallery service authenticates through Azure RBAC on the storage account
/// resource passed via `--os-vhd-storage-account`.
pub async fn upload_vhd(
    subscription: &str,
    account: &str,
    container: &str,
    filename: &str,
    source_path: &str,
    runner: &dyn CommandRunner,
    verbose: bool,
) -> Result<(), CloudError> {
    runner
        .run_stream(
            "az",
            &[
                "storage",
                "blob",
                "upload",
                "--subscription",
                subscription,
                "--account-name",
                account,
                "--container-name",
                container,
                "--name",
                filename,
                "--file",
                source_path,
                "--type",
                "page",
                "--auth-mode",
                "login",
                "--overwrite",
            ],
            verbose,
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to upload VHD: {e}"),
        })?;
    Ok(())
}

/// Ensure the Compute Gallery exists.
pub async fn ensure_gallery(
    subscription: &str,
    rg: &str,
    gallery: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "sig",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
            ],
        )
        .await
    {
        Ok(_) => return Ok(()),
        Err(CloudError::CommandFailed { .. }) => {}
        Err(e) => return Err(e),
    }

    runner
        .run_capture(
            "az",
            &[
                "sig",
                "create",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create gallery: {e}"),
        })?;
    Ok(())
}

/// Ensure the image definition exists with CVM support.
pub async fn ensure_image_definition(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-definition",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
            ],
        )
        .await
    {
        Ok(_) => return Ok(()),
        Err(CloudError::CommandFailed { .. }) => {}
        Err(e) => return Err(e),
    }

    runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-definition",
                "create",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
                "--publisher",
                "atakit",
                "--offer",
                "cvm",
                "--sku",
                definition,
                "--os-type",
                "Linux",
                "--os-state",
                "specialized",
                "--hyper-v-generation",
                "V2",
                "--features",
                "SecurityType=ConfidentialVMSupported",
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create image definition: {e}"),
        })?;
    Ok(())
}

/// Create an image version from a VHD blob URL. Returns the image version resource ID.
///
/// Submits the request via `az rest PUT` to the gallery images-version
/// endpoint directly, instead of the `az sig image-version create` CLI
/// wrapper. The wrapper has a long-standing bug (Azure/azure-cli#24624)
/// that silently drops the `source.uri` and `source.storageAccountId`
/// fields from the REST body — the gallery then reports the source blob
/// as "not accessible" because it has no valid source reference at all.
///
/// The direct REST path uses Azure's trusted-services authentication
/// between Compute Gallery and Storage (via the `storageAccountId`
/// reference), so the blob does NOT need public access, a SAS token, or
/// any RBAC grant.
///
/// Blocks until `provisioningState == Succeeded`.
#[allow(clippy::too_many_arguments)]
pub async fn create_image_version(
    subscription: &str,
    region: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    storage_account_id: &str,
    blob_url: &str,
    certs_dir: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let security_profile = load_security_profile(certs_dir)?;
    let mut properties = serde_json::json!({
        "publishingProfile": {
            "targetRegions": [{ "name": region, "regionalReplicaCount": 1 }],
        },
        "storageProfile": {
            "osDiskImage": {
                "hostCaching": "ReadOnly",
                "source": {
                    "storageAccountId": storage_account_id,
                    "uri": blob_url,
                },
            },
        },
    });
    properties["securityProfile"] = security_profile;

    let url = format!(
        "/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Compute\
         /galleries/{gallery}/images/{definition}/versions/{version}?api-version=2024-03-03"
    );
    let body = serde_json::json!({
        "location": region,
        "properties": properties,
    })
    .to_string();

    let output = runner
        .run_capture(
            "az",
            &[
                "rest",
                "--method",
                "PUT",
                "--subscription",
                subscription,
                "--url",
                &url,
                "--body",
                &body,
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to PUT image version: {e}"),
        })?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output.stdout).map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to parse image version response: {e}"),
        })?;
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CloudError::ImageUploadFailed {
            message: "image version response missing 'id' field".to_string(),
        })?
        .to_string();

    // Post-PUT grace: the version resource is sometimes not yet queryable
    // the instant the PUT returns 201.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    wait_for_image_version_succeeded(subscription, rg, gallery, definition, version, runner)
        .await?;

    Ok(id)
}

/// Build the `securityProfile` block for an `az rest` image-version create
/// request. PK / KEK / db / kernel are all required; missing any of them
/// is a hard error. Azure images registered by atakit must carry custom
/// Secure Boot variables — there is no fallback to Azure's default
/// Microsoft KEK/db.
fn load_security_profile(certs_dir: &str) -> Result<serde_json::Value, CloudError> {
    let dir = std::path::Path::new(certs_dir);
    let pk_path = dir.join("PK.crt");
    let kek_path = dir.join("KEK.crt");
    let db_path = dir.join("db.crt");
    let kernel_path = dir.join("kernel.crt");

    let mut missing = Vec::new();
    if !pk_path.exists() {
        missing.push("PK.crt");
    }
    if !kek_path.exists() {
        missing.push("KEK.crt");
    }
    if !db_path.exists() {
        missing.push("db.crt");
    }
    if !kernel_path.exists() {
        missing.push("kernel.crt");
    }
    if !missing.is_empty() {
        return Err(CloudError::ImageUploadFailed {
            message: format!(
                "secure boot certs missing from '{certs_dir}': {} — \
                 Azure images registered by atakit must carry custom \
                 PK/KEK/db. Ensure the base image archive (.atabi) was \
                 imported with its secure_boot_certs/ directory intact.",
                missing.join(", "),
            ),
        });
    }

    let pk = read_cert_b64(&pk_path)?;
    let kek = read_cert_b64(&kek_path)?;
    let db = read_cert_b64(&db_path)?;
    let kernel = read_cert_b64(&kernel_path)?;

    Ok(serde_json::json!({
        "uefiSettings": {
            "signatureTemplateNames": ["NoSignatureTemplate"],
            "additionalSignatures": {
                "pk": { "type": "x509", "value": [pk] },
                "kek": [{ "type": "x509", "value": [kek] }],
                "db": [{ "type": "x509", "value": [db, kernel] }],
            }
        }
    }))
}

fn read_cert_b64(path: &std::path::Path) -> Result<String, CloudError> {
    let bytes = std::fs::read(path).map_err(CloudError::Io)?;
    Ok(STANDARD.encode(bytes))
}

/// Poll an image version's `provisioningState` until `Succeeded` (or fail
/// on `Failed` / timeout). Safe to call against a version that's already
/// `Succeeded` — returns after the first poll. Gallery image versions
/// typically take 2–5 minutes to replicate; we allow up to 15 minutes.
pub async fn wait_for_image_version_succeeded(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    use tokio::time::{sleep, Duration};

    let max_attempts = 90; // 90 × 10s = 15 minutes
    let mut transient = 0;
    let mut last_state: Option<String> = None;
    for _ in 0..max_attempts {
        let output = match runner
            .run_capture(
                "az",
                &[
                    "sig",
                    "image-version",
                    "show",
                    "--subscription",
                    subscription,
                    "--resource-group",
                    rg,
                    "--gallery-name",
                    gallery,
                    "--gallery-image-definition",
                    definition,
                    "--gallery-image-version",
                    version,
                    "--query",
                    "provisioningState",
                    "-o",
                    "tsv",
                ],
            )
            .await
        {
            Ok(o) => {
                transient = 0;
                o
            }
            Err(_) if transient < 5 => {
                transient += 1;
                sleep(Duration::from_secs(10)).await;
                continue;
            }
            Err(e) => return Err(e),
        };

        let state = output.stdout.trim();
        match state {
            "Succeeded" => return Ok(()),
            "Failed" => {
                return Err(CloudError::ImageUploadFailed {
                    message: format!(
                        "image version '{definition}:{version}' is in Failed state — \
                         rerun with --force-image to delete and recreate it"
                    ),
                });
            }
            other => {
                // Log a line the first time we see a given state so the
                // user sees the wait is intentional.
                if last_state.as_deref() != Some(other) {
                    tracing::info!(
                        "waiting for image version '{definition}:{version}' \
                         (provisioningState={other})"
                    );
                    last_state = Some(other.to_string());
                }
                sleep(Duration::from_secs(10)).await;
            }
        }
    }

    Err(CloudError::ImageUploadFailed {
        message: format!(
            "timed out after 15 min waiting for image version \
             '{definition}:{version}' to reach Succeeded \
             (last state: {})",
            last_state.as_deref().unwrap_or("unknown"),
        ),
    })
}

/// Get the resource ID of an existing image version.
pub async fn get_image_version_id(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-version",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
                "--gallery-image-version",
                version,
                "--query",
                "id",
                "-o",
                "tsv",
            ],
        )
        .await?;

    Ok(output.stdout.trim().to_string())
}

/// Check if an image version exists.
pub async fn check_image_version_exists(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    runner: &dyn CommandRunner,
) -> Result<bool, CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-version",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
                "--gallery-image-version",
                version,
            ],
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(CloudError::CommandFailed { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Delete an image version.
pub async fn delete_image_version(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-version",
                "delete",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
                "--gallery-image-version",
                version,
            ],
        )
        .await
    {
        Ok(_) => {
            wait_for_image_version_deleted(subscription, rg, gallery, definition, version, runner)
                .await
        }
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("image version already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("image-version/{definition}:{version}"),
            message: e.to_string(),
        }),
    }
}

async fn wait_for_image_version_deleted(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    use tokio::time::{sleep, Duration};

    let max_attempts = 90; // 90 × 10s = 15 minutes
    for _ in 0..max_attempts {
        match runner
            .run_capture(
                "az",
                &[
                    "sig",
                    "image-version",
                    "show",
                    "--subscription",
                    subscription,
                    "--resource-group",
                    rg,
                    "--gallery-name",
                    gallery,
                    "--gallery-image-definition",
                    definition,
                    "--gallery-image-version",
                    version,
                ],
            )
            .await
        {
            Ok(_) => sleep(Duration::from_secs(10)).await,
            Err(CloudError::CommandFailed { stderr, .. })
                if stderr.contains("not found") || stderr.contains("NotFound") =>
            {
                return Ok(());
            }
            Err(e) => {
                return Err(CloudError::DestroyFailed {
                    resource: format!("image-version/{definition}:{version}"),
                    message: e.to_string(),
                });
            }
        }
    }

    Err(CloudError::DestroyFailed {
        resource: format!("image-version/{definition}:{version}"),
        message: "timed out waiting for image version deletion".to_string(),
    })
}

pub async fn delete_image_definition(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-definition",
                "delete",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
            ],
        )
        .await
    {
        Ok(_) => {
            wait_for_image_definition_deleted(subscription, rg, gallery, definition, runner).await
        }
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("image definition already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("image-definition/{definition}"),
            message: e.to_string(),
        }),
    }
}

async fn wait_for_image_definition_deleted(
    subscription: &str,
    rg: &str,
    gallery: &str,
    definition: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    use tokio::time::{sleep, Duration};

    let max_attempts = 90; // 90 × 10s = 15 minutes
    for _ in 0..max_attempts {
        match runner
            .run_capture(
                "az",
                &[
                    "sig",
                    "image-definition",
                    "show",
                    "--subscription",
                    subscription,
                    "--resource-group",
                    rg,
                    "--gallery-name",
                    gallery,
                    "--gallery-image-definition",
                    definition,
                ],
            )
            .await
        {
            Ok(_) => sleep(Duration::from_secs(10)).await,
            Err(CloudError::CommandFailed { stderr, .. })
                if stderr.contains("not found") || stderr.contains("NotFound") =>
            {
                return Ok(());
            }
            Err(e) => {
                return Err(CloudError::DestroyFailed {
                    resource: format!("image-definition/{definition}"),
                    message: e.to_string(),
                });
            }
        }
    }

    Err(CloudError::DestroyFailed {
        resource: format!("image-definition/{definition}"),
        message: "timed out waiting for image definition deletion".to_string(),
    })
}

/// Get the resource ID of a storage account.
pub async fn get_storage_account_id(
    subscription: &str,
    account: &str,
    rg: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "storage",
                "account",
                "show",
                "--subscription",
                subscription,
                "--name",
                account,
                "--resource-group",
                rg,
                "--query",
                "id",
                "-o",
                "tsv",
            ],
        )
        .await?;

    Ok(output.stdout.trim().to_string())
}

/// Delete a storage account.
pub async fn delete_storage_account(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "storage",
                "account",
                "delete",
                "--subscription",
                subscription,
                "--name",
                name,
                "--resource-group",
                rg,
                "--yes",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("storage account '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("storage-account/{name}"),
            message: e.to_string(),
        }),
    }
}
