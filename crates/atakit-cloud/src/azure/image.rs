use crate::error::CloudError;
use crate::exec::CommandRunner;

/// Ensure the resource group exists.
pub async fn ensure_resource_group(
    name: &str,
    region: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &["group", "create", "--name", name, "--location", region],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create resource group: {e}"),
        })?;
    Ok(())
}

/// Ensure the storage account exists.
pub async fn ensure_storage_account(
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

/// Upload a VHD file to blob storage as a page blob. Returns the blob URL.
pub async fn upload_vhd(
    account: &str,
    container: &str,
    filename: &str,
    source_path: &str,
    runner: &dyn CommandRunner,
    verbose: bool,
) -> Result<String, CloudError> {
    runner
        .run_stream(
            "az",
            &[
                "storage",
                "blob",
                "upload",
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

    let blob_url = format!(
        "https://{account}.blob.core.windows.net/{container}/{filename}"
    );
    Ok(blob_url)
}

/// Ensure the Compute Gallery exists.
pub async fn ensure_gallery(
    rg: &str,
    gallery: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &["sig", "show", "--resource-group", rg, "--gallery-name", gallery],
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
            &["sig", "create", "--resource-group", rg, "--gallery-name", gallery],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create gallery: {e}"),
        })?;
    Ok(())
}

/// Ensure the image definition exists with CVM support.
pub async fn ensure_image_definition(
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
pub async fn create_image_version(
    rg: &str,
    gallery: &str,
    definition: &str,
    version: &str,
    storage_account_id: &str,
    blob_url: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "sig",
                "image-version",
                "create",
                "--resource-group",
                rg,
                "--gallery-name",
                gallery,
                "--gallery-image-definition",
                definition,
                "--gallery-image-version",
                version,
                "--os-vhd-storage-account",
                storage_account_id,
                "--os-vhd-uri",
                blob_url,
                "--query",
                "id",
                "-o",
                "tsv",
            ],
        )
        .await
        .map_err(|e| CloudError::ImageUploadFailed {
            message: format!("failed to create image version: {e}"),
        })?;

    Ok(output.stdout.trim().to_string())
}

/// Get the resource ID of an existing image version.
pub async fn get_image_version_id(
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
        Ok(_) => Ok(()),
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

/// Get the resource ID of a storage account.
pub async fn get_storage_account_id(
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
