use std::time::Duration;

use crate::error::CloudError;

/// Agent environment configuration for the /init POST.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub rpc_url: String,
    pub session_registry: String,
    pub owner_private_key: String,
    pub relay_private_key: String,
    pub expire_offset: u64,
}

/// Poll the CVM agent health endpoint with exponential backoff.
pub async fn wait_for_agent(ip: &str, timeout_secs: u64) -> Result<(), CloudError> {
    let url = format!("https://{ip}:1024/platform-measurements");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut interval = Duration::from_secs(2);
    let max_interval = Duration::from_secs(30);

    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("CVM agent is ready at {ip}:1024");
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!("agent not ready yet (status {})", resp.status());
            }
            Err(e) => {
                tracing::debug!("agent not reachable: {e}");
            }
        }

        if tokio::time::Instant::now() + interval > deadline {
            return Err(CloudError::AgentTimeout {
                address: format!("{ip}:1024"),
                timeout_secs,
            });
        }

        tokio::time::sleep(interval).await;
        interval = (interval * 2).min(max_interval);
    }
}

/// POST /init to the CVM agent with workload archive and configuration.
///
/// Always uses HTTPS. The CVM agent serves a self-signed certificate,
/// so we always accept invalid certs for the init request.
pub async fn post_init(
    ip: &str,
    archive_path: &str,
    unmeasured_tar: Option<&[u8]>,
    agent_config: &AgentConfig,
) -> Result<(), CloudError> {
    let url = format!("https://{ip}:1024/init");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| CloudError::Http {
            message: e.to_string(),
        })?;

    // Read archive file.
    let archive_bytes = tokio::fs::read(archive_path).await.map_err(|e| {
        CloudError::IoPath {
            path: archive_path.into(),
            source: e,
        }
    })?;

    // Build agent env JSON (nested under "agent_env" key as the CVM agent expects).
    let config_json = serde_json::json!({
        "agent_env": {
            "rpc_url": agent_config.rpc_url,
            "session_registry": agent_config.session_registry,
            "owner_private_key": agent_config.owner_private_key,
            "relay_private_key": agent_config.relay_private_key,
            "expire_offset": agent_config.expire_offset,
        }
    });

    // Build multipart form.
    let mut form = reqwest::multipart::Form::new()
        .part(
            "atawl",
            reqwest::multipart::Part::bytes(archive_bytes)
                .file_name("archive.atawl")
                .mime_str("application/octet-stream")
                .map_err(|e| CloudError::Http {
                    message: e.to_string(),
                })?,
        )
        .part(
            "config",
            reqwest::multipart::Part::bytes(config_json.to_string().into_bytes())
                .file_name("config.json")
                .mime_str("application/json")
                .map_err(|e| CloudError::Http {
                    message: e.to_string(),
                })?,
        );

    if let Some(unmeasured) = unmeasured_tar {
        form = form.part(
            "unmeasured",
            reqwest::multipart::Part::bytes(unmeasured.to_vec())
                .file_name("unmeasured.tar.gz")
                .mime_str("application/octet-stream")
                .map_err(|e| CloudError::Http {
                    message: e.to_string(),
                })?,
        );
    }

    let resp = client
        .post(&url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| CloudError::AgentInitFailed {
            message: format!("request failed: {e}"),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(CloudError::AgentInitFailed {
            message: format!("agent returned {status}: {body}"),
        });
    }

    tracing::info!("workload initialized on CVM at {ip}");
    Ok(())
}
