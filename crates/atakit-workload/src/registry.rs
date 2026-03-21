use serde::{Deserialize, Serialize};

use crate::WorkloadError;

/// Metadata returned by the registry API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryMeta {
    pub workload_id: String,
    pub name: String,
    pub version: String,
    pub owner: String,
    pub pcr23: String,
    pub archive_size: u64,
    pub archive_hash: String,
    pub uploaded_at: String,
}

/// Paginated list response.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryListResponse {
    pub workloads: Vec<RegistryMeta>,
    pub total: u64,
}

/// Registry API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryApiError {
    pub error: String,
    pub message: String,
}

/// Filters for listing workloads from a registry.
#[derive(Debug, Default)]
pub struct RegistryFilters {
    pub owner: Option<String>,
    pub name: Option<String>,
    pub name_prefix: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// HTTP client for workload registry API.
pub struct RegistryClient {
    client: reqwest::Client,
    base_url: String,
}

impl RegistryClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Upload a workload archive to the registry.
    pub async fn upload(
        &self,
        workload_id: &str,
        data: Vec<u8>,
    ) -> Result<RegistryMeta, WorkloadError> {
        let url = format!("{}/v1/workloads/{}/archive", self.base_url, workload_id);
        let resp = self
            .client
            .put(&url)
            .header("content-type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(|e| WorkloadError::RegistryRequest {
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Ok(api_err) = serde_json::from_str::<RegistryApiError>(&body) {
                return Err(WorkloadError::Registry {
                    message: format!("{}: {}", api_err.error, api_err.message),
                });
            }
            return Err(WorkloadError::Registry {
                message: format!("HTTP {status}: {body}"),
            });
        }

        resp.json().await.map_err(|e| WorkloadError::RegistryRequest {
            reason: format!("failed to parse upload response: {e}"),
        })
    }

    /// Download a workload archive from the registry.
    /// Returns (bytes, filename from Content-Disposition or default).
    pub async fn download(
        &self,
        workload_id: &str,
    ) -> Result<(Vec<u8>, String), WorkloadError> {
        let url = format!("{}/v1/workloads/{}/archive", self.base_url, workload_id);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WorkloadError::RegistryRequest {
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Ok(api_err) = serde_json::from_str::<RegistryApiError>(&body) {
                return Err(WorkloadError::Registry {
                    message: format!("{}: {}", api_err.error, api_err.message),
                });
            }
            return Err(WorkloadError::Registry {
                message: format!("HTTP {status}: {body}"),
            });
        }

        // Try to extract filename from Content-Disposition header
        let filename = resp
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split("filename=")
                    .nth(1)
                    .map(|f| f.trim_matches('"').to_string())
            })
            .unwrap_or_else(|| format!("{workload_id}.atawl"));

        let bytes = resp.bytes().await.map_err(|e| WorkloadError::RegistryRequest {
            reason: format!("failed to read download body: {e}"),
        })?;

        Ok((bytes.to_vec(), filename))
    }

    /// Get metadata for a workload from the registry.
    pub async fn get_meta(
        &self,
        workload_id: &str,
    ) -> Result<RegistryMeta, WorkloadError> {
        let url = format!("{}/v1/workloads/{}", self.base_url, workload_id);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WorkloadError::RegistryRequest {
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Ok(api_err) = serde_json::from_str::<RegistryApiError>(&body) {
                return Err(WorkloadError::Registry {
                    message: format!("{}: {}", api_err.error, api_err.message),
                });
            }
            return Err(WorkloadError::Registry {
                message: format!("HTTP {status}: {body}"),
            });
        }

        resp.json().await.map_err(|e| WorkloadError::RegistryRequest {
            reason: format!("failed to parse metadata response: {e}"),
        })
    }

    /// List workloads from the registry with optional filters.
    pub async fn list(
        &self,
        filters: &RegistryFilters,
    ) -> Result<RegistryListResponse, WorkloadError> {
        let mut url = format!("{}/v1/workloads", self.base_url);
        let mut params = Vec::new();
        if let Some(ref owner) = filters.owner {
            params.push(format!("owner={owner}"));
        }
        if let Some(ref name) = filters.name {
            params.push(format!("name={name}"));
        }
        if let Some(ref prefix) = filters.name_prefix {
            params.push(format!("namePrefix={prefix}"));
        }
        if let Some(limit) = filters.limit {
            params.push(format!("limit={limit}"));
        }
        if let Some(offset) = filters.offset {
            params.push(format!("offset={offset}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WorkloadError::RegistryRequest {
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Ok(api_err) = serde_json::from_str::<RegistryApiError>(&body) {
                return Err(WorkloadError::Registry {
                    message: format!("{}: {}", api_err.error, api_err.message),
                });
            }
            return Err(WorkloadError::Registry {
                message: format!("HTTP {status}: {body}"),
            });
        }

        resp.json().await.map_err(|e| WorkloadError::RegistryRequest {
            reason: format!("failed to parse list response: {e}"),
        })
    }

    /// Health check the registry.
    pub async fn health(&self) -> Result<(), WorkloadError> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WorkloadError::RegistryRequest {
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            return Err(WorkloadError::Registry {
                message: format!("health check failed: HTTP {}", resp.status()),
            });
        }

        Ok(())
    }
}
