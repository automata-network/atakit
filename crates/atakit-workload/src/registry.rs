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
    ///
    /// Accepts any body type convertible to `reqwest::Body`, including `Vec<u8>`,
    /// `tokio::fs::File`, or a streaming body for large archives.
    pub async fn upload(
        &self,
        workload_id: &str,
        body: impl Into<reqwest::Body>,
    ) -> Result<RegistryMeta, WorkloadError> {
        let url = format!("{}/v1/workloads/{}", self.base_url, workload_id);
        let resp = self
            .client
            .put(&url)
            .header("content-type", "application/octet-stream")
            .body(body)
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

    /// Download a workload archive from the registry, streaming to a file.
    /// Returns the file size.
    pub async fn download_to_file(
        &self,
        workload_id: &str,
        dest: &std::path::Path,
    ) -> Result<u64, WorkloadError> {
        use futures_util::StreamExt;
        use std::io::Write;

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

        let mut file =
            std::fs::File::create(dest).map_err(|e| WorkloadError::WriteFile {
                path: dest.to_path_buf(),
                source: e,
            })?;

        let mut size: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| WorkloadError::RegistryRequest {
                reason: format!("failed to read download stream: {e}"),
            })?;
            file.write_all(&chunk).map_err(|e| WorkloadError::WriteFile {
                path: dest.to_path_buf(),
                source: e,
            })?;
            size += chunk.len() as u64;
        }

        Ok(size)
    }

    /// Get metadata for a workload from the registry.
    pub async fn get_meta(
        &self,
        workload_id: &str,
    ) -> Result<RegistryMeta, WorkloadError> {
        let url = format!("{}/v1/workloads/{}/meta", self.base_url, workload_id);
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
        let url = format!("{}/v1/workloads", self.base_url);
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(ref owner) = filters.owner {
            query.push(("owner", owner.clone()));
        }
        if let Some(ref name) = filters.name {
            query.push(("name", name.clone()));
        }
        if let Some(ref prefix) = filters.name_prefix {
            query.push(("name_prefix", prefix.clone()));
        }
        if let Some(limit) = filters.limit {
            query.push(("limit", limit.to_string()));
        }
        if let Some(offset) = filters.offset {
            query.push(("offset", offset.to_string()));
        }

        let resp = self
            .client
            .get(&url)
            .query(&query)
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
        let url = format!("{}/v1/health", self.base_url);
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
