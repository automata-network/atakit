//! HTTP-backed workload repository.
//!
//! Talks to the in-house workload registry service whose API is documented in
//! `docs/workload-registry-spec.md`. Identical wire format to the historical
//! `RegistryClient`; this is the same code with the new repository surface
//! bolted on.

use std::path::Path;

use atakit_core::ProgressReporter;

use crate::WorkloadError;

use super::{hex_equal, RepositoryArchiveMeta, RepositoryFilters, UploadContext, WorkloadCoords};

#[derive(Debug, Clone, serde::Deserialize)]
struct ApiError {
    error: String,
    message: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ListResponse {
    workloads: Vec<RepositoryArchiveMeta>,
    #[allow(dead_code)]
    total: u64,
}

/// HTTP client for the workload registry service.
pub struct HttpWorkloadRepository {
    client: reqwest::Client,
    base_url: String,
}

impl HttpWorkloadRepository {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Health check the repository service.
    pub async fn health(&self) -> Result<(), WorkloadError> {
        let url = format!("{}/v1/health", self.base_url);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| WorkloadError::RepositoryRequest {
                    reason: e.to_string(),
                })?;
        if !resp.status().is_success() {
            return Err(WorkloadError::Repository {
                message: format!("health check failed: HTTP {}", resp.status()),
            });
        }
        Ok(())
    }

    pub async fn resolve(
        &self,
        workload_id: &str,
    ) -> Result<Option<(WorkloadCoords, RepositoryArchiveMeta)>, WorkloadError> {
        let Some(meta) = self.get_meta_by_id(workload_id).await? else {
            return Ok(None);
        };
        let coords = WorkloadCoords {
            workload_id: meta.workload_id.clone(),
            name: meta.name.clone(),
            version: meta.version.clone(),
        };
        Ok(Some((coords, meta)))
    }

    pub async fn get_meta(
        &self,
        coords: &WorkloadCoords,
    ) -> Result<Option<RepositoryArchiveMeta>, WorkloadError> {
        self.get_meta_by_id(&coords.workload_id).await
    }

    async fn get_meta_by_id(
        &self,
        workload_id: &str,
    ) -> Result<Option<RepositoryArchiveMeta>, WorkloadError> {
        let url = format!("{}/v1/workloads/{}/meta", self.base_url, workload_id);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| WorkloadError::RepositoryRequest {
                    reason: e.to_string(),
                })?;

        let Some(resp) = check_response_optional(resp).await? else {
            return Ok(None);
        };
        let meta: RepositoryArchiveMeta =
            resp.json()
                .await
                .map_err(|e| WorkloadError::RepositoryRequest {
                    reason: format!("failed to parse metadata response: {e}"),
                })?;

        // Trust-but-verify: a repository must return metadata for the
        // exact workload ID we asked for. A server that returns a
        // different ID (whether through a bug or an intentional
        // redirect attack) could otherwise cause the caller to pull a
        // different workload than requested and still pass every
        // downstream identity check, because we'd thread the server's
        // lying ID through `WorkloadCoords` and compare the downloaded
        // archive against it.
        if !hex_equal(&meta.workload_id, workload_id) {
            return Err(WorkloadError::Repository {
                message: format!(
                    "repository {} returned metadata for {} but we asked for {}",
                    self.base_url, meta.workload_id, workload_id
                ),
            });
        }

        Ok(Some(meta))
    }

    pub async fn download_to_file(
        &self,
        coords: &WorkloadCoords,
        dest: &Path,
        progress: &dyn ProgressReporter,
    ) -> Result<u64, WorkloadError> {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;

        let url = format!("{}/v1/workloads/{}", self.base_url, coords.workload_id);
        let resp =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| WorkloadError::RepositoryRequest {
                    reason: e.to_string(),
                })?;
        let resp = check_response(resp).await?;

        // Use Content-Length when present so the bar shows ETA. 0 means
        // "unknown" to indicatif (it falls back to a spinner).
        let total = resp.content_length().unwrap_or(0);
        let label = format!("{}-{}.atawl", coords.name, coords.version);
        let handle = progress.create(&label, total);

        let mut file =
            tokio::fs::File::create(dest)
                .await
                .map_err(|e| WorkloadError::WriteFile {
                    path: dest.to_path_buf(),
                    source: e,
                })?;

        let mut size: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| WorkloadError::RepositoryRequest {
                reason: format!("failed to read download stream: {e}"),
            })?;
            file.write_all(&chunk)
                .await
                .map_err(|e| WorkloadError::WriteFile {
                    path: dest.to_path_buf(),
                    source: e,
                })?;
            size += chunk.len() as u64;
            handle.inc(chunk.len() as u64);
        }

        handle.finish();
        Ok(size)
    }

    pub async fn list(
        &self,
        filters: &RepositoryFilters,
    ) -> Result<Vec<RepositoryArchiveMeta>, WorkloadError> {
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
            .map_err(|e| WorkloadError::RepositoryRequest {
                reason: e.to_string(),
            })?;
        let resp = check_response(resp).await?;

        let body: ListResponse =
            resp.json()
                .await
                .map_err(|e| WorkloadError::RepositoryRequest {
                    reason: format!("failed to parse list response: {e}"),
                })?;
        Ok(body.workloads)
    }

    pub async fn upload(
        &self,
        ctx: &UploadContext<'_>,
    ) -> Result<RepositoryArchiveMeta, WorkloadError> {
        let file =
            tokio::fs::File::open(ctx.archive_path)
                .await
                .map_err(|e| WorkloadError::ReadFile {
                    path: ctx.archive_path.to_path_buf(),
                    source: e,
                })?;

        let url = format!("{}/v1/workloads/{}", self.base_url, ctx.coords.workload_id);
        let resp = self
            .client
            .put(&url)
            .header("content-type", "application/octet-stream")
            .body(reqwest::Body::from(file))
            .send()
            .await
            .map_err(|e| WorkloadError::RepositoryRequest {
                reason: e.to_string(),
            })?;
        let resp = check_response(resp).await?;

        resp.json()
            .await
            .map_err(|e| WorkloadError::RepositoryRequest {
                reason: format!("failed to parse upload response: {e}"),
            })
    }
}

async fn check_response(resp: reqwest::Response) -> Result<reqwest::Response, WorkloadError> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
        return Err(WorkloadError::Repository {
            message: format!("{}: {}", api_err.error, api_err.message),
        });
    }
    Err(WorkloadError::Repository {
        message: format!("HTTP {status}: {body}"),
    })
}

/// Same as [`check_response`] but treats HTTP 404 as a clean negative
/// (`Ok(None)`). Used by lookup endpoints where "not found in this
/// repository" is a legitimate non-error state during discovery.
async fn check_response_optional(
    resp: reqwest::Response,
) -> Result<Option<reqwest::Response>, WorkloadError> {
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    check_response(resp).await.map(Some)
}
