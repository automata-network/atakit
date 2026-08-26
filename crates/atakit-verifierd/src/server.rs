//! HTTP boundary for peer session verification.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use atakit_attestation::{BindingMode, SessionVerificationFailure, VerifiedSession};
use atakit_attestation_client::{
    prepare_portal_session_tls_verification, prepare_supplied_session_bundle, AttestationClient,
    ChainTrustSource, ChallengeBoundSessionEvidence, ExplicitTrustSource, PackTrustSource,
    PortalSessionVerificationRequest, PortalVerificationError, SessionVerificationMode,
    SuppliedSessionBundleVerificationRequest, TrustProvenance, TrustedWorkloadSessionPolicy,
};
use atakit_cvm_types::AppRef;
use axum::body::{to_bytes, Body};
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header::CONTENT_TYPE, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{LoadedPack, TrustModeConfig, VerifierdConfig};
use crate::destination::{PortalDestinationPolicy, PortalEndpoint, ResolvedPortalEndpoint};

const MAX_VERIFY_REQUEST_BYTES: usize = 16 * 1024;
const MAX_SESSION_BUNDLE_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONCURRENT_VERIFICATIONS: usize = 8;
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(360);
const VERIFIERD_REQUIRED_BINDING: Option<BindingMode> = None;
const SUPPORTED_PLATFORMS: &[&str] = &[
    "gcp-tdx",
    "gcp-sev-snp",
    "azure-tdx",
    "azure-sev-snp",
    "aws-sev-snp",
];

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("connect chain authority: {0}")]
    Chain(#[from] atakit_attestation_client::AttestationClientError),
    #[error("bind {address}: {source}")]
    Bind {
        address: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("serve HTTP: {0}")]
    Serve(std::io::Error),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub portal: PortalRequest,
    pub base_image: String,
    pub workload: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifySessionBundleRequest {
    pub session_evidence: ChallengeBoundSessionEvidence,
    pub expected_challenge: String,
    pub base_image: String,
    pub workload: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionPublicKeyResponse {
    pub type_id: u8,
    pub key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub session_id: String,
    pub session_key_fingerprint: String,
    pub session_public_key: SessionPublicKeyResponse,
    pub workload_id: String,
    pub base_image_id: String,
    pub binding_mode: BindingMode,
    pub binding_chain_id: u64,
    pub binding_registry: String,
    pub attestation_mode: atakit_attestation::SessionAttestationMode,
    pub sources: TrustProvenance,
    pub checks: Vec<atakit_attestation::SessionVerificationCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigResponse {
    pub trust_mode: String,
    pub portal_allowed_ports: Vec<u16>,
    pub portal_allowed_cidrs: Option<Vec<String>>,
    pub packs: Vec<LoadedPack>,
    pub supported_platforms: Vec<String>,
}

#[derive(Clone)]
pub struct Verifierd {
    state: Arc<AppState>,
    listen: std::net::SocketAddr,
}

struct AppState {
    portal_destination_policy: PortalDestinationPolicy,
    verification_slots: Arc<Semaphore>,
    verification_timeout: Duration,
    config: ConfigResponse,
    runner: Arc<dyn VerificationRunner>,
}

#[async_trait]
trait VerificationRunner: Send + Sync {
    async fn verify(
        &self,
        portal: &ResolvedPortalEndpoint,
        base_image: AppRef,
        workload: AppRef,
        permit: OwnedSemaphorePermit,
    ) -> Result<VerifyResponse, ApiError>;

    async fn verify_session_bundle(
        &self,
        session_evidence: ChallengeBoundSessionEvidence,
        expected_challenge: [u8; 32],
        base_image: AppRef,
        workload: AppRef,
        permit: OwnedSemaphorePermit,
    ) -> Result<VerifyResponse, ApiError>;
}

enum RuntimeMode {
    Chain(Box<ChainTrustSource>),
    TrustPack(PackTrustSource),
    Explicit {
        source: Box<ExplicitTrustSource>,
        measurement_policy: Box<atakit_attestation::MeasurementPolicy>,
        base_image: AppRef,
        workload_pcr23_sha256: [u8; 32],
        workload_pcr23_sha384: [u8; 48],
    },
}

struct RuntimeRunner {
    mode: RuntimeMode,
}

impl RuntimeRunner {
    fn session_verification_mode(
        &self,
        base_image: &AppRef,
        workload: &AppRef,
    ) -> Result<SessionVerificationMode, ApiError> {
        match &self.mode {
            RuntimeMode::Chain(source) => Ok(SessionVerificationMode::Chain {
                source: source.as_ref().clone(),
                base_image: base_image.clone(),
                workload: workload.clone(),
            }),
            RuntimeMode::TrustPack(source) => Ok(SessionVerificationMode::Packs {
                source: source.clone(),
                base_image_id: atakit_cvm_encoding::base_image_id(base_image),
                workload: workload.clone(),
            }),
            RuntimeMode::Explicit {
                source,
                measurement_policy,
                base_image: configured_base_image,
                workload_pcr23_sha256,
                workload_pcr23_sha384,
            } => {
                if base_image != configured_base_image {
                    return Err(ApiError::bad_request(format!(
                        "base_image is {base_image}, but VERIFIERD_MEASUREMENTS is for {configured_base_image}"
                    )));
                }
                let workload_policy = TrustedWorkloadSessionPolicy::from_manifest_pcr23(
                    &workload.to_string(),
                    *workload_pcr23_sha256,
                    *workload_pcr23_sha384,
                )
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
                Ok(SessionVerificationMode::Explicit {
                    source: source.as_ref().clone(),
                    measurement_policy: measurement_policy.clone(),
                    workload_policy,
                })
            }
        }
    }
}

impl Verifierd {
    pub async fn from_config(config: VerifierdConfig) -> Result<Self, StartError> {
        let report = config_response(&config);
        let listen = config.listen;
        let portal_destination_policy = config.portal_destination_policy;
        let mode = match config.mode {
            TrustModeConfig::Chain {
                client,
                tdx_dcap_collateral,
            } => {
                let client = AttestationClient::connect(client).await?;
                RuntimeMode::Chain(Box::new(ChainTrustSource::from_client(
                    client,
                    tdx_dcap_collateral,
                )))
            }
            TrustModeConfig::TrustPack { source, .. } => RuntimeMode::TrustPack(source),
            TrustModeConfig::Explicit {
                source,
                measurement_policy,
                base_image,
                workload_pcr23_sha256,
                workload_pcr23_sha384,
            } => RuntimeMode::Explicit {
                source,
                measurement_policy,
                base_image,
                workload_pcr23_sha256,
                workload_pcr23_sha384,
            },
        };
        Ok(Self {
            state: Arc::new(AppState {
                portal_destination_policy,
                verification_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
                verification_timeout: VERIFICATION_TIMEOUT,
                config: report,
                runner: Arc::new(RuntimeRunner { mode }),
            }),
            listen,
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/health", get(health))
            .route("/v1/config", get(get_config))
            .route(
                "/v1/verify",
                post(verify).layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES)),
            )
            .route("/v1/verify-session-bundle", post(verify_session_bundle))
            .with_state(self.state.clone())
    }

    pub async fn serve(self) -> Result<(), StartError> {
        let listener = tokio::net::TcpListener::bind(self.listen)
            .await
            .map_err(|source| StartError::Bind {
                address: self.listen,
                source,
            })?;
        axum::serve(listener, self.router())
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(StartError::Serve)
    }
}

#[async_trait]
impl VerificationRunner for RuntimeRunner {
    async fn verify(
        &self,
        portal: &ResolvedPortalEndpoint,
        base_image: AppRef,
        workload: AppRef,
        permit: OwnedSemaphorePermit,
    ) -> Result<VerifyResponse, ApiError> {
        let expected_base_image_id = atakit_cvm_encoding::base_image_id(&base_image);
        let expected_workload_id = atakit_cvm_encoding::workload_id(&workload);
        let mode = self.session_verification_mode(&base_image, &workload)?;
        let request = PortalSessionVerificationRequest {
            host: portal.host().to_string(),
            status_port: portal.port(),
            resolved_address: Some(portal.socket_address()),
            mode,
            report_path: None,
            required_binding: VERIFIERD_REQUIRED_BINDING,
        };
        let outcome = run_verification_worker(
            permit,
            async move {
                let prepared_tls = prepare_portal_session_tls_verification(request)
                    .await
                    .map_err(ApiError::verification)?;
                let verified_tls = prepared_tls.verify_tls().map_err(ApiError::verification)?;
                let fetched = verified_tls
                    .fetch_session()
                    .await
                    .map_err(ApiError::verification)?;
                let parsed = fetched.parse().map_err(ApiError::verification)?;
                let prepared = parsed.prepare().await.map_err(ApiError::verification)?;
                prepared.verify().map_err(ApiError::verification)
            },
            "portal verification worker failed",
        )
        .await?;
        Ok(success_response(
            outcome.session,
            outcome.portal_tls.trust_provenance().clone(),
            expected_base_image_id,
            expected_workload_id,
        ))
    }

    async fn verify_session_bundle(
        &self,
        session_evidence: ChallengeBoundSessionEvidence,
        expected_challenge: [u8; 32],
        base_image: AppRef,
        workload: AppRef,
        permit: OwnedSemaphorePermit,
    ) -> Result<VerifyResponse, ApiError> {
        let expected_base_image_id = atakit_cvm_encoding::base_image_id(&base_image);
        let expected_workload_id = atakit_cvm_encoding::workload_id(&workload);
        let mode = self.session_verification_mode(&base_image, &workload)?;
        let outcome = run_verification_worker(
            permit,
            async move {
                let prepared =
                    prepare_supplied_session_bundle(SuppliedSessionBundleVerificationRequest {
                        session_evidence,
                        expected_challenge,
                        mode,
                        required_binding: VERIFIERD_REQUIRED_BINDING,
                    })
                    .await
                    .map_err(ApiError::bundle_verification)?;
                prepared.verify().map_err(ApiError::bundle_verification)
            },
            "session bundle verification worker failed",
        )
        .await?;
        Ok(success_response(
            outcome.session,
            outcome.trust_provenance,
            expected_base_image_id,
            expected_workload_id,
        ))
    }
}

/// Run one complete verification on a blocking worker while asynchronous I/O
/// continues through the current Tokio runtime.
///
/// The worker owns the concurrency permit. If the HTTP timeout drops the
/// JoinHandle, the detached worker keeps the permit until every synchronous
/// parser and cryptographic check has stopped.
async fn run_verification_worker<F, T>(
    permit: OwnedSemaphorePermit,
    verification: F,
    worker_failure: &'static str,
) -> Result<T, ApiError>
where
    F: std::future::Future<Output = Result<T, ApiError>> + Send + 'static,
    T: Send + 'static,
{
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        runtime.block_on(verification)
    })
    .await
    .map_err(|_| ApiError::verification_message(worker_failure))?
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn get_config(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    Json(state.config.clone())
}

async fn verify(
    State(state): State<Arc<AppState>>,
    request: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let Json(request) = request.map_err(|error| {
        ApiError::bad_request(format!("invalid POST /v1/verify JSON body: {error}"))
    })?;
    let permit = state
        .verification_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy("too many verifications are already running"))?;
    let portal = PortalEndpoint::parse(&request.portal.host, request.portal.port)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let base_image = request
        .base_image
        .parse::<AppRef>()
        .map_err(|error| ApiError::bad_request(format!("invalid base_image: {error}")))?;
    let workload = request
        .workload
        .parse::<AppRef>()
        .map_err(|error| ApiError::bad_request(format!("invalid workload: {error}")))?;
    let result = tokio::time::timeout(state.verification_timeout, async {
        let portal = state
            .portal_destination_policy
            .resolve(portal)
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        state
            .runner
            .verify(&portal, base_image, workload, permit)
            .await
    })
    .await
    .map_err(|_| ApiError::timeout("portal verification exceeded its total time limit"))?;
    result.map(Json)
}

async fn verify_session_bundle(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let permit = state
        .verification_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy("too many verifications are already running"))?;
    let result = tokio::time::timeout(state.verification_timeout, async move {
        require_json_content_type(&request)?;
        let body = to_bytes(request.into_body(), MAX_SESSION_BUNDLE_REQUEST_BYTES)
            .await
            .map_err(|error| {
                ApiError::bad_request(format!(
                    "invalid POST /v1/verify-session-bundle JSON body: request body exceeds the {MAX_SESSION_BUNDLE_REQUEST_BYTES}-byte length limit: {error}"
                ))
            })?;
        let (permit, request) = tokio::task::spawn_blocking(move || {
            let request = serde_json::from_slice::<VerifySessionBundleRequest>(&body).map_err(
                |error| {
                    ApiError::bad_request(format!(
                        "invalid POST /v1/verify-session-bundle JSON body: {error}"
                    ))
                },
            );
            (permit, request)
        })
        .await
        .map_err(|_| ApiError::verification_message("session bundle JSON worker failed"))?;
        let request = request?;
        let expected_challenge = decode_expected_challenge(&request.expected_challenge)?;
        let base_image = request
            .base_image
            .parse::<AppRef>()
            .map_err(|error| ApiError::bad_request(format!("invalid base_image: {error}")))?;
        let workload = request
            .workload
            .parse::<AppRef>()
            .map_err(|error| ApiError::bad_request(format!("invalid workload: {error}")))?;
        state
            .runner
            .verify_session_bundle(
                request.session_evidence,
                expected_challenge,
                base_image,
                workload,
                permit,
            )
            .await
    })
    .await
    .map_err(|_| ApiError::timeout("session bundle verification exceeded its total time limit"))?;
    result.map(Json)
}

fn require_json_content_type(request: &Request<Body>) -> Result<(), ApiError> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type.is_some_and(|value| {
        value.eq_ignore_ascii_case("application/json")
            || value
                .strip_prefix("application/")
                .is_some_and(|subtype| subtype.to_ascii_lowercase().ends_with("+json"))
    }) {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "invalid POST /v1/verify-session-bundle JSON body: Content-Type must be application/json or application/*+json",
        ))
    }
}

fn decode_expected_challenge(value: &str) -> Result<[u8; 32], ApiError> {
    if value.contains('=') {
        return Err(ApiError::bad_request(
            "expected_challenge must be unpadded base64url",
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| ApiError::bad_request(format!("invalid expected_challenge: {error}")))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ApiError::bad_request(
            "expected_challenge must use canonical unpadded base64url",
        ));
    }
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ApiError::bad_request(format!(
            "expected_challenge must decode to exactly 32 bytes, got {}",
            bytes.len()
        ))
    })
}

fn success_response(
    session: VerifiedSession,
    sources: TrustProvenance,
    base_image_id: [u8; 32],
    workload_id: [u8; 32],
) -> VerifyResponse {
    VerifyResponse {
        verified: true,
        session_id: hex0x(&session.session_id),
        session_key_fingerprint: hex0x(&session.session_key_fingerprint),
        session_public_key: SessionPublicKeyResponse {
            type_id: session.session_key_type_id,
            key: hex0x(&session.session_public_key),
        },
        workload_id: hex0x(&workload_id),
        base_image_id: hex0x(&base_image_id),
        binding_mode: session.binding_mode,
        binding_chain_id: session.binding_chain_id,
        binding_registry: hex0x(&session.binding_registry),
        attestation_mode: session.attestation_mode,
        sources,
        checks: session.checks,
    }
}

fn config_response(config: &VerifierdConfig) -> ConfigResponse {
    let (packs, supported_platforms) = match &config.mode {
        TrustModeConfig::Chain { .. } => (
            Vec::new(),
            SUPPORTED_PLATFORMS
                .iter()
                .map(|platform| (*platform).to_string())
                .collect(),
        ),
        TrustModeConfig::TrustPack { source, packs } => {
            (packs.clone(), source.supported_platforms())
        }
        TrustModeConfig::Explicit { source, .. } => (Vec::new(), source.supported_platforms()),
    };
    ConfigResponse {
        trust_mode: config.mode.name().to_string(),
        portal_allowed_ports: config
            .portal_destination_policy
            .allowed_ports()
            .iter()
            .copied()
            .collect(),
        portal_allowed_cidrs: config
            .portal_destination_policy
            .allowed_cidrs()
            .map(|networks| networks.iter().map(ToString::to_string).collect()),
        packs,
        supported_platforms,
    }
}

struct ApiError {
    status: StatusCode,
    failure: SessionVerificationFailure,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            failure: SessionVerificationFailure {
                checks: Vec::new(),
                errors: vec![message.into()],
            },
        }
    }

    fn verification(error: PortalVerificationError) -> Self {
        match error {
            PortalVerificationError::SessionVerification { failure } => Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                failure: *failure,
            },
            PortalVerificationError::Config { .. } => Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                failure: SessionVerificationFailure {
                    checks: Vec::new(),
                    errors: vec!["portal verification configuration failed".to_string()],
                },
            },
            PortalVerificationError::Http { .. } => {
                Self::verification_message("portal connection failed")
            }
            PortalVerificationError::PortalTlsAttestationFailed { .. } => {
                Self::verification_message("portal TLS attestation failed")
            }
            PortalVerificationError::PortalSessionVerificationFailed { .. } => {
                Self::verification_message("portal session verification failed")
            }
            PortalVerificationError::IoPath { .. } | PortalVerificationError::Json(_) => {
                Self::verification_message("portal verification failed")
            }
        }
    }

    fn bundle_verification(error: PortalVerificationError) -> Self {
        match error {
            PortalVerificationError::SessionVerification { failure } => Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                failure: *failure,
            },
            PortalVerificationError::Config { .. } => {
                Self::verification_message("session bundle verification configuration failed")
            }
            PortalVerificationError::Http { .. }
            | PortalVerificationError::PortalTlsAttestationFailed { .. }
            | PortalVerificationError::PortalSessionVerificationFailed { .. }
            | PortalVerificationError::IoPath { .. }
            | PortalVerificationError::Json(_) => {
                Self::verification_message("session bundle trust resolution failed")
            }
        }
    }

    fn verification_message(message: &str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            failure: SessionVerificationFailure {
                checks: Vec::new(),
                errors: vec![message.to_string()],
            },
        }
    }

    fn busy(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            failure: SessionVerificationFailure {
                checks: Vec::new(),
                errors: vec![message.into()],
            },
        }
    }

    fn timeout(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            failure: SessionVerificationFailure {
                checks: Vec::new(),
                errors: vec![message.into()],
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.failure)).into_response()
    }
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct CountingRunner {
        calls: AtomicUsize,
    }

    struct PendingRunner;

    struct BlockingPortalRunner {
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    struct BlockingSessionBundleRunner {
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    #[async_trait]
    impl VerificationRunner for CountingRunner {
        async fn verify(
            &self,
            _portal: &ResolvedPortalEndpoint,
            _base_image: AppRef,
            _workload: AppRef,
            _permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ApiError::bad_request("test runner"))
        }

        async fn verify_session_bundle(
            &self,
            _session_evidence: ChallengeBoundSessionEvidence,
            _expected_challenge: [u8; 32],
            _base_image: AppRef,
            _workload: AppRef,
            _permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ApiError::bad_request("test runner"))
        }
    }

    #[async_trait]
    impl VerificationRunner for PendingRunner {
        async fn verify(
            &self,
            _portal: &ResolvedPortalEndpoint,
            _base_image: AppRef,
            _workload: AppRef,
            _permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            std::future::pending().await
        }

        async fn verify_session_bundle(
            &self,
            _session_evidence: ChallengeBoundSessionEvidence,
            _expected_challenge: [u8; 32],
            _base_image: AppRef,
            _workload: AppRef,
            _permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl VerificationRunner for BlockingPortalRunner {
        async fn verify(
            &self,
            _portal: &ResolvedPortalEndpoint,
            _base_image: AppRef,
            _workload: AppRef,
            permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            let started = self.started.clone();
            let release = self
                .release
                .lock()
                .expect("release receiver lock")
                .take()
                .expect("one blocking verification");
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                started.send(()).expect("report blocking worker start");
                release.recv().expect("release blocking worker");
                Err(ApiError::bad_request("test runner"))
            })
            .await
            .expect("blocking worker joins")
        }

        async fn verify_session_bundle(
            &self,
            _session_evidence: ChallengeBoundSessionEvidence,
            _expected_challenge: [u8; 32],
            _base_image: AppRef,
            _workload: AppRef,
            _permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            Err(ApiError::bad_request("test runner"))
        }
    }

    #[async_trait]
    impl VerificationRunner for BlockingSessionBundleRunner {
        async fn verify(
            &self,
            _portal: &ResolvedPortalEndpoint,
            _base_image: AppRef,
            _workload: AppRef,
            _permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            Err(ApiError::bad_request("test runner"))
        }

        async fn verify_session_bundle(
            &self,
            _session_evidence: ChallengeBoundSessionEvidence,
            _expected_challenge: [u8; 32],
            _base_image: AppRef,
            _workload: AppRef,
            permit: OwnedSemaphorePermit,
        ) -> Result<VerifyResponse, ApiError> {
            let started = self.started.clone();
            let release = self
                .release
                .lock()
                .expect("release receiver lock")
                .take()
                .expect("one blocking verification");
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                started.send(()).expect("report blocking worker start");
                release.recv().expect("release blocking worker");
                Err(ApiError::bad_request("test runner"))
            })
            .await
            .expect("blocking worker joins")
        }
    }

    fn test_router(runner: Arc<CountingRunner>) -> Router {
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
            verification_timeout: VERIFICATION_TIMEOUT,
            config: ConfigResponse {
                trust_mode: "explicit".to_string(),
                portal_allowed_ports: vec![2024],
                portal_allowed_cidrs: None,
                packs: Vec::new(),
                supported_platforms: Vec::new(),
            },
            runner,
        });
        Router::new()
            .route("/v1/health", get(health))
            .route("/v1/config", get(get_config))
            .route(
                "/v1/verify",
                post(verify).layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES)),
            )
            .route("/v1/verify-session-bundle", post(verify_session_bundle))
            .with_state(state)
    }

    fn session_bundle_request_value(padding: String) -> serde_json::Value {
        let publisher = format!("0x{}", "11".repeat(32));
        let challenge = URL_SAFE_NO_PAD.encode([0x22; 32]);
        let id = format!("0x{}", "00".repeat(32));
        serde_json::json!({
            "session_evidence": {
                "evidence_bundle": {
                    "format": 2,
                    "binding": {
                        "mode": "local",
                        "chain_id": 0,
                        "registry": format!("0x{}", "00".repeat(20)),
                        "owner_nonce": id,
                        "qualifying_data": id
                    },
                    "platform": {
                        "cloud": "gcp",
                        "cloud_provenance": {
                            "source": "dmi",
                            "detection": {
                                "dmi": {
                                    "sys_vendor": null,
                                    "product_name": null,
                                    "bios_vendor": null,
                                    "detected_cloud": "gcp"
                                },
                                "metadata": {
                                    "gcp": {
                                        "attempted": false,
                                        "matched": false,
                                        "http_status": null,
                                        "response_headers": {},
                                        "response_body": null,
                                        "error": null
                                    },
                                    "azure": {
                                        "attempted": false,
                                        "matched": false,
                                        "http_status": null,
                                        "response_headers": {},
                                        "response_body": null,
                                        "error": null
                                    },
                                    "aws": {
                                        "attempted": false,
                                        "matched": false,
                                        "http_status": null,
                                        "response_headers": {},
                                        "response_body": null,
                                        "error": null
                                    },
                                    "detected_cloud": "unknown",
                                    "conflict": false
                                }
                            },
                            "user_provided": null
                        },
                        "attestation_mode": "hardware",
                        "tee": "sev-snp",
                        "machine_type": "n2d-standard-2"
                    },
                    "tee_evidence": {"kind": "configfs_tsm", "report": "", "auxiliary": null},
                    "ak_evidence": {"kind": "gcp_cert_chain", "ak_public": "", "collateral": padding},
                    "tpm_quote": {
                        "tpms_attest": "",
                        "tpm_signature": "",
                        "signature_hash": id,
                        "pcr0_startup_locality": 0
                    },
                    "tpm_certify": {"tpms_attest": "", "tpm_signature": "", "tpmt_public": ""},
                    "pcr_values": [],
                    "event_log_hashes": [],
                    "session_key": {"type_id": 3, "bytes": "0x", "fingerprint": "0x"},
                    "session_key_delegation": {
                        "tpm_signing_key": {"type_id": 2, "bytes": "0x", "fingerprint": "0x"},
                        "digest": "0x",
                        "signature": "0x",
                        "session_key_possession_signature": "0x"
                    },
                    "session_id": id,
                    "policy": {
                        "workload_id": id,
                        "base_image_id": id,
                        "platform_profile_id": id,
                        "measurement_variant_id": id,
                        "pcr_bank_selection": "sha256",
                        "invariant_pcr_policy": {"pcr_specs256": [], "pcr_specs384": []},
                        "variant_pcr_policy": {"pcr_specs256": [], "pcr_specs384": []},
                        "workload_pcr_policy": {"pcr_specs256": [], "pcr_specs384": []},
                        "provider_pcr_policy": {"pcr_specs256": [], "pcr_specs384": []}
                    },
                    "owner": {"fingerprint": id, "contract_authorization": null}
                },
                "request_binding": {"challenge": challenge, "signature": "0x"}
            },
            "expected_challenge": challenge,
            "base_image": format!("{publisher}/base:v1"),
            "workload": format!("{publisher}/workload:v1")
        })
    }

    #[test]
    fn verifierd_does_not_impose_an_extra_binding_mode() {
        assert_eq!(VERIFIERD_REQUIRED_BINDING, None);

        let verify = serde_json::json!({
            "portal": {"host": "203.0.113.10", "port": 2024},
            "base_image": "base:v1",
            "workload": "workload:v1",
        });
        serde_json::from_value::<VerifyRequest>(verify.clone())
            .expect("the normal portal request schema remains valid");
        let mut verify = verify;
        verify["required_binding"] = serde_json::json!("chain");
        assert!(serde_json::from_value::<VerifyRequest>(verify).is_err());

        let supplied = session_bundle_request_value(String::new());
        serde_json::from_value::<VerifySessionBundleRequest>(supplied.clone())
            .expect("the normal supplied-bundle request schema remains valid");
        let mut supplied = supplied;
        supplied["required_binding"] = serde_json::json!("local");
        assert!(serde_json::from_value::<VerifySessionBundleRequest>(supplied).is_err());
    }

    fn session_bundle_body_with_exact_length(length: usize) -> Vec<u8> {
        let mut value = session_bundle_request_value(String::new());
        let empty = serde_json::to_vec(&value).expect("serialize request without padding");
        let padding_length = length
            .checked_sub(empty.len())
            .expect("requested body length can hold the fixed fields");
        value["session_evidence"]["evidence_bundle"]["ak_evidence"]["collateral"] =
            serde_json::Value::String("a".repeat(padding_length));
        let body = serde_json::to_vec(&value).expect("serialize padded request");
        assert_eq!(body.len(), length);
        body
    }

    #[tokio::test]
    async fn an_invalid_dynamic_portal_is_rejected_before_the_runner() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let response = test_router(runner.clone())
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"portal":{"host":"https://peer.example","port":2024},"base_image":"bad","workload":"bad"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let failure: SessionVerificationFailure = serde_json::from_slice(&body).unwrap();
        assert!(failure.errors[0].contains("portal.host"));
    }

    #[tokio::test]
    async fn a_dynamic_portal_reaches_the_runner_after_destination_and_references_parse() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let publisher = format!("0x{}", "11".repeat(32));
        let body = format!(
            r#"{{"portal":{{"host":"203.0.113.10","port":2024}},"base_image":"{publisher}/base:v1","workload":"{publisher}/workload:v1"}}"#
        );
        let response = test_router(runner.clone())
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_session_bundle_request_reaches_the_runner_without_a_portal_destination() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let body = session_bundle_request_value("a".repeat(MAX_VERIFY_REQUEST_BYTES));
        let response = test_router(runner.clone())
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_session_bundle_body_limit_accepts_exactly_eight_mib_and_rejects_the_next_byte() {
        let at_limit_runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let response = test_router(at_limit_runner.clone())
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from(session_bundle_body_with_exact_length(
                        MAX_SESSION_BUNDLE_REQUEST_BYTES,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(at_limit_runner.calls.load(Ordering::SeqCst), 1);

        let over_limit_runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let response = test_router(over_limit_runner.clone())
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from(session_bundle_body_with_exact_length(
                        MAX_SESSION_BUNDLE_REQUEST_BYTES + 1,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let failure: SessionVerificationFailure = serde_json::from_slice(&body).unwrap();
        assert!(failure.errors[0].contains("length limit"), "{failure:?}");
        assert_eq!(over_limit_runner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_session_bundle_slot_is_required_before_body_parsing() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: Arc::new(Semaphore::new(0)),
            verification_timeout: VERIFICATION_TIMEOUT,
            config: ConfigResponse {
                trust_mode: "explicit".to_string(),
                portal_allowed_ports: vec![2024],
                portal_allowed_cidrs: None,
                packs: Vec::new(),
                supported_platforms: Vec::new(),
            },
            runner: runner.clone(),
        });
        let response = Router::new()
            .route("/v1/verify-session-bundle", post(verify_session_bundle))
            .with_state(state)
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from("not JSON"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_noncanonical_or_wrong_length_expected_challenge_is_rejected() {
        for challenge in ["AA==", "AA"] {
            let runner = Arc::new(CountingRunner {
                calls: AtomicUsize::new(0),
            });
            let publisher = format!("0x{}", "11".repeat(32));
            let body = serde_json::json!({
                "session_evidence": {
                    "evidence_bundle": {},
                    "request_binding": {"challenge": challenge, "signature": "0x"}
                },
                "expected_challenge": challenge,
                "base_image": format!("{publisher}/base:v1"),
                "workload": format!("{publisher}/workload:v1")
            });
            let response = test_router(runner.clone())
                .oneshot(
                    Request::post("/v1/verify-session-bundle")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn an_unknown_request_binding_field_is_rejected_before_the_runner() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let mut body = session_bundle_request_value(String::new());
        body["session_evidence"]["request_binding"]["unexpected"] = serde_json::Value::Bool(true);
        let response = test_router(runner.clone())
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn health_and_config_are_structured_json() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        for (path, field) in [("/v1/health", "status"), ("/v1/config", "trust_mode")] {
            let response = test_router(runner.clone())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(value.get(field).is_some(), "{path}: {value}");
            if path == "/v1/config" {
                assert_eq!(value["portal_allowed_ports"], serde_json::json!([2024]));
                assert!(value["portal_allowed_cidrs"].is_null());
                assert!(value.get("peers").is_none());
            }
        }
    }

    #[tokio::test]
    async fn malformed_json_and_unknown_fields_use_the_session_failure_shape() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        for body in [
            "not JSON",
            r#"{"portal":{"host":"203.0.113.10","port":2024,"path":"/status"},"base_image":"x","workload":"y"}"#,
            r#"{"portal":{"host":"203.0.113.10","port":2024},"base_image":"x","workload":"y","peer":"beta"}"#,
        ] {
            let response = test_router(runner.clone())
                .oneshot(
                    Request::post("/v1/verify")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
            let failure: SessionVerificationFailure = serde_json::from_slice(&body).unwrap();
            assert!(failure.checks.is_empty());
            assert_eq!(failure.errors.len(), 1);
        }
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_oversized_request_uses_the_session_failure_shape() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let body = format!(
            r#"{{"portal":{{"host":"203.0.113.10","port":2024}},"base_image":"{}","workload":"x"}}"#,
            "a".repeat(MAX_VERIFY_REQUEST_BYTES)
        );
        let response = test_router(runner.clone())
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let failure: SessionVerificationFailure = serde_json::from_slice(&body).unwrap();
        assert!(failure.errors[0].contains("length limit"), "{failure:?}");
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_structured_session_failure_is_returned_without_translation() {
        let original = SessionVerificationFailure {
            checks: vec![atakit_attestation::SessionVerificationCheck {
                name: "session-key-possession".to_string(),
                valid: false,
                detail: Some("signature mismatch".to_string()),
            }],
            errors: vec!["session verification failed".to_string()],
        };
        let error = ApiError::verification(PortalVerificationError::SessionVerification {
            failure: Box::new(original),
        });

        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.failure.checks.len(), 1);
        assert_eq!(error.failure.checks[0].name, "session-key-possession");
        assert_eq!(
            error.failure.checks[0].detail.as_deref(),
            Some("signature mismatch")
        );
        assert_eq!(error.failure.errors, ["session verification failed"]);
    }

    #[test]
    fn unverified_remote_details_are_not_returned() {
        let secret = "internal-response-body-secret";
        for error in [
            PortalVerificationError::Http {
                message: secret.to_string(),
            },
            PortalVerificationError::PortalTlsAttestationFailed {
                message: secret.to_string(),
            },
            PortalVerificationError::PortalSessionVerificationFailed {
                message: secret.to_string(),
            },
        ] {
            let error = ApiError::verification(error);
            let rendered = serde_json::to_string(&error.failure).unwrap();
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }

    #[tokio::test]
    async fn a_full_verification_slot_set_fails_without_running_verification() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
        });
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: Arc::new(Semaphore::new(0)),
            verification_timeout: VERIFICATION_TIMEOUT,
            config: ConfigResponse {
                trust_mode: "explicit".to_string(),
                portal_allowed_ports: vec![2024],
                portal_allowed_cidrs: None,
                packs: Vec::new(),
                supported_platforms: Vec::new(),
            },
            runner: runner.clone(),
        });
        let response = Router::new()
            .route("/v1/verify", post(verify))
            .layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES))
            .with_state(state)
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"portal":{"host":"203.0.113.10","port":2024},"base_image":"bad","workload":"bad"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_total_timeout_bounds_destination_resolution_and_verification() {
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: Arc::new(Semaphore::new(1)),
            verification_timeout: Duration::from_millis(1),
            config: ConfigResponse {
                trust_mode: "explicit".to_string(),
                portal_allowed_ports: vec![2024],
                portal_allowed_cidrs: None,
                packs: Vec::new(),
                supported_platforms: Vec::new(),
            },
            runner: Arc::new(PendingRunner),
        });
        let publisher = format!("0x{}", "11".repeat(32));
        let body = format!(
            r#"{{"portal":{{"host":"203.0.113.10","port":2024}},"base_image":"{publisher}/base:v1","workload":"{publisher}/workload:v1"}}"#
        );
        let response = Router::new()
            .route("/v1/verify", post(verify))
            .layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES))
            .with_state(state)
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn a_timed_out_blocking_portal_verification_keeps_its_slot_and_health_stays_responsive() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let slots = Arc::new(Semaphore::new(1));
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: slots.clone(),
            verification_timeout: Duration::from_millis(20),
            config: ConfigResponse {
                trust_mode: "explicit".to_string(),
                portal_allowed_ports: vec![2024],
                portal_allowed_cidrs: None,
                packs: Vec::new(),
                supported_platforms: Vec::new(),
            },
            runner: Arc::new(BlockingPortalRunner {
                started: started_tx,
                release: std::sync::Mutex::new(Some(release_rx)),
            }),
        });
        let router = Router::new()
            .route("/v1/health", get(health))
            .route(
                "/v1/verify",
                post(verify).layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES)),
            )
            .with_state(state);
        let publisher = format!("0x{}", "11".repeat(32));
        let body = format!(
            r#"{{"portal":{{"host":"203.0.113.10","port":2024}},"base_image":"{publisher}/base:v1","workload":"{publisher}/workload:v1"}}"#
        );

        let response = router
            .clone()
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blocking worker started");

        let health = router
            .clone()
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let response = router
            .oneshot(
                Request::post("/v1/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        release_tx.send(()).expect("release blocking worker");
        tokio::time::timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking worker releases its slot");
    }

    #[tokio::test]
    async fn a_timed_out_blocking_verification_keeps_its_slot_until_it_exits() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let slots = Arc::new(Semaphore::new(1));
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: slots.clone(),
            verification_timeout: Duration::from_millis(20),
            config: ConfigResponse {
                trust_mode: "explicit".to_string(),
                portal_allowed_ports: vec![2024],
                portal_allowed_cidrs: None,
                packs: Vec::new(),
                supported_platforms: Vec::new(),
            },
            runner: Arc::new(BlockingSessionBundleRunner {
                started: started_tx,
                release: std::sync::Mutex::new(Some(release_rx)),
            }),
        });
        let router = Router::new()
            .route("/v1/verify-session-bundle", post(verify_session_bundle))
            .with_state(state);
        let body = serde_json::to_vec(&session_bundle_request_value(String::new())).unwrap();

        let response = router
            .clone()
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blocking worker started");

        let response = router
            .oneshot(
                Request::post("/v1/verify-session-bundle")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        release_tx.send(()).expect("release blocking worker");
        tokio::time::timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking worker releases its slot");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_runtime_worker_keeps_parsing_off_tokio_and_retains_its_permit() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots
            .clone()
            .try_acquire_owned()
            .expect("one verification slot");

        let verification = run_verification_worker(
            permit,
            async move {
                started_tx.send(()).expect("report worker start");
                release_rx.recv().expect("release worker");
                Ok(())
            },
            "test worker failed",
        );
        let result = tokio::time::timeout(Duration::from_millis(20), verification).await;
        assert!(result.is_err(), "the HTTP-side wait must time out");
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the blocking worker owns the parsing future");
        assert_eq!(slots.available_permits(), 0);

        tokio::time::timeout(Duration::from_millis(100), async {
            tokio::task::yield_now().await;
        })
        .await
        .expect("Tokio workers remain responsive");

        release_tx.send(()).expect("release blocking worker");
        tokio::time::timeout(Duration::from_secs(1), async {
            while slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the detached worker releases its permit only after exit");

        let caller_thread = std::thread::current().id();
        let permit = slots
            .clone()
            .try_acquire_owned()
            .expect("the released verification slot");
        let worker_result = run_verification_worker(
            permit,
            async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(std::thread::current().id())
            },
            "test worker failed",
        )
        .await;
        let worker_thread = match worker_result {
            Ok(worker_thread) => worker_thread,
            Err(_) => panic!("the blocking worker must drive Tokio timers"),
        };
        assert_ne!(caller_thread, worker_thread);
    }

    #[test]
    fn success_response_contains_the_verified_session_key_and_binding() {
        let session = VerifiedSession {
            session_id: [0x11; 32],
            session_key_fingerprint: [0x22; 32],
            session_key_type_id: 3,
            session_public_key: vec![0x04, 0x33],
            binding_mode: BindingMode::Chain,
            binding_chain_id: 560_048,
            binding_registry: [0x44; 20],
            attestation_mode: atakit_attestation::SessionAttestationMode::Hardware,
            checks: Vec::new(),
        };
        let response =
            success_response(session, TrustProvenance::default(), [0x55; 32], [0x66; 32]);

        assert!(response.verified);
        assert_eq!(response.session_public_key.type_id, 3);
        assert_eq!(response.session_public_key.key, "0x0433");
        assert_eq!(response.binding_mode, BindingMode::Chain);
        assert_eq!(response.binding_chain_id, 560_048);
        assert_eq!(response.binding_registry, format!("0x{}", "44".repeat(20)));
    }
}
