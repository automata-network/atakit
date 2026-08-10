//! HTTP boundary for peer session verification.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use atakit_attestation::{BindingMode, SessionVerificationFailure, VerifiedSession};
use atakit_attestation_client::{
    verify_portal_session, AttestationClient, ChainTrustSource, ExplicitTrustSource,
    PackTrustSource, PortalSessionVerificationRequest, PortalVerificationError,
    SessionVerificationMode, TrustProvenance, TrustedWorkloadSessionPolicy,
};
use atakit_cvm_types::AppRef;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::config::{LoadedPack, TrustModeConfig, VerifierdConfig};
use crate::destination::{PortalDestinationPolicy, PortalEndpoint, ResolvedPortalEndpoint};

const MAX_VERIFY_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_VERIFICATIONS: usize = 8;
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(360);
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
    verification_slots: Semaphore,
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
                verification_slots: Semaphore::new(MAX_CONCURRENT_VERIFICATIONS),
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
            .route("/v1/verify", post(verify))
            .layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES))
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
    ) -> Result<VerifyResponse, ApiError> {
        let expected_base_image_id = atakit_cvm_encoding::base_image_id(&base_image);
        let expected_workload_id = atakit_cvm_encoding::workload_id(&workload);
        let (mode, required_binding) = match &self.mode {
            RuntimeMode::Chain(source) => (
                SessionVerificationMode::Chain {
                    source: source.as_ref().clone(),
                    base_image,
                    workload,
                },
                Some(BindingMode::Chain),
            ),
            RuntimeMode::TrustPack(source) => (
                SessionVerificationMode::Packs {
                    source: source.clone(),
                    base_image_id: expected_base_image_id,
                    workload,
                },
                Some(BindingMode::Local),
            ),
            RuntimeMode::Explicit {
                source,
                measurement_policy,
                base_image: configured_base_image,
                workload_pcr23_sha256,
                workload_pcr23_sha384,
            } => {
                if &base_image != configured_base_image {
                    return Err(ApiError::bad_request(format!(
                        "base_image is {base_image}, but VERIFIED_MEASUREMENTS is for {configured_base_image}"
                    )));
                }
                let workload_policy = TrustedWorkloadSessionPolicy::from_manifest_pcr23(
                    &workload.to_string(),
                    *workload_pcr23_sha256,
                    *workload_pcr23_sha384,
                )
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
                (
                    SessionVerificationMode::Explicit {
                        source: source.as_ref().clone(),
                        measurement_policy: measurement_policy.clone(),
                        workload_policy,
                    },
                    Some(BindingMode::Local),
                )
            }
        };

        let outcome = verify_portal_session(PortalSessionVerificationRequest {
            host: portal.host().to_string(),
            status_port: portal.port(),
            resolved_address: Some(portal.socket_address()),
            mode,
            report_path: None,
            required_binding,
        })
        .await
        .map_err(ApiError::verification)?;
        Ok(success_response(
            outcome.session,
            outcome.portal_tls.trust_provenance().clone(),
            expected_base_image_id,
            expected_workload_id,
        ))
    }
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
        .try_acquire()
        .map_err(|_| ApiError::busy("too many portal verifications are already running"))?;
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
        state.runner.verify(&portal, base_image, workload).await
    })
    .await
    .map_err(|_| ApiError::timeout("portal verification exceeded its total time limit"))?;
    drop(permit);
    result.map(Json)
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

    #[async_trait]
    impl VerificationRunner for CountingRunner {
        async fn verify(
            &self,
            _portal: &ResolvedPortalEndpoint,
            _base_image: AppRef,
            _workload: AppRef,
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
        ) -> Result<VerifyResponse, ApiError> {
            std::future::pending().await
        }
    }

    fn test_router(runner: Arc<CountingRunner>) -> Router {
        let state = Arc::new(AppState {
            portal_destination_policy: PortalDestinationPolicy::portal_port_only(),
            verification_slots: Semaphore::new(MAX_CONCURRENT_VERIFICATIONS),
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
            .route("/v1/verify", post(verify))
            .layer(DefaultBodyLimit::max(MAX_VERIFY_REQUEST_BYTES))
            .with_state(state)
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
            verification_slots: Semaphore::new(0),
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
            verification_slots: Semaphore::new(1),
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
