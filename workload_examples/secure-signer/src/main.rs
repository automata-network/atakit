use axum::{Router, routing::{get, post}};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, UnixStream};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DATA_PATH: &str = "/data/disk.txt";
const CVM_AGENT_SOCK: &str = "/app/cvm-agent.sock";

async fn cvm_agent_get(path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let stream = UnixStream::connect(CVM_AGENT_SOCK).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let req = Request::builder()
        .uri(path)
        .header("Host", "localhost")
        .body(Empty::<Bytes>::new())?;

    let res = sender.send_request(req).await?;
    let body = res.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).to_string())
}

async fn cvm_agent_post(path: &str, body: String) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let stream = UnixStream::connect(CVM_AGENT_SOCK).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))?;

    let res = sender.send_request(req).await?;
    let body = res.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).to_string())
}

async fn hello() -> String {
    std::fs::read_to_string("/app/config/hello").unwrap_or_else(|_| "Hello, World!".to_string())
}

async fn signer_key() -> String {
    std::fs::read_to_string("/app/additional-data/signer_key").unwrap_or_else(|_| "No signer key found".to_string())
}

async fn read_data() -> String {
    std::fs::read_to_string(DATA_PATH).unwrap_or_else(|_| "No data found".to_string())
}

async fn write_data(body: String) -> String {
    match std::fs::write(DATA_PATH, &body) {
        Ok(_) => format!("Wrote {} bytes", body.len()),
        Err(e) => format!("Error writing data: {}", e),
    }
}

async fn platform() -> String {
    match cvm_agent_get("/platform").await {
        Ok(result) => result,
        Err(e) => format!("Error: {}", e),
    }
}

async fn sign_message(body: String) -> String {
    match cvm_agent_post("/sign-message", body).await {
        Ok(result) => result,
        Err(e) => format!("Error: {}", e),
    }
}

async fn rotate_key(body: String) -> String {
    match cvm_agent_post("/rotate-key", body).await {
        Ok(result) => result,
        Err(e) => format!("Error: {}", e),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let app = Router::new()
        .route("/", get(hello))
        .route("/signer_key", get(signer_key))
        .route("/read_data", get(read_data))
        .route("/write_data", post(write_data))
        .route("/platform", get(platform))
        .route("/sign-message", post(sign_message))
        .route("/rotate-key", post(rotate_key));
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
