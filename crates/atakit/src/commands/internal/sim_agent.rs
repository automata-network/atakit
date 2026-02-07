mod routes;

use anyhow::Result;
use clap::Args;
use tracing::info;

#[derive(Args)]
pub struct SimAgent {
    /// Port to listen on
    #[arg(long, default_value = "7999")]
    pub port: u16,
}

impl SimAgent {
    pub async fn run(self) -> Result<()> {
        let app = routes::router();
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], self.port));
        info!(%addr, "sim-agent listening");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}
