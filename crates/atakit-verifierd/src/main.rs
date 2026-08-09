use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use atakit_verifierd::config::{load, UNMEASURED_DATA_DIR};
use atakit_verifierd::server::Verifierd;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "atakit_verifierd=info".into()),
        )
        .init();
    let environment: BTreeMap<String, String> = std::env::vars().collect();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())?;
    let config = load(
        &environment,
        std::path::Path::new(UNMEASURED_DATA_DIR),
        now_unix,
    )?;
    Verifierd::from_config(config).await?.serve().await?;
    Ok(())
}
