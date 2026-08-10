//! Interaction with the portal under verification.

pub mod session;
pub mod status;
pub mod tls;

pub(crate) fn portal_url(host: &str, port: u16, path_and_query: &str) -> String {
    let host = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.to_string(),
    };
    format!("https://{host}:{port}{path_and_query}")
}
