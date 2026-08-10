//! Request-selected portal destinations and optional network restrictions.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use url::Host;

const IPV4_METADATA: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const IPV6_AWS_METADATA: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
const IPV6_GCP_METADATA: Ipv6Addr = Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalEndpoint {
    host: String,
    port: u16,
}

impl PortalEndpoint {
    pub fn parse(host: &str, port: u16) -> Result<Self, DestinationError> {
        if host.is_empty() || host.trim() != host {
            return Err(DestinationError::InvalidHost);
        }
        if port == 0 {
            return Err(DestinationError::InvalidPort);
        }
        let host = match host.parse::<IpAddr>() {
            Ok(address) => address.to_string(),
            Err(_) => match Host::parse(host).map_err(|_| DestinationError::InvalidHost)? {
                Host::Domain(domain) => domain,
                Host::Ipv4(address) => address.to_string(),
                Host::Ipv6(address) => address.to_string(),
            },
        };
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPortalEndpoint {
    endpoint: PortalEndpoint,
    socket_address: SocketAddr,
}

impl ResolvedPortalEndpoint {
    pub fn host(&self) -> &str {
        self.endpoint.host()
    }

    pub fn port(&self) -> u16 {
        self.endpoint.port()
    }

    pub fn socket_address(&self) -> SocketAddr {
        self.socket_address
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalDestinationPolicy {
    allowed_ports: BTreeSet<u16>,
    allowed_cidrs: Option<Vec<IpNet>>,
}

impl PortalDestinationPolicy {
    pub fn new(
        allowed_ports: BTreeSet<u16>,
        allowed_cidrs: Option<Vec<IpNet>>,
    ) -> Result<Self, DestinationError> {
        if allowed_ports.is_empty() || allowed_ports.contains(&0) {
            return Err(DestinationError::EmptyPortPolicy);
        }
        if matches!(allowed_cidrs.as_deref(), Some([])) {
            return Err(DestinationError::EmptyCidrPolicy);
        }
        Ok(Self {
            allowed_ports,
            allowed_cidrs,
        })
    }

    pub fn portal_port_only() -> Self {
        Self {
            allowed_ports: BTreeSet::from([2024]),
            allowed_cidrs: None,
        }
    }

    pub fn allowed_ports(&self) -> &BTreeSet<u16> {
        &self.allowed_ports
    }

    pub fn allowed_cidrs(&self) -> Option<&[IpNet]> {
        self.allowed_cidrs.as_deref()
    }

    pub async fn resolve(
        &self,
        endpoint: PortalEndpoint,
    ) -> Result<ResolvedPortalEndpoint, DestinationError> {
        if !self.allowed_ports.contains(&endpoint.port) {
            return Err(DestinationError::PortNotAllowed(endpoint.port));
        }

        let candidates = match endpoint.host.parse::<IpAddr>() {
            Ok(address) => vec![SocketAddr::new(address, endpoint.port)],
            Err(_) => tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
                .await
                .map_err(|_| DestinationError::ResolutionFailed)?
                .collect(),
        };

        if candidates.is_empty() {
            return Err(DestinationError::ResolutionFailed);
        }
        let mut rejected = None;
        for socket_address in candidates {
            match self.check_address(socket_address.ip()) {
                Ok(()) => {
                    return Ok(ResolvedPortalEndpoint {
                        endpoint,
                        socket_address,
                    });
                }
                Err(error) => rejected = Some(error),
            }
        }
        Err(rejected.unwrap_or(DestinationError::ResolutionFailed))
    }

    fn check_address(&self, address: IpAddr) -> Result<(), DestinationError> {
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        };
        if is_always_forbidden(address) {
            return Err(DestinationError::AddressForbidden);
        }

        let explicitly_allowed = self
            .allowed_cidrs
            .as_ref()
            .is_some_and(|networks| networks.iter().any(|network| network.contains(&address)));
        if self.allowed_cidrs.is_some() && !explicitly_allowed {
            return Err(DestinationError::AddressOutsidePolicy);
        }
        if (address.is_loopback() || is_link_local(address)) && !explicitly_allowed {
            return Err(DestinationError::LocalAddressNeedsExplicitPolicy);
        }
        Ok(())
    }
}

fn is_always_forbidden(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_multicast()
                || address == Ipv4Addr::BROADCAST
                || address == IPV4_METADATA
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_multicast()
                || address == IPV6_AWS_METADATA
                || address == IPV6_GCP_METADATA
        }
    }
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DestinationError {
    #[error("portal.host must be one DNS name or IP address without a scheme, path, port, credentials, or surrounding whitespace")]
    InvalidHost,
    #[error("portal.port must be between 1 and 65535")]
    InvalidPort,
    #[error("the portal destination policy must allow at least one nonzero port")]
    EmptyPortPolicy,
    #[error("the portal destination CIDR policy must not be empty")]
    EmptyCidrPolicy,
    #[error("portal port {0} is not allowed by the portal destination policy")]
    PortNotAllowed(u16),
    #[error("portal.host could not be resolved")]
    ResolutionFailed,
    #[error("the resolved portal address is always forbidden")]
    AddressForbidden,
    #[error("the resolved portal address is outside VERIFIED_PORTAL_ALLOWED_CIDRS")]
    AddressOutsidePolicy,
    #[error("loopback and link-local portal addresses require an explicit VERIFIED_PORTAL_ALLOWED_CIDRS entry")]
    LocalAddressNeedsExplicitPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_structured_and_strict() {
        assert_eq!(
            PortalEndpoint::parse("peer.example", 2024).unwrap(),
            PortalEndpoint {
                host: "peer.example".to_string(),
                port: 2024,
            }
        );
        assert_eq!(
            PortalEndpoint::parse("2001:db8::1", 2024).unwrap().host(),
            "2001:db8::1"
        );
        for host in [
            "",
            " peer.example",
            "https://peer.example",
            "peer.example/path",
            "user@peer.example",
            "peer.example:2024",
        ] {
            assert_eq!(
                PortalEndpoint::parse(host, 2024),
                Err(DestinationError::InvalidHost),
                "{host:?}"
            );
        }
        assert_eq!(
            PortalEndpoint::parse("peer.example", 0),
            Err(DestinationError::InvalidPort)
        );
    }

    #[tokio::test]
    async fn default_policy_accepts_dynamic_public_and_private_cvm_addresses() {
        let policy = PortalDestinationPolicy::portal_port_only();
        for host in ["203.0.113.10", "10.20.30.40"] {
            let endpoint = PortalEndpoint::parse(host, 2024).unwrap();
            assert_eq!(policy.resolve(endpoint).await.unwrap().host(), host);
        }
    }

    #[tokio::test]
    async fn unsafe_special_addresses_are_refused() {
        let policy = PortalDestinationPolicy::portal_port_only();
        for host in [
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "169.254.169.254",
            "::",
            "ff02::1",
            "fd00:ec2::254",
            "fd20:ce::254",
        ] {
            let error = policy
                .resolve(PortalEndpoint::parse(host, 2024).unwrap())
                .await
                .expect_err(host);
            assert_eq!(error, DestinationError::AddressForbidden, "{host}");
        }
    }

    #[tokio::test]
    async fn local_addresses_need_an_explicit_cidr() {
        let default = PortalDestinationPolicy::portal_port_only();
        let loopback = PortalEndpoint::parse("127.0.0.1", 2024).unwrap();
        assert_eq!(
            default.resolve(loopback.clone()).await.unwrap_err(),
            DestinationError::LocalAddressNeedsExplicitPolicy
        );

        let allowed = PortalDestinationPolicy::new(
            BTreeSet::from([2024]),
            Some(vec!["127.0.0.0/8".parse().unwrap()]),
        )
        .unwrap();
        assert_eq!(
            allowed.resolve(loopback).await.unwrap().socket_address(),
            "127.0.0.1:2024".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn cidrs_and_ports_are_independent_optional_restrictions() {
        let policy = PortalDestinationPolicy::new(
            BTreeSet::from([2024, 12024]),
            Some(vec!["10.0.0.0/8".parse().unwrap()]),
        )
        .unwrap();
        assert!(policy
            .resolve(PortalEndpoint::parse("10.1.2.3", 12024).unwrap())
            .await
            .is_ok());
        assert_eq!(
            policy
                .resolve(PortalEndpoint::parse("192.168.1.1", 2024).unwrap())
                .await
                .unwrap_err(),
            DestinationError::AddressOutsidePolicy
        );
        assert_eq!(
            policy
                .resolve(PortalEndpoint::parse("10.1.2.3", 443).unwrap())
                .await
                .unwrap_err(),
            DestinationError::PortNotAllowed(443)
        );
    }
}
