//! A [tower_governor](https://docs.rs/tower_governor) key extractor that rate
//! limits by the client IP [`IpFilter`](crate::IpFilter) resolved. Requires the
//! `governor` feature.
//!
//! tower_governor's own IP extractors trust `X-Forwarded-For` from any client,
//! so a client can dodge rate limits by sending a new address with each request.
//! [`ClientIpKeyExtractor`] uses the spoof-resistant [`ClientIp`] instead.
//!
//! ```rust
//! use axum::routing::get;
//! use axum::Router;
//! use axum_ipware::governor::ClientIpKeyExtractor;
//! use axum_ipware::IpFilter;
//! use tower_governor::governor::GovernorConfigBuilder;
//! use tower_governor::GovernorLayer;
//!
//! let config = GovernorConfigBuilder::default()
//!     .per_second(1)
//!     .burst_size(5)
//!     .key_extractor(ClientIpKeyExtractor::new().ipv6_prefix(64))
//!     .finish()
//!     .unwrap();
//!
//! // Layers added last run first: IpFilter resolves the IP before rate limiting.
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(GovernorLayer::new(config))
//!     .layer(IpFilter::new());
//! ```

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::Request;
use ipware::ClientIpResolver;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorError;

use crate::client_ip::ClientIp;
use crate::filter::{mask_v6, peer_ip};

/// Rate limit key: the client IP resolved by [`IpFilter`](crate::IpFilter).
///
/// Add `IpFilter` as an outer layer so the [`ClientIp`] extension is set before
/// the rate limiter runs, or give the extractor its own resolver with
/// [`with_resolver`](Self::with_resolver). Requests without a client IP are
/// rejected by tower_governor with `500 Internal Server Error`.
#[derive(Clone, Debug, Default)]
pub struct ClientIpKeyExtractor {
    resolver: Option<Arc<ClientIpResolver>>,
    ipv6_prefix: Option<u8>,
}

impl ClientIpKeyExtractor {
    /// Uses the [`ClientIp`] set by an outer `IpFilter` layer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves the client IP with `resolver` when no `IpFilter` set it, from the
    /// headers and the `ConnectInfo` peer address.
    pub fn with_resolver(mut self, resolver: ClientIpResolver) -> Self {
        self.resolver = Some(Arc::new(resolver));
        self
    }

    /// Counts IPv6 clients by their `/prefix` network, e.g. `64`, since one
    /// client usually controls a whole `/64`. IPv4 addresses are not grouped.
    pub fn ipv6_prefix(mut self, prefix: u8) -> Self {
        self.ipv6_prefix = Some(prefix.min(128));
        self
    }

    fn key(&self, ip: IpAddr) -> IpAddr {
        match (ip, self.ipv6_prefix) {
            (IpAddr::V6(v6), Some(prefix)) => IpAddr::V6(mask_v6(v6, prefix)),
            _ => ip,
        }
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn name(&self) -> &'static str {
        "axum-ipware client IP"
    }

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let ip = req
            .extensions()
            .get::<ClientIp>()
            .map(|client_ip| client_ip.ip)
            .or_else(|| {
                let resolver = self.resolver.as_ref()?;
                resolver
                    .resolve(req.headers(), peer_ip(req.extensions()))
                    .map(|resolved| resolved.ip)
            })
            .ok_or(GovernorError::UnableToExtractKey)?;
        Ok(self.key(ip))
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn masks_ipv6() {
        let ip: Ipv6Addr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(
            mask_v6(ip, 64),
            "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(mask_v6(ip, 128), ip);
        assert_eq!(mask_v6(ip, 0), Ipv6Addr::UNSPECIFIED);
        let extractor = ClientIpKeyExtractor::new().ipv6_prefix(64);
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(extractor.key(v4), v4);
    }
}
