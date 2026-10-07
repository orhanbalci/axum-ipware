use std::convert::Infallible;
use std::fmt;
use std::net::IpAddr;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ipware::{IpSource, ResolvedIp};

/// The client IP address resolved by [`IpFilter`](crate::IpFilter).
///
/// The filter stores it in the request extensions, so handlers can extract it:
///
/// ```rust
/// use axum_ipware::ClientIp;
///
/// async fn handler(client_ip: ClientIp) -> String {
///     client_ip.ip.to_string()
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientIp {
    /// The client IP address. IPv4-mapped IPv6 addresses are converted to IPv4.
    pub ip: IpAddr,
    /// Where the address came from.
    pub source: IpSource,
}

impl From<ResolvedIp> for ClientIp {
    fn from(resolved: ResolvedIp) -> Self {
        ClientIp { ip: resolved.ip, source: resolved.source }
    }
}

impl fmt::Display for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ip.fmt(f)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = MissingClientIp;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .ok_or(MissingClientIp)
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<ClientIp>().copied())
    }
}

/// Rejection for the [`ClientIp`] extractor when no address was resolved.
///
/// Either the route is not wrapped in an [`IpFilter`](crate::IpFilter) layer, or the
/// filter could not find an address and was configured to let such requests through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingClientIp;

impl fmt::Display for MissingClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("client IP address is not available; is the IpFilter layer installed?")
    }
}

impl std::error::Error for MissingClientIp {}

impl IntoResponse for MissingClientIp {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}
