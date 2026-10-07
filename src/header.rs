//! Names of headers proxies and CDNs use to pass the client IP.

use axum::http::HeaderName;

/// RFC 7239 `Forwarded`.
pub const FORWARDED: HeaderName = axum::http::header::FORWARDED;
/// `X-Forwarded-For`, a list appended to by each proxy.
pub const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
/// `X-Real-IP`, set by nginx.
pub const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
/// `CF-Connecting-IP`, set by Cloudflare.
pub const CF_CONNECTING_IP: HeaderName = HeaderName::from_static("cf-connecting-ip");
/// `True-Client-IP`, set by Akamai and Cloudflare Enterprise.
pub const TRUE_CLIENT_IP: HeaderName = HeaderName::from_static("true-client-ip");
/// `Fly-Client-IP`, set by Fly.io.
pub const FLY_CLIENT_IP: HeaderName = HeaderName::from_static("fly-client-ip");
/// `Fastly-Client-IP`, set by Fastly.
pub const FASTLY_CLIENT_IP: HeaderName = HeaderName::from_static("fastly-client-ip");
/// `X-Envoy-External-Address`, set by Envoy and Istio.
pub const X_ENVOY_EXTERNAL_ADDRESS: HeaderName =
    HeaderName::from_static("x-envoy-external-address");
