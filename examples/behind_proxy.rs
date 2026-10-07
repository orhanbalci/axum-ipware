//! An app behind a reverse proxy or load balancer.
//!
//! Run with `cargo run --example behind_proxy`. Loopback counts as the trusted
//! proxy here, so curl can play the proxy:
//!
//! ```text
//! # Through the "proxy": the client IP, scheme and host come from the headers.
//! curl -H 'X-Forwarded-For: 203.0.113.9, 10.0.0.5' \
//!      -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: app.example.com' \
//!      http://127.0.0.1:3000/
//!
//! # A forged leftmost entry is ignored: the walk stops at the first untrusted IP.
//! curl -H 'X-Forwarded-For: 1.1.1.1, 203.0.113.9' http://127.0.0.1:3000/
//! ```
//!
//! In production, list your proxies' real ranges in `trusted_proxies` instead of
//! trusting loopback, and only reach the app through them.

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use axum_ipware::ipware::{header, ClientIpResolver, ClientIpStrategy, IpRanges};
use axum_ipware::{ClientIp, ClientOrigin, IpFilter, IpSource};

async fn whoami(client_ip: ClientIp, origin: ClientOrigin) -> String {
    let source = match client_ip.source {
        IpSource::Header { .. } => "proxy header",
        IpSource::Peer => "TCP peer",
    };
    format!(
        "client {} (from {source}), requested {}://{}\n",
        client_ip.ip,
        origin.scheme.as_deref().unwrap_or("?"),
        origin.host.as_deref().unwrap_or("?"),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Skip trusted proxies from the right of X-Forwarded-For; the first address
    // that is not a proxy is the client.
    let resolver = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ))
    .trusted_proxies(IpRanges::parse(["10.0.0.0/8"])?)
    .trust_loopback(true)
    .max_forwarded_hops(10);

    let app = Router::new()
        .route("/", get(whoami))
        .layer(IpFilter::new().resolver(resolver));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
