# axum-ipware

[![Crates.io](https://img.shields.io/crates/v/axum-ipware.svg)](https://crates.io/crates/axum-ipware)
[![Documentation](https://docs.rs/axum-ipware/badge.svg)](https://docs.rs/axum-ipware)
[![License](https://img.shields.io/github/license/orhanbalci/axum-ipware.svg)](https://github.com/orhanbalci/axum-ipware/blob/main/LICENSE)

<!-- cargo-rdme start -->

Client IP extraction and IP allow/block filtering middleware for
[axum](https://github.com/tokio-rs/axum), powered by
[ipware](https://github.com/orhanbalci/ipware).

### 📦 Cargo.toml

```toml
[dependencies]
axum-ipware = "0.1"
```

Enable the `providers` feature for platform presets and the published IP
ranges of CDNs, load balancers and webhook senders:

```toml
axum-ipware = { version = "0.1", features = ["providers"] }
```

### 🔧 Example

```rust
use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use axum_ipware::{ClientIp, IpFilter};

async fn handler(client_ip: ClientIp) -> String {
    format!("hello {client_ip}")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = IpFilter::new()
        .allow(["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1", "::1"])?
        .block(["10.0.0.13"])?;

    let app = Router::new().route("/", get(handler)).layer(filter);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    // ConnectInfo gives the filter the TCP peer address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
```

### 🤝 Behind a proxy

The client IP is resolved by ipware's
[`ClientIpResolver`](ipware::ClientIpResolver). Proxy headers are only read when
the TCP peer is one of your trusted proxies, so a client that reaches the app
directly cannot bypass the rules by sending its own headers.

```rust
use axum_ipware::ipware::{header, ClientIpResolver, ClientIpStrategy, IpRanges};
use axum_ipware::IpFilter;

// Load balancers in 10.0.0.0/8 append the client address to X-Forwarded-For.
let filter = IpFilter::new()
    .resolver(
        ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
            header::X_FORWARDED_FOR,
        ))
        .trusted_proxies(IpRanges::parse(["10.0.0.0/8"])?)
        .max_forwarded_hops(10),
    )
    .allow(["10.0.0.0/8", "192.168.0.0/16"])?;
```

[`ClientIpStrategy`](ipware::ClientIpStrategy) also covers a fixed proxy count,
the rightmost public address, single-IP CDN headers such as `CF-Connecting-IP`,
RFC 7239 `Forwarded`, ipware's own header lookup, and chains of these. Without a
resolver, the filter uses the peer address.

### 🌐 Platform presets and webhook allow lists

With the `providers` feature, ipware's presets configure the header and the
proxy ranges of a CDN or hosting platform: `Cloudflare`, `CloudFront`,
`Fastly`, `GoogleCloudLoadBalancer` and `FlyIo`.

```rust
use axum_ipware::ipware::providers::{self, Platform};
use axum_ipware::ipware::ClientIpResolver;
use axum_ipware::IpFilter;

// Behind Cloudflare: CF-Connecting-IP, trusted only from Cloudflare's ranges.
let filter = IpFilter::new().resolver(ClientIpResolver::platform(Platform::Cloudflare));

// A webhook endpoint that only accepts GitHub's delivery ranges.
let webhooks = IpFilter::new().allow_ranges(providers::github_hooks());
```

The built-in ranges are snapshots; see
[`ipware::providers`](https://docs.rs/ipware/latest/ipware/providers/) for
their date and for parsers to load fresh lists, which you can pass to
[`IpFilter::allow_ranges`] and [`IpFilter::block_ranges`].

### 🛑 Custom rejections

```rust
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_ipware::IpFilter;

let filter = IpFilter::new()
    .block(["203.0.113.0/24"])?
    .on_block(|rejection| {
        (StatusCode::NOT_FOUND, format!("{}", rejection.reason)).into_response()
    });
```

To filter only some routes, add the layer with
[`Router::route_layer`](axum::Router::route_layer) on a nested router.

<!-- cargo-rdme end -->
