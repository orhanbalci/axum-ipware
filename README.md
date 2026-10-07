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

Proxy headers such as `X-Forwarded-For` are only trusted when ipware can verify
the proxy route. Tell it how many proxies sit in front of the app, or which ones:

```rust
use axum_ipware::ipware::{IpWare, IpWareConfig, IpWareProxy};
use axum_ipware::IpFilter;

// One load balancer appends the client address to X-Forwarded-For.
let filter = IpFilter::new().ipware(IpWare::new(
    IpWareConfig::new(["x-forwarded-for"], true),
    IpWareProxy::new(1, vec![]),
));
```

Without a verified route the filter uses the TCP peer address, so a client cannot
bypass the rules by sending its own headers.

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
