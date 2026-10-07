//! Rate limiting with tower_governor plus automatic bans for noisy clients.
//!
//! Run with `cargo run --example rate_limit --features governor,autoban`, then:
//!
//! ```text
//! # More than 5 quick requests get 429 Too Many Requests.
//! for i in $(seq 8); do curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/; done
//!
//! # 5 requests for missing pages within a minute ban the client for 2 minutes.
//! for i in $(seq 6); do curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/missing; done
//! ```
//!
//! Both use the client IP resolved by `IpFilter`, so a client cannot dodge them
//! by sending its own `X-Forwarded-For`.

use std::net::SocketAddr;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use axum_ipware::autoban::AutoBan;
use axum_ipware::governor::ClientIpKeyExtractor;
use axum_ipware::IpFilter;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("axum_ipware=info")
        .init();

    // One request per second on average, bursts of up to 5.
    let limits = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(5)
        .key_extractor(ClientIpKeyExtractor::new().ipv6_prefix(64))
        .finish()
        .ok_or("invalid rate limit")?;
    let autoban = AutoBan::new()
        .max_strikes(5)
        .window(Duration::from_secs(60))
        .ban_for(Duration::from_secs(2 * 60));

    // Layers added last run first: IpFilter resolves the client IP for the others.
    let app = Router::new()
        .route("/", get(|| async { "hello\n" }))
        .layer(GovernorLayer::new(limits))
        .layer(autoban)
        .layer(IpFilter::new());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
