//! Blocking Tor exit nodes with a list refreshed hourly over HTTPS.
//!
//! Run with `cargo run --example refresh --features fetch`, then
//! `curl http://127.0.0.1:3000/`. Requests through Tor would get 403.
//!
//! The first load happens before the server starts; later refreshes run in the
//! background and are logged. A failed or suspicious refresh (empty, too large,
//! suddenly half the size) keeps the list in use.

use std::net::SocketAddr;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use axum_ipware::refresh::{Refresh, Source};
use axum_ipware::{ClientIp, IpFilter};

async fn hello(client_ip: ClientIp) -> String {
    format!("hello {client_ip}, you are not a Tor exit node\n")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("axum_ipware=info")
        .init();

    let filter = IpFilter::new();
    let tor = Refresh::block_list(&filter.handle(), "tor")
        .source(Source::https(
            "https://check.torproject.org/torbulkexitlist",
        )?)
        .every(Duration::from_secs(60 * 60))
        .stale_after(Duration::from_secs(6 * 60 * 60));

    // Load once before serving, then keep refreshing in the background.
    if let Err(err) = tor.refresh_once().await {
        eprintln!("starting without the Tor list: {err}");
    }
    let task = tor.spawn();

    let app = Router::new().route("/", get(hello)).layer(filter.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!(
        "listening on {}; Tor list loaded: {}",
        listener.local_addr()?,
        task.last_success().is_some()
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
