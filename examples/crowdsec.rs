//! A CrowdSec bouncer: block the IPs your CrowdSec agent bans.
//!
//! Register the bouncer with `cscli bouncers add axum-example`, then run:
//!
//! ```text
//! CROWDSEC_API_KEY=<key> cargo run --example crowdsec --features crowdsec
//! ```
//!
//! `CROWDSEC_LAPI_URL` defaults to `http://127.0.0.1:8080`. Try
//! `cscli decisions add --ip 127.0.0.1 --duration 2m`, wait up to 10 seconds, and
//! `curl http://127.0.0.1:3000/` gets 403 until the decision expires.

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use axum_ipware::crowdsec::CrowdSec;
use axum_ipware::IpFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("axum_ipware=info")
        .init();

    let url =
        std::env::var("CROWDSEC_LAPI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
    let key = std::env::var("CROWDSEC_API_KEY").map_err(|_| "set CROWDSEC_API_KEY")?;

    let filter = IpFilter::new();
    let bouncer = CrowdSec::new(&url, key)?.refresh(&filter.handle())?;
    if let Err(err) = bouncer.refresh_once().await {
        eprintln!("starting without CrowdSec decisions: {err}");
    }
    let _task = bouncer.spawn();

    let app = Router::new()
        .route("/", get(|| async { "not banned\n" }))
        .layer(filter);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
