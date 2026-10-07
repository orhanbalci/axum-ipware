//! Run with `cargo run --example basic`, then `curl http://127.0.0.1:3000/`.

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use axum_ipware::{ClientIp, IpFilter};

async fn handler(client_ip: ClientIp) -> String {
    format!("hello {client_ip}\n")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = IpFilter::new().allow(["127.0.0.1", "::1"])?;
    let app = Router::new().route("/", get(handler)).layer(filter);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
