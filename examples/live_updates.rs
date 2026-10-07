//! Changing rules while the server runs, with ordered rules and request stats.
//!
//! Run with `cargo run --example live_updates`, then:
//!
//! ```text
//! curl http://127.0.0.1:3000/                       # allowed
//! curl -X POST http://127.0.0.1:3001/block/127.0.0.1 # block ourselves at runtime
//! curl http://127.0.0.1:3000/                       # 403 Forbidden
//! curl -X POST http://127.0.0.1:3001/unblock        # lift the block
//! curl http://127.0.0.1:3001/stats                  # allowed / blocked counts
//! ```
//!
//! The admin endpoints listen on a separate port so the public app's filter
//! cannot lock them out. Note the order of checks: ordered rules first, where
//! the first match decides, then block lists, then allow lists.

use std::future::IntoFuture;
use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::Router;
use axum_ipware::ipware::IpRanges;
use axum_ipware::{parse_rules, ClientIp, IpFilter, IpFilterHandle};

async fn hello(client_ip: ClientIp) -> String {
    format!("hello {client_ip}\n")
}

async fn block(State(handle): State<IpFilterHandle>, Path(range): Path<String>) -> String {
    match IpRanges::parse([&range]) {
        Ok(ranges) => {
            handle.set_block_list("admin", ranges);
            format!("blocked {range}\n")
        }
        Err(err) => format!("{err}\n"),
    }
}

async fn unblock(State(handle): State<IpFilterHandle>) -> &'static str {
    if handle.remove_block_list("admin") {
        "unblocked\n"
    } else {
        "nothing was blocked\n"
    }
}

async fn stats(State(handle): State<IpFilterHandle>) -> String {
    let stats = handle.stats();
    format!(
        "allowed {}, blocked {}, not allowed {}, denied by rule {}, unresolved {}\n",
        stats.allowed, stats.blocked, stats.not_allowed, stats.denied_by_rule, stats.unresolved
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("axum_ipware=debug")
        .init();

    // Ordered rules are checked first and the first match decides, so keep them
    // to the cases that must win over everything else.
    let filter = IpFilter::new()
        .rules(parse_rules(
            "deny 192.0.2.0/24; # a documentation range, as an example",
        )?)
        // Allow lists and block lists come next; a block list wins over allow lists,
        // which is what lets the admin endpoint block an allowed address.
        .allow(["127.0.0.0/8", "::1"])?;
    let handle = filter.handle();

    let app = Router::new().route("/", get(hello)).layer(filter);
    let admin = Router::new()
        .route("/block/{range}", post(block))
        .route("/unblock", post(unblock))
        .route("/stats", get(stats))
        .with_state(handle);

    let public = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    let private = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    println!("app on 127.0.0.1:3000, admin on 127.0.0.1:3001");
    tokio::try_join!(
        axum::serve(
            public,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .into_future(),
        axum::serve(private, admin).into_future(),
    )?;
    Ok(())
}
