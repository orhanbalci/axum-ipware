//! Country and ASN rules from MaxMind databases.
//!
//! Run with `cargo run --example geo --features geo -- <country.mmdb> [asn.mmdb]`,
//! using GeoLite2 databases from <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>.
//! Without arguments it uses the small test databases in `tests/data`.
//!
//! Requests from loopback are not in any database, so try the lookup endpoint:
//!
//! ```text
//! curl http://127.0.0.1:3000/lookup/89.160.20.112   # SE in the test database
//! curl http://127.0.0.1:3000/lookup/1.128.0.1       # AS1221 in the test database
//! ```

use std::net::{IpAddr, SocketAddr};

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Router;
use axum_ipware::geo::GeoDb;
use axum_ipware::{parse_rules, IpFilter};

async fn lookup(State(filter): State<IpFilter>, Path(ip): Path<IpAddr>) -> String {
    let verdict = match filter.check(ip) {
        Ok(()) => "allowed".to_owned(),
        Err(reason) => format!("rejected ({reason})"),
    };
    format!("{ip}: {verdict}\n")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let test_data = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
    let country = args
        .next()
        .unwrap_or_else(|| format!("{test_data}/GeoIP2-Country-Test.mmdb"));
    let asn = args
        .next()
        .unwrap_or_else(|| format!("{test_data}/GeoLite2-ASN-Test.mmdb"));
    let geo = GeoDb::new()
        .country_database(&country)?
        .asn_database(&asn)?;

    let filter = IpFilter::new().geo(geo).rules(parse_rules(
        "allow 127.0.0.0/8;
         allow ::1;
         deny country SE;
         deny asn 1221;
         allow all;",
    )?);

    // The lookup endpoint checks any IP against the rules, behind the filter itself.
    let app = Router::new()
        .route("/lookup/{ip}", get(lookup))
        .with_state(filter.clone())
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
