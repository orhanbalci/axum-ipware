#![cfg(feature = "geo")]

use std::net::IpAddr;

use axum_ipware::geo::GeoDb;
use axum_ipware::{IpFilter, RejectReason, Rule};

const SWEDEN: &str = "89.160.20.112";
const BRITAIN: &str = "81.2.69.160";
const TELSTRA_AS1221: &str = "1.128.0.1";
const GOOGLE_AS15169: &str = "1.0.0.1";
const UNKNOWN: &str = "10.0.0.1";

fn db() -> GeoDb {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
    GeoDb::new()
        .country_database(format!("{dir}/GeoIP2-Country-Test.mmdb"))
        .unwrap()
        .asn_database(format!("{dir}/GeoLite2-ASN-Test.mmdb"))
        .unwrap()
}

fn check(filter: &IpFilter, ip: &str) -> Result<(), RejectReason> {
    filter.check(ip.parse::<IpAddr>().unwrap())
}

#[test]
fn block_countries() {
    let filter = IpFilter::new().geo(db()).block_countries(["se"]).unwrap();
    assert_eq!(check(&filter, SWEDEN), Err(RejectReason::Blocked));
    assert_eq!(check(&filter, BRITAIN), Ok(()));
    assert_eq!(check(&filter, UNKNOWN), Ok(()));
}

#[test]
fn allow_countries_rejects_unknown() {
    let filter = IpFilter::new().geo(db()).allow_countries(["GB"]).unwrap();
    assert_eq!(check(&filter, BRITAIN), Ok(()));
    assert_eq!(check(&filter, SWEDEN), Err(RejectReason::NotAllowed));
    assert_eq!(check(&filter, UNKNOWN), Err(RejectReason::NotAllowed));
}

#[test]
fn asn_lists() {
    let filter = IpFilter::new().geo(db()).block_asns([1221]);
    assert_eq!(check(&filter, TELSTRA_AS1221), Err(RejectReason::Blocked));
    assert_eq!(check(&filter, GOOGLE_AS15169), Ok(()));

    let filter = IpFilter::new().geo(db()).allow_asns([15169]);
    assert_eq!(check(&filter, GOOGLE_AS15169), Ok(()));
    assert_eq!(
        check(&filter, TELSTRA_AS1221),
        Err(RejectReason::NotAllowed)
    );
}

#[test]
fn geo_rules_in_ordered_rules() {
    let filter = IpFilter::new().geo(db()).rules(
        axum_ipware::parse_rules(
            "deny country SE;
             allow asn AS15169;
             allow country GB,NO;
             deny all;",
        )
        .unwrap(),
    );
    assert_eq!(check(&filter, SWEDEN), Err(RejectReason::DeniedByRule));
    assert_eq!(check(&filter, GOOGLE_AS15169), Ok(()));
    assert_eq!(check(&filter, BRITAIN), Ok(()));
    assert_eq!(
        check(&filter, TELSTRA_AS1221),
        Err(RejectReason::DeniedByRule)
    );

    let in_code = IpFilter::new().geo(db()).rules([
        Rule::deny_countries(["SE"]).unwrap(),
        Rule::deny_asns([1221]),
    ]);
    assert_eq!(check(&in_code, SWEDEN), Err(RejectReason::DeniedByRule));
    assert_eq!(
        check(&in_code, TELSTRA_AS1221),
        Err(RejectReason::DeniedByRule)
    );
    assert_eq!(check(&in_code, BRITAIN), Ok(()));
}

#[test]
fn databases_can_be_swapped_at_runtime() {
    let filter = IpFilter::new().block_countries(["SE"]).unwrap();
    // No database yet: country rules match nothing.
    assert_eq!(check(&filter, SWEDEN), Ok(()));
    filter.handle().set_geo(db());
    assert_eq!(check(&filter, SWEDEN), Err(RejectReason::Blocked));
}

#[test]
fn rejects_invalid_input() {
    assert!(IpFilter::new().block_countries(["Sweden"]).is_err());
    assert!(Rule::parse("deny country S").is_err());
    assert!(Rule::parse("deny asn google").is_err());
    assert!(GeoDb::new().asn_database("/nonexistent.mmdb").is_err());
}
