#![cfg(feature = "crowdsec")]

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
use axum_ipware::crowdsec::CrowdSec;
use axum_ipware::refresh::RefreshError;
use axum_ipware::{IpFilter, RejectReason};

#[derive(Default)]
struct Lapi {
    responses: VecDeque<(StatusCode, String)>,
    /// `startup` value of each request, and whether the API key was right.
    requests: Vec<(String, bool)>,
}

type Shared = Arc<Mutex<Lapi>>;

async fn stream(
    State(lapi): State<Shared>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> (StatusCode, String) {
    let mut lapi = lapi.lock().unwrap();
    let key_ok = headers.get("x-api-key").is_some_and(|key| key == "secret");
    lapi.requests
        .push((query.get("startup").cloned().unwrap_or_default(), key_ok));
    if !key_ok {
        return (StatusCode::FORBIDDEN, "{}".to_owned());
    }
    lapi.responses
        .pop_front()
        .unwrap_or((StatusCode::OK, r#"{"new":null,"deleted":null}"#.to_owned()))
}

async fn start_lapi() -> (SocketAddr, Shared) {
    let lapi = Shared::default();
    let app = Router::new()
        .route("/v1/decisions/stream", get(stream))
        .with_state(lapi.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, lapi)
}

fn respond(lapi: &Shared, status: StatusCode, body: &str) {
    lapi.lock()
        .unwrap()
        .responses
        .push_back((status, body.to_owned()));
}

fn check(filter: &IpFilter, ip: &str) -> Result<(), RejectReason> {
    filter.check(ip.parse::<IpAddr>().unwrap())
}

#[tokio::test]
async fn follows_the_decision_stream() {
    let (addr, lapi) = start_lapi().await;
    let filter = IpFilter::new();
    let bouncer = CrowdSec::new(&format!("http://{addr}"), "secret")
        .unwrap()
        .refresh(&filter.handle())
        .unwrap();

    respond(
        &lapi,
        StatusCode::OK,
        r#"{"new":[
        {"id":1,"scope":"Ip","type":"ban","value":"203.0.113.9","origin":"crowdsec"},
        {"id":2,"scope":"Range","type":"ban","value":"198.51.100.0/24","origin":"lists"}
    ],"deleted":null}"#,
    );
    bouncer.refresh_once().await.unwrap();
    assert_eq!(check(&filter, "203.0.113.9"), Err(RejectReason::Blocked));
    assert_eq!(check(&filter, "198.51.100.7"), Err(RejectReason::Blocked));

    respond(
        &lapi,
        StatusCode::OK,
        r#"{"new":[
        {"id":3,"scope":"Ip","type":"ban","value":"192.0.2.7"}
    ],"deleted":[{"id":2,"scope":"Range","type":"ban","value":"198.51.100.0/24"}]}"#,
    );
    bouncer.refresh_once().await.unwrap();
    assert_eq!(check(&filter, "198.51.100.7"), Ok(()));
    assert_eq!(check(&filter, "192.0.2.7"), Err(RejectReason::Blocked));

    // A failed poll keeps the list and triggers a full resync.
    respond(&lapi, StatusCode::INTERNAL_SERVER_ERROR, "oops");
    assert!(matches!(
        bouncer.refresh_once().await,
        Err(RefreshError::Load(_))
    ));
    assert_eq!(check(&filter, "203.0.113.9"), Err(RejectReason::Blocked));
    respond(
        &lapi,
        StatusCode::OK,
        r#"{"new":[
        {"id":1,"scope":"Ip","type":"ban","value":"203.0.113.9"}
    ],"deleted":null}"#,
    );
    bouncer.refresh_once().await.unwrap();
    assert_eq!(check(&filter, "192.0.2.7"), Ok(()));
    assert_eq!(check(&filter, "203.0.113.9"), Err(RejectReason::Blocked));

    // All bans expired: the empty list is applied.
    respond(
        &lapi,
        StatusCode::OK,
        r#"{"new":null,"deleted":[{"id":1}]}"#,
    );
    bouncer.refresh_once().await.unwrap();
    assert_eq!(check(&filter, "203.0.113.9"), Ok(()));

    let requests = lapi.lock().unwrap().requests.clone();
    let startups: Vec<&str> = requests
        .iter()
        .map(|(startup, _)| startup.as_str())
        .collect();
    assert_eq!(startups, ["true", "false", "false", "true", "false"]);
    assert!(requests.iter().all(|(_, key_ok)| *key_ok));
}

#[tokio::test]
async fn wrong_api_key_keeps_the_list() {
    let (addr, lapi) = start_lapi().await;
    let filter = IpFilter::new();
    let bouncer = CrowdSec::new(&format!("http://{addr}"), "wrong")
        .unwrap()
        .refresh(&filter.handle())
        .unwrap();
    assert!(matches!(
        bouncer.refresh_once().await,
        Err(RefreshError::Load(_))
    ));
    assert_eq!(lapi.lock().unwrap().requests, [("true".to_owned(), false)]);
}
