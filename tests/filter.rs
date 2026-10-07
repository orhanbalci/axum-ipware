use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use axum_ipware::ipware::{IpWare, IpWareConfig, IpWareProxy};
use axum_ipware::{ClientIp, IpFilter, IpSource, RejectReason};
use tower::ServiceExt;

async fn echo(client_ip: Option<ClientIp>) -> String {
    match client_ip {
        Some(ClientIp { ip, source: IpSource::Peer }) => format!("peer {ip}"),
        Some(ClientIp { ip, source: IpSource::Header { trusted_route } }) => {
            format!("header {ip} {trusted_route}")
        }
        None => "none".to_owned(),
    }
}

fn app(filter: IpFilter, peer: Option<&str>) -> Router {
    let router = Router::new().route("/", get(echo)).layer(filter);
    match peer {
        Some(peer) => router.layer(MockConnectInfo(SocketAddr::new(
            peer.parse().unwrap(),
            4000,
        ))),
        None => router,
    }
}

fn proxied(count: u16) -> IpWare {
    IpWare::new(
        IpWareConfig::new(["x-forwarded-for"], true),
        IpWareProxy::new(count, vec![]),
    )
}

async fn send(app: Router, xff: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder().uri("/");
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn resolves_peer_without_rules() {
    let (status, body) = send(app(IpFilter::new(), Some("203.0.113.7")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "peer 203.0.113.7");
}

#[tokio::test]
async fn passes_without_rules_or_ip() {
    let (status, body) = send(app(IpFilter::new(), None), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "none");
}

#[tokio::test]
async fn allow_list() {
    let filter = IpFilter::new().allow(["10.0.0.0/8"]).unwrap();
    let (status, _) = send(app(filter.clone(), Some("10.1.2.3")), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(app(filter, Some("192.168.1.1")), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn block_wins_over_allow() {
    let filter = IpFilter::new()
        .allow(["10.0.0.0/8"])
        .unwrap()
        .block(["10.0.0.13"])
        .unwrap();
    let (status, _) = send(app(filter.clone(), Some("10.0.0.13")), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(app(filter, Some("10.0.0.14")), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn rejects_unresolved_ip_when_rules_exist() {
    let filter = IpFilter::new().block(["10.0.0.13"]).unwrap();
    let (status, _) = send(app(filter, None), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ignores_untrusted_headers() {
    let filter = IpFilter::new().allow(["10.0.0.0/8"]).unwrap();
    let (status, _) = send(app(filter, Some("198.51.100.1")), Some("10.0.0.1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn uses_header_on_trusted_route() {
    let filter = IpFilter::new()
        .ipware(proxied(1))
        .trusted_proxies(["10.0.0.0/8"])
        .unwrap();
    let (status, body) = send(
        app(filter, Some("10.0.0.2")),
        Some("6.6.6.6, 93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "header 93.184.216.34 true");
}

#[tokio::test]
async fn ignores_headers_without_trusted_proxies() {
    let filter = IpFilter::new().ipware(proxied(1));
    let (_, body) = send(
        app(filter, Some("10.0.0.2")),
        Some("93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(body, "peer 10.0.0.2");
}

#[tokio::test]
async fn ignores_spoofed_header_from_direct_client() {
    let filter = IpFilter::new()
        .ipware(proxied(1))
        .trusted_proxies(["10.0.0.0/8"])
        .unwrap()
        .allow(["93.184.216.0/24"])
        .unwrap();
    // The client connects directly and forges a route that ipware would accept.
    let (status, body) = send(
        app(filter, Some("198.51.100.1")),
        Some("93.184.216.34, 198.51.100.1"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Forbidden");
}

#[tokio::test]
async fn trusted_proxy_without_verified_route_uses_peer() {
    // Default ipware has no proxy count or list, so it cannot verify the route.
    let filter = IpFilter::new().trusted_proxies(["10.0.0.0/8"]).unwrap();
    let (_, body) = send(
        app(filter, Some("10.0.0.2")),
        Some("93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(body, "peer 10.0.0.2");
}

#[tokio::test]
async fn rules_apply_to_header_ip_from_trusted_proxy() {
    let filter = IpFilter::new()
        .ipware(proxied(1))
        .trusted_proxies(["10.0.0.0/8"])
        .unwrap()
        .block(["93.184.216.34"])
        .unwrap();
    let (status, _) = send(
        app(filter, Some("10.0.0.2")),
        Some("93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ipv4_mapped_peer_matches_trusted_proxies() {
    let filter = IpFilter::new()
        .ipware(proxied(1))
        .trusted_proxies(["10.0.0.0/8"])
        .unwrap();
    let (_, body) = send(
        app(filter, Some("::ffff:10.0.0.2")),
        Some("93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(body, "header 93.184.216.34 true");
}

#[tokio::test]
async fn allow_untrusted_uses_header() {
    let filter = IpFilter::new().allow_untrusted(true);
    let (_, body) = send(app(filter, Some("10.0.0.2")), Some("203.0.113.7")).await;
    assert_eq!(body, "header 203.0.113.7 false");
}

#[tokio::test]
async fn ipv4_mapped_peer_matches_ipv4_rules() {
    let filter = IpFilter::new().allow(["192.0.2.0/24"]).unwrap();
    let (status, body) = send(app(filter, Some("::ffff:192.0.2.1")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "peer 192.0.2.1");
}

#[tokio::test]
async fn custom_block_response() {
    let filter = IpFilter::new()
        .block(["192.0.2.1"])
        .unwrap()
        .on_block(|rejection| {
            assert_eq!(rejection.reason, RejectReason::Blocked);
            (StatusCode::NOT_FOUND, rejection.reason.to_string()).into_response()
        });
    let (status, body) = send(app(filter, Some("192.0.2.1")), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "blocked");
}

#[tokio::test]
async fn extractor_without_layer_is_internal_error() {
    async fn handler(client_ip: ClientIp) -> String {
        client_ip.to_string()
    }
    let app = Router::new().route("/", get(handler));
    let (status, _) = send(app, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
