use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use axum_ipware::ipware::{
    header,
    ClientIpResolver,
    ClientIpStrategy,
    IpRanges,
    IpWare,
    IpWareConfig,
    IpWareProxy,
};
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

/// Load balancers in 10.0.0.0/8 appending to X-Forwarded-For.
fn behind_proxy() -> ClientIpResolver {
    ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ))
    .trusted_proxies(IpRanges::parse(["10.0.0.0/8"]).unwrap())
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
async fn default_resolver_ignores_headers() {
    let filter = IpFilter::new().allow(["10.0.0.0/8"]).unwrap();
    let (status, _) = send(app(filter, Some("198.51.100.1")), Some("10.0.0.1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn uses_header_from_trusted_proxy() {
    let filter = IpFilter::new().resolver(behind_proxy());
    let (status, body) = send(
        app(filter, Some("10.0.0.2")),
        Some("6.6.6.6, 93.184.216.34, 10.0.0.5"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "header 93.184.216.34 true");
}

#[tokio::test]
async fn ignores_spoofed_header_from_direct_client() {
    let filter = IpFilter::new()
        .resolver(behind_proxy())
        .allow(["93.184.216.0/24"])
        .unwrap();
    let (status, body) = send(app(filter, Some("198.51.100.1")), Some("93.184.216.34")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Forbidden");
}

#[tokio::test]
async fn rules_apply_to_header_ip_from_trusted_proxy() {
    let filter = IpFilter::new()
        .resolver(behind_proxy())
        .block(["93.184.216.34"])
        .unwrap();
    let (status, _) = send(app(filter, Some("10.0.0.2")), Some("93.184.216.34")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn private_client_behind_trusted_proxy() {
    let filter = IpFilter::new()
        .resolver(
            ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
                header::X_FORWARDED_FOR,
            ))
            .trusted_proxies(IpRanges::parse(["10.0.0.0/24"]).unwrap()),
        )
        .allow(["10.1.0.0/16"])
        .unwrap();
    let (status, body) = send(app(filter, Some("10.0.0.2")), Some("10.1.2.3")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "header 10.1.2.3 true");
}

#[tokio::test]
async fn ipware_strategy_behind_trusted_proxy() {
    let ipware = IpWare::new(
        IpWareConfig::new(["x-forwarded-for"], true),
        IpWareProxy::new(1, vec![]),
    );
    let filter = IpFilter::new().resolver(
        ClientIpResolver::new(ClientIpStrategy::ipware(ipware, false))
            .trusted_proxies(IpRanges::parse(["10.0.0.0/8"]).unwrap()),
    );
    let (_, body) = send(
        app(filter.clone(), Some("10.0.0.2")),
        Some("93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(body, "header 93.184.216.34 true");
    let (_, body) = send(
        app(filter, Some("198.51.100.1")),
        Some("93.184.216.34, 10.0.0.2"),
    )
    .await;
    assert_eq!(body, "peer 198.51.100.1");
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

#[tokio::test]
async fn allow_and_block_parsed_ranges() {
    let filter = IpFilter::new()
        .allow_ranges(IpRanges::parse(["10.0.0.0/8"]).unwrap())
        .allow(["192.168.0.0/16"])
        .unwrap()
        .block_ranges(IpRanges::parse(["10.0.0.13"]).unwrap());
    for (peer, expected) in [
        ("10.1.2.3", StatusCode::OK),
        ("192.168.1.1", StatusCode::OK),
        ("10.0.0.13", StatusCode::FORBIDDEN),
        ("172.16.0.1", StatusCode::FORBIDDEN),
    ] {
        let (status, _) = send(app(filter.clone(), Some(peer)), None).await;
        assert_eq!(status, expected, "{peer}");
    }
}

#[tokio::test]
async fn empty_allow_set_fails_closed() {
    let filter = IpFilter::new().allow_ranges(IpRanges::new());
    let (status, _) = send(app(filter, Some("10.1.2.3")), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(feature = "providers")]
mod providers {
    use axum_ipware::ipware::providers::{self, Platform};

    use super::*;

    #[tokio::test]
    async fn cloudflare_preset() {
        let filter = IpFilter::new().resolver(ClientIpResolver::platform(Platform::Cloudflare));
        let req = Request::builder()
            .uri("/")
            .header("cf-connecting-ip", "93.184.216.34")
            .body(Body::empty())
            .unwrap();
        // 173.245.48.0/20 is a Cloudflare range.
        let res = app(filter.clone(), Some("173.245.48.10"))
            .oneshot(req)
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "header 93.184.216.34 true");

        let req = Request::builder()
            .uri("/")
            .header("cf-connecting-ip", "93.184.216.34")
            .body(Body::empty())
            .unwrap();
        let res = app(filter, Some("198.51.100.1"))
            .oneshot(req)
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "peer 198.51.100.1");
    }

    #[tokio::test]
    async fn github_webhook_allow_list() {
        let filter = IpFilter::new().allow_ranges(providers::github_hooks());
        // 140.82.112.0/20 is a GitHub hooks range.
        let (status, _) = send(app(filter.clone(), Some("140.82.112.1")), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(app(filter, Some("93.184.216.34")), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
