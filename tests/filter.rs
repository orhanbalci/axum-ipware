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

mod live_updates {
    use std::net::IpAddr;

    use axum_ipware::IpFilterHandle;

    use super::*;

    fn ranges(list: &[&str]) -> IpRanges {
        IpRanges::parse(list).unwrap()
    }

    async fn status(router: &Router) -> StatusCode {
        send(router.clone(), None).await.0
    }

    #[tokio::test]
    async fn handle_changes_rules_of_running_router() {
        let filter = IpFilter::new();
        let handle = filter.handle();
        let router = app(filter, Some("203.0.113.9"));
        assert_eq!(status(&router).await, StatusCode::OK);

        handle.set_block_list("abuse", ranges(&["203.0.113.0/24"]));
        assert_eq!(status(&router).await, StatusCode::FORBIDDEN);

        // Replacing the named list drops the old ranges.
        handle.set_block_list("abuse", ranges(&["198.51.100.0/24"]));
        assert_eq!(status(&router).await, StatusCode::OK);

        handle.set_block_list("abuse", ranges(&["203.0.113.9"]));
        assert!(handle.remove_block_list("abuse"));
        assert!(!handle.remove_block_list("abuse"));
        assert_eq!(status(&router).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn named_allow_lists_are_independent() {
        let filter = IpFilter::new()
            .allow_list("office", ranges(&["192.0.2.0/24"]))
            .allow(["10.0.0.0/8"])
            .unwrap();
        let handle = filter.handle();
        let office = app(filter.clone(), Some("192.0.2.7"));
        let internal = app(filter, Some("10.1.2.3"));
        assert_eq!(status(&office).await, StatusCode::OK);

        handle.set_allow_list("office", ranges(&["198.51.100.0/24"]));
        assert_eq!(status(&office).await, StatusCode::FORBIDDEN);
        // The unnamed list is untouched.
        assert_eq!(status(&internal).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn default_deny_until_first_list_arrives() {
        let filter = IpFilter::new().default_deny(true);
        let handle = filter.handle();
        let router = app(filter, Some("192.0.2.7"));
        assert_eq!(status(&router).await, StatusCode::FORBIDDEN);

        handle.set_allow_list("office", ranges(&["192.0.2.0/24"]));
        assert_eq!(status(&router).await, StatusCode::OK);

        handle.set_default_deny(false);
        assert!(handle.remove_allow_list("office"));
        assert_eq!(status(&router).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn set_resolver_live() {
        let filter = IpFilter::new();
        let handle = filter.handle();
        let router = app(filter, Some("10.0.0.2"));
        let (_, body) = send(router.clone(), Some("93.184.216.34")).await;
        assert_eq!(body, "peer 10.0.0.2");

        handle.set_resolver(behind_proxy());
        let (_, body) = send(router, Some("93.184.216.34")).await;
        assert_eq!(body, "header 93.184.216.34 true");
    }

    #[tokio::test]
    async fn clones_share_rules() {
        let filter = IpFilter::new();
        let router = app(filter.clone(), Some("203.0.113.9"));
        let _ = filter.block(["203.0.113.9"]).unwrap();
        assert_eq!(status(&router).await, StatusCode::FORBIDDEN);
    }

    #[test]
    fn check_and_resolve_parts() {
        let filter = IpFilter::new()
            .allow(["10.0.0.0/8"])
            .unwrap()
            .block(["10.0.0.13"])
            .unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(filter.check(ip("10.1.2.3")), Ok(()));
        assert_eq!(filter.check(ip("10.0.0.13")), Err(RejectReason::Blocked));
        assert_eq!(filter.check(ip("192.0.2.1")), Err(RejectReason::NotAllowed));
        assert_eq!(filter.check(ip("::ffff:10.1.2.3")), Ok(()));

        let (parts, ()) = Request::builder()
            .extension(MockConnectInfo(SocketAddr::new(ip("10.1.2.3"), 4000)))
            .body(())
            .unwrap()
            .into_parts();
        let client_ip = filter.resolve_parts(&parts).unwrap();
        assert_eq!(client_ip.ip, ip("10.1.2.3"));
        assert_eq!(client_ip.source, IpSource::Peer);
    }

    #[tokio::test]
    async fn updates_during_concurrent_requests() {
        let filter = IpFilter::new();
        let handle: IpFilterHandle = filter.handle();
        let router = app(filter, Some("203.0.113.9"));
        let requests = (0..200).map(|_| {
            let router = router.clone();
            tokio::spawn(async move { send(router, None).await.0 })
        });
        let requests: Vec<_> = requests.collect();
        for i in 0..200 {
            if i % 2 == 0 {
                handle.set_block_list("flip", ranges(&["203.0.113.9"]));
            } else {
                handle.remove_block_list("flip");
            }
        }
        for request in requests {
            let status = request.await.unwrap();
            assert!(status == StatusCode::OK || status == StatusCode::FORBIDDEN);
        }
    }
}

mod filter_api {
    use std::sync::{Arc, Mutex};

    use axum_ipware::{parse_rules, Allowed, FilterStats, Rule};

    use super::*;

    async fn status(filter: &IpFilter, peer: &str) -> StatusCode {
        send(app(filter.clone(), Some(peer)), None).await.0
    }

    #[tokio::test]
    async fn ordered_rules_first_match_wins() {
        let filter = IpFilter::new()
            .rules(
                parse_rules(
                    "deny 10.0.0.13;
                     allow 10.0.0.0/8;
                     deny all;",
                )
                .unwrap(),
            )
            .block(["10.1.2.3"])
            .unwrap();
        assert_eq!(status(&filter, "10.0.0.13").await, StatusCode::FORBIDDEN);
        // An ordered allow decides before the block lists.
        assert_eq!(status(&filter, "10.1.2.3").await, StatusCode::OK);
        assert_eq!(status(&filter, "192.0.2.1").await, StatusCode::FORBIDDEN);
        assert_eq!(
            filter.check("192.0.2.1".parse().unwrap()),
            Err(RejectReason::DeniedByRule)
        );
    }

    #[tokio::test]
    async fn rules_fall_through_to_lists() {
        let filter = IpFilter::new()
            .rules([Rule::deny(IpRanges::parse(["203.0.113.0/24"]).unwrap())])
            .allow(["192.0.2.0/24"])
            .unwrap();
        assert_eq!(status(&filter, "203.0.113.9").await, StatusCode::FORBIDDEN);
        assert_eq!(status(&filter, "192.0.2.9").await, StatusCode::OK);
        assert_eq!(status(&filter, "198.51.100.9").await, StatusCode::FORBIDDEN);
        assert_eq!(
            filter.check("198.51.100.9".parse().unwrap()),
            Err(RejectReason::NotAllowed)
        );
    }

    #[tokio::test]
    async fn handle_replaces_rules() {
        let filter = IpFilter::new();
        let handle = filter.handle();
        assert_eq!(status(&filter, "192.0.2.1").await, StatusCode::OK);
        handle.set_rules([Rule::deny_all()]);
        assert_eq!(status(&filter, "192.0.2.1").await, StatusCode::FORBIDDEN);
        handle.set_rules([]);
        assert_eq!(status(&filter, "192.0.2.1").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn on_allow_and_on_block_see_the_request() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let log = seen.clone();
        let filter = IpFilter::new()
            .block(["203.0.113.9"])
            .unwrap()
            .on_allow(move |allowed: &Allowed<'_>| {
                let ip = allowed.client_ip.map(|client_ip| client_ip.ip.to_string());
                log.lock().unwrap().push(format!(
                    "{} {} {}",
                    allowed.method,
                    allowed.uri,
                    ip.unwrap_or_default()
                ));
            })
            .on_block(|rejection| {
                assert_eq!(rejection.method, axum::http::Method::GET);
                rejection.clone().into_response()
            });
        assert_eq!(status(&filter, "192.0.2.1").await, StatusCode::OK);
        assert_eq!(status(&filter, "203.0.113.9").await, StatusCode::FORBIDDEN);
        assert_eq!(*seen.lock().unwrap(), vec!["GET / 192.0.2.1".to_owned()]);
    }

    #[tokio::test]
    async fn stats_count_outcomes() {
        let filter = IpFilter::new()
            .rules([Rule::parse("deny 198.51.100.0/24").unwrap()])
            .allow(["192.0.2.0/24"])
            .unwrap()
            .block(["192.0.2.13"])
            .unwrap();
        for peer in [
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.13",
            "203.0.113.1",
            "198.51.100.1",
        ] {
            status(&filter, peer).await;
        }
        send(app(filter.clone(), None), None).await;
        let stats = filter.handle().stats();
        assert_eq!(stats, filter.stats());
        let expected = (2, 1, 1, 1, 1);
        assert_eq!(
            (
                stats.allowed,
                stats.blocked,
                stats.not_allowed,
                stats.denied_by_rule,
                stats.unresolved
            ),
            expected
        );
        assert_ne!(stats, FilterStats::default());
    }

    #[cfg(feature = "glob")]
    #[tokio::test]
    async fn glob_patterns() {
        let filter = IpFilter::new()
            .allow_patterns(["192.168.1.*", "10.?.0.1"])
            .unwrap()
            .block_patterns(["192.168.1.13"])
            .unwrap();
        assert_eq!(status(&filter, "192.168.1.200").await, StatusCode::OK);
        assert_eq!(status(&filter, "10.5.0.1").await, StatusCode::OK);
        assert_eq!(status(&filter, "10.55.0.1").await, StatusCode::FORBIDDEN);
        assert_eq!(status(&filter, "192.168.1.13").await, StatusCode::FORBIDDEN);
        assert_eq!(status(&filter, "192.168.10.1").await, StatusCode::FORBIDDEN);
        assert!(IpFilter::new().allow_patterns(["192.168.1.x"]).is_err());

        let rules =
            IpFilter::new().rules([Rule::deny_pattern("172.16.*").unwrap(), Rule::allow_all()]);
        assert_eq!(status(&rules, "172.16.5.5").await, StatusCode::FORBIDDEN);
        assert_eq!(status(&rules, "172.17.5.5").await, StatusCode::OK);
    }
}

mod client_origin {
    use axum_ipware::ClientOrigin;

    use super::*;

    async fn origin(origin: ClientOrigin) -> String {
        format!(
            "{} {}",
            origin.scheme.unwrap_or_default(),
            origin.host.unwrap_or_default()
        )
    }

    async fn request(router: Router, peer: Option<&str>) -> String {
        let req = Request::builder()
            .uri("/")
            .header("x-forwarded-proto", "https")
            .header("forwarded", "for=93.184.216.34;host=App.Example.com");
        let router = match peer {
            Some(peer) => router.layer(MockConnectInfo(SocketAddr::new(
                peer.parse().unwrap(),
                4000,
            ))),
            None => router,
        };
        let res = router
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn from_trusted_proxy() {
        let router = Router::new()
            .route("/", get(origin))
            .layer(IpFilter::new().resolver(behind_proxy()));
        assert_eq!(
            request(router, Some("10.0.0.2")).await,
            "https app.example.com"
        );
    }

    #[tokio::test]
    async fn ignored_from_direct_clients_and_without_filter() {
        let router = Router::new()
            .route("/", get(origin))
            .layer(IpFilter::new().resolver(behind_proxy()));
        assert_eq!(request(router, Some("198.51.100.1")).await, " ");
        let without_filter = Router::new().route("/", get(origin));
        assert_eq!(request(without_filter, Some("10.0.0.2")).await, " ");
    }
}
