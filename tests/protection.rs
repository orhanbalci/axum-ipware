#![cfg(any(feature = "governor", feature = "autoban"))]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

/// Sends `GET path` from `peer` with an optional spoofed `X-Forwarded-For`.
async fn send(router: &Router, peer: &str, path: &str, xff: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .uri(path)
        .extension(MockConnectInfo(SocketAddr::new(
            peer.parse().unwrap(),
            4000,
        )));
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[cfg(feature = "governor")]
mod governor {
    use std::sync::Arc;

    use axum::routing::get;
    use axum_ipware::governor::ClientIpKeyExtractor;
    use axum_ipware::ipware::ClientIpResolver;
    use axum_ipware::IpFilter;
    use tower_governor::governor::GovernorConfigBuilder;
    use tower_governor::GovernorLayer;

    use super::*;

    fn limited(extractor: ClientIpKeyExtractor) -> Router {
        let config = GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(2)
            .key_extractor(extractor)
            .finish()
            .unwrap();
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(GovernorLayer::new(Arc::new(config)))
    }

    #[tokio::test]
    async fn limits_by_resolved_client_ip() {
        let router = limited(ClientIpKeyExtractor::new()).layer(IpFilter::new());
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::OK
        );
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::OK
        );
        // A new spoofed X-Forwarded-For value does not reset the limit.
        let spoofed = send(&router, "203.0.113.9", "/", Some("198.51.100.77")).await;
        assert_eq!(spoofed, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            send(&router, "203.0.113.10", "/", None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn groups_ipv6_networks() {
        let router = limited(ClientIpKeyExtractor::new().ipv6_prefix(64)).layer(IpFilter::new());
        assert_eq!(
            send(&router, "2001:db8:1:2::1", "/", None).await,
            StatusCode::OK
        );
        assert_eq!(
            send(&router, "2001:db8:1:2::2", "/", None).await,
            StatusCode::OK
        );
        let same_network = send(&router, "2001:db8:1:2::3", "/", None).await;
        assert_eq!(same_network, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            send(&router, "2001:db8:1:3::1", "/", None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn resolves_without_ip_filter() {
        let router =
            limited(ClientIpKeyExtractor::new().with_resolver(ClientIpResolver::default()));
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::OK
        );
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::OK
        );
        let third = send(&router, "203.0.113.9", "/", None).await;
        assert_eq!(third, StatusCode::TOO_MANY_REQUESTS);

        // Without a filter or resolver there is no key.
        let router = limited(ClientIpKeyExtractor::new());
        let status = send(&router, "203.0.113.9", "/", None).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[cfg(feature = "autoban")]
mod autoban {
    use std::time::Duration;

    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum_ipware::autoban::AutoBan;
    use axum_ipware::IpFilter;

    use super::*;

    fn app(autoban: &AutoBan) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(autoban.clone())
            .layer(IpFilter::new())
    }

    #[tokio::test]
    async fn bans_after_repeated_errors() {
        let autoban = AutoBan::new()
            .max_strikes(3)
            .ban_for(Duration::from_secs(60));
        let router = app(&autoban);
        for _ in 0..2 {
            assert_eq!(
                send(&router, "203.0.113.9", "/missing", None).await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::OK
        );
        assert_eq!(
            send(&router, "203.0.113.9", "/missing", None).await,
            StatusCode::NOT_FOUND
        );

        // Banned: even valid pages are refused, other clients are unaffected.
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(&router, "203.0.113.10", "/", None).await,
            StatusCode::OK
        );
        assert!(autoban.is_banned("203.0.113.9".parse().unwrap()));

        autoban.unban("203.0.113.9".parse().unwrap());
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn custom_ban_response() {
        let autoban = AutoBan::new().max_strikes(1).on_ban(|ip| {
            (StatusCode::TOO_MANY_REQUESTS, format!("{ip} is banned")).into_response()
        });
        let router = app(&autoban);
        send(&router, "203.0.113.9", "/missing", None).await;
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn rejections_from_ip_filter_do_not_count() {
        // IpFilter rejects before AutoBan runs, so its 403s are not strikes.
        let autoban = AutoBan::new().max_strikes(1);
        let router = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(autoban.clone())
            .layer(IpFilter::new().block(["203.0.113.9"]).unwrap());
        assert_eq!(
            send(&router, "203.0.113.9", "/", None).await,
            StatusCode::FORBIDDEN
        );
        assert!(autoban.banned().is_empty());
    }
}
