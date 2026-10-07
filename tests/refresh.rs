#![cfg(feature = "refresh")]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use axum_ipware::ipware::{header, ClientIpResolver, ClientIpStrategy};
use axum_ipware::refresh::{Refresh, RefreshError, Safeguards, Source};
use axum_ipware::{ClientIp, IpFilter, IpSource, RejectReason};
use tower::ServiceExt;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A source whose content the test can change.
fn text_source(initial: &str) -> (Source, Arc<Mutex<Result<String, String>>>) {
    let content = Arc::new(Mutex::new(Ok(initial.to_owned())));
    let shared = content.clone();
    let source = Source::from_fn(move || {
        let content = shared.lock().unwrap().clone();
        async move { content }
    });
    (source, content)
}

#[tokio::test]
async fn applies_block_list() {
    let filter = IpFilter::new();
    let (source, _) = text_source("# abuse\n203.0.113.0/24\n198.51.100.7 # single\n\n");
    let refresh = Refresh::block_list(&filter.handle(), "abuse").source(source);
    assert_eq!(filter.check(ip("203.0.113.9")), Ok(()));
    refresh.refresh_once().await.unwrap();
    assert_eq!(filter.check(ip("203.0.113.9")), Err(RejectReason::Blocked));
    assert_eq!(filter.check(ip("198.51.100.7")), Err(RejectReason::Blocked));
    assert_eq!(filter.check(ip("192.0.2.1")), Ok(()));
}

#[tokio::test]
async fn keeps_last_good_list_on_failures() {
    let filter = IpFilter::new();
    let (source, content) = text_source("203.0.113.0/24\n");
    let refresh = Refresh::block_list(&filter.handle(), "abuse").source(source);
    refresh.refresh_once().await.unwrap();

    *content.lock().unwrap() = Err("connection refused".to_owned());
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::Load(_))
    ));

    *content.lock().unwrap() = Ok("203.0.113.0/24\nnot-an-ip\n".to_owned());
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::Parse(_))
    ));

    *content.lock().unwrap() = Ok("# nothing\n".to_owned());
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::Empty)
    ));

    assert_eq!(filter.check(ip("203.0.113.9")), Err(RejectReason::Blocked));
}

#[tokio::test]
async fn rejects_too_broad_lists() {
    let filter = IpFilter::new();
    let (source, _) = text_source("0.0.0.0/0\n");
    let block = Refresh::block_list(&filter.handle(), "all").source(source.clone());
    assert!(matches!(
        block.refresh_once().await,
        Err(RefreshError::TooBroad)
    ));

    // A /8 is fine for a block list but too broad for an allow list.
    let (source, _) = text_source("10.0.0.0/7\n");
    let allow = Refresh::allow_list(&filter.handle(), "office").source(source);
    assert!(matches!(
        allow.refresh_once().await,
        Err(RefreshError::TooBroad)
    ));
    assert_eq!(filter.check(ip("11.0.0.1")), Ok(()));

    let (source, _) = text_source("::/0\n");
    let block = Refresh::block_list(&filter.handle(), "all6").source(source);
    assert!(matches!(
        block.refresh_once().await,
        Err(RefreshError::TooBroad)
    ));
}

#[tokio::test]
async fn rejects_sudden_shrink_and_growth() {
    let filter = IpFilter::new();
    let (source, content) = text_source("192.0.2.0/24\n");
    let refresh = Refresh::allow_list(&filter.handle(), "office").source(source);
    refresh.refresh_once().await.unwrap();

    *content.lock().unwrap() = Ok("192.0.2.0/26\n".to_owned());
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::ShrankTooMuch)
    ));

    *content.lock().unwrap() = Ok("192.0.0.0/22\n".to_owned());
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::GrewTooMuch)
    ));

    // Doubling is within the default growth limit.
    *content.lock().unwrap() = Ok("192.0.2.0/24\n198.51.100.0/24\n".to_owned());
    refresh.refresh_once().await.unwrap();
    assert_eq!(filter.check(ip("198.51.100.1")), Ok(()));

    // Custom safeguards can disable the change checks.
    let relaxed = refresh.clone().safeguards(
        Safeguards::for_allow_lists()
            .max_shrink(None)
            .max_growth(None),
    );
    *content.lock().unwrap() = Ok("192.0.2.1\n".to_owned());
    relaxed.refresh_once().await.unwrap();
    assert_eq!(
        filter.check(ip("198.51.100.1")),
        Err(RejectReason::NotAllowed)
    );
}

#[tokio::test]
async fn rejects_oversized_responses() {
    let filter = IpFilter::new();
    let (source, _) = text_source(&"192.0.2.1\n".repeat(100));
    let refresh = Refresh::block_list(&filter.handle(), "big")
        .source(source)
        .safeguards(Safeguards::for_block_lists().max_bytes(64));
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::TooLarge { limit: 64 })
    ));
}

#[tokio::test]
async fn file_source() {
    let path = std::env::temp_dir().join(format!("axum-ipware-test-{}.txt", std::process::id()));
    std::fs::write(&path, "203.0.113.0/24\n").unwrap();
    let filter = IpFilter::new();
    let refresh = Refresh::block_list(&filter.handle(), "file").source(Source::file(&path));
    refresh.refresh_once().await.unwrap();
    assert_eq!(filter.check(ip("203.0.113.9")), Err(RejectReason::Blocked));

    // The size limit is checked before reading.
    let small = refresh
        .clone()
        .safeguards(Safeguards::for_block_lists().max_bytes(4));
    assert!(matches!(
        small.refresh_once().await,
        Err(RefreshError::TooLarge { limit: 4 })
    ));

    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        refresh.refresh_once().await,
        Err(RefreshError::Load(_))
    ));
    assert_eq!(filter.check(ip("203.0.113.9")), Err(RejectReason::Blocked));
}

#[tokio::test]
async fn allow_list_with_default_deny() {
    let filter = IpFilter::new().default_deny(true);
    let (source, _) = text_source("192.0.2.0/24\n");
    let refresh = Refresh::allow_list(&filter.handle(), "office").source(source);
    assert_eq!(filter.check(ip("192.0.2.7")), Err(RejectReason::NotAllowed));
    refresh.refresh_once().await.unwrap();
    assert_eq!(filter.check(ip("192.0.2.7")), Ok(()));
    assert_eq!(
        filter.check(ip("198.51.100.1")),
        Err(RejectReason::NotAllowed)
    );
}

#[tokio::test]
async fn refreshes_trusted_proxies() {
    let filter = IpFilter::new();
    let resolver = ClientIpResolver::new(ClientIpStrategy::single_header(header::CF_CONNECTING_IP));
    let (source, _) = text_source("173.245.48.0/20\n");
    let refresh = Refresh::trusted_proxies(&filter.handle(), resolver).source(source);
    refresh.refresh_once().await.unwrap();

    let req = Request::builder()
        .header("cf-connecting-ip", "93.184.216.34")
        .extension(MockConnectInfo(SocketAddr::new(ip("173.245.48.10"), 443)))
        .body(Body::empty())
        .unwrap();
    let client_ip = filter.resolve(&req).unwrap();
    assert_eq!(client_ip.ip, ip("93.184.216.34"));
    assert_eq!(client_ip.source, IpSource::Header { trusted_route: true });
}

#[tokio::test(start_paused = true)]
async fn spawned_task_refreshes_on_interval() {
    let filter = IpFilter::new();
    let (source, content) = text_source("203.0.113.0/24\n");
    let task = Refresh::block_list(&filter.handle(), "abuse")
        .source(source)
        .every(Duration::from_secs(60))
        .spawn();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(task.last_success().is_some());
    assert_eq!(filter.check(ip("203.0.113.9")), Err(RejectReason::Blocked));

    *content.lock().unwrap() = Ok("198.51.100.0/24\n".to_owned());
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(filter.check(ip("203.0.113.9")), Ok(()));
    assert_eq!(filter.check(ip("198.51.100.9")), Err(RejectReason::Blocked));

    *content.lock().unwrap() = Err("down".to_owned());
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(task.last_error().unwrap().contains("down"));
    assert_eq!(filter.check(ip("198.51.100.9")), Err(RejectReason::Blocked));

    task.abort();
}

#[tokio::test]
async fn refreshed_list_applies_to_running_router() {
    async fn echo(client_ip: ClientIp) -> String {
        client_ip.to_string()
    }
    let filter = IpFilter::new();
    let (source, _) = text_source("203.0.113.0/24\n");
    let refresh = Refresh::block_list(&filter.handle(), "abuse").source(source);
    let router = Router::new()
        .route("/", get(echo))
        .layer(filter)
        .layer(MockConnectInfo(SocketAddr::new(ip("203.0.113.9"), 4000)));
    let send = |router: Router| async move {
        router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    };
    assert_eq!(send(router.clone()).await, StatusCode::OK);
    refresh.refresh_once().await.unwrap();
    assert_eq!(send(router).await, StatusCode::FORBIDDEN);
}

#[cfg(feature = "fetch")]
#[test]
fn https_source_rejects_other_schemes() {
    assert!(Source::https("http://example.com/list.txt").is_err());
    assert!(Source::https("file:///etc/hosts").is_err());
    assert!(Source::https("not a url").is_err());
    assert!(Source::https("https://example.com/list.txt").is_ok());
}

/// Fetches the live Tor exit list. Run with `cargo test --all-features -- --ignored`.
#[cfg(feature = "fetch")]
#[tokio::test]
#[ignore = "needs network access"]
async fn fetches_tor_exit_list() {
    let filter = IpFilter::new();
    let refresh = Refresh::block_list(&filter.handle(), "tor")
        .source(Source::https("https://check.torproject.org/torbulkexitlist").unwrap());
    refresh.refresh_once().await.unwrap();
    let debug = format!("{filter:?}");
    assert!(debug.contains("tor"), "{debug}");
}
