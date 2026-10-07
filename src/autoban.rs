//! Temporarily ban clients that collect too many error responses, like fail2ban.
//! Requires the `autoban` feature.
//!
//! ```rust
//! use std::time::Duration;
//!
//! use axum::routing::get;
//! use axum::Router;
//! use axum_ipware::autoban::AutoBan;
//! use axum_ipware::IpFilter;
//!
//! // Ban for 15 minutes after 20 responses of 401, 403, 404 or 429 within a minute.
//! let autoban = AutoBan::new()
//!     .max_strikes(20)
//!     .window(Duration::from_secs(60))
//!     .ban_for(Duration::from_secs(15 * 60));
//!
//! // Layers added last run first: IpFilter resolves the IP before AutoBan sees it.
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(autoban.clone())
//!     .layer(IpFilter::new());
//!
//! // Later: inspect or lift bans.
//! autoban.unban("203.0.113.9".parse().unwrap());
//! ```

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use ipware::IpRanges;
use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;

use crate::client_ip::ClientIp;
use crate::filter::mask_v6;

type BanHandler = Arc<dyn Fn(IpAddr) -> Response + Send + Sync>;

/// A layer that bans client IPs after too many matching responses.
///
/// It reads the [`ClientIp`] set by an outer [`IpFilter`](crate::IpFilter) layer;
/// requests without one pass through untouched. Banned clients get
/// `403 Forbidden` (see [`on_ban`](Self::on_ban)) until the ban expires.
///
/// Clones share their state, so keep a clone to inspect or lift bans.
#[derive(Clone)]
pub struct AutoBan {
    shared: Arc<Shared>,
}

struct Shared {
    config: Config,
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

#[derive(Clone)]
struct Config {
    statuses: Vec<StatusCode>,
    max_strikes: u32,
    window: Duration,
    ban_for: Duration,
    max_tracked: usize,
    exempt: IpRanges,
    ipv6_prefix: u8,
    on_ban: Option<BanHandler>,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    strikes: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

impl Default for AutoBan {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoBan {
    /// Bans for 10 minutes after 10 responses of 401, 403, 404 or 429 within a
    /// minute, tracking up to 100,000 clients and grouping IPv6 clients by `/64`.
    pub fn new() -> Self {
        AutoBan {
            shared: Arc::new(Shared {
                config: Config {
                    statuses: vec![
                        StatusCode::UNAUTHORIZED,
                        StatusCode::FORBIDDEN,
                        StatusCode::NOT_FOUND,
                        StatusCode::TOO_MANY_REQUESTS,
                    ],
                    max_strikes: 10,
                    window: Duration::from_secs(60),
                    ban_for: Duration::from_secs(10 * 60),
                    max_tracked: 100_000,
                    exempt: IpRanges::new(),
                    ipv6_prefix: 64,
                    on_ban: None,
                },
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn configure(mut self, f: impl FnOnce(&mut Config)) -> Self {
        let mut config = self.shared.config.clone();
        f(&mut config);
        self.shared = Arc::new(Shared { config, entries: Mutex::new(HashMap::new()) });
        self
    }

    /// Response statuses that count as a strike.
    pub fn statuses(self, statuses: impl IntoIterator<Item = StatusCode>) -> Self {
        let statuses = statuses.into_iter().collect();
        self.configure(|config| config.statuses = statuses)
    }

    /// Strikes within one [`window`](Self::window) that trigger a ban.
    pub fn max_strikes(self, strikes: u32) -> Self {
        self.configure(|config| config.max_strikes = strikes.max(1))
    }

    /// How long strikes are counted before the count starts over.
    pub fn window(self, window: Duration) -> Self {
        self.configure(|config| config.window = window)
    }

    /// How long a ban lasts.
    pub fn ban_for(self, duration: Duration) -> Self {
        self.configure(|config| config.ban_for = duration)
    }

    /// The most clients tracked at once. When full, expired entries are dropped
    /// and new clients are not tracked until there is room.
    pub fn max_tracked(self, clients: usize) -> Self {
        self.configure(|config| config.max_tracked = clients)
    }

    /// Addresses that are never banned, such as monitoring or office networks.
    pub fn exempt(self, ranges: IpRanges) -> Self {
        self.configure(|config| config.exempt = ranges)
    }

    /// Groups IPv6 clients by this prefix length; `128` tracks every address.
    pub fn ipv6_prefix(self, prefix: u8) -> Self {
        self.configure(|config| config.ipv6_prefix = prefix.min(128))
    }

    /// Builds the response for banned clients. Defaults to `403 Forbidden`.
    pub fn on_ban<F>(self, handler: F) -> Self
    where
        F: Fn(IpAddr) -> Response + Send + Sync + 'static,
    {
        let handler: BanHandler = Arc::new(handler);
        self.configure(|config| config.on_ban = Some(handler))
    }

    fn key(&self, ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, self.shared.config.ipv6_prefix)),
            ip => ip,
        }
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Entry>> {
        self.shared
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns `true` while `ip` is banned.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.ban_remaining(ip).is_some()
    }

    /// How long the ban on `ip` still lasts.
    pub fn ban_remaining(&self, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let entries = self.entries();
        let until = entries.get(&self.key(ip))?.banned_until?;
        until
            .checked_duration_since(now)
            .filter(|left| !left.is_zero())
    }

    /// Bans `ip` for `duration`, regardless of strikes or the exempt list.
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        let now = Instant::now();
        self.entries().insert(
            self.key(ip),
            Entry {
                strikes: 0,
                window_start: now,
                banned_until: Some(now + duration),
            },
        );
    }

    /// Lifts the ban on `ip` and clears its strikes. Returns `false` when the
    /// client was not tracked.
    pub fn unban(&self, ip: IpAddr) -> bool {
        self.entries().remove(&self.key(ip)).is_some()
    }

    /// The currently banned addresses (or IPv6 networks) and their remaining time.
    pub fn banned(&self) -> Vec<(IpAddr, Duration)> {
        let now = Instant::now();
        self.entries()
            .iter()
            .filter_map(|(ip, entry)| {
                let left = entry.banned_until?.checked_duration_since(now)?;
                (!left.is_zero()).then_some((*ip, left))
            })
            .collect()
    }

    /// Records a response for `ip`; returns `true` when it caused a ban.
    fn record(&self, ip: IpAddr, status: StatusCode) -> bool {
        let config = &self.shared.config;
        if !config.statuses.contains(&status) || config.exempt.contains(ip) {
            return false;
        }
        let key = self.key(ip);
        let now = Instant::now();
        let mut entries = self.entries();
        if !entries.contains_key(&key) && entries.len() >= config.max_tracked {
            entries.retain(|_, entry| !is_expired(entry, now, config.window));
            if entries.len() >= config.max_tracked {
                tracing::warn!(%ip, "autoban is tracking its maximum number of clients");
                return false;
            }
        }
        let entry = entries.entry(key).or_insert(Entry {
            strikes: 0,
            window_start: now,
            banned_until: None,
        });
        if entry.banned_until.is_some_and(|until| until > now) {
            return false;
        }
        if now.duration_since(entry.window_start) > config.window {
            *entry = Entry { strikes: 0, window_start: now, banned_until: None };
        }
        entry.strikes += 1;
        if entry.strikes < config.max_strikes {
            return false;
        }
        *entry = Entry {
            strikes: 0,
            window_start: now,
            banned_until: Some(now + config.ban_for),
        };
        tracing::warn!(%ip, ban_for = ?config.ban_for, "client banned by autoban");
        true
    }

    fn reject(&self, ip: IpAddr) -> Response {
        match &self.shared.config.on_ban {
            Some(handler) => handler(ip),
            None => (StatusCode::FORBIDDEN, "Forbidden").into_response(),
        }
    }
}

/// Neither banned nor holding strikes within the window.
fn is_expired(entry: &Entry, now: Instant, window: Duration) -> bool {
    let banned = entry.banned_until.is_some_and(|until| until > now);
    !banned && now.duration_since(entry.window_start) > window
}

impl fmt::Debug for AutoBan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let config = &self.shared.config;
        f.debug_struct("AutoBan")
            .field("statuses", &config.statuses)
            .field("max_strikes", &config.max_strikes)
            .field("window", &config.window)
            .field("ban_for", &config.ban_for)
            .field("max_tracked", &config.max_tracked)
            .field("exempt", &config.exempt)
            .field("ipv6_prefix", &config.ipv6_prefix)
            .field("banned", &self.banned().len())
            .finish()
    }
}

impl<S> Layer<S> for AutoBan {
    type Service = AutoBanService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AutoBanService { inner, autoban: self.clone() }
    }
}

/// The [`Service`] created by the [`AutoBan`] layer.
#[derive(Clone, Debug)]
pub struct AutoBanService<S> {
    inner: S,
    autoban: AutoBan,
}

impl<S, B> Service<Request<B>> for AutoBanService<S>
where
    S: Service<Request<B>, Response = Response>,
{
    type Response = Response;
    type Error = S::Error;
    type Future = AutoBanFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let ip = req
            .extensions()
            .get::<ClientIp>()
            .map(|client_ip| client_ip.ip);
        if let Some(ip) = ip.filter(|ip| self.autoban.is_banned(*ip)) {
            return AutoBanFuture::Banned { response: Some(self.autoban.reject(ip)) };
        }
        AutoBanFuture::Inner {
            future: self.inner.call(req),
            record: ip.map(|ip| (ip, self.autoban.clone())),
        }
    }
}

pin_project! {
    /// The response future of [`AutoBanService`].
    #[project = AutoBanFutureProj]
    pub enum AutoBanFuture<F> {
        /// The client is banned.
        Banned { response: Option<Response> },
        /// The request was passed on; its response status is recorded.
        Inner {
            #[pin]
            future: F,
            record: Option<(IpAddr, AutoBan)>,
        },
    }
}

impl<F, E> Future for AutoBanFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            AutoBanFutureProj::Banned { response } => {
                Poll::Ready(Ok(response.take().expect("polled after completion")))
            }
            AutoBanFutureProj::Inner { future, record } => {
                let result = std::task::ready!(future.poll(cx));
                if let (Ok(response), Some((ip, autoban))) = (&result, record.take()) {
                    autoban.record(ip, response.status());
                }
                Poll::Ready(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bans_after_max_strikes() {
        let autoban = AutoBan::new().max_strikes(3);
        assert!(!autoban.record(ip("203.0.113.9"), StatusCode::NOT_FOUND));
        assert!(!autoban.record(ip("203.0.113.9"), StatusCode::OK));
        assert!(!autoban.record(ip("203.0.113.9"), StatusCode::UNAUTHORIZED));
        assert!(autoban.record(ip("203.0.113.9"), StatusCode::FORBIDDEN));
        assert!(autoban.is_banned(ip("203.0.113.9")));
        assert!(!autoban.is_banned(ip("203.0.113.10")));
        assert_eq!(autoban.banned().len(), 1);
        assert!(autoban.unban(ip("203.0.113.9")));
        assert!(!autoban.is_banned(ip("203.0.113.9")));
    }

    #[test]
    fn exempt_and_untracked_statuses() {
        let autoban = AutoBan::new()
            .max_strikes(1)
            .exempt(IpRanges::parse(["192.0.2.0/24"]).unwrap())
            .statuses([StatusCode::UNAUTHORIZED]);
        assert!(!autoban.record(ip("192.0.2.1"), StatusCode::UNAUTHORIZED));
        assert!(!autoban.record(ip("198.51.100.1"), StatusCode::NOT_FOUND));
        assert!(autoban.record(ip("198.51.100.1"), StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn groups_ipv6_by_prefix() {
        let autoban = AutoBan::new().max_strikes(2);
        autoban.record(ip("2001:db8:1:2::1"), StatusCode::NOT_FOUND);
        assert!(autoban.record(ip("2001:db8:1:2::ffff"), StatusCode::NOT_FOUND));
        assert!(autoban.is_banned(ip("2001:db8:1:2::abcd")));
        assert!(!autoban.is_banned(ip("2001:db8:1:3::1")));
    }

    #[test]
    fn window_and_ban_expire() {
        let autoban = AutoBan::new()
            .max_strikes(2)
            .window(Duration::from_millis(20))
            .ban_for(Duration::from_millis(20));
        autoban.record(ip("203.0.113.9"), StatusCode::NOT_FOUND);
        std::thread::sleep(Duration::from_millis(30));
        assert!(!autoban.record(ip("203.0.113.9"), StatusCode::NOT_FOUND));
        assert!(autoban.record(ip("203.0.113.9"), StatusCode::NOT_FOUND));
        std::thread::sleep(Duration::from_millis(30));
        assert!(!autoban.is_banned(ip("203.0.113.9")));
    }

    #[test]
    fn limits_tracked_clients() {
        let autoban = AutoBan::new().max_strikes(5).max_tracked(2);
        autoban.record(ip("203.0.113.1"), StatusCode::NOT_FOUND);
        autoban.record(ip("203.0.113.2"), StatusCode::NOT_FOUND);
        autoban.record(ip("203.0.113.3"), StatusCode::NOT_FOUND);
        assert_eq!(autoban.entries().len(), 2);
        assert!(!autoban.entries().contains_key(&ip("203.0.113.3")));
    }

    #[test]
    fn manual_ban() {
        let autoban = AutoBan::new();
        autoban.ban(ip("192.0.2.1"), Duration::from_secs(60));
        let left = autoban.ban_remaining(ip("192.0.2.1")).unwrap();
        assert!(left <= Duration::from_secs(60) && left > Duration::from_secs(58));
    }
}
