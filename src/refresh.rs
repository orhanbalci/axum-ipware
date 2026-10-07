//! Keep allow lists, block lists and trusted proxies up to date from files or
//! remote sources. Requires the `refresh` feature; the HTTPS source requires `fetch`.
//!
//! ```rust,no_run
//! # #[cfg(feature = "fetch")] {
//! use std::time::Duration;
//!
//! use axum_ipware::refresh::{Refresh, Source};
//! use axum_ipware::IpFilter;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let filter = IpFilter::new();
//! let tor = Refresh::block_list(&filter.handle(), "tor")
//!     .source(Source::https(
//!         "https://check.torproject.org/torbulkexitlist",
//!     )?)
//!     .every(Duration::from_secs(60 * 60))
//!     .spawn();
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Safety rules
//!
//! Whoever controls a list's source controls what the list allows, so a refresh
//! is applied only when it passes every check, and otherwise the list in use is
//! kept:
//!
//! - A failed load, an oversized response, a parse error or an empty list never
//!   replaces the current list.
//! - [`Safeguards`] cap the response size and the number of addresses a list may
//!   cover, and reject sudden shrinking or growth. Allow lists and trusted proxies
//!   get stricter defaults than block lists, since a broader allow list or proxy
//!   list lets more clients in.
//! - Allow lists and trusted proxies each have their own constructor; nothing
//!   refreshes them unless you ask for it.
//! - The HTTPS source only fetches `https://` URLs and only follows redirects to
//!   the same host.
//!
//! Until the first successful refresh an allow list does not exist, so pair a
//! refreshed allow list with [`IpFilter::default_deny`](crate::IpFilter::default_deny)
//! or an initial list from [`IpFilter::allow_list`](crate::IpFilter::allow_list).

use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ipware::{ClientIpResolver, IpRangeError, IpRanges};
use tokio::task::JoinHandle;

use crate::filter::IpFilterHandle;

type BoxError = Box<dyn Error + Send + Sync>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type LoadFn = Arc<dyn Fn(usize) -> BoxFuture<Result<String, BoxError>> + Send + Sync>;
type ParseFn = Arc<dyn Fn(&str) -> Result<IpRanges, BoxError> + Send + Sync>;

/// Parses one address or range per line; blank lines and `#` comments are skipped.
///
/// The default parser of [`Refresh`]. Fits Tor's exit list and most plain-text
/// blocklists; for providers' JSON formats see `ipware::providers::parse`.
pub fn parse_lines(text: &str) -> Result<IpRanges, IpRangeError> {
    IpRanges::parse(
        text.lines()
            .map(|line| line.split(['#', ';']).next().unwrap_or_default().trim())
            .filter(|line| !line.is_empty()),
    )
}

/// Where a refreshed list is loaded from.
#[derive(Clone)]
pub struct Source {
    load: LoadFn,
}

impl Source {
    /// Loads the list with an async function, e.g. using your own HTTP client.
    ///
    /// The response size limit is checked after the function returns.
    pub fn from_fn<F, Fut, E>(load: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, E>> + Send + 'static,
        E: Into<BoxError>,
    {
        let load = Arc::new(load);
        Source {
            load: Arc::new(move |_max_bytes| {
                let load = load.clone();
                Box::pin(async move { load().await.map_err(Into::into) })
            }),
        }
    }

    /// Reads the list from a file on every refresh.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        let path = Arc::new(path.into());
        Source {
            load: Arc::new(move |max_bytes| {
                let path = path.clone();
                Box::pin(async move {
                    let len = tokio::fs::metadata(path.as_path()).await?.len();
                    if len > max_bytes as u64 {
                        return Err(RefreshError::TooLarge { limit: max_bytes }.into());
                    }
                    Ok(tokio::fs::read_to_string(path.as_path()).await?)
                })
            }),
        }
    }

    /// Fetches the list over HTTPS. Requires the `fetch` feature.
    ///
    /// Only `https://` URLs are accepted, redirects are followed only to the same
    /// host, requests time out after 30 seconds, and the body is read up to the
    /// [`Safeguards`] size limit.
    #[cfg(feature = "fetch")]
    pub fn https(url: &str) -> Result<Self, InvalidUrl> {
        let parsed = reqwest::Url::parse(url).map_err(|_| InvalidUrl(url.to_owned()))?;
        let host = match (parsed.scheme(), parsed.host_str()) {
            ("https", Some(host)) => host.to_owned(),
            _ => return Err(InvalidUrl(url.to_owned())),
        };
        let redirect = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() != "https" || attempt.url().host_str() != Some(&host) {
                attempt.error("redirect to another host or scheme")
            } else {
                attempt.follow()
            }
        });
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(redirect)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("axum-ipware/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| InvalidUrl(url.to_owned()))?;
        Ok(Source {
            load: Arc::new(move |max_bytes| {
                let client = client.clone();
                let url = parsed.clone();
                Box::pin(async move {
                    let mut response = client.get(url).send().await?.error_for_status()?;
                    if response
                        .content_length()
                        .is_some_and(|len| len > max_bytes as u64)
                    {
                        return Err(RefreshError::TooLarge { limit: max_bytes }.into());
                    }
                    let mut body = Vec::new();
                    while let Some(chunk) = response.chunk().await? {
                        if body.len() + chunk.len() > max_bytes {
                            return Err(RefreshError::TooLarge { limit: max_bytes }.into());
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Ok(String::from_utf8(body)?)
                })
            }),
        })
    }
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Source").finish_non_exhaustive()
    }
}

/// Returned by [`Source::https`] for URLs that are not `https://` with a host.
#[cfg(feature = "fetch")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidUrl(String);

#[cfg(feature = "fetch")]
impl fmt::Display for InvalidUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid list URL `{}`: expected an https:// URL", self.0)
    }
}

#[cfg(feature = "fetch")]
impl Error for InvalidUrl {}

/// Limits a refreshed list must stay within to be applied.
///
/// Address limits count IPv4 and IPv6 separately. Shrink and growth limits
/// compare with the list this refresher applied last.
#[derive(Clone, Debug, PartialEq)]
pub struct Safeguards {
    max_bytes: usize,
    max_ipv4_addresses: u64,
    max_ipv6_addresses: u128,
    max_shrink: Option<f64>,
    max_growth: Option<f64>,
}

impl Safeguards {
    /// Defaults for block lists: up to 32 MiB, a `/4` of IPv4 and a `/16` of IPv6,
    /// and no more than halving between refreshes.
    pub fn for_block_lists() -> Self {
        Safeguards {
            max_bytes: 32 << 20,
            max_ipv4_addresses: 1 << 28,
            max_ipv6_addresses: 1 << 112,
            max_shrink: Some(0.5),
            max_growth: None,
        }
    }

    /// Defaults for allow lists and trusted proxies: up to 4 MiB, a `/8` of IPv4
    /// and a `/32` of IPv6, and no more than halving or doubling between refreshes.
    pub fn for_allow_lists() -> Self {
        Safeguards {
            max_bytes: 4 << 20,
            max_ipv4_addresses: 1 << 24,
            max_ipv6_addresses: 1 << 96,
            max_shrink: Some(0.5),
            max_growth: Some(2.0),
        }
    }

    /// The largest response accepted, in bytes.
    pub fn max_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// The most IPv4 addresses a list may cover.
    pub fn max_ipv4_addresses(mut self, count: u64) -> Self {
        self.max_ipv4_addresses = count;
        self
    }

    /// The most IPv6 addresses a list may cover.
    pub fn max_ipv6_addresses(mut self, count: u128) -> Self {
        self.max_ipv6_addresses = count;
        self
    }

    /// Rejects a list that covers less than `1 - fraction` of the previous one,
    /// e.g. `0.5` rejects losing more than half. `None` disables the check.
    pub fn max_shrink(mut self, fraction: Option<f64>) -> Self {
        self.max_shrink = fraction;
        self
    }

    /// Rejects a list that covers more than `factor` times the previous one,
    /// e.g. `2.0` rejects more than doubling. `None` disables the check.
    pub fn max_growth(mut self, factor: Option<f64>) -> Self {
        self.max_growth = factor;
        self
    }

    fn check(
        &self,
        ranges: &IpRanges,
        previous: Option<Coverage>,
    ) -> Result<Coverage, RefreshError> {
        if ranges.is_empty() {
            return Err(RefreshError::Empty);
        }
        let coverage = Coverage {
            ipv4: ranges.ipv4_address_count(),
            ipv6: ranges.ipv6_address_count(),
        };
        if coverage.ipv4 > self.max_ipv4_addresses || coverage.ipv6 > self.max_ipv6_addresses {
            return Err(RefreshError::TooBroad);
        }
        if let Some(previous) = previous {
            for (old, new) in [
                (previous.ipv4 as f64, coverage.ipv4 as f64),
                (previous.ipv6 as f64, coverage.ipv6 as f64),
            ] {
                if old == 0.0 {
                    continue;
                }
                if self
                    .max_shrink
                    .is_some_and(|shrink| new < old * (1.0 - shrink))
                {
                    return Err(RefreshError::ShrankTooMuch);
                }
                if self.max_growth.is_some_and(|growth| new > old * growth) {
                    return Err(RefreshError::GrewTooMuch);
                }
            }
        }
        Ok(coverage)
    }
}

/// How many addresses an applied list covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Coverage {
    ipv4: u64,
    ipv6: u128,
}

/// Why a refresh was not applied. The list in use is kept.
#[derive(Debug)]
#[non_exhaustive]
pub enum RefreshError {
    /// The source failed.
    Load(BoxError),
    /// The response is larger than [`Safeguards::max_bytes`].
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The response could not be parsed.
    Parse(BoxError),
    /// The list has no entries.
    Empty,
    /// The list covers more addresses than the safeguards allow.
    TooBroad,
    /// The list lost more addresses than [`Safeguards::max_shrink`] allows.
    ShrankTooMuch,
    /// The list gained more addresses than [`Safeguards::max_growth`] allows.
    GrewTooMuch,
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshError::Load(err) => write!(f, "loading the list failed: {err}"),
            RefreshError::TooLarge { limit } => {
                write!(f, "the list is larger than the {limit} byte limit")
            }
            RefreshError::Parse(err) => write!(f, "parsing the list failed: {err}"),
            RefreshError::Empty => f.write_str("the list is empty"),
            RefreshError::TooBroad => f.write_str("the list covers too many addresses"),
            RefreshError::ShrankTooMuch => f.write_str("the list shrank more than allowed"),
            RefreshError::GrewTooMuch => f.write_str("the list grew more than allowed"),
        }
    }
}

impl Error for RefreshError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RefreshError::Load(err) | RefreshError::Parse(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

/// What a refresh updates.
#[derive(Clone, Debug)]
enum Target {
    Allow(Cow<'static, str>),
    Block(Cow<'static, str>),
    TrustedProxies(ClientIpResolver),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Allow(name) => write!(f, "allow list `{name}`"),
            Target::Block(name) => write!(f, "block list `{name}`"),
            Target::TrustedProxies(_) => f.write_str("trusted proxies"),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    coverage: Option<Coverage>,
    last_success: Option<SystemTime>,
    last_error: Option<String>,
}

/// Periodically reloads one list into an [`IpFilter`](crate::IpFilter).
///
/// Build it with [`block_list`](Self::block_list), [`allow_list`](Self::allow_list)
/// or [`trusted_proxies`](Self::trusted_proxies), set a [`source`](Self::source),
/// and [`spawn`](Self::spawn) it on the Tokio runtime.
#[derive(Clone)]
pub struct Refresh {
    handle: IpFilterHandle,
    target: Target,
    source: Option<Source>,
    parse: ParseFn,
    interval: Duration,
    safeguards: Safeguards,
    stale_after: Option<Duration>,
    state: Arc<Mutex<State>>,
}

impl Refresh {
    fn new(handle: &IpFilterHandle, target: Target, safeguards: Safeguards) -> Self {
        Refresh {
            handle: handle.clone(),
            target,
            source: None,
            parse: Arc::new(|text| parse_lines(text).map_err(Into::into)),
            interval: Duration::from_secs(60 * 60),
            safeguards,
            stale_after: None,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Refreshes the block list called `name`, with [`Safeguards::for_block_lists`].
    pub fn block_list(handle: &IpFilterHandle, name: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            handle,
            Target::Block(name.into()),
            Safeguards::for_block_lists(),
        )
    }

    /// Refreshes the allow list called `name`, with [`Safeguards::for_allow_lists`].
    ///
    /// Whoever controls the source decides who is allowed in; only use sources
    /// you trust, over HTTPS or from local files.
    pub fn allow_list(handle: &IpFilterHandle, name: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            handle,
            Target::Allow(name.into()),
            Safeguards::for_allow_lists(),
        )
    }

    /// Refreshes the trusted proxy ranges of `resolver`, e.g. a CDN's published
    /// ranges, with [`Safeguards::for_allow_lists`].
    ///
    /// Each refresh installs `resolver` with the loaded ranges as its trusted
    /// proxies, replacing the filter's resolver. Clients within trusted ranges can
    /// set their own client IP through headers, so only use sources you trust.
    pub fn trusted_proxies(handle: &IpFilterHandle, resolver: ClientIpResolver) -> Self {
        Self::new(
            handle,
            Target::TrustedProxies(resolver),
            Safeguards::for_allow_lists(),
        )
    }

    /// Sets where the list is loaded from. Required.
    pub fn source(mut self, source: Source) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets how the loaded text is parsed. Defaults to [`parse_lines`].
    pub fn parse<F, E>(mut self, parse: F) -> Self
    where
        F: Fn(&str) -> Result<IpRanges, E> + Send + Sync + 'static,
        E: Into<BoxError>,
    {
        self.parse = Arc::new(move |text| parse(text).map_err(Into::into));
        self
    }

    /// Sets how often the list is reloaded. Defaults to one hour.
    pub fn every(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Replaces the safeguards.
    pub fn safeguards(mut self, safeguards: Safeguards) -> Self {
        self.safeguards = safeguards;
        self
    }

    /// Logs an error on every failed refresh once the last successful one is
    /// older than `age`.
    pub fn stale_after(mut self, age: Duration) -> Self {
        self.stale_after = Some(age);
        self
    }

    /// Loads, checks and applies the list once.
    ///
    /// Useful to load a list before serving requests; [`spawn`](Self::spawn)
    /// calls it on every interval.
    pub async fn refresh_once(&self) -> Result<(), RefreshError> {
        let result = self.load_and_apply().await;
        let mut state = self.state.lock().expect("refresh state lock");
        match &result {
            Ok(coverage) => {
                tracing::info!(
                    target_list = %self.target,
                    ipv4_addresses = coverage.ipv4,
                    ipv6_addresses = %coverage.ipv6,
                    "ip list refreshed"
                );
                state.coverage = Some(*coverage);
                state.last_success = Some(SystemTime::now());
                state.last_error = None;
            }
            Err(err) => {
                tracing::warn!(target_list = %self.target, error = %err, "ip list refresh rejected; keeping the current list");
                state.last_error = Some(err.to_string());
                let stale = self.stale_after.is_some_and(|age| {
                    state
                        .last_success
                        .is_none_or(|at| at.elapsed().unwrap_or_default() > age)
                });
                if stale {
                    tracing::error!(target_list = %self.target, "ip list is stale");
                }
            }
        }
        result.map(|_| ())
    }

    async fn load_and_apply(&self) -> Result<Coverage, RefreshError> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| RefreshError::Load("no source configured".into()))?;
        let max_bytes = self.safeguards.max_bytes;
        let text =
            (source.load)(max_bytes)
                .await
                .map_err(|err| match err.downcast::<RefreshError>() {
                    Ok(err) => *err,
                    Err(err) => RefreshError::Load(err),
                })?;
        if text.len() > max_bytes {
            return Err(RefreshError::TooLarge { limit: max_bytes });
        }
        let ranges = (self.parse)(&text).map_err(RefreshError::Parse)?;
        let previous = self.state.lock().expect("refresh state lock").coverage;
        let coverage = self.safeguards.check(&ranges, previous)?;
        match &self.target {
            Target::Allow(name) => self.handle.set_allow_list(name.clone(), ranges),
            Target::Block(name) => self.handle.set_block_list(name.clone(), ranges),
            Target::TrustedProxies(resolver) => self
                .handle
                .set_resolver(resolver.clone().trusted_proxies(ranges)),
        }
        Ok(coverage)
    }

    /// Refreshes now and then on every interval, on the current Tokio runtime.
    ///
    /// The task keeps running when the returned [`RefreshTask`] is dropped; call
    /// [`RefreshTask::abort`] to stop it.
    pub fn spawn(self) -> RefreshTask {
        let state = self.state.clone();
        let task = tokio::spawn(async move {
            loop {
                let _ = self.refresh_once().await;
                tokio::time::sleep(self.interval).await;
            }
        });
        RefreshTask { task, state }
    }
}

impl fmt::Debug for Refresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refresh")
            .field("target", &self.target)
            .field("interval", &self.interval)
            .field("safeguards", &self.safeguards)
            .field("stale_after", &self.stale_after)
            .finish_non_exhaustive()
    }
}

/// A running [`Refresh`], returned by [`Refresh::spawn`].
#[derive(Debug)]
pub struct RefreshTask {
    task: JoinHandle<()>,
    state: Arc<Mutex<State>>,
}

impl RefreshTask {
    /// When the list was last applied.
    pub fn last_success(&self) -> Option<SystemTime> {
        self.state.lock().expect("refresh state lock").last_success
    }

    /// Why the last refresh was rejected, if it was.
    pub fn last_error(&self) -> Option<String> {
        self.state
            .lock()
            .expect("refresh state lock")
            .last_error
            .clone()
    }

    /// Stops refreshing. The list in use stays in place.
    pub fn abort(&self) {
        self.task.abort();
    }
}
