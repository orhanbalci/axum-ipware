use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::future::{self, Either, Ready};
use ipware::{ClientIpResolver, IpRangeError, IpRanges};
use tower_layer::Layer;
use tower_service::Service;

use crate::client_ip::ClientIp;

type BlockHandler = Arc<dyn Fn(&Rejection) -> Response + Send + Sync>;

/// IP filtering middleware for axum.
///
/// Resolves the client IP for every request, rejects requests that fail the
/// allow/block rules, and stores the address as a [`ClientIp`] request extension.
/// Without any rules it only resolves the address.
///
/// # Resolving the client IP
///
/// The client IP is resolved by a [`ClientIpResolver`] from the request headers
/// and the TCP peer address from [`ConnectInfo`] (or [`MockConnectInfo`] in
/// tests), so serve the app with
/// [`into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info).
/// The default resolver uses the peer address only; configure one with
/// [`resolver`](Self::resolver) to read proxy headers from trusted proxies.
///
/// # Rules
///
/// A request is rejected when its IP is in a block list, or when it is in no
/// allow list and either an allow list is set or [`default_deny`](Self::default_deny)
/// is on. Block lists win over allow lists. When rules are configured and no IP
/// can be resolved, the request is rejected. Allowing an empty set of ranges
/// rejects every request, so a provider list that unexpectedly comes back empty
/// fails closed.
///
/// # Live updates
///
/// Clones of an `IpFilter` share their rules, including the copies axum makes for
/// each route. Use [`handle`](Self::handle) to change the rules while the server
/// runs; every request sees either the old or the new rules, never a mix.
#[derive(Clone)]
pub struct IpFilter {
    rules: Arc<ArcSwap<Rules>>,
}

#[derive(Clone)]
struct Rules {
    resolver: ClientIpResolver,
    allow: Vec<RuleList>,
    block: Vec<RuleList>,
    default_deny: bool,
    on_block: Option<BlockHandler>,
}

/// A set of ranges, optionally named so it can be replaced or removed later.
#[derive(Clone, Debug)]
struct RuleList {
    name: Option<Cow<'static, str>>,
    ranges: Arc<IpRanges>,
}

impl Rules {
    fn has_rules(&self) -> bool {
        self.default_deny || !self.allow.is_empty() || !self.block.is_empty()
    }

    fn check(&self, ip: Option<IpAddr>) -> Result<(), RejectReason> {
        if !self.has_rules() {
            return Ok(());
        }
        let Some(ip) = ip else {
            return Err(RejectReason::Unresolved);
        };
        if self.block.iter().any(|list| list.ranges.contains(ip)) {
            return Err(RejectReason::Blocked);
        }
        let allowed = self.allow.iter().any(|list| list.ranges.contains(ip));
        if !allowed && (self.default_deny || !self.allow.is_empty()) {
            return Err(RejectReason::NotAllowed);
        }
        Ok(())
    }

    fn resolve(&self, headers: &HeaderMap, extensions: &Extensions) -> Option<ClientIp> {
        self.resolver
            .resolve(headers, peer_ip(extensions))
            .map(ClientIp::from)
    }
}

/// Inserts `list` into `lists`, replacing a list with the same name.
fn set_list(lists: &mut Vec<RuleList>, list: RuleList) {
    match lists
        .iter_mut()
        .find(|existing| existing.name.is_some() && existing.name == list.name)
    {
        Some(existing) => *existing = list,
        None => lists.push(list),
    }
}

fn remove_list(lists: &mut Vec<RuleList>, name: &str) -> bool {
    let before = lists.len();
    lists.retain(|list| list.name.as_deref() != Some(name));
    lists.len() != before
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IpFilter {
    /// Creates a filter with no rules that uses the peer address as the client IP.
    pub fn new() -> Self {
        IpFilter {
            rules: Arc::new(ArcSwap::from_pointee(Rules {
                resolver: ClientIpResolver::default(),
                allow: Vec::new(),
                block: Vec::new(),
                default_deny: false,
                on_block: None,
            })),
        }
    }

    fn update(self, f: impl FnMut(&mut Rules)) -> Self {
        update(&self.rules, f);
        self
    }

    /// Sets how the client IP is resolved.
    ///
    /// ```rust
    /// use axum_ipware::ipware::{header, ClientIpResolver, ClientIpStrategy, IpRanges};
    /// use axum_ipware::IpFilter;
    ///
    /// # fn main() -> Result<(), axum_ipware::ipware::IpRangeError> {
    /// let filter = IpFilter::new().resolver(
    ///     ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
    ///         header::X_FORWARDED_FOR,
    ///     ))
    ///     .trusted_proxies(IpRanges::parse(["10.0.0.0/8"])?),
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn resolver(self, resolver: ClientIpResolver) -> Self {
        self.update(|rules| rules.resolver = resolver.clone())
    }

    /// Adds IP addresses or CIDR ranges to the allow list.
    ///
    /// ```rust
    /// # fn main() -> Result<(), axum_ipware::ipware::IpRangeError> {
    /// let filter = axum_ipware::IpFilter::new().allow(["10.0.0.0/8", "2001:db8::1"])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn allow<I, R>(self, ranges: I) -> Result<Self, IpRangeError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        Ok(self.allow_ranges(IpRanges::parse(ranges)?))
    }

    /// Adds a parsed set of ranges to the allow list, such as a provider's
    /// published ranges.
    ///
    /// ```rust
    /// # #[cfg(feature = "providers")] {
    /// use axum_ipware::ipware::providers;
    /// use axum_ipware::IpFilter;
    ///
    /// // Only accept GitHub webhook deliveries.
    /// let filter = IpFilter::new().allow_ranges(providers::github_hooks());
    /// # }
    /// ```
    pub fn allow_ranges(self, ranges: IpRanges) -> Self {
        let ranges = Arc::new(ranges);
        self.update(|rules| {
            rules
                .allow
                .push(RuleList { name: None, ranges: ranges.clone() })
        })
    }

    /// Adds a named set of ranges to the allow list, replacing a list with the
    /// same name. Named lists can be replaced or removed with an [`IpFilterHandle`].
    pub fn allow_list(self, name: impl Into<Cow<'static, str>>, ranges: IpRanges) -> Self {
        self.handle().set_allow_list(name, ranges);
        self
    }

    /// Adds IP addresses or CIDR ranges to the block list.
    pub fn block<I, R>(self, ranges: I) -> Result<Self, IpRangeError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        Ok(self.block_ranges(IpRanges::parse(ranges)?))
    }

    /// Adds a parsed set of ranges to the block list, such as a blocklist
    /// fetched at startup.
    pub fn block_ranges(self, ranges: IpRanges) -> Self {
        let ranges = Arc::new(ranges);
        self.update(|rules| {
            rules
                .block
                .push(RuleList { name: None, ranges: ranges.clone() })
        })
    }

    /// Adds a named set of ranges to the block list, replacing a list with the
    /// same name. Named lists can be replaced or removed with an [`IpFilterHandle`].
    pub fn block_list(self, name: impl Into<Cow<'static, str>>, ranges: IpRanges) -> Self {
        self.handle().set_block_list(name, ranges);
        self
    }

    /// Rejects every IP that is not in an allow list, even when no allow list is
    /// set. Defaults to `false`, where requests are allowed until an allow list
    /// is added.
    ///
    /// Useful with allow lists loaded after startup: requests are rejected
    /// until the first list arrives.
    pub fn default_deny(self, deny: bool) -> Self {
        self.update(|rules| rules.default_deny = deny)
    }

    /// Builds the response for rejected requests. Defaults to `403 Forbidden`.
    pub fn on_block<F>(self, handler: F) -> Self
    where
        F: Fn(&Rejection) -> Response + Send + Sync + 'static,
    {
        let handler: BlockHandler = Arc::new(handler);
        self.update(|rules| rules.on_block = Some(handler.clone()))
    }

    /// Returns a handle that changes this filter's rules while the server runs.
    ///
    /// ```rust
    /// use axum_ipware::ipware::IpRanges;
    /// use axum_ipware::IpFilter;
    ///
    /// let filter = IpFilter::new().default_deny(true);
    /// let handle = filter.handle();
    /// // ... add `filter` to the router and start the server ...
    ///
    /// // Later, e.g. from a background task:
    /// handle.set_allow_list("office", IpRanges::parse(["192.0.2.0/24"]).unwrap());
    /// ```
    pub fn handle(&self) -> IpFilterHandle {
        IpFilterHandle { rules: self.rules.clone() }
    }

    /// Resolves the client IP of a request, without applying the rules.
    pub fn resolve<B>(&self, req: &Request<B>) -> Option<ClientIp> {
        self.rules.load().resolve(req.headers(), req.extensions())
    }

    /// Resolves the client IP from request parts, without applying the rules.
    pub fn resolve_parts(&self, parts: &Parts) -> Option<ClientIp> {
        self.rules.load().resolve(&parts.headers, &parts.extensions)
    }

    /// Checks an IP against the current rules.
    ///
    /// ```rust
    /// use axum_ipware::{IpFilter, RejectReason};
    ///
    /// # fn main() -> Result<(), axum_ipware::ipware::IpRangeError> {
    /// let filter = IpFilter::new().block(["203.0.113.0/24"])?;
    /// assert_eq!(
    ///     filter.check("203.0.113.9".parse().unwrap()),
    ///     Err(RejectReason::Blocked)
    /// );
    /// assert_eq!(filter.check("192.0.2.1".parse().unwrap()), Ok(()));
    /// # Ok(())
    /// # }
    /// ```
    pub fn check(&self, ip: IpAddr) -> Result<(), RejectReason> {
        self.rules.load().check(Some(ip.to_canonical()))
    }
}

/// Applies `f` to a copy of the current rules and swaps it in.
fn update(rules: &ArcSwap<Rules>, mut f: impl FnMut(&mut Rules)) {
    rules.rcu(|current| {
        let mut next = Rules::clone(current);
        f(&mut next);
        next
    });
}

/// Changes the rules of an [`IpFilter`] while the server runs.
///
/// Created with [`IpFilter::handle`]. Cloning the handle is cheap, and every
/// clone changes the same filter. Each change applies atomically to new requests.
#[derive(Clone)]
pub struct IpFilterHandle {
    rules: Arc<ArcSwap<Rules>>,
}

impl IpFilterHandle {
    /// Sets the allow list called `name`, replacing a list with the same name.
    pub fn set_allow_list(&self, name: impl Into<Cow<'static, str>>, ranges: IpRanges) {
        let list = RuleList { name: Some(name.into()), ranges: Arc::new(ranges) };
        update(&self.rules, |rules| {
            set_list(&mut rules.allow, list.clone())
        });
    }

    /// Removes the allow list called `name`. Returns `false` when there was none.
    pub fn remove_allow_list(&self, name: &str) -> bool {
        let mut removed = false;
        update(&self.rules, |rules| {
            removed = remove_list(&mut rules.allow, name)
        });
        removed
    }

    /// Sets the block list called `name`, replacing a list with the same name.
    pub fn set_block_list(&self, name: impl Into<Cow<'static, str>>, ranges: IpRanges) {
        let list = RuleList { name: Some(name.into()), ranges: Arc::new(ranges) };
        update(&self.rules, |rules| {
            set_list(&mut rules.block, list.clone())
        });
    }

    /// Removes the block list called `name`. Returns `false` when there was none.
    pub fn remove_block_list(&self, name: &str) -> bool {
        let mut removed = false;
        update(&self.rules, |rules| {
            removed = remove_list(&mut rules.block, name)
        });
        removed
    }

    /// Replaces the client IP resolver, e.g. after refreshing trusted proxy ranges.
    pub fn set_resolver(&self, resolver: ClientIpResolver) {
        update(&self.rules, |rules| rules.resolver = resolver.clone());
    }

    /// Changes [`IpFilter::default_deny`].
    pub fn set_default_deny(&self, deny: bool) {
        update(&self.rules, |rules| rules.default_deny = deny);
    }
}

impl fmt::Debug for IpFilterHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpFilterHandle").finish_non_exhaustive()
    }
}

/// The TCP peer address, from [`ConnectInfo`] or [`MockConnectInfo`].
fn peer_ip(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr)
        .or_else(|| {
            extensions
                .get::<MockConnectInfo<SocketAddr>>()
                .map(|MockConnectInfo(addr)| addr)
        })
        .map(|addr| addr.ip())
}

fn reject(rules: &Rules, rejection: Rejection) -> Response {
    tracing::debug!(
        ip = ?rejection.client_ip.map(|client_ip| client_ip.ip),
        reason = %rejection.reason,
        uri = %rejection.uri,
        "request rejected by ip filter"
    );
    match &rules.on_block {
        Some(handler) => handler(&rejection),
        None => rejection.into_response(),
    }
}

impl fmt::Debug for IpFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rules = self.rules.load();
        f.debug_struct("IpFilter")
            .field("resolver", &rules.resolver)
            .field("allow", &rules.allow)
            .field("block", &rules.block)
            .field("default_deny", &rules.default_deny)
            .field("on_block", &rules.on_block.is_some())
            .finish()
    }
}

impl<S> Layer<S> for IpFilter {
    type Service = IpFilterService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFilterService { inner, filter: self.clone() }
    }
}

/// The [`Service`] created by the [`IpFilter`] layer.
#[derive(Clone, Debug)]
pub struct IpFilterService<S> {
    inner: S,
    filter: IpFilter,
}

impl<S, B> Service<Request<B>> for IpFilterService<S>
where
    S: Service<Request<B>, Response = Response>,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Either<Ready<Result<Response, S::Error>>, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // One snapshot of the rules for the whole request.
        let rules = self.filter.rules.load();
        let client_ip = rules.resolve(req.headers(), req.extensions());
        if let Err(reason) = rules.check(client_ip.map(|client_ip| client_ip.ip)) {
            let rejection = Rejection { client_ip, reason, uri: req.uri().clone() };
            return Either::Left(future::ready(Ok(reject(&rules, rejection))));
        }
        drop(rules);
        if let Some(client_ip) = client_ip {
            req.extensions_mut().insert(client_ip);
        }
        Either::Right(self.inner.call(req))
    }
}

/// A request rejected by [`IpFilter`], passed to [`IpFilter::on_block`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Rejection {
    /// The resolved client IP, if any.
    pub client_ip: Option<ClientIp>,
    /// Why the request was rejected.
    pub reason: RejectReason,
    /// The request URI.
    pub uri: Uri,
}

/// Why [`IpFilter`] rejected a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// The IP is in the block list.
    Blocked,
    /// The IP is in no allow list, and an allow list is set or
    /// [`default_deny`](IpFilter::default_deny) is on.
    NotAllowed,
    /// No client IP could be resolved.
    Unresolved,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RejectReason::Blocked => "blocked",
            RejectReason::NotAllowed => "not allowed",
            RejectReason::Unresolved => "unresolved",
        })
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        (StatusCode::FORBIDDEN, "Forbidden").into_response()
    }
}
