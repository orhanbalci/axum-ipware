use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::connect_info::MockConnectInfo;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::future::{self, Either, Ready};
use ipware::IpWare;
use tower_layer::Layer;
use tower_service::Service;

use crate::client_ip::{ClientIp, IpSource};
use crate::rules::{IpRules, RuleError};

type BlockHandler = Arc<dyn Fn(&Rejection) -> Response + Send + Sync>;

/// IP filtering middleware for axum.
///
/// Resolves the client IP for every request, rejects requests that fail the
/// allow/block rules, and stores the address as a [`ClientIp`] request extension.
/// Without any rules it only resolves the address.
///
/// # Resolving the client IP
///
/// The client IP is the TCP peer address from [`ConnectInfo`] (or [`MockConnectInfo`]
/// in tests), so serve the app with
/// [`into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info).
///
/// Proxy headers are read by [`IpWare`] only when the peer is one of the
/// [`trusted_proxies`](Self::trusted_proxies), and the header address is used only
/// when ipware also reports a trusted route, which requires a proxy count or a
/// trusted proxy list in its [`IpWareProxy`](ipware::IpWareProxy) config.
/// [`allow_untrusted`](Self::allow_untrusted) skips both checks.
///
/// # Rules
///
/// A request is rejected when its IP is in the block list, or when the allow list
/// is not empty and does not contain the IP. The block list wins over the allow list.
/// When rules are configured and no IP can be resolved, the request is rejected.
#[derive(Clone)]
pub struct IpFilter {
    inner: Arc<Config>,
}

#[derive(Clone)]
struct Config {
    ipware: IpWare,
    strict: bool,
    allow_untrusted: bool,
    trusted_proxies: IpRules,
    allow: IpRules,
    block: IpRules,
    on_block: Option<BlockHandler>,
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IpFilter {
    /// Creates a filter with no rules that uses ipware's default header lookup.
    pub fn new() -> Self {
        IpFilter {
            inner: Arc::new(Config {
                ipware: IpWare::default(),
                strict: false,
                allow_untrusted: false,
                trusted_proxies: IpRules::default(),
                allow: IpRules::default(),
                block: IpRules::default(),
                on_block: None,
            }),
        }
    }

    fn config(&mut self) -> &mut Config {
        Arc::make_mut(&mut self.inner)
    }

    /// Sets the ipware instance used to read the client IP from headers.
    pub fn ipware(mut self, ipware: IpWare) -> Self {
        self.config().ipware = ipware;
        self
    }

    /// Passes `strict` to [`IpWare::get_client_ip`]. Defaults to `false`.
    pub fn strict(mut self, strict: bool) -> Self {
        self.config().strict = strict;
        self
    }

    /// Uses header addresses even when the peer is not a trusted proxy or ipware
    /// cannot verify the proxy route.
    ///
    /// Clients can set these headers themselves, so only enable this when every
    /// request reaches the app through a proxy that overwrites them. Defaults to `false`.
    pub fn allow_untrusted(mut self, allow_untrusted: bool) -> Self {
        self.config().allow_untrusted = allow_untrusted;
        self
    }

    /// Adds IP addresses or CIDR ranges of the proxies in front of the app.
    ///
    /// Proxy headers are only read for requests whose TCP peer is in these ranges.
    /// Requests from other peers use the peer address, so clients that reach the
    /// app directly cannot spoof their IP with headers.
    ///
    /// ```rust
    /// # fn main() -> Result<(), axum_ipware::RuleError> {
    /// let filter = axum_ipware::IpFilter::new().trusted_proxies(["10.0.0.0/8"])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn trusted_proxies<I, R>(mut self, rules: I) -> Result<Self, RuleError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        self.config().trusted_proxies.extend(rules)?;
        Ok(self)
    }

    /// Adds IP addresses or CIDR ranges to the allow list.
    ///
    /// ```rust
    /// # fn main() -> Result<(), axum_ipware::RuleError> {
    /// let filter = axum_ipware::IpFilter::new().allow(["10.0.0.0/8", "2001:db8::1"])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn allow<I, R>(mut self, rules: I) -> Result<Self, RuleError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        self.config().allow.extend(rules)?;
        Ok(self)
    }

    /// Adds IP addresses or CIDR ranges to the block list.
    pub fn block<I, R>(mut self, rules: I) -> Result<Self, RuleError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        self.config().block.extend(rules)?;
        Ok(self)
    }

    /// Builds the response for rejected requests. Defaults to `403 Forbidden`.
    pub fn on_block<F>(mut self, handler: F) -> Self
    where
        F: Fn(&Rejection) -> Response + Send + Sync + 'static,
    {
        self.config().on_block = Some(Arc::new(handler));
        self
    }

    fn resolve<B>(&self, req: &Request<B>) -> Option<ClientIp> {
        let config = &self.inner;
        let peer_ip = peer_ip(req);
        let trusted_peer = peer_ip.is_some_and(|ip| config.trusted_proxies.contains(ip));
        if trusted_peer || config.allow_untrusted {
            let (ip, trusted_route) = config.ipware.get_client_ip(req.headers(), config.strict);
            if let Some(ip) = ip.filter(|_| trusted_route || config.allow_untrusted) {
                return Some(ClientIp {
                    ip: ip.to_canonical(),
                    source: IpSource::Header { trusted_route },
                });
            }
        }
        peer_ip.map(|ip| ClientIp { ip, source: IpSource::Peer })
    }

    fn check(&self, ip: Option<IpAddr>) -> Result<(), RejectReason> {
        let config = &self.inner;
        if config.allow.is_empty() && config.block.is_empty() {
            return Ok(());
        }
        let Some(ip) = ip else {
            return Err(RejectReason::Unresolved);
        };
        if config.block.contains(ip) {
            return Err(RejectReason::Blocked);
        }
        if !config.allow.is_empty() && !config.allow.contains(ip) {
            return Err(RejectReason::NotAllowed);
        }
        Ok(())
    }

    fn reject(&self, rejection: Rejection) -> Response {
        tracing::debug!(
            ip = ?rejection.client_ip.map(|client_ip| client_ip.ip),
            reason = %rejection.reason,
            uri = %rejection.uri,
            "request rejected by ip filter"
        );
        match &self.inner.on_block {
            Some(handler) => handler(&rejection),
            None => rejection.into_response(),
        }
    }
}

/// The TCP peer address, from [`ConnectInfo`] or [`MockConnectInfo`].
fn peer_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    let extensions = req.extensions();
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr)
        .or_else(|| {
            extensions
                .get::<MockConnectInfo<SocketAddr>>()
                .map(|MockConnectInfo(addr)| addr)
        })
        .map(|addr| addr.ip().to_canonical())
}

impl fmt::Debug for IpFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let config = &self.inner;
        f.debug_struct("IpFilter")
            .field("ipware", &config.ipware)
            .field("strict", &config.strict)
            .field("allow_untrusted", &config.allow_untrusted)
            .field("trusted_proxies", &config.trusted_proxies)
            .field("allow", &config.allow)
            .field("block", &config.block)
            .field("on_block", &config.on_block.is_some())
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
        let client_ip = self.filter.resolve(&req);
        if let Err(reason) = self.filter.check(client_ip.map(|client_ip| client_ip.ip)) {
            let rejection = Rejection { client_ip, reason, uri: req.uri().clone() };
            return Either::Left(future::ready(Ok(self.filter.reject(rejection))));
        }
        if let Some(client_ip) = client_ip {
            req.extensions_mut().insert(client_ip);
        }
        Either::Right(self.inner.call(req))
    }
}

/// A request rejected by [`IpFilter`], passed to [`IpFilter::on_block`].
#[derive(Clone, Debug)]
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
pub enum RejectReason {
    /// The IP is in the block list.
    Blocked,
    /// The allow list is not empty and does not contain the IP.
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
