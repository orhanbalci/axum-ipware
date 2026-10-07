// This crate is entirely safe
#![forbid(unsafe_code)]
// Ensures that `pub` means published in the public API.
#![deny(unreachable_pub)]

//! Client IP extraction and IP allow/block filtering middleware for
//! [axum](https://github.com/tokio-rs/axum), powered by
//! [ipware](https://github.com/orhanbalci/ipware).
//!
//! ## 📦 Cargo.toml
//!
//! ```toml
//! [dependencies]
//! axum-ipware = "0.1"
//! ```
//!
//! Enable the `providers` feature for platform presets and the published IP
//! ranges of CDNs, load balancers and webhook senders:
//!
//! ```toml
//! axum-ipware = { version = "0.1", features = ["providers"] }
//! ```
//!
//! | Feature | Adds |
//! | --- | --- |
//! | `providers` | platform presets and provider IP ranges from ipware |
//! | `glob` | glob patterns such as `192.168.1.*` in lists and rules |
//! | `refresh` | lists kept up to date from files or custom loaders |
//! | `fetch` | an HTTPS source for `refresh`, built on reqwest with rustls |
//!
//! ## 🔧 Example
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//!
//! use axum::routing::get;
//! use axum::Router;
//! use axum_ipware::{ClientIp, IpFilter};
//!
//! async fn handler(client_ip: ClientIp) -> String {
//!     format!("hello {client_ip}")
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let filter = IpFilter::new()
//!         .allow(["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1", "::1"])?
//!         .block(["10.0.0.13"])?;
//!
//!     let app = Router::new().route("/", get(handler)).layer(filter);
//!
//!     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//!     // ConnectInfo gives the filter the TCP peer address.
//!     axum::serve(
//!         listener,
//!         app.into_make_service_with_connect_info::<SocketAddr>(),
//!     )
//!     .await?;
//!     Ok(())
//! }
//! ```
//!
//! ## 🤝 Behind a proxy
//!
//! The client IP is resolved by ipware's
//! [`ClientIpResolver`]. Proxy headers are only read when
//! the TCP peer is one of your trusted proxies, so a client that reaches the app
//! directly cannot bypass the rules by sending its own headers.
//!
//! ```rust
//! use axum_ipware::ipware::{header, ClientIpResolver, ClientIpStrategy, IpRanges};
//! use axum_ipware::IpFilter;
//!
//! # fn main() -> Result<(), axum_ipware::ipware::IpRangeError> {
//! // Load balancers in 10.0.0.0/8 append the client address to X-Forwarded-For.
//! let filter = IpFilter::new()
//!     .resolver(
//!         ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
//!             header::X_FORWARDED_FOR,
//!         ))
//!         .trusted_proxies(IpRanges::parse(["10.0.0.0/8"])?)
//!         .max_forwarded_hops(10),
//!     )
//!     .allow(["10.0.0.0/8", "192.168.0.0/16"])?;
//! # Ok(())
//! # }
//! ```
//!
//! [`ClientIpStrategy`] also covers a fixed proxy count,
//! the rightmost public address, single-IP CDN headers such as `CF-Connecting-IP`,
//! RFC 7239 `Forwarded`, ipware's own header lookup, and chains of these. Without a
//! resolver, the filter uses the peer address.
//!
//! ## 🌐 Platform presets and webhook allow lists
//!
//! With the `providers` feature, ipware's presets configure the header and the
//! proxy ranges of a CDN or hosting platform: `Cloudflare`, `CloudFront`,
//! `Fastly`, `GoogleCloudLoadBalancer` and `FlyIo`.
//!
//! ```rust
//! # #[cfg(feature = "providers")] {
//! use axum_ipware::ipware::providers::{self, Platform};
//! use axum_ipware::ipware::ClientIpResolver;
//! use axum_ipware::IpFilter;
//!
//! // Behind Cloudflare: CF-Connecting-IP, trusted only from Cloudflare's ranges.
//! let filter = IpFilter::new().resolver(ClientIpResolver::platform(Platform::Cloudflare));
//!
//! // A webhook endpoint that only accepts GitHub's delivery ranges.
//! let webhooks = IpFilter::new().allow_ranges(providers::github_hooks());
//! # }
//! ```
//!
//! The built-in ranges are snapshots; see
//! [`ipware::providers`](https://docs.rs/ipware/latest/ipware/providers/) for
//! their date and for parsers to load fresh lists, which you can pass to
//! [`IpFilter::allow_ranges`] and [`IpFilter::block_ranges`].
//!
//! ## 📜 Ordered rules
//!
//! Besides allow and block lists, [`IpFilter::rules`] takes nginx-style rules that
//! are checked first; the first matching rule decides, and when none matches the
//! lists decide. Rules can be written in code or parsed from text, e.g. a config
//! file:
//!
//! ```rust
//! use axum_ipware::{parse_rules, IpFilter, Rule};
//!
//! let filter = IpFilter::new().rules(
//!     parse_rules(
//!         "deny 10.0.0.13;
//!          allow 10.0.0.0/8;
//!          deny all;",
//!     )
//!     .unwrap(),
//! );
//! // Equivalent in code:
//! let same = IpFilter::new().rules([
//!     Rule::parse("deny 10.0.0.13").unwrap(),
//!     Rule::parse("allow 10.0.0.0/8").unwrap(),
//!     Rule::deny_all(),
//! ]);
//! ```
//!
//! With the `glob` feature, lists and rules also accept patterns such as
//! `192.168.1.*`, to ease migrating from glob-based filters. Patterns match the
//! address text, so prefer CIDR ranges where possible.
//!
//! ## 📈 Observability
//!
//! [`IpFilter::on_allow`] runs for every request let through and
//! [`IpFilter::on_block`] builds the response for rejected ones; both see the
//! client IP, method and URI. [`IpFilter::stats`] counts requests by outcome, and
//! every rejection is logged with `tracing` at debug level.
//!
//! ```rust
//! use axum_ipware::IpFilter;
//!
//! let filter = IpFilter::new().on_allow(|allowed| {
//!     tracing::info!(ip = ?allowed.client_ip, uri = %allowed.uri, "allowed");
//! });
//! let stats = filter.stats();
//! println!("{} allowed, {} blocked", stats.allowed, stats.blocked);
//! ```
//!
//! ## 🔄 Live updates
//!
//! Rules can change while the server runs. [`IpFilter::handle`] returns an
//! [`IpFilterHandle`] that replaces named allow and block lists, the resolver, or
//! the default policy; each change applies atomically to new requests.
//!
//! ```rust
//! use axum_ipware::ipware::IpRanges;
//! use axum_ipware::IpFilter;
//!
//! // Reject everything until the first allow list arrives.
//! let filter = IpFilter::new().default_deny(true);
//! let handle = filter.handle();
//! // ... add `filter` to the router and start the server ...
//!
//! // From a background task, e.g. after downloading a list:
//! handle.set_allow_list("office", IpRanges::parse(["192.0.2.0/24"]).unwrap());
//! handle.set_block_list("abuse", IpRanges::parse(["203.0.113.0/24"]).unwrap());
//! handle.remove_block_list("abuse");
//! ```
//!
//! Outside the middleware, [`IpFilter::check`] tests an IP against the current
//! rules, and [`IpFilter::resolve`] / [`IpFilter::resolve_parts`] resolve a
//! request's client IP.
//!
//! ## 🔁 Refreshing lists
//!
//! With the `refresh` feature, [`refresh::Refresh`] reloads a named list on an
//! interval from a file, an HTTPS URL (`fetch` feature) or your own async loader:
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
//! Whoever controls a list's source controls what it allows, so a refresh is
//! applied only when it passes every check, and the list in use is kept otherwise:
//!
//! - Failed loads, oversized responses, parse errors and empty lists never
//!   replace the current list.
//! - Safeguards cap the size and the number of addresses a list may cover, and
//!   reject sudden shrinking or growth; allow lists and trusted proxies get
//!   stricter limits than block lists.
//! - Allow lists and trusted proxies are only refreshed through their own
//!   constructors, `Refresh::allow_list` and `Refresh::trusted_proxies`.
//! - The HTTPS source only accepts `https://` URLs, follows redirects only to the
//!   same host, and times out after 30 seconds.
//!
//! ### Safeguards
//!
//! Every refresh is checked against `refresh::Safeguards` before it is applied.
//! Each list type starts from its own defaults, so lists are protected without
//! extra configuration:
//!
//! | Limit | Checks | Block lists | Allow lists and trusted proxies |
//! | --- | --- | --- | --- |
//! | `max_bytes` | size of the response or file | 32 MiB | 4 MiB |
//! | `max_ipv4_addresses` | IPv4 addresses the list may cover | 2²⁸ (a `/4`) | 2²⁴ (a `/8`) |
//! | `max_ipv6_addresses` | IPv6 addresses the list may cover | 2¹¹² (a `/16`) | 2⁹⁶ (a `/32`) |
//! | `max_shrink` | how much smaller than the last applied list | half | half |
//! | `max_growth` | how many times larger than the last applied list | no limit | double |
//!
//! Adjust them when a list legitimately needs more room, such as a large
//! blocklist or one that changes a lot between refreshes. `None` disables the
//! shrink or growth check:
//!
//! ```rust,no_run
//! # #[cfg(feature = "refresh")] {
//! use axum_ipware::refresh::{Refresh, Safeguards, Source};
//! use axum_ipware::IpFilter;
//!
//! let filter = IpFilter::new();
//! let blocklist = Refresh::block_list(&filter.handle(), "blocklist")
//!     .source(Source::file("/etc/myapp/blocklist.txt"))
//!     .safeguards(
//!         Safeguards::for_block_lists()
//!             .max_bytes(64 << 20) // accept up to 64 MiB
//!             .max_shrink(Some(0.8)) // allow losing up to 80% at once
//!             .max_growth(Some(3.0)), // reject more than tripling
//!     );
//! # }
//! ```
//!
//! Loosening the limits of allow lists and trusted proxies lets whoever controls
//! the source admit more addresses, so only do it for sources you trust.
//!
//! The `fetch` feature's dependencies need MSRV-aware dependency resolution on Rust
//! older than 1.88, which is the default for projects on the 2024 edition.
//!
//! ## 🛑 Custom rejections
//!
//! ```rust
//! use axum::http::StatusCode;
//! use axum::response::IntoResponse;
//! use axum_ipware::IpFilter;
//!
//! # fn main() -> Result<(), axum_ipware::ipware::IpRangeError> {
//! let filter = IpFilter::new()
//!     .block(["203.0.113.0/24"])?
//!     .on_block(|rejection| {
//!         (StatusCode::NOT_FOUND, format!("{}", rejection.reason)).into_response()
//!     });
//! # Ok(())
//! # }
//! ```
//!
//! To filter only some routes, add the layer with
//! [`Router::route_layer`] on a nested router.
//!
//! [`ClientIpResolver`]: https://docs.rs/ipware/latest/ipware/struct.ClientIpResolver.html
//! [`ClientIpStrategy`]: https://docs.rs/ipware/latest/ipware/enum.ClientIpStrategy.html
//! [`Router::route_layer`]: https://docs.rs/axum/latest/axum/struct.Router.html#method.route_layer
//! [`IpFilter::allow_ranges`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.allow_ranges
//! [`IpFilter::block_ranges`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.block_ranges
//! [`IpFilter::rules`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.rules
//! [`IpFilter::on_allow`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.on_allow
//! [`IpFilter::on_block`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.on_block
//! [`IpFilter::stats`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.stats
//! [`IpFilter::check`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.check
//! [`IpFilter::handle`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.handle
//! [`IpFilter::resolve`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.resolve
//! [`IpFilter::resolve_parts`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilter.html#method.resolve_parts
//! [`IpFilterHandle`]: https://docs.rs/axum-ipware/latest/axum_ipware/struct.IpFilterHandle.html
//! [`refresh::Refresh`]: https://docs.rs/axum-ipware/latest/axum_ipware/refresh/struct.Refresh.html

mod client_ip;
mod filter;
#[cfg(feature = "refresh")]
pub mod refresh;
mod rules;

pub use client_ip::{ClientIp, MissingClientIp};
pub use filter::{
    Allowed,
    FilterStats,
    IpFilter,
    IpFilterHandle,
    IpFilterService,
    RejectReason,
    Rejection,
};
pub use ipware;
pub use ipware::IpSource;
#[cfg(feature = "glob")]
pub use rules::PatternError;
pub use rules::{parse_rules, Action, Rule, RuleParseError};
