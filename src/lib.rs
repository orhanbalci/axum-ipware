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
//! Proxy headers such as `X-Forwarded-For` are only read when the TCP peer is one
//! of your proxies, and only trusted when ipware can verify the proxy route. Tell
//! the filter where your proxies are, and ipware how many sit in front of the app:
//!
//! ```rust
//! use axum_ipware::ipware::{IpWare, IpWareConfig, IpWareProxy};
//! use axum_ipware::IpFilter;
//!
//! # fn main() -> Result<(), axum_ipware::RuleError> {
//! // One load balancer in 10.0.0.0/8 appends the client address to X-Forwarded-For.
//! let filter = IpFilter::new()
//!     .trusted_proxies(["10.0.0.0/8"])?
//!     .ipware(IpWare::new(
//!         IpWareConfig::new(["x-forwarded-for"], true),
//!         IpWareProxy::new(1, vec![]),
//!     ));
//! # Ok(())
//! # }
//! ```
//!
//! Requests from any other peer use the peer address, so a client that reaches the
//! app directly cannot bypass the rules by sending its own headers.
//!
//! ## 🧭 Choosing a source
//!
//! [`ClientIpSource`] picks how the client IP is read once the peer is trusted:
//!
//! | Source | Use when |
//! | --- | --- |
//! | `Ipware` (default) | ipware's header lookup with its proxy count or proxy list |
//! | `RightmostTrustedRange(header)` | your proxies' ranges are known; skips them from the right |
//! | `RightmostTrustedCount(header, n)` | a fixed number of proxies sit in front of the app |
//! | `RightmostNonPrivate(header)` | proxies are on private networks, clients are on the internet |
//! | `SingleHeader(header)` | a CDN sets one header, such as `CF-Connecting-IP` |
//! | `ConnectInfo` | there is no proxy |
//! | `Chain(sources)` | try several sources in order |
//!
//! ```rust
//! use axum_ipware::{header, ClientIpSource, IpFilter};
//!
//! # fn main() -> Result<(), axum_ipware::RuleError> {
//! let filter = IpFilter::new()
//!     .trust_private(true)
//!     .source(ClientIpSource::RightmostTrustedRange(header::X_FORWARDED_FOR))
//!     .max_forwarded_hops(10);
//! # Ok(())
//! # }
//! ```
//!
//! Rightmost sources read `X-Forwarded-For` lists and RFC 7239 `Forwarded`
//! headers, and stop at the first entry they cannot parse.
//!
//! ## 🛑 Custom rejections
//!
//! ```rust
//! use axum::http::StatusCode;
//! use axum::response::IntoResponse;
//! use axum_ipware::IpFilter;
//!
//! # fn main() -> Result<(), axum_ipware::RuleError> {
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
//! [`Router::route_layer`](axum::Router::route_layer) on a nested router.

mod client_ip;
mod filter;
pub mod header;
mod rules;
mod source;

pub use client_ip::{ClientIp, IpSource, MissingClientIp};
pub use filter::{IpFilter, IpFilterService, RejectReason, Rejection};
pub use ipware;
pub use rules::RuleError;
pub use source::ClientIpSource;
