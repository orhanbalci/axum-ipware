# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ClientIpSource` to choose how the client IP is read: `ConnectInfo`, `Ipware`
  (default), `SingleHeader`, `RightmostNonPrivate`, `RightmostTrustedCount`,
  `RightmostTrustedRange`, and `Chain`.
- RFC 7239 `Forwarded` header parsing; `X-Forwarded-For` entries with ports,
  brackets, quotes and IPv6 zones; multiple header lines are combined.
- `trust_loopback`, `trust_private`, and `trust_link_local` switches for trusted proxies.
- `max_forwarded_hops` to limit how far the rightmost sources walk.
- `header` module with common client IP header names.

- `IpFilter` tower layer: resolves the client IP with ipware, falls back to the
  `ConnectInfo` peer address, and applies allow/block rules.
- IP address and CIDR rules for IPv4 and IPv6; block rules win over allow rules.
- `trusted_proxies`: proxy headers are only read when the TCP peer is in these
  ranges and ipware verifies the route; other requests use the peer address.
  `allow_untrusted` skips both checks.
- Private and loopback client IPs (e.g. `10.1.2.3`) behind a trusted proxy are
  resolved from the header instead of falling back to the proxy address, so
  intranet allow lists match the real client. Requires the ipware fix, used from
  git until ipware 0.4.1 is released.
- `ClientIp` extractor (also as `Option<ClientIp>`) with the address source.
- Custom rejection responses via `on_block`; `403 Forbidden` by default.
- IPv4-mapped IPv6 addresses are matched as IPv4.
