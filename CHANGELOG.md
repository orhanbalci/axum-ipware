# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `IpFilter` tower layer: resolves the client IP, applies allow/block rules, and
  stores the address as a `ClientIp` request extension.
- Client IP resolution through ipware's `ClientIpResolver`, set with
  `IpFilter::resolver`. Proxy headers are only read when the TCP peer is a
  trusted proxy; otherwise, and by default, the peer address from `ConnectInfo`
  (or `MockConnectInfo` in tests) is used.
- All ipware `ClientIpStrategy` options: rightmost trusted range, rightmost
  trusted count, rightmost non-private, single header, ipware lookup, and chains;
  `X-Forwarded-For` and RFC 7239 `Forwarded` headers.
- IP address and CIDR rules for IPv4 and IPv6; block rules win over allow rules.
  Requests are rejected when rules exist and no IP can be resolved.
- `allow_ranges` and `block_ranges` for parsed `IpRanges`, such as provider
  ranges or lists fetched at startup. An empty allow set rejects every request.
- `providers` feature: ipware's platform presets (Cloudflare, CloudFront,
  Fastly, Google Cloud load balancers, Fly.io) and webhook ranges.
- Live updates: `IpFilter::handle` returns an `IpFilterHandle` that replaces or
  removes named allow and block lists (`allow_list` / `block_list`), the
  resolver, and the default policy while the server runs. Rules are swapped
  atomically and read lock-free; clones of a filter share them.
- `default_deny` to reject IPs outside the allow lists even before any list is set.
- `refresh` feature: `refresh::Refresh` reloads a named block list, allow list
  or trusted proxy ranges on an interval from a file or a custom loader, and
  `fetch` adds an HTTPS source. A refresh is applied only when it loads, parses,
  is non-empty and passes `Safeguards` (size, address coverage, sudden shrink or
  growth); otherwise the list in use is kept. The HTTPS source is https-only and
  follows redirects only to the same host.
- `IpFilter::check`, `resolve` and `resolve_parts` for use outside the middleware.
- `ClientIp` extractor (also as `Option<ClientIp>`) with the address source.
- Custom rejection responses via `on_block`; `403 Forbidden` by default.
- IPv4-mapped IPv6 addresses are matched as IPv4.

Requires ipware 0.5 with `IpRanges` address counts (from git until the next ipware release).
