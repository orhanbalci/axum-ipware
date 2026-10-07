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
- `ClientIp` extractor (also as `Option<ClientIp>`) with the address source.
- Custom rejection responses via `on_block`; `403 Forbidden` by default.
- IPv4-mapped IPv6 addresses are matched as IPv4.

Requires ipware 0.5.
