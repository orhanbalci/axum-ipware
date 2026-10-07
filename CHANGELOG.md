# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `IpFilter` tower layer: resolves the client IP with ipware, falls back to the
  `ConnectInfo` peer address, and applies allow/block rules.
- IP address and CIDR rules for IPv4 and IPv6; block rules win over allow rules.
- `trusted_proxies`: proxy headers are only read when the TCP peer is in these
  ranges and ipware verifies the route; other requests use the peer address.
  `allow_untrusted` skips both checks.
- `ClientIp` extractor (also as `Option<ClientIp>`) with the address source.
- Custom rejection responses via `on_block`; `403 Forbidden` by default.
- IPv4-mapped IPv6 addresses are matched as IPv4.
