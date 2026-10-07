# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `IpFilter` tower layer: resolves the client IP with ipware, falls back to the
  `ConnectInfo` peer address, and applies allow/block rules.
- IP address and CIDR rules for IPv4 and IPv6; block rules win over allow rules.
- Header addresses are only used on a trusted proxy route unless `allow_untrusted` is enabled.
- `ClientIp` extractor (also as `Option<ClientIp>`) with the address source.
- Custom rejection responses via `on_block`; `403 Forbidden` by default.
- IPv4-mapped IPv6 addresses are matched as IPv4.
