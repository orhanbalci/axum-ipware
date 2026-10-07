use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use axum::http::{HeaderMap, HeaderName};

/// Where [`IpFilter`](crate::IpFilter) reads the client IP from.
///
/// Header sources are only consulted when the TCP peer is one of the
/// [`trusted_proxies`](crate::IpFilter::trusted_proxies) (or
/// [`allow_untrusted`](crate::IpFilter::allow_untrusted) is enabled). When a source
/// yields no address, the filter falls back to the peer address.
///
/// The rightmost sources read `X-Forwarded-For`-style lists or, for the
/// [`FORWARDED`](crate::header::FORWARDED) header, RFC 7239 `for=` parameters.
/// Multiple header lines are combined in order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientIpSource {
    /// The TCP peer address only. Headers are ignored.
    ConnectInfo,
    /// ipware's header lookup, configured with [`IpFilter::ipware`](crate::IpFilter::ipware).
    /// The header address is used when ipware reports a trusted route.
    Ipware,
    /// A header that holds a single IP set by the proxy, such as
    /// [`CF_CONNECTING_IP`](crate::header::CF_CONNECTING_IP) or
    /// [`X_REAL_IP`](crate::header::X_REAL_IP). The last header line is used.
    SingleHeader(HeaderName),
    /// The first IP from the right that is not private, loopback, link-local or
    /// otherwise reserved.
    RightmostNonPrivate(HeaderName),
    /// The IP added by the outermost of a fixed number of proxies: with `n`
    /// proxies in front of the app, the `n`th entry from the right.
    ///
    /// The proxy connecting to the app does not appear in the header, so one
    /// proxy means the rightmost entry is the client.
    RightmostTrustedCount(HeaderName, usize),
    /// The first IP from the right that is not a trusted proxy, using
    /// [`trusted_proxies`](crate::IpFilter::trusted_proxies) and the trust switches.
    RightmostTrustedRange(HeaderName),
    /// The first source in the list that yields an address.
    Chain(Vec<ClientIpSource>),
}

/// Reads the entries of a forwarding header, rightmost last.
///
/// Unparseable entries are kept as `None` so the rightmost walks stop at them
/// instead of skipping to an address further left.
pub(crate) fn forwarded_ips(headers: &HeaderMap, name: &HeaderName) -> Vec<Option<IpAddr>> {
    let forwarded = name == crate::header::FORWARDED;
    let mut ips = Vec::new();
    for value in headers.get_all(name) {
        let Ok(value) = value.to_str() else {
            ips.push(None);
            continue;
        };
        for element in split_unquoted(value, ',') {
            let ip = if forwarded {
                forwarded_for(element).and_then(parse_ip)
            } else {
                parse_ip(element)
            };
            ips.push(ip);
        }
    }
    ips
}

/// Reads a header that holds a single IP; the last header line wins.
pub(crate) fn single_ip(headers: &HeaderMap, name: &HeaderName) -> Option<IpAddr> {
    let value = headers.get_all(name).iter().next_back()?.to_str().ok()?;
    parse_ip(value)
}

/// The `for=` value of one RFC 7239 element, e.g. `for=192.0.2.60;proto=http`.
fn forwarded_for(element: &str) -> Option<&str> {
    split_unquoted(element, ';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim().eq_ignore_ascii_case("for").then_some(value)
    })
}

/// Splits on `separator`, ignoring separators inside double quotes.
fn split_unquoted(value: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;
    value.split(move |c: char| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        c == separator && !in_quotes
    })
}

/// Parses an IP from a header entry, accepting ports, brackets, quotes and IPv6 zones:
/// `192.0.2.1`, `192.0.2.1:80`, `"[2001:db8::1]:443"`, `fe80::1%eth0`.
pub(crate) fn parse_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim().trim_matches('"').trim();
    let host = if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if !(after.is_empty() || after.starts_with(':')) {
            return None;
        }
        host
    } else if entry.matches(':').count() == 1 {
        entry.split_once(':')?.0
    } else {
        entry
    };
    let host = host.split_once('%').map_or(host, |(addr, _zone)| addr);
    IpAddr::from_str(host).ok().map(|ip| ip.to_canonical())
}

pub(crate) fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

pub(crate) fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || in_v4(ip, [100, 64, 0, 0], 10),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Private, loopback, link-local, or another range that never identifies an
/// internet client.
pub(crate) fn is_non_public(ip: IpAddr) -> bool {
    if is_loopback(ip) || is_link_local(ip) || is_private(ip) || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => {
            ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || in_v4(ip, [0, 0, 0, 0], 8)
                || in_v4(ip, [192, 0, 0, 0], 24)
                || in_v4(ip, [198, 18, 0, 0], 15)
                || in_v4(ip, [240, 0, 0, 0], 4)
        }
        IpAddr::V6(ip) => ip.is_multicast() || in_v6(ip, [0x2001, 0xdb8], 32),
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX << (32 - prefix);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn in_v6(ip: Ipv6Addr, net: [u16; 2], prefix: u32) -> bool {
    let net = Ipv6Addr::new(net[0], net[1], 0, 0, 0, 0, 0, 0);
    let mask = u128::MAX << (128 - prefix);
    u128::from(ip) & mask == u128::from(net) & mask
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;
    use crate::header::{FORWARDED, X_FORWARDED_FOR, X_REAL_IP};

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn header_map(name: &HeaderName, values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn parses_entry_forms() {
        assert_eq!(parse_ip(" 192.0.2.1 "), ip("192.0.2.1"));
        assert_eq!(parse_ip("192.0.2.1:8080"), ip("192.0.2.1"));
        assert_eq!(parse_ip("2001:db8::1"), ip("2001:db8::1"));
        assert_eq!(parse_ip("[2001:db8::1]"), ip("2001:db8::1"));
        assert_eq!(parse_ip("\"[2001:db8::1]:443\""), ip("2001:db8::1"));
        assert_eq!(parse_ip("fe80::1%eth0"), ip("fe80::1"));
        assert_eq!(parse_ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_eq!(parse_ip("unknown"), None);
        assert_eq!(parse_ip("[2001:db8::1]x"), None);
        assert_eq!(parse_ip(""), None);
    }

    #[test]
    fn combines_x_forwarded_for_lines() {
        let headers = header_map(&X_FORWARDED_FOR, &["1.1.1.1, 2.2.2.2", "3.3.3.3"]);
        assert_eq!(
            forwarded_ips(&headers, &X_FORWARDED_FOR),
            vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")]
        );
    }

    #[test]
    fn keeps_invalid_entries_in_place() {
        let headers = header_map(&X_FORWARDED_FOR, &["1.1.1.1, garbage, 3.3.3.3"]);
        assert_eq!(
            forwarded_ips(&headers, &X_FORWARDED_FOR),
            vec![ip("1.1.1.1"), None, ip("3.3.3.3")]
        );
    }

    #[test]
    fn parses_rfc7239_forwarded() {
        let headers = header_map(
            &FORWARDED,
            &[
                "for=192.0.2.60;proto=http;by=203.0.113.43, For=\"[2001:db8:cafe::17]:4711\"",
                "for=unknown, proto=https, for=_hidden",
            ],
        );
        assert_eq!(
            forwarded_ips(&headers, &FORWARDED),
            vec![ip("192.0.2.60"), ip("2001:db8:cafe::17"), None, None, None]
        );
    }

    #[test]
    fn single_ip_uses_last_line() {
        let headers = header_map(&X_REAL_IP, &["1.1.1.1", "2.2.2.2"]);
        assert_eq!(single_ip(&headers, &X_REAL_IP), ip("2.2.2.2"));
        let headers = header_map(&X_REAL_IP, &["1.1.1.1, 2.2.2.2"]);
        assert_eq!(single_ip(&headers, &X_REAL_IP), None);
    }

    #[test]
    fn classifies_addresses() {
        for private in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "fd00::1",
        ] {
            assert!(is_private(private.parse().unwrap()), "{private}");
        }
        for link_local in ["169.254.1.1", "fe80::1"] {
            assert!(is_link_local(link_local.parse().unwrap()), "{link_local}");
        }
        for non_public in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "192.0.2.1",
            "2001:db8::1",
            "224.0.0.1",
        ] {
            assert!(is_non_public(non_public.parse().unwrap()), "{non_public}");
        }
        for public in ["93.184.216.34", "8.8.8.8", "2606:4700::1111"] {
            assert!(!is_non_public(public.parse().unwrap()), "{public}");
        }
    }
}
