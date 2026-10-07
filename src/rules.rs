use std::fmt;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;

use ipware::IpRanges;

/// One request's IP, with lookups computed at most once across all rules.
pub(crate) struct MatchContext<'a> {
    ip: IpAddr,
    #[cfg(feature = "glob")]
    text: Option<String>,
    #[cfg(feature = "geo")]
    geo: Option<&'a crate::geo::GeoDb>,
    #[cfg(feature = "geo")]
    country: Option<Option<crate::geo::CountryCode>>,
    #[cfg(feature = "geo")]
    asn: Option<Option<u32>>,
    _geo: PhantomData<&'a ()>,
}

impl<'a> MatchContext<'a> {
    pub(crate) fn new(ip: IpAddr) -> Self {
        MatchContext {
            ip,
            #[cfg(feature = "glob")]
            text: None,
            #[cfg(feature = "geo")]
            geo: None,
            #[cfg(feature = "geo")]
            country: None,
            #[cfg(feature = "geo")]
            asn: None,
            _geo: PhantomData,
        }
    }

    #[cfg(feature = "geo")]
    pub(crate) fn with_geo(mut self, geo: Option<&'a crate::geo::GeoDb>) -> Self {
        self.geo = geo;
        self
    }

    #[cfg(feature = "glob")]
    fn text(&mut self) -> &str {
        let ip = self.ip;
        self.text.get_or_insert_with(|| ip.to_string())
    }

    #[cfg(feature = "geo")]
    fn country(&mut self) -> Option<crate::geo::CountryCode> {
        let (ip, geo) = (self.ip, self.geo);
        *self
            .country
            .get_or_insert_with(|| geo.and_then(|geo| geo.country(ip)))
    }

    #[cfg(feature = "geo")]
    fn asn(&mut self) -> Option<u32> {
        let (ip, geo) = (self.ip, self.geo);
        *self
            .asn
            .get_or_insert_with(|| geo.and_then(|geo| geo.asn(ip)))
    }
}

/// What a list or rule matches.
#[derive(Clone, Debug)]
pub(crate) enum Matcher {
    All,
    Ranges(Arc<IpRanges>),
    #[cfg(feature = "glob")]
    Patterns(Arc<[GlobPattern]>),
    #[cfg(feature = "geo")]
    Countries(Arc<[crate::geo::CountryCode]>),
    #[cfg(feature = "geo")]
    Asns(Arc<[u32]>),
}

impl Matcher {
    pub(crate) fn matches(&self, ctx: &mut MatchContext<'_>) -> bool {
        match self {
            Matcher::All => true,
            Matcher::Ranges(ranges) => ranges.contains(ctx.ip),
            #[cfg(feature = "glob")]
            Matcher::Patterns(patterns) => {
                let text = ctx.text();
                patterns.iter().any(|pattern| pattern.matches(text))
            }
            #[cfg(feature = "geo")]
            Matcher::Countries(codes) => ctx.country().is_some_and(|code| codes.contains(&code)),
            #[cfg(feature = "geo")]
            Matcher::Asns(asns) => ctx.asn().is_some_and(|asn| asns.contains(&asn)),
        }
    }
}

/// Whether an ordered [`Rule`] lets a request through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Let the request through.
    Allow,
    /// Reject the request with [`RejectReason::DeniedByRule`](crate::RejectReason::DeniedByRule).
    Deny,
}

/// An nginx-style `allow` or `deny` rule for [`IpFilter::rules`](crate::IpFilter::rules).
///
/// Ordered rules are checked before the allow and block lists, and the first
/// rule that matches decides. When none matches, the lists decide.
///
/// ```rust
/// use axum_ipware::{IpFilter, RejectReason, Rule};
///
/// let filter = IpFilter::new().rules([
///     Rule::parse("deny 10.0.0.13").unwrap(),
///     Rule::parse("allow 10.0.0.0/8").unwrap(),
///     Rule::deny_all(),
/// ]);
/// assert_eq!(filter.check("10.1.2.3".parse().unwrap()), Ok(()));
/// assert_eq!(
///     filter.check("10.0.0.13".parse().unwrap()),
///     Err(RejectReason::DeniedByRule)
/// );
/// assert_eq!(
///     filter.check("192.0.2.1".parse().unwrap()),
///     Err(RejectReason::DeniedByRule)
/// );
/// ```
#[derive(Clone, Debug)]
pub struct Rule {
    action: Action,
    matcher: Matcher,
}

impl Rule {
    /// Allows addresses in `ranges`.
    pub fn allow(ranges: IpRanges) -> Self {
        Rule {
            action: Action::Allow,
            matcher: Matcher::Ranges(Arc::new(ranges)),
        }
    }

    /// Denies addresses in `ranges`.
    pub fn deny(ranges: IpRanges) -> Self {
        Rule {
            action: Action::Deny,
            matcher: Matcher::Ranges(Arc::new(ranges)),
        }
    }

    /// Allows every address; ends a list of rules with a default.
    pub fn allow_all() -> Self {
        Rule { action: Action::Allow, matcher: Matcher::All }
    }

    /// Denies every address; ends a list of rules with a default.
    pub fn deny_all() -> Self {
        Rule { action: Action::Deny, matcher: Matcher::All }
    }

    /// Allows addresses matching a glob pattern such as `192.168.1.*`. Requires
    /// the `glob` feature.
    #[cfg(feature = "glob")]
    pub fn allow_pattern(pattern: &str) -> Result<Self, PatternError> {
        Ok(Rule {
            action: Action::Allow,
            matcher: patterns([pattern])?,
        })
    }

    /// Denies addresses matching a glob pattern such as `192.168.1.*`. Requires
    /// the `glob` feature.
    #[cfg(feature = "glob")]
    pub fn deny_pattern(pattern: &str) -> Result<Self, PatternError> {
        Ok(Rule {
            action: Action::Deny,
            matcher: patterns([pattern])?,
        })
    }

    /// Allows clients in these countries (ISO codes such as `"SE"`). Requires the
    /// `geo` feature and a database set with [`IpFilter::geo`](crate::IpFilter::geo).
    #[cfg(feature = "geo")]
    pub fn allow_countries<I, C>(codes: I) -> Result<Self, crate::geo::InvalidCountryCode>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<str>,
    {
        let codes = crate::geo::country_codes(codes)?;
        Ok(Rule {
            action: Action::Allow,
            matcher: Matcher::Countries(codes),
        })
    }

    /// Denies clients in these countries. Requires the `geo` feature.
    #[cfg(feature = "geo")]
    pub fn deny_countries<I, C>(codes: I) -> Result<Self, crate::geo::InvalidCountryCode>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<str>,
    {
        let codes = crate::geo::country_codes(codes)?;
        Ok(Rule {
            action: Action::Deny,
            matcher: Matcher::Countries(codes),
        })
    }

    /// Allows clients in these autonomous systems. Requires the `geo` feature.
    #[cfg(feature = "geo")]
    pub fn allow_asns(asns: impl IntoIterator<Item = u32>) -> Self {
        Rule {
            action: Action::Allow,
            matcher: Matcher::Asns(asns.into_iter().collect()),
        }
    }

    /// Denies clients in these autonomous systems. Requires the `geo` feature.
    #[cfg(feature = "geo")]
    pub fn deny_asns(asns: impl IntoIterator<Item = u32>) -> Self {
        Rule {
            action: Action::Deny,
            matcher: Matcher::Asns(asns.into_iter().collect()),
        }
    }

    /// Parses `allow <target>` or `deny <target>`, where the target is `all`, an
    /// IP address, a CIDR range, with the `glob` feature a pattern such as
    /// `192.168.1.*`, or with the `geo` feature `country SE,NO` or `asn 64496`.
    /// A trailing `;` is accepted, as in nginx.
    pub fn parse(rule: &str) -> Result<Self, RuleParseError> {
        let error = |message: &str| RuleParseError { line: None, message: message.to_owned() };
        let rule = rule.trim().trim_end_matches(';').trim();
        let (action, target) = rule
            .split_once(char::is_whitespace)
            .ok_or_else(|| error("expected `allow <target>` or `deny <target>`"))?;
        let action = match action {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => return Err(error("the rule must start with `allow` or `deny`")),
        };
        let target = target.trim();
        let geo_target = target
            .split_once(char::is_whitespace)
            .filter(|(kind, _)| matches!(*kind, "country" | "asn"));
        let matcher = if let Some((kind, values)) = geo_target {
            #[cfg(feature = "geo")]
            {
                let values = values.split(',').map(str::trim).filter(|v| !v.is_empty());
                if kind == "country" {
                    Matcher::Countries(
                        crate::geo::country_codes(values).map_err(|err| error(&err.to_string()))?,
                    )
                } else {
                    let asns = values
                        .map(|asn| asn.trim_start_matches("AS").parse::<u32>())
                        .collect::<Result<Arc<[u32]>, _>>()
                        .map_err(|_| error("expected AS numbers such as `asn 64496`"))?;
                    Matcher::Asns(asns)
                }
            }
            #[cfg(not(feature = "geo"))]
            {
                let _ = (kind, values);
                return Err(error("country and asn rules require the `geo` feature"));
            }
        } else if target == "all" {
            Matcher::All
        } else if target.contains(['*', '?']) {
            #[cfg(feature = "glob")]
            {
                patterns([target]).map_err(|err| error(&err.to_string()))?
            }
            #[cfg(not(feature = "glob"))]
            {
                return Err(error("glob patterns require the `glob` feature"));
            }
        } else {
            let ranges = IpRanges::parse([target]).map_err(|err| error(&err.to_string()))?;
            Matcher::Ranges(Arc::new(ranges))
        };
        Ok(Rule { action, matcher })
    }

    /// Whether the rule allows or denies.
    pub fn action(&self) -> Action {
        self.action
    }

    pub(crate) fn matches(&self, ctx: &mut MatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }
}

/// Parses one rule per line with [`Rule::parse`]; blank lines and `#` comments
/// are skipped.
///
/// ```rust
/// let rules = axum_ipware::parse_rules(
///     "# office
///     allow 192.0.2.0/24;
///     deny all;",
/// )
/// .unwrap();
/// assert_eq!(rules.len(), 2);
/// ```
pub fn parse_rules(text: &str) -> Result<Vec<Rule>, RuleParseError> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.split('#').next().unwrap_or_default().trim()))
        .filter(|(_, line)| !line.is_empty())
        .map(|(number, line)| {
            Rule::parse(line).map_err(|err| RuleParseError { line: Some(number), ..err })
        })
        .collect()
}

/// Returned when a rule cannot be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleParseError {
    line: Option<usize>,
    message: String,
}

impl RuleParseError {
    /// The 1-based line number, when parsed with [`parse_rules`].
    pub fn line(&self) -> Option<usize> {
        self.line
    }
}

impl fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for RuleParseError {}

#[cfg(feature = "glob")]
pub(crate) fn patterns<I, P>(patterns: I) -> Result<Matcher, PatternError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let patterns = patterns
        .into_iter()
        .map(|pattern| GlobPattern::new(pattern.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Matcher::Patterns(patterns.into()))
}

/// A glob pattern over an IP's text form: `*` matches any run of characters
/// and `?` matches one.
#[cfg(feature = "glob")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GlobPattern(Box<[u8]>);

#[cfg(feature = "glob")]
impl GlobPattern {
    fn new(pattern: &str) -> Result<Self, PatternError> {
        let pattern = pattern.trim().to_ascii_lowercase();
        let valid = |c: char| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '*' | '?');
        if pattern.is_empty() || !pattern.chars().all(valid) {
            return Err(PatternError { pattern });
        }
        Ok(GlobPattern(pattern.into_bytes().into()))
    }

    fn matches(&self, text: &str) -> bool {
        let (pattern, text) = (&self.0[..], text.as_bytes());
        let (mut p, mut t) = (0, 0);
        // Position after the last `*` and the text position it was tried at.
        let mut backtrack: Option<(usize, usize)> = None;
        while t < text.len() {
            match pattern.get(p) {
                Some(b'*') => {
                    p += 1;
                    backtrack = Some((p, t));
                }
                Some(&c) if c == b'?' || c == text[t] => {
                    p += 1;
                    t += 1;
                }
                _ => match backtrack {
                    Some((star_p, star_t)) => {
                        p = star_p;
                        t = star_t + 1;
                        backtrack = Some((star_p, star_t + 1));
                    }
                    None => return false,
                },
            }
        }
        pattern[p..].iter().all(|&c| c == b'*')
    }
}

/// Returned when a glob pattern contains characters that cannot appear in an IP
/// address. Requires the `glob` feature.
#[cfg(feature = "glob")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternError {
    pattern: String,
}

#[cfg(feature = "glob")]
impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid IP pattern `{}`: use address characters with `*` and `?`",
            self.pattern
        )
    }
}

#[cfg(feature = "glob")]
impl std::error::Error for PatternError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn matches(rule: &Rule, s: &str) -> bool {
        rule.matches(&mut MatchContext::new(ip(s)))
    }

    #[test]
    fn parses_rules() {
        let rule = Rule::parse("  deny 10.0.0.0/8; ").unwrap();
        assert_eq!(rule.action(), Action::Deny);
        assert!(matches(&rule, "10.1.2.3"));
        assert!(!matches(&rule, "11.1.2.3"));
        assert!(matches(&Rule::parse("allow all").unwrap(), "::1"));
        assert!(Rule::parse("permit 10.0.0.1").is_err());
        assert!(Rule::parse("allow").is_err());
        assert!(Rule::parse("allow 10.0.0.0/33").is_err());
    }

    #[test]
    fn parse_rules_reports_line_numbers() {
        let err = parse_rules("allow 10.0.0.0/8\n\n# comment\nallow nope\n").unwrap_err();
        assert_eq!(err.line(), Some(4));
        assert!(err.to_string().starts_with("line 4:"));
    }

    #[cfg(not(feature = "geo"))]
    #[test]
    fn geo_rules_need_geo_feature() {
        assert!(Rule::parse("deny country RU").is_err());
    }

    #[cfg(not(feature = "glob"))]
    #[test]
    fn patterns_need_glob_feature() {
        assert!(Rule::parse("allow 192.168.1.*").is_err());
    }

    #[cfg(feature = "glob")]
    #[test]
    fn glob_patterns() {
        let glob = |pattern: &str, text: &str| GlobPattern::new(pattern).unwrap().matches(text);
        assert!(glob("192.168.1.*", "192.168.1.200"));
        assert!(!glob("192.168.1.*", "192.168.10.1"));
        assert!(glob("172.??.6*.12", "172.16.64.12"));
        assert!(!glob("172.??.6*.12", "172.1.64.12"));
        assert!(glob("*", "2001:db8::1"));
        assert!(glob("2001:DB8::*", "2001:db8::1"));
        assert!(glob("10.*.*.1", "10.20.30.1"));
        assert!(!glob("10.*.*.1", "10.20.30.10"));
        assert!(glob("1*1", "1.2.3.1"));
        assert!(GlobPattern::new("192.168.1.x").is_err());
        assert!(GlobPattern::new("").is_err());
        let rule = Rule::parse("deny 192.168.1.*").unwrap();
        assert!(matches(&rule, "192.168.1.5"));
    }
}
