use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// A list of IP addresses and CIDR ranges.
#[derive(Clone, Debug, Default)]
pub(crate) struct IpRules(Vec<IpNet>);

impl IpRules {
    pub(crate) fn extend<I, R>(&mut self, rules: I) -> Result<(), RuleError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        for rule in rules {
            self.0.push(parse_rule(rule.as_ref())?);
        }
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(&ip))
    }
}

/// Parses `"10.0.0.0/8"`, `"2001:db8::/32"`, or a single address like `"192.168.1.5"`.
fn parse_rule(rule: &str) -> Result<IpNet, RuleError> {
    let rule = rule.trim();
    let parsed = if rule.contains('/') {
        IpNet::from_str(rule).ok()
    } else {
        IpAddr::from_str(rule).ok().map(IpNet::from)
    };
    parsed.ok_or_else(|| RuleError { rule: rule.to_owned() })
}

/// Returned when an allow or block rule is neither an IP address nor a CIDR range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    rule: String,
}

impl RuleError {
    /// The rule that failed to parse.
    pub fn rule(&self) -> &str {
        &self.rule
    }
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid IP rule `{}`: expected an IP address or CIDR range",
            self.rule
        )
    }
}

impl std::error::Error for RuleError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(list: &[&str]) -> IpRules {
        let mut rules = IpRules::default();
        rules.extend(list).unwrap();
        rules
    }

    #[test]
    fn matches_single_addresses_and_ranges() {
        let rules = rules(&["10.0.0.0/8", "192.168.1.5", "2001:db8::/32"]);
        assert!(rules.contains("10.1.2.3".parse().unwrap()));
        assert!(rules.contains("192.168.1.5".parse().unwrap()));
        assert!(!rules.contains("192.168.1.6".parse().unwrap()));
        assert!(rules.contains("2001:db8::1".parse().unwrap()));
        assert!(!rules.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn host_bits_in_cidr_are_accepted() {
        assert!(rules(&["10.1.2.3/8"]).contains("10.200.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_rules() {
        let mut rules = IpRules::default();
        let err = rules.extend(["10.0.0.0/8", "10.0.0.*"]).unwrap_err();
        assert_eq!(err.rule(), "10.0.0.*");
        assert!(rules.extend(["10.0.0.0/33"]).is_err());
    }
}
