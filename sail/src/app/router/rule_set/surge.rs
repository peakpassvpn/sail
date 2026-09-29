//! Surge's rule-sets, as Surge reads them: a `RULE-SET` file holds a rule
//! without its policy a line (`classical`), a `DOMAIN-SET` file a domain a
//! line, `.x` for `x` and every name under it (`domain`). Comments start
//! with `#`, `//` or `;`. A line Surge would not take, or sail cannot,
//! is passed over, as Surge passes over a line it does not take.
//!
//! The plain lines of a set, of domains, keywords and IP prefixes, are
//! matched as one rule; each of the others as a rule of its own.

use anyhow::{anyhow, Result};
use tracing::debug;

use super::rule;
use crate::app::router::matcher::Condition;
use crate::config::rule_set::{ClashBehavior, HeadlessRule};
use crate::runtime::RuntimeEnv;

/// Reads a rule-set of Surge's text, of `behavior`; `env`'s data files are
/// those its rules name.
pub(crate) fn read(
    data: &[u8],
    behavior: ClashBehavior,
    env: &RuntimeEnv,
) -> Result<Vec<Condition>> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow!("not UTF-8 text"))?;
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(['#', ';']) && !l.starts_with("//"));
    match behavior {
        ClashBehavior::Domain => {
            let mut rule = HeadlessRule::default();
            for line in lines {
                // A comment after it, with a space before.
                let mut words = line.split_whitespace();
                let name = words.next().unwrap_or_default().to_ascii_lowercase();
                let comment = words
                    .next()
                    .is_none_or(|w| w.starts_with(['#', ';']) || w.starts_with("//"));
                if !comment || name.ends_with('.') {
                    debug!("rule-set: {:?} is no domain; passed over", line);
                    continue;
                }
                match name.strip_prefix('.') {
                    Some(base) if !base.is_empty() => rule.domain_suffix.push(base.to_string()),
                    Some(_) => debug!("rule-set: {:?} is no domain; passed over", line),
                    None => rule.domain.push(name),
                }
            }
            Ok(vec![rule::from_source(&rule, "rules[0]", env)?])
        }
        ClashBehavior::Classical => classical(lines, env),
        ClashBehavior::Ipcidr => Err(anyhow!(
            "behavior: a Surge rule-set is of domains or of rules"
        )),
    }
}

#[cfg(feature = "config-surge")]
fn classical<'a>(lines: impl Iterator<Item = &'a str>, env: &RuntimeEnv) -> Result<Vec<Condition>> {
    let mut plain = HeadlessRule::default();
    let mut rules = Vec::new();
    for (i, line) in lines.enumerate() {
        let rule = match crate::config::surge::headless(line) {
            Ok(rule) => rule,
            Err(e) => {
                debug!("rule-set: {:?}: {}; passed over", line, e);
                continue;
            }
        };
        if merge(&mut plain, &rule) {
            continue;
        }
        match rule::from_source(&rule, &format!("rules[{}]", i), env) {
            Ok(rule) => rules.push(rule),
            Err(e) => debug!("rule-set: {:?}: {}; passed over", line, e),
        }
    }
    if plain != HeadlessRule::default() {
        rules.insert(0, rule::from_source(&plain, "rules[0]", env)?);
    }
    Ok(rules)
}

#[cfg(not(feature = "config-surge"))]
fn classical<'a>(_: impl Iterator<Item = &'a str>, _: &RuntimeEnv) -> Result<Vec<Condition>> {
    Err(anyhow!(
        "a Surge rule-set of rules needs the config-surge feature, which is not compiled in"
    ))
}

/// Adds `rule` to `plain` when it is a plain one: of one domain, suffix,
/// keyword or IP prefix alone, which match as any of them in one rule.
#[cfg(feature = "config-surge")]
fn merge(plain: &mut HeadlessRule, rule: &HeadlessRule) -> bool {
    type Field = fn(&mut HeadlessRule) -> &mut Vec<String>;
    let fields: [(&Vec<String>, Field); 4] = [
        (&rule.domain, |r| &mut r.domain),
        (&rule.domain_suffix, |r| &mut r.domain_suffix),
        (&rule.domain_keyword, |r| &mut r.domain_keyword),
        (&rule.ip_cidr, |r| &mut r.ip_cidr),
    ];
    for (values, field) in fields {
        if values.is_empty() {
            continue;
        }
        let mut only = HeadlessRule::default();
        field(&mut only).clone_from(values);
        if *rule != only {
            return false;
        }
        field(plain).extend(values.iter().cloned());
        return true;
    }
    false
}

#[cfg(all(test, feature = "config-surge"))]
mod tests {
    use super::*;
    use crate::app::router::matcher::Facts;
    use crate::session::{Session, SocksAddr};

    fn matches(rules: &[Condition], destination: SocksAddr) -> bool {
        let facts = Facts::new(
            &Session {
                destination,
                ..Default::default()
            },
            &[],
        );
        rules.iter().any(|r| r.matches(&facts, false))
    }

    fn domain(name: &str) -> SocksAddr {
        SocksAddr::Domain(name.into(), 443)
    }

    #[test]
    fn a_domain_set_s_dot_is_the_name_and_those_under_it() {
        let rules = read(
            b"# comment\n.apple.com // note\nexact.org\n// note\n; note\nbad name\n.\n",
            ClashBehavior::Domain,
            &RuntimeEnv::default(),
        )
        .unwrap();
        for (host, want) in [
            ("apple.com", true),
            ("www.apple.com", true),
            ("pineapple.com", false),
            ("exact.org", true),
            ("www.exact.org", false),
        ] {
            assert_eq!(matches(&rules, domain(host)), want, "{}", host);
        }
    }

    #[test]
    fn a_rule_set_s_lines_are_surge_rules() {
        let rules = read(
            b"DOMAIN-SUFFIX,example.com // note\nDOMAIN,exact.org,extended-matching\n\
              IP-CIDR,10.0.0.0/8,no-resolve\nIP-CIDR6,2001:db8::/32\n\
              DOMAIN-WILDCARD,cdn?.example.net\nAND,((DOMAIN-KEYWORD,video),(DEST-PORT,8443))\n\
              SUBNET,TYPE:WIFI\nNOT A RULE\nGEOIP,CN\n",
            ClashBehavior::Classical,
            &RuntimeEnv::default(),
        )
        .unwrap();
        // The plain ones as one, and the wildcard and the logical one.
        assert_eq!(rules.len(), 3);
        for (to, want) in [
            (domain("a.example.com"), true),
            (domain("exact.org"), true),
            (
                SocksAddr::from((std::net::IpAddr::from([10, 1, 2, 3]), 1)),
                true,
            ),
            (domain("cdn1.example.net"), true),
            (domain("cdn12.example.net"), false),
            (SocksAddr::Domain("video.example".into(), 8443), true),
            (SocksAddr::Domain("video.example".into(), 443), false),
            (domain("other.org"), false),
        ] {
            assert_eq!(matches(&rules, to.clone()), want, "{}", to);
        }
    }
}
