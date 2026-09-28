//! Filters on names, as Mihomo writes them: the regular expressions that
//! pick a proxy-provider's proxies, and a proxy group's members, by name.

use anyhow::{anyhow, Result};

/// How far a name filter may backtrack before it is taken not to match:
/// the names come from the network.
const BACKTRACK_LIMIT: usize = 100_000;

/// A name filter, as Mihomo's regexp2 takes it (lookarounds included).
pub struct NameFilter {
    regex: fancy_regex::Regex,
}

impl NameFilter {
    pub fn new(pattern: &str) -> Result<Self> {
        let regex = fancy_regex::RegexBuilder::new(pattern)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            .map_err(|e| anyhow!("{:?}: {}", pattern, e))?;
        Ok(NameFilter { regex })
    }

    /// Several filters, as one Clash field writes them: split at
    /// backquotes.
    pub fn list(patterns: Option<&str>) -> Result<Vec<Self>> {
        match patterns {
            None | Some("") => Ok(Vec::new()),
            Some(patterns) => patterns.split('`').map(NameFilter::new).collect(),
        }
    }

    /// Whether `name` matches; a filter that backtracks too far does not,
    /// and says so.
    pub fn matches(&self, name: &str, warnings: &mut Vec<String>) -> bool {
        match self.regex.is_match(name) {
            Ok(matched) => matched,
            Err(e) => {
                warnings.push(format!(
                    "filter {:?} on {:?}: {}; taken not to match",
                    self.regex.as_str(),
                    name,
                    e
                ));
                false
            }
        }
    }

    /// `name` with every match replaced by `target`; as it is where the
    /// filter backtracks too far.
    pub fn replace(&self, name: &str, target: &str) -> String {
        match self.regex.try_replacen(name, 0, target) {
            Ok(replaced) => replaced.into_owned(),
            Err(_) => name.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runaway_filter_does_not_match() {
        let filter = NameFilter::new("(a+)+(?=b)").unwrap();
        let mut warnings = Vec::new();
        assert!(!filter.matches(&"a".repeat(64), &mut warnings));
        assert_eq!(warnings.len(), 1, "{:?}", warnings);
    }

    #[test]
    fn several_filters_split_at_backquotes() {
        let filters = NameFilter::list(Some("(?i)jp`(?!.*Ukraine)(HK|港)")).unwrap();
        let mut warnings = Vec::new();
        assert!(filters[0].matches("🇯🇵 JP 01", &mut warnings));
        assert!(filters[1].matches("🇭🇰 HK 01", &mut warnings));
        assert!(!filters[1].matches("HK Ukraine", &mut warnings));
        assert!(NameFilter::list(Some("")).unwrap().is_empty());
        assert_eq!(filters[1].replace("HK 01 HK", "港"), "港 01 港");
    }
}
