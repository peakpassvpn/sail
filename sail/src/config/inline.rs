//! Inline rules merged, for the Clash and Surge lowerings only.
//!
//! A Clash or Surge profile converted from a subscription lists thousands
//! of rules of one domain each, most next to others with the same target;
//! each a route rule of its own, they cost the router most of its memory.
//! Adjacent rules that differ only in their one domain become one rule
//! with all their domains: as only adjacent ones merge, the first rule a
//! connection matches routes it as it did before.
//!
//! Each merged line keeps its index in `route.rules` and is told as the
//! rule it was, and every rule keeps the index it had before the merge:
//! what a match reports (its rule, its index) is what the unmerged rules
//! would report.
//!
//! Never a native sing-box configuration: its `route.rules` are read as
//! written, and indexed by what reads them (a host matching rules by their
//! index), so nothing here touches one.

use super::model::{Line, LineKind, Rule, RuleType};

/// Merges adjacent `rules` that differ only in their one domain.
pub(crate) fn merge(rules: &mut Vec<Rule>) {
    let mut out: Vec<Rule> = Vec::with_capacity(rules.len());
    for (i, mut rule) in std::mem::take(rules).into_iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let line = one_domain(&rule).map(|(kind, value)| Line { index, kind, value });
        if let (Some(line), Some(last)) = (&line, out.last_mut()) {
            if !last.lines.is_empty() && alike(last, &rule) {
                domains(last, line.kind).push(line.value.clone());
                last.lines.push(line.clone());
                continue;
            }
        }
        rule.index = Some(index);
        rule.lines.extend(line);
        out.push(rule);
    }
    // A line nothing joined stays a plain rule.
    for rule in &mut out {
        if rule.lines.len() == 1 {
            rule.lines.clear();
        }
    }
    *rules = out;
}

/// The one domain `rule` names, and in which field: of a default rule,
/// neither inverted nor naming any other domain. (Inverted, a merged rule
/// would match a domain none of its lines would.)
fn one_domain(rule: &Rule) -> Option<(LineKind, String)> {
    if rule.kind != RuleType::Default || rule.invert {
        return None;
    }
    let fields = [
        (LineKind::Domain, &rule.domain),
        (LineKind::Suffix, &rule.domain_suffix),
        (LineKind::Keyword, &rule.domain_keyword),
    ];
    let mut named = fields.iter().filter(|(_, values)| !values.is_empty());
    let (kind, values) = named.next()?;
    if named.next().is_some() || values.len() != 1 {
        return None;
    }
    Some((*kind, values[0].clone()))
}

/// Whether `merged`, a rule lines were merged into, and `rule` differ
/// only in their domains.
fn alike(merged: &Rule, rule: &Rule) -> bool {
    let bare = |r: &Rule| Rule {
        domain: Vec::new(),
        domain_suffix: Vec::new(),
        domain_keyword: Vec::new(),
        lines: Vec::new(),
        index: None,
        ..r.clone()
    };
    bare(merged) == bare(rule)
}

fn domains(rule: &mut Rule, kind: LineKind) -> &mut Vec<String> {
    match kind {
        LineKind::Domain => &mut rule.domain,
        LineKind::Suffix => &mut rule.domain_suffix,
        LineKind::Keyword => &mut rule.domain_keyword,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(json: serde_json::Value) -> Rule {
        serde_json::from_value(json).unwrap()
    }

    fn indexes(rule: &Rule) -> Vec<u32> {
        rule.lines.iter().map(|l| l.index).collect()
    }

    #[test]
    fn adjacent_lines_with_one_target_merge_and_keep_their_indexes() {
        let mut rules = vec![
            rule(serde_json::json!({ "domain_suffix": ["a.test"], "outbound": "G" })),
            rule(serde_json::json!({ "domain": ["b.test"], "outbound": "G" })),
            rule(serde_json::json!({ "domain_keyword": ["c"], "outbound": "G" })),
            rule(serde_json::json!({ "ip_cidr": ["10.0.0.0/8"], "outbound": "G" })),
            rule(serde_json::json!({ "domain_suffix": ["d.test"], "outbound": "G" })),
            rule(serde_json::json!({ "domain_suffix": ["e.test"], "outbound": "DIRECT" })),
            rule(serde_json::json!({ "domain_suffix": ["f.test"], "outbound": "DIRECT" })),
        ];
        merge(&mut rules);
        assert_eq!(rules.len(), 4);
        assert_eq!(indexes(&rules[0]), [0, 1, 2]);
        assert_eq!(rules[0].domain_suffix, ["a.test"]);
        assert_eq!(rules[0].domain, ["b.test"]);
        assert_eq!(rules[0].domain_keyword, ["c"]);
        // A rule of another kind between them stops a run: d.test stays
        // a rule of its own, numbered as before.
        assert_eq!(rules[1].index, Some(3));
        assert_eq!((rules[2].index, rules[2].lines.len()), (Some(4), 0));
        assert_eq!(indexes(&rules[3]), [5, 6]);
    }

    #[test]
    fn rules_that_differ_beyond_their_domain_do_not_merge() {
        let mut rules = vec![
            rule(serde_json::json!({ "domain_suffix": ["a.test"], "outbound": "G" })),
            rule(serde_json::json!({ "domain_suffix": ["b.test"], "outbound": "H" })),
            rule(
                serde_json::json!({ "domain_suffix": ["c.test"], "port": [443], "outbound": "H" }),
            ),
            rule(
                serde_json::json!({ "domain_suffix": ["d.test"], "outbound": "H", "invert": true }),
            ),
            rule(
                serde_json::json!({ "domain_suffix": ["e.test"], "outbound": "H", "invert": true }),
            ),
            rule(serde_json::json!({ "domain_suffix": ["f.test", "g.test"], "outbound": "H" })),
        ];
        merge(&mut rules);
        assert_eq!(rules.len(), 6);
        assert!(rules.iter().all(|r| r.lines.is_empty()));
        let numbered: Vec<_> = rules.iter().map(|r| r.index).collect();
        assert_eq!(numbered, (0..6).map(Some).collect::<Vec<_>>());
    }

    /// A native configuration's rules are read as written: nothing merges
    /// them, however alike.
    #[test]
    fn a_native_configuration_is_not_merged() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "rules": [
                    { "domain_suffix": ["a.test"], "outbound": "a" },
                    { "domain_suffix": ["b.test"], "outbound": "a" },
                ] },
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(config.route.rules.len(), 2);
        assert!(config
            .route
            .rules
            .iter()
            .all(|r| r.lines.is_empty() && r.index.is_none()));
    }
}
