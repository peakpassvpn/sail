//! Inline rules merged, for the Clash and Surge lowerings only.
//!
//! A Clash or Surge profile converted from a subscription lists thousands
//! of rules of one domain each, most next to others with the same target;
//! each a route rule of its own, they cost the router most of its memory,
//! and the configuration model more while it is read. Adjacent rules that
//! differ only in their one domain become one rule with all their domains,
//! in the lowered JSON, before the model is read from it: as only adjacent
//! ones merge, the first rule a connection matches routes it as before.
//!
//! They merge as they are lowered (`Rules`), each into the one before it:
//! a rule of one line is a JSON object of some 600 bytes, and thirty
//! thousand of them kept until all were lowered were most of what reading
//! a profile took.
//!
//! Each merged line keeps its index in `route.rules` and is told as the
//! rule it was, and every rule keeps the index it had before the merge
//! (`attach`, once the model is read): what a match reports (its rule, its
//! index) is what the unmerged rules would report.
//!
//! Never a native sing-box configuration: its `route.rules` are read as
//! written, and indexed by what reads them (a host matching rules by their
//! index), so nothing here touches one.

use serde_json::{Map, Value};

use super::model::{Line, LineKind, Rule};

/// What a merged `route.rules` keeps of the rules it had: for each rule
/// now, its index before, and the lines merged into it, if any.
pub(crate) struct Told(Vec<(u32, Vec<Line>)>);

const DOMAINS: [(&str, LineKind); 3] = [
    ("domain", LineKind::Domain),
    ("domain_suffix", LineKind::Suffix),
    ("domain_keyword", LineKind::Keyword),
];

/// The route rules of a configuration being lowered, merged as they come.
///
/// A rule pushed joins the one before it when the two differ only in
/// their one domain. Rules put in front, which a lowering does once the
/// others are there (its listeners', its sniffing, a TUN's), are kept
/// apart until `finish` joins the two lists, so that what comes out is
/// what merging the whole list at the end would give.
#[derive(Default)]
pub(crate) struct Rules {
    front: Vec<Value>,
    rest: Run,
}

/// Rules merged in the order pushed, and what `Told` keeps of each.
#[derive(Default)]
struct Run {
    rules: Vec<Value>,
    told: Vec<(u32, Vec<Line>)>,
    /// How many were pushed: the index of the next.
    pushed: u32,
}

impl Run {
    fn push(&mut self, rule: Value) {
        let index = self.pushed;
        self.pushed = self.pushed.saturating_add(1);
        let line = one_domain(&rule).map(|(kind, value)| Line { index, kind, value });
        if let (Some(line), Some(last), Some((_, lines))) =
            (&line, self.rules.last_mut(), self.told.last_mut())
        {
            if !lines.is_empty() && alike(last, &rule) {
                push(last, line);
                lines.push(line.clone());
                return;
            }
        }
        self.told.push((index, line.into_iter().collect()));
        self.rules.push(rule);
    }

    /// Adds the rules of `after`, pushed after its own: the first of them
    /// joins its last as it would have, pushed one line at a time.
    fn append(&mut self, mut after: Run) {
        let shift = self.pushed;
        self.pushed = self.pushed.saturating_add(after.pushed);
        for (index, lines) in &mut after.told {
            *index += shift;
            for line in lines {
                line.index += shift;
            }
        }
        let joins = match (
            self.rules.last(),
            self.told.last(),
            after.rules.first(),
            after.told.first(),
        ) {
            (Some(last), Some((_, lines)), Some(rule), Some((_, first))) => {
                !lines.is_empty() && !first.is_empty() && alike(last, rule)
            }
            _ => false,
        };
        if joins {
            after.rules.remove(0);
            let (_, first) = after.told.remove(0);
            if let (Some(last), Some((_, lines))) = (self.rules.last_mut(), self.told.last_mut()) {
                for line in first {
                    push(last, &line);
                    lines.push(line);
                }
            }
        }
        self.rules.append(&mut after.rules);
        self.told.append(&mut after.told);
    }
}

impl Rules {
    /// Adds `rule` after those pushed so far.
    pub(crate) fn push(&mut self, rule: Value) {
        self.rest.push(rule);
    }

    /// Adds `rules`, in order, after those pushed so far.
    #[cfg(any(feature = "config-surge", test))]
    pub(crate) fn extend(&mut self, rules: impl IntoIterator<Item = Value>) {
        for rule in rules {
            self.rest.push(rule);
        }
    }

    /// Puts `rule` before every other.
    pub(crate) fn push_front(&mut self, rule: Value) {
        self.front.insert(0, rule);
    }

    /// Puts `rules`, in order, before every other.
    pub(crate) fn extend_front(&mut self, rules: Vec<Value>) {
        self.front.splice(0..0, rules);
    }

    /// The rules, merged, and what a merged `route.rules` keeps of the
    /// rules it had.
    pub(crate) fn finish(self) -> (Vec<Value>, Told) {
        let mut all = Run::default();
        for rule in self.front {
            all.push(rule);
        }
        all.append(self.rest);
        // A line nothing joined stays a plain rule.
        for (_, lines) in &mut all.told {
            if lines.len() == 1 {
                lines.clear();
            }
        }
        (all.rules, Told(all.told))
    }
}

/// Merges the adjacent rules of `config`'s `route.rules`, a lowered
/// configuration, that differ only in their one domain: the whole list at
/// once, which `Rules` does as the rules come. For tests.
#[cfg(test)]
pub(crate) fn merge(config: &mut Value) -> Told {
    let Some(rules) = config
        .get_mut("route")
        .and_then(|route| route.get_mut("rules"))
        .and_then(Value::as_array_mut)
    else {
        return Told(Vec::new());
    };
    let mut out: Vec<Value> = Vec::new();
    let mut told: Vec<(u32, Vec<Line>)> = Vec::new();
    for (i, rule) in std::mem::take(rules).into_iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let line = one_domain(&rule).map(|(kind, value)| Line { index, kind, value });
        if let (Some(line), Some(last), Some((_, lines))) = (&line, out.last_mut(), told.last_mut())
        {
            if !lines.is_empty() && alike(last, &rule) {
                push(last, line);
                lines.push(line.clone());
                continue;
            }
        }
        told.push((index, line.into_iter().collect()));
        out.push(rule);
    }
    // A line nothing joined stays a plain rule.
    for (_, lines) in &mut told {
        if lines.len() == 1 {
            lines.clear();
        }
    }
    *rules = out;
    Told(told)
}

/// Gives the rules read from a merged `route.rules` the index each had
/// before, and the lines merged into it.
pub(crate) fn attach(rules: &mut [Rule], told: Told) {
    for (rule, (index, lines)) in rules.iter_mut().zip(told.0) {
        rule.index = Some(index);
        rule.lines = lines.into();
    }
}

/// `message` with each `route.rules[N]` it names, an index of the merged
/// rules, given as the index that rule had before: what an error reports.
pub(crate) fn original(message: &str, told: &Told) -> String {
    const AT: &str = "route.rules[";
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find(AT) {
        let (before, after) = rest.split_at(at + AT.len());
        out.push_str(before);
        let digits = after.len() - after.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        match after[..digits]
            .parse::<usize>()
            .ok()
            .and_then(|n| told.0.get(n))
        {
            Some((index, _)) => out.push_str(&index.to_string()),
            None => out.push_str(&after[..digits]),
        }
        rest = &after[digits..];
    }
    out.push_str(rest);
    out
}

/// A rule's one domain, and in which field: of a default rule, neither
/// inverted nor naming any other domain. (Inverted, a merged rule would
/// match a domain none of its lines would.) A field is a string or a list,
/// as sing-box reads it.
fn one_domain(rule: &Value) -> Option<(LineKind, String)> {
    let rule = rule.as_object()?;
    let default = rule.get("type").is_none_or(|t| t == "default");
    if !default || rule.get("invert") == Some(&Value::Bool(true)) {
        return None;
    }
    let mut named = DOMAINS
        .iter()
        .filter_map(|(field, kind)| Some((*kind, rule.get(*field)?)));
    let (kind, values) = named.next()?;
    if named.next().is_some() {
        return None;
    }
    match values {
        Value::String(value) => Some((kind, value.clone())),
        Value::Array(values) if values.len() == 1 => Some((kind, values[0].as_str()?.to_string())),
        _ => None,
    }
}

/// Whether `merged`, a rule lines were merged into, and `rule` differ
/// only in their domains. Field by field, nothing copied: a run of
/// thousands of lines to one target compares each with the rule that has
/// all those before it.
fn alike(merged: &Value, rule: &Value) -> bool {
    let (Some(merged), Some(rule)) = (merged.as_object(), rule.as_object()) else {
        return false;
    };
    let domain = |field: &str| DOMAINS.iter().any(|(name, _)| *name == field);
    let others = |r: &Map<String, Value>| r.keys().filter(|field| !domain(field)).count();
    others(merged) == others(rule)
        && merged
            .iter()
            .filter(|(field, _)| !domain(field))
            .all(|(field, value)| rule.get(field) == Some(value))
}

/// Adds `line`'s domain to `merged`'s field of its kind, a list.
fn push(merged: &mut Value, line: &Line) {
    let Some((field, _)) = DOMAINS.iter().find(|(_, kind)| *kind == line.kind) else {
        return;
    };
    let Some(rule) = merged.as_object_mut() else {
        return;
    };
    let values = rule
        .entry(*field)
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::String(one) = values {
        *values = Value::Array(vec![Value::String(std::mem::take(one))]);
    }
    if let Value::Array(values) = values {
        values.push(Value::String(line.value.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merged(rules: Value) -> (Vec<Value>, Told) {
        let mut config = serde_json::json!({ "route": { "rules": rules } });
        let told = merge(&mut config);
        let rules = config["route"]["rules"].as_array().unwrap().clone();
        (rules, told)
    }

    fn indexes(told: &Told, at: usize) -> Vec<u32> {
        told.0[at].1.iter().map(|l| l.index).collect()
    }

    #[test]
    fn adjacent_lines_with_one_target_merge_and_keep_their_indexes() {
        let (rules, told) = merged(serde_json::json!([
            { "domain_suffix": ["a.test"], "outbound": "G" },
            { "domain": "b.test", "outbound": "G" },
            { "domain_keyword": ["c"], "outbound": "G" },
            { "ip_cidr": ["10.0.0.0/8"], "outbound": "G" },
            { "domain_suffix": ["d.test"], "outbound": "G" },
            { "domain_suffix": ["e.test"], "outbound": "DIRECT" },
            { "domain_suffix": ["f.test"], "outbound": "DIRECT" },
        ]));
        assert_eq!(rules.len(), 4);
        assert_eq!(indexes(&told, 0), [0, 1, 2]);
        assert_eq!(rules[0]["domain_suffix"], serde_json::json!(["a.test"]));
        assert_eq!(rules[0]["domain"], serde_json::json!(["b.test"]));
        assert_eq!(rules[0]["domain_keyword"], serde_json::json!(["c"]));
        // A rule of another kind between them stops a run: d.test stays
        // a rule of its own, numbered as before.
        assert_eq!(told.0[1].0, 3);
        assert_eq!((told.0[2].0, told.0[2].1.len()), (4, 0));
        assert_eq!(indexes(&told, 3), [5, 6]);
    }

    /// Merged as they come, with rules put in front along the way, the
    /// rules are those the whole list merged at once gives: the same
    /// rules, numbered and told the same.
    #[test]
    fn rules_merged_as_they_come_are_those_merged_at_once() {
        let g = |domain: &str| serde_json::json!({ "domain_suffix": [domain], "outbound": "G" });
        let d = |domain: &str| serde_json::json!({ "domain": domain, "outbound": "DIRECT" });
        let other = || serde_json::json!({ "ip_cidr": ["10.0.0.0/8"], "outbound": "G" });
        let sniff = || serde_json::json!({ "action": "sniff" });
        // What a lowering does: (true, rules) puts them in front.
        let cases: Vec<Vec<(bool, Vec<Value>)>> = vec![
            vec![(
                false,
                vec![g("a"), g("b"), other(), g("c"), d("d"), d("e"), g("f")],
            )],
            // The front's last and the first of the rest are alike: one rule.
            vec![
                (false, vec![g("a"), g("b"), d("c")]),
                (true, vec![sniff(), g("x"), g("y")]),
            ],
            // A rule of one line in front joins a run; one behind it too.
            vec![
                (false, vec![g("a"), g("b")]),
                (true, vec![g("x")]),
                (false, vec![g("c")]),
            ],
            // Front after front, the later one first; neither joins the rest.
            vec![
                (false, vec![d("a")]),
                (true, vec![g("x"), g("y")]),
                (true, vec![sniff()]),
            ],
            // Nothing but front; nothing at all.
            vec![(true, vec![g("x"), g("y"), d("z")])],
            vec![],
            // One line each side of the join, and a single in front of a single of another target.
            vec![(false, vec![g("a")]), (true, vec![g("x")])],
            vec![(false, vec![d("a")]), (true, vec![g("x")])],
        ];
        for case in cases {
            let mut rules = Rules::default();
            let mut whole: Vec<Value> = Vec::new();
            for (front, batch) in case {
                if front {
                    whole.splice(0..0, batch.clone());
                    // One at a time or all at once, as lowerings do both.
                    if batch.len() == 1 {
                        rules.push_front(batch.into_iter().next().unwrap());
                    } else {
                        rules.extend_front(batch);
                    }
                } else {
                    whole.extend(batch.clone());
                    rules.extend(batch);
                }
            }
            let mut config = serde_json::json!({ "route": { "rules": whole.clone() } });
            let at_once = merge(&mut config);
            let (as_they_came, told) = rules.finish();
            assert_eq!(
                Value::Array(as_they_came),
                config["route"]["rules"],
                "{:?}",
                whole
            );
            assert_eq!(told.0, at_once.0, "{:?}", whole);
        }
    }

    #[test]
    fn rules_that_differ_beyond_their_domain_do_not_merge() {
        let (rules, told) = merged(serde_json::json!([
            { "domain_suffix": ["a.test"], "outbound": "G" },
            { "domain_suffix": ["b.test"], "outbound": "H" },
            { "domain_suffix": ["c.test"], "port": [443], "outbound": "H" },
            { "domain_suffix": ["d.test"], "outbound": "H", "invert": true },
            { "domain_suffix": ["e.test"], "outbound": "H", "invert": true },
            { "domain_suffix": ["f.test", "g.test"], "outbound": "H" },
            { "type": "logical", "mode": "and", "rules": [], "outbound": "H" },
        ]));
        assert_eq!(rules.len(), 7);
        assert!(told.0.iter().all(|(_, lines)| lines.is_empty()));
        let numbered: Vec<u32> = told.0.iter().map(|(i, _)| *i).collect();
        assert_eq!(numbered, (0..7).collect::<Vec<_>>());
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

    #[test]
    fn an_error_names_a_rule_by_its_index_before_the_merge() {
        let (_, told) = merged(serde_json::json!([
            { "domain_suffix": ["a.test"], "outbound": "G" },
            { "domain_suffix": ["b.test"], "outbound": "G" },
            { "port": [0], "outbound": "G" },
        ]));
        assert_eq!(
            original("route.rules[1].port: bad; route.rules[0]", &told),
            "route.rules[2].port: bad; route.rules[0]"
        );
    }
}
