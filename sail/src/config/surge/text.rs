//! A Surge profile's text: sections of lines, its comments, quotes and
//! `#!` directives, and the files `#!include` names, as Surge reads them.

use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, Result};

use super::requirement;

/// Where a line is: its file, when it is not the profile's own, and its
/// number.
#[derive(Debug, Clone)]
pub struct Loc {
    pub file: Option<Rc<str>>,
    pub line: usize,
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.file {
            Some(file) => write!(f, "{} line {}", file, self.line),
            None => write!(f, "line {}", self.line),
        }
    }
}

/// A line of a section, without its comments.
#[derive(Debug, Clone)]
pub struct Line {
    pub text: String,
    pub loc: Loc,
}

/// A section: `[Name]` and its lines, those of the files it includes
/// among them where it includes them.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub lines: Vec<Line>,
}

/// A profile's sections, in order; a section named twice is two.
#[derive(Debug, Default)]
pub struct Profile {
    sections: Vec<Section>,
}

/// How deep includes may nest.
const MAX_DEPTH: usize = 8;

impl Profile {
    /// Reads a profile. `dir` is the directory it is in, which the files
    /// it includes are named relative to; without one, it includes none.
    pub fn read(text: &str, dir: Option<&Path>, warnings: &mut Vec<String>) -> Result<Self> {
        let mut reader = Reader {
            warnings,
            stack: Vec::new(),
        };
        let sections = reader.file(text, None, dir)?;
        Ok(Profile { sections })
    }

    /// The lines of the section `name`, whatever its case, taken out; of
    /// every section so named, in order.
    pub fn take(&mut self, name: &str) -> Vec<Line> {
        let mut lines = Vec::new();
        self.sections.retain_mut(|s| {
            if s.name.eq_ignore_ascii_case(name) {
                lines.append(&mut s.lines);
                false
            } else {
                true
            }
        });
        lines
    }

    /// The sections `[<kind> <name>]`, by name, taken out.
    pub fn take_named(&mut self, kind: &str) -> Vec<(String, Vec<Line>)> {
        let mut named: Vec<(String, Vec<Line>)> = Vec::new();
        self.sections
            .retain_mut(|s| match named_part(&s.name, kind) {
                // What `[WireGuard *]` included stands before it.
                Some("*") => false,
                Some(name) => {
                    match named.iter_mut().find(|(n, _)| n == name) {
                        Some((_, lines)) => lines.append(&mut s.lines),
                        None => named.push((name.to_string(), std::mem::take(&mut s.lines))),
                    }
                    false
                }
                None => true,
            });
        named
    }

    /// The sections not taken, in order.
    pub fn rest(self) -> Vec<Section> {
        self.sections
    }
}

/// `name` of `[<kind> name]`.
fn named_part<'a>(section: &'a str, kind: &str) -> Option<&'a str> {
    let (k, name) = section.split_once(' ')?;
    (k.eq_ignore_ascii_case(kind) && !name.trim().is_empty()).then(|| name.trim())
}

struct Reader<'a> {
    warnings: &'a mut Vec<String>,
    /// The files being read, for includes that lead back to one.
    stack: Vec<PathBuf>,
}

impl Reader<'_> {
    /// The sections of a file's `text`; `file` is its name, as its lines'
    /// locations write it, none for the profile's own.
    fn file(
        &mut self,
        text: &str,
        file: Option<Rc<str>>,
        dir: Option<&Path>,
    ) -> Result<Vec<Section>> {
        let mut sections: Vec<Section> = Vec::new();
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for (i, raw) in text.lines().enumerate() {
            let loc = Loc {
                file: file.clone(),
                line: i + 1,
            };
            let mut line = raw.trim();
            if line.is_empty() {
                continue;
            }
            // A requirement ahead of the line: `#!REQUIREMENT expr line`.
            if let Some(rest) = strip_word(line, "#!REQUIREMENT") {
                let (expr, rest) = requirement::split(rest);
                if !self.holds(expr, &loc)? {
                    continue;
                }
                line = rest.trim();
                if line.is_empty() {
                    continue;
                }
            }
            if let Some(rest) = strip_word(line, "#!include") {
                self.include(rest, &loc, dir, &mut sections)?;
                continue;
            }
            if strip_word(line, "#!MANAGED-CONFIG").is_some() {
                self.warnings.push(format!(
                    "{}: #!MANAGED-CONFIG: sail does not update managed profiles yet; read as \
                     it is",
                    loc
                ));
                continue;
            }
            // Other directives, `#!name` and the like, describe a module.
            if line.starts_with('#') || line.starts_with(';') || line.starts_with("//") {
                continue;
            }
            let Some(content) = self.content(line, &loc)? else {
                continue;
            };
            if content.starts_with('[') && content.ends_with(']') {
                let name = content[1..content.len() - 1].trim().to_string();
                sections.push(Section {
                    name,
                    lines: Vec::new(),
                });
                continue;
            }
            match sections.last_mut() {
                Some(section) => section.lines.push(Line { text: content, loc }),
                None => self.warnings.push(format!(
                    "{}: outside any section, where Surge reads nothing; ignored",
                    loc
                )),
            }
        }
        Ok(sections)
    }

    /// The line without its comment, none if a requirement at its end does
    /// not hold. A comment after a line starts with `#`, `;` or `//`, with
    /// a space before it.
    fn content(&mut self, line: &str, loc: &Loc) -> Result<Option<String>> {
        let Some(at) = comment_start(line) else {
            return Ok(Some(line.to_string()));
        };
        let content = line[..at].trim_end().to_string();
        let comment = &line[at..];
        let directive = comment
            .strip_prefix("#!")
            .or_else(|| comment.strip_prefix("//!"));
        if let Some(directive) = directive {
            let holds = match directive.split_whitespace().next().unwrap_or_default() {
                "REQUIREMENT" => {
                    let rest = directive["REQUIREMENT".len()..].trim();
                    let (expr, _) = requirement::split(rest);
                    self.holds(expr, loc)?
                }
                "IOS-ONLY" => requirement::system() == "iOS",
                "MACOS-ONLY" => requirement::system() == "macOS",
                "TVOS-ONLY" => requirement::system() == "tvOS",
                _ => true,
            };
            if !holds {
                return Ok(None);
            }
        }
        Ok(Some(content))
    }

    fn holds(&mut self, expr: &str, loc: &Loc) -> Result<bool> {
        requirement::holds(expr, self.warnings)
            .map_err(|e| anyhow!("{}: #!REQUIREMENT {}: {}", loc, expr, e))
    }

    /// `#!include a, b`: what the files hold of the section it stands in,
    /// there; of every section, before any.
    fn include(
        &mut self,
        list: &str,
        loc: &Loc,
        dir: Option<&Path>,
        sections: &mut Vec<Section>,
    ) -> Result<()> {
        let targets: Vec<&str> = list
            .split(',')
            .map(|t| t.trim().trim_matches('"'))
            .filter(|t| !t.is_empty())
            .collect();
        if targets.is_empty() {
            self.warnings.push(format!(
                "{}: #!include names no file; ignored, as by Surge",
                loc
            ));
            return Ok(());
        }
        for target in targets {
            if target.contains("://") {
                return Err(anyhow!(
                    "{}: #!include {}: sail does not fetch included URLs yet",
                    loc,
                    target
                ));
            }
            let dir = dir.ok_or_else(|| {
                anyhow!(
                    "{}: #!include {}: a profile read from text includes no files; read it \
                     from its file",
                    loc,
                    target
                )
            })?;
            let path = dir.join(target);
            if self.stack.contains(&path) || self.stack.len() >= MAX_DEPTH {
                return Err(anyhow!(
                    "{}: #!include {}: includes lead back to it, or nest too deep",
                    loc,
                    target
                ));
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| anyhow!("{}: #!include {}: {}", loc, target, e))?;
            self.stack.push(path.clone());
            let inner_dir = path.parent().map(Path::to_path_buf);
            let included = self.file(&text, Some(Rc::from(target)), inner_dir.as_deref());
            self.stack.pop();
            let included = included?;
            // Before any section: all of them.
            let Some(mut at) = sections.len().checked_sub(1) else {
                sections.extend(included);
                continue;
            };
            let name = sections[at].name.clone();
            // `[WireGuard *]`: every `[WireGuard <name>]` section.
            let kind = name.strip_suffix(" *").map(str::to_string);
            let mut found = false;
            for mut s in included {
                match &kind {
                    Some(kind) if named_part(&s.name, kind).is_some() => {
                        sections.insert(at, s);
                        at += 1;
                    }
                    None if s.name.eq_ignore_ascii_case(&name) => {
                        found = true;
                        sections[at].lines.append(&mut s.lines);
                    }
                    _ => {}
                }
            }
            if !found && kind.is_none() {
                return Err(anyhow!(
                    "{}: #!include {}: it has no [{}] section",
                    loc,
                    target,
                    name
                ));
            }
        }
        Ok(())
    }
}

/// `line` past `word` and the space after it, whatever the case.
fn strip_word<'a>(line: &'a str, word: &str) -> Option<&'a str> {
    let head = line.get(..word.len())?;
    let rest = &line[word.len()..];
    (head.eq_ignore_ascii_case(word) && (rest.is_empty() || rest.starts_with(char::is_whitespace)))
        .then(|| rest.trim_start())
}

/// `line` without a comment after it.
#[cfg(feature = "rule-set")]
pub fn strip_comment(line: &str) -> &str {
    match comment_start(line) {
        Some(at) => line[..at].trim_end(),
        None => line,
    }
}

/// Where a comment after a line starts: at `#`, `;` or `//` outside
/// quotes, with a space before it.
fn comment_start(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b'#' | b';' | b'/'
                if !quoted
                    && i > 0
                    && bytes[i - 1].is_ascii_whitespace()
                    && (b != b'/' || bytes.get(i + 1) == Some(&b'/')) =>
            {
                return Some(i);
            }
            _ => {}
        }
    }
    None
}

/// Splits `s` at its commas outside quotes, each part trimmed but quoted
/// as it is. `single` takes single quotes as quotes too, as rules do.
pub fn split(s: &str, single: bool) -> Vec<String> {
    split_at(s, single, true)
}

/// Splits a rule, as `split` with single quotes; within parentheses only a
/// logical rule's, which hold its rules: another's, a regular
/// expression's say, are the value's own.
pub fn split_rule(line: &str) -> Vec<String> {
    let kind = line.split(',').next().unwrap_or_default().trim();
    let logical = ["AND", "OR", "NOT"]
        .iter()
        .any(|k| kind.eq_ignore_ascii_case(k));
    split_at(line, true, logical)
}

fn split_at(s: &str, single: bool, parens: bool) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for c in s.chars() {
        if escaped {
            escaped = false;
            part.push(c);
            continue;
        }
        match c {
            '\\' if quote == Some('"') => {
                escaped = true;
                part.push(c);
            }
            '"' | '\'' if quote == Some(c) => {
                quote = None;
                part.push(c);
            }
            '"' if quote.is_none() => {
                quote = Some(c);
                part.push(c);
            }
            '\'' if quote.is_none() && single && part.trim().is_empty() => {
                quote = Some(c);
                part.push(c);
            }
            // `peer = (a = 1, b = 2)` keeps its parentheses whole.
            '(' if quote.is_none() && parens => {
                depth += 1;
                part.push(c);
            }
            ')' if quote.is_none() && parens => {
                depth = depth.saturating_sub(1);
                part.push(c);
            }
            ',' if quote.is_none() && depth == 0 => {
                parts.push(std::mem::take(&mut part).trim().to_string());
            }
            c => part.push(c),
        }
    }
    parts.push(part.trim().to_string());
    parts
}

/// A value without the quotes around it, `\"` and `\\` read.
pub fn unquote(s: &str) -> String {
    let s = s.trim();
    let quoted = s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')));
    if !quoted {
        return s.to_string();
    }
    let inner = &s[1..s.len() - 1];
    if s.starts_with('\'') {
        return inner.to_string();
    }
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(n @ ('"' | '\\')) => out.push(n),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            c => out.push(c),
        }
    }
    out
}

/// `key = value`, both trimmed, the value unquoted.
pub fn key_value(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    (!key.is_empty()).then(|| (key.to_string(), unquote(value)))
}

/// A part of a line as a parameter, `key=value`: the key lowercased, the
/// value unquoted. A part quoted whole that holds one, as some profiles
/// write it, is one too, with `stray` set.
pub fn param(part: &str) -> Option<(String, String, bool)> {
    let (inner, stray) = if part.starts_with('"') && part.ends_with('"') && part.len() >= 2 {
        (unquote(part), true)
    } else {
        (part.to_string(), false)
    };
    let (key, value) = inner.split_once('=')?;
    let key = key.trim();
    let plain = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    plain.then(|| (key.to_ascii_lowercase(), unquote(value), stray))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> (Profile, Vec<String>) {
        let mut warnings = Vec::new();
        let profile = Profile::read(text, None, &mut warnings).unwrap();
        (profile, warnings)
    }

    #[test]
    fn comments_and_sections() {
        let (mut p, _) = read(
            "# a\n; b\n// c\n[General]\r\nloglevel = notify // why\nipv6 = false # no\n\
             url = http://a/#x\n[Rule]\nFINAL,DIRECT ; end\n",
        );
        let general: Vec<String> = p.take("general").into_iter().map(|l| l.text).collect();
        assert_eq!(
            general,
            ["loglevel = notify", "ipv6 = false", "url = http://a/#x"]
        );
        let rule = p.take("Rule");
        assert_eq!(rule[0].text, "FINAL,DIRECT");
        assert_eq!(rule[0].loc.to_string(), "line 9");
    }

    #[test]
    fn quotes_keep_commas() {
        assert_eq!(
            split(r#"select, a, include-other-group="x, y", b"#, false),
            ["select", "a", r#"include-other-group="x, y""#, "b"]
        );
        assert_eq!(
            split("peer = (a = 1, b = \"2, 3\"), c", false),
            ["peer = (a = 1, b = \"2, 3\")", "c"]
        );
        assert_eq!(
            split("URL-REGEX,'a,b',P", true),
            ["URL-REGEX", "'a,b'", "P"]
        );
        assert_eq!(
            split_rule("URL-REGEX,^http://a/\\(x,P"),
            ["URL-REGEX", "^http://a/\\(x", "P"]
        );
        assert_eq!(
            split_rule("and,((DOMAIN,a),(DEST-PORT,1)),P"),
            ["and", "((DOMAIN,a),(DEST-PORT,1))", "P"]
        );
        assert_eq!(unquote(r#""say \"hi\", C:\\x""#), r#"say "hi", C:\x"#);
        assert_eq!(
            param(r#""update-interval=86400""#),
            Some(("update-interval".into(), "86400".into(), true))
        );
    }

    #[test]
    fn a_line_s_platform_decides_it() {
        let (mut p, _) = read(
            "[General]\na = 1 #!IOS-ONLY\nb = 2 #!MACOS-ONLY\nc = 3 //!REQUIREMENT CORE_VERSION<22\n\
             #!REQUIREMENT CORE_VERSION>=22 d = 4\n",
        );
        let lines: Vec<String> = p.take("General").into_iter().map(|l| l.text).collect();
        let mut expect = vec![];
        if requirement::system() == "iOS" {
            expect.push("a = 1");
        }
        if requirement::system() == "macOS" {
            expect.push("b = 2");
        }
        expect.push("d = 4");
        assert_eq!(lines, expect);
    }

    #[test]
    fn includes_are_read_where_they_stand() {
        let dir = std::env::temp_dir().join(format!("sail-surge-include-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rules.dconf"),
            "[Rule]\nDOMAIN,b,DIRECT\n[Proxy]\nX = direct\n",
        )
        .unwrap();
        let mut warnings = Vec::new();
        let mut p = Profile::read(
            "[Rule]\nDOMAIN,a,DIRECT\n#!include rules.dconf\nFINAL,DIRECT\n",
            Some(&dir),
            &mut warnings,
        )
        .unwrap();
        let rules: Vec<String> = p
            .take("Rule")
            .into_iter()
            .map(|l| l.loc.to_string())
            .collect();
        assert_eq!(rules, ["line 2", "rules.dconf line 2", "line 4"]);
        // Only the section it stands in.
        assert!(p.take("Proxy").is_empty());
        let err = Profile::read("[Rule]\n#!include rules.dconf\n", None, &mut warnings)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 2: #!include rules.dconf"), "{}", err);
        let err = Profile::read("[Host]\n#!include rules.dconf\n", Some(&dir), &mut warnings)
            .unwrap_err()
            .to_string();
        assert!(err.contains("has no [Host] section"), "{}", err);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
