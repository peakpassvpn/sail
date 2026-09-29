//! `#!REQUIREMENT` expressions: what a line needs of the device and the
//! Surge reading it. sail answers for itself: `SYSTEM` is the platform it
//! runs on, `CORE_VERSION` Surge's latest, whose features it reads; the
//! other variables name the device, which a profile sail reads does not
//! run on, and a comparison of one does not hold.

use anyhow::{anyhow, Result};

/// The Core Version sail reads profiles as: Surge Mac 6.10's.
const CORE_VERSION: f64 = 6_010_000.0;

/// `SYSTEM`, as Surge names the platforms.
pub fn system() -> &'static str {
    if cfg!(target_os = "ios") {
        "iOS"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "tvos") {
        "tvOS"
    } else if cfg!(target_os = "android") {
        "Android"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Linux"
    }
}

/// A requirement ahead of a line, and the line: the expression is up to
/// the first space, or in double quotes.
pub fn split(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (&rest[..end], &rest[end + 1..]);
        }
    }
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

/// Whether `expr` holds for sail.
pub fn holds(expr: &str, warnings: &mut Vec<String>) -> Result<bool> {
    let tokens = tokens(expr)?;
    let mut p = Parser {
        tokens,
        at: 0,
        warnings,
    };
    let value = p.or()?;
    if p.at != p.tokens.len() {
        return Err(anyhow!("{:?} is not understood", p.tokens[p.at]));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Str(String),
    Num(f64),
    Op(&'static str),
    Open,
    Close,
}

const OPS: &[&str] = &[
    "==", "=>", ">=", "=<", "<=", "!=", "<>", "&&", "||", "=", ">", "<", "!",
];

fn tokens(expr: &str) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '(' || c == ')' {
            out.push(if c == '(' { Token::Open } else { Token::Close });
            i += 1;
        } else if c == '\'' || c == '"' {
            let end = chars[i + 1..]
                .iter()
                .position(|&d| d == c)
                .ok_or_else(|| anyhow!("a quote is not closed"))?;
            out.push(Token::Str(chars[i + 1..i + 1 + end].iter().collect()));
            i += end + 2;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let number: String = chars[start..i].iter().collect();
            out.push(Token::Num(
                number
                    .parse()
                    .map_err(|_| anyhow!("{:?} is not a number", number))?,
            ));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Token::Word(chars[start..i].iter().collect()));
        } else {
            let rest: String = chars[i..].iter().take(2).collect();
            let op = OPS
                .iter()
                .find(|op| rest.starts_with(**op))
                .ok_or_else(|| anyhow!("{:?} is not an operator", c))?;
            out.push(Token::Op(op));
            i += op.len();
        }
    }
    Ok(out)
}

/// A value an operand stands for: none for what sail cannot tell.
#[derive(Debug, Clone)]
enum Value {
    Num(f64),
    Str(String),
    Unknown(String),
}

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    warnings: &'a mut Vec<String>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn keyword(&self, words: &[&str]) -> bool {
        match self.peek() {
            Some(Token::Word(w)) => words.iter().any(|k| w.eq_ignore_ascii_case(k)),
            Some(Token::Op(op)) => words.contains(op),
            _ => false,
        }
    }

    fn or(&mut self) -> Result<bool> {
        let mut value = self.and()?;
        while self.keyword(&["OR", "||"]) {
            self.at += 1;
            value |= self.and()?;
        }
        Ok(value)
    }

    fn and(&mut self) -> Result<bool> {
        let mut value = self.not()?;
        while self.keyword(&["AND", "&&"]) {
            self.at += 1;
            value &= self.not()?;
        }
        Ok(value)
    }

    fn not(&mut self) -> Result<bool> {
        if self.keyword(&["NOT", "!"]) {
            self.at += 1;
            return Ok(!self.not()?);
        }
        if self.peek() == Some(&Token::Open) {
            self.at += 1;
            let value = self.or()?;
            if self.peek() != Some(&Token::Close) {
                return Err(anyhow!("a '(' without its ')'"));
            }
            self.at += 1;
            return Ok(value);
        }
        self.comparison()
    }

    fn operand(&mut self) -> Result<Value> {
        let token = self
            .tokens
            .get(self.at)
            .cloned()
            .ok_or_else(|| anyhow!("it ends too soon"))?;
        self.at += 1;
        Ok(match token {
            Token::Num(n) => Value::Num(n),
            Token::Str(s) => Value::Str(s),
            Token::Word(w) => match w.as_str() {
                "CORE_VERSION" => Value::Num(CORE_VERSION),
                "SYSTEM" => Value::Str(system().to_string()),
                _ => Value::Unknown(w),
            },
            other => return Err(anyhow!("{:?} is no value", other)),
        })
    }

    fn comparison(&mut self) -> Result<bool> {
        let left = self.operand()?;
        let op = match self.peek() {
            Some(Token::Op(op)) if !matches!(*op, "&&" | "||" | "!") => op.to_string(),
            Some(Token::Word(w)) => w.to_ascii_uppercase(),
            _ => return Err(anyhow!("a comparison has no operator")),
        };
        self.at += 1;
        let right = self.operand()?;
        let (left, right) = match (left, right) {
            (Value::Unknown(name), _) | (_, Value::Unknown(name)) => {
                self.warnings.push(format!(
                    "#!REQUIREMENT: sail cannot tell {}; the comparison does not hold",
                    name
                ));
                return Ok(false);
            }
            pair => pair,
        };
        use std::cmp::Ordering::*;
        let ordering = match (&left, &right) {
            (Value::Num(a), Value::Num(b)) => a.partial_cmp(b),
            (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
            _ => None,
        };
        let text = |v: &Value| match v {
            Value::Num(n) => n.to_string(),
            Value::Str(s) => s.clone(),
            Value::Unknown(_) => String::new(),
        };
        let (a, b) = (text(&left), text(&right));
        Ok(match op.as_str() {
            "=" | "==" => ordering == Some(Equal),
            "!=" | "<>" => ordering != Some(Equal),
            ">" => ordering == Some(Greater),
            "<" => ordering == Some(Less),
            ">=" | "=>" => matches!(ordering, Some(Greater | Equal)),
            "<=" | "=<" => matches!(ordering, Some(Less | Equal)),
            "BEGINSWITH" => a.starts_with(&b),
            "ENDSWITH" => a.ends_with(&b),
            "CONTAINS" => a.contains(&b),
            "LIKE" => wildcard(&a, &b),
            "MATCHES" => fancy_regex::Regex::new(&format!("^(?:{})$", b))
                .map_err(|e| anyhow!("MATCHES: {}", e))?
                .is_match(&a)
                .unwrap_or(false),
            other => return Err(anyhow!("{:?} is not an operator", other)),
        })
    }
}

/// `*` any run of characters, `?` one.
fn wildcard(s: &str, pattern: &str) -> bool {
    let (s, p): (Vec<char>, Vec<char>) = (s.chars().collect(), pattern.chars().collect());
    let (mut i, mut j) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while i < s.len() {
        if j < p.len() && (p[j] == '?' || p[j] == s[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = Some(j);
            mark = i;
            j += 1;
        } else if let Some(k) = star {
            j = k + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    p[j..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(expr: &str) -> bool {
        holds(expr, &mut Vec::new()).unwrap()
    }

    #[test]
    fn requirements_hold_as_for_the_latest_surge() {
        assert!(eval("CORE_VERSION>=22"));
        assert!(!eval("CORE_VERSION<22"));
        assert!(eval(&format!("SYSTEM=='{}'", system())));
        assert!(!eval("SYSTEM=='nowhere' AND CORE_VERSION>1"));
        assert!(eval("NOT (SYSTEM=='nowhere') && CORE_VERSION > 1"));
        assert!(eval("SYSTEM LIKE '*'"));
        let mut warnings = Vec::new();
        assert!(!holds("DEVICE_NAME=='Tim'", &mut warnings).unwrap());
        assert_eq!(warnings.len(), 1);
        assert!(holds("CORE_VERSION >>", &mut Vec::new()).is_err());
        assert_eq!(
            split("\"A AND B\" rest of line"),
            ("A AND B", " rest of line")
        );
    }
}
