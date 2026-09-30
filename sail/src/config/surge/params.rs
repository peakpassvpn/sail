//! Keys and their values, read one by one: a section of `key = value`
//! lines, or the `key=value` parameters of a line. What is left once they
//! are read is sorted out as sail's policy has it.

use std::str::FromStr;

use anyhow::{anyhow, Result};
use indexmap::IndexMap;

/// How a key Surge takes and sail does not implement is treated; each with
/// what is said of it, after the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Ignoring it would route or secure traffic otherwise than the
    /// profile says: an error.
    Unsupported(&'static str),
    /// Ignoring it changes no routing or security: a warning.
    Ignored(&'static str),
    /// It means nothing where sail runs, or only to Surge's interface.
    Silent,
}

#[cfg(test)]
thread_local! {
    /// What was passed over without a word, as `silent` notes it.
    pub static SILENT: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Notes that `what`, where a key is and the key, was passed over without
/// a word: in tests, so that the field registry tells it from what is read.
pub fn silent(what: &str) {
    #[cfg(test)]
    SILENT.with(|s| s.borrow_mut().push(what.to_string()));
    #[cfg(not(test))]
    let _ = what;
}

/// The keys, each with its value and where it is.
pub struct Params {
    at: String,
    map: IndexMap<String, (String, String)>,
}

impl Params {
    /// None yet, at `at`.
    pub fn new(at: impl Into<String>) -> Self {
        Params {
            at: at.into(),
            map: IndexMap::new(),
        }
    }

    /// Adds `key` (lowercase) of `value`; `at` is where it is, when not
    /// where the others are. A key given again takes the later value.
    pub fn insert(&mut self, key: &str, value: String, at: Option<String>) {
        let at = at.unwrap_or_else(|| self.at.clone());
        self.map.shift_remove(key);
        self.map.insert(key.to_string(), (value, at));
    }

    /// Where the keys are.
    pub fn path(&self) -> &str {
        &self.at
    }

    /// Where `key` is, as errors write it.
    pub fn at(&self, key: &str) -> String {
        match self.map.get(key) {
            Some((_, at)) => format!("{}: {}", at, key),
            None => format!("{}: {}", self.at, key),
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Takes `key`, and where it was.
    pub fn take_at(&mut self, key: &str) -> Option<(String, String)> {
        self.map
            .shift_remove(key)
            .map(|(value, at)| (value, format!("{}: {}", at, key)))
    }

    /// Takes `key`; empty is none.
    pub fn string(&mut self, key: &str) -> Option<String> {
        self.map
            .shift_remove(key)
            .map(|(v, _)| v)
            .filter(|v| !v.is_empty())
    }

    /// Takes `key`, `true` or `false` as Surge writes them.
    pub fn bool(&mut self, key: &str) -> Result<Option<bool>> {
        let at = self.at(key);
        match self.string(key) {
            None => Ok(None),
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok(Some(true)),
                "false" | "no" | "off" | "0" => Ok(Some(false)),
                _ => Err(anyhow!("{}: {:?} is neither true nor false", at, v)),
            },
        }
    }

    /// Takes `key`, a number.
    pub fn num<T: FromStr>(&mut self, key: &str) -> Result<Option<T>> {
        let at = self.at(key);
        self.string(key)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|_| anyhow!("{}: {:?} is not a number in range", at, v))
            })
            .transpose()
    }

    /// Takes `key`, a list separated by commas.
    pub fn list(&mut self, key: &str) -> Vec<String> {
        self.string(key)
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sorts out what is left: a key `known` lists is an error, a warning
    /// or nothing as its tier says; any other Surge does not know either
    /// and passes over, and so does sail, warning of it. `what` is what a
    /// key is called: a key, a parameter.
    pub fn finish(
        self,
        known: &[(&str, Tier)],
        what: &str,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        for (key, (_, at)) in &self.map {
            let at = format!("{}: {}", at, key);
            match known.iter().find(|(k, _)| k == key) {
                Some((_, Tier::Unsupported(why))) => {
                    return Err(anyhow!(
                        "{}: sail does not implement this {} yet{}",
                        at,
                        what,
                        why
                    ));
                }
                Some((_, Tier::Ignored(why))) => warnings.push(format!(
                    "{}: sail does not implement this {}{}; ignored",
                    at, what, why
                )),
                Some((_, Tier::Silent)) => silent(&at),
                None => warnings.push(format!(
                    "{}: not a {} Surge takes; ignored, as by Surge",
                    at, what
                )),
            }
        }
        Ok(())
    }
}
