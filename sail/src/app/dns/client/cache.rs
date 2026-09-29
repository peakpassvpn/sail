//! The answers each server gave, kept as sing-box keeps them: for the
//! shortest TTL of their records, or a negative answer for its SOA's
//! (RFC 2308), and not at all without one; every record then carries that
//! TTL, less what has passed. With `disable_expire`, they are kept until
//! the cache is full or cleared. With `optimistic`, an answer that has
//! expired is still given, with a TTL of 1, for up to its timeout, while
//! the server is asked again in the background.

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use lru::LruCache;

use crate::util::DnsMessageExt;
use serde_derive::Serialize;

/// A server's answers, by the server, the question (name, record type)
/// and the client subnet asked for.
pub(super) type AnswerKey = (String, String, u16, Option<crate::config::model::Prefix>);

/// What the cache has for a question.
pub(super) enum Cached {
    Fresh(Message),
    /// Expired, but within the optimistic timeout.
    Stale(Message),
    Missing,
}

pub(super) struct Answers {
    entries: Mutex<LruCache<AnswerKey, (Message, Instant)>>,
    disable_expire: bool,
    optimistic: Option<Duration>,
    /// Questions being asked again in the background: one at a time each.
    refreshing: Mutex<HashSet<AnswerKey>>,
    hits: AtomicU64,
    stale_hits: AtomicU64,
    misses: AtomicU64,
}

/// What the cache holds and how it served, since the DNS client was built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    /// Expired answers given while asked for again.
    pub stale_hits: u64,
    pub misses: u64,
}

impl Answers {
    pub(super) fn new(
        capacity: NonZeroUsize,
        disable_expire: bool,
        optimistic: Option<Duration>,
    ) -> Self {
        Answers {
            entries: Mutex::new(LruCache::new(capacity)),
            disable_expire,
            optimistic,
            refreshing: Default::default(),
            hits: Default::default(),
            stale_hits: Default::default(),
            misses: Default::default(),
        }
    }

    /// The answer kept for `key`, with `id`.
    pub(super) fn get(&self, key: &AnswerKey, id: u16) -> Cached {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some((message, expires)) = entries.get(key) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Cached::Missing;
        };
        let now = Instant::now();
        let (ttl, stale) = if self.disable_expire {
            (None, false)
        } else if now < *expires {
            (Some((*expires - now).as_secs().max(1) as u32), false)
        } else if self
            .optimistic
            .is_some_and(|window| now < *expires + window)
        {
            (Some(1), true)
        } else {
            entries.pop(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Cached::Missing;
        };
        let mut message = message.clone();
        drop(entries);
        message.set_id(id);
        if let Some(ttl) = ttl {
            set_ttl(&mut message, ttl);
        }
        if stale {
            self.stale_hits.fetch_add(1, Ordering::Relaxed);
            Cached::Stale(message)
        } else {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Cached::Fresh(message)
        }
    }

    /// Keeps `message` for `ttl` seconds; not at all for none.
    pub(super) fn put(&self, key: AnswerKey, message: &Message, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let expires = Instant::now() + Duration::from_secs(ttl.into());
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, (message.clone(), expires));
    }

    /// Whether `key` may be asked again in the background now: not while
    /// it already is. [`Answers::refreshed`] ends it.
    pub(super) fn start_refresh(&self, key: &AnswerKey) -> bool {
        self.refreshing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone())
    }

    pub(super) fn refreshed(&self, key: &AnswerKey) {
        self.refreshing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// Forgets every answer.
    pub(super) fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub(super) fn stats(&self) -> CacheStats {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        CacheStats {
            entries: entries.len(),
            capacity: entries.cap().get(),
            hits: self.hits.load(Ordering::Relaxed),
            stale_hits: self.stale_hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

/// How long `response` may be kept, as sing-box has it: a negative answer
/// (no answer records) for its SOA's TTL or MINIMUM, whichever is less;
/// otherwise the shortest TTL of its records but zero, and 0, not kept,
/// when none has one.
pub(super) fn ttl_of(response: &Message) -> u32 {
    if response.answers().is_empty() {
        for record in response.name_servers() {
            if let RData::SOA(soa) = &record.data {
                return record.ttl.min(soa.minimum);
            }
        }
    }
    response
        .answers()
        .iter()
        .chain(response.name_servers())
        .chain(&response.additionals)
        .filter(|r| r.record_type() != RecordType::OPT && r.ttl > 0)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
}

/// Gives every record of `message` the TTL `ttl`, as sing-box does, so
/// that none outlives the answer kept.
pub(super) fn set_ttl(message: &mut Message, ttl: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        if record.record_type() != RecordType::OPT {
            record.ttl = ttl;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, Record};
    use std::str::FromStr;

    fn key(name: &str) -> AnswerKey {
        ("s".into(), name.into(), 1, None)
    }

    fn answer(ttls: &[u32]) -> Message {
        let name = Name::from_str("a.example.").unwrap();
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name.clone(), RecordType::A));
        for (i, ttl) in ttls.iter().enumerate() {
            m.add_answer(Record::from_rdata(
                name.clone(),
                *ttl,
                RData::A(A::new(10, 0, 0, i as u8)),
            ));
        }
        m
    }

    fn negative(soa_ttl: u32, minimum: u32) -> Message {
        let mut m = answer(&[]);
        let zone = Name::from_str("example.").unwrap();
        m.add_authority(Record::from_rdata(
            zone.clone(),
            soa_ttl,
            RData::SOA(SOA::new(zone.clone(), zone, 1, 2, 3, 4, minimum)),
        ));
        m
    }

    #[test]
    fn the_ttl_is_the_shortest_or_the_soas() {
        assert_eq!(ttl_of(&answer(&[300, 60, 0])), 60);
        assert_eq!(ttl_of(&negative(900, 30)), 30);
        assert_eq!(ttl_of(&negative(20, 30)), 20);
        // No records and no SOA: not kept.
        assert_eq!(ttl_of(&answer(&[])), 0);
        let mut m = answer(&[300, 60]);
        set_ttl(&mut m, 7);
        assert!(m.answers().iter().all(|r| r.ttl == 7));
    }

    fn cache(disable_expire: bool, optimistic: Option<Duration>) -> Answers {
        Answers::new(NonZeroUsize::new(4).unwrap(), disable_expire, optimistic)
    }

    fn age(answers: &Answers, key: &AnswerKey, by: Duration) {
        let mut entries = answers.entries.lock().unwrap();
        let (_, expires) = entries.get_mut(key).unwrap();
        *expires -= by;
    }

    #[test]
    fn an_answer_is_given_until_it_expires_with_what_is_left_of_its_ttl() {
        let answers = cache(false, None);
        let k = key("a");
        answers.put(k.clone(), &answer(&[60]), 60);
        age(&answers, &k, Duration::from_secs(20));
        let Cached::Fresh(m) = answers.get(&k, 9) else {
            panic!("fresh")
        };
        assert_eq!(m.id(), 9);
        assert!((39..=40).contains(&m.answers()[0].ttl));
        age(&answers, &k, Duration::from_secs(41));
        assert!(matches!(answers.get(&k, 9), Cached::Missing));
        // Gone for good.
        assert!(matches!(answers.get(&k, 9), Cached::Missing));
        answers.put(k.clone(), &answer(&[]), 0);
        assert!(matches!(answers.get(&k, 9), Cached::Missing));
        assert_eq!(
            answers.stats(),
            CacheStats {
                entries: 0,
                capacity: 4,
                hits: 1,
                stale_hits: 0,
                misses: 3
            }
        );
    }

    #[test]
    fn optimistic_gives_an_expired_answer_within_its_timeout() {
        let answers = cache(false, Some(Duration::from_secs(3600)));
        let k = key("a");
        answers.put(k.clone(), &answer(&[60]), 60);
        age(&answers, &k, Duration::from_secs(120));
        let Cached::Stale(m) = answers.get(&k, 1) else {
            panic!("stale")
        };
        assert_eq!(m.answers()[0].ttl, 1);
        assert!(answers.start_refresh(&k));
        assert!(!answers.start_refresh(&k));
        answers.refreshed(&k);
        assert!(answers.start_refresh(&k));
        age(&answers, &k, Duration::from_secs(3600));
        assert!(matches!(answers.get(&k, 1), Cached::Missing));
    }

    #[test]
    fn without_expiry_an_answer_stays_until_cleared() {
        let answers = cache(true, None);
        let k = key("a");
        answers.put(k.clone(), &answer(&[60]), 60);
        age(&answers, &k, Duration::from_secs(3600));
        assert!(matches!(answers.get(&k, 1), Cached::Fresh(_)));
        answers.clear();
        assert!(matches!(answers.get(&k, 1), Cached::Missing));
    }
}
