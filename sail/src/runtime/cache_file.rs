//! sing-box's `experimental.cache_file`: what an instance keeps across
//! restarts, in one embedded database. The selections of selector groups,
//! the Clash API's mode, and with `store_fakeip`, the fake IPs handed out.
//! Without it, nothing is kept, as in sing-box.
//!
//! One file per instance: redb locks it, so a second instance, or process,
//! given the same file fails to start rather than share it, once it has
//! waited as long as sing-box does for the lock. A reload with the same
//! file goes on with the database already open; the file is closed as soon
//! as the instance stops, or a reload moves to another, not when the last
//! of what used it goes, so that a restart finds it free. A file that
//! cannot be read is set aside and started afresh, as sing-box resets one.
//!
//! Fake IPs are written by a thread of the file's own, as they are handed
//! out: what has queued up is committed in one transaction, the addresses
//! with the cursor, so that the file always holds a state the store was in.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwapOption;
use redb::{Database, DatabaseError, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, warn};

use super::RuntimeEnv;
use crate::config::model::CacheFileOptions;

/// The file's name when `path` is not set, in the host's cache directory
/// or the data directory; sing-box's.
const DEFAULT_NAME: &str = "cache.db";

/// Group tag to the name of the outbound selected.
const SELECTED: &str = "selected";
/// `clash_mode`, and `fakeip_ranges`: the ranges the fake IPs are of.
const META: &str = "meta";
/// A fake IP's address (4 or 16 bytes) to its domain, and the order it
/// was handed out in.
const FAKEIP: &str = "fakeip";
/// 4 or 6 to the last address of that family handed out.
const FAKEIP_CURSOR: &str = "fakeip_cursor";

/// The instance's cache file, as its configuration has it; none without
/// one. Shared by what the instance builds, and replaced by a reload.
#[derive(Clone, Default)]
pub struct CacheFileSlot(Arc<ArcSwapOption<CacheFile>>);

impl std::fmt::Debug for CacheFileSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.load().as_deref() {
            Some(cache) => write!(f, "CacheFileSlot({})", cache.path().display()),
            None => write!(f, "CacheFileSlot(None)"),
        }
    }
}

impl CacheFileSlot {
    pub fn get(&self) -> Option<Arc<CacheFile>> {
        self.0.load_full()
    }

    /// The cache file `options` describe, in place until the guard is
    /// dropped unless it is kept: a reload that fails leaves the file it
    /// found. The same file is not opened again.
    pub fn replace(
        &self,
        options: Option<&CacheFileOptions>,
        env: &RuntimeEnv,
    ) -> Result<CacheFileGuard> {
        let next = match options.filter(|o| o.enabled) {
            None => None,
            Some(options) => {
                let path = path(options, env);
                let current = self.get();
                let shared = match current.as_ref().filter(|c| c.shared.path == path) {
                    Some(current) => current.shared.clone(),
                    None => Shared::open(path)?,
                };
                Some(Arc::new(CacheFile {
                    shared,
                    id: options.cache_id.clone().unwrap_or_default(),
                    store_fakeip: options.store_fakeip,
                }))
            }
        };
        let previous = self.0.swap(next);
        Ok(CacheFileGuard {
            slot: self.clone(),
            previous: Some(previous),
        })
    }
}

/// The cache file a [`CacheFileSlot::replace`] replaced, put back on drop.
pub struct CacheFileGuard {
    slot: CacheFileSlot,
    previous: Option<Option<Arc<CacheFile>>>,
}

impl CacheFileGuard {
    /// Keeps the new file; the old one is closed, if it is another.
    pub fn keep(mut self) {
        if let Some(previous) = self.previous.take() {
            close_unless_same(previous.as_deref(), self.slot.get().as_deref());
        }
    }
}

impl Drop for CacheFileGuard {
    /// Puts the old file back; the new one is closed, if it is another.
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            let new = self.slot.0.swap(previous.clone());
            close_unless_same(new.as_deref(), previous.as_deref());
        }
    }
}

/// Closes `file` unless it is the database `other` is of.
fn close_unless_same(file: Option<&CacheFile>, other: Option<&CacheFile>) {
    if let Some(file) = file {
        if !other.is_some_and(|other| Arc::ptr_eq(&file.shared, &other.shared)) {
            file.shared.close();
        }
    }
}

impl CacheFileSlot {
    /// Closes the file, as the instance stops: what still holds it finds
    /// it closed.
    pub fn close(&self) {
        if let Some(file) = self.0.swap(None) {
            file.shared.close();
        }
    }
}

/// `path`, in the host's cache directory, or the data directory, unless
/// it is absolute.
fn path(options: &CacheFileOptions, env: &RuntimeEnv) -> PathBuf {
    let name = options.path.as_deref().unwrap_or(DEFAULT_NAME);
    let dir = env.host.cache_dir.clone().unwrap_or_else(|| env.data_dir());
    dir.join(name)
}

pub struct CacheFile {
    shared: Arc<Shared>,
    /// `cache_id`: what the configuration keeps is apart from what others
    /// sharing the file keep under theirs.
    id: String,
    /// Whether fake IPs are kept.
    pub store_fakeip: bool,
}

/// The open database, which reloads with the same file go on with.
struct Shared {
    /// Tells this opening apart from any other, for what writes to it.
    serial: u64,
    path: PathBuf,
    /// None once closed.
    db: Arc<RwLock<Option<Database>>>,
    /// Feeds the thread that writes fake IPs; taken on close, which ends
    /// it.
    writes: Mutex<Option<mpsc::Sender<FakeIpWrite>>>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

/// How long a file another instance or process holds is waited for, as
/// sing-box waits (ten tries of a second each).
#[cfg(not(test))]
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

impl Shared {
    fn open(path: PathBuf) -> Result<Arc<Self>> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cache_file: create {}", dir.display()))?;
        }
        let waited = std::time::Instant::now();
        let db = loop {
            match Database::create(&path) {
                Ok(db) => break db,
                Err(DatabaseError::DatabaseAlreadyOpen) if waited.elapsed() < LOCK_WAIT => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(DatabaseError::DatabaseAlreadyOpen) => {
                    return Err(anyhow!(
                        "cache_file: {} is in use by another instance",
                        path.display()
                    ))
                }
                Err(e) => {
                    // Broken, or of a format this redb does not read: set
                    // aside, as sing-box resets a file it cannot open.
                    let aside = path.with_extension("db.broken");
                    warn!(
                        "cache_file: {} cannot be read ({}); moved to {} and started afresh",
                        path.display(),
                        e,
                        aside.display()
                    );
                    std::fs::rename(&path, &aside)
                        .with_context(|| format!("cache_file: move {} aside", path.display()))?;
                    break Database::create(&path)
                        .with_context(|| format!("cache_file: create {}", path.display()))?;
                }
            }
        };
        debug!("cache_file: {}", path.display());
        let db = Arc::new(RwLock::new(Some(db)));
        let (writes, queue) = mpsc::channel();
        let writer = std::thread::Builder::new()
            .name("sail-cache-file".into())
            .spawn({
                let db = db.clone();
                move || write_fake_ips(&db, queue)
            })
            .context("cache_file: start its writer")?;
        static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Ok(Arc::new(Shared {
            serial: SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            path,
            db,
            writes: Mutex::new(Some(writes)),
            writer: Mutex::new(Some(writer)),
        }))
    }
}

impl Shared {
    /// Writes what is queued, and closes the file, which frees it.
    fn close(&self) {
        drop(self.writes.lock().unwrap_or_else(|e| e.into_inner()).take());
        if let Some(writer) = self.writer.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = writer.join();
        }
        if self
            .db
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .is_some()
        {
            debug!("cache_file: {} closed", self.path.display());
        }
    }

    /// Runs `f` on the database, unless it is closed.
    fn with<T>(&self, f: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
        with(&self.db, f)
    }
}

fn with<T>(db: &RwLock<Option<Database>>, f: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
    match db.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(db) => f(db),
        None => Err(anyhow!("cache_file: closed")),
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close();
    }
}

impl CacheFile {
    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    /// The name of table `name` for this configuration's `cache_id`.
    fn table(&self, name: &str) -> String {
        table(name, &self.id)
    }

    fn get_str(&self, name: &str, key: &str) -> Result<Option<String>> {
        let table = self.table(name);
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            let table = match tx.open_table(TableDefinition::<&str, &str>::new(&table)) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            Ok(table.get(key)?.map(|v| v.value().to_owned()))
        })
    }

    fn put_str(&self, name: &str, key: &str, value: &str) -> Result<()> {
        let table = self.table(name);
        self.shared.with(|db| {
            let tx = db.begin_write()?;
            tx.open_table(TableDefinition::<&str, &str>::new(&table))?
                .insert(key, value)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// The outbound `group` had selected.
    pub fn load_selected(&self, group: &str) -> Result<Option<String>> {
        self.get_str(SELECTED, group)
    }

    pub fn store_selected(&self, group: &str, selected: &str) -> Result<()> {
        self.put_str(SELECTED, group, selected)
    }

    /// The Clash API's mode when the instance last ran.
    pub fn load_mode(&self) -> Result<Option<String>> {
        self.get_str(META, "clash_mode")
    }

    pub fn store_mode(&self, mode: &str) -> Result<()> {
        self.put_str(META, "clash_mode", mode)
    }

    /// The fake IPs kept for `ranges`, oldest first, and the last address
    /// of each family handed out; none, and the file's cleared of them,
    /// when they were kept for other ranges.
    pub(crate) fn load_fake_ips(&self, ranges: &str) -> Result<Option<FakeIps>> {
        let kept = self.get_str(META, "fakeip_ranges")?;
        if kept.as_deref() != Some(ranges) {
            self.shared.with(|db| {
                let tx = db.begin_write()?;
                clear_fake_ips(&tx, &self.id, ranges)?;
                tx.commit()?;
                Ok(())
            })?;
            return Ok(None);
        }
        let (fakeip, cursor) = (self.table(FAKEIP), self.table(FAKEIP_CURSOR));
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            let mut fake_ips = FakeIps::default();
            if let Ok(table) = tx.open_table(TableDefinition::<&[u8], (&str, u64)>::new(&fakeip)) {
                for entry in table.iter()? {
                    let (address, value) = entry?;
                    let (domain, order) = value.value();
                    let Some(address) = address_of(address.value()) else {
                        continue;
                    };
                    fake_ips.entries.push((order, address, domain.to_owned()));
                }
            }
            fake_ips.entries.sort_unstable_by_key(|(order, ..)| *order);
            if let Ok(table) = tx.open_table(TableDefinition::<u8, u128>::new(&cursor)) {
                fake_ips.cursor4 = table.get(4)?.map(|v| v.value());
                fake_ips.cursor6 = table.get(6)?.map(|v| v.value());
            }
            Ok(Some(fake_ips))
        })
    }

    /// What fake IPs are written to: this file, under this `cache_id`.
    pub(crate) fn fake_ip_binding(&self) -> (u64, String) {
        (self.shared.serial, self.id.clone())
    }

    /// Queues what a fake IP store did, to be written in turn.
    pub(crate) fn write_fake_ips(&self, ops: Vec<FakeIpOp>) {
        let write = FakeIpWrite {
            id: self.id.clone(),
            ops,
        };
        if let Some(writes) = self
            .shared
            .writes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let _ = writes.send(write);
        }
    }
}

fn table(name: &str, id: &str) -> String {
    if id.is_empty() {
        name.to_owned()
    } else {
        format!("{}@{}", name, id)
    }
}

fn address_of(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

fn bytes_of(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// The fake IPs a file kept.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct FakeIps {
    /// The order each was handed out in, its address and its domain,
    /// oldest first.
    pub entries: Vec<(u64, IpAddr, String)>,
    pub cursor4: Option<u128>,
    pub cursor6: Option<u128>,
}

/// What a fake IP store did.
#[derive(Debug)]
pub(crate) enum FakeIpOp {
    /// Handed out `address` for `domain`, the `order`th.
    Put {
        address: IpAddr,
        domain: String,
        order: u64,
    },
    /// Forgot `address`.
    Remove(IpAddr),
    /// The last address of the family handed out.
    Cursor { v6: bool, current: u128 },
    /// Forgot every one: what follows is all there is, of `ranges`.
    Clear { ranges: String },
}

struct FakeIpWrite {
    /// The `cache_id` the tables are of.
    id: String,
    ops: Vec<FakeIpOp>,
}

/// Empties the fake IP tables of `id`, now kept for `ranges`.
fn clear_fake_ips(tx: &redb::WriteTransaction, id: &str, ranges: &str) -> Result<()> {
    tx.delete_table(TableDefinition::<&[u8], (&str, u64)>::new(&table(
        FAKEIP, id,
    )))?;
    tx.delete_table(TableDefinition::<u8, u128>::new(&table(FAKEIP_CURSOR, id)))?;
    tx.open_table(TableDefinition::<&str, &str>::new(&table(META, id)))?
        .insert("fakeip_ranges", ranges)?;
    Ok(())
}

/// Writes what is queued, in one transaction for as much as has queued up
/// while the last committed, until the file closes.
fn write_fake_ips(db: &RwLock<Option<Database>>, queue: mpsc::Receiver<FakeIpWrite>) {
    while let Ok(first) = queue.recv() {
        let mut writes = vec![first];
        writes.extend(queue.try_iter());
        if let Err(e) = with(db, |db| commit_fake_ips(db, &writes)) {
            warn!("cache_file: fake IPs not kept: {}", e);
        }
    }
}

fn commit_fake_ips(db: &Database, writes: &[FakeIpWrite]) -> Result<()> {
    let tx = db.begin_write()?;
    for write in writes {
        let (fakeip, cursor) = (table(FAKEIP, &write.id), table(FAKEIP_CURSOR, &write.id));
        let (fakeip, cursor) = (
            TableDefinition::<&[u8], (&str, u64)>::new(&fakeip),
            TableDefinition::<u8, u128>::new(&cursor),
        );
        for op in &write.ops {
            match op {
                FakeIpOp::Put {
                    address,
                    domain,
                    order,
                } => {
                    tx.open_table(fakeip)?
                        .insert(bytes_of(*address).as_slice(), (domain.as_str(), *order))?;
                }
                FakeIpOp::Remove(address) => {
                    tx.open_table(fakeip)?
                        .remove(bytes_of(*address).as_slice())?;
                }
                FakeIpOp::Cursor { v6, current } => {
                    tx.open_table(cursor)?
                        .insert(if *v6 { 6 } else { 4 }, *current)?;
                }
                FakeIpOp::Clear { ranges } => clear_fake_ips(&tx, &write.id, ranges)?,
            }
        }
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::runtime::Host;

    pub(crate) fn env(dir: &Path) -> RuntimeEnv {
        RuntimeEnv {
            host: Host {
                cache_dir: Some(dir.to_path_buf()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub(crate) fn enabled() -> CacheFileOptions {
        CacheFileOptions {
            enabled: true,
            ..Default::default()
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sail-cache-file-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn nothing_is_kept_unless_it_is_enabled() {
        let dir = temp_dir("disabled");
        let slot = CacheFileSlot::default();
        slot.replace(Some(&CacheFileOptions::default()), &env(&dir))
            .unwrap()
            .keep();
        assert!(slot.get().is_none());
        assert!(!dir.exists());
    }

    #[test]
    fn selections_and_the_mode_are_kept_apart_by_cache_id() {
        let dir = temp_dir("ids");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.path(), dir.join("cache.db"));
        assert_eq!(cache.load_selected("g").unwrap(), None);
        cache.store_selected("g", "b").unwrap();
        cache.store_mode("Global").unwrap();

        let other = CacheFileOptions {
            cache_id: Some("other".into()),
            ..enabled()
        };
        slot.replace(Some(&other), &env).unwrap().keep();
        let by_id = slot.get().unwrap();
        // The same database, not opened again, which its lock would refuse.
        assert!(Arc::ptr_eq(&cache.shared, &by_id.shared));
        assert_eq!(by_id.load_selected("g").unwrap(), None);
        assert_eq!(by_id.load_mode().unwrap(), None);
        drop((cache, by_id));

        // Closed, and opened again: as a restart finds it.
        slot.replace(None, &env).unwrap().keep();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.load_selected("g").unwrap().as_deref(), Some("b"));
        assert_eq!(cache.load_mode().unwrap().as_deref(), Some("Global"));
        drop(cache);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_that_fails_puts_the_old_file_back() {
        let dir = temp_dir("guard");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let before = slot.get().unwrap().path().to_path_buf();
        {
            let _guard = slot.replace(None, &env).unwrap();
            assert!(slot.get().is_none());
        }
        assert_eq!(slot.get().unwrap().path(), before);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_in_use_is_an_error_and_a_broken_one_is_started_afresh() {
        let dir = temp_dir("lock");
        let env = env(&dir);
        let first = CacheFileSlot::default();
        first.replace(Some(&enabled()), &env).unwrap().keep();
        let err = CacheFileSlot::default()
            .replace(Some(&enabled()), &env)
            .err()
            .unwrap();
        assert!(err.to_string().contains("in use"), "{}", err);
        first.replace(None, &env).unwrap().keep();

        std::fs::write(dir.join("cache.db"), b"not a database").unwrap();
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        slot.get().unwrap().store_selected("g", "a").unwrap();
        assert!(dir.join("cache.db.broken").exists());
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fake_ips_are_kept_for_their_ranges() {
        let dir = temp_dir("fakeip");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.load_fake_ips("a").unwrap(), None);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        cache.write_fake_ips(vec![
            FakeIpOp::Put {
                address: ip("198.18.0.5"),
                domain: "b.example".into(),
                order: 2,
            },
            FakeIpOp::Put {
                address: ip("198.18.0.4"),
                domain: "a.example".into(),
                order: 1,
            },
            FakeIpOp::Put {
                address: ip("fc00::4"),
                domain: "c.example".into(),
                order: 3,
            },
            FakeIpOp::Cursor {
                v6: false,
                current: 5,
            },
        ]);
        cache.write_fake_ips(vec![FakeIpOp::Remove(ip("fc00::4"))]);
        drop(cache);
        // Closing writes what is queued.
        slot.replace(None, &env).unwrap().keep();

        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(
            cache.load_fake_ips("a").unwrap(),
            Some(FakeIps {
                entries: vec![
                    (1, ip("198.18.0.4"), "a.example".into()),
                    (2, ip("198.18.0.5"), "b.example".into()),
                ],
                cursor4: Some(5),
                cursor6: None,
            })
        );
        // Other ranges: what was kept goes.
        assert_eq!(cache.load_fake_ips("b").unwrap(), None);
        assert_eq!(cache.load_fake_ips("b").unwrap(), Some(FakeIps::default()));
        drop(cache);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
