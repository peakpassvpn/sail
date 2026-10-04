//! Memory a load freed, given back to the system: the allocator's
//! business, and so the business of whoever links one.
//!
//! sail never names an allocator. A binary that knows its allocator keeps
//! freed memory until later allocations (mimalloc purges lazily, and an
//! idle process after a load makes none) registers what gives it back;
//! sail runs it where a large document was just parsed and dropped: after
//! a start, a reload, and a provider's or rule-set's update, whether the
//! document was taken or refused. An embedding host with an allocator of
//! its own registers its own, or nothing.
//!
//! One registration for the process: two instances run the same one,
//! each after its own loads, which is harmless.

use std::sync::OnceLock;

static GIVE_BACK: OnceLock<fn()> = OnceLock::new();

/// Registers `give_back`, run on the task that loaded what was freed, once
/// it dropped it (on a multi-thread runtime, not always the thread that
/// parsed it), never on a connection's path. The first registration stays.
pub fn on_memory_freed(give_back: fn()) {
    let _ = GIVE_BACK.set(give_back);
}

/// Runs what was registered, if anything: an atomic load when nothing was.
pub(crate) fn freed() {
    if let Some(give_back) = GIVE_BACK.get() {
        give_back();
    }
}
