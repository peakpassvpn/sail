//! Counts the allocations a process makes, for the measurement builds of
//! the performance regression checks: a [`GlobalAlloc`] around the system's
//! that adds to two counters. Never in a released build.
//!
//! A binary makes it its allocator, and [`write_every`] has the counts
//! written to a file a measuring script reads before and after a load:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: sail::alloc_stats::Counting = sail::alloc_stats::Counting;
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

/// The system's allocator, counting.
pub struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc_zeroed(layout)
    }

    // A reallocation is counted as an allocation of the new size, as it may
    // move.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

fn count(size: usize) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(size as u64, Ordering::Relaxed);
}

/// The allocations made so far, and their bytes.
pub fn counts() -> (u64, u64) {
    (
        ALLOCATIONS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    )
}

/// From now on, writes `{"allocations": n, "bytes": n}` to `path` each
/// `every`, on a thread of its own, replacing the file whole so that a
/// reader never sees half of it.
pub fn write_every(path: PathBuf, every: Duration) {
    let partial = path.with_extension("partial");
    let _ = std::thread::Builder::new()
        .name("alloc-stats".into())
        .spawn(move || loop {
            let (allocations, bytes) = counts();
            let line = format!(
                "{{\"allocations\": {}, \"bytes\": {}}}\n",
                allocations, bytes
            );
            if std::fs::write(&partial, line).is_ok() {
                let _ = std::fs::rename(&partial, &path);
            }
            std::thread::sleep(every);
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allocation_through_it_is_counted() {
        let before = counts();
        let layout = Layout::from_size_align(100, 8).unwrap();
        unsafe {
            let p = Counting.alloc(layout);
            let p = Counting.realloc(p, layout, 300);
            Counting.dealloc(p, Layout::from_size_align(300, 8).unwrap());
        }
        let after = counts();
        // Other tests' threads count too, if they allocate through it; none
        // does, as it is no test binary's allocator.
        assert_eq!(after.0 - before.0, 2);
        assert_eq!(after.1 - before.1, 400);
    }

    #[test]
    fn the_counts_are_written_whole() {
        let dir = std::env::temp_dir().join(format!("sail-alloc-stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("counts.json");
        write_every(path.clone(), Duration::from_millis(10));
        let read = (0..200).find_map(|_| {
            std::thread::sleep(Duration::from_millis(10));
            std::fs::read_to_string(&path).ok()
        });
        let value: serde_json::Value = serde_json::from_str(&read.unwrap()).unwrap();
        assert!(value["allocations"].is_u64() && value["bytes"].is_u64());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
