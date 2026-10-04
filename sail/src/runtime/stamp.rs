//! Whether a file was written since it was read, by its size and time of
//! modification: for what reads a file and watches it only later, and for
//! what never watches it and must know, at a reload, whether to read it
//! again.

/// A file's size and time of modification, and when they were taken: what
/// a file is read against, taken just before it is read. A file is read
/// when what it configures is built, and watched only later, at a start
/// seconds later; a write in between raises no event, and without this
/// would never apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    len: u64,
    modified: std::time::SystemTime,
    taken: std::time::SystemTime,
}

/// A file modified this close before its stamp was taken may be written
/// again without its time of modification changing, where a file system
/// keeps it to the second or to two (ext3, HFS+, FAT).
const STAMP_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(2);

impl Stamp {
    pub(crate) fn of(path: &std::path::Path) -> Option<Self> {
        let taken = std::time::SystemTime::now();
        let meta = std::fs::metadata(path).ok()?;
        Some(Stamp {
            len: meta.len(),
            modified: meta.modified().ok()?,
            taken,
        })
    }

    /// Whether its time of modification is a whole second: a file system
    /// that keeps no finer one. One that does gives a whole second once in
    /// a great many writes, and the file is then read once more for
    /// nothing.
    fn coarse(&self) -> bool {
        self.modified
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|since| since.subsec_nanos() == 0)
    }
}

/// Whether `path` may have been written since `read` was taken of it: it
/// is not as it was then; or it is there and was not; or, on a file system
/// that keeps times to the second, it was modified too close to then to
/// tell, as git treats a file as old as its index. A file that is gone or
/// cannot be looked at was not: reading it would only fail.
pub(crate) fn written_since(read: Option<Stamp>, path: &std::path::Path) -> bool {
    let Some(now) = Stamp::of(path) else {
        return false;
    };
    let Some(read) = read else {
        return true;
    };
    (now.len, now.modified) != (read.len, read.modified)
        || (read.coarse()
            && read
                .modified
                .checked_add(STAMP_GRANULARITY)
                .is_none_or(|settled| settled >= read.taken))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stamp tells a file written since from one left alone, and one
    /// that appeared; a file that is gone was not written.
    #[test]
    fn a_stamp_tells_a_file_written_since() {
        let dir = std::env::temp_dir().join(format!("sail-stamp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("file");
        assert!(!written_since(None, &path), "not there, then or now");
        std::fs::write(&path, "one").unwrap();
        assert!(written_since(None, &path), "there now, and was not");
        let read = Stamp::of(&path);
        // On a file system that keeps whole seconds it reads as written,
        // being this fresh: only one with finer times tells it was not.
        if !read.unwrap().coarse() {
            assert!(!written_since(read, &path), "left alone");
        }
        std::fs::write(&path, "another").unwrap();
        assert!(written_since(read, &path), "written since");
        std::fs::remove_file(&path).unwrap();
        assert!(!written_since(read, &path), "gone");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
