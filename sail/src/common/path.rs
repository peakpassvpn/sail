//! Paths a configuration names that must stay in a directory: where a
//! downloaded provider, rule-set or dashboard is written. One rule for all
//! of them, Mihomo's `IsSafePath` and Go's `filepath.IsLocal`.
//!
//! On Windows a path with a drive but no root (`C:x`) or a root but no drive
//! (`\x`) is neither absolute nor relative: where it lands depends on the
//! process's current drive and directory, so it never counts as in one.

use std::path::{Component, Path, PathBuf};

/// `path` as a relative path that stays where it is put, `.` and `..` taken
/// away; none when it is empty, climbs out, or has a root or a drive.
pub fn local(path: &Path) -> Option<PathBuf> {
    let mut plain = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(part) => plain.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                if !plain.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!plain.as_os_str().is_empty()).then_some(plain)
}

/// `path` in `dir`: a [`local`] path joined to it, or an absolute one below
/// it (not `dir` itself), `.` and `..` taken away; none for anything else.
pub fn within(dir: &Path, path: &Path) -> Option<PathBuf> {
    if let Some(local) = local(path) {
        return Some(dir.join(local));
    }
    if !path.is_absolute() {
        return None;
    }
    let mut plain = PathBuf::new();
    for part in path.components() {
        match part {
            // Above the root is the root, as Go's Clean has it.
            Component::ParentDir => {
                plain.pop();
            }
            Component::CurDir => {}
            other => plain.push(other.as_os_str()),
        }
    }
    (plain.starts_with(dir) && plain != dir).then_some(plain)
}

/// Whether `path` stays in `dir`, or, with no directory to tell, is
/// [`local`]: an absolute path is then refused.
pub fn stays_in(dir: Option<&Path>, path: &str) -> bool {
    match dir {
        Some(dir) => within(dir, Path::new(path)).is_some(),
        None => local(Path::new(path)).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_path_stays_where_it_is_put() {
        for (path, plain) in [
            ("a.yaml", "a.yaml"),
            ("./sub/a.yaml", "sub/a.yaml"),
            ("sub/../a.yaml", "a.yaml"),
            ("sub/./x/../a.yaml", "sub/a.yaml"),
        ] {
            assert_eq!(local(Path::new(path)), Some(PathBuf::from(plain)), "{path}");
        }
        for path in ["", ".", "..", "../a", "sub/../../a", "a/..", "/a", "/"] {
            assert_eq!(local(Path::new(path)), None, "{path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_absolute_path_is_within_a_directory_only_below_it() {
        let dir = Path::new("/srv/sail/data");
        for (path, plain) in [
            ("/srv/sail/data/a.yaml", "/srv/sail/data/a.yaml"),
            ("/srv/sail/data/sub/../a.yaml", "/srv/sail/data/a.yaml"),
            ("sub/a.yaml", "/srv/sail/data/sub/a.yaml"),
        ] {
            assert_eq!(
                within(dir, Path::new(path)),
                Some(PathBuf::from(plain)),
                "{path}"
            );
        }
        for path in [
            "/srv/sail/data",
            "/srv/sail/data/",
            "/srv/sail/data/../other/a.yaml",
            "/srv/sail/database/a.yaml",
            "/etc/passwd",
            "/../srv/sail/other",
            "../data/a.yaml",
        ] {
            assert_eq!(within(dir, Path::new(path)), None, "{path}");
        }
        assert!(stays_in(None, "sub/a.yaml"));
        assert!(!stays_in(None, "/srv/sail/data/a.yaml"));
    }

    /// Fails without the Prefix and RootDir arms: `C:x` and `\x` are not
    /// absolute, and were taken as relative paths in the directory.
    #[cfg(windows)]
    #[test]
    fn a_windows_path_with_a_drive_or_a_root_alone_is_in_no_directory() {
        let dir = Path::new(r"C:\sail\data");
        for (path, plain) in [
            (r"C:\sail\data\a.yaml", r"C:\sail\data\a.yaml"),
            (r"sub\a.yaml", r"C:\sail\data\sub\a.yaml"),
            (r".\a.yaml", r"C:\sail\data\a.yaml"),
            ("sub/a.yaml", r"C:\sail\data\sub\a.yaml"),
        ] {
            assert_eq!(
                within(dir, Path::new(path)),
                Some(PathBuf::from(plain)),
                "{path}"
            );
        }
        for path in [
            r"C:\Windows\a.yaml",
            r"D:\sail\data\a.yaml",
            r"\\server\share\a.yaml",
            r"\\?\C:\Windows\a.yaml",
            r"\sail\data\a.yaml",
            r"C:a.yaml",
            r"C:sail\data\a.yaml",
            r"sub\..\..\a.yaml",
        ] {
            assert_eq!(within(dir, Path::new(path)), None, "{path}");
            assert_eq!(local(Path::new(path)), None, "{path}");
        }
    }
}
