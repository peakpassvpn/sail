//! What memory the system gives the process, and what of it is free: the
//! smaller of the system's and its cgroup's. Read on Linux (and Android);
//! elsewhere nothing is known.
//!
//! A cgroup's limit is what kills a process on a router or in a
//! container, and it may be much less than the system's memory: a
//! router's service, a container on a large host. Version 2's
//! `memory.max` and `memory.current` are read in the process's cgroup
//! and every one above it with a limit; version 1's
//! `memory.limit_in_bytes` and `memory.usage_in_bytes` the same way.

#[cfg(any(target_os = "linux", target_os = "android", test))]
use std::path::Path;
use std::path::PathBuf;

/// The memory the system gives the process, in bytes: Linux's MemTotal,
/// or a cgroup's limit where that is less; none elsewhere, or when it
/// cannot be read.
pub fn total() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let system = meminfo_field(&std::fs::read_to_string("/proc/meminfo").ok()?, "MemTotal");
        let cgroups = Free::new().limits.into_iter().map(|(limit, _)| limit);
        system.into_iter().chain(cgroups).min()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// The anonymous memory the process holds (RssAnon), in bytes: what its
/// allocations and buffers take, not its file's pages.
pub fn process_anon() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        meminfo_field(
            &std::fs::read_to_string("/proc/self/status").ok()?,
            "RssAnon",
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// Where the process's free memory is read from, found once.
#[derive(Debug, Default)]
pub struct Free {
    /// Each limited cgroup, the process's and those above it: its limit
    /// and the file its use is read from.
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    limits: Vec<(u64, PathBuf)>,
}

impl Free {
    /// The cgroups to read, as the process is placed when this is called.
    pub fn new() -> Self {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") {
            return Self {
                limits: cgroup_limits(&text, Path::new("/sys/fs/cgroup"), |path| {
                    std::fs::read_to_string(path).ok()
                }),
            };
        }
        Self::default()
    }

    /// The memory free for the process, in bytes: the least of the
    /// system's MemAvailable and every limited cgroup's limit less its
    /// use; none when nothing can be read.
    pub fn bytes(&self) -> Option<u64> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let system = std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|text| meminfo_field(&text, "MemAvailable"));
            let cgroups = self.limits.iter().filter_map(|(limit, used)| {
                let used = std::fs::read_to_string(used)
                    .ok()?
                    .trim()
                    .parse::<u64>()
                    .ok()?;
                Some(limit.saturating_sub(used))
            });
            system.into_iter().chain(cgroups).min()
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            None
        }
    }
}

/// A field of `/proc/meminfo` or `/proc/self/status`, `name:  86464 kB`,
/// in bytes.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn meminfo_field(text: &str, name: &str) -> Option<u64> {
    let kib = text
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(kib << 10)
}

/// The limited cgroups of a process placed as `/proc/self/cgroup`'s
/// `text` says, under `root`, with `read` reading a file: version 2's
/// where it is mounted, else version 1's memory controller's.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn cgroup_limits(
    text: &str,
    root: &Path,
    read: impl Fn(&Path) -> Option<String>,
) -> Vec<(u64, PathBuf)> {
    let placed = |controller: &str| {
        text.lines().find_map(|line| {
            let mut fields = line.splitn(3, ':');
            let (_, controllers, path) = (fields.next()?, fields.next()?, fields.next()?);
            (controllers.split(',').any(|c| c == controller)).then_some(path)
        })
    };
    let (dir, limit, used) = match (placed(""), placed("memory")) {
        (Some(path), _) if read(&root.join("cgroup.controllers")).is_some() => (
            root.join(path.trim_start_matches('/')),
            "memory.max",
            "memory.current",
        ),
        (_, Some(path)) => (
            root.join("memory").join(path.trim_start_matches('/')),
            "memory.limit_in_bytes",
            "memory.usage_in_bytes",
        ),
        _ => return Vec::new(),
    };
    dir.ancestors()
        .take_while(|dir| dir.starts_with(root))
        .filter_map(|dir| {
            // Version 2 says "max" when there is none; version 1 gives a
            // number near 2^63.
            let limit = read(&dir.join(limit))?.trim().parse::<u64>().ok()?;
            (limit < 1 << 62).then(|| (limit, dir.join(used)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn meminfo_fields_are_read_in_bytes() {
        let meminfo = "MemTotal:          86464 kB\nMemFree:           46412 kB\nMemAvailable:      50000 kB\n";
        assert_eq!(meminfo_field(meminfo, "MemTotal"), Some(86464 << 10));
        assert_eq!(meminfo_field(meminfo, "MemAvailable"), Some(50000 << 10));
        assert_eq!(meminfo_field("MemFree: 1 kB\n", "MemTotal"), None);
        assert_eq!(meminfo_field("MemTotal: many kB\n", "MemTotal"), None);
        // A name that only begins another's is not it.
        assert_eq!(meminfo_field("RssAnonX: 1 kB\n", "RssAnon"), None);
    }

    fn files(files: &[(&str, &str)]) -> impl Fn(&Path) -> Option<String> {
        let files: HashMap<PathBuf, String> = files
            .iter()
            .map(|(path, text)| (PathBuf::from(path), text.to_string()))
            .collect();
        move |path| files.get(path).cloned()
    }

    /// Every limited cgroup from the process's up is read, and one without
    /// a limit is not.
    #[test]
    fn a_version_2_cgroup_and_those_above_it_are_read() {
        let limits = cgroup_limits(
            "0::/sail.slice/sail.service\n",
            Path::new("/sys/fs/cgroup"),
            files(&[
                ("/sys/fs/cgroup/cgroup.controllers", "cpu memory\n"),
                (
                    "/sys/fs/cgroup/sail.slice/sail.service/memory.max",
                    "67108864\n",
                ),
                ("/sys/fs/cgroup/sail.slice/memory.max", "max\n"),
            ]),
        );
        assert_eq!(
            limits,
            [(
                64 << 20,
                PathBuf::from("/sys/fs/cgroup/sail.slice/sail.service/memory.current")
            )]
        );
    }

    #[test]
    fn a_version_1_memory_cgroup_is_read() {
        let limits = cgroup_limits(
            "12:cpu,cpuacct:/a\n9:memory:/docker/abc\n0::/\n",
            Path::new("/sys/fs/cgroup"),
            files(&[
                (
                    "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
                    "134217728\n",
                ),
                (
                    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                    "9223372036854771712\n",
                ),
            ]),
        );
        assert_eq!(
            limits,
            [(
                128 << 20,
                PathBuf::from("/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes")
            )]
        );
        // Neither version mounted: nothing.
        assert!(cgroup_limits("0::/a\n", Path::new("/sys/fs/cgroup"), files(&[])).is_empty());
    }
}
