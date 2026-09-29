//! Reading a dashboard's ZIP: its files, stored or deflated, as a GitHub
//! archive has them. What would leave the directory it goes into, and
//! archives larger than a dashboard, are refused.

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Result};

/// The most a dashboard's files may take, unpacked; metacubexd's take
/// some 10 MiB.
const MAX_UNPACKED: usize = 256 << 20;
/// The most files it may have.
const MAX_FILES: usize = 20_000;

const END_OF_DIRECTORY: u32 = 0x0605_4b50;
const DIRECTORY_ENTRY: u32 = 0x0201_4b50;
const LOCAL_HEADER: u32 = 0x0403_4b50;

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| anyhow!("truncated"))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| anyhow!("truncated"))
}

/// The files of `data`, each by its path, without the one directory
/// every path is under, if there is one, as a GitHub archive has it.
pub(super) fn files(data: &[u8]) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    // The end of the central directory, followed by a comment of at most
    // 64 KiB.
    let end = (0..=data.len().saturating_sub(22))
        .rev()
        .take(22 + 0xFFFF)
        .find(|&at| u32_at(data, at).ok() == Some(END_OF_DIRECTORY))
        .ok_or_else(|| anyhow!("not a ZIP"))?;
    let count = u16_at(data, end + 10)? as usize;
    let offset = u32_at(data, end + 16)?;
    if count == 0xFFFF || offset == 0xFFFF_FFFF {
        bail!("a ZIP64 archive, larger than a dashboard");
    }
    if count > MAX_FILES {
        bail!("more than {} files", MAX_FILES);
    }
    let mut at = offset as usize;
    let mut files = Vec::new();
    let mut unpacked = 0usize;
    for _ in 0..count {
        if u32_at(data, at)? != DIRECTORY_ENTRY {
            bail!("a damaged directory");
        }
        let method = u16_at(data, at + 10)?;
        let packed = u32_at(data, at + 20)? as usize;
        let size = u32_at(data, at + 24)? as usize;
        let name_len = u16_at(data, at + 28)? as usize;
        let extra_len = u16_at(data, at + 30)? as usize;
        let comment_len = u16_at(data, at + 32)? as usize;
        let local = u32_at(data, at + 42)? as usize;
        let name = data
            .get(at + 46..at + 46 + name_len)
            .ok_or_else(|| anyhow!("truncated"))?;
        let name = String::from_utf8_lossy(name).into_owned();
        at += 46 + name_len + extra_len + comment_len;
        if name.ends_with('/') {
            continue;
        }
        unpacked = unpacked.saturating_add(size);
        if unpacked > MAX_UNPACKED {
            bail!("larger than {} bytes unpacked", MAX_UNPACKED);
        }
        if u32_at(data, local)? != LOCAL_HEADER {
            bail!("{}: a damaged entry", name);
        }
        let start =
            local + 30 + u16_at(data, local + 26)? as usize + u16_at(data, local + 28)? as usize;
        let body = data
            .get(start..start + packed)
            .ok_or_else(|| anyhow!("{}: truncated", name))?;
        let body = match method {
            0 => body.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(body, size)
                .map_err(|e| anyhow!("{}: {:?}", name, e.status))?,
            other => bail!(
                "{}: compressed by method {}, not stored or deflated",
                name,
                other
            ),
        };
        if body.len() != size {
            bail!("{}: {} bytes, not the {} said", name, body.len(), size);
        }
        files.push((safe_path(&name)?, body));
    }
    Ok(strip_top(files))
}

/// `name` as a relative path that stays where it is put.
fn safe_path(name: &str) -> Result<PathBuf> {
    let mut path = PathBuf::new();
    for part in Path::new(name).components() {
        match part {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => bail!("{}: leaves the directory", name),
        }
    }
    if path.as_os_str().is_empty() {
        bail!("an entry without a name");
    }
    Ok(path)
}

/// Without the one directory all of `files` are under, if they are.
fn strip_top(files: Vec<(PathBuf, Vec<u8>)>) -> Vec<(PathBuf, Vec<u8>)> {
    let top = |p: &Path| match p.components().next() {
        Some(Component::Normal(top)) if p.components().count() > 1 => Some(top.to_owned()),
        _ => None,
    };
    let Some(first) = files.first().and_then(|(p, _)| top(p)) else {
        return files;
    };
    if !files.iter().all(|(p, _)| top(p).as_ref() == Some(&first)) {
        return files;
    }
    files
        .into_iter()
        .map(|(p, body)| {
            (
                p.strip_prefix(&first).map(Path::to_path_buf).unwrap_or(p),
                body,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ZIP of `entries`, each stored or deflated.
    pub(crate) fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for (name, body, deflate) in entries {
            let packed = if *deflate {
                miniz_oxide::deflate::compress_to_vec(body, 6)
            } else {
                body.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            let mut header = Vec::new();
            header.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
            header.extend_from_slice(&[20, 0, 0, 0]);
            header.extend_from_slice(&method.to_le_bytes());
            header.extend_from_slice(&[0; 8]); // time, date, crc
            header.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            header.extend_from_slice(&(body.len() as u32).to_le_bytes());
            header.extend_from_slice(&(name.len() as u16).to_le_bytes());
            header.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&header);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&packed);
            directory.extend_from_slice(&DIRECTORY_ENTRY.to_le_bytes());
            directory.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            directory.extend_from_slice(&method.to_le_bytes());
            directory.extend_from_slice(&[0; 8]);
            directory.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let offset = out.len() as u32;
        out.extend_from_slice(&directory);
        out.extend_from_slice(&END_OF_DIRECTORY.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn a_github_archive_is_read_without_its_top_directory() {
        let data = zip(&[
            ("ui-gh-pages/", b"", false),
            ("ui-gh-pages/index.html", b"<html>hello</html>", true),
            ("ui-gh-pages/assets/app.js", b"let a = 1;", false),
        ]);
        let read = files(&data).unwrap();
        assert_eq!(
            read,
            [
                (PathBuf::from("index.html"), b"<html>hello</html>".to_vec()),
                (PathBuf::from("assets/app.js"), b"let a = 1;".to_vec()),
            ]
        );
        // Files not all under one directory keep their paths.
        let data = zip(&[("index.html", b"a", false), ("assets/app.js", b"b", false)]);
        assert_eq!(files(&data).unwrap()[1].0, PathBuf::from("assets/app.js"));
    }

    #[test]
    fn what_would_leave_the_directory_is_refused() {
        let data = zip(&[("../evil", b"x", false)]);
        assert!(files(&data).unwrap_err().to_string().contains("leaves"));
        let data = zip(&[("/etc/evil", b"x", false)]);
        assert!(files(&data).is_err());
        assert!(files(b"not a zip at all, not at all").is_err());
    }
}
