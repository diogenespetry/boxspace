//! Object and version listings with prefix/delimiter/marker semantics.

use crate::{
    error::Result,
    storage::{ObjectVersion, Scan, Store},
};

/// Smallest key greater than every key starting with `prefix`
/// (UTF-8 never contains 0xFF, so the increment cannot overflow).
fn after_prefix(prefix: &str) -> Vec<u8> {
    let mut b = prefix.as_bytes().to_vec();
    if let Some(last) = b.last_mut() {
        *last += 1;
    }
    b
}

#[derive(Default, Debug)]
pub struct ListOut {
    pub contents: Vec<ObjectVersion>,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    /// Last key or common prefix returned (marker for the next page).
    pub next: Option<String>,
}

#[derive(Default, Debug)]
pub struct VersionsOut {
    /// (version, is_latest)
    pub entries: Vec<(ObjectVersion, bool)>,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    pub next_key: Option<String>,
    pub next_version: Option<String>,
}

/// Was `marker` a common prefix returned by a previous page?
fn marker_is_prefix(marker: &str, prefix: &str, delim: Option<&str>) -> bool {
    delim.is_some_and(|d| marker.len() > prefix.len() && marker.starts_with(prefix) && marker.ends_with(d))
}

fn common_prefix<'a>(key: &'a str, prefix: &str, delim: Option<&str>) -> Option<&'a str> {
    let d = delim?;
    let rest = &key[prefix.len()..];
    rest.find(d).map(|i| &key[..prefix.len() + i + d.len()])
}

/// List current (non-deleted) objects after `marker` (exclusive).
pub fn list_current(store: &Store, bucket: &str, prefix: &str, delim: Option<&str>, marker: &str, max: usize) -> Result<ListOut> {
    let mut out = ListOut::default();
    if max == 0 {
        return Ok(out);
    }
    let from = if marker > prefix { marker } else { prefix };
    let skip_under_marker = marker_is_prefix(marker, prefix, delim);
    let mut last_key: Option<String> = None;
    let mut count = 0usize;
    store.scan(bucket, from, |v| {
        if last_key.as_deref() == Some(v.key.as_str()) {
            return Scan::Next; // older version of a key already handled
        }
        last_key = Some(v.key.clone());
        if !v.key.starts_with(prefix) {
            return Scan::Stop;
        }
        if skip_under_marker && v.key.starts_with(marker) {
            return Scan::Seek(after_prefix(marker));
        }
        if !marker.is_empty() && v.key.as_str() <= marker {
            return Scan::Next;
        }
        if v.delete_marker {
            return Scan::Next;
        }
        if let Some(cp) = common_prefix(&v.key, prefix, delim) {
            if count >= max {
                out.truncated = true;
                return Scan::Stop;
            }
            out.prefixes.push(cp.to_string());
            out.next = Some(cp.to_string());
            count += 1;
            // Nothing else under this prefix needs to be visited.
            return Scan::Seek(after_prefix(cp));
        }
        if count >= max {
            out.truncated = true;
            return Scan::Stop;
        }
        out.next = Some(v.key.clone());
        out.contents.push(v);
        count += 1;
        Scan::Next
    })?;
    if !out.truncated {
        out.next = None;
    }
    Ok(out)
}

pub fn list_versions(
    store: &Store,
    bucket: &str,
    prefix: &str,
    delim: Option<&str>,
    key_marker: &str,
    version_marker: &str,
    max: usize,
) -> Result<VersionsOut> {
    let mut out = VersionsOut::default();
    if max == 0 {
        return Ok(out);
    }
    let from = if key_marker > prefix { key_marker } else { prefix };
    let skip_under_marker = marker_is_prefix(key_marker, prefix, delim);
    let mut last_key: Option<String> = None;
    let mut passed = version_marker.is_empty();
    let mut count = 0usize;
    store.scan(bucket, from, |v| {
        let latest = last_key.as_deref() != Some(v.key.as_str());
        if latest {
            last_key = Some(v.key.clone());
        }
        if !v.key.starts_with(prefix) {
            return Scan::Stop;
        }
        if !key_marker.is_empty() {
            if v.key.as_str() < key_marker {
                return Scan::Next;
            }
            if v.key == key_marker {
                if version_marker.is_empty() {
                    return Scan::Next;
                }
                if !passed {
                    passed = v.version_id == version_marker;
                    return Scan::Next;
                }
            } else if skip_under_marker && v.key.starts_with(key_marker) {
                return Scan::Seek(after_prefix(key_marker));
            }
        }
        if let Some(cp) = common_prefix(&v.key, prefix, delim) {
            if count >= max {
                out.truncated = true;
                return Scan::Stop;
            }
            out.prefixes.push(cp.to_string());
            out.next_key = Some(cp.to_string());
            out.next_version = None;
            count += 1;
            return Scan::Seek(after_prefix(cp));
        }
        if count >= max {
            out.truncated = true;
            return Scan::Stop;
        }
        out.next_key = Some(v.key.clone());
        out.next_version = Some(v.version_id.clone());
        out.entries.push((v, latest));
        count += 1;
        Scan::Next
    })?;
    if !out.truncated {
        out.next_key = None;
        out.next_version = None;
    }
    Ok(out)
}
