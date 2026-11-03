//! Small helpers shared across modules: time formats, XML escaping,
//! S3-style URI encoding, hashing and header manipulation.

use std::fmt::Write as _;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use md5::Md5;
use percent_encoding::percent_decode_str;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const S3_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
pub const XML_DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// ISO-8601 timestamp with milliseconds, as used in S3 XML bodies.
pub fn iso8601(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// RFC 7231 date, as used in Last-Modified and similar headers.
pub fn http_date(t: &DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub fn parse_http_date(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    DateTime::parse_from_rfc2822(s)
        .ok()
        .or_else(|| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
}

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters are not representable in XML 1.0; encode them.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                let _ = write!(out, "&#x{:X};", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// URI encoding as defined by AWS Signature Version 4.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len() * 3 / 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if !encode_slash => out.push('/'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

pub fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Random alphanumeric string (used for generated access keys).
pub fn random_alnum(n: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| CHARS[(*x as usize) % CHARS.len()] as char).collect()
}

/// Insert a header, ignoring values that are not valid header bytes.
pub fn set_header(h: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(value.as_bytes())) {
        h.insert(n, v);
    }
}

pub fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Decoded query-string parameters, in original order.
#[derive(Debug, Default, Clone)]
pub struct Query {
    pub pairs: Vec<(String, String)>,
}

impl Query {
    pub fn parse(raw: Option<&str>) -> Self {
        let mut pairs = Vec::new();
        if let Some(raw) = raw {
            for part in raw.split('&').filter(|p| !p.is_empty()) {
                let (k, v) = part.split_once('=').unwrap_or((part, ""));
                pairs.push((decode(k), decode(v)));
            }
        }
        Query { pairs }
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }

    pub fn has(&self, k: &str) -> bool {
        self.pairs.iter().any(|(key, _)| key == k)
    }
}

/// Match `pattern` (supporting `*` and `?`) against `s`.
pub fn wildcard(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_sigv4() {
        assert_eq!(uri_encode("a b/c~d+e", false), "a%20b/c~d%2Be");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("ç", true), "%C3%A7");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b.txt"));
        assert!(!wildcard("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket2/a"));
        assert!(wildcard("s3:Get*", "s3:GetObject"));
        assert!(wildcard("*", ""));
        assert!(wildcard("a?c", "abc"));
    }

    #[test]
    fn escapes_xml() {
        assert_eq!(esc("<a&b>"), "&lt;a&amp;b&gt;");
    }
}
