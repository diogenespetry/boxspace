//! AWS Signature Version 4 verification and presigning.

use axum::http::{HeaderMap, Method, Uri};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};

use crate::{
    error::{Result, S3Error},
    util::{ct_eq, header, hmac, sha256_hex, uri_encode, Query},
    App,
};

pub const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MAX_SKEW_MINUTES: i64 = 15;
const AMZ_FMT: &str = "%Y%m%dT%H%M%SZ";

#[derive(Clone, Debug)]
pub struct Identity {
    pub access_key: String,
    pub root: bool,
    pub read_only: bool,
}

#[derive(Clone, Debug)]
pub struct ChunkSigner {
    pub key: Vec<u8>,
    pub datetime: String,
    pub scope: String,
    pub prev: String,
}

#[derive(Clone, Debug)]
pub enum Payload {
    Unsigned,
    Sha256(String),
    Streaming { signer: Option<ChunkSigner> },
}

#[derive(Clone, Debug)]
pub struct AuthInfo {
    pub identity: Option<Identity>,
    pub payload: Payload,
}

/// Resolve the secret and identity behind an access key.
pub fn lookup(app: &App, ak: &str) -> Result<Option<(String, Identity)>> {
    if ak == app.cfg.root_user {
        return Ok(Some((
            app.cfg.root_password.clone(),
            Identity { access_key: ak.to_string(), root: true, read_only: false },
        )));
    }
    Ok(app.store.get_key(ak)?.map(|k| {
        (k.secret_key, Identity { access_key: k.access_key, root: false, read_only: k.read_only })
    }))
}

pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, service.as_bytes());
    hmac(&k, b"aws4_request")
}

fn canonical_query(q: &Query, exclude_signature: bool) -> String {
    let mut pairs: Vec<(String, String)> = q
        .pairs
        .iter()
        .filter(|(k, _)| !(exclude_signature && k == "X-Amz-Signature"))
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

fn canonical_headers(headers: &HeaderMap, signed: &[&str]) -> Result<String> {
    let mut out = String::new();
    for name in signed {
        let values: Vec<String> = headers
            .get_all(*name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        if values.is_empty() {
            return Err(S3Error::new(
                "AccessDenied",
                403,
                format!("There were headers present in the request which were not signed: {name}"),
            ));
        }
        out.push_str(name);
        out.push(':');
        out.push_str(&values.join(","));
        out.push('\n');
    }
    Ok(out)
}

fn parse_amz_date(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, AMZ_FMT).ok().map(|d| d.and_utc())
}

fn payload_mode(v: &str, signer: Option<ChunkSigner>) -> Result<Payload> {
    Ok(match v {
        "UNSIGNED-PAYLOAD" => Payload::Unsigned,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Payload::Streaming { signer: None },
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" | "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => {
            if signer.is_none() {
                return Err(S3Error::access_denied());
            }
            Payload::Streaming { signer }
        }
        h if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => Payload::Sha256(h.to_ascii_lowercase()),
        _ => return Err(S3Error::invalid_argument("invalid x-amz-content-sha256 value")),
    })
}

pub fn authenticate(app: &App, method: &Method, uri: &Uri, headers: &HeaderMap, q: &Query) -> Result<AuthInfo> {
    if let Some(a) = header(headers, "authorization") {
        if let Some(rest) = a.strip_prefix("AWS4-HMAC-SHA256 ") {
            return header_auth(app, method, uri, headers, q, rest);
        }
        if a.starts_with("AWS ") {
            return Err(S3Error::not_implemented("Signature Version 2 is not supported; use Signature Version 4."));
        }
        return Err(S3Error::invalid_argument("Unsupported Authorization Type"));
    }
    if q.has("X-Amz-Algorithm") {
        return presigned_auth(app, method, uri, headers, q);
    }
    if q.has("AWSAccessKeyId") {
        return Err(S3Error::not_implemented("Signature Version 2 is not supported; use Signature Version 4."));
    }
    let payload = match header(headers, "x-amz-content-sha256") {
        Some(v) => payload_mode(v, None)?,
        None => Payload::Unsigned,
    };
    Ok(AuthInfo { identity: None, payload })
}

struct Scope<'a> {
    access_key: &'a str,
    date: &'a str,
    region: &'a str,
    service: &'a str,
}

fn parse_credential(c: &str) -> Result<Scope<'_>> {
    let p: Vec<&str> = c.split('/').collect();
    if p.len() != 5 || p[4] != "aws4_request" {
        return Err(S3Error::new("AuthorizationHeaderMalformed", 400, "The authorization header is malformed."));
    }
    Ok(Scope { access_key: p[0], date: p[1], region: p[2], service: p[3] })
}

fn invalid_key() -> S3Error {
    S3Error::new("InvalidAccessKeyId", 403, "The Access Key Id you provided does not exist in our records.")
}

fn header_auth(app: &App, method: &Method, uri: &Uri, headers: &HeaderMap, q: &Query, rest: &str) -> Result<AuthInfo> {
    let (mut cred, mut signed, mut sig) = (None, None, None);
    for part in rest.split(',') {
        if let Some((k, v)) = part.trim().split_once('=') {
            match k {
                "Credential" => cred = Some(v),
                "SignedHeaders" => signed = Some(v),
                "Signature" => sig = Some(v),
                _ => {}
            }
        }
    }
    let malformed = || S3Error::new("AuthorizationHeaderMalformed", 400, "The authorization header is malformed.");
    let (cred, signed, sig) = (cred.ok_or_else(malformed)?, signed.ok_or_else(malformed)?, sig.ok_or_else(malformed)?);
    let scope = parse_credential(cred)?;
    let (secret, identity) = lookup(app, scope.access_key)?.ok_or_else(invalid_key)?;

    let amz_date = match header(headers, "x-amz-date") {
        Some(d) => d.to_string(),
        None => crate::util::parse_http_date(header(headers, "date").ok_or_else(S3Error::access_denied)?)
            .ok_or_else(S3Error::access_denied)?
            .format(AMZ_FMT)
            .to_string(),
    };
    let t = parse_amz_date(&amz_date).ok_or_else(|| S3Error::access_denied().header("x-reason", "bad date"))?;
    if (Utc::now() - t).num_minutes().abs() > MAX_SKEW_MINUTES {
        return Err(S3Error::new(
            "RequestTimeTooSkewed",
            403,
            "The difference between the request time and the server's time is too large.",
        ));
    }
    if !amz_date.starts_with(scope.date) {
        return Err(S3Error::signature_mismatch());
    }
    let payload_hash = header(headers, "x-amz-content-sha256").ok_or_else(|| {
        S3Error::invalid_request("Missing required header for this request: x-amz-content-sha256")
    })?;
    let signed_list: Vec<&str> = signed.split(';').collect();
    if !signed_list.contains(&"host") {
        return Err(S3Error::access_denied());
    }
    let path = if uri.path().is_empty() { "/" } else { uri.path() };
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        path,
        canonical_query(q, false),
        canonical_headers(headers, &signed_list)?,
        signed,
        payload_hash
    );
    let scope_str = format!("{}/{}/{}/aws4_request", scope.date, scope.region, scope.service);
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope_str}\n{}", sha256_hex(canonical.as_bytes()));
    let key = signing_key(&secret, scope.date, scope.region, scope.service);
    let expected = hex::encode(hmac(&key, sts.as_bytes()));
    if !ct_eq(expected.as_bytes(), sig.as_bytes()) {
        tracing::debug!("signature mismatch; canonical request:\n{canonical}");
        return Err(S3Error::signature_mismatch());
    }
    let signer = ChunkSigner { key, datetime: amz_date, scope: scope_str, prev: expected };
    Ok(AuthInfo { identity: Some(identity), payload: payload_mode(payload_hash, Some(signer))? })
}

fn presigned_auth(app: &App, method: &Method, uri: &Uri, headers: &HeaderMap, q: &Query) -> Result<AuthInfo> {
    let missing = || S3Error::new("AuthorizationQueryParametersError", 400, "Query-string authentication requires X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders and X-Amz-Signature.");
    if q.get("X-Amz-Algorithm") != Some("AWS4-HMAC-SHA256") {
        return Err(missing());
    }
    let cred = q.get("X-Amz-Credential").ok_or_else(missing)?;
    let amz_date = q.get("X-Amz-Date").ok_or_else(missing)?;
    let expires: i64 = q.get("X-Amz-Expires").and_then(|v| v.parse().ok()).ok_or_else(missing)?;
    let signed = q.get("X-Amz-SignedHeaders").ok_or_else(missing)?;
    let sig = q.get("X-Amz-Signature").ok_or_else(missing)?;
    if !(1..=604800).contains(&expires) {
        return Err(S3Error::new("AuthorizationQueryParametersError", 400, "X-Amz-Expires must be between 1 and 604800 seconds."));
    }
    let scope = parse_credential(cred)?;
    let (secret, identity) = lookup(app, scope.access_key)?.ok_or_else(invalid_key)?;
    let t = parse_amz_date(amz_date).ok_or_else(missing)?;
    let now = Utc::now();
    if t - now > Duration::minutes(MAX_SKEW_MINUTES) {
        return Err(S3Error::new("AccessDenied", 403, "Request is not valid yet"));
    }
    if now > t + Duration::seconds(expires) {
        return Err(S3Error::new("AccessDenied", 403, "Request has expired"));
    }
    let signed_list: Vec<&str> = signed.split(';').collect();
    let payload_hash = q.get("X-Amz-Content-Sha256").unwrap_or("UNSIGNED-PAYLOAD");
    let path = if uri.path().is_empty() { "/" } else { uri.path() };
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        path,
        canonical_query(q, true),
        canonical_headers(headers, &signed_list)?,
        signed,
        payload_hash
    );
    let scope_str = format!("{}/{}/{}/aws4_request", scope.date, scope.region, scope.service);
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope_str}\n{}", sha256_hex(canonical.as_bytes()));
    let key = signing_key(&secret, scope.date, scope.region, scope.service);
    let expected = hex::encode(hmac(&key, sts.as_bytes()));
    if !ct_eq(expected.as_bytes(), sig.as_bytes()) {
        return Err(S3Error::signature_mismatch());
    }
    let payload = if payload_hash == "UNSIGNED-PAYLOAD" { Payload::Unsigned } else { payload_mode(payload_hash, None)? };
    Ok(AuthInfo { identity: Some(identity), payload })
}

/// Build a presigned GET URL for `bucket/key`.
pub fn presign_get(server_url: &str, region: &str, ak: &str, sk: &str, bucket: &str, key: &str, expires: u64) -> String {
    let host = server_url.split_once("://").map(|(_, h)| h).unwrap_or(server_url).trim_end_matches('/');
    let now = Utc::now();
    let amz_date = now.format(AMZ_FMT).to_string();
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let path = format!("/{}/{}", uri_encode(bucket, true), uri_encode(key, false));
    let q = Query {
        pairs: vec![
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            ("X-Amz-Credential".into(), format!("{ak}/{scope}")),
            ("X-Amz-Date".into(), amz_date.clone()),
            ("X-Amz-Expires".into(), expires.to_string()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
        ],
    };
    let cq = canonical_query(&q, false);
    let canonical = format!("GET\n{path}\n{cq}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let sig = hex::encode(hmac(&signing_key(sk, date, region, "s3"), sts.as_bytes()));
    format!("{}{path}?{cq}&X-Amz-Signature={sig}", server_url.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example from the AWS SigV4 documentation ("GET Object" example).
    #[test]
    fn aws_documented_example() {
        let mut h = HeaderMap::new();
        h.insert("host", "examplebucket.s3.amazonaws.com".parse().unwrap());
        h.insert("range", "bytes=0-9".parse().unwrap());
        h.insert("x-amz-content-sha256", EMPTY_SHA.parse().unwrap());
        h.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let signed = ["host", "range", "x-amz-content-sha256", "x-amz-date"];
        let canonical = format!(
            "GET\n/test.txt\n\n{}\n{}\n{}",
            canonical_headers(&h, &signed).unwrap(),
            signed.join(";"),
            EMPTY_SHA
        );
        let sts = format!(
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let key = signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3");
        assert_eq!(
            hex::encode(hmac(&key, sts.as_bytes())),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }
}
