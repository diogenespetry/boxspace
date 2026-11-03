//! S3 REST API: request routing and operation handlers.

use std::{collections::BTreeMap, io, sync::Arc};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{request::Parts, HeaderMap, Method, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use bytes::Bytes;
use chrono::Utc;
use futures::{Stream, TryStreamExt};
use serde::{de::DeserializeOwned, Deserialize};

use crate::{
    auth::{self, AuthInfo, Payload},
    blob::{self, BlobWriter},
    body, cors,
    error::{Result, S3Error},
    lifecycle, listing,
    ops::{self, PutOpts, DEFAULT_CONTENT_TYPE},
    policy,
    storage::{ObjectVersion, PartMeta, UploadMeta, NULL_VERSION},
    util::{decode, esc, header, http_date, iso8601, md5_bytes, parse_http_date, random_hex, set_header, uri_encode, Query, S3_NS, XML_DECL},
    App,
};

const MAX_XML: usize = 1 << 20;
const MIN_PART: u64 = 5 * 1024 * 1024;
const OWNER_ID: &str = "boxspace";

type Target = (Option<String>, Option<String>);

// ---------------------------------------------------------------- entry ----

pub async fn handle(State(app): State<Arc<App>>, req: Request) -> Response {
    let rid = random_hex(8).to_uppercase();
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let head = method == Method::HEAD;
    let target = target(&app, &parts);
    let origin = header(&parts.headers, "origin").map(str::to_string);
    tracing::debug!("{} {}", method, parts.uri);
    let mut resp = match route(&app, parts, body, &target).await {
        Ok(r) => r,
        Err(e) => {
            if e.status.is_server_error() {
                tracing::warn!("{} {:?}: {} {}", method, target, e.code, e.message);
            }
            e.to_response(head, &rid)
        }
    };
    if method != Method::OPTIONS
        && let (Some(o), Some(b)) = (origin, &target.0)
    {
        cors::apply(&app, b, &o, method.as_str(), &mut resp);
    }
    let h = resp.headers_mut();
    set_header(h, "x-amz-request-id", &rid);
    set_header(h, "server", "BoxSpace");
    resp
}

fn target(app: &App, parts: &Parts) -> Target {
    let path = parts.uri.path();
    if let (Some(domain), Some(host)) = (&app.cfg.domain, header(&parts.headers, "host")) {
        let host = host.split(':').next().unwrap_or(host);
        if let Some(b) = host.strip_suffix(&format!(".{domain}")) {
            let key = decode(path.trim_start_matches('/'));
            return (Some(b.to_string()), (!key.is_empty()).then_some(key));
        }
    }
    let p = path.strip_prefix('/').unwrap_or(path);
    if p.is_empty() {
        return (None, None);
    }
    match p.split_once('/') {
        Some((b, k)) => {
            let k = decode(k);
            (Some(decode(b)), (!k.is_empty()).then_some(k))
        }
        None => (Some(decode(p)), None),
    }
}

struct Ctx<'a> {
    app: &'a Arc<App>,
    method: Method,
    headers: HeaderMap,
    q: Query,
    auth: AuthInfo,
}

async fn route(app: &Arc<App>, parts: Parts, body: Body, target: &Target) -> Result<Response> {
    let q = Query::parse(parts.uri.query());
    if parts.method == Method::OPTIONS {
        return cors::preflight(app, target.0.as_deref(), &parts.headers);
    }
    let auth = auth::authenticate(app, &parts.method, &parts.uri, &parts.headers, &q)?;
    let ctx = Ctx { app, method: parts.method, headers: parts.headers, q, auth };
    match target {
        (None, _) if ctx.method == Method::GET => list_buckets(&ctx),
        (None, _) => Err(S3Error::method_not_allowed()),
        (Some(b), None) => bucket_op(&ctx, b, body).await,
        (Some(b), Some(k)) => object_op(&ctx, b, k, body).await,
    }
}

impl Ctx<'_> {
    fn h(&self, n: &str) -> Option<&str> {
        header(&self.headers, n)
    }

    fn is_write(&self) -> bool {
        !(self.method == Method::GET || self.method == Method::HEAD)
    }

    /// Authorize `action`. Access keys act as the owner (read-only keys can
    /// only read); anonymous requests need a bucket policy allowing it.
    fn authorize(&self, action: &str, bucket: &str, key: Option<&str>) -> Result<()> {
        match &self.auth.identity {
            Some(id) if self.is_write() && id.read_only => Err(S3Error::access_denied()),
            Some(_) => Ok(()),
            None => {
                let bm = self.app.store.get_bucket(bucket)?.ok_or_else(S3Error::access_denied)?;
                let res = match key {
                    Some(k) => format!("arn:aws:s3:::{bucket}/{k}"),
                    None => format!("arn:aws:s3:::{bucket}"),
                };
                if bm.policy.as_deref().is_some_and(|p| policy::allows_anonymous(p, action, &res)) {
                    Ok(())
                } else {
                    Err(S3Error::access_denied())
                }
            }
        }
    }

    /// Bucket configuration is only changeable by authenticated owners.
    fn authorize_owner(&self, bucket: &str) -> Result<()> {
        match &self.auth.identity {
            Some(id) if !(self.is_write() && id.read_only) => {
                self.app.store.bucket(bucket)?;
                Ok(())
            }
            _ => Err(S3Error::access_denied()),
        }
    }

    async fn read_body(&self, body: Body) -> Result<Vec<u8>> {
        body::read_all(stream(body), &self.auth.payload, MAX_XML).await
    }
}

fn stream(body: Body) -> impl Stream<Item = io::Result<Bytes>> + Unpin {
    body.into_data_stream().map_err(io::Error::other)
}

// ------------------------------------------------------------ helpers ----

fn xml(body: String) -> Result<Response> {
    let mut r = Response::new(Body::from(format!("{XML_DECL}{body}")));
    set_header(r.headers_mut(), "content-type", "application/xml");
    Ok(r)
}

fn status(code: u16) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
    r
}

fn owner() -> String {
    format!("<Owner><ID>{OWNER_ID}</ID><DisplayName>{OWNER_ID}</DisplayName></Owner>")
}

fn acl_xml() -> String {
    format!(
        "<AccessControlPolicy xmlns=\"{S3_NS}\">{}<AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>{OWNER_ID}</ID><DisplayName>{OWNER_ID}</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>",
        owner()
    )
}

fn parse_xml<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    let s = std::str::from_utf8(b).map_err(|_| S3Error::malformed_xml())?;
    quick_xml::de::from_str(s).map_err(|e| {
        tracing::debug!("xml parse error: {e}");
        S3Error::malformed_xml()
    })
}

fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}

fn norm_etag(e: &str) -> String {
    e.trim().trim_matches('"').to_ascii_lowercase()
}

fn etag_matches(list: &str, etag: &str) -> bool {
    list.split(',').any(|t| {
        let t = t.trim().trim_start_matches("W/").trim_matches('"');
        t == "*" || t == etag
    })
}

fn enc(url: bool, s: &str) -> String {
    if url { esc(&uri_encode(s, false)) } else { esc(s) }
}

fn opt_elem(name: &str, v: Option<&str>, url: bool) -> String {
    v.map(|v| format!("<{name}>{}</{name}>", enc(url, v))).unwrap_or_default()
}

pub fn valid_bucket_name(n: &str) -> bool {
    let b = n.as_bytes();
    if !(3..=63).contains(&b.len()) {
        return false;
    }
    if !b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-') {
        return false;
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !alnum(b[0]) || !alnum(b[b.len() - 1]) || n.contains("..") || n.contains(".-") || n.contains("-.") {
        return false;
    }
    // Not formatted like an IPv4 address.
    !(n.split('.').count() == 4 && n.split('.').all(|p| p.parse::<u8>().is_ok()))
}

fn check_acl(ctx: &Ctx<'_>) -> Result<()> {
    if let Some(acl) = ctx.h("x-amz-acl")
        && !matches!(acl, "private" | "bucket-owner-full-control" | "bucket-owner-read")
    {
        return Err(S3Error::not_implemented(
            "Only private ACLs are supported. Use a bucket policy to grant public access.",
        ));
    }
    if ctx.headers.keys().any(|k| k.as_str().starts_with("x-amz-grant-")) {
        return Err(S3Error::not_implemented("ACL grants are not supported. Use a bucket policy."));
    }
    Ok(())
}

fn reject_object_lock(ctx: &Ctx<'_>) -> Result<()> {
    if ctx.headers.keys().any(|k| k.as_str().starts_with("x-amz-object-lock-")) {
        return Err(S3Error::not_implemented("Object Lock is not supported."));
    }
    Ok(())
}

// ---- tags ----

#[derive(Deserialize)]
struct TaggingXml {
    #[serde(rename = "TagSet", default)]
    set: TagSetXml,
}
#[derive(Deserialize, Default)]
struct TagSetXml {
    #[serde(rename = "Tag", default)]
    tags: Vec<TagXml>,
}
#[derive(Deserialize)]
struct TagXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

fn validate_tags(tags: &[(String, String)], max: usize) -> Result<()> {
    let bad = |m: &str| S3Error::new("InvalidTag", 400, m.to_string());
    if tags.len() > max {
        return Err(bad(&format!("Object tags cannot be greater than {max}")));
    }
    let mut seen = std::collections::HashSet::new();
    for (k, v) in tags {
        if k.is_empty() || k.chars().count() > 128 {
            return Err(bad("The TagKey you have provided is invalid"));
        }
        if v.chars().count() > 256 {
            return Err(bad("The TagValue you have provided is invalid"));
        }
        if !seen.insert(k) {
            return Err(bad("Cannot provide multiple Tags with the same key"));
        }
    }
    Ok(())
}

fn parse_tagging(b: &[u8], max: usize) -> Result<Vec<(String, String)>> {
    let t: TaggingXml = parse_xml(b)?;
    let tags: Vec<(String, String)> = t.set.tags.into_iter().map(|t| (t.key, t.value)).collect();
    validate_tags(&tags, max)?;
    Ok(tags)
}

fn parse_tag_header(s: &str) -> Result<Vec<(String, String)>> {
    let d = |x: &str| decode(&x.replace('+', " "));
    let tags: Vec<(String, String)> = s
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (d(k), d(v))
        })
        .collect();
    validate_tags(&tags, 10)?;
    Ok(tags)
}

fn tagging_xml(tags: &[(String, String)]) -> String {
    let inner: String = tags
        .iter()
        .map(|(k, v)| format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", esc(k), esc(v)))
        .collect();
    format!("<Tagging xmlns=\"{S3_NS}\"><TagSet>{inner}</TagSet></Tagging>")
}

// ---- object metadata from request headers ----

fn sse_header(ctx: &Ctx<'_>) -> Result<Option<bool>> {
    if ctx.h("x-amz-server-side-encryption-customer-algorithm").is_some() {
        return Err(S3Error::not_implemented("SSE-C is not supported. Use SSE-S3 (AES256)."));
    }
    match ctx.h("x-amz-server-side-encryption") {
        None => Ok(None),
        Some("AES256") => Ok(Some(true)),
        Some(v) if v.starts_with("aws:kms") => Err(S3Error::not_implemented("SSE-KMS is not supported. Use SSE-S3 (AES256).")),
        Some(_) => Err(S3Error::invalid_argument("The encryption method specified is not supported")),
    }
}

fn put_opts(ctx: &Ctx<'_>) -> Result<PutOpts> {
    let mut o = PutOpts { content_type: ctx.h("content-type").map(str::to_string), ..Default::default() };
    let mut meta_size = 0usize;
    for (name, value) in ctx.headers.iter() {
        if let Some(m) = name.as_str().strip_prefix("x-amz-meta-") {
            let v = String::from_utf8_lossy(value.as_bytes()).into_owned();
            meta_size += m.len() + v.len();
            o.meta.insert(m.to_string(), v);
        }
    }
    if meta_size > 2048 {
        return Err(S3Error::new("MetadataTooLarge", 400, "Your metadata headers exceed the maximum allowed metadata size."));
    }
    for n in ["cache-control", "content-disposition", "content-language", "expires"] {
        if let Some(v) = ctx.h(n) {
            o.headers.insert(n.to_string(), v.to_string());
        }
    }
    if let Some(ce) = ctx.h("content-encoding") {
        let v: Vec<&str> = ce.split(',').map(str::trim).filter(|t| !t.is_empty() && *t != "aws-chunked").collect();
        if !v.is_empty() {
            o.headers.insert("content-encoding".into(), v.join(", "));
        }
    }
    if let Some(t) = ctx.h("x-amz-tagging") {
        o.tags = parse_tag_header(t)?;
    }
    o.encrypt = sse_header(ctx)?;
    o.content_md5 = ctx.h("content-md5").map(str::to_string);
    if !matches!(ctx.auth.payload, Payload::Streaming { .. }) {
        o.crc32 = ctx.h("x-amz-checksum-crc32").map(str::to_string);
    }
    o.decoded_len = ctx.h("x-amz-decoded-content-length").and_then(|v| v.parse().ok());
    Ok(o)
}

fn object_headers(h: &mut HeaderMap, v: &ObjectVersion) {
    set_header(h, "etag", &quoted(&v.etag));
    set_header(h, "last-modified", &http_date(&v.last_modified));
    set_header(h, "content-type", if v.content_type.is_empty() { DEFAULT_CONTENT_TYPE } else { &v.content_type });
    set_header(h, "accept-ranges", "bytes");
    if v.version_id != NULL_VERSION {
        set_header(h, "x-amz-version-id", &v.version_id);
    }
    for (k, val) in &v.meta {
        set_header(h, &format!("x-amz-meta-{k}"), val);
    }
    for (k, val) in &v.headers {
        set_header(h, k, val);
    }
    if v.encrypted() {
        set_header(h, "x-amz-server-side-encryption", "AES256");
    }
    if !v.tags.is_empty() {
        set_header(h, "x-amz-tagging-count", &v.tags.len().to_string());
    }
    if let Some(p) = v.parts {
        set_header(h, "x-amz-mp-parts-count", &p.to_string());
    }
}

fn parse_range(r: &str, size: u64) -> Result<Option<(u64, u64)>> {
    let Some(spec) = r.trim().strip_prefix("bytes=") else { return Ok(None) };
    if spec.contains(',') {
        return Ok(None); // multiple ranges: serve the whole object
    }
    let (a, b) = spec.split_once('-').ok_or_else(S3Error::invalid_range)?;
    let (a, b) = (a.trim(), b.trim());
    let range = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| S3Error::invalid_range())?;
        if n == 0 || size == 0 {
            return Err(S3Error::invalid_range().header("content-range", format!("bytes */{size}")));
        }
        (size - n.min(size), size - 1)
    } else {
        let s: u64 = a.parse().map_err(|_| S3Error::invalid_range())?;
        let e: u64 = if b.is_empty() { size.saturating_sub(1) } else { b.parse().map_err(|_| S3Error::invalid_range())? };
        if s >= size || e < s {
            return Err(S3Error::invalid_range().header("content-range", format!("bytes */{size}")));
        }
        (s, e.min(size - 1))
    };
    Ok(Some(range))
}

fn check_conditions(h: &HeaderMap, v: &ObjectVersion) -> Result<()> {
    let lm = v.last_modified.timestamp();
    let validators = |e: S3Error| e.header("etag", quoted(&v.etag)).header("last-modified", http_date(&v.last_modified));
    if let Some(im) = header(h, "if-match") {
        if !etag_matches(im, &v.etag) {
            return Err(S3Error::precondition_failed());
        }
    } else if let Some(t) = header(h, "if-unmodified-since").and_then(parse_http_date)
        && lm > t.timestamp()
    {
        return Err(S3Error::precondition_failed());
    }
    if let Some(inm) = header(h, "if-none-match") {
        if etag_matches(inm, &v.etag) {
            return Err(validators(S3Error::not_modified()));
        }
    } else if let Some(t) = header(h, "if-modified-since").and_then(parse_http_date)
        && lm <= t.timestamp()
    {
        return Err(validators(S3Error::not_modified()));
    }
    Ok(())
}

fn check_copy_conditions(h: &HeaderMap, v: &ObjectVersion) -> Result<()> {
    let lm = v.last_modified.timestamp();
    if let Some(m) = header(h, "x-amz-copy-source-if-match")
        && !etag_matches(m, &v.etag)
    {
        return Err(S3Error::precondition_failed());
    }
    if let Some(m) = header(h, "x-amz-copy-source-if-none-match")
        && etag_matches(m, &v.etag)
    {
        return Err(S3Error::precondition_failed());
    }
    if let Some(t) = header(h, "x-amz-copy-source-if-unmodified-since").and_then(parse_http_date)
        && lm > t.timestamp()
    {
        return Err(S3Error::precondition_failed());
    }
    if let Some(t) = header(h, "x-amz-copy-source-if-modified-since").and_then(parse_http_date)
        && lm <= t.timestamp()
    {
        return Err(S3Error::precondition_failed());
    }
    Ok(())
}

/// Resolve a readable version, mapping delete markers to S3's errors.
fn lookup_version(ctx: &Ctx<'_>, b: &str, k: &str, vid: Option<&str>) -> Result<ObjectVersion> {
    match ctx.app.store.get_version(b, k, vid)? {
        None if vid.is_some() => Err(S3Error::no_such_version()),
        None => Err(S3Error::no_such_key(k)),
        Some(v) if v.delete_marker => {
            let base = if vid.is_some() { S3Error::method_not_allowed() } else { S3Error::no_such_key(k) };
            Err(base
                .header("x-amz-delete-marker", "true")
                .header("x-amz-version-id", v.version_id.clone())
                .header("last-modified", http_date(&v.last_modified)))
        }
        Some(v) => Ok(v),
    }
}

/// Parse x-amz-copy-source into (bucket, key, version).
fn parse_copy_source(raw: &str) -> Result<(String, String, Option<String>)> {
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    let path = decode(path.trim_start_matches('/'));
    let (b, k) = path
        .split_once('/')
        .filter(|(b, k)| !b.is_empty() && !k.is_empty())
        .ok_or_else(|| S3Error::invalid_argument("Copy Source must mention the source bucket and key: sourcebucket/sourcekey"))?;
    let vid = query.and_then(|q| q.strip_prefix("versionId=")).map(decode).filter(|v| !v.is_empty());
    Ok((b.to_string(), k.to_string(), vid))
}

fn copy_source_version(ctx: &Ctx<'_>, sb: &str, sk: &str, svid: Option<&str>) -> Result<ObjectVersion> {
    ctx.authorize(if svid.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" }, sb, Some(sk))?;
    ctx.app.store.bucket(sb)?;
    match ctx.app.store.get_version(sb, sk, svid)? {
        None if svid.is_some() => Err(S3Error::no_such_version()),
        None => Err(S3Error::no_such_key(sk)),
        Some(v) if v.delete_marker && svid.is_some() => Err(S3Error::invalid_request(
            "The source of a copy request may not specifically refer to a delete marker by version id.",
        )),
        Some(v) if v.delete_marker => Err(S3Error::no_such_key(sk)),
        Some(v) => {
            check_copy_conditions(&ctx.headers, &v)?;
            Ok(v)
        }
    }
}

fn version_header(r: &mut Response, vid: &str) {
    if vid != NULL_VERSION {
        set_header(r.headers_mut(), "x-amz-version-id", vid);
    }
}

// ------------------------------------------------------------ service ----

fn list_buckets(ctx: &Ctx<'_>) -> Result<Response> {
    if ctx.auth.identity.is_none() {
        return Err(S3Error::access_denied());
    }
    let mut buckets = ctx.app.store.list_buckets()?;
    buckets.sort_by(|a, b| a.name.cmp(&b.name));
    let items: String = buckets
        .iter()
        .map(|b| format!("<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>", esc(&b.name), iso8601(&b.created)))
        .collect();
    xml(format!("<ListAllMyBucketsResult xmlns=\"{S3_NS}\">{}<Buckets>{items}</Buckets></ListAllMyBucketsResult>", owner()))
}

// ------------------------------------------------------------- bucket ----

const UNSUPPORTED_BUCKET: &[&str] = &[
    "website", "replication", "logging", "accelerate", "requestPayment", "analytics", "metrics", "inventory",
    "intelligent-tiering", "ownershipControls", "publicAccessBlock", "policyStatus",
];

async fn bucket_op(ctx: &Ctx<'_>, b: &str, body: Body) -> Result<Response> {
    match ctx.method {
        Method::GET => bucket_get(ctx, b),
        Method::HEAD => {
            ctx.authorize("s3:ListBucket", b, None)?;
            ctx.app.store.bucket(b)?;
            let mut r = status(200);
            set_header(r.headers_mut(), "x-amz-bucket-region", &ctx.app.cfg.region);
            Ok(r)
        }
        Method::PUT => bucket_put(ctx, b, body).await,
        Method::DELETE => bucket_delete(ctx, b).await,
        Method::POST if ctx.q.has("delete") => delete_objects(ctx, b, body).await,
        Method::POST => Err(S3Error::not_implemented("POST object uploads (browser forms) are not supported.")),
        _ => Err(S3Error::method_not_allowed()),
    }
}

fn bucket_get(ctx: &Ctx<'_>, b: &str) -> Result<Response> {
    let q = &ctx.q;
    let s = &ctx.app.store;
    if q.has("location") {
        ctx.authorize("s3:GetBucketLocation", b, None)?;
        s.bucket(b)?;
        let r = &ctx.app.cfg.region;
        let v = if r == "us-east-1" { "" } else { r.as_str() };
        return xml(format!("<LocationConstraint xmlns=\"{S3_NS}\">{}</LocationConstraint>", esc(v)));
    }
    if q.has("versioning") {
        ctx.authorize("s3:GetBucketVersioning", b, None)?;
        let bm = s.bucket(b)?;
        let st = bm.versioning.map(|v| format!("<Status>{v}</Status>")).unwrap_or_default();
        return xml(format!("<VersioningConfiguration xmlns=\"{S3_NS}\">{st}</VersioningConfiguration>"));
    }
    if q.has("policy") {
        ctx.authorize("s3:GetBucketPolicy", b, None)?;
        let bm = s.bucket(b)?;
        let p = bm.policy.ok_or_else(|| S3Error::new("NoSuchBucketPolicy", 404, "The bucket policy does not exist").resource(b))?;
        let mut r = Response::new(Body::from(p));
        set_header(r.headers_mut(), "content-type", "application/json");
        return Ok(r);
    }
    if q.has("lifecycle") {
        ctx.authorize("s3:GetLifecycleConfiguration", b, None)?;
        let bm = s.bucket(b)?;
        if bm.lifecycle.is_empty() {
            return Err(S3Error::new("NoSuchLifecycleConfiguration", 404, "The lifecycle configuration does not exist").resource(b));
        }
        return xml(lifecycle::to_xml(&bm.lifecycle));
    }
    if q.has("cors") {
        ctx.authorize("s3:GetBucketCORS", b, None)?;
        let bm = s.bucket(b)?;
        if bm.cors.is_empty() {
            return Err(S3Error::new("NoSuchCORSConfiguration", 404, "The CORS configuration does not exist").resource(b));
        }
        return xml(cors::to_xml(&bm.cors));
    }
    if q.has("tagging") {
        ctx.authorize("s3:GetBucketTagging", b, None)?;
        let bm = s.bucket(b)?;
        let tags = bm.tags.ok_or_else(|| S3Error::new("NoSuchTagSet", 404, "The TagSet does not exist").resource(b))?;
        return xml(tagging_xml(&tags));
    }
    if q.has("encryption") {
        ctx.authorize("s3:GetEncryptionConfiguration", b, None)?;
        let bm = s.bucket(b)?;
        if !bm.encryption {
            return Err(S3Error::new(
                "ServerSideEncryptionConfigurationNotFoundError",
                404,
                "The server side encryption configuration was not found",
            )
            .resource(b));
        }
        return xml(format!(
            "<ServerSideEncryptionConfiguration xmlns=\"{S3_NS}\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
        ));
    }
    if q.has("acl") {
        ctx.authorize("s3:GetBucketAcl", b, None)?;
        s.bucket(b)?;
        return xml(acl_xml());
    }
    if q.has("uploads") {
        return list_uploads(ctx, b);
    }
    if q.has("versions") {
        return list_versions(ctx, b);
    }
    if q.has("object-lock") {
        ctx.authorize("s3:GetBucketObjectLockConfiguration", b, None)?;
        s.bucket(b)?;
        return Err(S3Error::new("ObjectLockConfigurationNotFoundError", 404, "Object Lock configuration does not exist for this bucket").resource(b));
    }
    if q.has("notification") {
        ctx.authorize("s3:GetBucketNotification", b, None)?;
        s.bucket(b)?;
        return xml(format!("<NotificationConfiguration xmlns=\"{S3_NS}\"></NotificationConfiguration>"));
    }
    if let Some(k) = UNSUPPORTED_BUCKET.iter().find(|k| q.has(k)) {
        return Err(S3Error::not_implemented(format!("The bucket subresource '{k}' is not supported.")));
    }
    list_objects(ctx, b)
}

fn max_keys(q: &Query, name: &str) -> Result<usize> {
    match q.get(name) {
        None => Ok(1000),
        Some(v) => v
            .parse::<i64>()
            .ok()
            .filter(|n| *n >= 0)
            .map(|n| n.min(1000) as usize)
            .ok_or_else(|| S3Error::invalid_argument(format!("Provided {name} not an integer or within integer range"))),
    }
}

fn encoding_url(q: &Query) -> Result<bool> {
    match q.get("encoding-type") {
        None => Ok(false),
        Some("url") => Ok(true),
        Some(_) => Err(S3Error::invalid_argument("Invalid Encoding Method specified in Request")),
    }
}

fn contents_xml(v: &ObjectVersion, url: bool, with_owner: bool) -> String {
    format!(
        "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size>{}<StorageClass>STANDARD</StorageClass></Contents>",
        enc(url, &v.key),
        iso8601(&v.last_modified),
        esc(&quoted(&v.etag)),
        v.size,
        if with_owner { owner() } else { String::new() }
    )
}

fn prefixes_xml(prefixes: &[String], url: bool) -> String {
    prefixes.iter().map(|p| format!("<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", enc(url, p))).collect()
}

fn list_objects(ctx: &Ctx<'_>, b: &str) -> Result<Response> {
    ctx.authorize("s3:ListBucket", b, None)?;
    ctx.app.store.bucket(b)?;
    let q = &ctx.q;
    let v2 = q.get("list-type") == Some("2");
    let prefix = q.get("prefix").unwrap_or("");
    let delim = q.get("delimiter").filter(|d| !d.is_empty());
    let max = max_keys(q, "max-keys")?;
    let url = encoding_url(q)?;
    let enc_type = if url { "<EncodingType>url</EncodingType>" } else { "" };

    if !v2 {
        let marker = q.get("marker").unwrap_or("");
        let out = listing::list_current(&ctx.app.store, b, prefix, delim, marker, max)?;
        let contents: String = out.contents.iter().map(|v| contents_xml(v, url, true)).collect();
        return xml(format!(
            "<ListBucketResult xmlns=\"{S3_NS}\"><Name>{}</Name><Prefix>{}</Prefix><Marker>{}</Marker><MaxKeys>{max}</MaxKeys>{}<IsTruncated>{}</IsTruncated>{}{contents}{}{enc_type}</ListBucketResult>",
            esc(b),
            enc(url, prefix),
            enc(url, marker),
            opt_elem("Delimiter", delim, url),
            out.truncated,
            opt_elem("NextMarker", out.next.as_deref(), url),
            prefixes_xml(&out.prefixes, url),
        ));
    }

    let token = q.get("continuation-token");
    let start_after = q.get("start-after").unwrap_or("");
    let marker = match token {
        Some(t) => String::from_utf8(B64URL.decode(t).map_err(|_| S3Error::invalid_argument("The continuation token provided is incorrect"))?)
            .map_err(|_| S3Error::invalid_argument("The continuation token provided is incorrect"))?,
        None => start_after.to_string(),
    };
    let fetch_owner = q.get("fetch-owner") == Some("true");
    let out = listing::list_current(&ctx.app.store, b, prefix, delim, &marker, max)?;
    let contents: String = out.contents.iter().map(|v| contents_xml(v, url, fetch_owner)).collect();
    let next = out.next.as_ref().map(|n| B64URL.encode(n));
    xml(format!(
        "<ListBucketResult xmlns=\"{S3_NS}\"><Name>{}</Name><Prefix>{}</Prefix>{}{}<KeyCount>{}</KeyCount><MaxKeys>{max}</MaxKeys>{}<IsTruncated>{}</IsTruncated>{}{contents}{}{enc_type}</ListBucketResult>",
        esc(b),
        enc(url, prefix),
        token.map(|t| format!("<ContinuationToken>{}</ContinuationToken>", esc(t))).unwrap_or_default(),
        if start_after.is_empty() { String::new() } else { format!("<StartAfter>{}</StartAfter>", enc(url, start_after)) },
        out.contents.len() + out.prefixes.len(),
        opt_elem("Delimiter", delim, url),
        out.truncated,
        next.map(|n| format!("<NextContinuationToken>{n}</NextContinuationToken>")).unwrap_or_default(),
        prefixes_xml(&out.prefixes, url),
    ))
}

fn list_versions(ctx: &Ctx<'_>, b: &str) -> Result<Response> {
    ctx.authorize("s3:ListBucketVersions", b, None)?;
    ctx.app.store.bucket(b)?;
    let q = &ctx.q;
    let prefix = q.get("prefix").unwrap_or("");
    let delim = q.get("delimiter").filter(|d| !d.is_empty());
    let key_marker = q.get("key-marker").unwrap_or("");
    let vid_marker = q.get("version-id-marker").unwrap_or("");
    let max = max_keys(q, "max-keys")?;
    let url = encoding_url(q)?;
    let out = listing::list_versions(&ctx.app.store, b, prefix, delim, key_marker, vid_marker, max)?;
    let mut items = String::new();
    for (v, latest) in &out.entries {
        if v.delete_marker {
            items.push_str(&format!(
                "<DeleteMarker><Key>{}</Key><VersionId>{}</VersionId><IsLatest>{latest}</IsLatest><LastModified>{}</LastModified>{}</DeleteMarker>",
                enc(url, &v.key),
                esc(&v.version_id),
                iso8601(&v.last_modified),
                owner()
            ));
        } else {
            items.push_str(&format!(
                "<Version><Key>{}</Key><VersionId>{}</VersionId><IsLatest>{latest}</IsLatest><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size>{}<StorageClass>STANDARD</StorageClass></Version>",
                enc(url, &v.key),
                esc(&v.version_id),
                iso8601(&v.last_modified),
                esc(&quoted(&v.etag)),
                v.size,
                owner()
            ));
        }
    }
    xml(format!(
        "<ListVersionsResult xmlns=\"{S3_NS}\"><Name>{}</Name><Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><VersionIdMarker>{}</VersionIdMarker><MaxKeys>{max}</MaxKeys>{}<IsTruncated>{}</IsTruncated>{}{}{items}{}{}</ListVersionsResult>",
        esc(b),
        enc(url, prefix),
        enc(url, key_marker),
        esc(vid_marker),
        opt_elem("Delimiter", delim, url),
        out.truncated,
        opt_elem("NextKeyMarker", out.next_key.as_deref(), url),
        opt_elem("NextVersionIdMarker", out.next_version.as_deref(), false),
        prefixes_xml(&out.prefixes, url),
        if url { "<EncodingType>url</EncodingType>" } else { "" },
    ))
}

fn list_uploads(ctx: &Ctx<'_>, b: &str) -> Result<Response> {
    ctx.authorize("s3:ListBucketMultipartUploads", b, None)?;
    ctx.app.store.bucket(b)?;
    let q = &ctx.q;
    let prefix = q.get("prefix").unwrap_or("");
    let key_marker = q.get("key-marker").unwrap_or("");
    let id_marker = q.get("upload-id-marker").unwrap_or("");
    let max = max_keys(q, "max-uploads")?;
    let url = encoding_url(q)?;
    let all: Vec<UploadMeta> = ctx
        .app
        .store
        .list_uploads(b)?
        .into_iter()
        .filter(|u| u.key.starts_with(prefix))
        .filter(|u| key_marker.is_empty() || u.key.as_str() > key_marker || (u.key == key_marker && !id_marker.is_empty() && u.upload_id.as_str() > id_marker))
        .collect();
    let truncated = all.len() > max;
    let page = &all[..all.len().min(max)];
    let items: String = page
        .iter()
        .map(|u| {
            format!(
                "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiator><ID>{OWNER_ID}</ID><DisplayName>{OWNER_ID}</DisplayName></Initiator>{}<StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
                enc(url, &u.key),
                esc(&u.upload_id),
                owner(),
                iso8601(&u.initiated)
            )
        })
        .collect();
    let (nk, nu) = match (truncated, page.last()) {
        (true, Some(u)) => (
            format!("<NextKeyMarker>{}</NextKeyMarker>", enc(url, &u.key)),
            format!("<NextUploadIdMarker>{}</NextUploadIdMarker>", esc(&u.upload_id)),
        ),
        _ => (String::new(), String::new()),
    };
    xml(format!(
        "<ListMultipartUploadsResult xmlns=\"{S3_NS}\"><Bucket>{}</Bucket><KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker>{nk}{nu}<Prefix>{}</Prefix><MaxUploads>{max}</MaxUploads><IsTruncated>{truncated}</IsTruncated>{items}{}</ListMultipartUploadsResult>",
        esc(b),
        enc(url, key_marker),
        esc(id_marker),
        enc(url, prefix),
        if url { "<EncodingType>url</EncodingType>" } else { "" },
    ))
}

#[derive(Deserialize)]
struct VersioningXml {
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "MfaDelete")]
    mfa_delete: Option<String>,
}

#[derive(Deserialize)]
struct SseConfigXml {
    #[serde(rename = "Rule", default)]
    rules: Vec<SseRuleXml>,
}
#[derive(Deserialize)]
struct SseRuleXml {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    default: Option<SseDefaultXml>,
}
#[derive(Deserialize)]
struct SseDefaultXml {
    #[serde(rename = "SSEAlgorithm")]
    algorithm: String,
}

async fn bucket_put(ctx: &Ctx<'_>, b: &str, body: Body) -> Result<Response> {
    let q = &ctx.q;
    let s = &ctx.app.store;
    if q.has("versioning") {
        ctx.authorize_owner(b)?;
        let v: VersioningXml = parse_xml(&ctx.read_body(body).await?)?;
        if v.mfa_delete.as_deref() == Some("Enabled") {
            return Err(S3Error::not_implemented("MFA Delete is not supported."));
        }
        let st = match v.status.as_deref() {
            Some(s @ ("Enabled" | "Suspended")) => s.to_string(),
            _ => return Err(S3Error::new("IllegalVersioningConfigurationException", 400, "The Versioning element must be specified")),
        };
        s.update_bucket(b, |m| {
            m.versioning = Some(st);
            Ok(())
        })?;
        return Ok(status(200));
    }
    if q.has("policy") {
        ctx.authorize_owner(b)?;
        let raw = ctx.read_body(body).await?;
        let text = String::from_utf8(raw).map_err(|_| S3Error::new("MalformedPolicy", 400, "Policy is not valid UTF-8"))?;
        policy::validate(b, &text).map_err(|m| S3Error::new("MalformedPolicy", 400, m))?;
        s.update_bucket(b, |m| {
            m.policy = Some(text);
            Ok(())
        })?;
        return Ok(status(204));
    }
    if q.has("lifecycle") {
        ctx.authorize_owner(b)?;
        let rules = lifecycle::parse(&ctx.read_body(body).await?)?;
        s.update_bucket(b, |m| {
            m.lifecycle = rules;
            Ok(())
        })?;
        return Ok(status(200));
    }
    if q.has("cors") {
        ctx.authorize_owner(b)?;
        let rules = cors::parse(&ctx.read_body(body).await?)?;
        s.update_bucket(b, |m| {
            m.cors = rules;
            Ok(())
        })?;
        return Ok(status(200));
    }
    if q.has("tagging") {
        ctx.authorize_owner(b)?;
        let tags = parse_tagging(&ctx.read_body(body).await?, 50)?;
        s.update_bucket(b, |m| {
            m.tags = Some(tags);
            Ok(())
        })?;
        return Ok(status(204));
    }
    if q.has("encryption") {
        ctx.authorize_owner(b)?;
        let c: SseConfigXml = parse_xml(&ctx.read_body(body).await?)?;
        let alg = c.rules.first().and_then(|r| r.default.as_ref()).map(|d| d.algorithm.as_str()).ok_or_else(S3Error::malformed_xml)?;
        if alg != "AES256" {
            return Err(S3Error::not_implemented("Only SSE-S3 (AES256) default encryption is supported."));
        }
        s.update_bucket(b, |m| {
            m.encryption = true;
            Ok(())
        })?;
        return Ok(status(200));
    }
    if q.has("acl") {
        ctx.authorize_owner(b)?;
        check_acl(ctx)?;
        let raw = ctx.read_body(body).await?;
        if String::from_utf8_lossy(&raw).contains("/groups/global/") {
            return Err(S3Error::not_implemented("Group ACL grants are not supported. Use a bucket policy."));
        }
        return Ok(status(200));
    }
    if q.has("notification") {
        return Err(S3Error::not_implemented("Configure event notifications as webhooks in the BoxSpace console."));
    }
    if q.has("object-lock") {
        return Err(S3Error::not_implemented("Object Lock is not supported."));
    }
    if let Some(k) = UNSUPPORTED_BUCKET.iter().find(|k| q.has(k)) {
        return Err(S3Error::not_implemented(format!("The bucket subresource '{k}' is not supported.")));
    }

    // CreateBucket
    if !valid_bucket_name(b) {
        return Err(S3Error::new("InvalidBucketName", 400, "The specified bucket is not valid.").resource(b));
    }
    match &ctx.auth.identity {
        Some(id) if !id.read_only => {}
        _ => return Err(S3Error::access_denied()),
    }
    check_acl(ctx)?;
    if ctx.h("x-amz-bucket-object-lock-enabled") == Some("true") {
        return Err(S3Error::not_implemented("Object Lock is not supported."));
    }
    let _ = ctx.read_body(body).await?; // CreateBucketConfiguration (ignored)
    s.create_bucket(b)?;
    let mut r = status(200);
    set_header(r.headers_mut(), "location", &format!("/{b}"));
    Ok(r)
}

async fn bucket_delete(ctx: &Ctx<'_>, b: &str) -> Result<Response> {
    let q = &ctx.q;
    let s = &ctx.app.store;
    type Clear = fn(&mut crate::storage::BucketMeta);
    let subs: [(&str, Clear); 5] = [
        ("policy", |m| m.policy = None),
        ("lifecycle", |m| m.lifecycle.clear()),
        ("cors", |m| m.cors.clear()),
        ("tagging", |m| m.tags = None),
        ("encryption", |m| m.encryption = false),
    ];
    for (name, clear) in subs {
        if q.has(name) {
            ctx.authorize_owner(b)?;
            s.update_bucket(b, |m| {
                clear(m);
                Ok(())
            })?;
            return Ok(status(204));
        }
    }
    if let Some(k) = UNSUPPORTED_BUCKET.iter().find(|k| q.has(k)) {
        return Err(S3Error::not_implemented(format!("The bucket subresource '{k}' is not supported.")));
    }
    ctx.authorize_owner(b)?;
    ops::delete_bucket(ctx.app, b).await?;
    Ok(status(204))
}

#[derive(Deserialize)]
struct DeleteXml {
    #[serde(rename = "Object", default)]
    objects: Vec<DelObjXml>,
    #[serde(rename = "Quiet", default)]
    quiet: bool,
}
#[derive(Deserialize)]
struct DelObjXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: Option<String>,
}

async fn delete_objects(ctx: &Ctx<'_>, b: &str, body: Body) -> Result<Response> {
    if ctx.auth.identity.is_none() {
        // Anonymous callers still need a policy granting s3:DeleteObject per key.
        ctx.app.store.get_bucket(b)?.ok_or_else(S3Error::access_denied)?;
    }
    let bm = ctx.app.store.bucket(b)?;
    let req: DeleteXml = parse_xml(&ctx.read_body(body).await?)?;
    if req.objects.len() > 1000 {
        return Err(S3Error::malformed_xml());
    }
    let mut out = String::new();
    for o in req.objects {
        let vid = o.version_id.as_deref().filter(|v| !v.is_empty());
        let action = if vid.is_some() { "s3:DeleteObjectVersion" } else { "s3:DeleteObject" };
        let res = match ctx.authorize(action, b, Some(&o.key)).and_then(|_| ops::check_key(&o.key)) {
            Ok(()) => ops::delete_object(ctx.app, &bm, &o.key, vid).await,
            Err(e) => Err(e),
        };
        match res {
            Ok(r) => {
                if req.quiet {
                    continue;
                }
                let mut d = format!("<Deleted><Key>{}</Key>", esc(&o.key));
                if let Some(v) = vid {
                    d.push_str(&format!("<VersionId>{}</VersionId>", esc(v)));
                }
                if r.delete_marker {
                    d.push_str("<DeleteMarker>true</DeleteMarker>");
                    if let Some(m) = &r.version_id {
                        d.push_str(&format!("<DeleteMarkerVersionId>{}</DeleteMarkerVersionId>", esc(m)));
                    }
                }
                d.push_str("</Deleted>");
                out.push_str(&d);
            }
            Err(e) => out.push_str(&format!(
                "<Error><Key>{}</Key>{}<Code>{}</Code><Message>{}</Message></Error>",
                esc(&o.key),
                vid.map(|v| format!("<VersionId>{}</VersionId>", esc(v))).unwrap_or_default(),
                e.code,
                esc(&e.message)
            )),
        }
    }
    xml(format!("<DeleteResult xmlns=\"{S3_NS}\">{out}</DeleteResult>"))
}

// ------------------------------------------------------------- object ----

async fn object_op(ctx: &Ctx<'_>, b: &str, k: &str, body: Body) -> Result<Response> {
    let q = &ctx.q;
    let unsupported = ["attributes", "torrent", "retention", "legal-hold", "restore", "select"];
    if let Some(s) = unsupported.iter().find(|s| q.has(s)) {
        return Err(S3Error::not_implemented(format!("The object subresource '{s}' is not supported.")));
    }
    match ctx.method {
        Method::GET if q.has("tagging") => get_object_tagging(ctx, b, k),
        Method::GET if q.has("uploadId") => list_parts(ctx, b, k),
        Method::GET if q.has("acl") => {
            ctx.authorize("s3:GetObjectAcl", b, Some(k))?;
            ctx.app.store.bucket(b)?;
            lookup_version(ctx, b, k, q.get("versionId"))?;
            xml(acl_xml())
        }
        Method::GET => get_object(ctx, b, k, false).await,
        Method::HEAD => get_object(ctx, b, k, true).await,
        Method::PUT if q.has("tagging") => put_object_tagging(ctx, b, k, body).await,
        Method::PUT if q.has("acl") => {
            ctx.authorize("s3:PutObjectAcl", b, Some(k))?;
            ctx.app.store.bucket(b)?;
            lookup_version(ctx, b, k, q.get("versionId"))?;
            check_acl(ctx)?;
            let raw = ctx.read_body(body).await?;
            if String::from_utf8_lossy(&raw).contains("/groups/global/") {
                return Err(S3Error::not_implemented("Group ACL grants are not supported. Use a bucket policy."));
            }
            Ok(status(200))
        }
        Method::PUT if q.has("uploadId") || q.has("partNumber") => upload_part(ctx, b, k, body).await,
        Method::PUT if ctx.h("x-amz-copy-source").is_some() => copy_object(ctx, b, k).await,
        Method::PUT => put_object(ctx, b, k, body).await,
        Method::DELETE if q.has("uploadId") => abort_upload(ctx, b, k).await,
        Method::DELETE if q.has("tagging") => delete_object_tagging(ctx, b, k),
        Method::DELETE => delete_object(ctx, b, k).await,
        Method::POST if q.has("uploads") => create_upload(ctx, b, k),
        Method::POST if q.has("uploadId") => complete_upload(ctx, b, k, body).await,
        Method::POST => Err(S3Error::not_implemented("Unsupported POST operation.")),
        _ => Err(S3Error::method_not_allowed()),
    }
}

async fn get_object(ctx: &Ctx<'_>, b: &str, k: &str, head: bool) -> Result<Response> {
    let q = &ctx.q;
    let vid = q.get("versionId").filter(|v| !v.is_empty());
    ctx.authorize(if vid.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" }, b, Some(k))?;
    ctx.app.store.bucket(b)?;
    if ctx.h("x-amz-server-side-encryption-customer-algorithm").is_some() {
        return Err(S3Error::invalid_request("The object was not stored with SSE-C."));
    }
    let v = lookup_version(ctx, b, k, vid)?;
    check_conditions(&ctx.headers, &v)?;
    if let Some(p) = q.get("partNumber")
        && p != "1"
    {
        return Err(S3Error::not_implemented("Reading individual parts (partNumber > 1) is not supported."));
    }
    let size = v.size;
    let range = match ctx.h("range") {
        Some(r) => parse_range(r, size)?,
        None => None,
    };
    let (start, end) = range.unwrap_or((0, size.saturating_sub(1)));
    let len = if size == 0 { 0 } else { end - start + 1 };
    let body = match (&v.blob, head || len == 0) {
        (Some(blob), false) => Body::from_stream(blob::open(ctx.app, blob, start, end).await?),
        _ => Body::empty(),
    };
    let mut r = Response::new(body);
    *r.status_mut() = if range.is_some() { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK };
    let h = r.headers_mut();
    object_headers(h, &v);
    set_header(h, "content-length", &len.to_string());
    if range.is_some() {
        set_header(h, "content-range", &format!("bytes {start}-{end}/{size}"));
    }
    for (param, name) in [
        ("response-content-type", "content-type"),
        ("response-content-language", "content-language"),
        ("response-expires", "expires"),
        ("response-cache-control", "cache-control"),
        ("response-content-disposition", "content-disposition"),
        ("response-content-encoding", "content-encoding"),
    ] {
        if let Some(val) = q.get(param) {
            set_header(h, name, val);
        }
    }
    Ok(r)
}

async fn put_object(ctx: &Ctx<'_>, b: &str, k: &str, body: Body) -> Result<Response> {
    ctx.authorize("s3:PutObject", b, Some(k))?;
    ops::check_key(k)?;
    ctx.app.store.bucket(b)?;
    check_acl(ctx)?;
    reject_object_lock(ctx)?;
    let opts = put_opts(ctx)?;
    // Conditional writes.
    let inm = ctx.h("if-none-match");
    let im = ctx.h("if-match");
    if inm.is_some() || im.is_some() {
        let cur = ctx.app.store.get_version(b, k, None)?.filter(|v| !v.delete_marker);
        if inm.map(str::trim) == Some("*") && cur.is_some() {
            return Err(S3Error::precondition_failed());
        }
        if let Some(im) = im {
            match &cur {
                Some(v) if etag_matches(im, &v.etag) => {}
                Some(_) => return Err(S3Error::precondition_failed()),
                None => return Err(S3Error::no_such_key(k)),
            }
        }
    }
    let v = ops::put_object(ctx.app, b, k, stream(body), &ctx.auth.payload, opts).await?;
    let mut r = status(200);
    set_header(r.headers_mut(), "etag", &quoted(&v.etag));
    if v.encrypted() {
        set_header(r.headers_mut(), "x-amz-server-side-encryption", "AES256");
    }
    version_header(&mut r, &v.version_id);
    Ok(r)
}

async fn copy_object(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    let (sb, sk, svid) = parse_copy_source(ctx.h("x-amz-copy-source").unwrap_or(""))?;
    ctx.authorize("s3:PutObject", b, Some(k))?;
    ops::check_key(k)?;
    check_acl(ctx)?;
    reject_object_lock(ctx)?;
    let dest = ctx.app.store.bucket(b)?;
    let src = copy_source_version(ctx, &sb, &sk, svid.as_deref())?;
    let directive = ctx.h("x-amz-metadata-directive").unwrap_or("COPY");
    let tag_directive = ctx.h("x-amz-tagging-directive").unwrap_or("COPY");
    if !matches!(directive, "COPY" | "REPLACE") || !matches!(tag_directive, "COPY" | "REPLACE") {
        return Err(S3Error::invalid_argument("Unknown metadata directive."));
    }
    let req = put_opts(ctx)?;
    if sb == b && sk == k && svid.is_none() && directive == "COPY" && req.encrypt.is_none() {
        return Err(S3Error::invalid_request(
            "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
        ));
    }
    let encrypt = req.encrypt.unwrap_or(dest.encryption);
    let rel = ctx.app.store.new_blob_rel(b);
    let (blob, md5) = ops::copy_data(ctx.app, &src, None, &rel, encrypt).await?;
    let (content_type, meta, headers) = if directive == "REPLACE" {
        (req.content_type.unwrap_or_else(|| DEFAULT_CONTENT_TYPE.into()), req.meta, req.headers)
    } else {
        (src.content_type.clone(), src.meta.clone(), src.headers.clone())
    };
    let v = ObjectVersion {
        key: k.to_string(),
        size: blob.size,
        etag: hex::encode(md5),
        last_modified: Utc::now(),
        content_type,
        meta,
        headers,
        tags: if tag_directive == "REPLACE" { req.tags } else { src.tags.clone() },
        blob: Some(blob),
        ..Default::default()
    };
    let stored = ops::commit_version(ctx.app, &dest, v, "ObjectCreated:Copy").await?;
    let mut r = xml(format!(
        "<CopyObjectResult xmlns=\"{S3_NS}\"><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>",
        iso8601(&stored.last_modified),
        esc(&quoted(&stored.etag))
    ))?;
    version_header(&mut r, &stored.version_id);
    if src.version_id != NULL_VERSION {
        set_header(r.headers_mut(), "x-amz-copy-source-version-id", &src.version_id);
    }
    if stored.encrypted() {
        set_header(r.headers_mut(), "x-amz-server-side-encryption", "AES256");
    }
    Ok(r)
}

fn delete_object_tagging(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    let vid = ctx.q.get("versionId").filter(|v| !v.is_empty());
    ctx.authorize(if vid.is_some() { "s3:DeleteObjectVersionTagging" } else { "s3:DeleteObjectTagging" }, b, Some(k))?;
    ctx.app.store.bucket(b)?;
    lookup_version(ctx, b, k, vid)?;
    let v = ctx.app.store.update_version(b, k, vid, |v| v.tags.clear())?.ok_or_else(|| S3Error::no_such_key(k))?;
    let mut r = status(204);
    version_header(&mut r, &v.version_id);
    Ok(r)
}

fn get_object_tagging(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    let vid = ctx.q.get("versionId").filter(|v| !v.is_empty());
    ctx.authorize(if vid.is_some() { "s3:GetObjectVersionTagging" } else { "s3:GetObjectTagging" }, b, Some(k))?;
    ctx.app.store.bucket(b)?;
    let v = lookup_version(ctx, b, k, vid)?;
    let mut r = xml(tagging_xml(&v.tags))?;
    version_header(&mut r, &v.version_id);
    Ok(r)
}

async fn put_object_tagging(ctx: &Ctx<'_>, b: &str, k: &str, body: Body) -> Result<Response> {
    let vid = ctx.q.get("versionId").filter(|v| !v.is_empty());
    ctx.authorize(if vid.is_some() { "s3:PutObjectVersionTagging" } else { "s3:PutObjectTagging" }, b, Some(k))?;
    ctx.app.store.bucket(b)?;
    lookup_version(ctx, b, k, vid)?;
    let tags = parse_tagging(&ctx.read_body(body).await?, 10)?;
    let v = ctx.app.store.update_version(b, k, vid, |v| v.tags = tags)?.ok_or_else(|| S3Error::no_such_key(k))?;
    let mut r = status(200);
    version_header(&mut r, &v.version_id);
    Ok(r)
}

async fn delete_object(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    let vid = ctx.q.get("versionId").filter(|v| !v.is_empty());
    ctx.authorize(if vid.is_some() { "s3:DeleteObjectVersion" } else { "s3:DeleteObject" }, b, Some(k))?;
    ops::check_key(k)?;
    let bm = ctx.app.store.bucket(b)?;
    let out = ops::delete_object(ctx.app, &bm, k, vid).await?;
    let mut r = status(204);
    if let Some(v) = &out.version_id {
        set_header(r.headers_mut(), "x-amz-version-id", v);
    }
    if out.delete_marker {
        set_header(r.headers_mut(), "x-amz-delete-marker", "true");
    }
    Ok(r)
}

// ---------------------------------------------------------- multipart ----

fn upload_for(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<UploadMeta> {
    let id = ctx.q.get("uploadId").ok_or_else(S3Error::no_such_upload)?;
    ctx.app.store.get_upload(id)?.filter(|u| u.bucket == b && u.key == k).ok_or_else(S3Error::no_such_upload)
}

fn create_upload(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    ctx.authorize("s3:PutObject", b, Some(k))?;
    ops::check_key(k)?;
    let bm = ctx.app.store.bucket(b)?;
    check_acl(ctx)?;
    reject_object_lock(ctx)?;
    let o = put_opts(ctx)?;
    let id = format!("{}{}", uuid::Uuid::new_v4().simple(), random_hex(8));
    let u = UploadMeta {
        upload_id: id.clone(),
        bucket: b.to_string(),
        key: k.to_string(),
        initiated: Utc::now(),
        content_type: o.content_type.unwrap_or_else(|| DEFAULT_CONTENT_TYPE.into()),
        meta: o.meta,
        headers: o.headers,
        tags: o.tags,
        encrypt: o.encrypt.unwrap_or(bm.encryption),
        parts: BTreeMap::new(),
    };
    std::fs::create_dir_all(ctx.app.store.abs(&format!("uploads/{id}")))?;
    ctx.app.store.put_upload(&u)?;
    let mut r = xml(format!(
        "<InitiateMultipartUploadResult xmlns=\"{S3_NS}\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        esc(b),
        esc(k),
        esc(&id)
    ))?;
    if u.encrypt {
        set_header(r.headers_mut(), "x-amz-server-side-encryption", "AES256");
    }
    Ok(r)
}

async fn upload_part(ctx: &Ctx<'_>, b: &str, k: &str, body: Body) -> Result<Response> {
    let n: u32 = ctx
        .q
        .get("partNumber")
        .and_then(|v| v.parse().ok())
        .filter(|n| (1..=10000).contains(n))
        .ok_or_else(|| S3Error::invalid_argument("Part number must be an integer between 1 and 10000, inclusive"))?;
    ctx.authorize("s3:PutObject", b, Some(k))?;
    ctx.app.store.bucket(b)?;
    let up = upload_for(ctx, b, k)?;
    let rel = format!("uploads/{}/{n}-{}", up.upload_id, uuid::Uuid::new_v4().simple());
    let copy = ctx.h("x-amz-copy-source").map(str::to_string);
    let (blob, md5) = if let Some(src) = &copy {
        let (sb, sk, svid) = parse_copy_source(src)?;
        let sv = copy_source_version(ctx, &sb, &sk, svid.as_deref())?;
        let range = match ctx.h("x-amz-copy-source-range") {
            Some(r) => {
                let rr = parse_range(r, sv.size).map_err(|_| S3Error::invalid_argument("The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy"))?;
                Some(rr.ok_or_else(|| S3Error::invalid_argument("Invalid x-amz-copy-source-range"))?)
            }
            None => None,
        };
        ops::copy_data(ctx.app, &sv, range, &rel, up.encrypt).await?
    } else {
        let opts = put_opts(ctx)?;
        ops::write_body(ctx.app, &rel, stream(body), &ctx.auth.payload, &opts, up.encrypt).await?
    };
    let now = Utc::now();
    let part = PartMeta { etag: hex::encode(md5), size: blob.size, last_modified: now, blob: blob.clone() };
    match ctx.app.store.set_part(&up.upload_id, n, part) {
        Ok(old) => blob::remove(ctx.app, old).await,
        Err(e) => {
            blob::remove(ctx.app, [blob]).await;
            return Err(e);
        }
    }
    let etag = quoted(&hex::encode(md5));
    let mut r = if copy.is_some() {
        xml(format!(
            "<CopyPartResult xmlns=\"{S3_NS}\"><LastModified>{}</LastModified><ETag>{}</ETag></CopyPartResult>",
            iso8601(&now),
            esc(&etag)
        ))?
    } else {
        let mut r = status(200);
        set_header(r.headers_mut(), "etag", &etag);
        r
    };
    if up.encrypt {
        set_header(r.headers_mut(), "x-amz-server-side-encryption", "AES256");
    }
    Ok(r)
}

#[derive(Deserialize)]
struct CompleteXml {
    #[serde(rename = "Part", default)]
    parts: Vec<CompletePartXml>,
}
#[derive(Deserialize)]
struct CompletePartXml {
    #[serde(rename = "PartNumber")]
    number: u32,
    #[serde(rename = "ETag")]
    etag: String,
}

async fn complete_upload(ctx: &Ctx<'_>, b: &str, k: &str, body: Body) -> Result<Response> {
    ctx.authorize("s3:PutObject", b, Some(k))?;
    let bm = ctx.app.store.bucket(b)?;
    let up = upload_for(ctx, b, k)?;
    let req: CompleteXml = parse_xml(&ctx.read_body(body).await?)?;
    if req.parts.is_empty() {
        return Err(S3Error::invalid_request("You must specify at least one part"));
    }
    if req.parts.windows(2).any(|w| w[1].number <= w[0].number) {
        return Err(S3Error::new(
            "InvalidPartOrder",
            400,
            "The list of parts was not in ascending order. Parts must be ordered by part number.",
        ));
    }
    let mut chosen = Vec::with_capacity(req.parts.len());
    let last = req.parts.len() - 1;
    for (i, p) in req.parts.iter().enumerate() {
        let invalid = || {
            S3Error::new(
                "InvalidPart",
                400,
                "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
            )
        };
        let pm = up.parts.get(&p.number).ok_or_else(invalid)?;
        if norm_etag(&p.etag) != pm.etag {
            return Err(invalid());
        }
        if i < last && pm.size < MIN_PART {
            return Err(S3Error::new("EntityTooSmall", 400, "Your proposed upload is smaller than the minimum allowed object size."));
        }
        chosen.push(pm.clone());
    }
    let mut w = BlobWriter::create(ctx.app, up.encrypt).await?;
    for pm in &chosen {
        w.pipe(blob::open_full(ctx.app, &pm.blob).await?).await?;
    }
    let rel = ctx.app.store.new_blob_rel(b);
    let (blob, _) = w.finish(ctx.app, &rel).await?;
    let mut cat = Vec::with_capacity(chosen.len() * 16);
    for pm in &chosen {
        cat.extend(hex::decode(&pm.etag).map_err(S3Error::internal)?);
    }
    let etag = format!("{}-{}", hex::encode(md5_bytes(&cat)), chosen.len());
    if ctx.app.store.delete_upload(&up.upload_id)?.is_none() {
        blob::remove(ctx.app, [blob]).await;
        return Err(S3Error::no_such_upload());
    }
    let v = ObjectVersion {
        key: k.to_string(),
        size: blob.size,
        etag,
        last_modified: Utc::now(),
        content_type: up.content_type.clone(),
        meta: up.meta.clone(),
        headers: up.headers.clone(),
        tags: up.tags.clone(),
        blob: Some(blob),
        parts: Some(chosen.len() as u32),
        ..Default::default()
    };
    let stored = ops::commit_version(ctx.app, &bm, v, "ObjectCreated:CompleteMultipartUpload").await;
    let _ = tokio::fs::remove_dir_all(ctx.app.store.abs(&format!("uploads/{}", up.upload_id))).await;
    let stored = stored?;
    let mut r = xml(format!(
        "<CompleteMultipartUploadResult xmlns=\"{S3_NS}\"><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
        esc(&format!("{}/{}/{}", ctx.app.cfg.server_url, b, uri_encode(k, false))),
        esc(b),
        esc(k),
        esc(&quoted(&stored.etag))
    ))?;
    version_header(&mut r, &stored.version_id);
    if stored.encrypted() {
        set_header(r.headers_mut(), "x-amz-server-side-encryption", "AES256");
    }
    Ok(r)
}

async fn abort_upload(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    ctx.authorize("s3:AbortMultipartUpload", b, Some(k))?;
    ctx.app.store.bucket(b)?;
    let up = upload_for(ctx, b, k)?;
    ops::abort_upload(ctx.app, &up.upload_id).await?;
    Ok(status(204))
}

fn list_parts(ctx: &Ctx<'_>, b: &str, k: &str) -> Result<Response> {
    ctx.authorize("s3:ListMultipartUploadParts", b, Some(k))?;
    ctx.app.store.bucket(b)?;
    let up = upload_for(ctx, b, k)?;
    let marker: u32 = ctx.q.get("part-number-marker").and_then(|v| v.parse().ok()).unwrap_or(0);
    let max = max_keys(&ctx.q, "max-parts")?;
    let parts: Vec<(&u32, &PartMeta)> = up.parts.range(marker + 1..).collect();
    let truncated = parts.len() > max;
    let page = &parts[..parts.len().min(max)];
    let items: String = page
        .iter()
        .map(|(n, p)| {
            format!(
                "<Part><PartNumber>{n}</PartNumber><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Part>",
                iso8601(&p.last_modified),
                esc(&quoted(&p.etag)),
                p.size
            )
        })
        .collect();
    let next = page.last().map(|(n, _)| **n).unwrap_or(marker);
    xml(format!(
        "<ListPartsResult xmlns=\"{S3_NS}\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><Initiator><ID>{OWNER_ID}</ID><DisplayName>{OWNER_ID}</DisplayName></Initiator>{}<StorageClass>STANDARD</StorageClass><PartNumberMarker>{marker}</PartNumberMarker><NextPartNumberMarker>{next}</NextPartNumberMarker><MaxParts>{max}</MaxParts><IsTruncated>{truncated}</IsTruncated>{items}</ListPartsResult>",
        esc(b),
        esc(k),
        esc(&up.upload_id),
        owner()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names() {
        assert!(valid_bucket_name("my-bucket.1"));
        assert!(!valid_bucket_name("My-Bucket"));
        assert!(!valid_bucket_name("ab"));
        assert!(!valid_bucket_name("-abc"));
        assert!(!valid_bucket_name("192.168.0.1"));
        assert!(!valid_bucket_name("a..b"));
        assert!(!valid_bucket_name("_console"));
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100).unwrap(), Some((0, 9)));
        assert_eq!(parse_range("bytes=90-", 100).unwrap(), Some((90, 99)));
        assert_eq!(parse_range("bytes=-10", 100).unwrap(), Some((90, 99)));
        assert_eq!(parse_range("bytes=50-500", 100).unwrap(), Some((50, 99)));
        assert!(parse_range("bytes=100-", 100).is_err());
        assert!(parse_range("bytes=0-0", 0).is_err());
    }

    #[test]
    fn copy_source() {
        let (b, k, v) = parse_copy_source("/src/a%20b%3Fc.txt?versionId=123").unwrap();
        assert_eq!((b.as_str(), k.as_str(), v.as_deref()), ("src", "a b?c.txt", Some("123")));
        assert!(parse_copy_source("onlybucket").is_err());
    }
}
