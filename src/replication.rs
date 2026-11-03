//! Asynchronous replication of bucket changes to other S3 endpoints
//! (another BoxSpace, AWS S3, Backblaze B2, Wasabi, MinIO...).
//!
//! Changes are recorded in a persistent queue and sent by a background
//! worker with exponential backoff. Requests carry `x-boxspace-replication`
//! so a BoxSpace target does not replicate them back (no loops).

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use futures::StreamExt;
use reqwest::{header::HeaderMap, Method, Url};
use serde::Serialize;

use crate::{
    auth::{canonical_query, signing_key, EMPTY_SHA},
    blob,
    storage::{BucketMeta, ObjectVersion, QueueItem, ReplTarget},
    util::{esc, hmac, sha256_hex, uri_encode, Query},
    App,
};

pub const REPLICA_HEADER: &str = "x-boxspace-replication";
const MULTIPART_THRESHOLD: u64 = 64 * 1024 * 1024;
const PART_SIZE: u64 = 64 * 1024 * 1024;
const MAX_ATTEMPTS: u32 = 25;

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReplStats {
    pub pending: usize,
    pub failed: usize,
    pub last_error: Option<String>,
}

fn targets_for<'a>(bm: &'a BucketMeta, key: &'a str, delete: bool) -> impl Iterator<Item = &'a ReplTarget> {
    bm.replication
        .iter()
        .filter(move |t| t.enabled && key.starts_with(&t.prefix) && (!delete || t.replicate_deletes))
}

fn push(app: &App, bm: &BucketMeta, key: &str, version_id: &str, op: &str) {
    let mut any = false;
    for t in targets_for(bm, key, op == "delete") {
        let item = QueueItem {
            bucket: bm.name.clone(),
            key: key.to_string(),
            version_id: version_id.to_string(),
            op: op.to_string(),
            target: t.id.clone(),
            attempts: 0,
            next_at: Utc::now(),
            last_error: None,
        };
        if let Err(e) = app.store.enqueue(&item) {
            tracing::error!("não foi possível enfileirar a replicação de {}/{key}: {}", bm.name, e.message);
        }
        any = true;
    }
    if any {
        app.repl_wake.notify_one();
    }
}

pub fn enqueue_put(app: &App, bm: &BucketMeta, v: &ObjectVersion) {
    push(app, bm, &v.key, &v.version_id, "put");
}

pub fn enqueue_delete(app: &App, bm: &BucketMeta, key: &str) {
    push(app, bm, key, "", "delete");
}

/// Queue every current object of a bucket for a target (initial sync).
pub fn resync(app: &App, bm: &BucketMeta, target_id: &str) -> crate::error::Result<usize> {
    let mut n = 0;
    let mut last: Option<String> = None;
    let mut items = Vec::new();
    app.store.scan(&bm.name, "", |v| {
        if last.as_deref() != Some(v.key.as_str()) {
            last = Some(v.key.clone());
            if !v.delete_marker {
                items.push((v.key, v.version_id));
            }
        }
        crate::storage::Scan::Next
    })?;
    for (key, vid) in items {
        if bm.replication.iter().any(|t| t.id == target_id && key.starts_with(&t.prefix)) {
            app.store.enqueue(&QueueItem {
                bucket: bm.name.clone(),
                key,
                version_id: vid,
                op: "put".into(),
                target: target_id.to_string(),
                attempts: 0,
                next_at: Utc::now(),
                last_error: None,
            })?;
            n += 1;
        }
    }
    app.repl_wake.notify_one();
    Ok(n)
}

pub fn stats(app: &App, bucket: Option<&str>) -> ReplStats {
    let mut s = ReplStats::default();
    for (_, i) in app.store.queue_items(100_000).unwrap_or_default() {
        if bucket.is_some_and(|b| b != i.bucket) {
            continue;
        }
        if i.attempts >= MAX_ATTEMPTS {
            s.failed += 1;
        } else {
            s.pending += 1;
        }
        if i.last_error.is_some() {
            s.last_error = i.last_error.clone();
        }
    }
    s
}

/// Make failed items eligible again.
pub fn retry_failed(app: &App, bucket: &str) -> usize {
    let mut n = 0;
    for (id, mut i) in app.store.queue_items(100_000).unwrap_or_default() {
        if i.bucket == bucket && i.attempts >= MAX_ATTEMPTS {
            i.attempts = 0;
            i.next_at = Utc::now();
            let _ = app.store.queue_update(id, Some(&i));
            n += 1;
        }
    }
    app.repl_wake.notify_one();
    n
}

pub async fn worker(app: Arc<App>) {
    loop {
        tokio::select! {
            _ = app.repl_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
        loop {
            let now = Utc::now();
            let due: Vec<(u64, QueueItem)> = app
                .store
                .queue_items(100_000)
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, i)| i.attempts < MAX_ATTEMPTS && i.next_at <= now)
                .take(64)
                .collect();
            if due.is_empty() {
                break;
            }
            futures::stream::iter(due)
                .for_each_concurrent(4, |(id, item)| {
                    let app = app.clone();
                    async move { process(&app, id, item).await }
                })
                .await;
        }
    }
}

async fn process(app: &App, id: u64, mut item: QueueItem) {
    let bm = match app.store.get_bucket(&item.bucket) {
        Ok(Some(b)) => b,
        _ => return drop_item(app, id),
    };
    let Some(target) = bm.replication.iter().find(|t| t.id == item.target).cloned() else {
        return drop_item(app, id);
    };
    let result = async {
        let secret = app.kms.open_bytes(&target.secret_enc).map_err(|e| format!("segredo do destino: {e}"))?;
        let secret = String::from_utf8(secret).map_err(|e| e.to_string())?;
        let client = Client { app, t: &target, secret: &secret };
        match item.op.as_str() {
            "put" => match app.store.get_version(&item.bucket, &item.key, Some(&item.version_id)) {
                Ok(Some(v)) if !v.delete_marker => client.put(&item.bucket, &v).await,
                _ => Ok(()), // superseded or deleted meanwhile
            },
            "delete" => client.delete(&item.key).await,
            _ => Ok(()),
        }
    }
    .await;
    match result {
        Ok(()) => drop_item(app, id),
        Err(e) => {
            item.attempts += 1;
            let backoff = (5u64 << item.attempts.min(10)).min(3600);
            item.next_at = Utc::now() + chrono::Duration::seconds(backoff as i64);
            tracing::warn!("replicação de {}/{} para {} falhou (tentativa {}): {e}", item.bucket, item.key, target.endpoint, item.attempts);
            item.last_error = Some(e);
            let _ = app.store.queue_update(id, Some(&item));
        }
    }
}

fn drop_item(app: &App, id: u64) {
    let _ = app.store.queue_update(id, None);
}

// ------------------------------------------------------------- client ----

pub struct Client<'a> {
    pub app: &'a App,
    pub t: &'a ReplTarget,
    pub secret: &'a str,
}

impl Client<'_> {
    fn url(&self, key: Option<&str>, query: &str) -> Result<Url, String> {
        let mut s = format!("{}/{}", self.t.endpoint.trim_end_matches('/'), uri_encode(&self.t.bucket, true));
        if let Some(k) = key {
            s.push('/');
            s.push_str(&uri_encode(k, false));
        }
        if !query.is_empty() {
            s.push('?');
            s.push_str(query);
        }
        Url::parse(&s).map_err(|e| format!("endpoint inválido: {e}"))
    }

    fn sign(&self, method: &Method, url: &Url, headers: &mut HeaderMap, payload: &str) {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = &amz_date[..8];
        let region = if self.t.region.is_empty() { "us-east-1" } else { &self.t.region };
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
            None => url.host_str().unwrap_or("").to_string(),
        };
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload.parse().unwrap());
        let mut signed: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| k.as_str().starts_with("x-amz-") || k.as_str() == "content-md5")
            .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).trim().to_string()))
            .collect();
        signed.push(("host".into(), host));
        signed.sort();
        let names = signed.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        let canon_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let q = Query::parse(url.query());
        let canonical = format!("{}\n{}\n{}\n{}\n{}\n{}", method.as_str(), url.path(), canonical_query(&q, false), canon_headers, names, payload);
        let scope = format!("{date}/{region}/s3/aws4_request");
        let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
        let sig = hex::encode(hmac(&signing_key(self.secret, date, region, "s3"), sts.as_bytes()));
        let auth = format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={sig}", self.t.access_key);
        headers.insert("authorization", auth.parse().unwrap());
    }

    async fn send(&self, method: Method, url: Url, mut headers: HeaderMap, body: Option<reqwest::Body>, payload: &str) -> Result<reqwest::Response, String> {
        headers.insert(REPLICA_HEADER, "1".parse().unwrap());
        self.sign(&method, &url, &mut headers, payload);
        let mut req = self.app.http.request(method, url).headers(headers).timeout(Duration::from_secs(3600));
        if let Some(b) = body {
            req = req.body(b);
        }
        let resp = req.send().await.map_err(|e| format!("falha de conexão com {}: {}", self.t.endpoint, e.without_url()))?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let code = text.split("<Code>").nth(1).and_then(|s| s.split("</Code>").next()).unwrap_or("");
            Err(format!("o destino respondeu {status} {code}"))
        }
    }

    pub async fn check(&self) -> Result<(), String> {
        let url = self.url(None, "")?;
        self.send(Method::HEAD, url, HeaderMap::new(), None, EMPTY_SHA).await.map(|_| ())
    }

    fn object_headers(v: &ObjectVersion) -> HeaderMap {
        let mut h = HeaderMap::new();
        let mut put = |k: &str, val: &str| {
            if let (Ok(n), Ok(v)) = (reqwest::header::HeaderName::from_bytes(k.as_bytes()), reqwest::header::HeaderValue::from_bytes(val.as_bytes())) {
                h.insert(n, v);
            }
        };
        if !v.content_type.is_empty() {
            put("content-type", &v.content_type);
        }
        for (k, val) in &v.meta {
            put(&format!("x-amz-meta-{k}"), val);
        }
        for (k, val) in &v.headers {
            put(k, val);
        }
        if !v.tags.is_empty() {
            let t: Vec<String> = v.tags.iter().map(|(k, val)| format!("{}={}", uri_encode(k, true), uri_encode(val, true))).collect();
            put("x-amz-tagging", &t.join("&"));
        }
        h
    }

    async fn body(&self, bucket: &str, v: &ObjectVersion, start: u64, end: u64) -> Result<reqwest::Body, String> {
        let s = blob::open(self.app, bucket, v, start, end).await.map_err(|e| e.message)?;
        Ok(reqwest::Body::wrap_stream(s))
    }

    pub async fn put(&self, bucket: &str, v: &ObjectVersion) -> Result<(), String> {
        if v.size <= MULTIPART_THRESHOLD {
            let mut h = Self::object_headers(v);
            h.insert("content-length", v.size.into());
            let body = if v.size == 0 { reqwest::Body::from(Vec::new()) } else { self.body(bucket, v, 0, v.size - 1).await? };
            return self.send(Method::PUT, self.url(Some(&v.key), "")?, h, Some(body), "UNSIGNED-PAYLOAD").await.map(|_| ());
        }
        let resp = self
            .send(Method::POST, self.url(Some(&v.key), "uploads=")?, Self::object_headers(v), Some(reqwest::Body::from(Vec::new())), EMPTY_SHA)
            .await?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        let upload_id = text
            .split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .ok_or("resposta sem UploadId")?
            .to_string();
        let q = |extra: &str| format!("{extra}uploadId={}", uri_encode(&upload_id, true));
        let result: Result<(), String> = async {
            let mut etags = Vec::new();
            let mut off = 0u64;
            let mut n = 1u32;
            while off < v.size {
                let end = (off + PART_SIZE).min(v.size) - 1;
                let mut h = HeaderMap::new();
                h.insert("content-length", (end - off + 1).into());
                let body = self.body(bucket, v, off, end).await?;
                let r = self.send(Method::PUT, self.url(Some(&v.key), &q(&format!("partNumber={n}&")))?, h, Some(body), "UNSIGNED-PAYLOAD").await?;
                let etag = r.headers().get("etag").and_then(|e| e.to_str().ok()).ok_or("parte sem ETag")?.to_string();
                etags.push((n, etag));
                off = end + 1;
                n += 1;
            }
            let xml: String = etags.iter().map(|(n, e)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>", esc(e))).collect();
            let xml = format!("<CompleteMultipartUpload>{xml}</CompleteMultipartUpload>");
            let hash = sha256_hex(xml.as_bytes());
            let r = self.send(Method::POST, self.url(Some(&v.key), &q(""))?, HeaderMap::new(), Some(reqwest::Body::from(xml)), &hash).await?;
            let text = r.text().await.unwrap_or_default();
            if text.contains("<Error>") {
                return Err("o destino recusou a conclusão do upload".into());
            }
            Ok(())
        }
        .await;
        if result.is_err()
            && let Ok(u) = self.url(Some(&v.key), &q(""))
        {
            let _ = self.send(Method::DELETE, u, HeaderMap::new(), None, EMPTY_SHA).await;
        }
        result
    }

    pub async fn delete(&self, key: &str) -> Result<(), String> {
        self.send(Method::DELETE, self.url(Some(key), "")?, HeaderMap::new(), None, EMPTY_SHA).await.map(|_| ())
    }
}
