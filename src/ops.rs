//! Object operations shared by the S3 API, the console and lifecycle.
//! Every change goes through here so metadata files, readable views,
//! replication and event notifications stay consistent.

use std::{collections::BTreeMap, io};

use bytes::Bytes;
use chrono::Utc;
use futures::Stream;

use crate::{
    auth::Payload,
    blob::{self, BlobWriter},
    body,
    error::{Result, S3Error},
    events::{self, Event},
    replication, sidecar,
    storage::{valid_object_key, BlobRef, BucketMeta, DeleteOutcome, ObjectVersion},
    view, App,
};

#[derive(Debug, Default, Clone)]
pub struct PutOpts {
    pub content_type: Option<String>,
    pub meta: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub tags: Vec<(String, String)>,
    /// None = bucket default.
    pub encrypt: Option<bool>,
    /// Base64 Content-MD5 to verify.
    pub content_md5: Option<String>,
    /// Base64 CRC32 to verify (x-amz-checksum-crc32 header).
    pub crc32: Option<String>,
    /// Expected decoded length for aws-chunked bodies.
    pub decoded_len: Option<u64>,
    /// The write itself comes from replication: do not replicate it again.
    pub replica: bool,
}

pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

pub fn check_key(key: &str) -> Result<()> {
    if !valid_object_key(key) {
        return Err(if key.len() > 1024 {
            S3Error::new("KeyTooLongError", 400, "Your key is too long")
        } else {
            S3Error::invalid_argument("Invalid object key")
        });
    }
    Ok(())
}

fn verify_md5(md5: &[u8; 16], expected_b64: Option<&str>) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    if let Some(exp) = expected_b64 {
        let raw = B64
            .decode(exp.trim())
            .map_err(|_| S3Error::new("InvalidDigest", 400, "The Content-MD5 you specified is not valid."))?;
        if raw.as_slice() != md5 {
            return Err(S3Error::bad_digest("The Content-MD5 you specified did not match what we received."));
        }
    }
    Ok(())
}

/// Write a request body into a new blob. Returns (blob, md5).
pub async fn write_body<S>(app: &App, bucket: &str, stream: S, payload: &Payload, opts: &PutOpts, encrypt: bool) -> Result<(BlobRef, [u8; 16])>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    let mut w = BlobWriter::create(app, bucket, encrypt).await?;
    body::ingest(stream, payload, opts.crc32.as_deref(), &mut w).await?;
    if let Some(n) = opts.decoded_len
        && n != w.size
    {
        return Err(S3Error::incomplete_body());
    }
    let (blob, md5) = w.finish().await?;
    if let Err(e) = verify_md5(&md5, opts.content_md5.as_deref()) {
        blob::remove_blob(app, bucket, &blob).await;
        return Err(e);
    }
    Ok((blob, md5))
}

/// Store a finished version and propagate the change.
pub async fn commit_version(app: &App, bm: &BucketMeta, mut v: ObjectVersion, event: &str, replica: bool) -> Result<ObjectVersion> {
    if v.oid.is_empty()
        && let Some(b) = &v.blob
    {
        v.oid = b.id.clone();
    }
    let data = v.clone();
    let (stored, replaced) = match app.store.put_version(&bm.name, v) {
        Ok(r) => r,
        Err(e) => {
            blob::remove_version(app, &bm.name, &data).await;
            return Err(e);
        }
    };
    sidecar::write_version(app, &bm.name, &stored).await;
    for old in &replaced {
        blob::remove_version(app, &bm.name, old).await;
    }
    view::refresh(app, &bm.name, &stored.key).await;
    if !replica {
        replication::enqueue_put(app, bm, &stored);
    }
    events::emit(
        &app.http,
        bm,
        Event { name: event, key: &stored.key, size: stored.size, etag: &stored.etag, version_id: Some(&stored.version_id) },
    );
    Ok(stored)
}

pub async fn put_object<S>(app: &App, bucket: &str, key: &str, stream: S, payload: &Payload, opts: PutOpts) -> Result<ObjectVersion>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    check_key(key)?;
    let bm = app.store.bucket(bucket)?;
    let encrypt = opts.encrypt.unwrap_or(bm.encryption);
    let (blob, md5) = write_body(app, bucket, stream, payload, &opts, encrypt).await?;
    let v = ObjectVersion {
        key: key.to_string(),
        size: blob.size,
        etag: hex::encode(md5),
        last_modified: Utc::now(),
        content_type: opts.content_type.unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_string()),
        meta: opts.meta,
        headers: opts.headers,
        tags: opts.tags,
        blob: Some(blob),
        ..Default::default()
    };
    commit_version(app, &bm, v, "ObjectCreated:Put", opts.replica).await
}

/// Copy `range` (inclusive) of a source version into a new blob in `dest_bucket`.
pub async fn copy_data(
    app: &App,
    src_bucket: &str,
    src: &ObjectVersion,
    range: Option<(u64, u64)>,
    dest_bucket: &str,
    encrypt: bool,
) -> Result<(BlobRef, [u8; 16])> {
    let mut w = BlobWriter::create(app, dest_bucket, encrypt).await?;
    let (s, e) = range.unwrap_or((0, src.size.saturating_sub(1)));
    w.pipe(blob::open(app, src_bucket, src, s, e).await?).await?;
    w.finish().await
}

pub async fn delete_object(app: &App, bm: &BucketMeta, key: &str, version_id: Option<&str>, replica: bool) -> Result<DeleteOutcome> {
    let out = app.store.delete_object(&bm.name, key, version_id)?;
    if let Some(m) = &out.marker {
        sidecar::write_version(app, &bm.name, m).await;
    }
    for v in &out.removed {
        blob::remove_version(app, &bm.name, v).await;
    }
    view::refresh(app, &bm.name, key).await;
    let created_marker = out.marker.is_some();
    if version_id.is_none() && (created_marker || !out.removed.is_empty()) && !replica {
        replication::enqueue_delete(app, bm, key);
    }
    if created_marker || !out.removed.is_empty() || version_id.is_some() {
        let name = if created_marker { "ObjectRemoved:DeleteMarkerCreated" } else { "ObjectRemoved:Delete" };
        events::emit(&app.http, bm, Event { name, key, size: 0, etag: "", version_id: out.version_id.as_deref() });
    }
    Ok(out)
}

/// Change a version's tags (and its meta.json).
pub async fn set_tags(app: &App, bucket: &str, key: &str, version_id: Option<&str>, tags: Vec<(String, String)>) -> Result<Option<ObjectVersion>> {
    let v = app.store.update_version(bucket, key, version_id, |v| v.tags = tags)?;
    if let Some(v) = &v
        && !v.delete_marker
    {
        sidecar::write_version(app, bucket, v).await;
    }
    Ok(v)
}

pub async fn abort_upload(app: &App, upload_id: &str) -> Result<bool> {
    match app.store.delete_upload(upload_id)? {
        Some(u) => {
            for p in u.parts.values() {
                blob::remove_blob(app, &u.bucket, &p.blob).await;
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Remove every version of every object (and pending uploads) in a bucket.
pub async fn empty_bucket(app: &App, bucket: &str) -> Result<()> {
    let bm = app.store.bucket(bucket)?;
    let mut all = Vec::new();
    app.store.scan(bucket, "", |v| {
        all.push((v.key, v.version_id));
        crate::storage::Scan::Next
    })?;
    for (k, vid) in all {
        delete_object(app, &bm, &k, Some(&vid), true).await?;
    }
    for u in app.store.list_uploads(bucket)? {
        abort_upload(app, &u.upload_id).await?;
    }
    Ok(())
}

pub async fn delete_bucket(app: &App, bucket: &str) -> Result<()> {
    let bm = app.store.bucket(bucket)?;
    app.store.delete_bucket(bucket)?;
    // Move the data directories aside immediately (a rename is atomic), so a
    // bucket recreated with the same name right away starts from an empty
    // directory; the old data (including pending upload parts) is removed
    // afterwards.
    let mut trash = Vec::new();
    for d in app.disks.online() {
        let t = d.tmp();
        if tokio::fs::rename(d.bucket_dir(bucket), &t).await.is_ok() {
            trash.push(t);
        }
    }
    for t in trash {
        let _ = tokio::fs::remove_dir_all(t).await;
    }
    if bm.readable {
        view::clear(app, bucket).await;
    }
    Ok(())
}
