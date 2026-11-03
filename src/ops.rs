//! Object operations shared by the S3 API, the console and lifecycle.

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
    storage::{valid_object_key, BucketMeta, DeleteOutcome, ObjectVersion},
    App,
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

/// Write a request body into a new blob. Returns (writer-finished blob, md5).
pub async fn write_body<S>(
    app: &App,
    rel: &str,
    stream: S,
    payload: &Payload,
    opts: &PutOpts,
    encrypt: bool,
) -> Result<(crate::storage::BlobRef, [u8; 16])>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    let mut w = BlobWriter::create(app, encrypt).await?;
    body::ingest(stream, payload, opts.crc32.as_deref(), &mut w).await?;
    if let Some(n) = opts.decoded_len
        && n != w.size
    {
        return Err(S3Error::incomplete_body());
    }
    let (blob, md5) = w.finish(app, rel).await?;
    if let Err(e) = verify_md5(&md5, opts.content_md5.as_deref()) {
        blob::remove(app, [blob]).await;
        return Err(e);
    }
    Ok((blob, md5))
}

/// Store a finished blob as a new object version and fire events.
pub async fn commit_version(app: &App, bm: &BucketMeta, v: ObjectVersion, event: &str) -> Result<ObjectVersion> {
    let blob_copy = v.blob.clone();
    let (stored, garbage) = match app.store.put_version(&bm.name, v) {
        Ok(r) => r,
        Err(e) => {
            blob::remove(app, blob_copy).await;
            return Err(e);
        }
    };
    blob::remove(app, garbage).await;
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
    let rel = app.store.new_blob_rel(bucket);
    let (blob, md5) = write_body(app, &rel, stream, payload, &opts, encrypt).await?;
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
    commit_version(app, &bm, v, "ObjectCreated:Put").await
}

/// Copy `range` (inclusive) of a source version into a new blob.
pub async fn copy_data(
    app: &App,
    src: &ObjectVersion,
    range: Option<(u64, u64)>,
    rel: &str,
    encrypt: bool,
) -> Result<(crate::storage::BlobRef, [u8; 16])> {
    let mut w = BlobWriter::create(app, encrypt).await?;
    if let Some(b) = &src.blob {
        let (s, e) = range.unwrap_or((0, b.size.saturating_sub(1)));
        w.pipe(blob::open(app, b, s, e).await?).await?;
    }
    w.finish(app, rel).await
}

pub async fn delete_object(app: &App, bm: &BucketMeta, key: &str, version_id: Option<&str>) -> Result<DeleteOutcome> {
    let out = app.store.delete_object(&bm.name, key, version_id)?;
    let removed_any = !out.removed.is_empty();
    blob::remove(app, out.removed.clone()).await;
    let created_marker = version_id.is_none() && out.delete_marker;
    if created_marker || removed_any || version_id.is_some() {
        let name = if created_marker { "ObjectRemoved:DeleteMarkerCreated" } else { "ObjectRemoved:Delete" };
        events::emit(&app.http, bm, Event { name, key, size: 0, etag: "", version_id: out.version_id.as_deref() });
    }
    Ok(out)
}

pub async fn abort_upload(app: &App, upload_id: &str) -> Result<bool> {
    match app.store.delete_upload(upload_id)? {
        Some(_) => {
            let dir = app.store.abs(&format!("uploads/{upload_id}"));
            if let Err(e) = tokio::fs::remove_dir_all(&dir).await
                && e.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!("não foi possível remover {}: {e}", dir.display());
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
        true
    })?;
    for (k, vid) in all {
        delete_object(app, &bm, &k, Some(&vid)).await?;
    }
    for u in app.store.list_uploads(bucket)? {
        abort_upload(app, &u.upload_id).await?;
    }
    Ok(())
}

pub async fn delete_bucket(app: &App, bucket: &str) -> Result<()> {
    let uploads = app.store.delete_bucket(bucket)?;
    for id in uploads {
        let _ = tokio::fs::remove_dir_all(app.store.abs(&format!("uploads/{id}"))).await;
    }
    let _ = tokio::fs::remove_dir_all(app.store.abs(&format!("blobs/{bucket}"))).await;
    Ok(())
}
