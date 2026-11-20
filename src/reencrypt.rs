//! Encryption status of a bucket and re-encryption of data written before
//! encryption was turned on.
//!
//! Re-encryption rewrites each unencrypted blob as a new encrypted blob and
//! swaps the references inside a transaction that first checks the version
//! was not changed meanwhile. Object contents, ETag, version id and Object
//! Lock settings stay the same; only the bytes on disk change.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, Mutex},
};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    blob::{self, BlobWriter},
    error::{Result, S3Error},
    sidecar,
    storage::{BlobRef, ObjectVersion, Scan},
    App,
};

const BATCH: usize = 256;

#[derive(Serialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Current objects (latest version, not a delete marker).
    pub objects: u64,
    pub objects_encrypted: u64,
    /// Every stored version (delete markers have no data and are not counted).
    pub versions: u64,
    pub versions_encrypted: u64,
    pub bytes: u64,
    pub bytes_encrypted: u64,
}

/// Count encrypted data in a bucket (reads only the metadata index).
pub fn status(app: &App, bucket: &str) -> Result<Status> {
    app.store.bucket(bucket)?;
    let mut s = Status::default();
    let mut last_key: Option<String> = None;
    app.store.scan(bucket, "", |v| {
        let latest = last_key.as_deref() != Some(v.key.as_str());
        if latest {
            last_key = Some(v.key.clone());
        }
        if v.delete_marker {
            return Scan::Next;
        }
        let enc = fully_encrypted(&v);
        s.versions += 1;
        s.bytes += v.size;
        if enc {
            s.versions_encrypted += 1;
            s.bytes_encrypted += v.size;
        }
        if latest {
            s.objects += 1;
            s.objects_encrypted += enc as u64;
        }
        Scan::Next
    })?;
    Ok(s)
}

/// True when every piece of the version's data is encrypted.
pub fn fully_encrypted(v: &ObjectVersion) -> bool {
    let mut any = false;
    for b in v.blobs() {
        if b.enc.is_none() {
            return false;
        }
        any = true;
    }
    any
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub running: bool,
    pub done: u64,
    pub failed: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

static JOBS: LazyLock<Mutex<HashMap<String, Job>>> = LazyLock::new(Default::default);

pub fn job(bucket: &str) -> Option<Job> {
    JOBS.lock().unwrap().get(bucket).cloned()
}

pub fn forget(bucket: &str) {
    let mut jobs = JOBS.lock().unwrap();
    if jobs.get(bucket).is_some_and(|j| !j.running) {
        jobs.remove(bucket);
    }
}

fn update(bucket: &str, f: impl FnOnce(&mut Job)) {
    if let Some(j) = JOBS.lock().unwrap().get_mut(bucket) {
        f(j);
    }
}

/// Start encrypting the existing data of `bucket` in the background.
/// Returns false if a job is already running for it.
pub fn start(app: Arc<App>, bucket: String) -> bool {
    {
        let mut jobs = JOBS.lock().unwrap();
        if jobs.get(&bucket).is_some_and(|j| j.running) {
            return false;
        }
        jobs.insert(
            bucket.clone(),
            Job { running: true, done: 0, failed: 0, started_at: Utc::now(), finished_at: None, last_error: None },
        );
    }
    tokio::spawn(async move {
        let err = run(&app, &bucket).await.err().map(|e| e.message);
        if let Some(e) = &err {
            tracing::warn!(bucket = %bucket, "re-encryption stopped: {e}");
        }
        update(&bucket, |j| {
            j.running = false;
            j.finished_at = Some(Utc::now());
            if err.is_some() {
                j.last_error = err;
            }
        });
    });
    true
}

async fn run(app: &App, bucket: &str) -> Result<()> {
    let mut cursor = String::new();
    // Versions that could not be encrypted in this run (never retried).
    let mut skip: HashSet<(String, String)> = HashSet::new();
    loop {
        let bm = app.store.bucket(bucket)?;
        if !bm.encryption {
            return Err(S3Error::internal("a criptografia do bucket foi desativada"));
        }
        let mut batch = Vec::new();
        app.store.scan(bucket, &cursor, |v| {
            if !v.delete_marker && !fully_encrypted(&v) && !skip.contains(&(v.key.clone(), v.version_id.clone())) {
                batch.push(v);
                if batch.len() >= BATCH {
                    return Scan::Stop;
                }
            }
            Scan::Next
        })?;
        let Some(last) = batch.last() else { return Ok(()) };
        cursor = last.key.clone();
        for v in batch {
            match encrypt_version(app, bucket, &v).await {
                Ok(()) => update(bucket, |j| j.done += 1),
                Err(e) => {
                    tracing::warn!(bucket = %bucket, key = %v.key, version = %v.version_id, "re-encryption failed: {}", e.message);
                    update(bucket, |j| {
                        j.failed += 1;
                        j.last_error = Some(format!("{}: {}", v.key, e.message));
                    });
                    skip.insert((v.key, v.version_id));
                }
            }
        }
    }
}

/// Rewrite the unencrypted blobs of one version and swap them in.
pub async fn encrypt_version(app: &App, bucket: &str, v: &ObjectVersion) -> Result<()> {
    let mut created: Vec<BlobRef> = Vec::new();
    let result = async {
        let blob = match v.blob.clone() {
            Some(b) => {
                let (nb, md5) = copy_blob(app, bucket, b, &mut created).await?;
                // Single-part objects: the ETag is the MD5 of the data, so
                // the copy can be checked against it.
                if let Some(md5) = md5
                    && v.etag.len() == 32
                    && v.etag.bytes().all(|c| c.is_ascii_hexdigit())
                    && hex::encode(md5) != v.etag.to_ascii_lowercase()
                {
                    return Err(S3Error::internal("os dados lidos não conferem com o ETag; arquivo mantido como está"));
                }
                Some(nb)
            }
            None => None,
        };
        let mut segments = Vec::with_capacity(v.segments.len());
        for s in v.segments.clone() {
            segments.push(copy_blob(app, bucket, s, &mut created).await?.0);
        }
        Ok::<_, S3Error>((blob, segments))
    }
    .await;
    let (blob, segments) = match result {
        Ok(r) => r,
        Err(e) => {
            discard(app, bucket, &created).await;
            return Err(e);
        }
    };
    let old: Vec<BlobRef> = v.blobs().cloned().collect();
    let swap = app.store.try_update_version(bucket, &v.key, Some(&v.version_id), |cur| {
        if cur.oid != v.oid || !cur.blobs().map(|b| &b.id).eq(old.iter().map(|b| &b.id)) {
            return Err(S3Error::internal("o objeto foi alterado durante a operação"));
        }
        cur.blob = blob;
        cur.segments = segments;
        Ok(())
    });
    match swap {
        Ok(Some(nv)) => {
            sidecar::write_version(app, bucket, &nv).await;
            for b in old.iter().filter(|b| b.enc.is_none()) {
                blob::remove_blob(app, bucket, b).await;
            }
            Ok(())
        }
        Ok(None) => {
            discard(app, bucket, &created).await;
            Err(S3Error::internal("o objeto foi apagado durante a operação"))
        }
        Err(e) => {
            discard(app, bucket, &created).await;
            Err(e)
        }
    }
}

/// Encrypted copy of a blob (already encrypted blobs are kept as they are).
async fn copy_blob(app: &App, bucket: &str, b: BlobRef, created: &mut Vec<BlobRef>) -> Result<(BlobRef, Option<[u8; 16]>)> {
    if b.enc.is_some() {
        return Ok((b, None));
    }
    let mut w = BlobWriter::create(app, bucket, true).await?;
    let data = blob::open_blob(app.disks.clone(), app.kms.clone(), bucket, &b, 0, b.size.saturating_sub(1)).await?;
    w.pipe(data).await?;
    let (nb, md5) = w.finish().await?;
    created.push(nb.clone());
    if nb.size != b.size {
        return Err(S3Error::internal("tamanho lido diferente do esperado"));
    }
    Ok((nb, Some(md5)))
}

async fn discard(app: &App, bucket: &str, blobs: &[BlobRef]) {
    for b in blobs {
        blob::remove_blob(app, bucket, b).await;
    }
}
