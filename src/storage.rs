//! Metadata store (redb) and on-disk layout.
//!
//! Layout under `<data>/.boxspace/`:
//!   meta.redb            metadata database
//!   master.key           SSE master key (if not provided via env)
//!   tmp/                 in-flight uploads
//!   blobs/<bucket>/..    object data
//!   uploads/<id>/..      multipart parts
//!
//! Object versions live in one table keyed by
//! `bucket \0 key \0 (u64::MAX - seq)`, so a range scan yields keys in
//! lexicographic order and, for each key, versions newest first.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    cors::CorsRule,
    error::{Result, S3Error},
    events::Webhook,
    lifecycle::LifecycleRule,
};

const BUCKETS: TableDefinition<&str, &[u8]> = TableDefinition::new("buckets");
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const UPLOADS: TableDefinition<&str, &[u8]> = TableDefinition::new("uploads");
const KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");

pub const NULL_VERSION: &str = "null";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncInfo {
    /// Data key wrapped with the master key (base64).
    pub key: String,
    /// 8-byte nonce prefix (base64).
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlobRef {
    /// Path relative to the `.boxspace` directory.
    pub path: String,
    /// Plaintext size.
    pub size: u64,
    #[serde(default)]
    pub enc: Option<EncInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ObjectVersion {
    pub key: String,
    pub version_id: String,
    pub seq: u64,
    pub delete_marker: bool,
    pub size: u64,
    /// ETag without quotes.
    pub etag: String,
    pub last_modified: DateTime<Utc>,
    pub content_type: String,
    /// User metadata (x-amz-meta-*), lowercase names without prefix.
    pub meta: BTreeMap<String, String>,
    /// Standard headers: cache-control, content-disposition, ...
    pub headers: BTreeMap<String, String>,
    pub tags: Vec<(String, String)>,
    pub blob: Option<BlobRef>,
    pub parts: Option<u32>,
}

impl ObjectVersion {
    pub fn encrypted(&self) -> bool {
        self.blob.as_ref().is_some_and(|b| b.enc.is_some())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct BucketMeta {
    pub name: String,
    pub created: DateTime<Utc>,
    /// None (never enabled), "Enabled" or "Suspended".
    pub versioning: Option<String>,
    pub policy: Option<String>,
    pub lifecycle: Vec<LifecycleRule>,
    pub cors: Vec<CorsRule>,
    pub tags: Option<Vec<(String, String)>>,
    /// Default SSE-S3 encryption for new objects.
    pub encryption: bool,
    pub webhooks: Vec<Webhook>,
}

impl BucketMeta {
    pub fn versioning_enabled(&self) -> bool {
        self.versioning.as_deref() == Some("Enabled")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PartMeta {
    pub etag: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    pub blob: BlobRef,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct UploadMeta {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub initiated: DateTime<Utc>,
    pub content_type: String,
    pub meta: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub tags: Vec<(String, String)>,
    pub encrypt: bool,
    pub parts: BTreeMap<u32, PartMeta>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct AccessKey {
    pub access_key: String,
    pub secret_key: String,
    pub read_only: bool,
    pub description: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct DeleteOutcome {
    /// Version id that was deleted, or of the delete marker created.
    pub version_id: Option<String>,
    /// True if a delete marker was created or removed.
    pub delete_marker: bool,
    pub removed: Vec<BlobRef>,
}

pub struct Store {
    db: Database,
    meta_dir: PathBuf,
    seq: AtomicU64,
}

fn de<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    serde_json::from_slice(b).map_err(S3Error::internal)
}

fn ser<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("serializable")
}

fn okey(bucket: &str, key: &str, seq: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(bucket.len() + key.len() + 10);
    v.extend_from_slice(bucket.as_bytes());
    v.push(0);
    v.extend_from_slice(key.as_bytes());
    v.push(0);
    v.extend_from_slice(&(u64::MAX - seq).to_be_bytes());
    v
}

fn key_range(bucket: &str, key: &str) -> (Vec<u8>, Vec<u8>) {
    let mut s = Vec::new();
    s.extend_from_slice(bucket.as_bytes());
    s.push(0);
    s.extend_from_slice(key.as_bytes());
    let mut e = s.clone();
    s.push(0);
    e.push(1);
    (s, e)
}

fn bucket_range(bucket: &str, from_key: &str) -> (Vec<u8>, Vec<u8>) {
    let mut s = bucket.as_bytes().to_vec();
    s.push(0);
    s.extend_from_slice(from_key.as_bytes());
    let mut e = bucket.as_bytes().to_vec();
    e.push(1);
    (s, e)
}

type Entries = Vec<(Vec<u8>, ObjectVersion)>;

fn versions_of<T>(t: &T, bucket: &str, key: &str) -> Result<Entries>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let (s, e) = key_range(bucket, key);
    let mut out = Vec::new();
    for item in t.range(s.as_slice()..e.as_slice())? {
        let (k, v) = item?;
        out.push((k.value().to_vec(), de::<ObjectVersion>(v.value())?));
    }
    Ok(out)
}

pub fn valid_object_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 1024 && !key.contains('\0')
}

impl Store {
    pub fn open(root: &Path) -> std::result::Result<Store, String> {
        let meta_dir = root.join(".boxspace");
        for d in ["tmp", "blobs", "uploads"] {
            std::fs::create_dir_all(meta_dir.join(d)).map_err(|e| format!("{}: {e}", meta_dir.join(d).display()))?;
        }
        // Leftovers from interrupted uploads.
        if let Ok(rd) = std::fs::read_dir(meta_dir.join("tmp")) {
            for e in rd.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let db = Database::create(meta_dir.join("meta.redb")).map_err(|e| e.to_string())?;
        let tx = db.begin_write().map_err(|e| e.to_string())?;
        {
            tx.open_table(BUCKETS).map_err(|e| e.to_string())?;
            tx.open_table(OBJECTS).map_err(|e| e.to_string())?;
            tx.open_table(UPLOADS).map_err(|e| e.to_string())?;
            tx.open_table(KEYS).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        let now = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        Ok(Store { db, meta_dir, seq: AtomicU64::new(now) })
    }

    pub fn meta_dir(&self) -> &Path {
        &self.meta_dir
    }

    pub fn abs(&self, rel: &str) -> PathBuf {
        self.meta_dir.join(rel)
    }

    pub fn tmp_path(&self) -> PathBuf {
        self.meta_dir.join("tmp").join(uuid::Uuid::new_v4().simple().to_string())
    }

    pub fn new_blob_rel(&self, bucket: &str) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        format!("blobs/{bucket}/{}/{id}", &id[..2])
    }

    fn next_seq(&self) -> u64 {
        let now = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let prev = self
            .seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| Some(std::cmp::max(cur + 1, now)))
            .expect("closure always returns Some");
        std::cmp::max(prev + 1, now)
    }

    // ---------------- buckets ----------------

    pub fn create_bucket(&self, name: &str) -> Result<BucketMeta> {
        let tx = self.db.begin_write()?;
        let bm;
        {
            let mut t = tx.open_table(BUCKETS)?;
            let exists = t.get(name)?.is_some();
            if exists {
                return Err(S3Error::new(
                    "BucketAlreadyOwnedByYou",
                    409,
                    "Your previous request to create the named bucket succeeded and you already own it.",
                )
                .resource(name));
            }
            bm = BucketMeta { name: name.to_string(), created: Utc::now(), ..Default::default() };
            t.insert(name, ser(&bm).as_slice())?;
        }
        tx.commit()?;
        Ok(bm)
    }

    pub fn get_bucket(&self, name: &str) -> Result<Option<BucketMeta>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(BUCKETS)?;
        let r = t.get(name)?;
        r.map(|g| de(g.value())).transpose()
    }

    pub fn bucket(&self, name: &str) -> Result<BucketMeta> {
        self.get_bucket(name)?.ok_or_else(|| S3Error::no_such_bucket(name))
    }

    pub fn list_buckets(&self) -> Result<Vec<BucketMeta>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(BUCKETS)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            out.push(de(v.value())?);
        }
        Ok(out)
    }

    pub fn update_bucket<F>(&self, name: &str, f: F) -> Result<BucketMeta>
    where
        F: FnOnce(&mut BucketMeta) -> Result<()>,
    {
        let tx = self.db.begin_write()?;
        let bm;
        {
            let mut t = tx.open_table(BUCKETS)?;
            let cur = t.get(name)?.map(|g| de::<BucketMeta>(g.value())).transpose()?;
            let mut m = cur.ok_or_else(|| S3Error::no_such_bucket(name))?;
            f(&mut m)?;
            t.insert(name, ser(&m).as_slice())?;
            bm = m;
        }
        tx.commit()?;
        Ok(bm)
    }

    /// Delete an empty bucket. In-progress multipart uploads are discarded;
    /// returns their ids so the caller can remove the part files.
    pub fn delete_bucket(&self, name: &str) -> Result<Vec<String>> {
        let tx = self.db.begin_write()?;
        let mut upload_ids = Vec::new();
        {
            let mut buckets = tx.open_table(BUCKETS)?;
            if buckets.get(name)?.is_none() {
                return Err(S3Error::no_such_bucket(name));
            }
            let objs = tx.open_table(OBJECTS)?;
            let (s, e) = bucket_range(name, "");
            if objs.range(s.as_slice()..e.as_slice())?.next().is_some() {
                return Err(S3Error::new("BucketNotEmpty", 409, "The bucket you tried to delete is not empty").resource(name));
            }
            let mut uploads = tx.open_table(UPLOADS)?;
            for item in uploads.iter()? {
                let (k, v) = item?;
                let u: UploadMeta = de(v.value())?;
                if u.bucket == name {
                    upload_ids.push(k.value().to_string());
                }
            }
            for id in &upload_ids {
                uploads.remove(id.as_str())?;
            }
            buckets.remove(name)?;
        }
        tx.commit()?;
        Ok(upload_ids)
    }

    // ---------------- objects ----------------

    /// Store a new version according to the bucket's versioning state.
    /// Returns the stored version and blobs that are no longer referenced.
    pub fn put_version(&self, bucket: &str, mut v: ObjectVersion) -> Result<(ObjectVersion, Vec<BlobRef>)> {
        let tx = self.db.begin_write()?;
        let mut garbage = Vec::new();
        {
            let buckets = tx.open_table(BUCKETS)?;
            let bm: BucketMeta = match buckets.get(bucket)? {
                Some(g) => de(g.value())?,
                None => return Err(S3Error::no_such_bucket(bucket)),
            };
            let mut objs = tx.open_table(OBJECTS)?;
            v.seq = self.next_seq();
            if bm.versioning_enabled() {
                v.version_id = uuid::Uuid::new_v4().to_string();
            } else {
                v.version_id = NULL_VERSION.to_string();
                for (k, old) in versions_of(&objs, bucket, &v.key)? {
                    if old.version_id == NULL_VERSION {
                        objs.remove(k.as_slice())?;
                        garbage.extend(old.blob);
                    }
                }
            }
            objs.insert(okey(bucket, &v.key, v.seq).as_slice(), ser(&v).as_slice())?;
        }
        tx.commit()?;
        Ok((v, garbage))
    }

    /// Latest version (may be a delete marker) or a specific version.
    pub fn get_version(&self, bucket: &str, key: &str, version_id: Option<&str>) -> Result<Option<ObjectVersion>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(OBJECTS)?;
        let vs = versions_of(&t, bucket, key)?;
        Ok(match version_id {
            None => vs.into_iter().next().map(|(_, v)| v),
            Some(id) => vs.into_iter().map(|(_, v)| v).find(|v| v.version_id == id),
        })
    }

    pub fn key_versions(&self, bucket: &str, key: &str) -> Result<Vec<ObjectVersion>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(OBJECTS)?;
        Ok(versions_of(&t, bucket, key)?.into_iter().map(|(_, v)| v).collect())
    }

    pub fn delete_object(&self, bucket: &str, key: &str, version_id: Option<&str>) -> Result<DeleteOutcome> {
        let tx = self.db.begin_write()?;
        let mut out = DeleteOutcome::default();
        {
            let buckets = tx.open_table(BUCKETS)?;
            let bm: BucketMeta = match buckets.get(bucket)? {
                Some(g) => de(g.value())?,
                None => return Err(S3Error::no_such_bucket(bucket)),
            };
            let mut objs = tx.open_table(OBJECTS)?;
            let versions = versions_of(&objs, bucket, key)?;
            match version_id {
                Some(id) => {
                    if let Some((k, v)) = versions.into_iter().find(|(_, v)| v.version_id == id) {
                        objs.remove(k.as_slice())?;
                        out.delete_marker = v.delete_marker;
                        out.removed.extend(v.blob);
                    }
                    out.version_id = Some(id.to_string());
                }
                None => {
                    let marker_id = match bm.versioning.as_deref() {
                        Some("Enabled") => Some(uuid::Uuid::new_v4().to_string()),
                        Some(_) => Some(NULL_VERSION.to_string()),
                        None => None,
                    };
                    if marker_id.as_deref() != Some(NULL_VERSION) && marker_id.is_some() {
                        // Versioning enabled: keep everything, add a marker.
                    } else {
                        for (k, v) in versions {
                            if v.version_id == NULL_VERSION {
                                objs.remove(k.as_slice())?;
                                out.removed.extend(v.blob);
                            }
                        }
                    }
                    if let Some(id) = marker_id {
                        let m = ObjectVersion {
                            key: key.to_string(),
                            version_id: id.clone(),
                            seq: self.next_seq(),
                            delete_marker: true,
                            last_modified: Utc::now(),
                            ..Default::default()
                        };
                        objs.insert(okey(bucket, key, m.seq).as_slice(), ser(&m).as_slice())?;
                        out.version_id = Some(id);
                        out.delete_marker = true;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn update_version<F>(&self, bucket: &str, key: &str, version_id: Option<&str>, f: F) -> Result<Option<ObjectVersion>>
    where
        F: FnOnce(&mut ObjectVersion),
    {
        let tx = self.db.begin_write()?;
        let mut result = None;
        {
            let mut objs = tx.open_table(OBJECTS)?;
            let versions = versions_of(&objs, bucket, key)?;
            let found = match version_id {
                None => versions.into_iter().next(),
                Some(id) => versions.into_iter().find(|(_, v)| v.version_id == id),
            };
            if let Some((k, mut v)) = found {
                if !v.delete_marker {
                    f(&mut v);
                    objs.insert(k.as_slice(), ser(&v).as_slice())?;
                }
                result = Some(v);
            }
        }
        tx.commit()?;
        Ok(result)
    }

    /// Iterate over all versions in a bucket starting at `from_key`
    /// (inclusive, by prefix ordering). The callback returns false to stop.
    pub fn scan<F>(&self, bucket: &str, from_key: &str, mut f: F) -> Result<()>
    where
        F: FnMut(ObjectVersion) -> bool,
    {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(OBJECTS)?;
        let (s, e) = bucket_range(bucket, from_key);
        for item in t.range(s.as_slice()..e.as_slice())? {
            let (_, v) = item?;
            if !f(de(v.value())?) {
                break;
            }
        }
        Ok(())
    }

    // ---------------- multipart uploads ----------------

    pub fn put_upload(&self, u: &UploadMeta) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(UPLOADS)?.insert(u.upload_id.as_str(), ser(u).as_slice())?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_upload(&self, id: &str) -> Result<Option<UploadMeta>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(UPLOADS)?;
        let r = t.get(id)?;
        r.map(|g| de(g.value())).transpose()
    }

    pub fn delete_upload(&self, id: &str) -> Result<Option<UploadMeta>> {
        let tx = self.db.begin_write()?;
        let removed;
        {
            let mut t = tx.open_table(UPLOADS)?;
            let r = t.remove(id)?;
            removed = r.map(|g| de::<UploadMeta>(g.value())).transpose()?;
        }
        tx.commit()?;
        Ok(removed)
    }

    pub fn list_uploads(&self, bucket: &str) -> Result<Vec<UploadMeta>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(UPLOADS)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            let u: UploadMeta = de(v.value())?;
            if u.bucket == bucket {
                out.push(u);
            }
        }
        out.sort_by(|a, b| (&a.key, a.initiated).cmp(&(&b.key, b.initiated)));
        Ok(out)
    }

    /// Record a part; returns the blob of the part it replaced, if any.
    pub fn set_part(&self, id: &str, n: u32, part: PartMeta) -> Result<Option<BlobRef>> {
        let tx = self.db.begin_write()?;
        let old;
        {
            let mut t = tx.open_table(UPLOADS)?;
            let cur = t.get(id)?.map(|g| de::<UploadMeta>(g.value())).transpose()?;
            let mut u = cur.ok_or_else(S3Error::no_such_upload)?;
            old = u.parts.insert(n, part).map(|p| p.blob);
            t.insert(id, ser(&u).as_slice())?;
        }
        tx.commit()?;
        Ok(old)
    }

    // ---------------- access keys ----------------

    pub fn list_keys(&self) -> Result<Vec<AccessKey>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(KEYS)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            out.push(de(v.value())?);
        }
        Ok(out)
    }

    pub fn get_key(&self, ak: &str) -> Result<Option<AccessKey>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(KEYS)?;
        let r = t.get(ak)?;
        r.map(|g| de(g.value())).transpose()
    }

    pub fn put_key(&self, k: &AccessKey) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(KEYS)?.insert(k.access_key.as_str(), ser(k).as_slice())?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_key(&self, ak: &str) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.open_table(KEYS)?.remove(ak)?.is_some();
        tx.commit()?;
        Ok(existed)
    }

    // ---------------- stats ----------------

    /// (current objects, bytes stored across all versions)
    pub fn bucket_usage(&self, bucket: &str) -> Result<(u64, u64)> {
        let (mut objects, mut bytes) = (0u64, 0u64);
        let mut last: Option<String> = None;
        self.scan(bucket, "", |v| {
            let latest = last.as_deref() != Some(v.key.as_str());
            if latest {
                last = Some(v.key.clone());
                if !v.delete_marker {
                    objects += 1;
                }
            }
            bytes += v.size;
            true
        })?;
        Ok((objects, bytes))
    }
}
