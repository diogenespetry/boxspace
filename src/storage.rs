//! Metadata index (redb).
//!
//! Object versions live in one table keyed by
//! `bucket \0 key \0 (u64::MAX - seq)`, so a range scan yields keys in
//! lexicographic order and, for each key, versions newest first.
//!
//! The index is derived data: every version is also described by a
//! `meta.json` written to each disk, so the index can be rebuilt (see
//! `rebuild.rs`) if the database is lost.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::Notify;

use crate::{
    cors::CorsRule,
    error::{Result, S3Error},
    events::Webhook,
    lifecycle::LifecycleRule,
    phys::Layout,
};

const BUCKETS: TableDefinition<&str, &[u8]> = TableDefinition::new("buckets");
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const UPLOADS: TableDefinition<&str, &[u8]> = TableDefinition::new("uploads");
const KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
const STATS: TableDefinition<&str, &[u8]> = TableDefinition::new("stats");
const QUEUE: TableDefinition<u64, &[u8]> = TableDefinition::new("replication_queue");
/// Small counters; "seq" is the highest version sequence ever issued, so a
/// clock that goes backwards cannot make new versions sort as older.
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

pub const NULL_VERSION: &str = "null";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncInfo {
    /// Data key wrapped with the master key (base64).
    pub key: String,
    /// 8-byte nonce prefix (base64).
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BlobRef {
    /// Directory id under `objects/<bucket>/`.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub layout: Option<Layout>,
    /// Pre-multi-disk installs: path relative to disk 0's `.boxspace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Plaintext size.
    pub size: u64,
    #[serde(default)]
    pub enc: Option<EncInfo>,
}

impl BlobRef {
    pub fn layout(&self) -> Layout {
        self.layout.clone().unwrap_or_else(|| Layout::Legacy { path: self.path.clone().unwrap_or_default() })
    }
    /// Bytes physically stored (ciphertext when encrypted).
    pub fn stored_len(&self) -> u64 {
        if self.enc.is_some() { crate::crypto::cipher_len(self.size) } else { self.size }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ObjectVersion {
    pub key: String,
    pub version_id: String,
    /// Internal id of this version's directory (holds meta.json).
    pub oid: String,
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
    /// Single-part data.
    pub blob: Option<BlobRef>,
    /// Multipart data, in order (no copy is made on completion).
    pub segments: Vec<BlobRef>,
    pub parts: Option<u32>,
}

impl ObjectVersion {
    pub fn encrypted(&self) -> bool {
        self.blob.as_ref().is_some_and(|b| b.enc.is_some()) || self.segments.iter().any(|s| s.enc.is_some())
    }
    pub fn blobs(&self) -> impl Iterator<Item = &BlobRef> {
        self.blob.iter().chain(self.segments.iter())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ReplTarget {
    pub id: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    /// Secret key wrapped with the master key (base64).
    pub secret_enc: String,
    pub prefix: String,
    pub replicate_deletes: bool,
    pub enabled: bool,
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
    /// Mirror current objects as plain files under `<disk0>/<bucket>/`.
    pub readable: bool,
    pub webhooks: Vec<Webhook>,
    pub replication: Vec<ReplTarget>,
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Grant {
    /// Bucket name or pattern (`*` wildcard).
    pub bucket: String,
    pub write: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct AccessKey {
    pub access_key: String,
    pub secret_key: String,
    pub read_only: bool,
    pub description: String,
    pub created: DateTime<Utc>,
    /// Empty = every bucket.
    pub grants: Vec<Grant>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
#[serde(default)]
pub struct Stats {
    pub objects: i64,
    pub versions: i64,
    pub bytes: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueueItem {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    /// "put" or "delete".
    pub op: String,
    pub target: String,
    pub attempts: u32,
    pub next_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct DeleteOutcome {
    /// Version id that was deleted, or of the delete marker created.
    pub version_id: Option<String>,
    /// True if a delete marker was created or removed.
    pub delete_marker: bool,
    /// The delete marker that was created, if any.
    pub marker: Option<ObjectVersion>,
    pub removed: Vec<ObjectVersion>,
}

/// What `scan` should do after visiting a version.
pub enum Scan {
    Next,
    Stop,
    /// Continue from this key (bytes), skipping everything before it.
    Seek(Vec<u8>),
}

pub struct Store {
    db: Database,
    seq: AtomicU64,
    /// Signalled when bucket configs or keys change (persisted to every disk).
    pub sys_changed: Notify,
    /// True when the database was created by this process (index may need rebuilding).
    pub fresh: bool,
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

fn bucket_prefix(bucket: &str) -> Vec<u8> {
    let mut s = bucket.as_bytes().to_vec();
    s.push(0);
    s
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

fn latest_live<T>(t: &T, bucket: &str, key: &str) -> Result<bool>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let (s, e) = key_range(bucket, key);
    match t.range(s.as_slice()..e.as_slice())?.next() {
        Some(item) => {
            let (_, v) = item?;
            Ok(!de::<ObjectVersion>(v.value())?.delete_marker)
        }
        None => Ok(false),
    }
}

fn bump_seq(tx: &redb::WriteTransaction, seq: u64) -> Result<()> {
    let mut t = tx.open_table(META)?;
    let cur = t.get("seq")?.map(|g| g.value()).unwrap_or(0);
    if seq > cur {
        t.insert("seq", seq)?;
    }
    Ok(())
}

fn adjust(t: &mut redb::Table<&str, &[u8]>, bucket: &str, objects: i64, versions: i64, bytes: i64) -> Result<()> {
    if objects == 0 && versions == 0 && bytes == 0 {
        return Ok(());
    }
    let cur = t.get(bucket)?.map(|g| de::<Stats>(g.value())).transpose()?;
    let mut s = cur.unwrap_or_default();
    s.objects += objects;
    s.versions += versions;
    s.bytes += bytes;
    t.insert(bucket, ser(&s).as_slice())?;
    Ok(())
}

pub fn valid_object_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 1024 && !key.contains('\0')
}

impl Store {
    pub fn open(meta_dir: &Path) -> std::result::Result<Store, String> {
        let path = meta_dir.join("meta.redb");
        let fresh = !path.exists();
        let db = Database::create(&path).map_err(|e| e.to_string())?;
        let tx = db.begin_write().map_err(|e| e.to_string())?;
        {
            tx.open_table(BUCKETS).map_err(|e| e.to_string())?;
            tx.open_table(OBJECTS).map_err(|e| e.to_string())?;
            tx.open_table(UPLOADS).map_err(|e| e.to_string())?;
            tx.open_table(KEYS).map_err(|e| e.to_string())?;
            tx.open_table(STATS).map_err(|e| e.to_string())?;
            tx.open_table(QUEUE).map_err(|e| e.to_string())?;
            tx.open_table(META).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        let stored_seq = {
            let tx = db.begin_read().map_err(|e| e.to_string())?;
            let t = tx.open_table(META).map_err(|e| e.to_string())?;
            t.get("seq").map_err(|e| e.to_string())?.map(|g| g.value()).unwrap_or(0)
        };
        let now = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        if stored_seq > now {
            tracing::warn!("o relógio do sistema está atrás do último registro gravado; mantendo a ordem das versões");
        }
        let store = Store { db, seq: AtomicU64::new(now.max(stored_seq)), sys_changed: Notify::new(), fresh };
        store.migrate_stats().map_err(|e| e.message)?;
        Ok(store)
    }

    fn next_seq(&self) -> u64 {
        let now = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let prev = self
            .seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| Some(std::cmp::max(cur + 1, now)))
            .expect("closure always returns Some");
        std::cmp::max(prev + 1, now)
    }

    pub fn new_oid() -> String {
        uuid::Uuid::new_v4().simple().to_string()
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
        self.sys_changed.notify_one();
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
        self.sys_changed.notify_one();
        Ok(bm)
    }

    /// Delete an empty bucket. In-progress multipart uploads are discarded
    /// and returned so the caller can remove their parts.
    pub fn delete_bucket(&self, name: &str) -> Result<Vec<UploadMeta>> {
        let tx = self.db.begin_write()?;
        let mut removed = Vec::new();
        {
            let mut buckets = tx.open_table(BUCKETS)?;
            if buckets.get(name)?.is_none() {
                return Err(S3Error::no_such_bucket(name));
            }
            let objs = tx.open_table(OBJECTS)?;
            let s = bucket_prefix(name);
            let mut e = name.as_bytes().to_vec();
            e.push(1);
            if objs.range(s.as_slice()..e.as_slice())?.next().is_some() {
                return Err(S3Error::new("BucketNotEmpty", 409, "The bucket you tried to delete is not empty").resource(name));
            }
            let mut uploads = tx.open_table(UPLOADS)?;
            for item in uploads.iter()? {
                let (_, v) = item?;
                let u: UploadMeta = de(v.value())?;
                if u.bucket == name {
                    removed.push(u);
                }
            }
            for u in &removed {
                uploads.remove(u.upload_id.as_str())?;
            }
            buckets.remove(name)?;
            tx.open_table(STATS)?.remove(name)?;
        }
        tx.commit()?;
        self.sys_changed.notify_one();
        Ok(removed)
    }

    // ---------------- objects ----------------

    /// Store a new version according to the bucket's versioning state.
    /// Returns the stored version and versions that were replaced (the old
    /// "null" version when versioning is off or suspended).
    pub fn put_version(&self, bucket: &str, mut v: ObjectVersion) -> Result<(ObjectVersion, Vec<ObjectVersion>)> {
        let tx = self.db.begin_write()?;
        let mut replaced = Vec::new();
        {
            let buckets = tx.open_table(BUCKETS)?;
            let bm: BucketMeta = match buckets.get(bucket)? {
                Some(g) => de(g.value())?,
                None => return Err(S3Error::no_such_bucket(bucket)),
            };
            let mut objs = tx.open_table(OBJECTS)?;
            let before = latest_live(&objs, bucket, &v.key)?;
            v.seq = self.next_seq();
            if v.oid.is_empty() {
                v.oid = Self::new_oid();
            }
            if bm.versioning_enabled() {
                v.version_id = uuid::Uuid::new_v4().to_string();
            } else {
                v.version_id = NULL_VERSION.to_string();
                for (k, old) in versions_of(&objs, bucket, &v.key)? {
                    if old.version_id == NULL_VERSION {
                        objs.remove(k.as_slice())?;
                        replaced.push(old);
                    }
                }
            }
            objs.insert(okey(bucket, &v.key, v.seq).as_slice(), ser(&v).as_slice())?;
            let after = latest_live(&objs, bucket, &v.key)?;
            let dbytes = v.size as i64 - replaced.iter().map(|r| r.size as i64).sum::<i64>();
            let dversions = 1 - replaced.len() as i64;
            adjust(&mut tx.open_table(STATS)?, bucket, after as i64 - before as i64, dversions, dbytes)?;
        }
        bump_seq(&tx, v.seq)?;
        tx.commit()?;
        Ok((v, replaced))
    }

    /// Insert a version exactly as described (index rebuild).
    pub fn import_version(&self, bucket: &str, v: &ObjectVersion) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(OBJECTS)?.insert(okey(bucket, &v.key, v.seq).as_slice(), ser(v).as_slice())?;
        bump_seq(&tx, v.seq)?;
        tx.commit()?;
        self.seq.fetch_max(v.seq, Ordering::SeqCst);
        Ok(())
    }

    pub fn import_bucket(&self, bm: &BucketMeta) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(BUCKETS)?.insert(bm.name.as_str(), ser(bm).as_slice())?;
        tx.commit()?;
        Ok(())
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
            let before = latest_live(&objs, bucket, key)?;
            let versions = versions_of(&objs, bucket, key)?;
            match version_id {
                Some(id) => {
                    if let Some((k, v)) = versions.into_iter().find(|(_, v)| v.version_id == id) {
                        objs.remove(k.as_slice())?;
                        out.delete_marker = v.delete_marker;
                        out.removed.push(v);
                    }
                    out.version_id = Some(id.to_string());
                }
                None => {
                    let marker_id = match bm.versioning.as_deref() {
                        Some("Enabled") => Some(uuid::Uuid::new_v4().to_string()),
                        Some(_) => Some(NULL_VERSION.to_string()),
                        None => None,
                    };
                    // With versioning enabled everything is kept; otherwise
                    // the "null" version is replaced.
                    if !bm.versioning_enabled() {
                        for (k, v) in versions {
                            if v.version_id == NULL_VERSION {
                                objs.remove(k.as_slice())?;
                                out.removed.push(v);
                            }
                        }
                    }
                    if let Some(id) = marker_id {
                        let m = ObjectVersion {
                            key: key.to_string(),
                            version_id: id.clone(),
                            oid: Self::new_oid(),
                            seq: self.next_seq(),
                            delete_marker: true,
                            last_modified: Utc::now(),
                            ..Default::default()
                        };
                        objs.insert(okey(bucket, key, m.seq).as_slice(), ser(&m).as_slice())?;
                        out.version_id = Some(id);
                        out.delete_marker = true;
                        out.marker = Some(m);
                    }
                }
            }
            let after = latest_live(&objs, bucket, key)?;
            let dversions = out.marker.is_some() as i64 - out.removed.len() as i64;
            let dbytes = -out.removed.iter().map(|r| r.size as i64).sum::<i64>();
            adjust(&mut tx.open_table(STATS)?, bucket, after as i64 - before as i64, dversions, dbytes)?;
        }
        if let Some(m) = &out.marker {
            bump_seq(&tx, m.seq)?;
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

    /// Visit versions in a bucket in key order (newest version first per
    /// key), starting at `from_key`. The callback can stop or seek ahead.
    pub fn scan<F>(&self, bucket: &str, from_key: &str, mut f: F) -> Result<()>
    where
        F: FnMut(ObjectVersion) -> Scan,
    {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(OBJECTS)?;
        let mut end = bucket.as_bytes().to_vec();
        end.push(1);
        let mut start = bucket_prefix(bucket);
        start.extend_from_slice(from_key.as_bytes());
        'outer: loop {
            for item in t.range(start.as_slice()..end.as_slice())? {
                let (_, v) = item?;
                match f(de(v.value())?) {
                    Scan::Next => {}
                    Scan::Stop => break 'outer,
                    Scan::Seek(k) => {
                        let mut s = bucket_prefix(bucket);
                        s.extend_from_slice(&k);
                        if s.as_slice() <= start.as_slice() {
                            continue; // never go backwards
                        }
                        start = s;
                        continue 'outer;
                    }
                }
            }
            break;
        }
        Ok(())
    }

    // ---------------- stats ----------------

    pub fn stats(&self, bucket: &str) -> Result<Stats> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(STATS)?;
        let r = t.get(bucket)?;
        Ok(r.map(|g| de(g.value())).transpose()?.unwrap_or_default())
    }

    /// Recompute a bucket's counters from scratch.
    pub fn recount(&self, bucket: &str) -> Result<Stats> {
        let mut s = Stats::default();
        let mut last: Option<String> = None;
        self.scan(bucket, "", |v| {
            if last.as_deref() != Some(v.key.as_str()) {
                if !v.delete_marker {
                    s.objects += 1;
                }
                last = Some(v.key);
            }
            s.versions += 1;
            s.bytes += v.size as i64;
            Scan::Next
        })?;
        let tx = self.db.begin_write()?;
        tx.open_table(STATS)?.insert(bucket, ser(&s).as_slice())?;
        tx.commit()?;
        Ok(s)
    }

    fn migrate_stats(&self) -> Result<()> {
        let empty = {
            let tx = self.db.begin_read()?;
            tx.open_table(STATS)?.len()? == 0
        };
        if empty {
            for b in self.list_buckets()? {
                self.recount(&b.name)?;
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
        self.sys_changed.notify_one();
        Ok(())
    }

    pub fn delete_key(&self, ak: &str) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.open_table(KEYS)?.remove(ak)?.is_some();
        tx.commit()?;
        self.sys_changed.notify_one();
        Ok(existed)
    }

    // ---------------- replication queue ----------------

    pub fn enqueue(&self, item: &QueueItem) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(QUEUE)?.insert(self.next_seq(), ser(item).as_slice())?;
        tx.commit()?;
        Ok(())
    }

    pub fn queue_items(&self, limit: usize) -> Result<Vec<(u64, QueueItem)>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(QUEUE)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (k, v) = item?;
            out.push((k.value(), de(v.value())?));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn queue_update(&self, id: u64, item: Option<&QueueItem>) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(QUEUE)?;
            match item {
                Some(i) => {
                    t.insert(id, ser(i).as_slice())?;
                }
                None => {
                    t.remove(id)?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
