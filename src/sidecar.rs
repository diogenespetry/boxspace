//! Self-describing metadata on every disk, and rebuilding the index from it.
//!
//! Each version directory holds `meta.json` (bucket + version record) on
//! every online disk. Bucket configurations and access keys are written to
//! `sys/` on every disk; access keys are encrypted with the master key.
//! If the index database is lost, `rebuild` restores it from these files.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    error::Result,
    storage::{AccessKey, BucketMeta, ObjectVersion},
    App,
};

#[derive(Serialize, Deserialize)]
pub struct Sidecar {
    pub bucket: String,
    pub version: ObjectVersion,
}

#[derive(Serialize, Deserialize)]
struct SysFile<T> {
    updated: DateTime<Utc>,
    items: T,
}

async fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    let tmp = dir.join(format!("{name}.tmp"));
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, dir.join(name)).await
}

/// Write (or rewrite) a version's meta.json to every online disk.
pub async fn write_version(app: &App, bucket: &str, v: &ObjectVersion) {
    if v.oid.is_empty() {
        return;
    }
    let data = serde_json::to_vec(&Sidecar { bucket: bucket.to_string(), version: v.clone() }).expect("serializable");
    for d in app.disks.online() {
        if let Err(e) = write_atomic(&d.obj_dir(bucket, &v.oid), "meta.json", &data).await {
            d.report(&e);
        }
    }
}

pub fn has_version_meta(app: &App, disk: usize, bucket: &str, oid: &str) -> bool {
    app.disks.list[disk].obj_dir(bucket, oid).join("meta.json").exists()
}

/// Persist bucket configs and access keys to every online disk.
pub async fn write_sys(app: &App) -> Result<()> {
    let now = Utc::now();
    let buckets = serde_json::to_vec_pretty(&SysFile { updated: now, items: app.store.list_buckets()? })?;
    let keys_plain = serde_json::to_vec(&app.store.list_keys()?)?;
    let keys = serde_json::to_vec_pretty(&SysFile { updated: now, items: app.kms.seal_bytes(&keys_plain) })?;
    let ip = serde_json::to_vec_pretty(&SysFile { updated: now, items: app.ipfilter.config() })?;
    for d in app.disks.online() {
        let dir = d.sys_dir();
        for (name, data) in [("buckets.json", &buckets), ("keys.json", &keys), ("ipfilter.json", &ip)] {
            if let Err(e) = write_atomic(&dir, name, data).await {
                d.report(&e);
            }
        }
    }
    Ok(())
}

/// Debounced writer for `sys/` files.
pub async fn sys_loop(app: Arc<App>) {
    loop {
        app.store.sys_changed.notified().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        if let Err(e) = write_sys(&app).await {
            tracing::warn!("não foi possível gravar a configuração nos discos: {}", e.message);
        }
    }
}

fn newest<T: DeserializeOwned>(app: &App, name: &str) -> Option<T> {
    app.disks
        .online()
        .filter_map(|d| std::fs::read(d.sys_dir().join(name)).ok())
        .filter_map(|b| serde_json::from_slice::<SysFile<T>>(&b).ok())
        .max_by_key(|f| f.updated)
        .map(|f| f.items)
}

/// Does any disk hold data from a previous run?
pub fn disks_have_data(app: &App) -> bool {
    app.disks.online().any(|d| {
        d.sys_dir().join("buckets.json").exists()
            || std::fs::read_dir(d.sys.join("objects")).map(|mut r| r.next().is_some()).unwrap_or(false)
    })
}

/// Rebuild the index from the files on the disks.
/// Returns (buckets, versions) restored.
pub fn rebuild(app: &App) -> Result<(usize, usize)> {
    let mut buckets: HashMap<String, BucketMeta> = newest::<Vec<BucketMeta>>(app, "buckets.json")
        .unwrap_or_default()
        .into_iter()
        .map(|b| (b.name.clone(), b))
        .collect();
    if let Some(sealed) = newest::<String>(app, "keys.json") {
        match app.kms.open_bytes(&sealed).and_then(|b| serde_json::from_slice::<Vec<AccessKey>>(&b).map_err(|e| e.to_string())) {
            Ok(keys) => {
                for k in keys {
                    app.store.put_key(&k)?;
                }
            }
            Err(e) => tracing::error!("não foi possível restaurar as chaves de acesso: {e}"),
        }
    }
    if let Some(cfg) = newest::<crate::ipfilter::IpConfig>(app, "ipfilter.json") {
        app.store.put_setting("ipfilter", &cfg)?;
    }
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut versions = 0;
    let mut pending: Vec<Sidecar> = Vec::new();
    for d in app.disks.online() {
        let Ok(bdirs) = std::fs::read_dir(d.sys.join("objects")) else { continue };
        for b in bdirs.flatten() {
            for fan in std::fs::read_dir(b.path()).into_iter().flatten().flatten() {
                for vd in std::fs::read_dir(fan.path()).into_iter().flatten().flatten() {
                    let Ok(bytes) = std::fs::read(vd.path().join("meta.json")) else { continue };
                    let Ok(sc) = serde_json::from_slice::<Sidecar>(&bytes) else { continue };
                    if seen.insert((sc.bucket.clone(), sc.version.oid.clone())) {
                        pending.push(sc);
                    }
                }
            }
        }
    }
    // Without versioning a key has a single "null" version; if stale copies
    // survived on a disk, keep only the newest one.
    let mut newest_null: HashMap<(String, String), u64> = HashMap::new();
    for sc in &pending {
        if sc.version.version_id == crate::storage::NULL_VERSION {
            let e = newest_null.entry((sc.bucket.clone(), sc.version.key.clone())).or_insert(0);
            *e = (*e).max(sc.version.seq);
        }
    }
    pending.retain(|sc| {
        sc.version.version_id != crate::storage::NULL_VERSION
            || newest_null.get(&(sc.bucket.clone(), sc.version.key.clone())) == Some(&sc.version.seq)
    });
    for sc in &pending {
        buckets.entry(sc.bucket.clone()).or_insert_with(|| BucketMeta {
            name: sc.bucket.clone(),
            created: sc.version.last_modified,
            ..Default::default()
        });
    }
    for bm in buckets.values() {
        app.store.import_bucket(bm)?;
    }
    for sc in pending {
        app.store.import_version(&sc.bucket, &sc.version)?;
        versions += 1;
    }
    for name in buckets.keys() {
        app.store.recount(name)?;
    }
    Ok((buckets.len(), versions))
}
