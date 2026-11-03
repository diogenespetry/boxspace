//! Background integrity checks and repair.
//!
//! The healer walks every object version: it rewrites missing `meta.json`
//! files, verifies each copy (mirror) or shard (erasure), optionally checking
//! every CRC ("deep"), rebuilds the missing or corrupt ones, and removes
//! orphaned data directories left by interrupted writes.
//!
//! It runs at startup when a disk was replaced, whenever a disk comes back
//! online, periodically, and on demand from the console.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Notify;

use crate::{
    phys::{self, Layout},
    sidecar,
    storage::{ObjectVersion, Scan},
    App,
};

const ORPHAN_AGE: Duration = Duration::from_secs(3600);

#[derive(Serialize, Clone, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HealStatus {
    pub running: bool,
    pub deep: bool,
    pub started: Option<DateTime<Utc>>,
    pub finished: Option<DateTime<Utc>>,
    pub checked: u64,
    pub healed: u64,
    pub orphans: u64,
    /// Objects that can no longer be reconstructed (first 100).
    pub lost: Vec<String>,
    pub lost_count: u64,
    pub errors: Vec<String>,
}

#[derive(Default)]
pub struct Healer {
    pub status: Mutex<HealStatus>,
    trigger: Notify,
    deep: AtomicBool,
}

impl Healer {
    pub fn request(&self, deep: bool) {
        if deep {
            self.deep.store(true, Ordering::Relaxed);
        }
        self.trigger.notify_one();
    }

    pub fn snapshot(&self) -> HealStatus {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn update(&self, f: impl FnOnce(&mut HealStatus)) {
        f(&mut self.status.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

/// Watch offline disks and trigger a heal when they return.
pub async fn monitor(app: Arc<App>) {
    let mut iv = tokio::time::interval(Duration::from_secs(10));
    loop {
        iv.tick().await;
        if !app.disks.recheck().is_empty() {
            app.healer.request(false);
        }
    }
}

pub async fn run_loop(app: Arc<App>, run_now: bool) {
    if run_now {
        run(&app, false).await;
    }
    let every = Duration::from_secs(app.cfg.heal_interval_secs);
    loop {
        tokio::select! {
            _ = app.healer.trigger.notified() => {}
            _ = tokio::time::sleep(every) => {}
        }
        let deep = app.healer.deep.swap(false, Ordering::Relaxed);
        run(&app, deep).await;
    }
}

pub async fn run(app: &App, deep: bool) {
    app.healer.update(|s| {
        *s = HealStatus { running: true, deep, started: Some(Utc::now()), ..Default::default() };
    });
    tracing::info!("verificação de integridade iniciada{}", if deep { " (completa)" } else { "" });
    if let Err(e) = sidecar::write_sys(app).await {
        app.healer.update(|s| s.errors.push(e.message.clone()));
    }
    let run_start = SystemTime::now();
    let buckets = match app.store.list_buckets() {
        Ok(b) => b,
        Err(e) => {
            app.healer.update(|s| {
                s.errors.push(e.message);
                s.running = false;
                s.finished = Some(Utc::now());
            });
            return;
        }
    };
    let redundant = app.disks.list.len() > 1;

    for bm in &buckets {
        let mut versions: Vec<ObjectVersion> = Vec::new();
        if let Err(e) = app.store.scan(&bm.name, "", |v| {
            versions.push(v);
            Scan::Next
        }) {
            app.healer.update(|s| s.errors.push(e.message));
            continue;
        }
        for v in versions {
            let missing_meta = !v.oid.is_empty()
                && app.disks.online().any(|d| !sidecar::has_version_meta(app, d.idx, &bm.name, &v.oid));
            if missing_meta {
                // Re-read: the snapshot may be stale (tags changed, version deleted).
                if let Ok(Some(cur)) = app.store.get_version(&bm.name, &v.key, Some(&v.version_id))
                    && cur.oid == v.oid
                {
                    sidecar::write_version(app, &bm.name, &cur).await;
                }
            }
            for b in v.blobs() {
                let layout = b.layout();
                if matches!(layout, Layout::Legacy { .. }) || (!redundant && !deep) {
                    continue;
                }
                let c = phys::check(&app.disks, &bm.name, &b.id, &layout, b.stored_len(), deep).await;
                if c.lost {
                    let label = format!("{}/{} (versão {})", bm.name, v.key, v.version_id);
                    tracing::error!("objeto irrecuperável: {label}");
                    app.healer.update(|s| {
                        s.lost_count += 1;
                        if s.lost.len() < 100 {
                            s.lost.push(label);
                        }
                    });
                } else if !c.bad.is_empty() {
                    match phys::heal(&app.disks, &bm.name, &b.id, &layout, b.stored_len(), &c.bad).await {
                        Ok(()) => {
                            tracing::info!("reparado: {}/{} ({} cópia(s)/fragmento(s))", bm.name, v.key, c.bad.len());
                            app.healer.update(|s| s.healed += 1);
                        }
                        Err(e) => app.healer.update(|s| s.errors.push(e.message)),
                    }
                }
            }
            app.healer.update(|s| s.checked += 1);
        }
    }

    let orphans = collect_orphans(app, run_start).await;
    app.healer.update(|s| {
        s.orphans = orphans;
        s.running = false;
        s.finished = Some(Utc::now());
    });
    let st = app.healer.snapshot();
    tracing::info!(
        "verificação concluída: {} versões, {} reparadas, {} irrecuperáveis, {} órfãos removidos",
        st.checked,
        st.healed,
        st.lost_count,
        st.orphans
    );
}

/// Ids referenced by a bucket's versions and in-progress uploads.
/// Uploads are listed *before* versions: a multipart upload completing in
/// between is then covered either by the upload list or by its new version.
fn references(app: &App, bucket: &str) -> crate::error::Result<HashSet<String>> {
    let mut set = HashSet::new();
    for u in app.store.list_uploads(bucket)? {
        for p in u.parts.values() {
            set.insert(p.blob.id.clone());
        }
    }
    app.store.scan(bucket, "", |v| {
        set.insert(v.oid.clone());
        for b in v.blobs() {
            set.insert(b.id.clone());
        }
        Scan::Next
    })?;
    Ok(set)
}

/// Remove data directories that nothing refers to.
///
/// Only directories last modified more than an hour before this run started
/// are candidates, and references are re-read *after* the candidates are
/// collected, so anything written or committed during the run is kept. Any
/// error reading the index skips the affected bucket entirely.
async fn collect_orphans(app: &App, run_start: SystemTime) -> u64 {
    let Some(cutoff) = run_start.checked_sub(ORPHAN_AGE) else { return 0 };
    let older = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).map(|t| t < cutoff).unwrap_or(false);
    let Ok(buckets) = app.store.list_buckets() else { return 0 };
    let known: HashSet<String> = buckets.into_iter().map(|b| b.name).collect();

    // (bucket, Some(id) for one directory | None for a whole unknown bucket, path)
    let mut candidates: Vec<(String, Option<String>, std::path::PathBuf)> = Vec::new();
    for d in app.disks.online() {
        let Ok(bdirs) = std::fs::read_dir(d.sys.join("objects")) else { continue };
        for b in bdirs.flatten() {
            let name = b.file_name().to_string_lossy().into_owned();
            if !known.contains(&name) {
                if older(&b.path()) {
                    candidates.push((name, None, b.path()));
                }
                continue;
            }
            for fan in std::fs::read_dir(b.path()).into_iter().flatten().flatten() {
                for vd in std::fs::read_dir(fan.path()).into_iter().flatten().flatten() {
                    if older(&vd.path()) {
                        candidates.push((name.clone(), Some(vd.file_name().to_string_lossy().into_owned()), vd.path()));
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        return 0;
    }
    let mut refs: HashMap<String, Option<HashSet<String>>> = HashMap::new();
    let mut removed = 0u64;
    for (bucket, id, path) in candidates {
        let delete = match id {
            None => matches!(app.store.get_bucket(&bucket), Ok(None)),
            Some(id) => {
                let set = refs.entry(bucket.clone()).or_insert_with(|| references(app, &bucket).ok());
                set.as_ref().is_some_and(|s| !s.contains(&id))
            }
        };
        if delete && tokio::fs::remove_dir_all(&path).await.is_ok() {
            removed += 1;
            if let Some(parent) = path.parent() {
                let _ = std::fs::remove_dir(parent); // only succeeds when empty
            }
        }
    }
    removed
}
