//! "Readable" buckets: the current version of every object is also exposed
//! as a plain file with its real name under `<disk 0>/<bucket>/<key>`, so the
//! data can be browsed and copied without BoxSpace.
//!
//! Files are independent of the stored data, so editing them can never
//! change what BoxSpace serves: they are copy-on-write clones (reflinks, no
//! extra space on btrfs/XFS) when possible, otherwise plain copies. They are
//! read-only: changes made directly on disk are not imported.

use std::{
    io,
    path::{Component, Path, PathBuf},
};

use futures::StreamExt;
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};

use crate::{
    blob,
    phys::Layout,
    storage::{ObjectVersion, Scan},
    App,
};

pub struct Views {
    locks: Vec<Mutex<()>>,
}

impl Default for Views {
    fn default() -> Self {
        Views { locks: (0..64).map(|_| Mutex::new(())).collect() }
    }
}

impl Views {
    fn lock(&self, bucket: &str, key: &str) -> &Mutex<()> {
        let h = crc32fast::hash(format!("{bucket}\0{key}").as_bytes()) as usize;
        &self.locks[h % self.locks.len()]
    }
}

pub fn bucket_root(app: &App, bucket: &str) -> PathBuf {
    app.disks.primary().root.join(bucket)
}

/// Map an object key to a safe path inside the bucket's view directory.
pub fn view_path(app: &App, bucket: &str, key: &str) -> Option<PathBuf> {
    let (body, is_dir) = match key.strip_suffix('/') {
        Some(b) => (b, true),
        None => (key, false),
    };
    if body.is_empty() {
        return None;
    }
    let mut p = bucket_root(app, bucket);
    for seg in body.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.len() > 255 || seg.contains('\0') {
            return None;
        }
        p.push(seg);
    }
    // Defensive: the result must stay inside the bucket root.
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    let _ = is_dir;
    Some(p)
}

/// Copy-on-write clone (Linux FICLONE). Fails on filesystems without reflink.
fn reflink(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        const FICLONE: libc::c_ulong = 0x4004_9409;
        let s = std::fs::File::open(src)?;
        let d = std::fs::File::create(dst)?;
        // SAFETY: both descriptors are valid for the duration of the call.
        let r = unsafe { libc::ioctl(d.as_raw_fd(), FICLONE as _, s.as_raw_fd()) };
        if r == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        drop(d);
        let _ = std::fs::remove_file(dst);
        Err(e)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (src, dst);
        Err(io::Error::other("reflink não suportado"))
    }
}

async fn set_readonly(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, std::fs::Permissions::from_mode(0o444)).await;
}

async fn prune(root: &Path, mut dir: &Path) {
    while dir != root && dir.starts_with(root) {
        if fs::remove_dir(dir).await.is_err() {
            break;
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
}

async fn materialize(app: &App, bucket: &str, v: &ObjectVersion, path: &Path) -> io::Result<()> {
    if v.key.ends_with('/') {
        return fs::create_dir_all(path).await;
    }
    if fs::metadata(path).await.map(|m| m.is_dir()).unwrap_or(false) {
        tracing::debug!("visão legível: {} é uma pasta; o objeto {} não será exibido", path.display(), v.key);
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent).await
    {
        tracing::debug!("visão legível: não foi possível criar {}: {e}", parent.display());
        return Ok(());
    }
    let tmp = app.disks.primary().tmp();
    let cloned = match &v.blob {
        Some(b) if b.enc.is_none() && b.layout().full_copy_on(0) => {
            let src = match b.layout() {
                Layout::Legacy { path } => app.disks.primary().sys.join(path),
                _ => app.disks.primary().obj_dir(bucket, &b.id).join("data"),
            };
            let dst = tmp.clone();
            tokio::task::spawn_blocking(move || reflink(&src, &dst)).await.map(|r| r.is_ok()).unwrap_or(false)
        }
        _ => false,
    };
    if cloned {
        set_readonly(&tmp).await;
    } else {
        let mut f = fs::File::create(&tmp).await?;
        let mut s = blob::open_full(app, bucket, v).await.map_err(|e| io::Error::other(e.message))?;
        while let Some(chunk) = s.next().await {
            f.write_all(&chunk?).await?;
        }
        f.flush().await?;
        set_readonly(&tmp).await;
    }
    fs::rename(&tmp, path).await.inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

async fn remove_view(app: &App, bucket: &str, key: &str, path: &Path) {
    let root = bucket_root(app, bucket);
    if key.ends_with('/') {
        let _ = fs::remove_dir(path).await;
    } else if fs::metadata(path).await.map(|m| m.is_file()).unwrap_or(false) {
        let _ = fs::remove_file(path).await;
    }
    if let Some(parent) = path.parent() {
        prune(&root, parent).await;
    }
}

/// Bring the readable file for `key` in line with its current version.
pub async fn refresh(app: &App, bucket: &str, key: &str) {
    let Ok(Some(bm)) = app.store.get_bucket(bucket) else { return };
    if !bm.readable || !app.disks.primary().online() {
        return;
    }
    let Some(path) = view_path(app, bucket, key) else { return };
    let _g = app.views.lock(bucket, key).lock().await;
    match app.store.get_version(bucket, key, None) {
        Ok(Some(v)) if !v.delete_marker && !v.encrypted() => {
            if let Err(e) = materialize(app, bucket, &v, &path).await {
                tracing::warn!("visão legível de {bucket}/{key}: {e}");
            }
        }
        Ok(_) => remove_view(app, bucket, key, &path).await,
        Err(e) => tracing::warn!("visão legível de {bucket}/{key}: {}", e.message),
    }
}

/// Create readable files for every current object in a bucket.
pub async fn backfill(app: &App, bucket: &str) {
    let mut keys = Vec::new();
    let mut last: Option<String> = None;
    let _ = app.store.scan(bucket, "", |v| {
        if last.as_deref() != Some(v.key.as_str()) {
            last = Some(v.key.clone());
            if !v.delete_marker {
                keys.push(v.key);
            }
        }
        Scan::Next
    });
    let _ = fs::create_dir_all(bucket_root(app, bucket)).await;
    let n = keys.len();
    for k in keys {
        refresh(app, bucket, &k).await;
    }
    tracing::info!("visão legível do bucket {bucket}: {n} arquivo(s) criados");
}

/// Remove the readable directory of a bucket.
pub async fn clear(app: &App, bucket: &str) {
    let root = bucket_root(app, bucket);
    if let Err(e) = fs::remove_dir_all(&root).await
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!("não foi possível remover {}: {e}", root.display());
    }
}
