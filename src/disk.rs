//! The set of data disks and their on-disk format.
//!
//! Each disk directory holds a `.boxspace/` system folder:
//!   format.json       deployment id, disk index, redundancy mode
//!   objects/<bucket>/<aa>/<id>/   one directory per object version or blob
//!       meta.json     self-describing version metadata (written to every disk)
//!       data          full object data (single / mirror)
//!       shard         one erasure-coded shard (erasure)
//!   sys/              bucket configs and access keys (copied to every disk)
//!   tmp/              in-flight writes
//! Disk 0 additionally holds `meta.redb` (an index that can be rebuilt from
//! the meta.json files) and the audit log.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Single,
    Mirror,
    Erasure,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "single" => Some(Mode::Single),
            "mirror" | "espelho" => Some(Mode::Mirror),
            "erasure" | "ec" => Some(Mode::Erasure),
            _ => None,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Single => "single",
            Mode::Mirror => "mirror",
            Mode::Erasure => "erasure",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Format {
    pub version: u32,
    pub deployment: String,
    pub disk: usize,
    pub disks: usize,
    pub mode: Mode,
    pub parity: usize,
}

pub struct Disk {
    pub idx: usize,
    /// The directory given on the command line.
    pub root: PathBuf,
    /// `<root>/.boxspace`
    pub sys: PathBuf,
    online: AtomicBool,
}

impl Disk {
    pub fn online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    /// Record an I/O failure. Missing files are not disk failures.
    pub fn report(&self, e: &std::io::Error) {
        use std::io::ErrorKind::*;
        if !matches!(e.kind(), NotFound | AlreadyExists | InvalidInput | DirectoryNotEmpty) && self.online.swap(false, Ordering::Relaxed) {
            tracing::error!("disco {} ({}) ficou offline: {e}", self.idx, self.root.display());
        }
    }

    pub fn tmp(&self) -> PathBuf {
        self.sys.join("tmp").join(uuid::Uuid::new_v4().simple().to_string())
    }

    pub fn obj_dir(&self, bucket: &str, id: &str) -> PathBuf {
        self.sys.join("objects").join(bucket).join(&id[..2.min(id.len())]).join(id)
    }

    pub fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.sys.join("objects").join(bucket)
    }

    pub fn sys_dir(&self) -> PathBuf {
        self.sys.join("sys")
    }

    fn healthy(&self) -> bool {
        std::fs::read(self.sys.join("format.json")).is_ok()
    }

    /// (free, total) bytes on the filesystem holding this disk.
    pub fn space(&self) -> Option<(u64, u64)> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(self.root.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is a valid NUL-terminated path and `st` a valid out-pointer.
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        let frsize = st.f_frsize as u64;
        Some((st.f_bavail as u64 * frsize, st.f_blocks as u64 * frsize))
    }
}

pub struct Disks {
    pub list: Vec<Disk>,
    pub mode: Mode,
    pub parity: usize,
    pub deployment: String,
    /// Disks that were freshly formatted into an existing deployment.
    pub replaced: Vec<usize>,
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

impl Disks {
    pub fn open(paths: &[PathBuf], requested: Option<Mode>, parity: Option<usize>) -> Result<Disks, String> {
        let n = paths.len();
        if n == 0 {
            return Err("informe ao menos um diretório de dados".into());
        }
        let mut formats: Vec<Option<Format>> = Vec::with_capacity(n);
        for p in paths {
            std::fs::create_dir_all(p.join(".boxspace")).map_err(|e| format!("{}: {e}", p.display()))?;
            let f = match std::fs::read(p.join(".boxspace/format.json")) {
                Ok(b) => Some(serde_json::from_slice::<Format>(&b).map_err(|e| format!("{}: format.json inválido: {e}", p.display()))?),
                Err(_) => None,
            };
            formats.push(f);
        }
        let existing: Vec<&Format> = formats.iter().flatten().collect();
        let (deployment, mode, par, mut replaced) = if let Some(first) = existing.first() {
            for f in &existing {
                if f.deployment != first.deployment {
                    return Err("os diretórios pertencem a instalações diferentes do BoxSpace".into());
                }
            }
            if first.disks != n {
                return Err(format!(
                    "esta instalação foi criada com {} disco(s), mas {} foram informados; não é possível adicionar ou remover discos",
                    first.disks, n
                ));
            }
            for (i, f) in formats.iter().enumerate() {
                if let Some(f) = f
                    && f.disk != i
                {
                    return Err(format!(
                        "o diretório {} é o disco {} desta instalação, mas foi informado na posição {}; mantenha a ordem original",
                        paths[i].display(),
                        f.disk,
                        i
                    ));
                }
            }
            if let Some(r) = requested
                && r != first.mode
            {
                return Err(format!("esta instalação usa o modo {}; não é possível mudar para {}", first.mode.label(), r.label()));
            }
            (first.deployment.clone(), first.mode, first.parity, Vec::new())
        } else {
            let mode = requested.unwrap_or(if n == 1 { Mode::Single } else { Mode::Mirror });
            let par = match mode {
                Mode::Single => {
                    if n != 1 {
                        return Err("o modo single usa exatamente um disco".into());
                    }
                    0
                }
                Mode::Mirror => {
                    if n < 2 {
                        return Err("o modo mirror precisa de pelo menos 2 discos".into());
                    }
                    0
                }
                Mode::Erasure => {
                    if n < 3 {
                        return Err("o modo erasure precisa de pelo menos 3 discos".into());
                    }
                    if n > 32 {
                        return Err("o modo erasure suporta até 32 discos".into());
                    }
                    let p = parity.unwrap_or(n / 2);
                    if p == 0 || p > n / 2 {
                        return Err(format!("a paridade deve ficar entre 1 e {} para {n} discos", n / 2));
                    }
                    p
                }
            };
            (uuid::Uuid::new_v4().to_string(), mode, par, Vec::new())
        };

        let mut list = Vec::with_capacity(n);
        for (i, p) in paths.iter().enumerate() {
            let sys = p.join(".boxspace");
            if formats[i].is_none() {
                if !existing.is_empty() {
                    tracing::warn!("disco {} ({}) é novo ou foi substituído; os dados serão reconstruídos", i, p.display());
                    replaced.push(i);
                }
                let f = Format { version: 1, deployment: deployment.clone(), disk: i, disks: n, mode, parity: par };
                write_atomic(&sys.join("format.json"), &serde_json::to_vec_pretty(&f).unwrap()).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            for d in ["tmp", "objects", "sys"] {
                std::fs::create_dir_all(sys.join(d)).map_err(|e| format!("{}: {e}", sys.join(d).display()))?;
            }
            if let Ok(rd) = std::fs::read_dir(sys.join("tmp")) {
                for e in rd.flatten() {
                    let _ = std::fs::remove_file(e.path()).or_else(|_| std::fs::remove_dir_all(e.path()));
                }
            }
            list.push(Disk { idx: i, root: p.clone(), sys, online: AtomicBool::new(true) });
        }
        Ok(Disks { list, mode, parity: par, deployment, replaced })
    }

    pub fn primary(&self) -> &Disk {
        &self.list[0]
    }

    pub fn meta_dir(&self) -> &Path {
        &self.list[0].sys
    }

    pub fn get(&self, i: usize) -> Option<&Disk> {
        self.list.get(i)
    }

    pub fn online(&self) -> impl Iterator<Item = &Disk> {
        self.list.iter().filter(|d| d.online())
    }

    pub fn online_count(&self) -> usize {
        self.online().count()
    }

    pub fn data_shards(&self) -> usize {
        self.list.len() - self.parity
    }

    /// Minimum number of disks that must accept a write.
    pub fn write_quorum(&self) -> usize {
        match self.mode {
            Mode::Single | Mode::Mirror => 1,
            Mode::Erasure => (self.data_shards() + 1).min(self.list.len()),
        }
    }

    pub fn writable(&self) -> bool {
        self.online_count() >= self.write_quorum()
    }

    /// Bring disks back online once their format file is readable again.
    /// Returns the indexes that came back.
    pub fn recheck(&self) -> Vec<usize> {
        let mut back = Vec::new();
        for d in &self.list {
            if !d.online() && d.healthy() {
                d.online.store(true, Ordering::Relaxed);
                tracing::info!("disco {} ({}) voltou a ficar online", d.idx, d.root.display());
                back.push(d.idx);
            } else if d.online() && !d.healthy() {
                d.report(&std::io::Error::other("format.json ilegível"));
            }
        }
        back
    }
}
