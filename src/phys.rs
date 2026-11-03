//! Physical storage of a byte stream across disks: single copy, mirrored
//! copies, or Reed-Solomon erasure coding.
//!
//! Erasure layout: the stream is cut into blocks of `data * chunk` bytes.
//! Each block is split into `data` equal shards (zero padded), `parity`
//! shards are computed, and shard `i` is appended to the shard file on disk
//! `disks[i]` followed by its CRC32. Any `data` intact shards rebuild a block,
//! and CRC mismatches (bitrot) are treated as missing shards.

use std::{io, path::PathBuf, sync::Arc};

use bytes::Bytes;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter},
};
use tokio_util::io::ReaderStream;

use crate::{
    blob::ByteStream,
    disk::{Disks, Mode},
    error::{Result, S3Error},
};

pub const EC_CHUNK: usize = 1 << 20;
const CRC_LEN: usize = 4;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Layout {
    Single { disk: usize },
    Mirror { disks: Vec<usize> },
    Erasure { data: usize, parity: usize, disks: Vec<usize>, chunk: usize },
    /// Files written before multi-disk support (path relative to disk 0's `.boxspace`).
    Legacy { path: String },
}

impl Layout {
    pub fn file_name(&self) -> &'static str {
        match self {
            Layout::Erasure { .. } => "shard",
            _ => "data",
        }
    }

    pub fn disks(&self) -> Vec<usize> {
        match self {
            Layout::Single { disk } => vec![*disk],
            Layout::Mirror { disks } | Layout::Erasure { disks, .. } => disks.clone(),
            Layout::Legacy { .. } => vec![0],
        }
    }

    /// Does disk `d` hold a complete, directly readable copy?
    pub fn full_copy_on(&self, d: usize) -> bool {
        match self {
            Layout::Single { disk } => *disk == d,
            Layout::Mirror { disks } => disks.contains(&d),
            Layout::Legacy { .. } => d == 0,
            Layout::Erasure { .. } => false,
        }
    }
}

pub fn unavailable() -> S3Error {
    S3Error::new("SlowDown", 503, "Not enough disks are online to serve this request. Please retry.")
}

/// Expected size of one shard file for `len` stored bytes.
pub fn shard_file_len(len: u64, data: usize, chunk: usize) -> u64 {
    if len == 0 {
        return 0;
    }
    let bs = (data * chunk) as u64;
    let mut s = (len / bs) * (chunk + CRC_LEN) as u64;
    let rest = len % bs;
    if rest > 0 {
        s += rest.div_ceil(data as u64) + CRC_LEN as u64;
    }
    s
}

fn shard_split(block: &[u8], d: usize, p: usize) -> Vec<Vec<u8>> {
    let sl = block.len().div_ceil(d);
    (0..d + p)
        .map(|i| {
            let mut v = if i < d && i * sl < block.len() { block[i * sl..((i + 1) * sl).min(block.len())].to_vec() } else { Vec::new() };
            v.resize(sl, 0);
            v
        })
        .collect()
}

// ------------------------------------------------------------- writer ----

struct Slot {
    disk: usize,
    tmp: PathBuf,
    file: Option<BufWriter<File>>,
}

pub struct PhysWriter {
    disks: Arc<Disks>,
    bucket: String,
    pub id: String,
    pub layout: Layout,
    slots: Vec<Slot>,
    ec: Option<(ReedSolomon, Vec<u8>)>,
    pub len: u64,
    quorum: usize,
    done: bool,
}

impl PhysWriter {
    pub async fn create(disks: &Arc<Disks>, bucket: &str) -> Result<PhysWriter> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let n = disks.list.len();
        let (layout, targets, quorum, ec) = match disks.mode {
            Mode::Single => (Layout::Single { disk: 0 }, vec![0], 1, None),
            Mode::Mirror => (Layout::Mirror { disks: (0..n).collect() }, (0..n).collect(), 1, None),
            Mode::Erasure => {
                let p = disks.parity;
                let d = n - p;
                let start = crc32fast::hash(id.as_bytes()) as usize % n;
                let order: Vec<usize> = (0..n).map(|i| (start + i) % n).collect();
                let rs = ReedSolomon::new(d, p).map_err(|e| S3Error::internal(format!("{e:?}")))?;
                (
                    Layout::Erasure { data: d, parity: p, disks: order.clone(), chunk: EC_CHUNK },
                    order,
                    disks.write_quorum(),
                    Some((rs, Vec::with_capacity(d * EC_CHUNK))),
                )
            }
        };
        let mut slots = Vec::with_capacity(targets.len());
        for d in targets {
            let disk = &disks.list[d];
            let tmp = disk.tmp();
            let file = if disk.online() {
                match File::create(&tmp).await {
                    Ok(f) => Some(BufWriter::with_capacity(256 * 1024, f)),
                    Err(e) => {
                        disk.report(&e);
                        None
                    }
                }
            } else {
                None
            };
            slots.push(Slot { disk: d, tmp, file });
        }
        let w = PhysWriter { disks: disks.clone(), bucket: bucket.to_string(), id, layout, slots, ec, len: 0, quorum, done: false };
        w.check_quorum()?;
        Ok(w)
    }

    fn check_quorum(&self) -> Result<()> {
        if self.slots.iter().filter(|s| s.file.is_some()).count() < self.quorum {
            return Err(unavailable());
        }
        Ok(())
    }

    async fn write_all(&mut self, i: usize, parts: &[&[u8]]) {
        let slot = &mut self.slots[i];
        if let Some(f) = &mut slot.file {
            for p in parts {
                if let Err(e) = f.write_all(p).await {
                    self.disks.list[slot.disk].report(&e);
                    slot.file = None;
                    return;
                }
            }
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.len += data.len() as u64;
        match &mut self.ec {
            None => {
                for i in 0..self.slots.len() {
                    self.write_all(i, &[data]).await;
                }
            }
            Some((rs, buf)) => {
                buf.extend_from_slice(data);
                let bs = rs.data_shard_count() * EC_CHUNK;
                while self.ec.as_ref().is_some_and(|(_, b)| b.len() >= bs) {
                    let block: Vec<u8> = self.ec.as_mut().unwrap().1.drain(..bs).collect();
                    self.write_block(&block).await?;
                }
            }
        }
        self.check_quorum()
    }

    async fn write_block(&mut self, block: &[u8]) -> Result<()> {
        let shards = {
            let (rs, _) = self.ec.as_ref().expect("erasure writer");
            let mut shards = shard_split(block, rs.data_shard_count(), rs.parity_shard_count());
            rs.encode(&mut shards).map_err(|e| S3Error::internal(format!("{e:?}")))?;
            shards
        };
        for (i, s) in shards.iter().enumerate() {
            let crc = crc32fast::hash(s).to_be_bytes();
            self.write_all(i, &[s, &crc]).await;
        }
        self.check_quorum()
    }

    /// Flush, sync and move every copy/shard into place.
    pub async fn finish(&mut self) -> Result<(Layout, u64)> {
        if let Some((_, buf)) = &mut self.ec {
            let rest = std::mem::take(buf);
            if !rest.is_empty() {
                self.write_block(&rest).await?;
            }
        }
        let name = self.layout.file_name();
        let mut ok = 0;
        for slot in &mut self.slots {
            let disk = &self.disks.list[slot.disk];
            let Some(f) = &mut slot.file else { continue };
            let r: io::Result<()> = async {
                f.flush().await?;
                f.get_ref().sync_data().await?;
                let dir = disk.obj_dir(&self.bucket, &self.id);
                tokio::fs::create_dir_all(&dir).await?;
                let dest = dir.join(name);
                tokio::fs::rename(&slot.tmp, &dest).await?;
                let _ = set_readonly(&dest).await;
                Ok(())
            }
            .await;
            match r {
                Ok(()) => ok += 1,
                Err(e) => {
                    disk.report(&e);
                    slot.file = None;
                }
            }
        }
        if ok < self.quorum {
            remove(&self.disks, &self.bucket, &self.id).await;
            return Err(unavailable());
        }
        self.done = true;
        Ok((self.layout.clone(), self.len))
    }
}

impl Drop for PhysWriter {
    fn drop(&mut self) {
        if !self.done {
            for s in &self.slots {
                let _ = std::fs::remove_file(&s.tmp);
            }
        }
    }
}

async fn set_readonly(p: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(p, std::fs::Permissions::from_mode(0o444)).await
}

/// Remove a blob/version directory from every disk.
pub async fn remove(disks: &Disks, bucket: &str, id: &str) {
    for d in disks.online() {
        let dir = d.obj_dir(bucket, id);
        if let Err(e) = tokio::fs::remove_dir_all(&dir).await
            && e.kind() != io::ErrorKind::NotFound
        {
            d.report(&e);
        }
        // Prune the two-character fan-out directory when it becomes empty.
        if let Some(parent) = dir.parent() {
            let _ = tokio::fs::remove_dir(parent).await;
        }
    }
}

// ------------------------------------------------------------- reader ----

fn path_for(disks: &Disks, bucket: &str, id: &str, layout: &Layout, pos: usize) -> PathBuf {
    match layout {
        Layout::Legacy { path } => disks.primary().sys.join(path),
        _ => disks.list[layout.disks()[pos]].obj_dir(bucket, id).join(layout.file_name()),
    }
}

/// Are enough copies/shards present to read this blob? (cheap metadata check)
pub async fn available(disks: &Disks, bucket: &str, id: &str, layout: &Layout) -> bool {
    let needed = match layout {
        Layout::Erasure { data, .. } => *data,
        _ => 1,
    };
    let mut found = 0;
    for (pos, d) in layout.disks().iter().enumerate() {
        if disks.list[*d].online() && tokio::fs::metadata(path_for(disks, bucket, id, layout, pos)).await.is_ok() {
            found += 1;
            if found >= needed {
                return true;
            }
        }
    }
    false
}

/// Stream stored bytes `start..=end` of a blob.
pub async fn open(disks: &Arc<Disks>, bucket: &str, id: &str, layout: &Layout, len: u64, start: u64, end: u64) -> Result<ByteStream> {
    if len == 0 || start > end {
        return Ok(Box::pin(futures::stream::empty()));
    }
    match layout {
        Layout::Erasure { data, parity, chunk, .. } => {
            if !available(disks, bucket, id, layout).await {
                return Err(unavailable());
            }
            let n = data + parity;
            let paths = (0..n).map(|i| path_for(disks, bucket, id, layout, i)).collect();
            let rs = ReedSolomon::new(*data, *parity).map_err(|e| S3Error::internal(format!("{e:?}")))?;
            let st = EcRead {
                disks: disks.clone(),
                disk_of: layout.disks(),
                paths,
                files: (0..n).map(|_| None).collect(),
                failed: vec![false; n],
                rs,
                d: *data,
                chunk: *chunk,
                len,
                block: start / (*data * *chunk) as u64,
                start,
                end,
            };
            Ok(Box::pin(futures::stream::try_unfold(st, ec_next)))
        }
        _ => {
            let positions = layout.disks();
            // Online disks first.
            let mut order: Vec<usize> = (0..positions.len()).collect();
            order.sort_by_key(|p| !disks.list[positions[*p]].online());
            for pos in order {
                let path = path_for(disks, bucket, id, layout, pos);
                let disk = &disks.list[positions[pos]];
                let opened: io::Result<File> = async {
                    let mut f = File::open(&path).await?;
                    if f.metadata().await?.len() != len {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "tamanho inesperado"));
                    }
                    f.seek(io::SeekFrom::Start(start)).await?;
                    Ok(f)
                }
                .await;
                match opened {
                    Ok(f) => return Ok(Box::pin(ReaderStream::with_capacity(f.take(end - start + 1), 256 * 1024))),
                    Err(e) => {
                        if e.kind() != io::ErrorKind::InvalidData {
                            disk.report(&e);
                        }
                        tracing::warn!("cópia indisponível em {}: {e}", path.display());
                    }
                }
            }
            Err(unavailable())
        }
    }
}

struct EcRead {
    disks: Arc<Disks>,
    disk_of: Vec<usize>,
    paths: Vec<PathBuf>,
    files: Vec<Option<File>>,
    failed: Vec<bool>,
    rs: ReedSolomon,
    d: usize,
    chunk: usize,
    len: u64,
    block: u64,
    start: u64,
    end: u64,
}

/// Read one shard chunk of a block, verifying its CRC.
#[allow(clippy::too_many_arguments)]
async fn read_chunk(files: &mut [Option<File>], failed: &mut [bool], paths: &[PathBuf], disks: &Disks, disk_of: &[usize], i: usize, off: u64, sl: usize) -> Option<Vec<u8>> {
    if failed[i] {
        return None;
    }
    if files[i].is_none() {
        match File::open(&paths[i]).await {
            Ok(f) => files[i] = Some(f),
            Err(e) => {
                disks.list[disk_of[i]].report(&e);
                failed[i] = true;
                return None;
            }
        }
    }
    let f = files[i].as_mut()?;
    let mut buf = vec![0u8; sl + CRC_LEN];
    let r: io::Result<()> = async {
        f.seek(io::SeekFrom::Start(off)).await?;
        f.read_exact(&mut buf).await?;
        Ok(())
    }
    .await;
    if let Err(e) = r {
        if e.kind() != io::ErrorKind::UnexpectedEof {
            disks.list[disk_of[i]].report(&e);
            failed[i] = true;
        }
        return None;
    }
    let crc = u32::from_be_bytes(buf[sl..].try_into().unwrap());
    buf.truncate(sl);
    if crc32fast::hash(&buf) != crc {
        tracing::warn!("bitrot detectado em {} (offset {off}); usando paridade", paths[i].display());
        return None;
    }
    Some(buf)
}

/// Read and decode one block; returns its shards.
#[allow(clippy::needless_range_loop)]
async fn read_block(st: &mut EcRead, b: u64, all: bool) -> io::Result<Vec<Option<Vec<u8>>>> {
    let n = st.paths.len();
    let bs = (st.d * st.chunk) as u64;
    let blen = (bs.min(st.len - b * bs)) as usize;
    let sl = blen.div_ceil(st.d);
    let off = b * (st.chunk + CRC_LEN) as u64;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut have = 0;
    for i in 0..n {
        if have >= st.d && !all {
            break;
        }
        if let Some(v) = read_chunk(&mut st.files, &mut st.failed, &st.paths, &st.disks, &st.disk_of, i, off, sl).await {
            shards[i] = Some(v);
            have += 1;
        }
    }
    if have < st.d {
        return Err(io::Error::other(format!("só {have} de {} fragmentos disponíveis; não é possível reconstruir", st.d)));
    }
    let missing_data = shards[..st.d].iter().any(Option::is_none);
    if all && shards.iter().any(Option::is_none) {
        st.rs.reconstruct(&mut shards).map_err(|e| io::Error::other(format!("{e:?}")))?;
    } else if missing_data {
        st.rs.reconstruct_data(&mut shards).map_err(|e| io::Error::other(format!("{e:?}")))?;
    }
    Ok(shards)
}

async fn ec_next(mut st: EcRead) -> io::Result<Option<(Bytes, EcRead)>> {
    let bs = (st.d * st.chunk) as u64;
    let b = st.block;
    let bstart = b * bs;
    if bstart > st.end || bstart >= st.len {
        return Ok(None);
    }
    let blen = (bs.min(st.len - bstart)) as usize;
    let shards = read_block(&mut st, b, false).await?;
    let mut out = Vec::with_capacity(blen + st.chunk);
    for s in shards.into_iter().take(st.d) {
        out.extend_from_slice(&s.expect("reconstructed"));
    }
    out.truncate(blen);
    let s = st.start.saturating_sub(bstart) as usize;
    let e = (st.end.min(bstart + blen as u64 - 1) - bstart) as usize;
    st.block += 1;
    Ok(Some((Bytes::copy_from_slice(&out[s..=e]), st)))
}

// --------------------------------------------------------- check/heal ----

#[derive(Debug, Default)]
pub struct Check {
    /// Layout positions that need repair (on online disks).
    pub bad: Vec<usize>,
    /// Data can no longer be reconstructed.
    pub lost: bool,
}

/// Verify presence and size of every copy/shard; `deep` also verifies CRCs.
pub async fn check(disks: &Arc<Disks>, bucket: &str, id: &str, layout: &Layout, len: u64, deep: bool) -> Check {
    let mut c = Check::default();
    let positions = layout.disks();
    let expected = match layout {
        Layout::Erasure { data, chunk, .. } => shard_file_len(len, *data, *chunk),
        _ => len,
    };
    let mut good = 0;
    for (pos, d) in positions.iter().enumerate() {
        let disk = &disks.list[*d];
        if !disk.online() {
            continue;
        }
        let path = path_for(disks, bucket, id, layout, pos);
        let ok = match tokio::fs::metadata(&path).await {
            Ok(m) => m.len() == expected,
            Err(_) => false,
        };
        let ok = if ok && deep {
            if let Layout::Erasure { data, chunk, .. } = layout {
                verify_shard_file(&path, len, *data, *chunk).await
            } else {
                true
            }
        } else {
            ok
        };
        if ok {
            good += 1;
        } else {
            c.bad.push(pos);
        }
    }
    let needed = match layout {
        Layout::Erasure { data, .. } => *data,
        _ => 1,
    };
    c.lost = good < needed;
    if matches!(layout, Layout::Single { .. } | Layout::Legacy { .. }) {
        c.bad.clear(); // nothing to heal from
    }
    c
}

async fn verify_shard_file(path: &std::path::Path, len: u64, d: usize, chunk: usize) -> bool {
    let Ok(mut f) = File::open(path).await else { return false };
    let bs = (d * chunk) as u64;
    let mut off = 0u64;
    while off < len {
        let blen = bs.min(len - off) as usize;
        let sl = blen.div_ceil(d);
        let mut buf = vec![0u8; sl + CRC_LEN];
        if f.read_exact(&mut buf).await.is_err() {
            return false;
        }
        let crc = u32::from_be_bytes(buf[sl..].try_into().unwrap());
        if crc32fast::hash(&buf[..sl]) != crc {
            return false;
        }
        off += blen as u64;
    }
    true
}

/// Rebuild the copies/shards at `positions` from the healthy ones.
pub async fn heal(disks: &Arc<Disks>, bucket: &str, id: &str, layout: &Layout, len: u64, positions: &[usize]) -> Result<()> {
    let name = layout.file_name();
    let targets: Vec<(usize, PathBuf)> = positions.iter().map(|p| (*p, disks.list[layout.disks()[*p]].tmp())).collect();
    let result: io::Result<()> = async {
        match layout {
            Layout::Mirror { .. } => {
                let mut src = open(disks, bucket, id, layout, len, 0, len.saturating_sub(1)).await.map_err(|e| io::Error::other(e.message))?;
                let mut files = Vec::new();
                for (_, tmp) in &targets {
                    files.push(BufWriter::new(File::create(tmp).await?));
                }
                use futures::StreamExt;
                while let Some(chunk) = src.next().await {
                    let chunk = chunk?;
                    for f in &mut files {
                        f.write_all(&chunk).await?;
                    }
                }
                for f in &mut files {
                    f.flush().await?;
                    f.get_ref().sync_data().await?;
                }
            }
            Layout::Erasure { data, parity, chunk, .. } => {
                let n = data + parity;
                let mut st = EcRead {
                    disks: disks.clone(),
                    disk_of: layout.disks(),
                    paths: (0..n).map(|i| path_for(disks, bucket, id, layout, i)).collect(),
                    files: (0..n).map(|_| None).collect(),
                    failed: vec![false; n],
                    rs: ReedSolomon::new(*data, *parity).map_err(|e| io::Error::other(format!("{e:?}")))?,
                    d: *data,
                    chunk: *chunk,
                    len,
                    block: 0,
                    start: 0,
                    end: len.saturating_sub(1),
                };
                // Never read from the shards being replaced.
                for p in positions {
                    st.failed[*p] = true;
                }
                let mut files = Vec::new();
                for (_, tmp) in &targets {
                    files.push(BufWriter::new(File::create(tmp).await?));
                }
                let blocks = if len == 0 { 0 } else { len.div_ceil((data * chunk) as u64) };
                for b in 0..blocks {
                    let shards = read_block(&mut st, b, true).await?;
                    for (k, (p, _)) in targets.iter().enumerate() {
                        let s = shards[*p].as_ref().expect("reconstructed");
                        files[k].write_all(s).await?;
                        files[k].write_all(&crc32fast::hash(s).to_be_bytes()).await?;
                    }
                }
                for f in &mut files {
                    f.flush().await?;
                    f.get_ref().sync_data().await?;
                }
            }
            _ => return Err(io::Error::other("layout sem redundância")),
        }
        for (p, tmp) in &targets {
            let dir = disks.list[layout.disks()[*p]].obj_dir(bucket, id);
            tokio::fs::create_dir_all(&dir).await?;
            let dest = dir.join(name);
            let _ = tokio::fs::remove_file(&dest).await;
            tokio::fs::rename(tmp, &dest).await?;
            let _ = set_readonly(&dest).await;
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        for (_, tmp) in &targets {
            let _ = tokio::fs::remove_file(tmp).await;
        }
    }
    result.map_err(|e| S3Error::internal(format!("heal {bucket}/{id}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_sizes() {
        assert_eq!(shard_file_len(0, 2, 4), 0);
        assert_eq!(shard_file_len(8, 2, 4), 4 + 4); // one full block
        assert_eq!(shard_file_len(9, 2, 4), 8 + 1 + 4); // + 1-byte block
        assert_eq!(shard_file_len(3, 2, 4), 2 + 4);
    }

    #[test]
    fn rs_roundtrip() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let block = b"hello erasure coding!".to_vec();
        let mut shards = shard_split(&block, 3, 2);
        rs.encode(&mut shards).unwrap();
        let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        opt[0] = None;
        opt[4] = None;
        rs.reconstruct(&mut opt).unwrap();
        let joined: Vec<u8> = opt[..3].iter().flat_map(|s| s.clone().unwrap()).collect();
        assert_eq!(&joined[..block.len()], &block[..]);
    }
}
