//! Object data: optional SSE encryption on top of the physical layer
//! (single disk, mirror or erasure coding), and reading of multipart
//! objects stored as a list of segments.

use std::{io, pin::Pin, sync::Arc};

use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};
use md5::{Digest, Md5};
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;

use crate::{
    crypto::{self, Kms, CHUNK, TAG},
    disk::Disks,
    error::{Result, S3Error},
    phys::{self, Layout, PhysWriter},
    storage::{BlobRef, EncInfo, ObjectVersion},
    util::random_bytes,
    App,
};

pub type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

struct EncState {
    cipher: Aes256Gcm,
    prefix: [u8; 8],
    idx: u32,
    buf: Vec<u8>,
    info: EncInfo,
}

/// Streams plaintext into a new blob.
pub struct BlobWriter {
    phys: PhysWriter,
    md5: Md5,
    pub size: u64,
    enc: Option<EncState>,
}

impl BlobWriter {
    pub async fn create(app: &App, bucket: &str, encrypt: bool) -> Result<BlobWriter> {
        let phys = PhysWriter::create(&app.disks, bucket).await?;
        let enc = if encrypt {
            let (key, wrapped) = app.kms.new_data_key();
            let prefix = random_bytes::<8>();
            Some(EncState {
                cipher: crypto::cipher(&key),
                prefix,
                idx: 0,
                buf: Vec::with_capacity(CHUNK * 2),
                info: EncInfo { key: wrapped, nonce: B64.encode(prefix) },
            })
        } else {
            None
        };
        Ok(BlobWriter { phys, md5: Md5::new(), size: 0, enc })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.md5.update(data);
        self.size += data.len() as u64;
        match &mut self.enc {
            None => self.phys.write(data).await,
            Some(e) => {
                e.buf.extend_from_slice(data);
                // Keep the final chunk buffered so it can be sealed as "last".
                while e.buf.len() > CHUNK {
                    let rest = e.buf.split_off(CHUNK);
                    let chunk = std::mem::replace(&mut e.buf, rest);
                    let ct = crypto::seal(&e.cipher, &e.prefix, e.idx, false, &chunk);
                    e.idx += 1;
                    self.phys.write(&ct).await?;
                }
                Ok(())
            }
        }
    }

    pub async fn pipe(&mut self, mut s: ByteStream) -> Result<()> {
        while let Some(chunk) = s.next().await {
            self.write(&chunk.map_err(|e| S3Error::internal(format!("leitura da origem: {e}")))?).await?;
        }
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(BlobRef, [u8; 16])> {
        let mut info = None;
        if let Some(e) = &mut self.enc {
            let chunk = std::mem::take(&mut e.buf);
            let ct = crypto::seal(&e.cipher, &e.prefix, e.idx, true, &chunk);
            self.phys.write(&ct).await?;
            info = Some(e.info.clone());
        }
        let (layout, _) = self.phys.finish().await?;
        let md5: [u8; 16] = std::mem::take(&mut self.md5).finalize().into();
        Ok((BlobRef { id: self.phys.id.clone(), layout: Some(layout), path: None, size: self.size, enc: info }, md5))
    }
}

/// Stream plaintext bytes `start..=end` of one blob.
pub async fn open_blob(disks: Arc<Disks>, kms: Arc<Kms>, bucket: &str, blob: &BlobRef, start: u64, end: u64) -> Result<ByteStream> {
    if blob.size == 0 || start > end {
        return Ok(Box::pin(futures::stream::empty()));
    }
    let layout = blob.layout();
    let stored = blob.stored_len();
    let Some(enc) = &blob.enc else {
        return phys::open(&disks, bucket, &blob.id, &layout, stored, start, end).await;
    };
    let key = kms.unwrap_key(&enc.key).map_err(S3Error::internal)?;
    let prefix: [u8; 8] = B64
        .decode(&enc.nonce)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| S3Error::internal("invalid nonce"))?;
    let first = start / CHUNK as u64;
    let last = end / CHUNK as u64;
    let cs = first * (CHUNK + TAG) as u64;
    let ce = ((last + 1) * (CHUNK + TAG) as u64).min(stored) - 1;
    let raw = phys::open(&disks, bucket, &blob.id, &layout, stored, cs, ce).await?;
    let st = DecState {
        reader: StreamReader::new(raw),
        cipher: crypto::cipher(&key),
        prefix,
        idx: first,
        total: crypto::chunk_count(blob.size),
        size: blob.size,
        start,
        end,
    };
    Ok(Box::pin(futures::stream::try_unfold(st, dec_next)))
}

struct DecState {
    reader: StreamReader<ByteStream, Bytes>,
    cipher: Aes256Gcm,
    prefix: [u8; 8],
    idx: u64,
    total: u64,
    size: u64,
    start: u64,
    end: u64,
}

async fn dec_next(mut st: DecState) -> io::Result<Option<(Bytes, DecState)>> {
    let chunk_start = st.idx * CHUNK as u64;
    if st.idx >= st.total || chunk_start > st.end {
        return Ok(None);
    }
    let plain_len = std::cmp::min(CHUNK as u64, st.size - chunk_start) as usize;
    let mut ct = vec![0u8; plain_len + TAG];
    st.reader.read_exact(&mut ct).await?;
    let last = st.idx + 1 == st.total;
    let plain = crypto::open(&st.cipher, &st.prefix, st.idx as u32, last, &ct)
        .map_err(|_| io::Error::other("falha de autenticação ao decifrar o objeto"))?;
    let s = st.start.saturating_sub(chunk_start) as usize;
    let e = (std::cmp::min(st.end, chunk_start + plain_len as u64 - 1) - chunk_start) as usize;
    st.idx += 1;
    Ok(Some((Bytes::copy_from_slice(&plain[s..=e]), st)))
}

/// Stream plaintext bytes `start..=end` of an object version
/// (single blob or multipart segments).
pub async fn open(app: &App, bucket: &str, v: &ObjectVersion, start: u64, end: u64) -> Result<ByteStream> {
    if v.size == 0 || start > end {
        return Ok(Box::pin(futures::stream::empty()));
    }
    if let Some(b) = &v.blob {
        return open_blob(app.disks.clone(), app.kms.clone(), bucket, b, start, end).await;
    }
    // Segments overlapping the range, opened lazily one after another.
    let mut parts = Vec::new();
    let mut off = 0u64;
    for seg in &v.segments {
        let (s, e) = (off, off + seg.size);
        if seg.size > 0 && e > start && s <= end {
            parts.push((seg.clone(), start.max(s) - s, end.min(e - 1) - s));
        }
        off = e;
    }
    // Fail before any byte is sent if a segment cannot be read.
    for (seg, _, _) in &parts {
        let layout = seg.layout();
        if !matches!(layout, Layout::Legacy { .. }) && !phys::available(&app.disks, bucket, &seg.id, &layout).await {
            return Err(phys::unavailable());
        }
    }
    let (disks, kms, bucket) = (app.disks.clone(), app.kms.clone(), bucket.to_string());
    let stream = futures::stream::iter(parts)
        .then(move |(seg, s, e)| {
            let (disks, kms, bucket) = (disks.clone(), kms.clone(), bucket.clone());
            async move { open_blob(disks, kms, &bucket, &seg, s, e).await.map_err(|e| io::Error::other(e.message)) }
        })
        .try_flatten();
    Ok(Box::pin(stream))
}

pub async fn open_full(app: &App, bucket: &str, v: &ObjectVersion) -> Result<ByteStream> {
    open(app, bucket, v, 0, v.size.saturating_sub(1)).await
}

pub async fn remove_blob(app: &App, bucket: &str, b: &BlobRef) {
    match b.layout() {
        Layout::Legacy { path } => {
            let _ = tokio::fs::remove_file(app.disks.primary().sys.join(path)).await;
        }
        _ => phys::remove(&app.disks, bucket, &b.id).await,
    }
}

/// Remove a version's directory (meta.json) and all of its data.
pub async fn remove_version(app: &App, bucket: &str, v: &ObjectVersion) {
    for b in v.blobs() {
        remove_blob(app, bucket, b).await;
    }
    if !v.oid.is_empty() {
        phys::remove(&app.disks, bucket, &v.oid).await;
    }
}
