//! Writing and reading object data files, with optional SSE encryption.

use std::{io, path::PathBuf, pin::Pin};

use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use md5::{Digest, Md5};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter},
};
use tokio_util::io::ReaderStream;

use crate::{
    crypto::{self, CHUNK, TAG},
    error::{Result, S3Error},
    storage::{BlobRef, EncInfo},
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

/// Streams data into a temporary file; `finish` moves it into place.
pub struct BlobWriter {
    file: BufWriter<File>,
    tmp: PathBuf,
    md5: Md5,
    pub size: u64,
    enc: Option<EncState>,
    done: bool,
}

impl BlobWriter {
    pub async fn create(app: &App, encrypt: bool) -> Result<BlobWriter> {
        let tmp = app.store.tmp_path();
        let file = BufWriter::with_capacity(256 * 1024, File::create(&tmp).await?);
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
        Ok(BlobWriter { file, tmp, md5: Md5::new(), size: 0, enc, done: false })
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.md5.update(data);
        self.size += data.len() as u64;
        match &mut self.enc {
            None => self.file.write_all(data).await?,
            Some(e) => {
                e.buf.extend_from_slice(data);
                // Keep the final chunk buffered so it can be sealed as "last".
                while e.buf.len() > CHUNK {
                    let rest = e.buf.split_off(CHUNK);
                    let chunk = std::mem::replace(&mut e.buf, rest);
                    let ct = crypto::seal(&e.cipher, &e.prefix, e.idx, false, &chunk);
                    e.idx += 1;
                    self.file.write_all(&ct).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn pipe(&mut self, mut s: ByteStream) -> Result<()> {
        while let Some(chunk) = s.next().await {
            self.write(&chunk?).await?;
        }
        Ok(())
    }

    /// Finalize and move the data to `rel` (relative to the meta dir).
    pub async fn finish(&mut self, app: &App, rel: &str) -> Result<(BlobRef, [u8; 16])> {
        let mut info = None;
        if let Some(e) = &mut self.enc {
            let chunk = std::mem::take(&mut e.buf);
            let ct = crypto::seal(&e.cipher, &e.prefix, e.idx, true, &chunk);
            self.file.write_all(&ct).await?;
            info = Some(e.info.clone());
        }
        self.file.flush().await?;
        self.file.get_ref().sync_data().await?;
        let dest = app.store.abs(rel);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&self.tmp, &dest).await?;
        self.done = true;
        let md5: [u8; 16] = std::mem::take(&mut self.md5).finalize().into();
        Ok((BlobRef { path: rel.to_string(), size: self.size, enc: info }, md5))
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Open a stream over plaintext bytes `start..=end` of a blob.
pub async fn open(app: &App, blob: &BlobRef, start: u64, end: u64) -> Result<ByteStream> {
    if blob.size == 0 || start > end {
        return Ok(Box::pin(futures::stream::empty()));
    }
    let path = app.store.abs(&blob.path);
    let mut file = File::open(&path).await?;
    match &blob.enc {
        None => {
            file.seek(io::SeekFrom::Start(start)).await?;
            Ok(Box::pin(ReaderStream::with_capacity(file.take(end - start + 1), 256 * 1024)))
        }
        Some(enc) => {
            let key = app.kms.unwrap_key(&enc.key).map_err(S3Error::internal)?;
            let prefix: [u8; 8] = B64
                .decode(&enc.nonce)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| S3Error::internal("invalid nonce"))?;
            let first = start / CHUNK as u64;
            file.seek(io::SeekFrom::Start(first * (CHUNK + TAG) as u64)).await?;
            let st = DecState {
                file,
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
    }
}

pub async fn open_full(app: &App, blob: &BlobRef) -> Result<ByteStream> {
    open(app, blob, 0, blob.size.saturating_sub(1)).await
}

struct DecState {
    file: File,
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
    st.file.read_exact(&mut ct).await?;
    let last = st.idx + 1 == st.total;
    let plain = crypto::open(&st.cipher, &st.prefix, st.idx as u32, last, &ct)
        .map_err(|_| io::Error::other("falha de autenticação ao decifrar o objeto"))?;
    let s = st.start.saturating_sub(chunk_start) as usize;
    let e = (std::cmp::min(st.end, chunk_start + plain_len as u64 - 1) - chunk_start) as usize;
    st.idx += 1;
    Ok(Some((Bytes::copy_from_slice(&plain[s..=e]), st)))
}

pub async fn remove(app: &App, blobs: impl IntoIterator<Item = BlobRef>) {
    for b in blobs {
        if let Err(e) = tokio::fs::remove_file(app.store.abs(&b.path)).await
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!("não foi possível remover {}: {e}", b.path);
        }
    }
}
