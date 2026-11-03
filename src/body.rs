//! Request body ingestion: plain, SHA-256 verified, and aws-chunked
//! (signed or unsigned streaming, with optional trailing checksums).

use std::io;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use sha2::{Digest, Sha256};

use crate::{
    auth::{ChunkSigner, Payload, EMPTY_SHA},
    blob::BlobWriter,
    error::{Result, S3Error},
    util::{ct_eq, hmac, sha256_hex},
};

const MAX_CHUNK: usize = 64 * 1024 * 1024;

enum St {
    Header,
    Data(usize, Option<String>),
    Trailer,
    Final,
}

pub struct ChunkDecoder {
    buf: Vec<u8>,
    state: St,
    signer: Option<ChunkSigner>,
    crc: crc32fast::Hasher,
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

fn malformed() -> S3Error {
    S3Error::invalid_argument("malformed aws-chunked body")
}

impl ChunkDecoder {
    pub fn new(signer: Option<ChunkSigner>) -> Self {
        ChunkDecoder { buf: Vec::new(), state: St::Header, signer, crc: crc32fast::Hasher::new() }
    }

    /// Feed raw bytes; decoded payload is appended to `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.buf.extend_from_slice(data);
        loop {
            match std::mem::replace(&mut self.state, St::Final) {
                St::Header => {
                    let Some(pos) = find_crlf(&self.buf) else {
                        if self.buf.len() > 4096 {
                            return Err(malformed());
                        }
                        self.state = St::Header;
                        return Ok(());
                    };
                    let line = std::str::from_utf8(&self.buf[..pos]).map_err(|_| malformed())?.to_string();
                    self.buf.drain(..pos + 2);
                    let (size_s, ext) = match line.split_once(';') {
                        Some((a, b)) => (a, Some(b)),
                        None => (line.as_str(), None),
                    };
                    let size = usize::from_str_radix(size_s.trim(), 16).map_err(|_| malformed())?;
                    if size > MAX_CHUNK {
                        return Err(malformed());
                    }
                    let sig = ext.and_then(|e| e.trim().strip_prefix("chunk-signature=")).map(str::to_string);
                    if size == 0 {
                        self.verify(&[], sig.as_deref())?;
                        self.state = St::Trailer;
                        continue;
                    }
                    self.state = St::Data(size, sig);
                }
                St::Data(size, sig) => {
                    if self.buf.len() < size + 2 {
                        self.state = St::Data(size, sig);
                        return Ok(());
                    }
                    if &self.buf[size..size + 2] != b"\r\n" {
                        return Err(malformed());
                    }
                    let chunk: Vec<u8> = self.buf.drain(..size).collect();
                    self.buf.drain(..2);
                    self.verify(&chunk, sig.as_deref())?;
                    self.crc.update(&chunk);
                    out.extend_from_slice(&chunk);
                    self.state = St::Header;
                }
                s @ (St::Trailer | St::Final) => {
                    self.state = s;
                    return Ok(());
                }
            }
        }
    }

    fn verify(&mut self, chunk: &[u8], sig: Option<&str>) -> Result<()> {
        if let Some(s) = &mut self.signer {
            let sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
                s.datetime,
                s.scope,
                s.prev,
                EMPTY_SHA,
                sha256_hex(chunk)
            );
            let expected = hex::encode(hmac(&s.key, sts.as_bytes()));
            if !ct_eq(expected.as_bytes(), sig.unwrap_or("").as_bytes()) {
                return Err(S3Error::signature_mismatch());
            }
            s.prev = expected;
        }
        Ok(())
    }

    /// Validate end of stream and any trailing CRC32 checksum.
    pub fn finish(&self) -> Result<()> {
        match self.state {
            St::Trailer | St::Final => {}
            _ => return Err(S3Error::incomplete_body()),
        }
        let text = String::from_utf8_lossy(&self.buf);
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("x-amz-checksum-crc32")
            {
                let actual = B64.encode(self.crc.clone().finalize().to_be_bytes());
                if v.trim() != actual {
                    return Err(S3Error::bad_digest("The CRC32 you specified did not match the calculated checksum."));
                }
            }
        }
        Ok(())
    }
}

enum Out<'a> {
    Blob(&'a mut BlobWriter),
    Mem(&'a mut Vec<u8>, usize),
}

impl Out<'_> {
    async fn write(&mut self, d: &[u8]) -> Result<()> {
        match self {
            Out::Blob(w) => w.write(d).await,
            Out::Mem(v, limit) => {
                if v.len() + d.len() > *limit {
                    return Err(S3Error::new("EntityTooLarge", 400, "Your proposed upload exceeds the maximum allowed size."));
                }
                v.extend_from_slice(d);
                Ok(())
            }
        }
    }
}

async fn run<S>(mut stream: S, payload: &Payload, crc_expect: Option<&str>, mut out: Out<'_>) -> Result<()>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    let read = |r: io::Result<Bytes>| r.map_err(|_| S3Error::incomplete_body());
    match payload {
        Payload::Unsigned | Payload::Sha256(_) => {
            let mut sha = matches!(payload, Payload::Sha256(_)).then(Sha256::new);
            let mut crc = crc_expect.map(|_| crc32fast::Hasher::new());
            while let Some(c) = stream.next().await {
                let c = read(c)?;
                if let Some(h) = &mut sha {
                    h.update(&c);
                }
                if let Some(h) = &mut crc {
                    h.update(&c);
                }
                out.write(&c).await?;
            }
            if let (Payload::Sha256(expected), Some(h)) = (payload, sha)
                && hex::encode(h.finalize()) != *expected
            {
                return Err(S3Error::new(
                    "XAmzContentSHA256Mismatch",
                    400,
                    "The provided 'x-amz-content-sha256' header does not match what was computed.",
                ));
            }
            if let (Some(expected), Some(h)) = (crc_expect, crc)
                && B64.encode(h.finalize().to_be_bytes()) != expected.trim()
            {
                return Err(S3Error::bad_digest("The CRC32 you specified did not match the calculated checksum."));
            }
        }
        Payload::Streaming { signer } => {
            let mut dec = ChunkDecoder::new(signer.clone());
            let mut buf = Vec::new();
            while let Some(c) = stream.next().await {
                let c = read(c)?;
                buf.clear();
                dec.feed(&c, &mut buf)?;
                out.write(&buf).await?;
            }
            dec.finish()?;
        }
    }
    Ok(())
}

pub async fn ingest<S>(stream: S, payload: &Payload, crc_expect: Option<&str>, w: &mut BlobWriter) -> Result<()>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    run(stream, payload, crc_expect, Out::Blob(w)).await
}

pub async fn read_all<S>(stream: S, payload: &Payload, limit: usize) -> Result<Vec<u8>>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    let mut v = Vec::new();
    run(stream, payload, None, Out::Mem(&mut v, limit)).await?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unsigned_chunks_with_crc_trailer() {
        let data = b"hello world";
        let crc = B64.encode(crc32fast::hash(data).to_be_bytes());
        let body = format!("b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:{crc}\r\n\r\n");
        let mut d = ChunkDecoder::new(None);
        let mut out = Vec::new();
        // Feed one byte at a time to exercise buffering.
        for b in body.as_bytes() {
            d.feed(std::slice::from_ref(b), &mut out).unwrap();
        }
        d.finish().unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn rejects_bad_crc() {
        let body = "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
        let mut d = ChunkDecoder::new(None);
        let mut out = Vec::new();
        d.feed(body.as_bytes(), &mut out).unwrap();
        assert!(d.finish().is_err());
    }

    #[test]
    fn rejects_truncated() {
        let mut d = ChunkDecoder::new(None);
        let mut out = Vec::new();
        d.feed(b"a\r\nabc", &mut out).unwrap();
        assert!(d.finish().is_err());
    }
}
