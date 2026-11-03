//! Server-side encryption (SSE-S3).
//!
//! Each object gets a random 256-bit data key, wrapped with the server master
//! key. Object data is split into 64 KiB chunks, each sealed with AES-256-GCM.
//! The nonce is an 8-byte random prefix plus the chunk index, and the
//! associated data binds the chunk index and a "last chunk" flag, so chunks
//! cannot be reordered or truncated without detection.

use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::util::random_bytes;

pub const CHUNK: usize = 64 * 1024;
pub const TAG: usize = 16;

pub struct Kms {
    master: Aes256Gcm,
}

impl Kms {
    /// Load the master key from BOXSPACE_KMS_SECRET_KEY, or from (creating if
    /// needed) `<meta_dir>/master.key`.
    pub fn load(meta_dir: &Path) -> Result<Kms, String> {
        let key = if let Ok(v) = std::env::var("BOXSPACE_KMS_SECRET_KEY") {
            B64.decode(v.trim()).map_err(|e| format!("BOXSPACE_KMS_SECRET_KEY inválida: {e}"))?
        } else {
            let path = meta_dir.join("master.key");
            if path.exists() {
                let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
                B64.decode(s.trim()).map_err(|e| format!("master.key inválida: {e}"))?
            } else {
                let k = random_bytes::<32>();
                write_private(&path, B64.encode(k).as_bytes()).map_err(|e| e.to_string())?;
                tracing::warn!(
                    "chave mestra gerada em {}; para produção defina BOXSPACE_KMS_SECRET_KEY e guarde-a fora do disco de dados",
                    path.display()
                );
                k.to_vec()
            }
        };
        if key.len() != 32 {
            return Err("a chave mestra deve ter 32 bytes".into());
        }
        Ok(Kms { master: Aes256Gcm::new_from_slice(&key).expect("32-byte key") })
    }

    /// Create a new data key; returns (plain key, wrapped base64).
    pub fn new_data_key(&self) -> ([u8; 32], String) {
        let key = random_bytes::<32>();
        let nonce = random_bytes::<12>();
        let ct = self.master.encrypt(Nonce::from_slice(&nonce), key.as_ref()).expect("encrypt");
        let mut out = nonce.to_vec();
        out.extend(ct);
        (key, B64.encode(out))
    }

    pub fn unwrap_key(&self, wrapped: &str) -> Result<[u8; 32], String> {
        let raw = B64.decode(wrapped).map_err(|e| e.to_string())?;
        if raw.len() < 12 {
            return Err("wrapped key too short".into());
        }
        let plain = self
            .master
            .decrypt(Nonce::from_slice(&raw[..12]), &raw[12..])
            .map_err(|_| "não foi possível abrir a chave do objeto (chave mestra diferente?)".to_string())?;
        plain.try_into().map_err(|_| "invalid data key length".to_string())
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

pub fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

fn nonce(prefix: &[u8; 8], idx: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&idx.to_be_bytes());
    n
}

fn aad(idx: u32, last: bool) -> [u8; 5] {
    let mut a = [0u8; 5];
    a[..4].copy_from_slice(&idx.to_be_bytes());
    a[4] = last as u8;
    a
}

pub fn seal(c: &Aes256Gcm, prefix: &[u8; 8], idx: u32, last: bool, plain: &[u8]) -> Vec<u8> {
    let n = nonce(prefix, idx);
    let a = aad(idx, last);
    c.encrypt(Nonce::from_slice(&n), Payload { msg: plain, aad: &a }).expect("encrypt")
}

pub fn open(c: &Aes256Gcm, prefix: &[u8; 8], idx: u32, last: bool, ct: &[u8]) -> Result<Vec<u8>, ()> {
    let n = nonce(prefix, idx);
    let a = aad(idx, last);
    c.decrypt(Nonce::from_slice(&n), Payload { msg: ct, aad: &a }).map_err(|_| ())
}

/// Number of encrypted chunks for an object of `size` plaintext bytes.
pub fn chunk_count(size: u64) -> u64 {
    if size == 0 { 1 } else { size.div_ceil(CHUNK as u64) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let c = cipher(&[7u8; 32]);
        let p = [1u8; 8];
        let ct = seal(&c, &p, 3, true, b"hello");
        assert_eq!(open(&c, &p, 3, true, &ct).unwrap(), b"hello");
        assert!(open(&c, &p, 3, false, &ct).is_err(), "last flag is authenticated");
        assert!(open(&c, &p, 2, true, &ct).is_err(), "index is authenticated");
    }
}
