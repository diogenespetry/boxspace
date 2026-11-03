//! Minimal streaming ZIP writer (stored, no compression) with ZIP64 support.
//! Used by the console to download several objects at once.

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Datelike, Timelike, Utc};
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::{blob, storage::ObjectVersion, App};

const U32_MAX: u64 = 0xFFFF_FFFF;

fn dos_time(t: &DateTime<Utc>) -> (u16, u16) {
    let year = (t.year().clamp(1980, 2107) - 1980) as u16;
    let date = (year << 9) | ((t.month() as u16) << 5) | t.day() as u16;
    let time = ((t.hour() as u16) << 11) | ((t.minute() as u16) << 5) | (t.second() as u16 / 2);
    (time, date)
}

struct Central {
    name: Vec<u8>,
    crc: u32,
    size: u64,
    offset: u64,
    time: u16,
    date: u16,
}

/// Stream a ZIP of `entries` (archive name, bucket, version).
pub fn stream(app: Arc<App>, entries: Vec<(String, String, ObjectVersion)>) -> mpsc::Receiver<std::io::Result<Bytes>> {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut offset = 0u64;
        let mut central = Vec::new();
        for (name, bucket, v) in entries {
            let name_b = name.into_bytes();
            let (time, date) = dos_time(&v.last_modified);
            let z64 = v.size >= U32_MAX || offset >= U32_MAX;
            // Local header; sizes and CRC follow in the data descriptor.
            let mut h = Vec::with_capacity(30 + name_b.len() + 20);
            h.extend(0x04034b50u32.to_le_bytes());
            h.extend((if z64 { 45u16 } else { 20u16 }).to_le_bytes());
            h.extend(0x0808u16.to_le_bytes()); // data descriptor + UTF-8 names
            h.extend(0u16.to_le_bytes()); // stored
            h.extend(time.to_le_bytes());
            h.extend(date.to_le_bytes());
            h.extend(0u32.to_le_bytes());
            h.extend((if z64 { U32_MAX as u32 } else { 0 }).to_le_bytes());
            h.extend((if z64 { U32_MAX as u32 } else { 0 }).to_le_bytes());
            h.extend((name_b.len() as u16).to_le_bytes());
            h.extend((if z64 { 20u16 } else { 0 }).to_le_bytes());
            h.extend(&name_b);
            if z64 {
                h.extend(0x0001u16.to_le_bytes());
                h.extend(16u16.to_le_bytes());
                h.extend(0u64.to_le_bytes());
                h.extend(0u64.to_le_bytes());
            }
            let local_offset = offset;
            offset += h.len() as u64;
            if tx.send(Ok(Bytes::from(h))).await.is_err() {
                return;
            }
            let mut crc = crc32fast::Hasher::new();
            let mut size = 0u64;
            match blob::open_full(&app, &bucket, &v).await {
                Ok(mut s) => {
                    while let Some(chunk) = s.next().await {
                        match chunk {
                            Ok(c) => {
                                crc.update(&c);
                                size += c.len() as u64;
                                if tx.send(Ok(c)).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.message))).await;
                    return;
                }
            }
            offset += size;
            let crc = crc.finalize();
            let mut d = Vec::with_capacity(24);
            d.extend(0x08074b50u32.to_le_bytes());
            d.extend(crc.to_le_bytes());
            if z64 {
                d.extend(size.to_le_bytes());
                d.extend(size.to_le_bytes());
            } else {
                d.extend((size as u32).to_le_bytes());
                d.extend((size as u32).to_le_bytes());
            }
            offset += d.len() as u64;
            if tx.send(Ok(Bytes::from(d))).await.is_err() {
                return;
            }
            central.push(Central { name: name_b, crc, size, offset: local_offset, time, date });
        }

        let cd_start = offset;
        let mut cd = Vec::new();
        for c in &central {
            let big_size = c.size >= U32_MAX;
            let big_off = c.offset >= U32_MAX;
            let mut extra = Vec::new();
            if big_size {
                extra.extend(c.size.to_le_bytes());
                extra.extend(c.size.to_le_bytes());
            }
            if big_off {
                extra.extend(c.offset.to_le_bytes());
            }
            let mut ex = Vec::new();
            if !extra.is_empty() {
                ex.extend(0x0001u16.to_le_bytes());
                ex.extend((extra.len() as u16).to_le_bytes());
                ex.extend(extra);
            }
            cd.extend(0x02014b50u32.to_le_bytes());
            cd.extend((0x0300u16 | 45).to_le_bytes()); // made by: Unix, spec 4.5
            cd.extend((if ex.is_empty() { 20u16 } else { 45 }).to_le_bytes());
            cd.extend(0x0808u16.to_le_bytes());
            cd.extend(0u16.to_le_bytes());
            cd.extend(c.time.to_le_bytes());
            cd.extend(c.date.to_le_bytes());
            cd.extend(c.crc.to_le_bytes());
            let s32 = if big_size { U32_MAX as u32 } else { c.size as u32 };
            cd.extend(s32.to_le_bytes());
            cd.extend(s32.to_le_bytes());
            cd.extend((c.name.len() as u16).to_le_bytes());
            cd.extend((ex.len() as u16).to_le_bytes());
            cd.extend(0u16.to_le_bytes()); // comment
            cd.extend(0u16.to_le_bytes()); // disk
            cd.extend(0u16.to_le_bytes()); // internal attrs
            cd.extend((0o100644u32 << 16).to_le_bytes()); // regular file rw-r--r--
            cd.extend((if big_off { U32_MAX as u32 } else { c.offset as u32 }).to_le_bytes());
            cd.extend(&c.name);
            cd.extend(ex);
        }
        let cd_size = cd.len() as u64;
        let n = central.len() as u64;
        let mut end = Vec::new();
        if n >= 0xFFFF || cd_start >= U32_MAX || cd_size >= U32_MAX {
            let z64_eocd = cd_start + cd_size;
            end.extend(0x06064b50u32.to_le_bytes());
            end.extend(44u64.to_le_bytes());
            end.extend(45u16.to_le_bytes());
            end.extend(45u16.to_le_bytes());
            end.extend(0u32.to_le_bytes());
            end.extend(0u32.to_le_bytes());
            end.extend(n.to_le_bytes());
            end.extend(n.to_le_bytes());
            end.extend(cd_size.to_le_bytes());
            end.extend(cd_start.to_le_bytes());
            end.extend(0x07064b50u32.to_le_bytes());
            end.extend(0u32.to_le_bytes());
            end.extend(z64_eocd.to_le_bytes());
            end.extend(1u32.to_le_bytes());
        }
        end.extend(0x06054b50u32.to_le_bytes());
        end.extend(0u16.to_le_bytes());
        end.extend(0u16.to_le_bytes());
        end.extend((n.min(0xFFFF) as u16).to_le_bytes());
        end.extend((n.min(0xFFFF) as u16).to_le_bytes());
        end.extend((cd_size.min(U32_MAX) as u32).to_le_bytes());
        end.extend((cd_start.min(U32_MAX) as u32).to_le_bytes());
        end.extend(0u16.to_le_bytes());
        cd.extend(end);
        let _ = tx.send(Ok(Bytes::from(cd))).await;
    });
    rx
}
