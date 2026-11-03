//! Audit log: one JSON line per request, in daily files under
//! `<disk 0>/.boxspace/audit/audit-YYYY-MM-DD.jsonl`.

use std::{io::Write, path::PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Entry {
    pub time: DateTime<Utc>,
    pub request_id: String,
    /// "s3" or "console".
    pub source: String,
    pub op: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,
    pub remote: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct Audit {
    dir: PathBuf,
    tx: Option<mpsc::UnboundedSender<Entry>>,
}

fn file_for(dir: &std::path::Path, d: NaiveDate) -> PathBuf {
    dir.join(format!("audit-{}.jsonl", d.format("%Y-%m-%d")))
}

impl Audit {
    pub fn start(dir: PathBuf, enabled: bool, retention_days: u64) -> Audit {
        if !enabled {
            return Audit { dir, tx: None };
        }
        let _ = std::fs::create_dir_all(&dir);
        let (tx, mut rx) = mpsc::unbounded_channel::<Entry>();
        let wdir = dir.clone();
        tokio::spawn(async move {
            let mut day: Option<NaiveDate> = None;
            let mut file: Option<std::fs::File> = None;
            while let Some(e) = rx.recv().await {
                let today = e.time.date_naive();
                if day != Some(today) {
                    day = Some(today);
                    file = std::fs::OpenOptions::new().create(true).append(true).open(file_for(&wdir, today)).ok();
                    cleanup(&wdir, today, retention_days);
                }
                if let (Some(f), Ok(line)) = (&mut file, serde_json::to_string(&e)) {
                    let _ = writeln!(f, "{line}");
                }
            }
        });
        Audit { dir, tx: Some(tx) }
    }

    pub fn enabled(&self) -> bool {
        self.tx.is_some()
    }

    pub fn log(&self, e: Entry) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(e);
        }
    }

    /// Most recent entries first, matching `filter`, from the last 7 days.
    pub fn tail(&self, limit: usize, filter: impl Fn(&Entry) -> bool) -> Vec<Entry> {
        let mut out = Vec::new();
        let today = Utc::now().date_naive();
        for back in 0..7 {
            let Some(d) = today.checked_sub_days(chrono::Days::new(back)) else { break };
            let Ok(text) = std::fs::read_to_string(file_for(&self.dir, d)) else { continue };
            for line in text.lines().rev() {
                if let Ok(e) = serde_json::from_str::<Entry>(line)
                    && filter(&e)
                {
                    out.push(e);
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }
}

fn cleanup(dir: &std::path::Path, today: NaiveDate, keep: u64) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(date) = name.strip_prefix("audit-").and_then(|s| s.strip_suffix(".jsonl")) else { continue };
        if let Ok(d) = NaiveDate::parse_from_str(date, "%Y-%m-%d")
            && (today - d).num_days() > keep as i64
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}
