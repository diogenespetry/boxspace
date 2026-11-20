//! Prometheus metrics, served at `/_boxspace/metrics`.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Instant,
};

use crate::{replication, App};

const BOUNDS: [f64; 13] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

#[derive(Default, Clone)]
struct Hist {
    counts: [u64; BOUNDS.len()],
    sum: f64,
    count: u64,
}

/// Traffic of one bucket since the server started.
#[derive(Default, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Traffic {
    pub requests: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// (metric name, help text, value)
type Series = (&'static str, &'static str, fn(&Traffic) -> u64);

pub struct Metrics {
    requests: Mutex<BTreeMap<(String, u16), u64>>,
    traffic: Mutex<BTreeMap<String, Traffic>>,
    durations: Mutex<BTreeMap<String, Hist>>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    started: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            requests: Mutex::default(),
            traffic: Mutex::default(),
            durations: Mutex::default(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

fn label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

impl Metrics {
    pub fn record(&self, op: &str, status: u16, secs: f64, bytes_in: u64, bytes_out: u64) {
        *self.requests.lock().unwrap_or_else(|e| e.into_inner()).entry((op.to_string(), status)).or_default() += 1;
        {
            let mut d = self.durations.lock().unwrap_or_else(|e| e.into_inner());
            let h = d.entry(op.to_string()).or_default();
            for (i, b) in BOUNDS.iter().enumerate() {
                if secs <= *b {
                    h.counts[i] += 1;
                }
            }
            h.sum += secs;
            h.count += 1;
        }
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    /// Count a request against a bucket. Callers only pass buckets that
    /// exist or requests that were authenticated, so random names probed by
    /// scanners do not create series.
    pub fn record_bucket(&self, bucket: &str, status: u16, bytes_in: u64, bytes_out: u64) {
        let mut t = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if t.len() >= 10_000 && !t.contains_key(bucket) {
            return;
        }
        let e = t.entry(bucket.to_string()).or_default();
        e.requests += 1;
        e.errors += (status >= 400) as u64;
        e.bytes_in += bytes_in;
        e.bytes_out += bytes_out;
    }

    pub fn bucket_traffic(&self, bucket: &str) -> Traffic {
        self.traffic.lock().unwrap_or_else(|e| e.into_inner()).get(bucket).copied().unwrap_or_default()
    }

    pub fn render(&self, app: &App) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "# HELP boxspace_info Server information.\n# TYPE boxspace_info gauge");
        let _ = writeln!(
            o,
            "boxspace_info{{version=\"{}\",mode=\"{}\",disks=\"{}\"}} 1",
            crate::config::VERSION,
            app.disks.mode.label(),
            app.disks.list.len()
        );
        let _ = writeln!(o, "# TYPE boxspace_uptime_seconds gauge\nboxspace_uptime_seconds {}", self.started.elapsed().as_secs());

        let _ = writeln!(o, "# HELP boxspace_requests_total S3 API requests by operation and status.\n# TYPE boxspace_requests_total counter");
        for ((op, st), n) in self.requests.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let _ = writeln!(o, "boxspace_requests_total{{op=\"{}\",status=\"{st}\"}} {n}", label(op));
        }
        let _ = writeln!(o, "# HELP boxspace_request_duration_seconds S3 API request latency.\n# TYPE boxspace_request_duration_seconds histogram");
        for (op, h) in self.durations.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let op = label(op);
            for (i, b) in BOUNDS.iter().enumerate() {
                let _ = writeln!(o, "boxspace_request_duration_seconds_bucket{{op=\"{op}\",le=\"{b}\"}} {}", h.counts[i]);
            }
            let _ = writeln!(o, "boxspace_request_duration_seconds_bucket{{op=\"{op}\",le=\"+Inf\"}} {}", h.count);
            let _ = writeln!(o, "boxspace_request_duration_seconds_sum{{op=\"{op}\"}} {}", h.sum);
            let _ = writeln!(o, "boxspace_request_duration_seconds_count{{op=\"{op}\"}} {}", h.count);
        }
        let _ = writeln!(o, "# TYPE boxspace_received_bytes_total counter\nboxspace_received_bytes_total {}", self.bytes_in.load(Ordering::Relaxed));
        let _ = writeln!(o, "# TYPE boxspace_sent_bytes_total counter\nboxspace_sent_bytes_total {}", self.bytes_out.load(Ordering::Relaxed));

        let buckets = app.store.list_buckets().unwrap_or_default();
        let _ = writeln!(o, "# TYPE boxspace_buckets gauge\nboxspace_buckets {}", buckets.len());
        let _ = writeln!(o, "# HELP boxspace_bucket_objects Current objects per bucket.\n# TYPE boxspace_bucket_objects gauge");
        let mut stats = Vec::new();
        for b in &buckets {
            stats.push((label(&b.name), app.store.stats(&b.name).unwrap_or_default()));
        }
        for (b, s) in &stats {
            let _ = writeln!(o, "boxspace_bucket_objects{{bucket=\"{b}\"}} {}", s.objects);
        }
        let _ = writeln!(o, "# HELP boxspace_bucket_versions Stored versions per bucket.\n# TYPE boxspace_bucket_versions gauge");
        for (b, s) in &stats {
            let _ = writeln!(o, "boxspace_bucket_versions{{bucket=\"{b}\"}} {}", s.versions);
        }
        let _ = writeln!(o, "# HELP boxspace_bucket_bytes Logical bytes per bucket (all versions).\n# TYPE boxspace_bucket_bytes gauge");
        for (b, s) in &stats {
            let _ = writeln!(o, "boxspace_bucket_bytes{{bucket=\"{b}\"}} {}", s.bytes);
        }
        let _ = writeln!(o, "# HELP boxspace_bucket_quota_bytes Byte quota per bucket (only buckets with a quota).\n# TYPE boxspace_bucket_quota_bytes gauge");
        for b in buckets.iter().filter(|b| b.quota_bytes.is_some()) {
            let _ = writeln!(o, "boxspace_bucket_quota_bytes{{bucket=\"{}\"}} {}", label(&b.name), b.quota_bytes.unwrap_or(0));
        }
        let _ = writeln!(o, "# HELP boxspace_bucket_quota_objects Object quota per bucket (only buckets with a quota).\n# TYPE boxspace_bucket_quota_objects gauge");
        for b in buckets.iter().filter(|b| b.quota_objects.is_some()) {
            let _ = writeln!(o, "boxspace_bucket_quota_objects{{bucket=\"{}\"}} {}", label(&b.name), b.quota_objects.unwrap_or(0));
        }
        {
            let mut traffic = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
            traffic.retain(|name, _| buckets.iter().any(|b| &b.name == name));
            let series: [Series; 4] = [
                ("boxspace_bucket_requests_total", "S3 API requests per bucket.", |t| t.requests),
                ("boxspace_bucket_errors_total", "S3 API requests per bucket that ended in an error (4xx/5xx).", |t| t.errors),
                ("boxspace_bucket_received_bytes_total", "Bytes received per bucket.", |t| t.bytes_in),
                ("boxspace_bucket_sent_bytes_total", "Bytes sent per bucket.", |t| t.bytes_out),
            ];
            for (name, help, get) in series {
                let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} counter");
                for (b, t) in traffic.iter() {
                    let _ = writeln!(o, "{name}{{bucket=\"{}\"}} {}", label(b), get(t));
                }
            }
        }

        let _ = writeln!(o, "# HELP boxspace_disk_online 1 if the disk is online.\n# TYPE boxspace_disk_online gauge");
        for d in &app.disks.list {
            let _ = writeln!(o, "boxspace_disk_online{{disk=\"{}\",path=\"{}\"}} {}", d.idx, label(&d.root.display().to_string()), d.online() as u8);
        }
        let _ = writeln!(o, "# TYPE boxspace_disk_free_bytes gauge");
        let mut totals = String::new();
        for d in &app.disks.list {
            if let Some((free, total)) = d.space() {
                let _ = writeln!(o, "boxspace_disk_free_bytes{{disk=\"{}\"}} {free}", d.idx);
                let _ = writeln!(totals, "boxspace_disk_total_bytes{{disk=\"{}\"}} {total}", d.idx);
            }
        }
        let _ = write!(o, "# TYPE boxspace_disk_total_bytes gauge\n{totals}");

        let h = app.healer.snapshot();
        let _ = writeln!(o, "# TYPE boxspace_heal_running gauge\nboxspace_heal_running {}", h.running as u8);
        if let Some(t) = h.finished {
            let _ = writeln!(o, "# TYPE boxspace_heal_last_finished_timestamp_seconds gauge\nboxspace_heal_last_finished_timestamp_seconds {}", t.timestamp());
        }
        let _ = writeln!(o, "# TYPE boxspace_heal_healed gauge\nboxspace_heal_healed {}", h.healed);
        let _ = writeln!(o, "# HELP boxspace_heal_lost Objects that could not be reconstructed in the last check.\n# TYPE boxspace_heal_lost gauge\nboxspace_heal_lost {}", h.lost_count);

        let _ = writeln!(o, "# HELP boxspace_ip_blocked_total Requests refused by the IP filter.\n# TYPE boxspace_ip_blocked_total counter\nboxspace_ip_blocked_total {}", app.ipfilter.blocked_total.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(o, "# HELP boxspace_ip_bans_total Automatic IP bans issued.\n# TYPE boxspace_ip_bans_total counter\nboxspace_ip_bans_total {}", app.ipfilter.bans_total.load(std::sync::atomic::Ordering::Relaxed));
        let _ = writeln!(o, "# TYPE boxspace_ip_bans_active gauge\nboxspace_ip_bans_active {}", app.ipfilter.bans().len());
        let r = replication::stats(app, None);
        let _ = writeln!(o, "# TYPE boxspace_replication_pending gauge\nboxspace_replication_pending {}", r.pending);
        let _ = writeln!(o, "# TYPE boxspace_replication_failed gauge\nboxspace_replication_failed {}", r.failed);
        o
    }
}
