//! Bucket event notifications delivered to webhooks.

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{storage::BucketMeta, util::iso8601, util::random_hex};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Webhook {
    pub url: String,
    /// e.g. "s3:ObjectCreated:*", "s3:ObjectRemoved:Delete". Empty = all.
    pub events: Vec<String>,
    pub prefix: String,
    pub suffix: String,
    /// Sent as "Authorization: Bearer <token>" when set.
    pub token: Option<String>,
}

impl Webhook {
    fn wants(&self, event: &str, key: &str) -> bool {
        let full = format!("s3:{event}");
        let class = event.split(':').next().unwrap_or("");
        let event_ok = self.events.is_empty()
            || self.events.iter().any(|e| e == "*" || *e == full || *e == format!("s3:{class}:*"));
        event_ok && key.starts_with(&self.prefix) && key.ends_with(&self.suffix)
    }
}

pub fn valid_event(e: &str) -> bool {
    matches!(
        e,
        "*" | "s3:ObjectCreated:*"
            | "s3:ObjectCreated:Put"
            | "s3:ObjectCreated:Copy"
            | "s3:ObjectCreated:CompleteMultipartUpload"
            | "s3:ObjectRemoved:*"
            | "s3:ObjectRemoved:Delete"
            | "s3:ObjectRemoved:DeleteMarkerCreated"
    )
}

pub struct Event<'a> {
    /// Without the "s3:" prefix, e.g. "ObjectCreated:Put".
    pub name: &'a str,
    pub key: &'a str,
    pub size: u64,
    pub etag: &'a str,
    pub version_id: Option<&'a str>,
}

/// Fire matching webhooks in the background (3 attempts each).
pub fn emit(http: &reqwest::Client, bucket: &BucketMeta, ev: Event<'_>) {
    let hooks: Vec<Webhook> = bucket.webhooks.iter().filter(|w| w.wants(ev.name, ev.key)).cloned().collect();
    if hooks.is_empty() {
        return;
    }
    let mut object = serde_json::json!({
        "key": crate::util::uri_encode(ev.key, false),
        "size": ev.size,
        "eTag": ev.etag,
        "sequencer": random_hex(8).to_uppercase(),
    });
    if let Some(v) = ev.version_id.filter(|v| *v != crate::storage::NULL_VERSION) {
        object["versionId"] = serde_json::json!(v);
    }
    let payload = serde_json::json!({
        "EventName": format!("s3:{}", ev.name),
        "Key": format!("{}/{}", bucket.name, ev.key),
        "Records": [{
            "eventVersion": "2.0",
            "eventSource": "boxspace:s3",
            "awsRegion": "",
            "eventTime": iso8601(&Utc::now()),
            "eventName": ev.name,
            "s3": {
                "s3SchemaVersion": "1.0",
                "bucket": {"name": bucket.name, "arn": format!("arn:aws:s3:::{}", bucket.name)},
                "object": object
            }
        }]
    });
    for hook in hooks {
        let http = http.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            for attempt in 0..3u32 {
                let mut req = http.post(&hook.url).json(&payload).timeout(Duration::from_secs(10));
                if let Some(t) = &hook.token {
                    req = req.bearer_auth(t);
                }
                match req.send().await {
                    Ok(r) if r.status().is_success() => return,
                    Ok(r) => tracing::warn!("webhook {} respondeu {}", hook.url, r.status()),
                    Err(e) => tracing::warn!("webhook {} falhou: {e}", hook.url),
                }
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
        });
    }
}
