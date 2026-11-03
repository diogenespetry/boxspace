//! Bucket lifecycle rules: expiration of current and noncurrent versions,
//! removal of expired delete markers and abort of stale multipart uploads.

use std::sync::Arc;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, S3Error},
    ops,
    storage::{ObjectVersion, Scan},
    util::{esc, iso8601},
    App,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct LifecycleRule {
    pub id: String,
    pub enabled: bool,
    pub prefix: String,
    pub tags: Vec<(String, String)>,
    pub expiration_days: Option<u32>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub expired_delete_marker: bool,
    pub noncurrent_days: Option<u32>,
    pub abort_days: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct Cfg {
    #[serde(rename = "Rule", default)]
    rules: Vec<RuleXml>,
}

#[derive(Deserialize, Debug, Default)]
struct TagXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

#[derive(Deserialize, Debug, Default)]
struct AndXml {
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default)]
    tags: Vec<TagXml>,
}

#[derive(Deserialize, Debug, Default)]
struct FilterXml {
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Tag")]
    tag: Option<TagXml>,
    #[serde(rename = "And")]
    and: Option<AndXml>,
}

#[derive(Deserialize, Debug)]
struct ExpXml {
    #[serde(rename = "Days")]
    days: Option<u32>,
    #[serde(rename = "Date")]
    date: Option<String>,
    #[serde(rename = "ExpiredObjectDeleteMarker")]
    marker: Option<bool>,
}

#[derive(Deserialize, Debug)]
struct NcXml {
    #[serde(rename = "NoncurrentDays")]
    days: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct AbortXml {
    #[serde(rename = "DaysAfterInitiation")]
    days: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct RuleXml {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Filter")]
    filter: Option<FilterXml>,
    #[serde(rename = "Expiration")]
    expiration: Option<ExpXml>,
    #[serde(rename = "NoncurrentVersionExpiration")]
    noncurrent: Option<NcXml>,
    #[serde(rename = "AbortIncompleteMultipartUpload")]
    abort: Option<AbortXml>,
    #[serde(rename = "Transition")]
    transition: Option<serde::de::IgnoredAny>,
    #[serde(rename = "NoncurrentVersionTransition")]
    nc_transition: Option<serde::de::IgnoredAny>,
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok().map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc()))
}

pub fn parse(body: &[u8]) -> Result<Vec<LifecycleRule>> {
    let s = std::str::from_utf8(body).map_err(|_| S3Error::malformed_xml())?;
    let cfg: Cfg = quick_xml::de::from_str(s).map_err(|e| {
        tracing::debug!("lifecycle xml: {e}");
        S3Error::malformed_xml()
    })?;
    if cfg.rules.is_empty() || cfg.rules.len() > 1000 {
        return Err(S3Error::malformed_xml());
    }
    let mut out = Vec::new();
    for (i, r) in cfg.rules.into_iter().enumerate() {
        if r.transition.is_some() || r.nc_transition.is_some() {
            return Err(S3Error::not_implemented("Lifecycle transitions are not supported (single storage class)."));
        }
        let enabled = match r.status.as_str() {
            "Enabled" => true,
            "Disabled" => false,
            _ => return Err(S3Error::malformed_xml()),
        };
        let mut rule = LifecycleRule { id: r.id.unwrap_or_else(|| format!("rule-{}", i + 1)), enabled, ..Default::default() };
        if let Some(p) = r.prefix {
            rule.prefix = p;
        }
        if let Some(f) = r.filter {
            if let Some(p) = f.prefix {
                rule.prefix = p;
            }
            if let Some(t) = f.tag {
                rule.tags.push((t.key, t.value));
            }
            if let Some(a) = f.and {
                if let Some(p) = a.prefix {
                    rule.prefix = p;
                }
                rule.tags.extend(a.tags.into_iter().map(|t| (t.key, t.value)));
            }
        }
        if let Some(e) = r.expiration {
            rule.expiration_days = e.days;
            if let Some(d) = e.date {
                rule.expiration_date = Some(parse_date(&d).ok_or_else(|| S3Error::invalid_argument("Invalid Expiration Date"))?);
            }
            rule.expired_delete_marker = e.marker.unwrap_or(false);
            if rule.expiration_days == Some(0) {
                return Err(S3Error::invalid_argument("'Days' for Expiration action must be a positive integer"));
            }
        }
        rule.noncurrent_days = r.noncurrent.and_then(|n| n.days);
        rule.abort_days = r.abort.and_then(|a| a.days);
        if rule.expiration_days.is_none()
            && rule.expiration_date.is_none()
            && !rule.expired_delete_marker
            && rule.noncurrent_days.is_none()
            && rule.abort_days.is_none()
        {
            return Err(S3Error::invalid_request("At least one action needs to be specified in a rule"));
        }
        out.push(rule);
    }
    Ok(out)
}

pub fn to_xml(rules: &[LifecycleRule]) -> String {
    let mut x = format!("<LifecycleConfiguration xmlns=\"{}\">", crate::util::S3_NS);
    for r in rules {
        x.push_str("<Rule>");
        x.push_str(&format!("<ID>{}</ID>", esc(&r.id)));
        if r.tags.is_empty() {
            x.push_str(&format!("<Filter><Prefix>{}</Prefix></Filter>", esc(&r.prefix)));
        } else {
            x.push_str(&format!("<Filter><And><Prefix>{}</Prefix>", esc(&r.prefix)));
            for (k, v) in &r.tags {
                x.push_str(&format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", esc(k), esc(v)));
            }
            x.push_str("</And></Filter>");
        }
        x.push_str(&format!("<Status>{}</Status>", if r.enabled { "Enabled" } else { "Disabled" }));
        if r.expiration_days.is_some() || r.expiration_date.is_some() || r.expired_delete_marker {
            x.push_str("<Expiration>");
            if let Some(d) = r.expiration_days {
                x.push_str(&format!("<Days>{d}</Days>"));
            }
            if let Some(d) = r.expiration_date {
                x.push_str(&format!("<Date>{}</Date>", iso8601(&d)));
            }
            if r.expired_delete_marker {
                x.push_str("<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>");
            }
            x.push_str("</Expiration>");
        }
        if let Some(d) = r.noncurrent_days {
            x.push_str(&format!("<NoncurrentVersionExpiration><NoncurrentDays>{d}</NoncurrentDays></NoncurrentVersionExpiration>"));
        }
        if let Some(d) = r.abort_days {
            x.push_str(&format!("<AbortIncompleteMultipartUpload><DaysAfterInitiation>{d}</DaysAfterInitiation></AbortIncompleteMultipartUpload>"));
        }
        x.push_str("</Rule>");
    }
    x.push_str("</LifecycleConfiguration>");
    x
}

pub async fn run_loop(app: Arc<App>) {
    let mut iv = tokio::time::interval(std::time::Duration::from_secs(app.cfg.lifecycle_interval_secs));
    iv.tick().await;
    loop {
        iv.tick().await;
        match run_once(&app).await {
            Ok((e, a)) if e + a > 0 => tracing::info!("lifecycle: {e} versões expiradas, {a} uploads abortados"),
            Ok(_) => {}
            Err(e) => tracing::warn!("lifecycle falhou: {}", e.message),
        }
    }
}

fn applies(rule: &LifecycleRule, v: &ObjectVersion) -> bool {
    rule.enabled && v.key.starts_with(&rule.prefix) && rule.tags.iter().all(|t| v.tags.contains(t))
}

/// Apply all lifecycle rules once. Returns (versions expired, uploads aborted).
pub async fn run_once(app: &App) -> Result<(usize, usize)> {
    let day = Duration::seconds(app.cfg.day_seconds as i64);
    let now = Utc::now();
    let (mut expired, mut aborted) = (0, 0);
    for bm in app.store.list_buckets()? {
        if !bm.lifecycle.iter().any(|r| r.enabled) {
            continue;
        }
        // Group versions by key (scan yields newest first per key).
        let mut groups: Vec<Vec<ObjectVersion>> = Vec::new();
        app.store.scan(&bm.name, "", |v| {
            match groups.last_mut() {
                Some(g) if g[0].key == v.key => g.push(v),
                _ => groups.push(vec![v]),
            }
            Scan::Next
        })?;
        // (key, Some(version) | None for "current")
        let mut actions: Vec<(String, Option<String>)> = Vec::new();
        for g in &groups {
            let cur = &g[0];
            for rule in bm.lifecycle.iter() {
                if !applies(rule, cur) && !(rule.enabled && cur.key.starts_with(&rule.prefix) && cur.delete_marker) {
                    continue;
                }
                if !cur.delete_marker {
                    let by_days = rule.expiration_days.is_some_and(|d| now >= cur.last_modified + day * d as i32);
                    let by_date = rule.expiration_date.is_some_and(|d| now >= d);
                    if by_days || by_date {
                        actions.push((cur.key.clone(), None));
                        break;
                    }
                } else if rule.expired_delete_marker && g.len() == 1 {
                    actions.push((cur.key.clone(), Some(cur.version_id.clone())));
                    break;
                }
            }
            for rule in bm.lifecycle.iter().filter(|r| r.enabled && cur.key.starts_with(&r.prefix)) {
                let Some(days) = rule.noncurrent_days else { continue };
                for i in 1..g.len() {
                    let since = g[i - 1].last_modified;
                    if now >= since + day * days as i32 {
                        actions.push((g[i].key.clone(), Some(g[i].version_id.clone())));
                    }
                }
            }
        }
        actions.dedup();
        for (key, vid) in actions {
            // Lifecycle deletions are not replicated (same as S3).
            ops::delete_object(app, &bm, &key, vid.as_deref(), true).await?;
            expired += 1;
        }
        for u in app.store.list_uploads(&bm.name)? {
            let stale = bm.lifecycle.iter().any(|r| {
                r.enabled && u.key.starts_with(&r.prefix) && r.abort_days.is_some_and(|d| now >= u.initiated + day * d as i32)
            });
            if stale && ops::abort_upload(app, &u.upload_id).await? {
                aborted += 1;
            }
        }
    }
    Ok((expired, aborted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_shapes() {
        let x = br#"<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>
            <Expiration><Days>30</Days></Expiration>
            <NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays></NoncurrentVersionExpiration></Rule>
          <Rule><Filter><And><Prefix>tmp/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter><Status>Disabled</Status>
            <AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>
        </LifecycleConfiguration>"#;
        let r = parse(x).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].prefix, "logs/");
        assert_eq!(r[0].expiration_days, Some(30));
        assert_eq!(r[0].noncurrent_days, Some(7));
        assert!(!r[1].enabled);
        assert_eq!(r[1].tags, vec![("k".into(), "v".into())]);
        let again = parse(to_xml(&r).as_bytes()).unwrap();
        assert_eq!(again[1].abort_days, Some(2));
    }
}
