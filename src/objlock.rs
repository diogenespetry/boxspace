//! S3 Object Lock: per-version retention (GOVERNANCE / COMPLIANCE) and
//! legal hold, plus a per-bucket default retention.
//!
//! Rules (same as Amazon S3):
//! - Object Lock can only be enabled on a versioned bucket, and once enabled
//!   it cannot be disabled and versioning cannot be suspended.
//! - A version under legal hold, or with a retention date in the future,
//!   cannot be deleted (deleting without a version id still just adds a
//!   delete marker, which never destroys data).
//! - GOVERNANCE retention can be shortened or removed, and such versions
//!   deleted, only with `x-amz-bypass-governance-retention: true` from an
//!   administrator key. COMPLIANCE retention can only be extended, by anyone,
//!   and nobody can delete the version before the date, not even root.
//! - Lifecycle rules never remove locked versions.
//!
//! The checks live in the metadata layer (`Store::delete_object`), so every
//! path that removes a version (API, console, bulk delete, lifecycle,
//! emptying a bucket) is covered.

use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, S3Error},
    storage::{BucketMeta, ObjectVersion},
    util::{esc, header, iso8601, set_header, S3_NS},
};

pub const GOVERNANCE: &str = "GOVERNANCE";
pub const COMPLIANCE: &str = "COMPLIANCE";
pub const BYPASS_HEADER: &str = "x-amz-bypass-governance-retention";

/// Longest retention accepted (100 years), as in S3.
const MAX_DAYS: u32 = 36_500;
const MAX_YEARS: u32 = 100;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct DefaultRetention {
    pub mode: String,
    pub days: Option<u32>,
    pub years: Option<u32>,
}

impl DefaultRetention {
    pub fn validate(&self) -> Result<()> {
        valid_mode(&self.mode)?;
        match (self.days, self.years) {
            (Some(d), None) if (1..=MAX_DAYS).contains(&d) => Ok(()),
            (None, Some(y)) if (1..=MAX_YEARS).contains(&y) => Ok(()),
            _ => Err(S3Error::malformed_xml()),
        }
    }

    pub fn until(&self, from: DateTime<Utc>) -> DateTime<Utc> {
        match (self.days, self.years) {
            (Some(d), _) => from + Duration::days(d as i64),
            (_, Some(y)) => from.checked_add_months(chrono::Months::new(12 * y)).unwrap_or(from + Duration::days(365 * y as i64)),
            _ => from,
        }
    }
}

/// Lock settings requested when an object is written.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct LockSpec {
    pub mode: Option<String>,
    pub retain_until: Option<DateTime<Utc>>,
    pub legal_hold: Option<bool>,
}

impl LockSpec {
    pub fn is_empty(&self) -> bool {
        self.mode.is_none() && self.retain_until.is_none() && self.legal_hold.is_none()
    }
}

fn valid_mode(m: &str) -> Result<()> {
    if m == GOVERNANCE || m == COMPLIANCE {
        Ok(())
    } else {
        Err(S3Error::invalid_argument("Unknown wormMode directive."))
    }
}

pub fn parse_date(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| S3Error::invalid_argument("The retain until date must be provided in ISO 8601 format"))
}

fn not_enabled() -> S3Error {
    S3Error::invalid_request("Bucket is missing Object Lock Configuration")
}

/// Read `x-amz-object-lock-*` request headers.
pub fn spec_from_headers(h: &HeaderMap) -> Result<LockSpec> {
    let mode = header(h, "x-amz-object-lock-mode").map(str::to_string);
    let until = header(h, "x-amz-object-lock-retain-until-date").map(parse_date).transpose()?;
    let hold = match header(h, "x-amz-object-lock-legal-hold") {
        None => None,
        Some("ON") => Some(true),
        Some("OFF") => Some(false),
        Some(_) => return Err(S3Error::invalid_argument("Legal Hold must be either of 'ON' or 'OFF'")),
    };
    if mode.is_some() != until.is_some() {
        return Err(S3Error::invalid_argument(
            "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied",
        ));
    }
    if let Some(m) = &mode {
        valid_mode(m)?;
    }
    if until.is_some_and(|u| u <= Utc::now()) {
        return Err(S3Error::invalid_argument("The retain until date must be in the future!"));
    }
    Ok(LockSpec { mode, retain_until: until, legal_hold: hold })
}

/// Refuse lock headers on a bucket without Object Lock.
pub fn check_spec(bm: &BucketMeta, spec: &LockSpec) -> Result<()> {
    if !spec.is_empty() && !bm.object_lock {
        return Err(not_enabled());
    }
    Ok(())
}

/// Set the lock fields of a new version: explicit settings win, otherwise
/// the bucket's default retention applies.
pub fn apply(bm: &BucketMeta, spec: &LockSpec, v: &mut ObjectVersion) {
    if !bm.object_lock {
        return;
    }
    if let (Some(m), Some(u)) = (&spec.mode, spec.retain_until) {
        v.lock_mode = Some(m.clone());
        v.retain_until = Some(u);
    } else if let Some(d) = &bm.lock_default {
        v.lock_mode = Some(d.mode.clone());
        v.retain_until = Some(d.until(v.last_modified));
    }
    v.legal_hold = spec.legal_hold.unwrap_or(false);
}

/// Is the version protected right now?
pub fn locked(v: &ObjectVersion, now: DateTime<Utc>) -> bool {
    v.legal_hold || v.retain_until.is_some_and(|u| u > now)
}

fn denied() -> S3Error {
    S3Error::new("AccessDenied", 403, "Access Denied because object protected by object lock.")
}

/// May this version be permanently deleted?
pub fn check_delete(v: &ObjectVersion, bypass: bool, now: DateTime<Utc>) -> Result<()> {
    if v.legal_hold {
        return Err(denied());
    }
    match (v.lock_mode.as_deref(), v.retain_until) {
        (Some(m), Some(u)) if u > now => {
            if m == GOVERNANCE && bypass {
                Ok(())
            } else {
                Err(denied())
            }
        }
        _ => Ok(()),
    }
}

/// May the retention of `cur` become (`mode`, `until`)? `None` removes it.
pub fn check_retention_change(cur: &ObjectVersion, mode: Option<&str>, until: Option<DateTime<Utc>>, bypass: bool, now: DateTime<Utc>) -> Result<()> {
    if let Some(m) = mode {
        valid_mode(m)?;
    }
    if until.is_some_and(|u| u <= now) {
        return Err(S3Error::invalid_argument("The retain until date must be in the future!"));
    }
    let (Some(cm), Some(cu)) = (cur.lock_mode.as_deref(), cur.retain_until) else { return Ok(()) };
    if cu <= now {
        return Ok(()); // expired: anything goes
    }
    let extends = mode == Some(cm) && until.is_some_and(|u| u >= cu);
    if extends {
        return Ok(());
    }
    if cm == GOVERNANCE && bypass {
        return Ok(());
    }
    Err(denied())
}

// ------------------------------------------------------------- XML ----

#[derive(Deserialize)]
struct ConfigXml {
    #[serde(rename = "ObjectLockEnabled")]
    enabled: Option<String>,
    #[serde(rename = "Rule")]
    rule: Option<RuleXml>,
}
#[derive(Deserialize)]
struct RuleXml {
    #[serde(rename = "DefaultRetention")]
    default: Option<DefaultXml>,
}
#[derive(Deserialize)]
struct DefaultXml {
    #[serde(rename = "Mode")]
    mode: Option<String>,
    #[serde(rename = "Days")]
    days: Option<u32>,
    #[serde(rename = "Years")]
    years: Option<u32>,
}

fn from_xml<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    let s = std::str::from_utf8(b).map_err(|_| S3Error::malformed_xml())?;
    quick_xml::de::from_str(s).map_err(|_| S3Error::malformed_xml())
}

/// Parse a PutObjectLockConfiguration body into the default retention.
pub fn parse_config(b: &[u8]) -> Result<Option<DefaultRetention>> {
    let c: ConfigXml = from_xml(b)?;
    if c.enabled.as_deref() != Some("Enabled") {
        return Err(S3Error::malformed_xml());
    }
    match c.rule.and_then(|r| r.default) {
        None => Ok(None),
        Some(d) => {
            let r = DefaultRetention { mode: d.mode.unwrap_or_default(), days: d.days, years: d.years };
            r.validate()?;
            Ok(Some(r))
        }
    }
}

pub fn config_xml(bm: &BucketMeta) -> String {
    let rule = bm
        .lock_default
        .as_ref()
        .map(|d| {
            let period = match (d.days, d.years) {
                (Some(n), _) => format!("<Days>{n}</Days>"),
                (_, Some(n)) => format!("<Years>{n}</Years>"),
                _ => String::new(),
            };
            format!("<Rule><DefaultRetention><Mode>{}</Mode>{period}</DefaultRetention></Rule>", esc(&d.mode))
        })
        .unwrap_or_default();
    format!("<ObjectLockConfiguration xmlns=\"{S3_NS}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}</ObjectLockConfiguration>")
}

#[derive(Deserialize)]
struct RetentionXml {
    #[serde(rename = "Mode")]
    mode: Option<String>,
    #[serde(rename = "RetainUntilDate")]
    until: Option<String>,
}

/// Parse a PutObjectRetention body. An empty Retention element removes it.
pub fn parse_retention(b: &[u8]) -> Result<(Option<String>, Option<DateTime<Utc>>)> {
    let r: RetentionXml = from_xml(b)?;
    let until = r.until.as_deref().map(parse_date).transpose()?;
    if r.mode.is_some() != until.is_some() {
        return Err(S3Error::malformed_xml());
    }
    Ok((r.mode, until))
}

pub fn retention_xml(v: &ObjectVersion) -> Option<String> {
    let (m, u) = (v.lock_mode.as_ref()?, v.retain_until?);
    Some(format!(
        "<Retention xmlns=\"{S3_NS}\"><Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
        esc(m),
        iso8601(&u)
    ))
}

#[derive(Deserialize)]
struct LegalHoldXml {
    #[serde(rename = "Status")]
    status: String,
}

pub fn parse_legal_hold(b: &[u8]) -> Result<bool> {
    let h: LegalHoldXml = from_xml(b)?;
    match h.status.as_str() {
        "ON" => Ok(true),
        "OFF" => Ok(false),
        _ => Err(S3Error::malformed_xml()),
    }
}

pub fn legal_hold_xml(on: bool) -> String {
    format!("<LegalHold xmlns=\"{S3_NS}\"><Status>{}</Status></LegalHold>", if on { "ON" } else { "OFF" })
}

/// Response headers for GET/HEAD object.
pub fn set_headers(h: &mut HeaderMap, v: &ObjectVersion) {
    if let (Some(m), Some(u)) = (&v.lock_mode, v.retain_until) {
        set_header(h, "x-amz-object-lock-mode", m);
        set_header(h, "x-amz-object-lock-retain-until-date", &iso8601(&u));
    }
    if v.legal_hold {
        set_header(h, "x-amz-object-lock-legal-hold", "ON");
    }
}

pub fn not_configured() -> S3Error {
    S3Error::new("ObjectLockConfigurationNotFoundError", 404, "Object Lock configuration does not exist for this bucket")
}

/// Bucket-level check for retention/legal-hold calls.
pub fn require_enabled(bm: &BucketMeta) -> Result<()> {
    if bm.object_lock { Ok(()) } else { Err(not_enabled()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(mode: Option<&str>, until: Option<DateTime<Utc>>, hold: bool) -> ObjectVersion {
        ObjectVersion { lock_mode: mode.map(str::to_string), retain_until: until, legal_hold: hold, ..Default::default() }
    }

    #[test]
    fn delete_rules() {
        let now = Utc::now();
        let future = now + Duration::days(1);
        let past = now - Duration::days(1);
        assert!(check_delete(&version(None, None, false), false, now).is_ok());
        assert!(check_delete(&version(Some(GOVERNANCE), Some(future), false), false, now).is_err());
        assert!(check_delete(&version(Some(GOVERNANCE), Some(future), false), true, now).is_ok());
        assert!(check_delete(&version(Some(COMPLIANCE), Some(future), false), true, now).is_err(), "compliance ignores bypass");
        assert!(check_delete(&version(Some(COMPLIANCE), Some(past), false), false, now).is_ok(), "expired retention");
        assert!(check_delete(&version(None, None, true), true, now).is_err(), "legal hold always blocks");
    }

    #[test]
    fn retention_changes() {
        let now = Utc::now();
        let d = |n: i64| Some(now + Duration::days(n));
        let comp = version(Some(COMPLIANCE), d(10), false);
        assert!(check_retention_change(&comp, Some(COMPLIANCE), d(20), false, now).is_ok(), "extend");
        assert!(check_retention_change(&comp, Some(COMPLIANCE), d(5), true, now).is_err(), "shorten");
        assert!(check_retention_change(&comp, Some(GOVERNANCE), d(20), true, now).is_err(), "weaken mode");
        assert!(check_retention_change(&comp, None, None, true, now).is_err(), "remove");
        let gov = version(Some(GOVERNANCE), d(10), false);
        assert!(check_retention_change(&gov, Some(GOVERNANCE), d(5), false, now).is_err());
        assert!(check_retention_change(&gov, Some(GOVERNANCE), d(5), true, now).is_ok());
        assert!(check_retention_change(&gov, Some(COMPLIANCE), d(10), false, now).is_err());
        assert!(check_retention_change(&gov, None, None, true, now).is_ok());
        assert!(check_retention_change(&version(None, None, false), Some(GOVERNANCE), d(-1), false, now).is_err(), "past date");
    }

    #[test]
    fn config_roundtrip() {
        let x = br#"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>5</Years></DefaultRetention></Rule></ObjectLockConfiguration>"#;
        let d = parse_config(x).unwrap().unwrap();
        assert_eq!(d, DefaultRetention { mode: COMPLIANCE.into(), days: None, years: Some(5) });
        let bm = BucketMeta { object_lock: true, lock_default: Some(d), ..Default::default() };
        assert_eq!(parse_config(config_xml(&bm).as_bytes()).unwrap(), bm.lock_default);
        assert!(parse_config(b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>").unwrap().is_none());
        let both = br#"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule></ObjectLockConfiguration>"#;
        assert!(parse_config(both).is_err());
        let start = DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z").unwrap().with_timezone(&Utc);
        let y = DefaultRetention { mode: GOVERNANCE.into(), days: None, years: Some(1) };
        assert_eq!(iso8601(&y.until(start)), "2027-01-31T00:00:00.000Z");
    }

    #[test]
    fn default_applies_only_without_explicit_settings() {
        let bm = BucketMeta {
            object_lock: true,
            lock_default: Some(DefaultRetention { mode: GOVERNANCE.into(), days: Some(30), years: None }),
            ..Default::default()
        };
        let now = Utc::now();
        let mut v = ObjectVersion { last_modified: now, ..Default::default() };
        apply(&bm, &LockSpec::default(), &mut v);
        assert_eq!(v.lock_mode.as_deref(), Some(GOVERNANCE));
        assert_eq!(v.retain_until, Some(now + Duration::days(30)));
        let explicit = LockSpec { mode: Some(COMPLIANCE.into()), retain_until: Some(now + Duration::days(2)), legal_hold: Some(true) };
        let mut v = ObjectVersion { last_modified: now, ..Default::default() };
        apply(&bm, &explicit, &mut v);
        assert_eq!(v.lock_mode.as_deref(), Some(COMPLIANCE));
        assert!(v.legal_hold);
        let plain = BucketMeta::default();
        assert!(check_spec(&plain, &explicit).is_err());
        assert!(check_spec(&plain, &LockSpec::default()).is_ok());
    }
}
