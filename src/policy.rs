//! Bucket policies (IAM-style JSON), evaluated for anonymous requests.
//!
//! Authenticated access keys always act as the bucket owner (read-only keys
//! are limited to reads). Policies grant access to anonymous principals:
//! an explicit Deny wins, then any matching Allow, otherwise access is denied.
//! Statements with Condition, NotAction, NotResource or NotPrincipal are not
//! supported: such Allow statements are ignored (fail closed), and such Deny
//! statements are applied as if unconditional.

use serde_json::Value;

use crate::util::wildcard;

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

fn statements(doc: &Value) -> Vec<&Value> {
    match doc.get("Statement") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v @ Value::Object(_)) => vec![v],
        _ => vec![],
    }
}

fn anonymous_principal(p: Option<&Value>) -> bool {
    match p {
        Some(Value::String(s)) => s == "*",
        Some(Value::Object(m)) => m.get("AWS").map(|a| strings(a).iter().any(|x| x == "*")).unwrap_or(false),
        _ => false,
    }
}

/// Validate a policy document for `bucket`. Returns a human-readable error.
pub fn validate(bucket: &str, policy: &str) -> Result<(), String> {
    let doc: Value = serde_json::from_str(policy).map_err(|e| format!("Policy is not valid JSON: {e}"))?;
    let stmts = statements(&doc);
    if stmts.is_empty() {
        return Err("Policy has no statements".into());
    }
    for s in stmts {
        match s.get("Effect").and_then(Value::as_str) {
            Some("Allow") | Some("Deny") => {}
            _ => return Err("Statement Effect must be Allow or Deny".into()),
        }
        if s.get("Principal").is_none() && s.get("NotPrincipal").is_none() {
            return Err("Statement is missing Principal".into());
        }
        let actions = s.get("Action").map(strings).unwrap_or_default();
        if actions.is_empty() && s.get("NotAction").is_none() {
            return Err("Statement is missing Action".into());
        }
        for a in &actions {
            if !(a == "*" || a.to_ascii_lowercase().starts_with("s3:")) {
                return Err(format!("Policy has invalid action: {a}"));
            }
        }
        let resources = s.get("Resource").map(strings).unwrap_or_default();
        if resources.is_empty() && s.get("NotResource").is_none() {
            return Err("Statement is missing Resource".into());
        }
        for r in &resources {
            let rest = r.strip_prefix("arn:aws:s3:::").ok_or_else(|| format!("Policy has invalid resource: {r}"))?;
            let b = rest.split('/').next().unwrap_or("");
            if !wildcard(b, bucket) {
                return Err(format!("Policy has invalid resource: {r} (must refer to bucket {bucket})"));
            }
        }
    }
    Ok(())
}

fn matches_any(patterns: &[String], s: &str, case_insensitive: bool) -> bool {
    patterns.iter().any(|p| {
        if case_insensitive {
            wildcard(&p.to_ascii_lowercase(), &s.to_ascii_lowercase())
        } else {
            wildcard(p, s)
        }
    })
}

/// Does `policy` let an anonymous user perform `action` on `resource`?
pub fn allows_anonymous(policy: &str, action: &str, resource: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<Value>(policy) else { return false };
    let mut allowed = false;
    for s in statements(&doc) {
        let effect = s.get("Effect").and_then(Value::as_str).unwrap_or("");
        let unsupported = ["Condition", "NotAction", "NotResource", "NotPrincipal"].iter().any(|k| s.get(*k).is_some());
        let principal = anonymous_principal(s.get("Principal")) || (effect == "Deny" && s.get("NotPrincipal").is_some());
        if !principal {
            continue;
        }
        let action_ok = matches_any(&s.get("Action").map(strings).unwrap_or_default(), action, true);
        let resource_ok = matches_any(&s.get("Resource").map(strings).unwrap_or_default(), resource, false);
        match effect {
            "Deny" if (action_ok && resource_ok) || unsupported => return false,
            "Allow" if action_ok && resource_ok && !unsupported => allowed = true,
            _ => {}
        }
    }
    allowed
}

/// Canned policy giving anonymous read (download + list) access to a bucket.
pub fn public_read(bucket: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": ["s3:GetBucketLocation", "s3:ListBucket"], "Resource": [format!("arn:aws:s3:::{bucket}")]},
            {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": ["s3:GetObject"], "Resource": [format!("arn:aws:s3:::{bucket}/*")]}
        ]
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_read_policy() {
        let p = public_read("photos");
        assert!(validate("photos", &p).is_ok());
        assert!(allows_anonymous(&p, "s3:GetObject", "arn:aws:s3:::photos/a/b.jpg"));
        assert!(allows_anonymous(&p, "s3:ListBucket", "arn:aws:s3:::photos"));
        assert!(!allows_anonymous(&p, "s3:PutObject", "arn:aws:s3:::photos/a"));
        assert!(!allows_anonymous(&p, "s3:GetObject", "arn:aws:s3:::other/a"));
    }

    #[test]
    fn deny_wins() {
        let p = r#"{"Statement":[
            {"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*"},
            {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/secret/*"}]}"#;
        assert!(allows_anonymous(p, "s3:GetObject", "arn:aws:s3:::b/x"));
        assert!(!allows_anonymous(p, "s3:GetObject", "arn:aws:s3:::b/secret/x"));
    }

    #[test]
    fn conditional_allow_is_ignored() {
        let p = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}"#;
        assert!(!allows_anonymous(p, "s3:GetObject", "arn:aws:s3:::b/x"));
    }

    #[test]
    fn rejects_foreign_bucket() {
        let p = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"}]}"#;
        assert!(validate("mine", p).is_err());
    }
}
