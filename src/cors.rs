//! Bucket CORS configuration.

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, S3Error},
    util::{header, set_header, wildcard},
    App,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct CorsRule {
    pub id: Option<String>,
    pub origins: Vec<String>,
    pub methods: Vec<String>,
    pub headers: Vec<String>,
    pub expose: Vec<String>,
    pub max_age: Option<u32>,
}

#[derive(Deserialize)]
struct CorsXml {
    #[serde(rename = "CORSRule", default)]
    rules: Vec<RuleXml>,
}

#[derive(Deserialize)]
struct RuleXml {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "AllowedOrigin", default)]
    origins: Vec<String>,
    #[serde(rename = "AllowedMethod", default)]
    methods: Vec<String>,
    #[serde(rename = "AllowedHeader", default)]
    headers: Vec<String>,
    #[serde(rename = "ExposeHeader", default)]
    expose: Vec<String>,
    #[serde(rename = "MaxAgeSeconds")]
    max_age: Option<u32>,
}

pub fn parse(body: &[u8]) -> Result<Vec<CorsRule>> {
    let s = std::str::from_utf8(body).map_err(|_| S3Error::malformed_xml())?;
    let x: CorsXml = quick_xml::de::from_str(s).map_err(|_| S3Error::malformed_xml())?;
    if x.rules.is_empty() || x.rules.len() > 100 {
        return Err(S3Error::malformed_xml());
    }
    let mut out = Vec::new();
    for r in x.rules {
        if r.origins.is_empty() || r.methods.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        for m in &r.methods {
            if !["GET", "PUT", "POST", "DELETE", "HEAD"].contains(&m.as_str()) {
                return Err(S3Error::invalid_request(format!("Found unsupported HTTP method in CORS config. Unsupported method is {m}")));
            }
        }
        out.push(CorsRule { id: r.id, origins: r.origins, methods: r.methods, headers: r.headers, expose: r.expose, max_age: r.max_age });
    }
    Ok(out)
}

pub fn to_xml(rules: &[CorsRule]) -> String {
    use crate::util::esc;
    let mut x = format!("<CORSConfiguration xmlns=\"{}\">", crate::util::S3_NS);
    for r in rules {
        x.push_str("<CORSRule>");
        if let Some(id) = &r.id {
            x.push_str(&format!("<ID>{}</ID>", esc(id)));
        }
        for (tag, list) in [("AllowedHeader", &r.headers), ("AllowedMethod", &r.methods), ("AllowedOrigin", &r.origins), ("ExposeHeader", &r.expose)] {
            for v in list {
                x.push_str(&format!("<{tag}>{}</{tag}>", esc(v)));
            }
        }
        if let Some(m) = r.max_age {
            x.push_str(&format!("<MaxAgeSeconds>{m}</MaxAgeSeconds>"));
        }
        x.push_str("</CORSRule>");
    }
    x.push_str("</CORSConfiguration>");
    x
}

fn find<'a>(rules: &'a [CorsRule], origin: &str, method: &str, req_headers: &[String]) -> Option<&'a CorsRule> {
    rules.iter().find(|r| {
        r.origins.iter().any(|o| wildcard(o, origin))
            && r.methods.iter().any(|m| m == method)
            && req_headers.iter().all(|h| r.headers.iter().any(|a| wildcard(&a.to_ascii_lowercase(), &h.to_ascii_lowercase())))
    })
}

fn write_headers(h: &mut HeaderMap, rule: &CorsRule, origin: &str) {
    let any = rule.origins.iter().any(|o| o == "*");
    set_header(h, "access-control-allow-origin", if any { "*" } else { origin });
    if !any {
        set_header(h, "access-control-allow-credentials", "true");
    }
    set_header(h, "vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method");
    set_header(h, "access-control-allow-methods", &rule.methods.join(", "));
    if !rule.expose.is_empty() {
        set_header(h, "access-control-expose-headers", &rule.expose.join(", "));
    }
    if let Some(m) = rule.max_age {
        set_header(h, "access-control-max-age", &m.to_string());
    }
}

fn forbidden() -> S3Error {
    S3Error::new("AccessForbidden", 403, "CORSResponse: This CORS request is not allowed.")
}

/// Answer an OPTIONS preflight request.
pub fn preflight(app: &App, bucket: Option<&str>, headers: &HeaderMap) -> Result<Response> {
    let origin = header(headers, "origin").ok_or_else(|| S3Error::new("BadRequest", 400, "Insufficient information. Origin request header needed."))?;
    let method = header(headers, "access-control-request-method")
        .ok_or_else(|| S3Error::new("BadRequest", 400, "Invalid Access-Control-Request-Method header."))?;
    let req_headers: Vec<String> = header(headers, "access-control-request-headers")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let bucket = bucket.ok_or_else(forbidden)?;
    let bm = app.store.get_bucket(bucket)?.ok_or_else(forbidden)?;
    let rule = find(&bm.cors, origin, method, &req_headers).ok_or_else(forbidden)?;
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    write_headers(h, rule, origin);
    if !req_headers.is_empty() {
        set_header(h, "access-control-allow-headers", &req_headers.join(", "));
    }
    Ok(resp)
}

/// Add CORS headers to an actual (non-preflight) response.
pub fn apply(app: &App, bucket: &str, origin: &str, method: &str, resp: &mut Response) {
    if let Ok(Some(bm)) = app.store.get_bucket(bucket)
        && let Some(rule) = find(&bm.cors, origin, method, &[])
    {
        write_headers(resp.headers_mut(), rule, origin);
    }
}
