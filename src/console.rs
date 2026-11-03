//! Web console: a small JSON API plus a single-page UI, served on its own port.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, Request, State},
    http::{request::Parts, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::valid_bucket_name,
    auth::{self, Payload},
    blob,
    error::S3Error,
    events::{self, Webhook},
    lifecycle::LifecycleRule,
    listing, ops, policy,
    storage::{AccessKey, ObjectVersion},
    util::{ct_eq, header, random_alnum, random_hex, set_header, uri_encode},
    App,
};

const COOKIE: &str = "bs_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const INDEX: &str = include_str!("../console/index.html");

pub struct Session {
    pub access_key: String,
    pub root: bool,
    pub read_only: bool,
    pub expires: Instant,
}

// ------------------------------------------------------------- errors ----

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<S3Error> for ApiError {
    fn from(e: S3Error) -> Self {
        let msg = match e.code {
            "NoSuchBucket" => "O bucket não existe.".to_string(),
            "BucketNotEmpty" => "O bucket não está vazio.".to_string(),
            "BucketAlreadyOwnedByYou" => "Já existe um bucket com esse nome.".to_string(),
            "NoSuchKey" => "Objeto não encontrado.".to_string(),
            "AccessDenied" => "Acesso negado.".to_string(),
            "KeyTooLongError" => "O nome do objeto é longo demais (máx. 1024 bytes).".to_string(),
            "MalformedPolicy" => format!("Política inválida: {}", e.message),
            "InternalError" => "Erro interno do servidor.".to_string(),
            _ => e.message,
        };
        ApiError(e.status, msg)
    }
}

type R<T> = Result<T, ApiError>;

fn bad(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, m.into())
}

fn forbidden() -> ApiError {
    ApiError(StatusCode::FORBIDDEN, "Sua chave de acesso não tem permissão para esta ação.".into())
}

// ------------------------------------------------------------ session ----

#[derive(Clone)]
pub struct Auth {
    access_key: String,
    root: bool,
    read_only: bool,
}

impl Auth {
    fn writable(&self) -> R<()> {
        if self.read_only { Err(forbidden()) } else { Ok(()) }
    }
    fn require_root(&self) -> R<()> {
        if self.root { Ok(()) } else { Err(forbidden()) }
    }
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

impl FromRequestParts<Arc<App>> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        let unauth = || ApiError(StatusCode::UNAUTHORIZED, "Sessão expirada. Entre novamente.".into());
        let token = cookie(&parts.headers, COOKIE).ok_or_else(unauth)?;
        // Mutating requests must carry a custom header, which a cross-site
        // form cannot send (CSRF protection on top of SameSite=Strict).
        if parts.method != Method::GET && parts.method != Method::HEAD && header(&parts.headers, "x-boxspace-csrf") != Some("1") {
            return Err(ApiError(StatusCode::FORBIDDEN, "Requisição sem cabeçalho CSRF.".into()));
        }
        let now = Instant::now();
        let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, s| s.expires > now);
        let s = sessions.get(&token).ok_or_else(unauth)?;
        Ok(Auth { access_key: s.access_key.clone(), root: s.root, read_only: s.read_only })
    }
}

// ------------------------------------------------------------- router ----

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/info", get(info))
        .route("/api/buckets", get(buckets_list).post(bucket_create))
        .route("/api/buckets/{b}", get(bucket_get).delete(bucket_delete))
        .route("/api/buckets/{b}/versioning", put(bucket_versioning))
        .route("/api/buckets/{b}/encryption", put(bucket_encryption))
        .route("/api/buckets/{b}/policy", put(bucket_policy))
        .route("/api/buckets/{b}/lifecycle", put(bucket_lifecycle))
        .route("/api/buckets/{b}/webhooks", put(bucket_webhooks))
        .route("/api/buckets/{b}/objects", get(objects_list))
        .route("/api/buckets/{b}/object", get(object_info).put(object_upload).delete(object_delete))
        .route("/api/buckets/{b}/prefix", delete(prefix_delete))
        .route("/api/buckets/{b}/download", get(download))
        .route("/api/buckets/{b}/share", post(share))
        .route("/api/keys", get(keys_list).post(keys_create))
        .route("/api/keys/{ak}", delete(keys_delete))
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    set_header(h, "x-frame-options", "DENY");
    set_header(h, "x-content-type-options", "nosniff");
    set_header(h, "referrer-policy", "no-referrer");
    set_header(
        h,
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    set_header(h, "cache-control", "no-store");
    r
}

// -------------------------------------------------------------- login ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginReq {
    access_key: String,
    secret_key: String,
}

async fn login(State(app): State<Arc<App>>, Json(req): Json<LoginReq>) -> R<Response> {
    let found = auth::lookup(&app, req.access_key.trim())?;
    let ok = found.as_ref().is_some_and(|(secret, _)| ct_eq(secret.as_bytes(), req.secret_key.as_bytes()));
    let Some((_, id)) = found.filter(|_| ok) else {
        tokio::time::sleep(Duration::from_millis(600)).await; // slow down guessing
        return Err(ApiError(StatusCode::UNAUTHORIZED, "Access key ou secret key incorretas.".into()));
    };
    let token = random_hex(32);
    app.sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(
        token.clone(),
        Session { access_key: id.access_key.clone(), root: id.root, read_only: id.read_only, expires: Instant::now() + SESSION_TTL },
    );
    let mut r = Json(json!({ "accessKey": id.access_key, "root": id.root, "readOnly": id.read_only })).into_response();
    set_header(
        r.headers_mut(),
        "set-cookie",
        &format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", SESSION_TTL.as_secs()),
    );
    Ok(r)
}

async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie(&headers, COOKIE) {
        app.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&t);
    }
    let mut r = Json(json!({ "ok": true })).into_response();
    set_header(r.headers_mut(), "set-cookie", &format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"));
    r
}

async fn session(a: Auth) -> Json<Value> {
    Json(json!({ "accessKey": a.access_key, "root": a.root, "readOnly": a.read_only }))
}

async fn info(State(app): State<Arc<App>>, a: Auth) -> R<Json<Value>> {
    let buckets = app.store.list_buckets()?;
    let (mut objects, mut bytes) = (0u64, 0u64);
    for b in &buckets {
        let (o, s) = app.store.bucket_usage(&b.name)?;
        objects += o;
        bytes += s;
    }
    Ok(Json(json!({
        "version": crate::config::VERSION,
        "region": app.cfg.region,
        "serverUrl": app.cfg.server_url,
        "buckets": buckets.len(),
        "objects": objects,
        "bytes": bytes,
        "defaultCredentials": a.root && app.cfg.using_default_credentials(),
        "keys": if a.root { app.store.list_keys()?.len() } else { 0 },
    })))
}

// ------------------------------------------------------------ buckets ----

fn is_public(bucket: &str, policy: Option<&str>) -> bool {
    policy.is_some_and(|p| policy::allows_anonymous(p, "s3:GetObject", &format!("arn:aws:s3:::{bucket}/x")))
}

async fn buckets_list(State(app): State<Arc<App>>, _a: Auth) -> R<Json<Value>> {
    let mut buckets = app.store.list_buckets()?;
    buckets.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::new();
    for b in buckets {
        let (objects, bytes) = app.store.bucket_usage(&b.name)?;
        out.push(json!({
            "name": b.name,
            "created": b.created,
            "versioning": b.versioning,
            "encryption": b.encryption,
            "public": is_public(&b.name, b.policy.as_deref()),
            "objects": objects,
            "bytes": bytes,
        }));
    }
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
struct NameReq {
    name: String,
}

async fn bucket_create(State(app): State<Arc<App>>, a: Auth, Json(req): Json<NameReq>) -> R<Json<Value>> {
    a.writable()?;
    let name = req.name.trim();
    if !valid_bucket_name(name) {
        return Err(bad(
            "Nome inválido. Use 3 a 63 caracteres: letras minúsculas, números, pontos e hífens, começando e terminando com letra ou número.",
        ));
    }
    app.store.create_bucket(name)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ForceQ {
    #[serde(default)]
    force: bool,
}

async fn bucket_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<ForceQ>) -> R<Json<Value>> {
    a.writable()?;
    if q.force {
        ops::empty_bucket(&app, &b).await?;
    }
    ops::delete_bucket(&app, &b).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct RuleJson {
    id: String,
    prefix: String,
    enabled: bool,
    expiration_days: Option<u32>,
    noncurrent_days: Option<u32>,
    abort_days: Option<u32>,
    expired_delete_marker: bool,
}

async fn bucket_get(State(app): State<Arc<App>>, _a: Auth, Path(b): Path<String>) -> R<Json<Value>> {
    let bm = app.store.bucket(&b)?;
    let (objects, bytes) = app.store.bucket_usage(&b)?;
    let rules: Vec<RuleJson> = bm
        .lifecycle
        .iter()
        .map(|r| RuleJson {
            id: r.id.clone(),
            prefix: r.prefix.clone(),
            enabled: r.enabled,
            expiration_days: r.expiration_days,
            noncurrent_days: r.noncurrent_days,
            abort_days: r.abort_days,
            expired_delete_marker: r.expired_delete_marker,
        })
        .collect();
    Ok(Json(json!({
        "name": bm.name,
        "created": bm.created,
        "versioning": bm.versioning,
        "encryption": bm.encryption,
        "policyMode": match bm.policy.as_deref() {
            None => "private",
            Some(p) if serde_json::from_str::<Value>(p).ok() == serde_json::from_str::<Value>(&policy::public_read(&b)).ok() => "public-read",
            Some(_) => "custom",
        },
        "policy": bm.policy,
        "public": is_public(&b, bm.policy.as_deref()),
        "lifecycle": rules,
        "webhooks": bm.webhooks,
        "cors": bm.cors.len(),
        "tags": bm.tags,
        "objects": objects,
        "bytes": bytes,
    })))
}

#[derive(Deserialize)]
struct EnabledReq {
    enabled: bool,
}

async fn bucket_versioning(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<EnabledReq>) -> R<Json<Value>> {
    a.writable()?;
    app.store.update_bucket(&b, |m| {
        if req.enabled {
            m.versioning = Some("Enabled".into());
        } else if m.versioning.is_some() {
            m.versioning = Some("Suspended".into());
        }
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

async fn bucket_encryption(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<EnabledReq>) -> R<Json<Value>> {
    a.writable()?;
    app.store.update_bucket(&b, |m| {
        m.encryption = req.enabled;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PolicyReq {
    /// "private" | "public-read" | "custom"
    mode: String,
    policy: Option<String>,
}

async fn bucket_policy(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<PolicyReq>) -> R<Json<Value>> {
    a.writable()?;
    let p = match req.mode.as_str() {
        "private" => None,
        "public-read" => Some(policy::public_read(&b)),
        "custom" => {
            let p = req.policy.unwrap_or_default();
            policy::validate(&b, &p).map_err(|m| bad(format!("Política inválida: {m}")))?;
            Some(p)
        }
        _ => return Err(bad("modo de política desconhecido")),
    };
    app.store.update_bucket(&b, |m| {
        m.policy = p;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct LifecycleReq {
    rules: Vec<RuleJson>,
}

async fn bucket_lifecycle(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<LifecycleReq>) -> R<Json<Value>> {
    a.writable()?;
    let mut rules = Vec::new();
    for (i, r) in req.rules.into_iter().enumerate() {
        if r.expiration_days.is_none() && r.noncurrent_days.is_none() && r.abort_days.is_none() && !r.expired_delete_marker {
            return Err(bad(format!("A regra {} não tem nenhuma ação.", i + 1)));
        }
        if [r.expiration_days, r.noncurrent_days, r.abort_days].contains(&Some(0)) {
            return Err(bad("Os dias devem ser maiores que zero."));
        }
        rules.push(LifecycleRule {
            id: if r.id.trim().is_empty() { format!("regra-{}", i + 1) } else { r.id.trim().to_string() },
            enabled: r.enabled,
            prefix: r.prefix,
            expiration_days: r.expiration_days,
            noncurrent_days: r.noncurrent_days,
            abort_days: r.abort_days,
            expired_delete_marker: r.expired_delete_marker,
            ..Default::default()
        });
    }
    app.store.update_bucket(&b, |m| {
        m.lifecycle = rules;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct WebhooksReq {
    webhooks: Vec<Webhook>,
}

async fn bucket_webhooks(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<WebhooksReq>) -> R<Json<Value>> {
    a.writable()?;
    for w in &req.webhooks {
        if !(w.url.starts_with("http://") || w.url.starts_with("https://")) {
            return Err(bad(format!("URL de webhook inválida: {}", w.url)));
        }
        if let Some(e) = w.events.iter().find(|e| !events::valid_event(e)) {
            return Err(bad(format!("Evento desconhecido: {e}")));
        }
    }
    app.store.update_bucket(&b, |m| {
        m.webhooks = req.webhooks;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------ objects ----

#[derive(Deserialize)]
struct ListQ {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    token: String,
}

fn object_json(v: &ObjectVersion) -> Value {
    json!({
        "key": v.key,
        "size": v.size,
        "lastModified": v.last_modified,
        "etag": v.etag,
        "contentType": v.content_type,
        "encrypted": v.encrypted(),
    })
}

async fn objects_list(State(app): State<Arc<App>>, _a: Auth, Path(b): Path<String>, Query(q): Query<ListQ>) -> R<Json<Value>> {
    app.store.bucket(&b)?;
    let out = listing::list_current(&app.store, &b, &q.prefix, Some("/"), &q.token, 500)?;
    Ok(Json(json!({
        "prefixes": out.prefixes,
        "objects": out.contents.iter().map(object_json).collect::<Vec<_>>(),
        "nextToken": out.next,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyQ {
    key: String,
    version_id: Option<String>,
}

async fn object_info(State(app): State<Arc<App>>, _a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>) -> R<Json<Value>> {
    app.store.bucket(&b)?;
    let versions = app.store.key_versions(&b, &q.key)?;
    let cur = versions.first().filter(|v| !v.delete_marker).ok_or_else(|| ApiError::from(S3Error::no_such_key(&q.key)))?;
    let mut info = object_json(cur);
    info["meta"] = json!(cur.meta);
    info["headers"] = json!(cur.headers);
    info["tags"] = json!(cur.tags);
    info["versionId"] = json!(cur.version_id);
    info["versions"] = versions
        .iter()
        .enumerate()
        .map(|(i, v)| {
            json!({ "versionId": v.version_id, "size": v.size, "lastModified": v.last_modified, "deleteMarker": v.delete_marker, "isLatest": i == 0, "etag": v.etag })
        })
        .collect();
    Ok(Json(info))
}

async fn object_upload(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>, headers: HeaderMap, body: Body) -> R<Json<Value>> {
    a.writable()?;
    let opts = ops::PutOpts {
        content_type: header(&headers, "content-type").filter(|c| !c.is_empty()).map(str::to_string),
        ..Default::default()
    };
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let v = ops::put_object(&app, &b, &q.key, stream, &Payload::Unsigned, opts).await?;
    Ok(Json(object_json(&v)))
}

async fn object_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>) -> R<Json<Value>> {
    a.writable()?;
    let bm = app.store.bucket(&b)?;
    let out = ops::delete_object(&app, &bm, &q.key, q.version_id.as_deref().filter(|v| !v.is_empty())).await?;
    Ok(Json(json!({ "ok": true, "deleteMarker": out.delete_marker })))
}

#[derive(Deserialize)]
struct PrefixQ {
    prefix: String,
}

async fn prefix_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<PrefixQ>) -> R<Json<Value>> {
    a.writable()?;
    if q.prefix.is_empty() {
        return Err(bad("prefixo vazio"));
    }
    let bm = app.store.bucket(&b)?;
    let mut keys = Vec::new();
    let mut last: Option<String> = None;
    app.store.scan(&b, &q.prefix, |v| {
        if !v.key.starts_with(&q.prefix) {
            return false;
        }
        if last.as_deref() != Some(v.key.as_str()) {
            last = Some(v.key.clone());
            if !v.delete_marker {
                keys.push(v.key);
            }
        }
        true
    })?;
    for k in &keys {
        ops::delete_object(&app, &bm, k, None).await?;
    }
    Ok(Json(json!({ "deleted": keys.len() })))
}

async fn download(State(app): State<Arc<App>>, _a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>) -> R<Response> {
    app.store.bucket(&b)?;
    let vid = q.version_id.as_deref().filter(|v| !v.is_empty());
    let v = app
        .store
        .get_version(&b, &q.key, vid)?
        .filter(|v| !v.delete_marker)
        .ok_or_else(|| ApiError::from(S3Error::no_such_key(&q.key)))?;
    let body = match &v.blob {
        Some(bl) if v.size > 0 => Body::from_stream(blob::open_full(&app, bl).await?),
        _ => Body::empty(),
    };
    let mut r = Response::new(body);
    let h = r.headers_mut();
    let name = q.key.rsplit('/').next().unwrap_or("download");
    set_header(h, "content-type", if v.content_type.is_empty() { ops::DEFAULT_CONTENT_TYPE } else { &v.content_type });
    set_header(h, "content-length", &v.size.to_string());
    set_header(h, "content-disposition", &format!("attachment; filename*=UTF-8''{}", uri_encode(name, true)));
    Ok(r)
}

#[derive(Deserialize)]
struct ShareReq {
    key: String,
    expires: u64,
}

async fn share(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<ShareReq>) -> R<Json<Value>> {
    app.store.bucket(&b)?;
    if !(1..=604800).contains(&req.expires) {
        return Err(bad("A validade deve ser de 1 segundo a 7 dias."));
    }
    let (secret, _) = auth::lookup(&app, &a.access_key)?.ok_or_else(forbidden)?;
    let url = auth::presign_get(&app.cfg.server_url, &app.cfg.region, &a.access_key, &secret, &b, &req.key, req.expires);
    let expires_at: DateTime<Utc> = Utc::now() + chrono::Duration::seconds(req.expires as i64);
    Ok(Json(json!({ "url": url, "expiresAt": expires_at })))
}

// --------------------------------------------------------------- keys ----

async fn keys_list(State(app): State<Arc<App>>, a: Auth) -> R<Json<Value>> {
    a.require_root()?;
    let mut keys = app.store.list_keys()?;
    keys.sort_by_key(|k| k.created);
    Ok(Json(Value::Array(
        keys.iter()
            .map(|k| json!({ "accessKey": k.access_key, "readOnly": k.read_only, "description": k.description, "created": k.created }))
            .collect(),
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewKeyReq {
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    description: String,
}

async fn keys_create(State(app): State<Arc<App>>, a: Auth, Json(req): Json<NewKeyReq>) -> R<Json<Value>> {
    a.require_root()?;
    let key = AccessKey {
        access_key: random_alnum(20),
        secret_key: {
            use base64::{engine::general_purpose::STANDARD as B64, Engine};
            B64.encode(crate::util::random_bytes::<30>()).replace(['+', '/'], "x")
        },
        read_only: req.read_only,
        description: req.description.chars().take(200).collect(),
        created: Utc::now(),
    };
    app.store.put_key(&key)?;
    Ok(Json(json!({ "accessKey": key.access_key, "secretKey": key.secret_key, "readOnly": key.read_only })))
}

async fn keys_delete(State(app): State<Arc<App>>, a: Auth, Path(ak): Path<String>) -> R<Json<Value>> {
    a.require_root()?;
    if !app.store.delete_key(&ak)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "Chave não encontrada.".into()));
    }
    app.sessions.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, s| s.access_key != ak);
    Ok(Json(json!({ "ok": true })))
}
