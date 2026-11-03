//! Web console: a small JSON API plus a single-page UI, served on its own port.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, Request, State},
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
use tokio_stream_shim::ReceiverStream;

use crate::{
    api::{client_ip, valid_bucket_name},
    audit,
    auth::{self, Payload},
    blob,
    error::S3Error,
    events::{self, Webhook},
    lifecycle::LifecycleRule,
    listing, ops, policy, replication,
    storage::{AccessKey, Grant, ObjectVersion, ReplTarget, Scan},
    util::{ct_eq, header, random_alnum, random_hex, set_header, uri_encode},
    view, zip, App,
};

const COOKIE: &str = "bs_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const INDEX: &str = include_str!("../console/index.html");

pub struct Session {
    pub access_key: String,
    pub root: bool,
    pub read_only: bool,
    pub grants: Vec<Grant>,
    pub expires: Instant,
    /// One-time ZIP download tokens: token -> (bucket, keys).
    pub zips: Vec<(String, String, Vec<String>, Instant)>,
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
            "SlowDown" => "Não há discos online suficientes para concluir a operação.".to_string(),
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
    grants: Vec<Grant>,
}

impl Auth {
    fn identity(&self) -> auth::Identity {
        auth::Identity { access_key: self.access_key.clone(), root: self.root, read_only: self.read_only, grants: self.grants.clone() }
    }
    fn read(&self, bucket: &str) -> R<()> {
        if self.identity().can(bucket, false) { Ok(()) } else { Err(forbidden()) }
    }
    fn write(&self, bucket: &str) -> R<()> {
        if self.identity().can(bucket, true) { Ok(()) } else { Err(forbidden()) }
    }
    /// Unrestricted read-write key (bucket creation and settings).
    fn admin(&self) -> R<()> {
        if self.identity().admin() { Ok(()) } else { Err(forbidden()) }
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

fn session_key(app: &App, h: &HeaderMap) -> Option<String> {
    let token = cookie(h, COOKIE)?;
    let s = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    s.get(&token).filter(|s| s.expires > Instant::now()).map(|s| s.access_key.clone())
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
        Ok(Auth { access_key: s.access_key.clone(), root: s.root, read_only: s.read_only, grants: s.grants.clone() })
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
        .route("/api/system", get(system))
        .route("/api/system/heal", post(heal_now))
        .route("/api/audit", get(audit_list))
        .route("/api/buckets", get(buckets_list).post(bucket_create))
        .route("/api/buckets/{b}", get(bucket_get).delete(bucket_delete))
        .route("/api/buckets/{b}/versioning", put(bucket_versioning))
        .route("/api/buckets/{b}/encryption", put(bucket_encryption))
        .route("/api/buckets/{b}/readable", put(bucket_readable))
        .route("/api/buckets/{b}/policy", put(bucket_policy))
        .route("/api/buckets/{b}/lifecycle", put(bucket_lifecycle))
        .route("/api/buckets/{b}/webhooks", put(bucket_webhooks))
        .route("/api/buckets/{b}/replication", put(replication_set))
        .route("/api/buckets/{b}/replication/test", post(replication_test))
        .route("/api/buckets/{b}/replication/retry", post(replication_retry))
        .route("/api/buckets/{b}/replication/{id}/resync", post(replication_resync))
        .route("/api/buckets/{b}/objects", get(objects_list))
        .route("/api/buckets/{b}/search", get(objects_search))
        .route("/api/buckets/{b}/object", get(object_info).put(object_upload).delete(object_delete))
        .route("/api/buckets/{b}/prefix", delete(prefix_delete))
        .route("/api/buckets/{b}/bulk-delete", post(bulk_delete))
        .route("/api/buckets/{b}/zip", post(zip_prepare))
        .route("/api/zip/{token}", get(zip_download))
        .route("/api/buckets/{b}/download", get(download))
        .route("/api/buckets/{b}/share", post(share))
        .route("/api/keys", get(keys_list).post(keys_create))
        .route("/api/keys/{ak}", put(keys_update).delete(keys_delete))
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn_with_state(app.clone(), audit_layer))
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

async fn security_headers(req: Request, next: Next) -> Response {
    let preview = req.uri().query().is_some_and(|q| q.contains("inline=1"));
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    set_header(h, "x-frame-options", if preview { "SAMEORIGIN" } else { "DENY" });
    set_header(h, "x-content-type-options", "nosniff");
    set_header(h, "referrer-policy", "no-referrer");
    if !preview {
        set_header(
            h,
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self'; frame-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        );
    }
    set_header(h, "cache-control", "no-store");
    r
}

/// Record console API calls in the audit log.
async fn audit_layer(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    // Logins are audited by the handler itself (it knows the key and outcome).
    if !path.starts_with("/api/") || path == "/api/login" || !app.audit.enabled() {
        return next.run(req).await;
    }
    let started = Instant::now();
    let method = req.method().clone();
    let remote = client_ip(&app, req.headers(), peer);
    let key = session_key(&app, req.headers());
    let ua = header(req.headers(), "user-agent").map(str::to_string);
    let bucket = path.strip_prefix("/api/buckets/").and_then(|r| r.split('/').next()).map(crate::util::decode);
    let query_key = req.uri().query().and_then(|q| crate::util::Query::parse(Some(q)).get("key").map(str::to_string));
    let resp = next.run(req).await;
    let reads = method == Method::GET && !path.ends_with("/download") && !path.starts_with("/api/zip/");
    if !reads {
        app.audit.log(audit::Entry {
            time: Utc::now(),
            request_id: random_hex(8).to_uppercase(),
            source: "console".into(),
            op: format!("{method} {path}"),
            method: method.to_string(),
            bucket,
            key: query_key,
            status: resp.status().as_u16(),
            access_key: key,
            remote,
            duration_ms: started.elapsed().as_millis() as u64,
            user_agent: ua,
            ..Default::default()
        });
    }
    resp
}

// -------------------------------------------------------------- login ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginReq {
    access_key: String,
    secret_key: String,
}

fn session_json(a: &Auth) -> Value {
    json!({ "accessKey": a.access_key, "root": a.root, "readOnly": a.read_only, "admin": a.identity().admin(), "grants": a.grants })
}

async fn login(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(req): Json<LoginReq>) -> R<Response> {
    let ak = req.access_key.trim().to_string();
    let found = auth::lookup(&app, &ak)?;
    let ok = found.as_ref().is_some_and(|(secret, _)| ct_eq(secret.as_bytes(), req.secret_key.as_bytes()));
    app.audit.log(audit::Entry {
        time: Utc::now(),
        request_id: random_hex(8).to_uppercase(),
        source: "console".into(),
        op: if ok { "ConsoleLogin".into() } else { "ConsoleLoginFailed".into() },
        method: "POST".into(),
        status: if ok { 200 } else { 401 },
        access_key: Some(ak.chars().take(128).collect()),
        remote: client_ip(&app, &headers, peer),
        user_agent: header(&headers, "user-agent").map(str::to_string),
        ..Default::default()
    });
    let Some((_, id)) = found.filter(|_| ok) else {
        tokio::time::sleep(Duration::from_millis(600)).await; // slow down guessing
        return Err(ApiError(StatusCode::UNAUTHORIZED, "Access key ou secret key incorretas.".into()));
    };
    let token = random_hex(32);
    app.sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(
        token.clone(),
        Session {
            access_key: id.access_key.clone(),
            root: id.root,
            read_only: id.read_only,
            grants: id.grants.clone(),
            expires: Instant::now() + SESSION_TTL,
            zips: Vec::new(),
        },
    );
    let a = Auth { access_key: id.access_key, root: id.root, read_only: id.read_only, grants: id.grants };
    let mut r = Json(session_json(&a)).into_response();
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
    Json(session_json(&a))
}

async fn info(State(app): State<Arc<App>>, a: Auth) -> R<Json<Value>> {
    let buckets: Vec<_> = app.store.list_buckets()?.into_iter().filter(|b| a.read(&b.name).is_ok()).collect();
    let (mut objects, mut bytes) = (0i64, 0i64);
    for b in &buckets {
        let s = app.store.stats(&b.name)?;
        objects += s.objects;
        bytes += s.bytes;
    }
    let heal = app.healer.snapshot();
    Ok(Json(json!({
        "version": crate::config::VERSION,
        "region": app.cfg.region,
        "serverUrl": app.cfg.server_url,
        "buckets": buckets.len(),
        "objects": objects,
        "bytes": bytes,
        "defaultCredentials": a.root && app.cfg.using_default_credentials(),
        "keys": if a.root { app.store.list_keys()?.len() } else { 0 },
        "mode": app.disks.mode.label(),
        "disks": app.disks.list.len(),
        "disksOnline": app.disks.online_count(),
        "lost": heal.lost_count,
    })))
}

// ------------------------------------------------------------- system ----

async fn system(State(app): State<Arc<App>>, a: Auth) -> R<Json<Value>> {
    a.admin()?;
    let disks: Vec<Value> = app
        .disks
        .list
        .iter()
        .map(|d| {
            let (free, total) = d.space().unwrap_or((0, 0));
            json!({ "index": d.idx, "path": d.root.display().to_string(), "online": d.online(), "free": free, "total": total })
        })
        .collect();
    Ok(Json(json!({
        "mode": app.disks.mode.label(),
        "parity": app.disks.parity,
        "dataShards": app.disks.data_shards(),
        "disks": disks,
        "writable": app.disks.writable(),
        "heal": app.healer.snapshot(),
        "healIntervalSecs": app.cfg.heal_interval_secs,
        "replication": replication::stats(&app, None),
        "audit": app.audit.enabled(),
        "metricsProtected": !app.cfg.metrics_public,
        "metricsEnabled": app.cfg.metrics_public || app.cfg.metrics_token.is_some(),
    })))
}

#[derive(Deserialize)]
struct HealReq {
    #[serde(default)]
    deep: bool,
}

async fn heal_now(State(app): State<Arc<App>>, a: Auth, Json(req): Json<HealReq>) -> R<Json<Value>> {
    a.admin()?;
    app.healer.request(req.deep);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct AuditQ {
    #[serde(default)]
    key: String,
    #[serde(default)]
    bucket: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    errors: String,
    limit: Option<usize>,
}

async fn audit_list(State(app): State<Arc<App>>, a: Auth, Query(q): Query<AuditQ>) -> R<Json<Value>> {
    a.require_root()?;
    if !app.audit.enabled() {
        return Ok(Json(json!({ "enabled": false, "entries": [] })));
    }
    let limit = q.limit.unwrap_or(200).min(1000);
    let op = q.op.to_lowercase();
    let entries = app.audit.tail(limit, |e| {
        (q.key.is_empty() || e.access_key.as_deref() == Some(q.key.as_str()))
            && (q.bucket.is_empty() || e.bucket.as_deref() == Some(q.bucket.as_str()))
            && (op.is_empty() || e.op.to_lowercase().contains(&op))
            && (!matches!(q.errors.as_str(), "1" | "true") || e.status >= 400)
    });
    Ok(Json(json!({ "enabled": true, "entries": entries })))
}

// ------------------------------------------------------------ buckets ----

fn is_public(bucket: &str, policy: Option<&str>) -> bool {
    policy.is_some_and(|p| policy::allows_anonymous(p, "s3:GetObject", &format!("arn:aws:s3:::{bucket}/x")))
}

async fn buckets_list(State(app): State<Arc<App>>, a: Auth) -> R<Json<Value>> {
    let mut buckets: Vec<_> = app.store.list_buckets()?.into_iter().filter(|b| a.read(&b.name).is_ok()).collect();
    buckets.sort_by(|x, y| x.name.cmp(&y.name));
    let mut out = Vec::new();
    for b in buckets {
        let s = app.store.stats(&b.name)?;
        out.push(json!({
            "name": b.name,
            "created": b.created,
            "versioning": b.versioning,
            "encryption": b.encryption,
            "readable": b.readable,
            "replicated": b.replication.iter().any(|t| t.enabled),
            "public": is_public(&b.name, b.policy.as_deref()),
            "objects": s.objects,
            "bytes": s.bytes,
            "writable": a.write(&b.name).is_ok(),
        }));
    }
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
struct CreateReq {
    name: String,
    #[serde(default)]
    readable: bool,
}

async fn bucket_create(State(app): State<Arc<App>>, a: Auth, Json(req): Json<CreateReq>) -> R<Json<Value>> {
    a.admin()?;
    let name = req.name.trim();
    if !valid_bucket_name(name) {
        return Err(bad(
            "Nome inválido. Use 3 a 63 caracteres: letras minúsculas, números, pontos e hífens, começando e terminando com letra ou número.",
        ));
    }
    app.store.create_bucket(name)?;
    if req.readable {
        app.store.update_bucket(name, |m| {
            m.readable = true;
            Ok(())
        })?;
        let _ = tokio::fs::create_dir_all(view::bucket_root(&app, name)).await;
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ForceQ {
    #[serde(default)]
    force: bool,
}

async fn bucket_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<ForceQ>) -> R<Json<Value>> {
    a.admin()?;
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

fn target_json(t: &ReplTarget) -> Value {
    json!({
        "id": t.id, "endpoint": t.endpoint, "bucket": t.bucket, "region": t.region,
        "accessKey": t.access_key, "prefix": t.prefix, "replicateDeletes": t.replicate_deletes, "enabled": t.enabled,
    })
}

async fn bucket_get(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>) -> R<Json<Value>> {
    a.read(&b)?;
    let bm = app.store.bucket(&b)?;
    let s = app.store.stats(&b)?;
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
        "readable": bm.readable,
        "readablePath": view::bucket_root(&app, &b).display().to_string(),
        "policyMode": match bm.policy.as_deref() {
            None => "private",
            Some(p) if serde_json::from_str::<Value>(p).ok() == serde_json::from_str::<Value>(&policy::public_read(&b)).ok() => "public-read",
            Some(_) => "custom",
        },
        "policy": bm.policy,
        "public": is_public(&b, bm.policy.as_deref()),
        "lifecycle": rules,
        "webhooks": bm.webhooks,
        "replication": bm.replication.iter().map(target_json).collect::<Vec<_>>(),
        "replicationStats": replication::stats(&app, Some(&b)),
        "cors": bm.cors.len(),
        "tags": bm.tags,
        "objects": s.objects,
        "versions": s.versions,
        "bytes": s.bytes,
        "canAdmin": a.admin().is_ok(),
        "canWrite": a.write(&b).is_ok(),
        "mode": app.disks.mode.label(),
    })))
}

#[derive(Deserialize)]
struct EnabledReq {
    enabled: bool,
}

async fn bucket_versioning(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<EnabledReq>) -> R<Json<Value>> {
    a.admin()?;
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
    a.admin()?;
    let bm = app.store.bucket(&b)?;
    if req.enabled && bm.readable {
        return Err(bad("Desative os arquivos legíveis no disco antes de ativar a criptografia: arquivos cifrados não podem ser lidos fora do BoxSpace."));
    }
    app.store.update_bucket(&b, |m| {
        m.encryption = req.enabled;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

async fn bucket_readable(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<EnabledReq>) -> R<Json<Value>> {
    a.admin()?;
    let bm = app.store.bucket(&b)?;
    if req.enabled && bm.encryption {
        return Err(bad("Desative a criptografia do bucket antes: arquivos cifrados não podem ser lidos fora do BoxSpace."));
    }
    if req.enabled == bm.readable {
        return Ok(Json(json!({ "ok": true })));
    }
    app.store.update_bucket(&b, |m| {
        m.readable = req.enabled;
        Ok(())
    })?;
    let app2 = app.clone();
    if req.enabled {
        tokio::spawn(async move { view::backfill(&app2, &b).await });
    } else {
        view::clear(&app2, &b).await;
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PolicyReq {
    /// "private" | "public-read" | "custom"
    mode: String,
    policy: Option<String>,
}

async fn bucket_policy(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<PolicyReq>) -> R<Json<Value>> {
    a.admin()?;
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
    a.admin()?;
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
    a.admin()?;
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

// -------------------------------------------------------- replication ----

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct TargetReq {
    id: String,
    endpoint: String,
    bucket: String,
    region: String,
    access_key: String,
    /// Empty when editing = keep the stored secret.
    secret_key: String,
    prefix: String,
    replicate_deletes: bool,
    enabled: bool,
}

#[derive(Deserialize)]
struct TargetsReq {
    targets: Vec<TargetReq>,
}

fn validate_target(t: &TargetReq) -> R<()> {
    if !(t.endpoint.starts_with("http://") || t.endpoint.starts_with("https://")) {
        return Err(bad("O endereço do destino deve começar com http:// ou https://"));
    }
    if t.bucket.trim().is_empty() || t.access_key.trim().is_empty() {
        return Err(bad("Informe o bucket de destino e a access key."));
    }
    Ok(())
}

async fn replication_set(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<TargetsReq>) -> R<Json<Value>> {
    a.admin()?;
    let bm = app.store.bucket(&b)?;
    let mut targets = Vec::new();
    let mut new_ids = Vec::new();
    for t in req.targets {
        validate_target(&t)?;
        let existing = bm.replication.iter().find(|x| !t.id.is_empty() && x.id == t.id);
        let secret_enc = if !t.secret_key.is_empty() {
            app.kms.seal_bytes(t.secret_key.as_bytes())
        } else if let Some(e) = existing {
            e.secret_enc.clone()
        } else {
            return Err(bad("Informe a secret key do destino."));
        };
        let id = if existing.is_some() { t.id.clone() } else { uuid::Uuid::new_v4().simple().to_string()[..12].to_string() };
        if existing.is_none() {
            new_ids.push(id.clone());
        }
        targets.push(ReplTarget {
            id,
            endpoint: t.endpoint.trim().trim_end_matches('/').to_string(),
            bucket: t.bucket.trim().to_string(),
            region: t.region.trim().to_string(),
            access_key: t.access_key.trim().to_string(),
            secret_enc,
            prefix: t.prefix,
            replicate_deletes: t.replicate_deletes,
            enabled: t.enabled,
        });
    }
    let bm = app.store.update_bucket(&b, |m| {
        m.replication = targets;
        Ok(())
    })?;
    // New targets receive the existing objects.
    let mut queued = 0;
    for id in new_ids {
        queued += replication::resync(&app, &bm, &id)?;
    }
    Ok(Json(json!({ "ok": true, "queued": queued })))
}

async fn replication_test(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(t): Json<TargetReq>) -> R<Json<Value>> {
    a.admin()?;
    validate_target(&t)?;
    let bm = app.store.bucket(&b)?;
    let secret = if !t.secret_key.is_empty() {
        t.secret_key.clone()
    } else {
        let e = bm.replication.iter().find(|x| x.id == t.id).ok_or_else(|| bad("Informe a secret key do destino."))?;
        String::from_utf8(app.kms.open_bytes(&e.secret_enc).map_err(bad)?).map_err(|e| bad(e.to_string()))?
    };
    let target = ReplTarget {
        endpoint: t.endpoint.trim().trim_end_matches('/').to_string(),
        bucket: t.bucket.trim().to_string(),
        region: t.region.trim().to_string(),
        access_key: t.access_key.trim().to_string(),
        ..Default::default()
    };
    let client = replication::Client { app: &app, t: &target, secret: &secret };
    match client.check().await {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) => Ok(Json(json!({ "ok": false, "error": e }))),
    }
}

async fn replication_retry(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>) -> R<Json<Value>> {
    a.admin()?;
    Ok(Json(json!({ "retried": replication::retry_failed(&app, &b) })))
}

async fn replication_resync(State(app): State<Arc<App>>, a: Auth, Path((b, id)): Path<(String, String)>) -> R<Json<Value>> {
    a.admin()?;
    let bm = app.store.bucket(&b)?;
    Ok(Json(json!({ "queued": replication::resync(&app, &bm, &id)? })))
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

async fn objects_list(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<ListQ>) -> R<Json<Value>> {
    a.read(&b)?;
    app.store.bucket(&b)?;
    let out = listing::list_current(&app.store, &b, &q.prefix, Some("/"), &q.token, 500)?;
    Ok(Json(json!({
        "prefixes": out.prefixes,
        "objects": out.contents.iter().map(object_json).collect::<Vec<_>>(),
        "nextToken": out.next,
    })))
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    #[serde(default)]
    prefix: String,
}

/// Case-insensitive substring search over current object names.
async fn objects_search(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<SearchQ>) -> R<Json<Value>> {
    a.read(&b)?;
    app.store.bucket(&b)?;
    let needle = q.q.to_lowercase();
    if needle.trim().is_empty() {
        return Err(bad("Digite algo para buscar."));
    }
    let mut found = Vec::new();
    let mut last: Option<String> = None;
    let mut scanned = 0u64;
    let mut truncated = false;
    app.store.scan(&b, &q.prefix, |v| {
        if !v.key.starts_with(&q.prefix) {
            return Scan::Stop;
        }
        if last.as_deref() == Some(v.key.as_str()) {
            return Scan::Next;
        }
        last = Some(v.key.clone());
        scanned += 1;
        if !v.delete_marker && v.key.to_lowercase().contains(&needle) {
            found.push(object_json(&v));
            if found.len() >= 200 {
                truncated = true;
                return Scan::Stop;
            }
        }
        Scan::Next
    })?;
    Ok(Json(json!({ "objects": found, "truncated": truncated, "scanned": scanned })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyQ {
    key: String,
    version_id: Option<String>,
    #[serde(default)]
    inline: Option<String>,
}

async fn object_info(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>) -> R<Json<Value>> {
    a.read(&b)?;
    let bm = app.store.bucket(&b)?;
    let versions = app.store.key_versions(&b, &q.key)?;
    let cur = versions.first().filter(|v| !v.delete_marker).ok_or_else(|| ApiError::from(S3Error::no_such_key(&q.key)))?;
    let mut info = object_json(cur);
    info["meta"] = json!(cur.meta);
    info["headers"] = json!(cur.headers);
    info["tags"] = json!(cur.tags);
    info["versionId"] = json!(cur.version_id);
    info["parts"] = json!(cur.parts);
    if bm.readable && !cur.encrypted() {
        info["diskPath"] = json!(view::view_path(&app, &b, &q.key).map(|p| p.display().to_string()));
    }
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
    a.write(&b)?;
    let opts = ops::PutOpts {
        content_type: header(&headers, "content-type").filter(|c| !c.is_empty()).map(str::to_string),
        ..Default::default()
    };
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let v = ops::put_object(&app, &b, &q.key, stream, &Payload::Unsigned, opts).await?;
    Ok(Json(object_json(&v)))
}

async fn object_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>) -> R<Json<Value>> {
    a.write(&b)?;
    let bm = app.store.bucket(&b)?;
    let out = ops::delete_object(&app, &bm, &q.key, q.version_id.as_deref().filter(|v| !v.is_empty()), false).await?;
    Ok(Json(json!({ "ok": true, "deleteMarker": out.delete_marker })))
}

/// Current keys under `prefix`.
fn keys_under(app: &App, bucket: &str, prefix: &str) -> R<Vec<String>> {
    let mut keys = Vec::new();
    let mut last: Option<String> = None;
    app.store.scan(bucket, prefix, |v| {
        if !v.key.starts_with(prefix) {
            return Scan::Stop;
        }
        if last.as_deref() != Some(v.key.as_str()) {
            last = Some(v.key.clone());
            if !v.delete_marker {
                keys.push(v.key);
            }
        }
        Scan::Next
    })?;
    Ok(keys)
}

#[derive(Deserialize)]
struct PrefixQ {
    prefix: String,
}

async fn prefix_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<PrefixQ>) -> R<Json<Value>> {
    a.write(&b)?;
    if q.prefix.is_empty() {
        return Err(bad("prefixo vazio"));
    }
    let bm = app.store.bucket(&b)?;
    let keys = keys_under(&app, &b, &q.prefix)?;
    for k in &keys {
        ops::delete_object(&app, &bm, k, None, false).await?;
    }
    Ok(Json(json!({ "deleted": keys.len() })))
}

#[derive(Deserialize)]
struct SelectionReq {
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    prefixes: Vec<String>,
}

fn expand(app: &App, bucket: &str, sel: &SelectionReq) -> R<Vec<String>> {
    let mut keys = sel.keys.clone();
    for p in sel.prefixes.iter().filter(|p| !p.is_empty()) {
        keys.extend(keys_under(app, bucket, p)?);
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

async fn bulk_delete(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(sel): Json<SelectionReq>) -> R<Json<Value>> {
    a.write(&b)?;
    let bm = app.store.bucket(&b)?;
    let keys = expand(&app, &b, &sel)?;
    let mut deleted = 0;
    for k in &keys {
        if ops::delete_object(&app, &bm, k, None, false).await.is_ok() {
            deleted += 1;
        }
    }
    Ok(Json(json!({ "deleted": deleted })))
}

async fn zip_prepare(State(app): State<Arc<App>>, a: Auth, headers: HeaderMap, Path(b): Path<String>, Json(sel): Json<SelectionReq>) -> R<Json<Value>> {
    a.read(&b)?;
    app.store.bucket(&b)?;
    let keys = expand(&app, &b, &sel)?;
    if keys.is_empty() {
        return Err(bad("Nada selecionado."));
    }
    if keys.len() > 50_000 {
        return Err(bad("Selecione no máximo 50.000 arquivos por download."));
    }
    let token = random_hex(24);
    let session = cookie(&headers, COOKIE).unwrap_or_default();
    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let s = sessions.get_mut(&session).ok_or_else(forbidden)?;
    s.zips.retain(|z| z.3 > Instant::now());
    s.zips.push((token.clone(), b, keys, Instant::now() + Duration::from_secs(300)));
    Ok(Json(json!({ "token": token })))
}

async fn zip_download(State(app): State<Arc<App>>, a: Auth, headers: HeaderMap, Path(token): Path<String>) -> R<Response> {
    let session = cookie(&headers, COOKIE).unwrap_or_default();
    let (bucket, keys) = {
        let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let s = sessions.get_mut(&session).ok_or_else(forbidden)?;
        let pos = s.zips.iter().position(|z| z.0 == token && z.3 > Instant::now()).ok_or_else(|| bad("Link de download expirado."))?;
        let z = s.zips.remove(pos);
        (z.1, z.2)
    };
    a.read(&bucket)?;
    let common = keys
        .iter()
        .map(|k| k.rfind('/').map(|i| &k[..=i]).unwrap_or(""))
        .reduce(|x, y| if y.starts_with(x) { x } else if x.starts_with(y) { y } else { "" })
        .unwrap_or("")
        .to_string();
    let mut entries = Vec::new();
    for k in keys {
        if let Some(v) = app.store.get_version(&bucket, &k, None)?.filter(|v| !v.delete_marker && !k.ends_with('/')) {
            entries.push((k[common.len()..].to_string(), bucket.clone(), v));
        }
    }
    let rx = zip::stream(app.clone(), entries);
    let mut r = Response::new(Body::from_stream(ReceiverStream::new(rx)));
    let name = format!("{bucket}-{}.zip", Utc::now().format("%Y%m%d-%H%M%S"));
    set_header(r.headers_mut(), "content-type", "application/zip");
    set_header(r.headers_mut(), "content-disposition", &format!("attachment; filename=\"{name}\""));
    Ok(r)
}

/// Types that may be shown inline in the console's preview.
fn previewable(ct: &str) -> Option<&'static str> {
    let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    Some(match ct.as_str() {
        "image/png" => "image/png",
        "image/jpeg" | "image/jpg" => "image/jpeg",
        "image/gif" => "image/gif",
        "image/webp" => "image/webp",
        "image/avif" => "image/avif",
        "image/svg+xml" => "image/svg+xml",
        "application/pdf" => "application/pdf",
        "video/mp4" => "video/mp4",
        "video/webm" => "video/webm",
        "audio/mpeg" => "audio/mpeg",
        "audio/ogg" => "audio/ogg",
        "audio/wav" | "audio/x-wav" => "audio/wav",
        t if t.starts_with("text/") || t == "application/json" || t == "application/xml" => "text/plain; charset=utf-8",
        _ => return None,
    })
}

async fn download(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Query(q): Query<KeyQ>) -> R<Response> {
    a.read(&b)?;
    app.store.bucket(&b)?;
    let vid = q.version_id.as_deref().filter(|v| !v.is_empty());
    let v = app
        .store
        .get_version(&b, &q.key, vid)?
        .filter(|v| !v.delete_marker)
        .ok_or_else(|| ApiError::from(S3Error::no_such_key(&q.key)))?;
    let inline = q.inline.as_deref() == Some("1");
    let preview_type = if inline { previewable(&v.content_type) } else { None };
    if inline && preview_type.is_none() {
        return Err(bad("Este tipo de arquivo não tem pré-visualização."));
    }
    let body = if v.size > 0 { Body::from_stream(blob::open_full(&app, &b, &v).await?) } else { Body::empty() };
    let mut r = Response::new(body);
    let h = r.headers_mut();
    let name = q.key.trim_end_matches('/').rsplit('/').next().unwrap_or("download");
    set_header(h, "content-length", &v.size.to_string());
    match preview_type {
        Some(t) => {
            set_header(h, "content-type", t);
            set_header(h, "content-disposition", &format!("inline; filename*=UTF-8''{}", uri_encode(name, true)));
            // Previewed content must never run scripts with the console's origin.
            set_header(h, "content-security-policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'");
        }
        None => {
            set_header(h, "content-type", if v.content_type.is_empty() { ops::DEFAULT_CONTENT_TYPE } else { &v.content_type });
            set_header(h, "content-disposition", &format!("attachment; filename*=UTF-8''{}", uri_encode(name, true)));
        }
    }
    Ok(r)
}

#[derive(Deserialize)]
struct ShareReq {
    key: String,
    expires: u64,
}

async fn share(State(app): State<Arc<App>>, a: Auth, Path(b): Path<String>, Json(req): Json<ShareReq>) -> R<Json<Value>> {
    a.read(&b)?;
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

fn key_json(k: &AccessKey) -> Value {
    json!({ "accessKey": k.access_key, "readOnly": k.read_only, "description": k.description, "created": k.created, "grants": k.grants })
}

async fn keys_list(State(app): State<Arc<App>>, a: Auth) -> R<Json<Value>> {
    a.require_root()?;
    let mut keys = app.store.list_keys()?;
    keys.sort_by_key(|k| k.created);
    Ok(Json(Value::Array(keys.iter().map(key_json).collect())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyReq {
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    description: String,
    #[serde(default)]
    grants: Vec<Grant>,
}

fn clean_grants(g: Vec<Grant>) -> R<Vec<Grant>> {
    let mut out = Vec::new();
    for x in g {
        let b = x.bucket.trim().to_string();
        if b.is_empty() {
            continue;
        }
        if !b.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '*')) {
            return Err(bad(format!("Nome de bucket inválido na permissão: {b}")));
        }
        out.push(Grant { bucket: b, write: x.write });
    }
    Ok(out)
}

async fn keys_create(State(app): State<Arc<App>>, a: Auth, Json(req): Json<KeyReq>) -> R<Json<Value>> {
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
        grants: clean_grants(req.grants)?,
    };
    app.store.put_key(&key)?;
    let mut out = key_json(&key);
    out["secretKey"] = json!(key.secret_key);
    Ok(Json(out))
}

fn refresh_sessions(app: &App, ak: &str, f: impl Fn(&mut Session)) {
    for s in app.sessions.lock().unwrap_or_else(|e| e.into_inner()).values_mut() {
        if s.access_key == ak {
            f(s);
        }
    }
}

async fn keys_update(State(app): State<Arc<App>>, a: Auth, Path(ak): Path<String>, Json(req): Json<KeyReq>) -> R<Json<Value>> {
    a.require_root()?;
    let mut k = app.store.get_key(&ak)?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Chave não encontrada.".into()))?;
    k.read_only = req.read_only;
    k.description = req.description.chars().take(200).collect();
    k.grants = clean_grants(req.grants)?;
    app.store.put_key(&k)?;
    let (ro, grants) = (k.read_only, k.grants.clone());
    refresh_sessions(&app, &ak, |s| {
        s.read_only = ro;
        s.grants = grants.clone();
    });
    Ok(Json(key_json(&k)))
}

async fn keys_delete(State(app): State<Arc<App>>, a: Auth, Path(ak): Path<String>) -> R<Json<Value>> {
    a.require_root()?;
    if !app.store.delete_key(&ak)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "Chave não encontrada.".into()));
    }
    app.sessions.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, s| s.access_key != ak);
    Ok(Json(json!({ "ok": true })))
}

/// Tiny adapter: mpsc receiver as a Stream (avoids an extra dependency).
mod tokio_stream_shim {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::sync::mpsc::Receiver;

    pub struct ReceiverStream<T>(Receiver<T>);

    impl<T> ReceiverStream<T> {
        pub fn new(r: Receiver<T>) -> Self {
            ReceiverStream(r)
        }
    }

    impl<T> futures::Stream for ReceiverStream<T> {
        type Item = T;
        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
            self.0.poll_recv(cx)
        }
    }
}
