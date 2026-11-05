//! BoxSpace — S3-compatible object storage server.

mod api;
mod audit;
mod auth;
mod blob;
mod body;
mod config;
mod console;
mod cors;
mod crypto;
mod disk;
mod error;
mod events;
mod heal;
mod ipfilter;
mod lifecycle;
mod listing;
mod metrics;
mod ops;
mod phys;
mod policy;
mod replication;
mod sidecar;
mod storage;
mod util;
mod view;
mod zip;

use std::{collections::HashMap, net::SocketAddr, sync::Arc, sync::Mutex, time::Duration};

use axum::{extract::DefaultBodyLimit, Router};
use tokio::{net::TcpListener, sync::Notify};

pub struct App {
    pub cfg: config::Config,
    pub disks: Arc<disk::Disks>,
    pub store: storage::Store,
    pub kms: Arc<crypto::Kms>,
    pub http: reqwest::Client,
    pub sessions: Mutex<HashMap<String, console::Session>>,
    pub healer: heal::Healer,
    pub views: view::Views,
    pub metrics: metrics::Metrics,
    pub audit: audit::Audit,
    pub repl_wake: Notify,
    pub ipfilter: ipfilter::IpFilter,
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("boxspace: {msg}");
    std::process::exit(1);
}

async fn healthcheck(url: &str) -> ! {
    let ok = match reqwest::Client::new().get(url).timeout(Duration::from_secs(5)).send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    };
    std::process::exit(if ok { 0 } else { 1 });
}

#[tokio::main]
async fn main() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let level = match filter.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt().with_max_level(level).with_target(false).init();

    let cfg = match config::Config::from_args() {
        Ok(config::Command::Server(c)) => *c,
        Ok(config::Command::Healthcheck(url)) => healthcheck(&url).await,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    };
    let disks = disk::Disks::open(&cfg.data_dirs, cfg.redundancy, cfg.parity).unwrap_or_else(|e| fail(e));
    let store = storage::Store::open(disks.meta_dir()).unwrap_or_else(|e| fail(e));
    let sys_dirs: Vec<&std::path::Path> = disks.list.iter().map(|d| d.sys.as_path()).collect();
    let kms = crypto::Kms::load(&sys_dirs).unwrap_or_else(|e| fail(e));
    let http = reqwest::Client::builder().user_agent(format!("BoxSpace/{}", config::VERSION)).build().unwrap_or_else(|e| fail(e));
    let audit = audit::Audit::start(disks.meta_dir().join("audit"), cfg.audit, cfg.audit_retention_days);

    if cfg.using_default_credentials() {
        tracing::warn!("usando as credenciais padrão (boxspaceadmin); defina BOXSPACE_ROOT_USER e BOXSPACE_ROOT_PASSWORD");
    }

    let replaced = !disks.replaced.is_empty();
    let ip_cfg: ipfilter::IpConfig = store.get_setting("ipfilter").ok().flatten().unwrap_or_default();
    let ip_off = matches!(std::env::var("BOXSPACE_IP_FILTER").ok().as_deref(), Some("off" | "0" | "false"));
    let app = Arc::new(App {
        cfg,
        disks: Arc::new(disks),
        store,
        kms: Arc::new(kms),
        http,
        sessions: Mutex::new(HashMap::new()),
        healer: heal::Healer::default(),
        views: view::Views::default(),
        metrics: metrics::Metrics::default(),
        audit,
        repl_wake: Notify::new(),
        ipfilter: ipfilter::IpFilter::new(ip_cfg, ip_off),
    });

    let mut rebuilt = false;
    if app.store.fresh && sidecar::disks_have_data(&app) {
        tracing::warn!("índice de metadados ausente; reconstruindo a partir dos discos");
        match sidecar::rebuild(&app) {
            Ok((b, v)) => {
                tracing::info!("índice reconstruído: {b} bucket(s), {v} versão(ões)");
                rebuilt = true;
                if let Ok(Some(cfg)) = app.store.get_setting::<ipfilter::IpConfig>("ipfilter") {
                    let _ = app.ipfilter.set(cfg);
                }
            }
            Err(e) => fail(format!("falha ao reconstruir o índice: {}", e.message)),
        }
    }
    if let Err(e) = sidecar::write_sys(&app).await {
        tracing::warn!("não foi possível gravar a configuração nos discos: {}", e.message);
    }

    tokio::spawn(lifecycle::run_loop(app.clone()));
    tokio::spawn(sidecar::sys_loop(app.clone()));
    tokio::spawn(heal::monitor(app.clone()));
    tokio::spawn(heal::run_loop(app.clone(), replaced || rebuilt));
    tokio::spawn(replication::worker(app.clone()));

    let api = Router::new().fallback(api::handle).layer(DefaultBodyLimit::disable()).with_state(app.clone());
    let console = console::router(app.clone());

    let api_l = TcpListener::bind(&app.cfg.address).await.unwrap_or_else(|e| fail(format!("{}: {e}", app.cfg.address)));
    let console_l = TcpListener::bind(&app.cfg.console_address)
        .await
        .unwrap_or_else(|e| fail(format!("{}: {e}", app.cfg.console_address)));

    let dirs: Vec<String> = app.disks.list.iter().map(|d| d.root.display().to_string()).collect();
    tracing::info!("BoxSpace {} — modo {} com {} disco(s): {}", config::VERSION, app.disks.mode.label(), dirs.len(), dirs.join(", "));
    if app.disks.mode == disk::Mode::Erasure {
        tracing::info!("erasure coding: {} dados + {} paridade (tolera a perda de {} disco(s))", app.disks.data_shards(), app.disks.parity, app.disks.parity);
    }
    tracing::info!("API S3:  http://{}  (URL pública {})", api_l.local_addr().map(|a| a.to_string()).unwrap_or_default(), app.cfg.server_url);
    tracing::info!("Console: http://{}", console_l.local_addr().map(|a| a.to_string()).unwrap_or_default());

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("encerrando");
    };
    tokio::select! {
        r = axum::serve(api_l, api.into_make_service_with_connect_info::<SocketAddr>()) => if let Err(e) = r { fail(e) },
        r = axum::serve(console_l, console.into_make_service_with_connect_info::<SocketAddr>()) => if let Err(e) = r { fail(e) },
        _ = shutdown => {}
    }
}
