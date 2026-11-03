//! BoxSpace — S3-compatible object storage server.

mod api;
mod auth;
mod blob;
mod body;
mod config;
mod console;
mod cors;
mod crypto;
mod error;
mod events;
mod lifecycle;
mod listing;
mod ops;
mod policy;
mod storage;
mod util;

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use axum::{extract::DefaultBodyLimit, Router};
use tokio::net::TcpListener;

pub struct App {
    pub cfg: config::Config,
    pub store: storage::Store,
    pub kms: crypto::Kms,
    pub http: reqwest::Client,
    pub sessions: Mutex<HashMap<String, console::Session>>,
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("boxspace: {msg}");
    std::process::exit(1);
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

    let cfg = config::Config::from_args().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    std::fs::create_dir_all(&cfg.data_dir).unwrap_or_else(|e| fail(format!("{}: {e}", cfg.data_dir.display())));
    let store = storage::Store::open(&cfg.data_dir).unwrap_or_else(|e| fail(e));
    let kms = crypto::Kms::load(store.meta_dir()).unwrap_or_else(|e| fail(e));
    let http = reqwest::Client::builder().user_agent(format!("BoxSpace/{}", config::VERSION)).build().unwrap_or_else(|e| fail(e));

    if cfg.using_default_credentials() {
        tracing::warn!("usando as credenciais padrão (boxspaceadmin); defina BOXSPACE_ROOT_USER e BOXSPACE_ROOT_PASSWORD");
    }

    let app = Arc::new(App { cfg, store, kms, http, sessions: Mutex::new(HashMap::new()) });
    tokio::spawn(lifecycle::run_loop(app.clone()));

    let api = Router::new().fallback(api::handle).layer(DefaultBodyLimit::disable()).with_state(app.clone());
    let console = console::router(app.clone());

    let api_l = TcpListener::bind(&app.cfg.address).await.unwrap_or_else(|e| fail(format!("{}: {e}", app.cfg.address)));
    let console_l = TcpListener::bind(&app.cfg.console_address)
        .await
        .unwrap_or_else(|e| fail(format!("{}: {e}", app.cfg.console_address)));

    tracing::info!("BoxSpace {} — dados em {}", config::VERSION, app.cfg.data_dir.display());
    tracing::info!("API S3:  http://{}  (URL pública {})", api_l.local_addr().map(|a| a.to_string()).unwrap_or_default(), app.cfg.server_url);
    tracing::info!("Console: http://{}", console_l.local_addr().map(|a| a.to_string()).unwrap_or_default());

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("encerrando");
    };
    tokio::select! {
        r = axum::serve(api_l, api) => if let Err(e) = r { fail(e) },
        r = axum::serve(console_l, console) => if let Err(e) = r { fail(e) },
        _ = shutdown => {}
    }
}
