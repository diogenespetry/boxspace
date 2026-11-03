//! Command-line and environment configuration.

use std::path::PathBuf;

use crate::disk::Mode;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dirs: Vec<PathBuf>,
    pub redundancy: Option<Mode>,
    pub parity: Option<usize>,
    pub address: String,
    pub console_address: String,
    pub root_user: String,
    pub root_password: String,
    pub region: String,
    /// Base domain for virtual-host style requests (bucket.domain).
    pub domain: Option<String>,
    /// Public URL of the S3 API, used for presigned links from the console.
    pub server_url: String,
    pub lifecycle_interval_secs: u64,
    /// Length of a lifecycle "day" in seconds (86400 in production; lower for tests).
    pub day_seconds: u64,
    pub heal_interval_secs: u64,
    pub metrics_token: Option<String>,
    pub metrics_public: bool,
    pub audit: bool,
    pub audit_retention_days: u64,
    /// Use X-Forwarded-For for client addresses (behind a reverse proxy).
    pub trust_proxy: bool,
}

pub enum Command {
    Server(Box<Config>),
    Healthcheck(String),
}

const HELP: &str = "BoxSpace — servidor de armazenamento de objetos compatível com S3

USO:
    boxspace server [OPÇÕES] <DIRETÓRIO>...
    boxspace healthcheck [URL]

Com um diretório, os dados ficam em um disco. Com vários, cada um deve ser
um disco diferente e os dados ficam protegidos contra a perda de discos.

OPÇÕES:
    --address <ENDEREÇO>           Endereço da API S3 (padrão :9000)
    --console-address <ENDEREÇO>   Endereço do console web (padrão :9001)
    --redundancy <MODO>            mirror (padrão com 2+ discos) ou erasure (3+ discos)
    --parity <N>                   Discos de paridade no modo erasure (padrão: metade)
    -h, --help                     Mostra esta ajuda
    -V, --version                  Mostra a versão

VARIÁVEIS DE AMBIENTE:
    BOXSPACE_ROOT_USER             Usuário root (access key)          [padrão boxspaceadmin]
    BOXSPACE_ROOT_PASSWORD         Senha root (secret key, mín. 8)    [padrão boxspaceadmin]
    BOXSPACE_REGION                Região reportada aos clientes      [padrão us-east-1]
    BOXSPACE_DOMAIN                Domínio para requisições virtual-host (bucket.dominio)
    BOXSPACE_SERVER_URL            URL pública da API (links compartilhados do console)
    BOXSPACE_KMS_SECRET_KEY        Chave mestra base64 (32 bytes) para criptografia
    BOXSPACE_LIFECYCLE_INTERVAL    Intervalo do lifecycle em segundos [padrão 3600]
    BOXSPACE_HEAL_INTERVAL         Intervalo da verificação de integridade [padrão 86400]
    BOXSPACE_METRICS_TOKEN         Token Bearer para /_boxspace/metrics
    BOXSPACE_METRICS_PUBLIC        1 para expor as métricas sem token
    BOXSPACE_AUDIT                 0 para desligar o log de auditoria [padrão 1]
    BOXSPACE_AUDIT_RETENTION_DAYS  Dias de log de auditoria guardados [padrão 30]
    BOXSPACE_TRUST_PROXY           1 para usar X-Forwarded-For como IP do cliente
";

fn normalize_addr(a: &str) -> String {
    if let Some(port) = a.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        a.to_string()
    }
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string())
}

fn env_flag(k: &str, default: bool) -> bool {
    match std::env::var(k).ok().as_deref().map(str::trim) {
        Some("1" | "true" | "on" | "yes" | "sim") => true,
        Some("0" | "false" | "off" | "no" | "nao" | "não") => false,
        _ => default,
    }
}

impl Config {
    pub fn from_args() -> Result<Command, String> {
        let mut args = std::env::args().skip(1).peekable();
        let mut address = ":9000".to_string();
        let mut console_address = ":9001".to_string();
        let mut redundancy = None;
        let mut parity = None;
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut saw_server = false;

        if args.peek().map(String::as_str) == Some("healthcheck") {
            args.next();
            let port = std::env::var("BOXSPACE_HEALTH_URL").ok();
            let url = args.next().or(port).unwrap_or_else(|| "http://127.0.0.1:9000/_boxspace/health".into());
            return Ok(Command::Healthcheck(url));
        }
        while let Some(a) = args.next() {
            match a.as_str() {
                "-h" | "--help" | "help" => {
                    print!("{HELP}");
                    std::process::exit(0);
                }
                "-V" | "--version" | "version" => {
                    println!("boxspace {VERSION}");
                    std::process::exit(0);
                }
                "server" if !saw_server => saw_server = true,
                "--address" => address = args.next().ok_or("--address requer um valor")?,
                "--console-address" => console_address = args.next().ok_or("--console-address requer um valor")?,
                "--redundancy" => {
                    let v = args.next().ok_or("--redundancy requer um valor")?;
                    redundancy = Some(Mode::parse(&v).ok_or(format!("modo desconhecido: {v} (use mirror ou erasure)"))?);
                }
                "--parity" => {
                    let v = args.next().ok_or("--parity requer um valor")?;
                    parity = Some(v.parse::<usize>().map_err(|_| format!("paridade inválida: {v}"))?);
                }
                s if s.starts_with("--address=") => address = s["--address=".len()..].to_string(),
                s if s.starts_with("--console-address=") => console_address = s["--console-address=".len()..].to_string(),
                s if s.starts_with('-') => return Err(format!("opção desconhecida: {s}\n\n{HELP}")),
                s => dirs.push(PathBuf::from(s)),
            }
        }
        if !saw_server {
            return Err(HELP.to_string());
        }
        if dirs.is_empty() {
            return Err(format!("informe ao menos um diretório de dados\n\n{HELP}"));
        }
        let mut uniq = dirs.clone();
        uniq.sort();
        uniq.dedup();
        if uniq.len() != dirs.len() {
            return Err("o mesmo diretório foi informado mais de uma vez".into());
        }

        let root_user = env_or("BOXSPACE_ROOT_USER", "boxspaceadmin");
        let root_password = env_or("BOXSPACE_ROOT_PASSWORD", "boxspaceadmin");
        if root_user.len() < 3 {
            return Err("BOXSPACE_ROOT_USER deve ter pelo menos 3 caracteres".into());
        }
        if root_password.len() < 8 {
            return Err("BOXSPACE_ROOT_PASSWORD deve ter pelo menos 8 caracteres".into());
        }

        let address = normalize_addr(&address);
        let console_address = normalize_addr(&console_address);
        let port = address.rsplit(':').next().unwrap_or("9000");
        let server_url = env_or("BOXSPACE_SERVER_URL", &format!("http://localhost:{port}")).trim_end_matches('/').to_string();

        Ok(Command::Server(Box::new(Config {
            data_dirs: dirs,
            redundancy,
            parity,
            address,
            console_address,
            root_user,
            root_password,
            region: env_or("BOXSPACE_REGION", "us-east-1"),
            domain: std::env::var("BOXSPACE_DOMAIN").ok().filter(|d| !d.is_empty()),
            server_url,
            lifecycle_interval_secs: env_or("BOXSPACE_LIFECYCLE_INTERVAL", "3600").parse().unwrap_or(3600).max(1),
            day_seconds: env_or("BOXSPACE_LIFECYCLE_DAY_SECONDS", "86400").parse().unwrap_or(86400).max(1),
            heal_interval_secs: env_or("BOXSPACE_HEAL_INTERVAL", "86400").parse().unwrap_or(86400).max(10),
            metrics_token: std::env::var("BOXSPACE_METRICS_TOKEN").ok().filter(|t| !t.is_empty()),
            metrics_public: env_flag("BOXSPACE_METRICS_PUBLIC", false),
            audit: env_flag("BOXSPACE_AUDIT", true),
            audit_retention_days: env_or("BOXSPACE_AUDIT_RETENTION_DAYS", "30").parse().unwrap_or(30).max(1),
            trust_proxy: env_flag("BOXSPACE_TRUST_PROXY", false),
        })))
    }

    pub fn using_default_credentials(&self) -> bool {
        self.root_user == "boxspaceadmin" && self.root_password == "boxspaceadmin"
    }
}
