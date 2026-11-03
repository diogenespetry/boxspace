//! Command-line and environment configuration.

use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
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
}

const HELP: &str = "BoxSpace — servidor de armazenamento de objetos compatível com S3

USO:
    boxspace server [OPÇÕES] <DIRETÓRIO>

OPÇÕES:
    --address <ENDEREÇO>           Endereço da API S3 (padrão :9000)
    --console-address <ENDEREÇO>   Endereço do console web (padrão :9001)
    -h, --help                     Mostra esta ajuda
    -V, --version                  Mostra a versão

VARIÁVEIS DE AMBIENTE:
    BOXSPACE_ROOT_USER             Usuário root (access key)          [padrão boxspaceadmin]
    BOXSPACE_ROOT_PASSWORD         Senha root (secret key, mín. 8)    [padrão boxspaceadmin]
    BOXSPACE_REGION                Região reportada aos clientes      [padrão us-east-1]
    BOXSPACE_DOMAIN                Domínio para requisições virtual-host (bucket.dominio)
    BOXSPACE_SERVER_URL            URL pública da API (links compartilhados do console)
    BOXSPACE_KMS_SECRET_KEY        Chave mestra base64 (32 bytes) para criptografia SSE
    BOXSPACE_LIFECYCLE_INTERVAL    Intervalo do lifecycle em segundos [padrão 3600]
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

impl Config {
    pub fn from_args() -> Result<Config, String> {
        let mut args = std::env::args().skip(1);
        let mut address = ":9000".to_string();
        let mut console_address = ":9001".to_string();
        let mut dir: Option<String> = None;
        let mut saw_server = false;

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
                s if s.starts_with("--address=") => address = s["--address=".len()..].to_string(),
                s if s.starts_with("--console-address=") => console_address = s["--console-address=".len()..].to_string(),
                s if s.starts_with('-') => return Err(format!("opção desconhecida: {s}\n\n{HELP}")),
                s => {
                    if dir.is_some() {
                        return Err("apenas um diretório de dados é suportado".into());
                    }
                    dir = Some(s.to_string());
                }
            }
        }
        if !saw_server {
            return Err(HELP.to_string());
        }
        let data_dir = PathBuf::from(dir.ok_or_else(|| format!("informe o diretório de dados\n\n{HELP}"))?);

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
        let server_url = env_or("BOXSPACE_SERVER_URL", &format!("http://localhost:{port}"))
            .trim_end_matches('/')
            .to_string();

        Ok(Config {
            data_dir,
            address,
            console_address,
            root_user,
            root_password,
            region: env_or("BOXSPACE_REGION", "us-east-1"),
            domain: std::env::var("BOXSPACE_DOMAIN").ok().filter(|d| !d.is_empty()),
            server_url,
            lifecycle_interval_secs: env_or("BOXSPACE_LIFECYCLE_INTERVAL", "3600").parse().unwrap_or(3600).max(1),
            day_seconds: env_or("BOXSPACE_LIFECYCLE_DAY_SECONDS", "86400").parse().unwrap_or(86400).max(1),
        })
    }

    pub fn using_default_credentials(&self) -> bool {
        self.root_user == "boxspaceadmin" && self.root_password == "boxspaceadmin"
    }
}
