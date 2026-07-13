use std::net::SocketAddr;

/// Server configuration, loaded entirely from environment variables so the
/// whole deployment is a binary + an .env file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind, e.g. `0.0.0.0:8080`. Env: `BV_LISTEN_ADDR`.
    pub listen_addr: SocketAddr,
    /// SQLite database path, e.g. `/data/vault.db`. Env: `BV_DB_PATH`.
    pub db_path: String,
    /// Public base URL used in e-mail links, e.g. `https://vault.example.com`.
    /// Env: `BV_BASE_URL`.
    pub base_url: String,
    /// Whether new registrations are accepted. Env: `BV_REGISTRATION_OPEN`
    /// (default true; set to false once your household has its accounts).
    pub registration_open: bool,
    /// Trust `X-Forwarded-For` from a reverse proxy. Only enable when the
    /// server is reachable exclusively through your proxy. Env: `BV_TRUST_PROXY`.
    pub trust_proxy: bool,
    pub mail: MailConfig,
}

#[derive(Debug, Clone)]
pub enum MailConfig {
    /// Log e-mails to stdout instead of sending. For development and for
    /// VPN-only deployments where you create accounts by reading the log.
    Console,
    /// Send through an SMTP relay (submission port, STARTTLS or implicit TLS).
    Smtp {
        host: String,
        port: u16,
        username: String,
        password: String,
        from: String,
        implicit_tls: bool,
    },
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let listen_addr = env("BV_LISTEN_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .map_err(|e| format!("BV_LISTEN_ADDR: {e}"))?;
        let db_path = env("BV_DB_PATH").unwrap_or_else(|| "vault.db".into());
        let base_url = env("BV_BASE_URL")
            .unwrap_or_else(|| "http://127.0.0.1:8080".into())
            .trim_end_matches('/')
            .to_string();
        let registration_open = env("BV_REGISTRATION_OPEN")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);
        let trust_proxy = env("BV_TRUST_PROXY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let mail = match env("BV_MAILER").as_deref() {
            None | Some("console") => MailConfig::Console,
            Some("smtp") => MailConfig::Smtp {
                host: env("BV_SMTP_HOST").ok_or("BV_SMTP_HOST is required for BV_MAILER=smtp")?,
                port: env("BV_SMTP_PORT")
                    .unwrap_or_else(|| "587".into())
                    .parse()
                    .map_err(|e| format!("BV_SMTP_PORT: {e}"))?,
                username: env("BV_SMTP_USERNAME").unwrap_or_default(),
                password: env("BV_SMTP_PASSWORD").unwrap_or_default(),
                from: env("BV_SMTP_FROM").ok_or("BV_SMTP_FROM is required for BV_MAILER=smtp")?,
                implicit_tls: env("BV_SMTP_IMPLICIT_TLS")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
            },
            Some(other) => return Err(format!("BV_MAILER: unknown mailer '{other}'")),
        };

        Ok(Self {
            listen_addr,
            db_path,
            base_url,
            registration_open,
            trust_proxy,
            mail,
        })
    }
}
