use std::net::SocketAddr;

use vault_server::config::Config;
use vault_server::mailer::Mailer;
use vault_server::state::AppState;
use vault_server::{build_app, db};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vault_server=info,tower_http=info".into()),
        )
        .init();

    let cfg = Config::from_env().map_err(|e| format!("configuration error: {e}"))?;
    let pool = db::connect(&cfg.db_path).await?;
    let mailer = Mailer::from_config(&cfg.mail).map_err(|e| format!("mailer error: {e}"))?;

    let listen = cfg.listen_addr;
    let state = AppState::new(pool, cfg, mailer);
    let app = build_app(state);

    tracing::info!(%listen, "Basementen Vault server listening");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    })
    .await?;
    Ok(())
}
