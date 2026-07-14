use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};
use std::str::FromStr;

#[derive(Debug, FromRow)]
pub struct Account {
    pub id: i64,
    pub email: String,
    pub email_verified_at: Option<i64>,
    pub server_auth_hash: String,
    pub kdf_params: String,
    /// Random 128-bit per-account KDF salt (not secret; returned by prelogin).
    pub kdf_salt: Vec<u8>,
    pub master_wrapped_vault_key: String,
    pub recovery_wrapped_vault_key: String,
    pub failed_attempts: i64,
    pub lockout_until: Option<i64>,
}

pub async fn connect(db_path: &str) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// In-memory database for tests. A single connection is mandatory: every
/// pooled connection to `sqlite::memory:` would otherwise get its own
/// empty database.
pub async fn connect_in_memory() -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn account_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<Account>, sqlx::Error> {
    sqlx::query_as::<_, Account>(
        "SELECT id, email, email_verified_at, server_auth_hash, kdf_params, kdf_salt,
                master_wrapped_vault_key, recovery_wrapped_vault_key,
                failed_attempts, lockout_until
         FROM accounts WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub async fn account_by_id(pool: &SqlitePool, id: i64) -> Result<Option<Account>, sqlx::Error> {
    sqlx::query_as::<_, Account>(
        "SELECT id, email, email_verified_at, server_auth_hash, kdf_params, kdf_salt,
                master_wrapped_vault_key, recovery_wrapped_vault_key,
                failed_attempts, lockout_until
         FROM accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}
