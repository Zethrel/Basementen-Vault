//! Encrypted vault item storage and delta sync.
//!
//! The server treats item content as an opaque `EncryptedItem` envelope —
//! it validates shape, never plaintext. Concurrency control is optimistic:
//! every write carries the revision it was built on (revision − 1 must match
//! the stored row), and a mismatch returns `409 Conflict` with the current
//! server state so the client can merge.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use vault_core::EncryptedItem;

use crate::error::ApiError;
use crate::security;
use crate::state::{AppState, AuthSession};

/// Tombstones older than this are purged; clients further behind must full-resync.
const TOMBSTONE_TTL_SECS: i64 = 30 * 24 * 3600;
/// Guardrail against runaway payloads; real items are a few KiB.
const MAX_CONTENT_BYTES: usize = 512 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteItem {
    pub item_id: String,
    pub revision: i64,
    pub seq: i64,
    pub deleted: bool,
    /// Present unless this is a tombstone.
    pub content: Option<Value>,
}

/// Allocate the next per-account sequence number (atomic single statement).
async fn next_seq<'e, E>(executor: E, account_id: i64) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query_scalar(
        "UPDATE accounts SET sync_seq = sync_seq + 1 WHERE id = ? RETURNING sync_seq",
    )
    .bind(account_id)
    .fetch_one(executor)
    .await
}

fn row_to_remote(row: &sqlx::sqlite::SqliteRow) -> RemoteItem {
    let content: Option<String> = row.get("content");
    RemoteItem {
        item_id: row.get("item_id"),
        revision: row.get("revision"),
        seq: row.get("seq"),
        deleted: row.get::<i64, _>("deleted") != 0,
        content: content.and_then(|c| serde_json::from_str(&c).ok()),
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// Highest seq the client has already seen; 0 (or absent) = everything.
    #[serde(default)]
    pub since: i64,
}

/// GET /api/v1/vault/items?since=N — delta pull.
pub async fn list_items(
    State(state): State<AppState>,
    session: AuthSession,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    let mut tx = state.db.begin().await?;

    // Lazy tombstone purge: drop expired tombstones and advance the horizon.
    let purged_max: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(seq) FROM vault_items
         WHERE account_id = ? AND deleted = 1 AND updated_at < ?",
    )
    .bind(session.account_id)
    .bind(now - TOMBSTONE_TTL_SECS)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(purged_max) = purged_max {
        sqlx::query(
            "DELETE FROM vault_items WHERE account_id = ? AND deleted = 1 AND updated_at < ?",
        )
        .bind(session.account_id)
        .bind(now - TOMBSTONE_TTL_SECS)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE accounts SET purged_before_seq = MAX(purged_before_seq, ?) WHERE id = ?",
        )
        .bind(purged_max)
        .bind(session.account_id)
        .execute(&mut *tx)
        .await?;
    }

    let (latest_seq, purged_before_seq): (i64, i64) =
        sqlx::query_as("SELECT sync_seq, purged_before_seq FROM accounts WHERE id = ?")
            .bind(session.account_id)
            .fetch_one(&mut *tx)
            .await?;

    // A client behind the purge horizon may have missed tombstones that no
    // longer exist; hand it the full current state instead of a delta.
    let full_resync = q.since > 0 && q.since < purged_before_seq;
    let since = if full_resync { 0 } else { q.since };

    let rows = sqlx::query(
        "SELECT item_id, revision, seq, deleted, content FROM vault_items
         WHERE account_id = ? AND seq > ? ORDER BY seq",
    )
    .bind(session.account_id)
    .bind(since)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let items: Vec<RemoteItem> = rows
        .iter()
        .map(row_to_remote)
        // On a full resync tombstones are noise: the client rebuilds from scratch.
        .filter(|i| !(full_resync && i.deleted))
        .collect();

    Ok(Json(json!({
        "items": items,
        "latest_seq": latest_seq,
        "full_resync": full_resync,
    })))
}

/// PUT /api/v1/vault/items/{item_id} — create or update one encrypted item.
///
/// The body is the `EncryptedItem` envelope; its embedded `revision` is the
/// revision this write *produces* (base revision + 1). New items start at 1.
pub async fn put_item(
    State(state): State<AppState>,
    session: AuthSession,
    Path(item_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    let envelope: EncryptedItem =
        serde_json::from_value(body.clone()).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if envelope.item_id != item_id {
        return Err(ApiError::BadRequest(
            "item_id mismatch with envelope".into(),
        ));
    }
    if envelope.revision == 0 || envelope.revision > i64::MAX as u64 {
        return Err(ApiError::BadRequest("revision must be >= 1".into()));
    }
    let content = body.to_string();
    if content.len() > MAX_CONTENT_BYTES {
        return Err(ApiError::BadRequest("item too large".into()));
    }
    let new_revision = envelope.revision as i64;
    let now = security::now();

    let mut tx = state.db.begin().await?;
    let current: Option<(i64, i64)> = sqlx::query_as(
        "SELECT revision, deleted FROM vault_items WHERE account_id = ? AND item_id = ?",
    )
    .bind(session.account_id)
    .bind(&item_id)
    .fetch_optional(&mut *tx)
    .await?;

    let current_revision = current.map(|(r, _)| r).unwrap_or(0);
    if new_revision != current_revision + 1 {
        drop(tx);
        return conflict_response(&state, session.account_id, &item_id).await;
    }

    let seq = next_seq(&mut *tx, session.account_id).await?;
    sqlx::query(
        "INSERT INTO vault_items (account_id, item_id, revision, seq, deleted, content, updated_at)
         VALUES (?, ?, ?, ?, 0, ?, ?)
         ON CONFLICT(account_id, item_id) DO UPDATE SET
           revision = excluded.revision, seq = excluded.seq, deleted = 0,
           content = excluded.content, updated_at = excluded.updated_at",
    )
    .bind(session.account_id)
    .bind(&item_id)
    .bind(new_revision)
    .bind(seq)
    .bind(&content)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    state.notifier.notify(session.account_id, seq);
    Ok((
        StatusCode::OK,
        Json(json!({ "item_id": item_id, "revision": new_revision, "seq": seq })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    /// The revision the client believes is current.
    pub base_revision: i64,
}

/// DELETE /api/v1/vault/items/{item_id}?base_revision=N — tombstone an item.
pub async fn delete_item(
    State(state): State<AppState>,
    session: AuthSession,
    Path(item_id): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let now = security::now();
    let mut tx = state.db.begin().await?;

    let current: Option<(i64, i64)> = sqlx::query_as(
        "SELECT revision, deleted FROM vault_items WHERE account_id = ? AND item_id = ?",
    )
    .bind(session.account_id)
    .bind(&item_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((current_revision, deleted)) = current else {
        return Err(ApiError::NotFound);
    };
    if deleted != 0 {
        // Already a tombstone; deleting a deleted item is idempotent success.
        tx.commit().await?;
        return Ok((
            StatusCode::OK,
            Json(json!({ "item_id": item_id, "revision": current_revision, "deleted": true })),
        )
            .into_response());
    }
    if q.base_revision != current_revision {
        drop(tx);
        return conflict_response(&state, session.account_id, &item_id).await;
    }

    let seq = next_seq(&mut *tx, session.account_id).await?;
    let new_revision = current_revision + 1;
    sqlx::query(
        "UPDATE vault_items SET revision = ?, seq = ?, deleted = 1, content = NULL, updated_at = ?
         WHERE account_id = ? AND item_id = ?",
    )
    .bind(new_revision)
    .bind(seq)
    .bind(now)
    .bind(session.account_id)
    .bind(&item_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    state.notifier.notify(session.account_id, seq);
    Ok((
        StatusCode::OK,
        Json(json!({ "item_id": item_id, "revision": new_revision, "deleted": true })),
    )
        .into_response())
}

/// 409 with the current server-side state of the item, so the losing client
/// can merge without another round trip.
async fn conflict_response(
    state: &AppState,
    account_id: i64,
    item_id: &str,
) -> Result<axum::response::Response, ApiError> {
    let row = sqlx::query(
        "SELECT item_id, revision, seq, deleted, content FROM vault_items
         WHERE account_id = ? AND item_id = ?",
    )
    .bind(account_id)
    .bind(item_id)
    .fetch_optional(&state.db)
    .await?;

    Ok((
        StatusCode::CONFLICT,
        Json(json!({
            "error": "conflict",
            "current": row.as_ref().map(row_to_remote),
        })),
    )
        .into_response())
}

/// GET /api/v1/vault/events — SSE stream of change nudges. Each event is the
/// account's new latest seq; clients react by pulling. Carries no vault data.
pub async fn events(
    State(state): State<AppState>,
    session: AuthSession,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let mut rx = state.notifier.subscribe(session.account_id);
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(seq) => yield Ok(Event::default().event("changed").data(seq.to_string())),
                // Lagged: we dropped some nudges; the latest one still means "pull".
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    yield Ok(Event::default().event("changed").data("0"));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}
