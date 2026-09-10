//! Install records.
//!
//! One row per (workflow, installation), never a counter. The schema is
//! explicit about this and it is worth restating: a stored count cannot be
//! corrected, cannot be narrowed to installs still alive, and is trivially
//! inflated by anyone in a loop. Rows can be counted, aged out, and
//! deduplicated after the fact.
//!
//! `last_seen_at` is refreshed on every call so a count can later be limited
//! to harnesses that still exist.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use crate::{
    error::{Error, Result},
    models::RecordInstall,
    AppState,
};

pub async fn record(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<RecordInstall>,
) -> Result<Json<Value>> {
    let workflow_id: Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM registry_workflows WHERE slug = $1")
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await?;
    let (workflow_id,) = workflow_id.ok_or(Error::NotFound("workflow"))?;

    // The version must exist. Otherwise a typo silently records an install of
    // something that was never published, and the number is quietly wrong.
    let known: Option<(i32,)> = sqlx::query_as(
        "SELECT version FROM registry_versions WHERE workflow_id = $1 AND version = $2",
    )
    .bind(workflow_id)
    .bind(body.version)
    .fetch_optional(&state.pool)
    .await?;
    if known.is_none() {
        return Err(Error::NotFound("version"));
    }

    sqlx::query(
        "INSERT INTO registry_installs (workflow_id, installation_id, version)
         VALUES ($1, $2, $3)
         ON CONFLICT (workflow_id, installation_id)
         DO UPDATE SET version = EXCLUDED.version, last_seen_at = now()",
    )
    .bind(workflow_id)
    .bind(body.installation_id)
    .bind(body.version)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "status": "recorded" })))
}

/// Forget an install, so the count comes back down.
///
/// Without this the count only ever rises, which is the one-directional drift
/// the record-based design exists to avoid — a harness that removes a workflow
/// would have no way to say so, and the number would slowly become a figure
/// nobody could correct.
///
/// `404` for a row that is not there, so a repeated uninstall is honest about
/// having found nothing rather than reporting a deletion it did not make. The
/// harness treats both the same: it is best-effort either way, and removing a
/// workflow locally must never depend on this call succeeding.
///
/// Unauthenticated, like `record`, and keyed the same way. That makes
/// `installation_id` a bearer secret in practice — anyone who learns one can
/// drop that harness's rows. The stakes are a count rather than anybody's data,
/// and the alternative is issuing credentials to every install for the privilege
/// of being counted; it does argue for keeping the id out of logs, and for the
/// rate limit that already guards `record`.
pub async fn forget(
    State(state): State<AppState>,
    Path((slug, installation_id)): Path<(String, uuid::Uuid)>,
) -> Result<StatusCode> {
    let workflow_id: Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM registry_workflows WHERE slug = $1")
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await?;
    let (workflow_id,) = workflow_id.ok_or(Error::NotFound("workflow"))?;

    let done = sqlx::query(
        "DELETE FROM registry_installs WHERE workflow_id = $1 AND installation_id = $2",
    )
    .bind(workflow_id)
    .bind(installation_id)
    .execute(&state.pool)
    .await?;

    if done.rows_affected() == 0 {
        return Err(Error::NotFound("install"));
    }
    Ok(StatusCode::NO_CONTENT)
}
