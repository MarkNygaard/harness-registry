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
