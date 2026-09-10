//! Liveness and readiness.
//!
//! Split because they answer different questions. Liveness says the process is
//! up; readiness says it can serve, which means the database is reachable. A
//! liveness probe that touched the database would restart the pod every time
//! Postgres was briefly unavailable -- during a node drain, for instance --
//! which is exactly when restarting helps least.

use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::AppState;

pub async fn live() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "database unavailable" })),
            )
        }
    }
}
