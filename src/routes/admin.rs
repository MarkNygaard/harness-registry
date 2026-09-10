//! Registry-operator endpoints.
//!
//! These are the reason this service is a separate, private program rather
//! than part of the open-source harness. Minting publisher tokens, blocking an
//! account and setting the `official` badge are things the *operator* of a
//! registry does; shipping them inside the harness would put endpoints for
//! this registry on every self-hosted instance.
//!
//! Guarded by `Admin`, which returns 404 when `ADMIN_TOKEN` is unset, so a
//! deployment that forgets the secret has no admin surface at all instead of
//! an unauthenticated one.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{generate_token, hash_token, Admin},
    error::{on_unique_violation, Error, Result},
    models::IssuedToken,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct IssueToken {
    /// GitHub's numeric id, never the login. The schema is explicit: a login
    /// can be renamed and the old one claimed by someone else, so trusting it
    /// would let an account be inherited along with its workflows.
    pub github_id: i64,
    pub github_login: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// What this token is for, so one can be revoked without killing the rest.
    pub name: String,
}

pub async fn issue_token(
    State(state): State<AppState>,
    _: Admin,
    Json(body): Json<IssueToken>,
) -> Result<Json<IssuedToken>> {
    if body.name.trim().is_empty() {
        return Err(Error::BadRequest("name is required".into()));
    }

    let mut tx = state.pool.begin().await?;

    // Upsert on github_id: issuing a second token for an existing publisher is
    // the normal case, not an error. The login is refreshed while we are here,
    // since it can have been renamed since the last token.
    let publisher: (Uuid,) = sqlx::query_as(
        "INSERT INTO registry_publishers (github_id, github_login, display_name, avatar_url)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (github_id) DO UPDATE
            SET github_login = EXCLUDED.github_login,
                display_name = COALESCE(EXCLUDED.display_name, registry_publishers.display_name),
                avatar_url = COALESCE(EXCLUDED.avatar_url, registry_publishers.avatar_url)
         RETURNING id",
    )
    .bind(body.github_id)
    .bind(&body.github_login)
    .bind(&body.display_name)
    .bind(&body.avatar_url)
    .fetch_one(&mut *tx)
    .await?;

    let token = generate_token();

    sqlx::query(
        "INSERT INTO registry_publisher_tokens (publisher_id, token_hash, name)
         VALUES ($1, $2, $3)",
    )
    .bind(publisher.0)
    .bind(hash_token(&token))
    .bind(&body.name)
    .execute(&mut *tx)
    .await
    .map_err(|e| on_unique_violation(e, "token collision; retry"))?;

    tx.commit().await?;

    // The login is logged; the token never is.
    tracing::info!(
        github_login = %body.github_login,
        name = %body.name,
        "publisher token issued"
    );

    Ok(Json(IssuedToken {
        publisher_id: publisher.0,
        github_login: body.github_login,
        name: body.name,
        token,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SetFlag {
    pub value: bool,
}

pub async fn set_official(
    State(state): State<AppState>,
    _: Admin,
    Path(slug): Path<String>,
    Json(body): Json<SetFlag>,
) -> Result<Json<Value>> {
    // Never inferred from the publisher. The schema notes why: infer it and
    // the first lookalike account inherits the badge.
    let affected = sqlx::query("UPDATE registry_workflows SET official = $2 WHERE slug = $1")
        .bind(&slug)
        .bind(body.value)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(Error::NotFound("workflow"));
    }

    tracing::warn!(%slug, official = body.value, "official flag changed");
    Ok(Json(json!({ "slug": slug, "official": body.value })))
}

pub async fn set_blocked(
    State(state): State<AppState>,
    _: Admin,
    Path(github_id): Path<i64>,
    Json(body): Json<SetFlag>,
) -> Result<Json<Value>> {
    // Blocking stops further publishing without deleting existing work, so
    // installs that already took a workflow keep resolving.
    let affected = sqlx::query(
        "UPDATE registry_publishers
            SET blocked_at = CASE WHEN $2 THEN now() ELSE NULL END
          WHERE github_id = $1",
    )
    .bind(github_id)
    .bind(body.value)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(Error::NotFound("publisher"));
    }

    tracing::warn!(github_id, blocked = body.value, "publisher block changed");
    Ok(Json(
        json!({ "github_id": github_id, "blocked": body.value }),
    ))
}
