//! Who a publisher token belongs to, and the name that token publishes under.
//!
//! The harness needs both before it can offer a Publish button. Without the
//! first it cannot say whether a token is live, so the only way to find out
//! would be to publish something and read the error. Without the second it
//! cannot show whose name will appear on the entry — and a publisher who
//! discovers that only after publishing has already published it.
//!
//! **The token is the identity; the name is a label.** Everything ownership
//! depends on hangs off `publisher.id`, which comes from the token and is not
//! sent by the client. `display_name` is the human-readable half, and a caller
//! may change only its own — `PATCH` writes the row the presented token
//! resolves to, so no token can rename another publisher.

use axum::{extract::State, Json};
use serde::Deserialize;

use crate::{
    auth::Publisher,
    error::{Error, Result},
    models::Me,
    AppState,
};

/// `GET /v1/me` — the publisher this token authenticates as.
pub async fn get(State(state): State<AppState>, publisher: Publisher) -> Result<Json<Me>> {
    let me: Me = sqlx::query_as(
        "SELECT github_login, display_name, avatar_url
           FROM registry_publishers
          WHERE id = $1",
    )
    .bind(publisher.id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(me))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMe {
    /// Blank is not a name. Sending one clears the display name back to the
    /// login rather than publishing under an empty string.
    pub display_name: Option<String>,
}

/// `PATCH /v1/me` — set the name this publisher's entries are shown under.
///
/// Harness accounts do not carry a GitHub identity, so the login on the row is
/// whatever the admin recorded when minting the token — often not what the
/// person would choose to be called in a public library. This lets them fix it
/// once, from the same dialog they publish in, instead of asking an operator to
/// edit the database.
pub async fn update(
    State(state): State<AppState>,
    publisher: Publisher,
    Json(body): Json<UpdateMe>,
) -> Result<Json<Me>> {
    let name = body.display_name.map(|n| n.trim().to_string());
    if let Some(n) = &name {
        if n.chars().count() > 60 {
            return Err(Error::BadRequest("display name is too long".into()));
        }
    }
    // Empty becomes NULL: the read side falls back to the login, so a blank
    // name shows as the login rather than as nothing at all.
    let name = name.filter(|n| !n.is_empty());

    let me: Me = sqlx::query_as(
        "UPDATE registry_publishers SET display_name = $2
          WHERE id = $1
      RETURNING github_login, display_name, avatar_url",
    )
    .bind(publisher.id)
    .bind(name)
    .fetch_one(&state.pool)
    .await?;

    tracing::info!(publisher = %me.github_login, "display name changed");
    Ok(Json(me))
}
