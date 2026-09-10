//! One error type for every handler, and one place that decides status codes.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    BadRequest(String),

    /// No credential, or one that does not verify. Deliberately does not
    /// distinguish the two: telling a caller that a token exists but is
    /// revoked confirms the token was real.
    #[error("authentication required")]
    Unauthorized,

    #[error("{0}")]
    Forbidden(String),

    #[error("{0} not found")]
    NotFound(&'static str),

    #[error("{0}")]
    Conflict(String),

    #[error("payload too large")]
    TooLarge,

    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Error::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Error::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            Error::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Error::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            Error::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            // The message is logged, never returned: a Postgres error can
            // carry table and column names, and a constraint name is a map of
            // the schema.
            Error::Database(e) => {
                tracing::error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_owned(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Turn a unique-violation into a 409 with a caller-facing message.
///
/// Used where a race is legitimate rather than a bug -- two publishes landing
/// on the same version number, say -- so the caller can retry instead of
/// reading a 500.
pub fn on_unique_violation(e: sqlx::Error, message: &str) -> Error {
    match &e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            Error::Conflict(message.to_owned())
        }
        _ => Error::Database(e),
    }
}
