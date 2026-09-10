//! Publisher tokens.
//!
//! A token is 32 random bytes, handed out once and stored only as a SHA-256
//! digest. SHA-256 rather than a password KDF is deliberate: the secret is
//! full-entropy machine-generated, so there is no dictionary to grind and
//! nothing for a slow hash to buy, while a KDF would run on every single
//! request and hand anyone a cheap way to saturate the CPU. This is what
//! GitHub and Stripe do with API tokens, and the reasoning is the same.
//!
//! `harness_tokens` in the harness itself stores hashes the same way.

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::{Error, Result},
    AppState,
};

/// Number of random bytes behind a token. 256 bits, so the digest is the
/// weakest link rather than the secret.
const TOKEN_BYTES: usize = 32;

/// Prefixed so a leaked string is recognisable in a log or a paste, and so
/// secret scanners have something to match.
pub const TOKEN_PREFIX: &str = "hrp_";

/// Generate a token. Returned once, in clear, and never recoverable after.
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A caller that presented a live token belonging to an unblocked publisher.
#[derive(Debug, Clone)]
pub struct Publisher {
    pub id: Uuid,
    pub github_login: String,
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

impl FromRequestParts<AppState> for Publisher {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        let token = bearer(parts).ok_or(Error::Unauthorized)?;

        // One statement so a valid-but-blocked publisher cannot be told apart
        // from an unknown token by timing two round trips.
        let row: Option<(Uuid, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT p.id, p.github_login, p.blocked_at
               FROM registry_publisher_tokens t
               JOIN registry_publishers p ON p.id = t.publisher_id
              WHERE t.token_hash = $1 AND t.revoked_at IS NULL",
        )
        .bind(hash_token(token))
        .fetch_optional(&state.pool)
        .await?;

        let (id, github_login, blocked_at) = row.ok_or(Error::Unauthorized)?;
        if blocked_at.is_some() {
            return Err(Error::Forbidden("publisher is blocked".into()));
        }

        // Best-effort: a failed bookkeeping write must not fail the request it
        // was only observing.
        let _ = sqlx::query(
            "UPDATE registry_publisher_tokens SET last_used_at = now() WHERE token_hash = $1",
        )
        .bind(hash_token(token))
        .execute(&state.pool)
        .await;

        Ok(Self { id, github_login })
    }
}

/// Guards the admin endpoints. Separate from publisher tokens because these
/// grant things no publisher may do -- minting tokens, blocking accounts,
/// setting `official`.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        // No configured token means the admin surface does not exist, rather
        // than existing with an empty password.
        let expected = state
            .config
            .admin_token
            .as_deref()
            .ok_or(Error::NotFound("route"))?;
        let presented = bearer(parts).ok_or(Error::Unauthorized)?;

        // Compare digests, so the comparison is over fixed-length input.
        if hash_token(presented) == hash_token(expected) {
            Ok(Self)
        } else {
            Err(Error::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_and_full_entropy() {
        let token = generate_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        // Hex, so two characters per byte.
        assert_eq!(token.len(), TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
    }

    #[test]
    fn tokens_do_not_repeat() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }

    #[test]
    fn hashing_is_stable_and_not_the_token() {
        let token = generate_token();
        assert_eq!(hash_token(&token), hash_token(&token));
        assert_ne!(hash_token(&token), token);
        // SHA-256 as hex.
        assert_eq!(hash_token(&token).len(), 64);
    }

    #[test]
    fn a_different_token_hashes_differently() {
        assert_ne!(hash_token("hrp_a"), hash_token("hrp_b"));
    }
}
