//! Workflow registry API for ai-harness.
//!
//! A small service that owns the `harness-registry` database and publishes it
//! over HTTP. It exists as a separate, private program rather than as part of
//! the open-source harness for three reasons, only one of which is about
//! secrecy:
//!
//! - **It is operator code, not tool code.** Minting publisher tokens,
//!   blocking accounts and setting the `official` badge are things the person
//!   *running* a registry does. In the harness they would ship endpoints for
//!   this registry to everyone who self-hosts it.
//! - **Anti-abuse genuinely benefits from being private.** Rate limits and
//!   trust heuristics lose value when published, unlike authentication, which
//!   does not.
//! - **Independent blast radius.** A harness release does not become a
//!   registry deployment, and a bug in either does not reach the other.
//!
//! The harness talks to this as a client over HTTPS with a publisher token,
//! and *that* half is open source: it is the same code anyone self-hosting
//! uses to publish here.
//!
//! Postgres is never exposed. This service reaches it inside the cluster, and
//! is itself published through the Cloudflare Tunnel, which dials outbound and
//! so needs no forwarded port.

mod auth;
mod config;
mod error;
mod github;
mod models;
mod ratelimit;
mod routes;

use std::time::Duration;

use axum::{
    http::{header, HeaderValue, Method},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: std::sync::Arc<Config>,
    /// Guards the unauthenticated install writes. Shared across handlers, so
    /// the window is per client rather than per request.
    pub install_limiter: std::sync::Arc<ratelimit::RateLimiter>,
    /// Guards starting a device flow. Its own bucket, and a strict one: this
    /// endpoint hands out publisher tokens.
    pub enroll_limiter: std::sync::Arc<ratelimit::RateLimiter>,
    /// Guards polling one. Separate and generous, because polling is how the
    /// flow works rather than a sign of abuse.
    pub enroll_poll_limiter: std::sync::Arc<ratelimit::RateLimiter>,
    /// GitHub, for self-serve enrollment. `None` when no client id is
    /// configured, which removes the enrollment routes.
    pub github: Option<github::GitHub>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,harness_registry=debug")),
        )
        .json()
        .init();

    let config = Config::from_env()?;

    // Bounded, and small. Postgres is shared with the rest of the cluster and
    // the role is capped at 30 connections, so a pool that tried to grow past
    // that would fail at connect time under load rather than queue.
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await?;

    if config.admin_token.is_none() {
        tracing::warn!("ADMIN_TOKEN is unset; the admin endpoints are disabled");
    }

    let github = github::GitHub::new(config.github_client_id.as_deref());
    if github.is_none() {
        tracing::warn!(
            "GITHUB_CLIENT_ID is unset; self-serve enrollment is disabled and \
             publisher tokens can only be minted by an admin"
        );
    }

    // Polling is the normal path, so its window allows one flow's worth of
    // calls many times over: a 15-minute code at a 5-second interval is around
    // 180 polls. Derived from the start limit rather than configured
    // separately, so the two cannot drift into a combination that throttles
    // the flow it is meant to permit.
    let poll_limit = config.enroll_rate_limit.saturating_mul(200);

    let state = AppState {
        pool,
        config: std::sync::Arc::new(config.clone()),
        install_limiter: std::sync::Arc::new(ratelimit::RateLimiter::new(
            config.install_rate_limit,
            Duration::from_secs(config.install_rate_window_secs),
        )),
        enroll_limiter: std::sync::Arc::new(ratelimit::RateLimiter::new(
            config.enroll_rate_limit,
            Duration::from_secs(config.enroll_rate_window_secs),
        )),
        enroll_poll_limiter: std::sync::Arc::new(ratelimit::RateLimiter::new(
            poll_limit,
            Duration::from_secs(config.enroll_rate_window_secs),
        )),
        github,
    };

    let app = Router::new()
        .merge(routes::router())
        .layer(cors(&config))
        .layer(TraceLayer::new_for_http())
        // Bounds the body before a handler sees it, so an oversized document
        // is refused at the edge rather than after being buffered. The
        // per-field YAML limit in `models` is the finer check on top.
        .layer(axum::extract::DefaultBodyLimit::max(
            config.max_yaml_bytes + 64 * 1024,
        ))
        .with_state(state);

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!(addr = %config.bind, "registry API listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;

    Ok(())
}

/// CORS for the read endpoints.
///
/// The site is a static export on a different origin, so a browser fetch needs
/// this. Origins are listed explicitly rather than mirrored: `Any` plus
/// credentials is rejected by browsers anyway, and an allowlist keeps the
/// write endpoints unreachable from a page the user did not intend to be on.
fn cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    if origins.is_empty() {
        // No configured origins means no browser access, which is the right
        // default for a service whose main clients are harness instances
        // making server-side calls.
        return CorsLayer::new();
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::HEAD])
        .allow_headers([header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600))
}

/// Stop accepting on SIGTERM so in-flight publishes finish.
///
/// Kubernetes sends SIGTERM and waits; without handling it the pod is killed
/// mid-request during any rollout or node drain, and a publish that had
/// committed but not responded looks like a failure to the caller.
async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl-c");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received, draining");
}
