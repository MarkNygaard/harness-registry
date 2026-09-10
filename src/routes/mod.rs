pub mod admin;
pub mod health;
pub mod installs;
pub mod workflows;

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health::live))
        .route("/readyz", get(health::ready))
        // Read side. Public: the registry is a library, and the static site
        // fetches this at build time.
        .route(
            "/v1/workflows",
            get(workflows::list).post(workflows::create),
        )
        .route(
            "/v1/workflows/{slug}",
            get(workflows::detail)
                .patch(workflows::update)
                .delete(workflows::unlist),
        )
        .route(
            "/v1/workflows/{slug}/versions",
            get(workflows::versions).post(workflows::publish_version),
        )
        .route(
            "/v1/workflows/{slug}/versions/{version}",
            get(workflows::version_document),
        )
        // Install records. Not publisher-authenticated: the caller is any
        // harness that installed this workflow, identified only by the opaque
        // installation id it generated for itself.
        .route("/v1/workflows/{slug}/installs", put(installs::record))
        // Uninstall. The id is in the path here rather than a body: a DELETE
        // carrying one is poorly supported by intermediaries and by some HTTP
        // clients, and there is nothing to send that the path cannot name.
        .route(
            "/v1/workflows/{slug}/installs/{installation_id}",
            delete(installs::forget),
        )
        // Admin. Disabled outright when ADMIN_TOKEN is unset.
        .route("/v1/admin/tokens", post(admin::issue_token))
        .route(
            "/v1/admin/workflows/{slug}/official",
            put(admin::set_official),
        )
        .route(
            "/v1/admin/publishers/{github_id}/blocked",
            put(admin::set_blocked),
        )
}
