//! Self-serve enrollment: how somebody gets a publisher token.
//!
//! Before this, the only way to obtain one was `POST /v1/admin/tokens`, which
//! needs the admin token. A third party running their own harness who wrote a
//! workflow and pressed Publish was told to ask the operator, by hand, out of
//! band. The Community tier of the library was unreachable in practice.
//!
//! These two endpoints are the only public writes in the service besides the
//! install records, and unlike those they hand out a credential, so they are
//! rate limited before anything else happens.
//!
//! **This is where the abuse rules belong.** A minimum account age can only be
//! checked at the moment an account is first seen, and the per-publisher cap on
//! listed workflows is checked at publish. Both were written down when the
//! library was designed and neither had anywhere to run until now.
//!
//! **A blocked publisher cannot enroll around the block.** The check is on the
//! upsert path rather than only on publish, or blocking somebody would amount
//! to asking them to sign in again.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{generate_token, hash_token},
    error::{Error, Result},
    github::{GitHub, GitHubUser, Poll},
    ratelimit::client_key,
    AppState,
};

/// What a token minted this way is called, so it can be told apart from an
/// admin-minted one when revoking.
const TOKEN_NAME: &str = "self-serve enrollment";

/// Resolve the GitHub client, or report enrollment as absent.
///
/// `404` rather than `503`: with no client id configured these routes do not
/// exist, which is the same fail-closed shape the admin surface uses for a
/// missing `ADMIN_TOKEN`.
fn github(state: &AppState) -> Result<&GitHub> {
    state.github.as_ref().ok_or(Error::NotFound("route"))
}

/// `POST /v1/enroll` — begin a device flow.
///
/// The response is GitHub's, forwarded. The harness shows `user_code` and
/// `verification_uri` to the person and holds `device_code` for the poll.
pub async fn start(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>> {
    // Checked first, so a throttled caller cannot use the endpoint to find out
    // whether enrollment is configured here.
    if !state.enroll_limiter.check(&client_key(&headers, None)) {
        return Err(Error::TooManyRequests);
    }
    let flow = github(&state)?.start().await?;

    Ok(Json(json!({
        "device_code": flow.device_code,
        "user_code": flow.user_code,
        "verification_uri": flow.verification_uri,
        "expires_in": flow.expires_in,
        "interval": flow.interval,
    })))
}

#[derive(Debug, Deserialize)]
pub struct PollRequest {
    pub device_code: String,
}

/// `POST /v1/enroll/poll` — finish the flow, or say it is not finished.
///
/// Answers with a `status` the harness switches on rather than with a status
/// code per outcome, because "not yet" is the overwhelmingly common answer and
/// it is not an error. The two that *are* errors, a declined authorization and
/// an expired code, end the flow and so are worth a status code the harness
/// cannot mistake for a retry.
pub async fn poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PollRequest>,
) -> Result<Json<Value>> {
    // A generous bucket of its own. Polling is the design here: a 15-minute
    // code at GitHub's 5-second interval is around 180 calls, so sharing the
    // strict start limit would throttle the normal path.
    if !state.enroll_poll_limiter.check(&client_key(&headers, None)) {
        return Err(Error::TooManyRequests);
    }
    let github = github(&state)?;

    let access_token = match github.poll(&body.device_code).await? {
        Poll::Pending => return Ok(Json(json!({ "status": "pending" }))),
        Poll::SlowDown => return Ok(Json(json!({ "status": "slow_down" }))),
        Poll::Declined => {
            return Err(Error::Forbidden(
                "the sign-in was declined on GitHub".into(),
            ))
        }
        Poll::Expired => {
            return Err(Error::BadRequest(
                "the code expired before it was entered; start again".into(),
            ))
        }
        Poll::Authorized(token) => token,
    };

    // The access token is used once, here, and never stored. Everything after
    // this point is about the registry's own publisher row.
    let user = github.user(&access_token).await?;
    enrolled(&state, &user, TOKEN_NAME).await
}

#[derive(Debug, Deserialize)]
pub struct GitHubTokenRequest {
    /// A GitHub access token the person granted, to any OAuth app.
    pub access_token: String,
}

/// `POST /v1/enroll/github` — a publisher token for whoever a GitHub access
/// token belongs to.
///
/// For a harness whose people already signed in with GitHub. Instead of a
/// device flow, it hands over the token it holds for the person pressing
/// Publish, and this service asks GitHub whose it is. The harness never says
/// who the person is; GitHub does, which is the same proof the device flow
/// ends with.
///
/// Works whether or not this registry has an OAuth app of its own: `/user`
/// answers for a token from any app. The account-age and blocked checks are
/// the device flow's, unchanged.
pub async fn with_github_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GitHubTokenRequest>,
) -> Result<Json<Value>> {
    // The generous bucket, not the strict one. Every person on a harness
    // reaches this from that harness's address, so a limit sized for one
    // person starting device flows would turn away a team's first morning.
    // Each call still needs a token GitHub accepts, which is not something a
    // caller can mint in bulk.
    if !state.enroll_poll_limiter.check(&client_key(&headers, None)) {
        return Err(Error::TooManyRequests);
    }
    let access_token = plausible_token(&body.access_token)?;
    let user = state.profiles.user(access_token).await?;
    enrolled(&state, &user, TOKEN_NAME_GITHUB).await
}

/// What a token minted from a harness's GitHub sign-in is called.
const TOKEN_NAME_GITHUB: &str = "harness GitHub sign-in";

/// Reject what cannot be a GitHub token before spending a call on it.
///
/// GitHub's tokens are well under 300 characters. A body far longer than that
/// is not a token, and passing it on would put arbitrary input into a request
/// header.
fn plausible_token(token: &str) -> Result<&str> {
    let token = token.trim();
    if token.is_empty()
        || token.len() > 512
        || token.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::BadRequest(
            "access_token is not a GitHub token".into(),
        ));
    }
    Ok(token)
}

/// The end of every enrollment: check the account, create or reuse its
/// publisher row, and issue a token for it.
async fn enrolled(state: &AppState, user: &GitHubUser, token_name: &str) -> Result<Json<Value>> {
    check_account_age(state, user)?;

    let publisher_id = upsert_publisher(state, user).await?;
    let token = generate_token();

    sqlx::query(
        "INSERT INTO registry_publisher_tokens (publisher_id, token_hash, name)
         VALUES ($1, $2, $3)",
    )
    .bind(publisher_id)
    .bind(hash_token(&token))
    .bind(token_name)
    .execute(&state.pool)
    .await?;

    tracing::info!(
        publisher = %user.login,
        github_id = user.id,
        via = token_name,
        "publisher enrolled"
    );

    Ok(Json(json!({
        "status": "complete",
        "token": token,
        "publisher_id": publisher_id,
        "github_login": user.login,
    })))
}

/// Refuse an account created too recently to have a history.
///
/// A cheap, standard heuristic, and the only one available at this point: a
/// fresh account is the thing somebody makes in bulk, and an old one is not.
/// It is a speed bump rather than a wall, which is the honest description of
/// every account-age check.
fn check_account_age(state: &AppState, user: &GitHubUser) -> Result<()> {
    let days = state.config.min_account_age_days;
    if old_enough(user.created_at, chrono::Utc::now(), days) {
        return Ok(());
    }
    tracing::warn!(publisher = %user.login, github_id = user.id, "enrollment refused: account too new");
    Err(Error::Forbidden(format!(
        "a GitHub account must be at least {days} days old to publish here"
    )))
}

/// Whether an account created at `created_at` is old enough at `now`.
///
/// Takes `now` rather than reading the clock so the boundary can be tested.
/// Zero or less turns the check off, which is what a private registry among
/// colleagues wants and what keeps the rule from being a thing to work around
/// in a deployment that does not need it.
fn old_enough(
    created_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    min_days: i64,
) -> bool {
    min_days <= 0 || now - created_at >= chrono::Duration::days(min_days)
}

/// Create the publisher row, or return the existing one.
///
/// Enrolling twice is the normal way to replace a lost token, not an error, so
/// this upserts exactly as `admin::issue_token` does. The difference is where
/// the values come from: GitHub, in exchange for an authorization, rather than
/// from the body of the request.
///
/// `display_name` and `avatar_url` use COALESCE on the *existing* value so that
/// re-enrolling never overwrites a name the publisher chose in the publish
/// dialog with whatever their GitHub profile says today.
async fn upsert_publisher(state: &AppState, user: &GitHubUser) -> Result<Uuid> {
    let row: (Uuid, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "INSERT INTO registry_publishers (github_id, github_login, display_name, avatar_url)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (github_id) DO UPDATE
            SET github_login = EXCLUDED.github_login,
                display_name = COALESCE(registry_publishers.display_name, EXCLUDED.display_name),
                avatar_url   = COALESCE(EXCLUDED.avatar_url, registry_publishers.avatar_url)
         RETURNING id, blocked_at",
    )
    .bind(user.id)
    .bind(&user.login)
    .bind(
        user.name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty()),
    )
    .bind(&user.avatar_url)
    .fetch_one(&state.pool)
    .await?;

    let (id, blocked_at) = row;

    // Checked after the upsert rather than before, so there is one statement
    // deciding the row and no window between a lookup and a write. A blocked
    // publisher signing in again must not come back with a working token.
    if blocked_at.is_some() {
        tracing::warn!(publisher = %user.login, github_id = user.id, "blocked publisher attempted to enroll");
        return Err(Error::Forbidden("publisher is blocked".into()));
    }

    Ok(id)
}

/// `GET /v1/enroll` — which ways of enrolling this registry offers.
///
/// `enrollment` is the device flow, which needs this registry's own OAuth app.
/// `github_token` is `POST /v1/enroll/github`, which needs nothing and is
/// always on; the field exists so a harness can tell this registry from an
/// older one that would answer that route with a 404.
pub async fn available(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "enrollment": state.github.is_some(),
            "github_token": true,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    fn at(day: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, day, 12, 0, 0).unwrap()
    }

    #[test]
    fn an_account_older_than_the_minimum_may_enroll() {
        let now = at(30);
        assert!(old_enough(now - Duration::days(31), now, 30));
    }

    #[test]
    fn an_account_younger_than_the_minimum_may_not() {
        let now = at(30);
        assert!(!old_enough(now - Duration::days(29), now, 30));
        // The account made moments ago, which is the case the rule is for.
        assert!(!old_enough(now, now, 30));
    }

    #[test]
    fn the_boundary_admits_rather_than_refuses() {
        // Exactly the minimum is old enough. An off-by-one here refuses
        // somebody on the day they become eligible, which reads as the check
        // being broken rather than as a rule.
        let now = at(30);
        assert!(old_enough(now - Duration::days(30), now, 30));
    }

    #[test]
    fn only_something_shaped_like_a_token_is_sent_to_github() {
        assert_eq!(plausible_token("  gho_abc123  ").unwrap(), "gho_abc123");
        for bad in [
            "",
            "   ",
            "gho_abc def",
            "gho_abc\nX-Injected: 1",
            &"a".repeat(513),
        ] {
            assert!(plausible_token(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_minimum_of_zero_turns_the_check_off() {
        let now = at(30);
        assert!(old_enough(now, now, 0));
        assert!(old_enough(now, now, -1));
    }
}
