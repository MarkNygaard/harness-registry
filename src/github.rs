//! GitHub's device flow, and the one profile read that follows it.
//!
//! Enrollment exists so that somebody running their own harness can obtain a
//! publisher token without asking the operator of this registry for one. The
//! flow has to work from a harness on any hostname, which is what rules out the
//! ordinary authorization-code redirect: that needs a callback URL registered
//! per client, and every self-hosted install is on a different address. The
//! device flow has no callback at all, so nothing about a new install has to be
//! registered anywhere.
//!
//! **No scope is requested.** The public profile is all enrollment needs, and
//! `GET /user` returns it for a token with no scopes. Authorizing this app
//! therefore grants it nothing. No repositories, no email, no write of any
//! kind, which is the correct thing to ask of someone who only wants to publish
//! a YAML file.
//!
//! **No client secret.** The device flow's token exchange is specified for
//! public clients and GitHub does not require one, so there is no secret here
//! to leak or rotate. The `device_code` is the flow's secret, it is single-use
//! and short-lived, and it travels over TLS between the harness and this
//! service.
//!
//! Nothing here is stored. The device code this service hands back is GitHub's
//! own and the harness returns it on each poll, so a flow in progress needs no
//! row and no in-memory state. That is also what lets it survive a rollout and
//! work with more than one replica.

use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};

const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";

/// GitHub rejects an API call with no `User-Agent`, so this is required rather
/// than polite.
const USER_AGENT: &str = "harness-registry";

/// Every call here has a person waiting on a screen. A hung request to GitHub
/// must not become a hung request to the harness.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A device flow that has started. The `user_code` and `verification_uri` are
/// for the person, and the `device_code` is for the next call.
#[derive(Debug, Deserialize)]
pub struct DeviceFlow {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// Where a poll got to.
///
/// `Pending` and `SlowDown` are both "not yet", kept apart because the second
/// is GitHub saying the caller's interval is too short. Polling through a
/// `slow_down` gets the flow rate-limited, so it has to reach the harness.
pub enum Poll {
    Pending,
    SlowDown,
    Declined,
    Expired,
    Authorized(String),
}

/// A GitHub account, as much of it as enrollment looks at.
#[derive(Debug, Deserialize)]
pub struct GitHubUser {
    /// The numeric id, which is the identity a publisher row is keyed on. A
    /// login can be renamed and the old one claimed by somebody else, so
    /// keying on the login would let an account be inherited along with its
    /// workflows.
    pub id: i64,
    pub login: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct GitHub {
    http: reqwest::Client,
    client_id: String,
    profiles: Profiles,
}

/// Reads the account behind a GitHub access token, and nothing else.
///
/// Separate from [`GitHub`] because it needs no client id: `GET /user` answers
/// for a token issued by *any* OAuth app. That is what lets a harness whose
/// people already signed in with GitHub hand over their token instead of
/// running a device flow, on a registry that never set up an OAuth app at all.
#[derive(Clone)]
pub struct Profiles {
    http: reqwest::Client,
}

impl Default for Profiles {
    fn default() -> Self {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .unwrap_or_default();
        Self { http }
    }
}

impl Profiles {
    /// Read the account an access token belongs to.
    ///
    /// This is what makes the `github_id` on a publisher row mean something.
    /// It comes from GitHub in exchange for a token the person authorized,
    /// never from the body of a request.
    pub async fn user(&self, access_token: &str) -> Result<GitHubUser> {
        let resp = self
            .http
            .get(USER_URL)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(unreachable)?;

        if !resp.status().is_success() {
            return Err(profile_refused(resp.status()));
        }

        resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "unreadable profile response");
            Error::BadGateway("GitHub sent an unreadable response".into())
        })
    }
}

/// What a refused profile read means to the caller.
///
/// A 401 is the token: revoked, expired, or never real. That is the caller's
/// to fix by signing in again, and it must not read as GitHub being down,
/// which is what a 502 says. Anything else is GitHub's fault.
fn profile_refused(status: reqwest::StatusCode) -> Error {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        tracing::info!("GitHub did not accept the access token");
        return Error::Unauthorized;
    }
    tracing::error!(status = %status, "GitHub refused the profile read");
    Error::BadGateway("GitHub would not confirm the account".into())
}

/// What GitHub answers a token request with. Success and failure share one
/// shape, because GitHub returns both with a 200.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

impl GitHub {
    /// Build a client, or `None` when no client id is configured.
    ///
    /// Absent configuration disables enrollment rather than half-enabling it,
    /// the same way an unset `ADMIN_TOKEN` removes the admin routes. A
    /// deployment that forgets the variable fails closed.
    pub fn new(client_id: Option<&str>) -> Option<Self> {
        let client_id = client_id.map(str::trim).filter(|c| !c.is_empty())?;
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .ok()?;
        Some(Self {
            http,
            client_id: client_id.to_owned(),
            profiles: Profiles::default(),
        })
    }

    /// Ask GitHub to start a flow and issue a code for the person to type.
    pub async fn start(&self) -> Result<DeviceFlow> {
        let resp = self
            .http
            .post(DEVICE_CODE_URL)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[("client_id", self.client_id.as_str())])
            .send()
            .await
            .map_err(unreachable)?;

        if !resp.status().is_success() {
            tracing::error!(status = %resp.status(), "GitHub refused to start a device flow");
            return Err(Error::BadGateway(
                "GitHub would not start the sign-in".into(),
            ));
        }

        resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "unreadable device flow response");
            Error::BadGateway("GitHub sent an unreadable response".into())
        })
    }

    /// Exchange a device code, or report why it is not ready.
    pub async fn poll(&self, device_code: &str) -> Result<Poll> {
        let resp = self
            .http
            .post(ACCESS_TOKEN_URL)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .map_err(unreachable)?;

        let body: TokenResponse = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "unreadable token response");
            Error::BadGateway("GitHub sent an unreadable response".into())
        })?;

        Ok(classify(body))
    }

    /// Read the account the device flow's access token belongs to.
    pub async fn user(&self, access_token: &str) -> Result<GitHubUser> {
        self.profiles.user(access_token).await
    }
}

fn unreachable(e: reqwest::Error) -> Error {
    tracing::error!(error = %e, "GitHub unreachable");
    Error::BadGateway("GitHub could not be reached".into())
}

/// Read one token response.
///
/// Separated from the request so the mapping can be tested: every outcome of
/// the flow arrives here as a 200, and getting one of them wrong is the
/// difference between a harness that stops and a harness that polls forever.
///
/// An unrecognised error counts as expired rather than as pending. Pending
/// would leave the harness polling a flow that can never complete, until the
/// code runs out, which reads as a hang rather than as a failure.
fn classify(body: TokenResponse) -> Poll {
    if let Some(token) = body.access_token {
        return Poll::Authorized(token);
    }
    match body.error.as_deref() {
        Some("authorization_pending") => Poll::Pending,
        Some("slow_down") => Poll::SlowDown,
        Some("access_denied") => Poll::Declined,
        other => {
            if other != Some("expired_token") {
                tracing::warn!(error = ?other, "unexpected device flow error");
            }
            Poll::Expired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(access_token: Option<&str>, error: Option<&str>) -> TokenResponse {
        TokenResponse {
            access_token: access_token.map(str::to_owned),
            error: error.map(str::to_owned),
        }
    }

    #[test]
    fn a_token_is_an_authorization() {
        assert!(matches!(
            classify(response(Some("gho_x"), None)),
            Poll::Authorized(t) if t == "gho_x"
        ));
    }

    #[test]
    fn waiting_is_told_apart_from_being_too_fast() {
        // Both mean "not yet", and conflating them gets the flow rate-limited
        // by GitHub, because slow_down is the only signal to back off.
        assert!(matches!(
            classify(response(None, Some("authorization_pending"))),
            Poll::Pending
        ));
        assert!(matches!(
            classify(response(None, Some("slow_down"))),
            Poll::SlowDown
        ));
    }

    #[test]
    fn declining_and_expiring_are_separate_endings() {
        assert!(matches!(
            classify(response(None, Some("access_denied"))),
            Poll::Declined
        ));
        assert!(matches!(
            classify(response(None, Some("expired_token"))),
            Poll::Expired
        ));
    }

    #[test]
    fn an_unknown_answer_ends_the_flow_rather_than_hanging_it() {
        // The failure mode being avoided: treating this as Pending leaves the
        // harness polling something that will never complete.
        for error in ["incorrect_device_code", "unsupported_grant_type", "wat"] {
            assert!(
                matches!(classify(response(None, Some(error))), Poll::Expired),
                "{error}"
            );
        }
        assert!(matches!(classify(response(None, None)), Poll::Expired));
    }

    #[test]
    fn a_rejected_token_is_the_callers_to_fix_not_an_outage() {
        // A harness holding a revoked token has to be told to sign in again.
        // A 502 would send it retrying a token that will never work.
        assert!(matches!(
            profile_refused(reqwest::StatusCode::UNAUTHORIZED),
            Error::Unauthorized
        ));
        for status in [
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(
                matches!(profile_refused(status), Error::BadGateway(_)),
                "{status}"
            );
        }
    }
}
