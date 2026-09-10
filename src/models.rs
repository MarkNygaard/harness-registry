//! Wire types and the validation that guards the schema's invariants.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Upper bound on a slug. Long enough for a descriptive name, short enough
/// that it cannot be used to push other columns out of a listing.
const SLUG_MAX: usize = 64;
const TITLE_MAX: usize = 120;
const DESCRIPTION_MAX: usize = 2_000;
const TAG_MAX: usize = 32;
const TAGS_MAX: usize = 10;
const CHANGELOG_MAX: usize = 4_000;

/// Slugs nobody may publish, because the harness ships a workflow of each name.
///
/// A harness resolves `.harness/workflows/<name>.yaml` **before** its bundled
/// defaults, so an installed workflow of the same name does not sit beside the
/// built-in one — it silently replaces it. Installing a library workflow called
/// `idea-to-pr` would leave every run of `idea-to-pr` doing whatever the
/// publisher wrote, with nothing on screen to say so and nothing deleted to
/// notice. That is the one collision worth refusing outright rather than
/// renaming around, and refusing it here means the bad name never exists to be
/// installed.
///
/// **Only the names that stay bundled.** `geo-audit`, `bc-idea-to-pr` and
/// `review-area` are moving out of the harness and into the library, so they
/// have to remain publishable — by the project, which is the only party that
/// can publish at all until a publisher token is minted for somebody else.
/// Publishing them before handing out any third-party token is what closes the
/// squatting window, not a reservation.
///
/// `linear-epic-supervise` is here for a stronger reason than the rest: the
/// harness dispatches to it by name from its epic router, so shadowing it does
/// not degrade a workflow, it breaks a code path.
const RESERVED_SLUGS: &[&str] = &[
    "idea-to-pr",
    "revise-pr",
    "review-pr",
    "merge-pr",
    "judge-ab",
    "architect",
    "linear-epic-supervise",
];

/// Whether a slug is one the harness ships and must keep.
pub fn slug_is_reserved(slug: &str) -> bool {
    RESERVED_SLUGS.contains(&slug)
}

/// Validate a slug.
///
/// Lowercase, digits and single dashes only. The schema notes that a slug must
/// not be able to shadow a bundled workflow written to
/// `.harness/workflows/<name>.yaml`, so this also refuses anything that could
/// escape that directory or collide with a path: no dots, no slashes, no
/// leading or trailing dash.
pub fn validate_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.len() > SLUG_MAX {
        return Err(Error::BadRequest(format!(
            "slug must be 1-{SLUG_MAX} characters"
        )));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::BadRequest(
            "slug may contain only lowercase letters, digits and dashes".into(),
        ));
    }
    if slug.starts_with('-') || slug.ends_with('-') || slug.contains("--") {
        return Err(Error::BadRequest(
            "slug may not start or end with a dash, or contain a double dash".into(),
        ));
    }
    // Last, so the shape of a slug is reported before its availability: told
    // both at once, "Idea-To-PR" would be refused as reserved and the author
    // would fix the wrong thing.
    if slug_is_reserved(slug) {
        return Err(Error::BadRequest(format!(
            "`{slug}` is the name of a workflow the harness ships, and installing \
             one of that name would silently replace it"
        )));
    }
    Ok(())
}

fn validate_len(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::BadRequest(format!("{field} is required")));
    }
    if value.len() > max {
        return Err(Error::BadRequest(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(())
}

pub fn validate_tags(tags: &[String]) -> Result<()> {
    if tags.len() > TAGS_MAX {
        return Err(Error::BadRequest(format!("at most {TAGS_MAX} tags")));
    }
    for tag in tags {
        if tag.is_empty() || tag.len() > TAG_MAX {
            return Err(Error::BadRequest(format!(
                "each tag must be 1-{TAG_MAX} characters"
            )));
        }
        if !tag
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(Error::BadRequest(
                "tags may contain only lowercase letters, digits and dashes".into(),
            ));
        }
    }
    Ok(())
}

// --- requests ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateWorkflow {
    pub slug: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub yaml: String,
    #[serde(default)]
    pub changelog: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PublishVersion {
    pub yaml: String,
    #[serde(default)]
    pub changelog: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWorkflow {
    pub title: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RecordInstall {
    /// Opaque per-harness UUID. Not a user, not a hostname -- the schema is
    /// explicit that this must not identify a person or a machine.
    pub installation_id: Uuid,
    pub version: i32,
}

impl CreateWorkflow {
    pub fn validate(&self, max_yaml: usize) -> Result<()> {
        validate_slug(&self.slug)?;
        validate_len("title", &self.title, TITLE_MAX)?;
        validate_len("description", &self.description, DESCRIPTION_MAX)?;
        validate_tags(&self.tags)?;
        validate_yaml(&self.yaml, max_yaml)?;
        if let Some(c) = &self.changelog {
            validate_len("changelog", c, CHANGELOG_MAX)?;
        }
        Ok(())
    }
}

impl PublishVersion {
    pub fn validate(&self, max_yaml: usize) -> Result<()> {
        validate_yaml(&self.yaml, max_yaml)?;
        if let Some(c) = &self.changelog {
            validate_len("changelog", c, CHANGELOG_MAX)?;
        }
        Ok(())
    }
}

impl UpdateWorkflow {
    pub fn validate(&self) -> Result<()> {
        if let Some(t) = &self.title {
            validate_len("title", t, TITLE_MAX)?;
        }
        if let Some(d) = &self.description {
            validate_len("description", d, DESCRIPTION_MAX)?;
        }
        if let Some(tags) = &self.tags {
            validate_tags(tags)?;
        }
        if self.title.is_none() && self.description.is_none() && self.tags.is_none() {
            return Err(Error::BadRequest("nothing to update".into()));
        }
        Ok(())
    }
}

fn validate_yaml(yaml: &str, max: usize) -> Result<()> {
    if yaml.trim().is_empty() {
        return Err(Error::BadRequest("yaml is required".into()));
    }
    if yaml.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(())
}

// --- responses --------------------------------------------------------------

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct WorkflowSummary {
    pub slug: String,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub official: bool,
    pub publisher: String,
    pub latest_version: Option<i32>,
    pub installs: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct VersionSummary {
    pub version: i32,
    pub changelog: Option<String>,
    pub published_at: DateTime<Utc>,
    pub withdrawn: bool,
}

#[derive(Debug, Serialize)]
pub struct VersionDocument {
    pub slug: String,
    pub version: i32,
    pub yaml: String,
    pub changelog: Option<String>,
    pub published_at: DateTime<Utc>,
    pub withdrawn: bool,
}

/// The publisher a token authenticates as, as the harness shows it.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Me {
    pub github_login: String,
    /// What entries are shown under. Null falls back to the login.
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssuedToken {
    pub publisher_id: Uuid,
    pub github_login: String,
    pub name: String,
    /// Present exactly once, in the response that created it.
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_slugs_are_accepted() {
        for slug in ["deploy", "geo-audit-ecommerce", "geo-audit-2"] {
            assert!(validate_slug(slug).is_ok(), "{slug}");
        }
    }

    /// A harness resolves a project workflow *before* its bundled defaults, so
    /// an installed workflow of a bundled name replaces it rather than sitting
    /// beside it — invisibly, with nothing deleted to notice. Refusing the name
    /// here means it never exists to be installed.
    #[test]
    fn a_bundled_workflows_name_cannot_be_published() {
        for slug in [
            "idea-to-pr",
            "revise-pr",
            "review-pr",
            "merge-pr",
            "judge-ab",
            "architect",
            "linear-epic-supervise",
        ] {
            assert!(validate_slug(slug).is_err(), "{slug} should be reserved");
        }
    }

    /// The three moving out of the harness must stay publishable, or the move
    /// cannot happen. Their squatting window is closed by publishing them
    /// before any third-party token exists, not by reserving them.
    #[test]
    fn the_workflows_moving_into_the_library_are_not_reserved() {
        for slug in ["geo-audit", "bc-idea-to-pr", "review-area"] {
            assert!(
                validate_slug(slug).is_ok(),
                "{slug} is moving to the library and must remain publishable"
            );
        }
    }

    /// Reservation is checked last, so an author is told about the shape of
    /// their slug before its availability — otherwise `Idea-To-PR` would be
    /// reported as reserved and they would fix the wrong thing.
    #[test]
    fn shape_is_reported_before_availability() {
        let e = validate_slug("Idea-To-PR").unwrap_err();
        assert!(
            format!("{e:?}").contains("lowercase"),
            "expected the casing complaint, got {e:?}"
        );
    }

    #[test]
    fn a_slug_cannot_escape_the_workflows_directory() {
        // The schema notes a slug must not shadow or escape
        // `.harness/workflows/<name>.yaml`. These are the shapes that would.
        for slug in ["../etc/passwd", "a/b", "a.yaml", r"a\b", "..", "."] {
            assert!(validate_slug(slug).is_err(), "{slug} should be rejected");
        }
    }

    #[test]
    fn a_slug_cannot_be_cosmetically_confusable() {
        // Leading, trailing and doubled dashes all render as near-identical
        // names in a listing, which is how one workflow impersonates another.
        for slug in ["-deploy", "deploy-", "idea--to-pr"] {
            assert!(validate_slug(slug).is_err(), "{slug} should be rejected");
        }
    }

    #[test]
    fn slugs_are_length_bounded_in_both_directions() {
        assert!(validate_slug("").is_err());
        assert!(validate_slug(&"a".repeat(SLUG_MAX)).is_ok());
        assert!(validate_slug(&"a".repeat(SLUG_MAX + 1)).is_err());
    }

    #[test]
    fn uppercase_is_rejected_rather_than_folded() {
        // Folding would make Deploy and deploy the same row on one path and
        // different rows on another; refusing is unambiguous.
        assert!(validate_slug("Deploy").is_err());
    }

    #[test]
    fn tags_are_bounded_in_count_and_length() {
        assert!(validate_tags(&[]).is_ok());
        assert!(validate_tags(&vec!["ci".to_owned(); TAGS_MAX]).is_ok());
        assert!(validate_tags(&vec!["ci".to_owned(); TAGS_MAX + 1]).is_err());
        assert!(validate_tags(&["".to_owned()]).is_err());
        assert!(validate_tags(&["a".repeat(TAG_MAX + 1)]).is_err());
    }

    #[test]
    fn an_oversized_document_is_too_large_not_bad_request() {
        // The distinction matters to a client deciding whether to retry.
        let body = PublishVersion {
            yaml: "x".repeat(101),
            changelog: None,
        };
        assert!(matches!(body.validate(100), Err(Error::TooLarge)));
    }

    #[test]
    fn whitespace_only_fields_do_not_count_as_present() {
        let body = CreateWorkflow {
            slug: "ok".into(),
            title: "   ".into(),
            description: "d".into(),
            tags: vec![],
            yaml: "y".into(),
            changelog: None,
        };
        assert!(body.validate(1024).is_err());
    }

    #[test]
    fn an_update_must_change_something() {
        let empty = UpdateWorkflow {
            title: None,
            description: None,
            tags: None,
        };
        assert!(empty.validate().is_err());
    }
}
