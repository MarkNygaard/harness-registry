//! The library: browse, publish, amend, unlist.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::Publisher,
    error::{on_unique_violation, Error, Result},
    models::{
        CreateWorkflow, PublishVersion, UpdateWorkflow, VersionDocument, VersionSummary,
        WorkflowSummary,
    },
    AppState,
};

/// Columns behind every listing.
///
/// The install count is `count(*)` over the records rather than a stored
/// number, and the latest version excludes withdrawn ones so a pulled release
/// does not keep being advertised as current.
///
/// Only installs seen in the last 90 days count, which is the second half of
/// making the number safe to rank by. The rate limit bounds how fast a count
/// can be inflated; this bounds how long an inflated one survives, because a
/// fabricated install has to keep calling to keep counting. It also makes the
/// figure mean "installs still out there" rather than "installs ever made",
/// which is the more useful number anyway -- the schema anticipated this by
/// refreshing `last_seen_at` on every read of the library.
const SUMMARY_SELECT: &str = r#"
SELECT w.slug,
       w.title,
       w.description,
       w.tags,
       w.official,
       p.github_login AS publisher,
       (SELECT max(v.version) FROM registry_versions v
          WHERE v.workflow_id = w.id AND v.withdrawn_at IS NULL) AS latest_version,
       (SELECT count(*) FROM registry_installs i
          WHERE i.workflow_id = w.id
            AND i.last_seen_at > now() - interval '90 days') AS installs,
       w.updated_at
  FROM registry_workflows w
  JOIN registry_publishers p ON p.id = w.publisher_id
"#;

/// Filter for a listing. Every field is bound as a parameter; the search term
/// has its wildcards added in SQL around the bound value, never by pasting the
/// value into the statement.
const LIST_FILTER: &str = r#"
 WHERE w.unlisted_at IS NULL
   AND ($1::text IS NULL OR $1 = ANY(w.tags))
   AND ($2::text IS NULL OR w.title ILIKE '%' || $2 || '%'
                         OR w.description ILIKE '%' || $2 || '%')
   AND ($3::boolean IS NULL OR w.official = $3)
"#;

/// How a listing is ordered.
///
/// **Installs first, by default.** Ordering by recency rewards publishing
/// volume: whoever publishes the most owns the top of the list, which is the
/// shape of every spam incentive. Ordering by installs makes a workflow nobody
/// installs invisible however many are published — it removes the reward
/// rather than policing the behaviour, and costs one clause.
///
/// `official` still leads, so the project's own workflows are found first
/// whatever their counts.
const ORDER_INSTALLS: &str = " ORDER BY w.official DESC, installs DESC, w.updated_at DESC";

/// Newest first. Kept for anyone genuinely looking for what just landed —
/// which is a real thing to want, and safe as an explicit choice rather than
/// as what everybody gets by default.
const ORDER_RECENT: &str = " ORDER BY w.official DESC, w.updated_at DESC";

const LIST_PAGE: &str = " LIMIT $4 OFFSET $5";

/// Listing order. Anything unrecognised falls back to the default rather than
/// erroring: a bad `sort=` is not worth failing a browse over.
///
/// Deserialized by hand for that reason. A derived impl rejects an unknown
/// variant, and `#[serde(default)]` on the field does not help -- it supplies a
/// default when the key is *absent*, not when its value is unparseable -- so
/// `?sort=bogus` came back as a 400 from `Query` extraction while this comment
/// claimed otherwise.
#[derive(Debug, Default, PartialEq)]
pub enum Sort {
    #[default]
    Installs,
    Recent,
}

impl<'de> Deserialize<'de> for Sort {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.trim().to_ascii_lowercase().as_str() {
            "recent" => Self::Recent,
            // Includes "installs" and everything else. Falling back rather
            // than erroring is the whole point.
            _ => Self::Installs,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub tag: Option<String>,
    pub q: Option<String>,
    pub official: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    #[serde(default)]
    pub sort: Sort,
}

pub async fn list(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<WorkflowSummary>>> {
    // Clamped rather than rejected: a listing is a convenience endpoint and a
    // silly limit should not be an error, but it must not be a way to ask for
    // the whole table either.
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let order = match params.sort {
        Sort::Installs => ORDER_INSTALLS,
        Sort::Recent => ORDER_RECENT,
    };
    let sql = format!("{SUMMARY_SELECT}{LIST_FILTER}{order}{LIST_PAGE}");
    let rows = sqlx::query_as::<_, WorkflowSummary>(&sql)
        .bind(params.tag)
        .bind(params.q)
        .bind(params.official)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(rows))
}

pub async fn detail(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<WorkflowSummary>> {
    let sql = format!("{SUMMARY_SELECT} WHERE w.slug = $1 AND w.unlisted_at IS NULL");
    sqlx::query_as::<_, WorkflowSummary>(&sql)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await?
        .map(Json)
        .ok_or(Error::NotFound("workflow"))
}

pub async fn versions(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<VersionSummary>>> {
    let id = workflow_id(&state, &slug).await?;
    let rows = sqlx::query_as::<_, VersionSummary>(
        "SELECT version, changelog, published_at, (withdrawn_at IS NOT NULL) AS withdrawn
           FROM registry_versions
          WHERE workflow_id = $1
          ORDER BY version DESC",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

type VersionRow = (
    i32,
    String,
    Option<String>,
    chrono::DateTime<chrono::Utc>,
    bool,
);

pub async fn version_document(
    State(state): State<AppState>,
    Path((slug, version)): Path<(String, i32)>,
) -> Result<Json<VersionDocument>> {
    let id = workflow_id(&state, &slug).await?;

    // A withdrawn version is still served, with the flag set. The schema is
    // deliberate about this: installs already holding it keep resolving, and
    // are told rather than broken.
    let row: Option<VersionRow> = sqlx::query_as(
        "SELECT version, yaml, changelog, published_at, (withdrawn_at IS NOT NULL)
           FROM registry_versions
          WHERE workflow_id = $1 AND version = $2",
    )
    .bind(id)
    .bind(version)
    .fetch_optional(&state.pool)
    .await?;

    let (version, yaml, changelog, published_at, withdrawn) =
        row.ok_or(Error::NotFound("version"))?;

    Ok(Json(VersionDocument {
        slug,
        version,
        yaml,
        changelog,
        published_at,
        withdrawn,
    }))
}

pub async fn create(
    State(state): State<AppState>,
    publisher: Publisher,
    Json(body): Json<CreateWorkflow>,
) -> Result<Json<Value>> {
    body.validate(state.config.max_yaml_bytes)?;

    // Workflow and its first version in one transaction: a workflow with no
    // versions is not something the read side knows how to render.
    let mut tx = state.pool.begin().await?;

    let workflow: (Uuid,) = sqlx::query_as(
        "INSERT INTO registry_workflows (slug, title, description, tags, publisher_id)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(&body.slug)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.tags)
    .bind(publisher.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| on_unique_violation(e, "that slug is already taken"))?;

    sqlx::query(
        "INSERT INTO registry_versions (workflow_id, version, yaml, changelog)
         VALUES ($1, 1, $2, $3)",
    )
    .bind(workflow.0)
    .bind(&body.yaml)
    .bind(&body.changelog)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(slug = %body.slug, publisher = %publisher.github_login, "workflow published");
    Ok(Json(json!({ "slug": body.slug, "version": 1 })))
}

pub async fn publish_version(
    State(state): State<AppState>,
    publisher: Publisher,
    Path(slug): Path<String>,
    Json(body): Json<PublishVersion>,
) -> Result<Json<Value>> {
    body.validate(state.config.max_yaml_bytes)?;
    let id = owned_workflow_id(&state, &slug, &publisher).await?;

    let mut tx = state.pool.begin().await?;

    // The next number is derived, not supplied. `version` is a per-workflow
    // counter and not semver: the author presses publish, and nobody wants to
    // choose a number for that.
    //
    // Two publishes racing both read the same max and one loses the unique
    // constraint on (workflow_id, version). That surfaces as 409 so the client
    // retries, rather than as a 500.
    let next: (i32,) = sqlx::query_as(
        "INSERT INTO registry_versions (workflow_id, version, yaml, changelog)
         SELECT $1, COALESCE(max(version), 0) + 1, $2, $3
           FROM registry_versions WHERE workflow_id = $1
         RETURNING version",
    )
    .bind(id)
    .bind(&body.yaml)
    .bind(&body.changelog)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| on_unique_violation(e, "a concurrent publish took that version; retry"))?;

    sqlx::query("UPDATE registry_workflows SET updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::info!(
        %slug,
        version = next.0,
        publisher = %publisher.github_login,
        "version published"
    );
    Ok(Json(json!({ "slug": slug, "version": next.0 })))
}

pub async fn update(
    State(state): State<AppState>,
    publisher: Publisher,
    Path(slug): Path<String>,
    Json(body): Json<UpdateWorkflow>,
) -> Result<Json<Value>> {
    body.validate()?;
    let id = owned_workflow_id(&state, &slug, &publisher).await?;

    // COALESCE so an omitted field keeps its value rather than being nulled.
    sqlx::query(
        "UPDATE registry_workflows
            SET title = COALESCE($2, title),
                description = COALESCE($3, description),
                tags = COALESCE($4, tags),
                updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.tags)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "status": "updated" })))
}

pub async fn unlist(
    State(state): State<AppState>,
    publisher: Publisher,
    Path(slug): Path<String>,
) -> Result<Json<Value>> {
    let id = owned_workflow_id(&state, &slug, &publisher).await?;

    // Soft delete. Nothing is removed from under an install that already took
    // it; it simply stops appearing in the library.
    sqlx::query("UPDATE registry_workflows SET unlisted_at = now() WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    tracing::info!(%slug, publisher = %publisher.github_login, "workflow unlisted");
    Ok(Json(json!({ "status": "unlisted" })))
}

// --- helpers ----------------------------------------------------------------

async fn workflow_id(state: &AppState, slug: &str) -> Result<Uuid> {
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM registry_workflows WHERE slug = $1")
        .bind(slug)
        .fetch_optional(&state.pool)
        .await?
        .map(|r| r.0)
        .ok_or(Error::NotFound("workflow"))
}

/// Resolve a slug to an id the caller is allowed to change.
///
/// Returns 404 rather than 403 when the workflow exists but belongs to someone
/// else: a publisher has no business learning which slugs are taken by whom
/// through the difference in status code.
async fn owned_workflow_id(state: &AppState, slug: &str, publisher: &Publisher) -> Result<Uuid> {
    sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM registry_workflows WHERE slug = $1 AND publisher_id = $2",
    )
    .bind(slug)
    .bind(publisher.id)
    .fetch_optional(&state.pool)
    .await?
    .map(|r| r.0)
    .ok_or(Error::NotFound("workflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The listing's default order is the anti-spam property, not a
    /// preference: ordering by recency hands the top of the list to whoever
    /// publishes the most, which is the shape of every spam incentive. If this
    /// test starts failing, that reward has been put back.
    #[test]
    fn the_default_listing_order_is_installs_not_recency() {
        assert_eq!(Sort::default(), Sort::Installs);
        assert!(ORDER_INSTALLS.contains("installs DESC"));
        assert!(!ORDER_RECENT.contains("installs"));
        // Official leads either way, so the project's own workflows are found
        // whatever their counts.
        assert!(ORDER_INSTALLS.starts_with(" ORDER BY w.official DESC"));
        assert!(ORDER_RECENT.starts_with(" ORDER BY w.official DESC"));
    }

    /// `sort=` is optional and its absence must mean the default, not an
    /// error — a browse should never fail over a missing query parameter.
    #[test]
    fn sort_parses_and_defaults() {
        let params: ListParams = serde_json::from_str("{}").expect("empty params");
        assert_eq!(params.sort, Sort::Installs);
        assert_eq!(params.tag, None);

        let recent: ListParams =
            serde_json::from_str(r#"{"sort":"recent"}"#).expect("explicit sort");
        assert_eq!(recent.sort, Sort::Recent);

        let installs: ListParams =
            serde_json::from_str(r#"{"sort":"installs"}"#).expect("explicit sort");
        assert_eq!(installs.sort, Sort::Installs);
    }

    /// The case the derived impl got wrong. `?sort=bogus` used to come back as
    /// a 400 from Query extraction, while the docs promised a fallback -- so
    /// this pins the promise rather than the implementation detail.
    #[test]
    fn an_unrecognised_sort_falls_back_instead_of_erroring() {
        let params: ListParams =
            serde_json::from_str(r#"{"sort":"bogus"}"#).expect("must not error");
        assert_eq!(params.sort, Sort::Installs);
    }

    /// Case and stray whitespace should not be the difference between a
    /// working sort and a silently ignored one.
    #[test]
    fn sort_is_case_and_whitespace_insensitive() {
        for raw in [r#"{"sort":"RECENT"}"#, r#"{"sort":" recent "}"#] {
            let p: ListParams = serde_json::from_str(raw).expect(raw);
            assert_eq!(p.sort, Sort::Recent, "{raw}");
        }
    }

    /// The paging clause is bound separately from the order, so the two cannot
    /// be reordered into `LIMIT` before `ORDER BY` by an edit to either.
    #[test]
    fn a_listing_orders_before_it_pages() {
        let sql = format!("{SUMMARY_SELECT}{LIST_FILTER}{ORDER_INSTALLS}{LIST_PAGE}");
        let order = sql.find("ORDER BY").expect("ordered");
        let limit = sql.find("LIMIT").expect("paged");
        assert!(order < limit, "ORDER BY must precede LIMIT:\n{sql}");
    }
}
