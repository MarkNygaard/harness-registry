# harness-registry

The workflow registry API for [ai-harness](https://github.com/MarkNygaard/ai-harness).

A small Rust service that owns the `harness-registry` Postgres database and
publishes it over HTTP, so that any harness instance — including ones other
people self-host — can browse and publish workflows.

## Why this is a separate, private repository

The harness itself is open source. This is not, and the reason is worth stating
precisely, because "the code is secret" is the *weakest* of the arguments and
should not be the load-bearing one. Tokens are stored as hashes and secrets come
from the environment, so nothing here becomes safer merely by being unreadable.

The real reasons:

- **It is operator code, not tool code.** Minting publisher tokens, blocking an
  account, setting the `official` badge — these are things the person *running*
  a registry does. Inside the harness they would ship endpoints for *this*
  registry to everyone who self-hosts it, needing disabling, documenting and
  defending.
- **Anti-abuse genuinely benefits from privacy.** Rate limits and trust
  heuristics lose value when published. Unlike authentication, which does not.
- **Independent blast radius and lifecycle.** A harness release is not a
  registry deployment. A bug in either does not reach the other.

The harness reaches this service as a **client**, over HTTPS, with a publisher
token — and that half stays open source, because it is the same code anyone
self-hosting uses to publish here. Only the server is private. That is the usual
split for a package registry.

## Why Postgres is not exposed

An earlier design put the shared CNPG cluster behind a WAN port-forward so a
Vercel serverless function could speak the Postgres wire protocol directly.
That was dropped, and the reasoning is worth keeping:

- Vercel has no stable egress range without Secure Compute, so the port could
  not be narrowed by source IP — it was simply **open**.
- The `pg_hba` lockdown was only sound while `externalTrafficPolicy: Local`
  held, because under the default `Cluster` policy Cilium SNATs the client to a
  node address in the one range `pg_hba` must trust for every role.
- Cloudflare Tunnel cannot carry the Postgres protocol — TCP ingress needs
  `cloudflared access tcp` running beside the caller — which is what forced the
  port-forward in the first place.

None of it was necessary. The harness runs *in* the cluster and writes to
Postgres directly. Only reading the registry from outside needed solving, and
that is an HTTP problem. This service is published through the existing
Cloudflare Tunnel, which dials **outbound**, so there is no forwarded port and
no listening port on the WAN at all.

The database credential now never leaves the cluster, which also means rotating
it is a Flux reconcile rather than a coordinated change with an external
platform's environment variables.

## API

Read endpoints are public: the registry is a library, and the static site
fetches them at build time.

| Method | Path | Auth | |
|---|---|---|---|
| `GET` | `/healthz` | — | process is up |
| `GET` | `/readyz` | — | database is reachable |
| `GET` | `/v1/workflows` | — | list; `?tag=`, `?q=`, `?official=`, `?limit=`, `?offset=` |
| `GET` | `/v1/workflows/{slug}` | — | one workflow |
| `GET` | `/v1/workflows/{slug}/versions` | — | version history |
| `GET` | `/v1/workflows/{slug}/versions/{n}` | — | the YAML document |
| `POST` | `/v1/workflows` | publisher | create, with version 1 |
| `POST` | `/v1/workflows/{slug}/versions` | publisher | publish the next version |
| `PATCH` | `/v1/workflows/{slug}` | publisher | title, description, tags |
| `DELETE` | `/v1/workflows/{slug}` | publisher | unlist (soft) |
| `PUT` | `/v1/workflows/{slug}/installs` | — | record or refresh an install |
| `POST` | `/v1/admin/tokens` | admin | issue a publisher token |
| `PUT` | `/v1/admin/workflows/{slug}/official` | admin | set the badge |
| `PUT` | `/v1/admin/publishers/{github_id}/blocked` | admin | block or unblock |

### Decisions worth knowing

**Liveness and readiness are separate.** `/readyz` touches the database;
`/healthz` does not. A liveness probe that checked Postgres would restart the
pod every time the database was briefly away — during a node drain, say — which
is exactly when restarting helps least.

**Versions are a counter, not semver.** The author presses publish; nobody
wants to choose a number for that. The next value is derived server-side, and
two concurrent publishes resolve through the `UNIQUE (workflow_id, version)`
constraint into a `409`, so the client retries rather than reading a `500`.

**Unlisting and withdrawal are soft.** An unlisted workflow leaves the library
but installs that already took it keep resolving. A withdrawn version is still
served, with `withdrawn: true` set, so a harness holding it is *told* rather
than broken.

**Install counts are records, not a counter.** One row per
`(workflow, installation_id)`, counted with `count(*)`. A stored number cannot
be corrected, cannot be narrowed to installs still alive, and is trivially
inflated by anyone in a loop. `installation_id` is an opaque UUID the harness
generates for itself — not a user, not a hostname.

**A publisher acting on someone else's workflow gets `404`, not `403`.** The
difference would leak which slugs are taken by whom.

**Slugs are validated hard.** Lowercase, digits and single dashes; no dots, no
slashes, no leading, trailing or doubled dashes. The schema notes that a slug
must not shadow a bundled workflow at `.harness/workflows/<name>.yaml`, and
`../` in a slug must never reach a path join. Uppercase is refused rather than
folded, so `Deploy` and `deploy` can never be the same row on one code path and
different rows on another.

**Tokens are SHA-256, not Argon2.** The secret is 32 random bytes, so there is
no dictionary to grind and nothing a slow hash buys — while a KDF would run on
every request and hand anyone a cheap way to saturate the CPU. This is what
GitHub and Stripe do with API tokens, for the same reason. Passwords are a
different problem and would deserve a different answer.

**The admin surface returns `404` when `ADMIN_TOKEN` is unset**, rather than
existing with an empty password, so a deployment that forgets the secret fails
closed.

## Configuration

| Variable | Default | |
|---|---|---|
| `DATABASE_URL` | *required* | in-cluster CNPG connection string |
| `BIND_ADDR` | `0.0.0.0:8080` | |
| `CORS_ALLOW_ORIGINS` | *(none)* | comma-separated; empty means no browser access |
| `ADMIN_TOKEN` | *(none)* | unset disables the admin endpoints |
| `MAX_YAML_BYTES` | `262144` | largest workflow document accepted |
| `RUST_LOG` | `info,harness_registry=debug` | |

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Queries are **runtime-checked** (`sqlx::query`, not `query!`) on purpose. The
macros need a reachable database at compile time or a checked-in `.sqlx` cache,
and the schema is owned by a Kubernetes Job in the home-ops repo rather than by
migrations here. CI must be able to build without a Postgres.

## Releasing

CI builds an image only on a version tag, and only if `fmt`, `clippy` and
`test` passed:

```sh
git tag v0.1.1 && git push origin v0.1.1
```

That pushes `ghcr.io/marknygaard/harness-registry:0.1.1`. The package is
private, so the cluster pulls it with the `ghcr-login-secret` image pull
secret — the same pattern ticket0 already uses. Note that secret is
namespace-local and must exist in whichever namespace runs this.
