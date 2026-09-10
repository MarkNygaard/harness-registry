//! Configuration, read once at startup.

use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: String,
    /// Origins allowed to call the read endpoints from a browser. The site is
    /// a static export served from Vercel, so its origin is not the API's.
    pub cors_origins: Vec<String>,
    /// Grants the admin endpoints. Unset disables them entirely rather than
    /// leaving them open, so a deployment that forgets the secret fails
    /// closed.
    pub admin_token: Option<String>,
    /// Largest workflow document accepted, in bytes.
    pub max_yaml_bytes: usize,
    /// Install writes allowed per client per window. Generous: a harness
    /// records one install per workflow it takes, so a legitimate client is
    /// nowhere near this, while inflating a count to the top of the library
    /// becomes something that has to be sustained rather than done once.
    pub install_rate_limit: u32,
    pub install_rate_window_secs: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("{0} is required")]
pub struct MissingVar(&'static str);

impl Config {
    pub fn from_env() -> Result<Self, MissingVar> {
        Ok(Self {
            database_url: env::var("DATABASE_URL").map_err(|_| MissingVar("DATABASE_URL"))?,
            bind: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            cors_origins: env::var("CORS_ALLOW_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            admin_token: env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty()),
            max_yaml_bytes: env::var("MAX_YAML_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256 * 1024),
            install_rate_limit: env::var("INSTALL_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            install_rate_window_secs: env::var("INSTALL_RATE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        })
    }
}
