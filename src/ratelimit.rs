//! A per-client fixed-window limiter for the install endpoints.
//!
//! These are the only unauthenticated writes in the service, and since
//! listings are ordered by install count they decide who sits at the top of
//! the library. Without a limit anyone can invent unlimited `installation_id`s
//! and rank their own workflow first, which costs nothing and needs no
//! publisher token — strictly cheaper to game than the recency ordering it
//! replaced.
//!
//! Hand-rolled rather than pulled in, because it is about forty lines and the
//! whole point of the module is to be auditable. Fixed window rather than a
//! token bucket: a burst at a window boundary can reach twice the limit, which
//! is a real weakness and an acceptable one here — the aim is to make sustained
//! inflation expensive, not to police an exact rate.
//!
//! In-memory, so it is per-replica and resets on restart. Also acceptable, and
//! worth being explicit about: this bounds casual abuse, not a distributed
//! adversary. The other half of the defence is that install counts only include
//! recently-seen rows, so anything inflated has to be *maintained* to keep
//! counting.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, HeaderName};

/// Entries are dropped once this many accumulate, oldest window first, so a
/// long-running process cannot be made to grow without bound by cycling source
/// addresses. Well above any plausible legitimate client count.
const MAX_TRACKED: usize = 20_000;

struct Window {
    started: Instant,
    hits: u32,
}

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    seen: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Record a hit for `key`. `false` means the caller is over its limit.
    ///
    /// A poisoned lock fails open rather than rejecting every request: the
    /// limiter protects a counter's integrity, and letting it take the whole
    /// endpoint down would be the more serious failure.
    pub fn check(&self, key: &str) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return true;
        };
        let now = Instant::now();

        if seen.len() >= MAX_TRACKED {
            seen.retain(|_, w| now.duration_since(w.started) < self.window);
            // Still full of live windows: shed rather than grow.
            if seen.len() >= MAX_TRACKED {
                return false;
            }
        }

        match seen.get_mut(key) {
            Some(w) if now.duration_since(w.started) < self.window => {
                w.hits += 1;
                w.hits <= self.limit
            }
            // Absent, or the window has expired and starts again.
            _ => {
                seen.insert(
                    key.to_owned(),
                    Window {
                        started: now,
                        hits: 1,
                    },
                );
                true
            }
        }
    }
}

/// Identify the client for rate-limiting purposes.
///
/// The only route in from outside is the Cloudflare Tunnel, and Cloudflare
/// overwrites `CF-Connecting-IP` on ingress rather than appending to it, so it
/// cannot be spoofed by an external caller. `X-Forwarded-For` is the fallback
/// for a request arriving through the gateway without it, and its *first*
/// entry is the original client.
///
/// A caller already inside the cluster can set either header to anything, and
/// that is fine: in-cluster access is trusted, and the harness in this cluster
/// reaches the service over cluster DNS rather than through the tunnel.
///
/// Nothing derived here is stored. The value lives in memory for the length of
/// one window and never reaches the database, which keeps the schema's
/// intention intact — `installation_id` identifies an installation, not a
/// person or a machine, and an address would undo that.
pub fn client_key(headers: &HeaderMap, socket: Option<IpAddr>) -> String {
    const CF_CONNECTING_IP: HeaderName = HeaderName::from_static("cf-connecting-ip");
    const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

    if let Some(ip) = headers.get(CF_CONNECTING_IP).and_then(|v| v.to_str().ok()) {
        let ip = ip.trim();
        if !ip.is_empty() {
            return ip.to_owned();
        }
    }

    if let Some(chain) = headers.get(X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
        if let Some(first) = chain.split(',').next().map(str::trim) {
            if !first.is_empty() {
                return first.to_owned();
            }
        }
    }

    socket.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caller_within_its_limit_is_allowed() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        for i in 1..=3 {
            assert!(limiter.check("1.2.3.4"), "hit {i} should pass");
        }
    }

    #[test]
    fn the_hit_past_the_limit_is_refused() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(limiter.check("1.2.3.4"));
        }
        assert!(!limiter.check("1.2.3.4"), "the fourth must be refused");
    }

    #[test]
    fn callers_are_counted_separately() {
        // Otherwise one busy client would lock everybody else out, which is a
        // denial of service dressed as a rate limit.
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("1.1.1.1"));
        assert!(!limiter.check("1.1.1.1"));
        assert!(limiter.check("2.2.2.2"), "a different caller is unaffected");
    }

    #[test]
    fn the_window_expires() {
        let limiter = RateLimiter::new(1, Duration::from_millis(1));
        assert!(limiter.check("1.2.3.4"));
        assert!(!limiter.check("1.2.3.4"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check("1.2.3.4"), "a fresh window starts over");
    }

    #[test]
    fn cloudflares_header_wins_over_the_chain() {
        // Cloudflare overwrites CF-Connecting-IP on ingress, so it is the one
        // an external caller cannot forge.
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "9.9.9.9".parse().unwrap());
        headers.insert("x-forwarded-for", "1.1.1.1, 2.2.2.2".parse().unwrap());
        assert_eq!(client_key(&headers, None), "9.9.9.9");
    }

    #[test]
    fn the_forwarded_chain_yields_the_original_client() {
        // First entry, not last: later hops are proxies.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.1.1.1, 2.2.2.2".parse().unwrap());
        assert_eq!(client_key(&headers, None), "1.1.1.1");
    }

    #[test]
    fn the_socket_address_is_the_last_resort() {
        let headers = HeaderMap::new();
        let socket: IpAddr = "10.42.0.1".parse().unwrap();
        assert_eq!(client_key(&headers, Some(socket)), "10.42.0.1");
        assert_eq!(client_key(&headers, None), "unknown");
    }

    #[test]
    fn an_empty_header_does_not_become_the_key() {
        // Otherwise every caller sending a blank header shares one bucket.
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "".parse().unwrap());
        let socket: IpAddr = "10.42.0.1".parse().unwrap();
        assert_eq!(client_key(&headers, Some(socket)), "10.42.0.1");
    }
}
