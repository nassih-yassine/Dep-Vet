//! Shared HTTP layer: one agent, one body limit, one cache policy.
//!
//! Cache policy in three lines: a fresh entry skips the network; a network or
//! server failure falls back to a stale entry; everything else is an error.

use std::sync::Mutex;
use std::time::Duration;

use crate::cache::{Cache, now_seconds};

/// ureq's default is 10 MB, which is smaller than some real npm packuments.
pub const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("HTTP {status} from {url}")]
    Status { status: u16, url: String },
    #[error("network error fetching {url}: {message}")]
    Network { url: String, message: String },
}

impl HttpError {
    /// Server-side problems may be papered over with a stale cache entry;
    /// a 404 must never be, or deleted packages would look alive.
    fn is_transient(&self) -> bool {
        match self {
            Self::Network { .. } => true,
            // 429 is a rate limit: a stale entry beats failing the check.
            Self::Status { status, .. } => *status == 429 || *status >= 500,
        }
    }
}

pub struct HttpClient {
    agent: ureq::Agent,
    /// Mutex so the client stays `Send + Sync` for future parallel fetches.
    cache: Option<Mutex<Cache>>,
}

impl HttpClient {
    pub fn from_env(no_cache: bool) -> Self {
        let cache = if no_cache {
            None
        } else {
            Cache::open_default()
        };
        Self::with_cache(cache)
    }

    pub fn with_cache(cache: Option<Cache>) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .user_agent(concat!("dep-vet/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            cache: cache.map(Mutex::new),
        }
    }

    pub fn get(&self, url: &str) -> Result<String, HttpError> {
        self.cached(url, || self.fetch_get(url))
    }

    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
        let key = format!("POST {url}\n{body}");
        self.cached(&key, || self.fetch_post(url, body))
    }

    fn cached(
        &self,
        key: &str,
        fetch: impl FnOnce() -> Result<String, HttpError>,
    ) -> Result<String, HttpError> {
        let now = now_seconds();
        if let Some(cache) = &self.cache
            && let Ok(cache) = cache.lock()
            && let Ok(Some(body)) = cache.fresh(key, now)
        {
            return Ok(body);
        }

        match fetch() {
            Ok(body) => {
                if let Some(cache) = &self.cache
                    && let Ok(cache) = cache.lock()
                {
                    let _ = cache.put(key, &body, now);
                }
                Ok(body)
            }
            Err(error) => {
                if error.is_transient()
                    && let Some(cache) = &self.cache
                    && let Ok(cache) = cache.lock()
                    && let Ok(Some(body)) = cache.stale(key)
                {
                    return Ok(body);
                }
                Err(error)
            }
        }
    }

    fn fetch_get(&self, url: &str) -> Result<String, HttpError> {
        match self.agent.get(url).call() {
            Ok(mut response) => read_body(&mut response, url),
            Err(ureq::Error::StatusCode(status)) => Err(HttpError::Status {
                status,
                url: url.to_string(),
            }),
            Err(error) => Err(HttpError::Network {
                url: url.to_string(),
                message: error.to_string(),
            }),
        }
    }

    fn fetch_post(&self, url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
        match self.agent.post(url).send_json(body) {
            Ok(mut response) => read_body(&mut response, url),
            Err(ureq::Error::StatusCode(status)) => Err(HttpError::Status {
                status,
                url: url.to_string(),
            }),
            Err(error) => Err(HttpError::Network {
                url: url.to_string(),
                message: error.to_string(),
            }),
        }
    }
}

fn read_body(
    response: &mut ureq::http::Response<ureq::Body>,
    url: &str,
) -> Result<String, HttpError> {
    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(|error| HttpError::Network {
            url: url.to_string(),
            message: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(ttl: i64) -> (tempfile::TempDir, Cache) {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::open(directory.path().join("cache.db"), ttl).unwrap();
        (directory, cache)
    }

    fn network_error() -> HttpError {
        HttpError::Network {
            url: "https://example.test/x".to_string(),
            message: "offline".to_string(),
        }
    }

    #[test]
    fn fresh_cache_entry_skips_the_network() {
        let (_directory, cache) = cache(60);
        cache.put("k", "cached", now_seconds()).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let body = http
            .cached("k", || panic!("network must not be used on a cache hit"))
            .unwrap();
        assert_eq!(body, "cached");
    }

    #[test]
    fn network_failure_falls_back_to_stale_cache() {
        let (_directory, cache) = cache(60);
        cache.put("k", "stale", now_seconds() - 3600).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let body = http.cached("k", || Err(network_error())).unwrap();
        assert_eq!(body, "stale");
    }

    #[test]
    fn server_error_falls_back_to_stale_cache() {
        let (_directory, cache) = cache(60);
        cache.put("k", "stale", now_seconds() - 3600).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let body = http
            .cached("k", || {
                Err(HttpError::Status {
                    status: 503,
                    url: "https://example.test/x".to_string(),
                })
            })
            .unwrap();
        assert_eq!(body, "stale");
    }

    #[test]
    fn rate_limited_falls_back_to_stale_cache() {
        let (_directory, cache) = cache(60);
        cache.put("k", "stale", now_seconds() - 3600).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let body = http
            .cached("k", || {
                Err(HttpError::Status {
                    status: 429,
                    url: "https://example.test/x".to_string(),
                })
            })
            .unwrap();
        assert_eq!(body, "stale");
    }

    #[test]
    fn not_found_does_not_use_a_stale_entry() {
        let (_directory, cache) = cache(60);
        cache.put("k", "stale", now_seconds() - 3600).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let error = http
            .cached("k", || {
                Err(HttpError::Status {
                    status: 404,
                    url: "https://example.test/x".to_string(),
                })
            })
            .unwrap_err();
        assert!(matches!(error, HttpError::Status { status: 404, .. }));
    }

    #[test]
    fn without_cache_every_call_fetches() {
        let http = HttpClient::with_cache(None);
        let body = http.cached("k", || Ok("fresh".to_string())).unwrap();
        assert_eq!(body, "fresh");
    }

    #[test]
    fn successful_fetch_is_written_to_the_cache() {
        let (_directory, cache) = cache(60);
        let http = HttpClient::with_cache(Some(cache));

        let body = http.cached("k", || Ok("network".to_string())).unwrap();
        assert_eq!(body, "network");
        let again = http
            .cached("k", || panic!("second read should be cached"))
            .unwrap();
        assert_eq!(again, "network");
    }

    #[test]
    fn error_without_cache_stays_an_error() {
        let http = HttpClient::with_cache(None);
        let error = http.cached("k", || Err(network_error())).unwrap_err();
        assert!(matches!(error, HttpError::Network { .. }));
    }
}
