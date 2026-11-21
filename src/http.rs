//! Shared HTTP layer: one agent, one body limit, one cache policy.
//!
//! Cache policy in three lines: a fresh entry skips the network; a network or
//! server failure falls back to a stale entry; everything else is an error.
//! Transient failures retry with bounded exponential backoff and honour
//! `Retry-After`, because registries rate-limit bursts.

use std::sync::Mutex;
use std::time::Duration;

use crate::cache::{Cache, now_seconds};

/// ureq's default is 10 MB, which is smaller than some real npm packuments.
pub const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("HTTP {status} from {url}")]
    Status {
        status: u16,
        url: String,
        retry_after: Option<u64>,
    },
    #[error("network error fetching {url}: {message}")]
    Network { url: String, message: String },
}

/// Initial attempt plus two retries.
pub const MAX_ATTEMPTS: u32 = 3;
/// Advisories change hourly; a day-old answer is the one staleness that matters.
pub const ADVISORY_TTL_SECONDS: i64 = 300;
const RETRY_BASE_MS: u64 = 150;
const RETRY_CAP_SECONDS: u64 = 5;

impl HttpError {
    fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            Self::Network { .. } => None,
        }
    }

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
            // Statuses are data here: 404, 429, and 5xx carry meaning and
            // headers (Retry-After) that an opaque error would drop.
            .http_status_as_error(false)
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

    /// Raw response for callers that must stream a body (archives). Statuses
    /// are checked here, so a caller still sees `HttpError::Status` on 404.
    pub fn get_raw(&self, url: &str) -> Result<ureq::http::Response<ureq::Body>, HttpError> {
        match self.agent.get(url).call() {
            Ok(response) => {
                let status = response.status().as_u16();
                if (200..300).contains(&status) {
                    Ok(response)
                } else {
                    let retry_after = response
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(parse_retry_after);
                    Err(HttpError::Status {
                        status,
                        url: url.to_string(),
                        retry_after,
                    })
                }
            }
            Err(error) => Err(network_error(error, url)),
        }
    }

    /// True when the URL answers 2xx. Used for cheap existence checks
    /// (provenance endpoints) where the body is irrelevant.
    pub fn head(&self, url: &str) -> Result<bool, HttpError> {
        match self.agent.head(url).call() {
            Ok(response) => Ok((200..300).contains(&response.status().as_u16())),
            Err(error) => Err(network_error(error, url)),
        }
    }

    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
        let key = format!("POST {url}\n{body}");
        self.cached(&key, || self.fetch_post(url, body))
    }

    fn cached(
        &self,
        key: &str,
        mut fetch: impl FnMut() -> Result<String, HttpError>,
    ) -> Result<String, HttpError> {
        let now = now_seconds();
        if let Some(cache) = &self.cache
            && let Ok(cache) = cache.lock()
        {
            let ttl = if is_advisory(key) {
                ADVISORY_TTL_SECONDS
            } else {
                cache.ttl_seconds()
            };
            if let Ok(Some(body)) = cache.fresh_with(key, now, ttl) {
                return Ok(body);
            }
        }

        let mut attempt = 0;
        let result = loop {
            match fetch() {
                Ok(body) => break Ok(body),
                Err(error) if error.is_transient() && attempt + 1 < MAX_ATTEMPTS => {
                    std::thread::sleep(retry_delay(attempt, error.retry_after()));
                    attempt += 1;
                }
                Err(error) => break Err(error),
            }
        };

        match result {
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
            Ok(response) => read_response(response, url),
            Err(error) => Err(network_error(error, url)),
        }
    }

    fn fetch_post(&self, url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
        match self.agent.post(url).send_json(body) {
            Ok(response) => read_response(response, url),
            Err(error) => Err(network_error(error, url)),
        }
    }
}

fn network_error(error: ureq::Error, url: &str) -> HttpError {
    HttpError::Network {
        url: url.to_string(),
        message: error.to_string(),
    }
}

fn read_response(
    mut response: ureq::http::Response<ureq::Body>,
    url: &str,
) -> Result<String, HttpError> {
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after);
        return Err(HttpError::Status {
            status,
            url: url.to_string(),
            retry_after,
        });
    }
    read_body(&mut response, url)
}

fn is_advisory(key: &str) -> bool {
    key.contains("api.osv.dev")
}

fn parse_retry_after(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

/// Bounded exponential backoff. A server-provided Retry-After wins, capped so
/// one registry cannot stall a whole audit.
fn retry_delay(attempt: u32, retry_after: Option<u64>) -> Duration {
    if let Some(seconds) = retry_after {
        return Duration::from_secs(seconds.min(RETRY_CAP_SECONDS));
    }
    let factor = 1_u64 << attempt.min(5);
    let millis = (RETRY_BASE_MS * factor).min(RETRY_CAP_SECONDS * 1000);
    Duration::from_millis(millis)
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
                    retry_after: None,
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
                    retry_after: None,
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
                    retry_after: None,
                })
            })
            .unwrap_err();
        assert!(matches!(error, HttpError::Status { status: 404, .. }));
    }

    #[test]
    fn a_network_error_is_retried_once() {
        let http = HttpClient::with_cache(None);
        let mut attempts = 0;

        let body = http
            .cached("k", || {
                attempts += 1;
                if attempts == 1 {
                    Err(network_error())
                } else {
                    Ok("recovered".to_string())
                }
            })
            .unwrap();

        assert_eq!(body, "recovered");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn a_network_error_retries_up_to_the_cap() {
        let http = HttpClient::with_cache(None);
        let mut attempts = 0;

        let error = http
            .cached("k", || {
                attempts += 1;
                Err(network_error())
            })
            .unwrap_err();

        assert!(matches!(error, HttpError::Network { .. }));
        assert_eq!(attempts, MAX_ATTEMPTS);
    }

    #[test]
    fn not_found_is_not_retried() {
        let http = HttpClient::with_cache(None);
        let mut attempts = 0;

        let _ = http.cached("k", || {
            attempts += 1;
            Err(HttpError::Status {
                status: 404,
                url: "https://example.test/x".to_string(),
                retry_after: None,
            })
        });

        assert_eq!(attempts, 1);
    }

    #[test]
    fn advisories_go_stale_five_minutes_after_fetch() {
        let (_directory, cache) = cache(86_400);
        let http = HttpClient::with_cache(Some(cache));
        let key = "https://api.osv.dev/v1/querybatch";
        let mut calls = 0;

        let first = http
            .cached(key, || {
                calls += 1;
                Ok("live".to_string())
            })
            .unwrap();
        assert_eq!(first, "live");

        {
            let cache = http.cache.as_ref().unwrap().lock().unwrap();
            cache.put(key, "old", now_seconds() - 600).unwrap();
        }
        let again = http
            .cached(key, || {
                calls += 1;
                Ok("refetched".to_string())
            })
            .unwrap();
        assert_eq!(again, "refetched");
        assert_eq!(calls, 2);
    }

    #[test]
    fn metadata_keeps_the_default_ttl() {
        let (_directory, cache) = cache(86_400);
        cache
            .put(
                "https://registry.npmjs.org/x",
                "cached",
                now_seconds() - 600,
            )
            .unwrap();
        let http = HttpClient::with_cache(Some(cache));
        let body = http
            .cached("https://registry.npmjs.org/x", || {
                panic!("metadata should still be fresh")
            })
            .unwrap();
        assert_eq!(body, "cached");
    }

    #[test]
    fn backoff_grows_and_honours_retry_after() {
        assert_eq!(retry_delay(0, None), Duration::from_millis(150));
        assert_eq!(retry_delay(1, None), Duration::from_millis(300));
        assert_eq!(retry_delay(10, None), Duration::from_millis(4800));
        assert_eq!(retry_delay(0, Some(2)), Duration::from_secs(2));
        assert_eq!(retry_delay(0, Some(99)), Duration::from_secs(5));
        assert_eq!(parse_retry_after("3"), Some(3));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
    }

    #[test]
    fn a_successful_retry_is_cached() {
        let (_directory, cache) = cache(60);
        let http = HttpClient::with_cache(Some(cache));
        let mut attempts = 0;

        let body = http
            .cached("k", || {
                attempts += 1;
                if attempts == 1 {
                    Err(network_error())
                } else {
                    Ok("recovered".to_string())
                }
            })
            .unwrap();
        assert_eq!(body, "recovered");

        let again = http
            .cached("k", || panic!("the retried body should be cached"))
            .unwrap();
        assert_eq!(again, "recovered");
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
