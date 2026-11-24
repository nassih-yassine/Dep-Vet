//! Shared HTTP layer: one agent, one body limit, one cache policy.
//!
//! Cache policy in three lines: a fresh entry skips the network; a network or
//! server failure falls back to a stale entry; everything else is an error.
//! Transient failures retry with bounded exponential backoff and honour
//! `Retry-After`, because registries rate-limit bursts.

use std::sync::Mutex;
use std::time::Duration;

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

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
    #[error("outbound URL refused for {url}: {message}")]
    Policy { url: String, message: String },
}

/// Where a response came from. `Stale` is only produced after a transient
/// failure, never for a 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Cached and still inside its TTL.
    Fresh,
    /// Fetched over the network just now.
    Network,
    /// Served from cache because the refresh failed.
    Stale { age_seconds: i64 },
}

/// Advisory answers older than this are refused outright, so a week-old
/// advisory cache cannot masquerade as today's answer.
pub const ADVISORY_MAX_STALE_SECONDS: i64 = 24 * 60 * 60;

/// Initial attempt plus two retries.
pub const MAX_ATTEMPTS: u32 = 3;
/// Advisories change hourly; a day-old answer is the one staleness that matters.
pub const ADVISORY_TTL_SECONDS: i64 = 300;
const RETRY_BASE_MS: u64 = 150;
const RETRY_CAP_SECONDS: u64 = 5;

impl HttpError {
    pub(crate) fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            Self::Network { .. } | Self::Policy { .. } => None,
        }
    }

    /// Server-side problems may be papered over with a stale cache entry;
    /// a 404 must never be, or deleted packages would look alive.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Self::Network { .. } => true,
            // 429 is a rate limit: a stale entry beats failing the check.
            Self::Status { status, .. } => *status == 429 || *status >= 500,
            Self::Policy { .. } => false,
        }
    }
}

pub struct HttpClient {
    agent: ureq::Agent,
    /// Archives use a separate agent with automatic redirects disabled.
    archive_agent: ureq::Agent,
    /// Mutex so the client stays `Send + Sync` for future parallel fetches.
    cache: Option<Mutex<Cache>>,
    /// Set when a `DEPVET_*_BASE` override is present without the gate.
    policy_error: Option<String>,
    /// Configured OSV base, so tests and self-hosted mirrors get the advisory
    /// TTL and stale cap instead of the literal api.osv.dev.
    advisory_base: String,
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
        Self::with_cache_and_base(cache, advisory_base_from_env())
    }

    pub fn with_cache_and_base(cache: Option<Cache>, advisory_base: String) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            // Statuses are data here: 404, 429, and 5xx carry meaning and
            // headers (Retry-After) that an opaque error would drop.
            .http_status_as_error(false)
            .user_agent(concat!("dep-vet/", env!("CARGO_PKG_VERSION")))
            .build();
        let archive_config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(concat!("dep-vet/", env!("CARGO_PKG_VERSION")))
            .build();
        // Both agents use a resolver that filters every DNS answer before the
        // connector sees it, closing the resolve-then-rebind window. Read the
        // override set once; DNS lookups must not re-parse the environment.
        let overrides = crate::netpolicy::Overrides::from_env();
        let agent = ureq::Agent::with_parts(
            config,
            DefaultConnector::new(),
            PublicOnlyResolver {
                overrides: overrides.clone(),
            },
        );
        let archive_agent = ureq::Agent::with_parts(
            archive_config,
            DefaultConnector::new(),
            PublicOnlyResolver { overrides },
        );
        let policy_error = crate::netpolicy::check_overrides_env()
            .err()
            .map(|error| error.to_string());
        Self {
            agent,
            archive_agent,
            cache: cache.map(Mutex::new),
            policy_error,
            advisory_base,
        }
    }

    fn guard(&self) -> Result<(), HttpError> {
        match &self.policy_error {
            Some(message) => Err(HttpError::Policy {
                url: "(configuration)".to_string(),
                message: message.clone(),
            }),
            None => Ok(()),
        }
    }

    pub fn get(&self, url: &str) -> Result<String, HttpError> {
        self.get_with_source(url).map(|(body, _)| body)
    }

    /// Validate and fetch a URL that registry data selected (archives,
    /// provenance), following at most three redirects with validation on
    /// every hop.
    pub fn get_trusted(
        &self,
        ecosystem: crate::model::Ecosystem,
        url: &str,
    ) -> Result<String, HttpError> {
        self.guard()?;
        let mut response = self.get_raw(ecosystem, url)?;
        read_body(&mut response, url)
    }

    pub fn head_trusted(
        &self,
        ecosystem: crate::model::Ecosystem,
        url: &str,
    ) -> Result<bool, HttpError> {
        self.guard()?;
        let mut current =
            crate::netpolicy::validate_archive_url(ecosystem, url, None).map_err(|error| {
                HttpError::Policy {
                    url: url.to_string(),
                    message: error.to_string(),
                }
            })?;
        let mut redirects = 0;
        loop {
            let response = match self.archive_agent.head(current.as_str()).call() {
                Ok(response) => response,
                Err(error) => return Err(network_error(error, current.as_str())),
            };
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                if redirects >= 3 {
                    return Err(HttpError::Policy {
                        url: current.to_string(),
                        message: "more than 3 redirects".to_string(),
                    });
                }
                let Some(location) = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                else {
                    return Err(status_error(response, current.as_str()));
                };
                let next =
                    redirect_target(&current, location).map_err(|message| HttpError::Policy {
                        url: current.to_string(),
                        message,
                    })?;
                current = crate::netpolicy::validate_archive_url(ecosystem, next.as_str(), None)
                    .map_err(|error| HttpError::Policy {
                        url: next.to_string(),
                        message: error.to_string(),
                    })?;
                redirects += 1;
                continue;
            }
            return Ok((200..300).contains(&status));
        }
    }

    /// Advisory detail fetches also need the source, so stale bodies can be
    /// disclosed rather than silently blended with fresh ones.
    pub fn get_with_source(&self, url: &str) -> Result<(String, Source), HttpError> {
        self.guard()?;
        self.cached(url, || self.fetch_get(url))
    }

    /// Fetch with a caller-chosen TTL instead of the cache-wide one. Used for
    /// questions where a day-old answer is wrong, such as "what is the latest
    /// release".
    pub fn get_with_ttl(&self, url: &str, ttl_seconds: i64) -> Result<String, HttpError> {
        self.guard()?;
        self.cached_with_ttl(url, Some(ttl_seconds), || self.fetch_get(url))
            .map(|(body, _)| body)
    }

    /// Raw response for callers that must stream a body (archives). Statuses
    /// are checked here, so a caller still sees `HttpError::Status` on 404.
    pub fn get_raw(
        &self,
        ecosystem: crate::model::Ecosystem,
        url: &str,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpError> {
        self.get_raw_with_origin(ecosystem, url, None)
    }

    pub fn get_raw_with_origin(
        &self,
        ecosystem: crate::model::Ecosystem,
        url: &str,
        composer_origin: Option<&crate::netpolicy::ComposerOrigin>,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpError> {
        self.guard()?;
        let mut current = crate::netpolicy::validate_archive_url(ecosystem, url, composer_origin)
            .map_err(|error| HttpError::Policy {
            url: url.to_string(),
            message: error.to_string(),
        })?;
        let mut redirects = 0;
        loop {
            let response = match self.archive_agent.get(current.as_str()).call() {
                Ok(response) => response,
                Err(error) => return Err(network_error(error, current.as_str())),
            };
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                if redirects >= 3 {
                    return Err(HttpError::Policy {
                        url: current.to_string(),
                        message: "more than 3 redirects".to_string(),
                    });
                }
                let Some(location) = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                else {
                    return Err(status_error(response, current.as_str()));
                };
                let next =
                    redirect_target(&current, location).map_err(|message| HttpError::Policy {
                        url: current.to_string(),
                        message,
                    })?;
                current = crate::netpolicy::validate_archive_url(
                    ecosystem,
                    next.as_str(),
                    composer_origin,
                )
                .map_err(|error| HttpError::Policy {
                    url: next.to_string(),
                    message: error.to_string(),
                })?;
                redirects += 1;
                continue;
            }
            if (200..300).contains(&status) {
                return Ok(response);
            }
            return Err(status_error(response, current.as_str()));
        }
    }

    /// True when the URL answers 2xx. Used for cheap existence checks
    /// (provenance endpoints) where the body is irrelevant.
    pub fn head(&self, url: &str) -> Result<bool, HttpError> {
        self.guard()?;
        match self.agent.head(url).call() {
            Ok(response) => Ok((200..300).contains(&response.status().as_u16())),
            Err(error) => Err(network_error(error, url)),
        }
    }

    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
        self.post_json_with_source(url, body).map(|(body, _)| body)
    }

    /// Advisories need the source to disclose stale data.
    pub fn post_json_with_source(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<(String, Source), HttpError> {
        self.guard()?;
        let key = format!("POST {url}\n{body}");
        self.cached(&key, || self.fetch_post(url, body))
    }

    fn cached(
        &self,
        key: &str,
        fetch: impl FnMut() -> Result<String, HttpError>,
    ) -> Result<(String, Source), HttpError> {
        self.cached_with_ttl(key, None, fetch)
    }

    fn cached_with_ttl(
        &self,
        key: &str,
        ttl_override: Option<i64>,
        mut fetch: impl FnMut() -> Result<String, HttpError>,
    ) -> Result<(String, Source), HttpError> {
        let now = now_seconds();
        let advisory = self.is_advisory(key);
        if let Some(cache) = &self.cache
            && let Ok(cache) = cache.lock()
        {
            let ttl = ttl_override.unwrap_or(if advisory {
                ADVISORY_TTL_SECONDS
            } else {
                cache.ttl_seconds()
            });
            if let Ok(Some(body)) = cache.fresh_with(key, now, ttl) {
                return Ok((body, Source::Fresh));
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
                Ok((body, Source::Network))
            }
            Err(error) => {
                if error.is_transient()
                    && let Some(cache) = &self.cache
                    && let Ok(cache) = cache.lock()
                    && let Ok(Some((body, age_seconds))) = cache.stale_with_age(key, now)
                {
                    if advisory && age_seconds > ADVISORY_MAX_STALE_SECONDS {
                        return Err(error);
                    }
                    return Ok((body, Source::Stale { age_seconds }));
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

/// Resolve a redirect target and enforce the no-downgrade rule before the
/// URL policy sees it. Relative locations are resolved against the current URL.
pub(crate) fn redirect_target(current: &url::Url, location: &str) -> Result<url::Url, String> {
    let next = current
        .join(location)
        .map_err(|error| format!("invalid redirect location: {error}"))?;
    if current.scheme() == "https" && next.scheme() != "https" {
        return Err("redirect would downgrade https to http".to_string());
    }
    Ok(next)
}

fn status_error(response: ureq::http::Response<ureq::Body>, url: &str) -> HttpError {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after);
    HttpError::Status {
        status,
        url: url.to_string(),
        retry_after,
    }
}

#[derive(Debug, Clone)]
struct PublicOnlyResolver {
    overrides: crate::netpolicy::Overrides,
}

impl Resolver for PublicOnlyResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addresses = DefaultResolver::default().resolve(uri, config, timeout)?;
        let host = uri
            .host()
            .ok_or_else(|| ureq::Error::BadUri("URL has no host".to_string()))?;
        let port = uri
            .port_u16()
            .or_else(|| match uri.scheme_str() {
                Some("https") => Some(443),
                Some("http") => Some(80),
                _ => None,
            })
            .ok_or_else(|| ureq::Error::BadUri("URL has no port".to_string()))?;
        let filtered = crate::netpolicy::filter_resolved_addresses(
            host,
            port,
            addresses.iter().map(|address| address.ip()),
            &self.overrides,
        )
        .map_err(|error| {
            ureq::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                error.to_string(),
            ))
        })?;
        let mut out = self.empty();
        for address in filtered {
            out.push(address);
        }
        Ok(out)
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

fn advisory_base_from_env() -> String {
    std::env::var("DEPVET_OSV_BASE").unwrap_or_else(|_| "https://api.osv.dev".to_string())
}

impl HttpClient {
    fn is_advisory(&self, key: &str) -> bool {
        key.contains(self.advisory_base.trim_end_matches('/'))
    }
}

fn parse_retry_after(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

/// Bounded exponential backoff. A server-provided Retry-After wins, capped so
/// one registry cannot stall a whole audit.
/// Same policy, with jitter so parallel clients do not retry in lockstep.
pub(crate) fn retry_delay_jittered(attempt: u32, retry_after: Option<u64>) -> Duration {
    let base = retry_delay(attempt, retry_after);
    let jitter = u64::from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos() % 100)
            .unwrap_or(0),
    );
    base + Duration::from_millis(jitter)
}

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
    fn redirects_cannot_downgrade_https_or_escape_relative_locations() {
        let current = url::Url::parse("https://registry.npmjs.org/lib.tgz").unwrap();
        assert!(redirect_target(&current, "http://registry.npmjs.org/lib.tgz").is_err());
        assert_eq!(
            redirect_target(&current, "/other.tgz").unwrap().as_str(),
            "https://registry.npmjs.org/other.tgz"
        );
        assert_eq!(
            redirect_target(&current, "../x.tgz").unwrap().as_str(),
            "https://registry.npmjs.org/x.tgz"
        );
    }

    #[test]
    fn fresh_cache_entry_skips_the_network() {
        let (_directory, cache) = cache(60);
        cache.put("k", "cached", now_seconds()).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let body = http
            .cached("k", || panic!("network must not be used on a cache hit"))
            .unwrap();
        assert_eq!(body.0, "cached");
        assert_eq!(body.1, Source::Fresh);
    }

    #[test]
    fn network_failure_falls_back_to_stale_cache() {
        let (_directory, cache) = cache(60);
        cache.put("k", "stale", now_seconds() - 3600).unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let (body, source) = http.cached("k", || Err(network_error())).unwrap();
        assert_eq!(body, "stale");
        assert!(matches!(source, Source::Stale { .. }));
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
        assert_eq!(body.0, "stale");
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
        assert_eq!(body.0, "stale");
    }

    fn advisory_key() -> &'static str {
        "POST https://api.osv.dev/v1/querybatch\n{\"queries\":[]}"
    }

    #[test]
    fn detail_gets_report_their_source_too() {
        let (_directory, cache) = cache(60);
        cache.put("k", "cached", now_seconds()).unwrap();
        let http = HttpClient::with_cache(Some(cache));
        let (body, source) = http.get_with_source("k").unwrap();
        assert_eq!(body, "cached");
        assert_eq!(source, Source::Fresh);
    }

    #[test]
    fn a_two_hour_old_advisory_is_served_and_labelled_stale() {
        let (_directory, cache) = cache(60);
        cache
            .put(advisory_key(), "old-advisories", now_seconds() - 2 * 3600)
            .unwrap();
        let http = HttpClient::with_cache(Some(cache));

        let (body, source) = http
            .cached(advisory_key(), || Err(network_error()))
            .unwrap();
        assert_eq!(body, "old-advisories");
        match source {
            Source::Stale { age_seconds } => {
                assert!((7100..=7300).contains(&age_seconds), "{age_seconds}")
            }
            other => panic!("expected stale, got {other:?}"),
        }
    }

    #[test]
    fn a_three_day_old_advisory_is_refused() {
        let (_directory, cache) = cache(60);
        cache
            .put(advisory_key(), "ancient", now_seconds() - 3 * 24 * 3600)
            .unwrap();
        let http = HttpClient::with_cache(Some(cache));

        assert!(
            http.cached(advisory_key(), || Err(network_error()))
                .is_err()
        );
    }

    #[test]
    fn a_configured_osv_base_gets_the_advisory_policy() {
        let (_first, store) = cache(60);
        let key = "POST https://osv.test/v1/querybatch\n{}";
        store
            .put(key, "ancient", now_seconds() - 25 * 3600)
            .unwrap();
        let http = HttpClient::with_cache_and_base(Some(store), "https://osv.test".to_string());

        // Past 24h the advisory stale cap applies: refused, not served.
        assert!(http.cached(key, || Err(network_error())).is_err());

        // Six minutes old is past the five-minute advisory TTL: the network is
        // consulted even though the general TTL would still consider it fresh.
        let (_second, store) = cache(3600);
        store.put(key, "cached", now_seconds() - 360).unwrap();
        let http = HttpClient::with_cache_and_base(Some(store), "https://osv.test".to_string());
        let (body, source) = http.cached(key, || Ok("network".to_string())).unwrap();
        assert_eq!(body, "network");
        assert_eq!(source, Source::Network);
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

        assert_eq!(body.0, "recovered");
        assert_eq!(body.1, Source::Network);
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
        assert_eq!(first.0, "live");
        assert_eq!(first.1, Source::Network);

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
        assert_eq!(again.0, "refetched");
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
        assert_eq!(body.0, "cached");
        assert_eq!(body.1, Source::Fresh);
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
        assert_eq!(body.0, "recovered");

        let again = http
            .cached("k", || panic!("the retried body should be cached"))
            .unwrap();
        assert_eq!(again.0, "recovered");
    }

    #[test]
    fn without_cache_every_call_fetches() {
        let http = HttpClient::with_cache(None);
        let body = http.cached("k", || Ok("fresh".to_string())).unwrap();
        assert_eq!(body.0, "fresh");
        assert_eq!(body.1, Source::Network);
    }

    #[test]
    fn successful_fetch_is_written_to_the_cache() {
        let (_directory, cache) = cache(60);
        let http = HttpClient::with_cache(Some(cache));

        let body = http.cached("k", || Ok("network".to_string())).unwrap();
        assert_eq!(body.0, "network");
        let again = http
            .cached("k", || panic!("second read should be cached"))
            .unwrap();
        assert_eq!(again.0, "network");
    }

    #[test]
    fn error_without_cache_stays_an_error() {
        let http = HttpClient::with_cache(None);
        let error = http.cached("k", || Err(network_error())).unwrap_err();
        assert!(matches!(error, HttpError::Network { .. }));
    }
}
