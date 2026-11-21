//! On-disk HTTP cache. Fresh entries skip the network; stale entries are the
//! fallback when the network fails, so a warmed cache works offline.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};

pub const DEFAULT_TTL_SECONDS: i64 = 24 * 60 * 60;

pub struct Cache {
    connection: Connection,
    ttl_seconds: i64,
}

impl Cache {
    /// `None` when caching is disabled or the cache directory is unusable.
    /// A broken cache must never break the check.
    pub fn open_default() -> Option<Self> {
        if std::env::var_os("DEPVET_NO_CACHE").is_some_and(|value| !value.is_empty()) {
            return None;
        }
        let directory = cache_directory()?;
        std::fs::create_dir_all(&directory).ok()?;
        Self::open(directory.join("http-cache.db"), ttl_from_env()).ok()
    }

    pub fn open(path: impl AsRef<Path>, ttl_seconds: i64) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS http_cache (
                key        TEXT PRIMARY KEY,
                body       TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )",
            (),
        )?;
        Ok(Self {
            connection,
            ttl_seconds,
        })
    }

    /// Entry that is still inside the TTL.
    pub fn fresh(&self, key: &str, now: i64) -> rusqlite::Result<Option<String>> {
        let entry: Option<(String, i64)> = self
            .connection
            .query_row(
                "SELECT body, fetched_at FROM http_cache WHERE key = ?1",
                (key,),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(entry
            .filter(|(_, fetched_at)| now.saturating_sub(*fetched_at) < self.ttl_seconds)
            .map(|(body, _)| body))
    }

    /// Entry regardless of age, for network-failure fallback.
    pub fn stale(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT body FROM http_cache WHERE key = ?1",
                (key,),
                |row| row.get(0),
            )
            .optional()
    }

    pub fn put(&self, key: &str, body: &str, now: i64) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO http_cache (key, body, fetched_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET body = excluded.body, fetched_at = excluded.fetched_at",
            (key, body, now),
        )?;
        Ok(())
    }
}

fn cache_directory() -> Option<PathBuf> {
    if let Some(directory) = std::env::var_os("DEPVET_CACHE_DIR") {
        return Some(PathBuf::from(directory));
    }
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("dep-vet"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").join("dep-vet"))
}

fn ttl_from_env() -> i64 {
    std::env::var("DEPVET_CACHE_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|seconds| *seconds >= 0)
        .unwrap_or(DEFAULT_TTL_SECONDS)
}

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> (tempfile::TempDir, Cache) {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::open(directory.path().join("cache.db"), 60).unwrap();
        (directory, cache)
    }

    #[test]
    fn missing_key_is_none() {
        let (_directory, cache) = cache();
        assert_eq!(cache.fresh("nope", 1000).unwrap(), None);
        assert_eq!(cache.stale("nope").unwrap(), None);
    }

    #[test]
    fn fresh_entry_is_returned_within_ttl() {
        let (_directory, cache) = cache();
        cache.put("k", "body", 1000).unwrap();
        assert_eq!(cache.fresh("k", 1059).unwrap().as_deref(), Some("body"));
    }

    #[test]
    fn entry_expires_at_ttl_boundary() {
        let (_directory, cache) = cache();
        cache.put("k", "body", 1000).unwrap();
        assert_eq!(cache.fresh("k", 1060).unwrap(), None);
        assert_eq!(cache.stale("k").unwrap().as_deref(), Some("body"));
    }

    #[test]
    fn put_overwrites_the_same_key() {
        let (_directory, cache) = cache();
        cache.put("k", "old", 1000).unwrap();
        cache.put("k", "new", 2000).unwrap();
        assert_eq!(cache.fresh("k", 2000).unwrap().as_deref(), Some("new"));
    }

    #[test]
    fn keys_are_independent() {
        let (_directory, cache) = cache();
        cache.put("a", "one", 1000).unwrap();
        cache.put("b", "two", 1000).unwrap();
        assert_eq!(cache.fresh("a", 1000).unwrap().as_deref(), Some("one"));
        assert_eq!(cache.fresh("b", 1000).unwrap().as_deref(), Some("two"));
    }

    #[test]
    fn survives_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        {
            let cache = Cache::open(&path, 60).unwrap();
            cache.put("k", "body", 1000).unwrap();
        }
        let cache = Cache::open(&path, 60).unwrap();
        assert_eq!(cache.fresh("k", 1000).unwrap().as_deref(), Some("body"));
    }

    #[test]
    fn zero_ttl_never_serves_fresh_entries() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::open(directory.path().join("cache.db"), 0).unwrap();
        cache.put("k", "body", 1000).unwrap();
        assert_eq!(cache.fresh("k", 1000).unwrap(), None);
        assert_eq!(cache.stale("k").unwrap().as_deref(), Some("body"));
    }
}
