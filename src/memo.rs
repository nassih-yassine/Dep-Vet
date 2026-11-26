//! One lookup per key, shared by every worker that asks at the same moment.
//!
//! A tree repeats the same repository dozens of times (monorepos pin many
//! packages from one repo). The HTTP cache already answers the second request
//! from disk, but with several workers the second request is issued *before*
//! the first one finishes, so a plain map still sends one request per worker.
//! A `OnceLock` per key makes the first caller do the work and the others wait
//! for its answer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Keyed, single-flight, process-lifetime memo.
pub struct LookupMemo<T> {
    slots: Mutex<HashMap<String, Arc<OnceLock<Option<T>>>>>,
}

impl<T: Clone> Default for LookupMemo<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> LookupMemo<T> {
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the memoised value for `key`, calling `lookup` at most once for
    /// concurrent callers. A miss is memoised too: "no scorecard" is an answer,
    /// and re-asking deps.dev for every package of an unscored repository is
    /// the traffic this type exists to avoid.
    pub fn get_or_lookup(&self, key: &str, lookup: impl FnOnce() -> Option<T>) -> Option<T> {
        let slot = {
            let mut slots = self
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(slots.entry(key.to_string()).or_default())
        };
        // `get_or_init` is the single-flight primitive: concurrent callers
        // block until the first one finishes instead of every one issuing the
        // request and racing to store the same answer.
        slot.get_or_init(lookup).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn concurrent_callers_share_one_lookup() {
        let memo: LookupMemo<u32> = LookupMemo::new();
        let calls = AtomicUsize::new(0);
        let barrier = Barrier::new(8);

        let results: Vec<Option<u32>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let memo = &memo;
                    let calls = &calls;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        memo.get_or_lookup("github.com/a/b", || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(30));
                            Some(7)
                        })
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the lookup ran more than once"
        );
        assert!(results.iter().all(|value| *value == Some(7)));
    }

    #[test]
    fn a_second_call_reuses_the_first_answer() {
        let memo: LookupMemo<String> = LookupMemo::new();
        let calls = AtomicUsize::new(0);
        let first = memo.get_or_lookup("k", || {
            calls.fetch_add(1, Ordering::SeqCst);
            Some("v".to_string())
        });
        let second = memo.get_or_lookup("k", || {
            calls.fetch_add(1, Ordering::SeqCst);
            Some("other".to_string())
        });
        assert_eq!(first.as_deref(), Some("v"));
        assert_eq!(second.as_deref(), Some("v"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn distinct_keys_are_looked_up_separately() {
        let memo: LookupMemo<u32> = LookupMemo::new();
        assert_eq!(memo.get_or_lookup("a", || Some(1)), Some(1));
        assert_eq!(memo.get_or_lookup("b", || Some(2)), Some(2));
    }

    #[test]
    fn a_missing_answer_is_remembered_too() {
        let memo: LookupMemo<u32> = LookupMemo::new();
        let calls = AtomicUsize::new(0);
        let miss = memo.get_or_lookup("none", || {
            calls.fetch_add(1, Ordering::SeqCst);
            None
        });
        let again = memo.get_or_lookup("none", || {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(9)
        });
        assert_eq!(miss, None);
        assert_eq!(again, None, "a memoised miss must not become a hit");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
