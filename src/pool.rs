//! A fixed-size worker pool for per-package work.
//!
//! The old shape was `chunks(4)`: each batch waited for its slowest package
//! before the next one started, so a run of mostly-fast packages with one
//! slow fetch left three workers idle. Here every worker pulls the next index
//! as soon as it finishes.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

/// Runs `work(0..count)` on at most `jobs` threads.
///
/// Results come back by index, never in completion order, so the report keeps
/// the lockfile's order. A panicking item yields `None` for that index and
/// does not take the other items down; `on_done` runs once per finished item
/// on the calling thread, which keeps the progress bar single-threaded.
pub fn run<R, F>(count: usize, jobs: usize, work: F, mut on_done: impl FnMut()) -> Vec<Option<R>>
where
    R: Send,
    F: Fn(usize) -> R + Sync,
{
    if count == 0 {
        return Vec::new();
    }
    let workers = jobs.clamp(1, count);
    let next = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let next = &next;
            let work = &work;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    let outcome = catch_unwind(AssertUnwindSafe(|| work(index))).ok();
                    if sender.send((index, outcome)).is_err() {
                        break;
                    }
                }
            });
        }
        // Drop the original so `receiver` closes once every worker is done.
        drop(sender);

        let mut slots: Vec<Option<R>> = (0..count).map(|_| None).collect();
        for (index, outcome) in receiver.iter() {
            slots[index] = outcome;
            on_done();
        }
        slots
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn results_come_back_in_index_order_whatever_finishes_first() {
        let results = run(
            6,
            3,
            |index| {
                // Later indices finish first, so completion order is reversed.
                std::thread::sleep(std::time::Duration::from_millis((6 - index) as u64));
                index * 10
            },
            || {},
        );
        assert_eq!(
            results,
            (0..6).map(|index| Some(index * 10)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_index_runs_exactly_once() {
        let seen: Vec<AtomicUsize> = (0..10).map(|_| AtomicUsize::new(0)).collect();
        let seen_ref = &seen;
        let results = run(
            10,
            4,
            |index| {
                seen_ref[index].fetch_add(1, Ordering::SeqCst);
                index
            },
            || {},
        );
        assert_eq!(
            seen.iter()
                .map(|slot| slot.load(Ordering::SeqCst))
                .collect::<Vec<_>>(),
            vec![1; 10]
        );
        assert!(results.iter().all(Option::is_some));
    }

    #[test]
    fn one_worker_still_does_everything() {
        let results = run(5, 1, |index| index, || {});
        assert_eq!(results, (0..5).map(Some).collect::<Vec<_>>());
    }

    #[test]
    fn more_workers_than_items_is_fine() {
        let results = run(2, 32, |index| index, || {});
        assert_eq!(results, vec![Some(0), Some(1)]);
    }

    #[test]
    fn a_panicking_item_becomes_none_without_stopping_the_rest() {
        let results = run(
            5,
            2,
            |index| {
                assert_ne!(index, 3, "this item explodes");
                index
            },
            || {},
        );
        assert_eq!(results[3], None);
        assert_eq!(results[0], Some(0));
        assert_eq!(results[4], Some(4));
    }

    #[test]
    fn the_callback_runs_once_per_item_on_the_calling_thread() {
        let mut done = 0;
        let results = run(7, 3, |index| index, || done += 1);
        assert_eq!(results.len(), 7);
        assert_eq!(done, 7);
    }

    #[test]
    fn an_empty_run_does_nothing() {
        let results: Vec<Option<u8>> = run(0, 8, |_| 1, || panic!("no callback"));
        assert!(results.is_empty());
    }
}
