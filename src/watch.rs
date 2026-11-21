//! File watching for the `watch` command.
//!
//! Only the lockfile itself matters here. Editors often write a file several
//! times in a row, so events are debounced before each rerun.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{RecursiveMode, Watcher};

const DEBOUNCE: Duration = Duration::from_millis(300);

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("could not watch {path}: {source}")]
    Notify {
        path: String,
        #[source]
        source: notify::Error,
    },
    #[error("the file watcher stopped")]
    Disconnected,
}

/// Registers the watcher, runs `on_start`, then runs `on_change` once per
/// settled change to `target`. Blocking forever; the watcher is live before
/// `on_start` runs, so an edit during the first report is not missed.
pub fn watch(
    target: &Path,
    on_start: impl FnOnce(),
    mut on_change: impl FnMut(),
) -> Result<(), WatchError> {
    let target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    let parent = target.parent().unwrap_or_else(|| Path::new("."));

    let (sender, receiver) = std::sync::mpsc::channel();
    let mut watcher =
        notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
            if let Ok(event) = event {
                let _ = sender.send(event);
            }
        })
        .map_err(|source| WatchError::Notify {
            path: target.display().to_string(),
            source,
        })?;
    watcher
        .watch(parent, RecursiveMode::NonRecursive)
        .map_err(|source| WatchError::Notify {
            path: parent.display().to_string(),
            source,
        })?;

    on_start();

    loop {
        let event = receiver.recv().map_err(|_| WatchError::Disconnected)?;
        if !is_target(&event, &target) {
            continue;
        }
        // Swallow the burst that editors produce.
        while receiver.recv_timeout(DEBOUNCE).is_ok() {}
        on_change();
    }
}

/// True when the event touches the watched file, not a sibling in its folder.
pub fn is_target(event: &notify::Event, target: &Path) -> bool {
    event.paths.iter().any(|path| same_file(path, target))
}

fn same_file(candidate: &Path, target: &Path) -> bool {
    if candidate == target {
        return true;
    }
    let candidate_name = candidate.file_name();
    let target_name = target.file_name();
    if candidate_name != target_name {
        return false;
    }
    match (candidate.parent(), target.parent()) {
        (Some(candidate_parent), Some(target_parent)) => {
            let canonical = candidate_parent
                .canonicalize()
                .unwrap_or_else(|_| candidate_parent.to_path_buf());
            let expected = target_parent
                .canonicalize()
                .unwrap_or_else(|_| target_parent.to_path_buf());
            canonical == expected
        }
        _ => false,
    }
}

/// Exposed for tests that need to turn a path into the form events use.
pub fn absolute(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(paths: &[&Path]) -> notify::Event {
        notify::Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Any),
            paths: paths.iter().map(|path| path.to_path_buf()).collect(),
            attrs: notify::event::EventAttributes::default(),
        }
    }

    #[test]
    fn accepts_the_watched_file() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("package-lock.json");
        std::fs::write(&target, "{}").unwrap();
        assert!(is_target(&event(&[&target]), &absolute(&target)));
    }

    #[test]
    fn ignores_siblings_in_the_same_folder() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("package-lock.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::write(directory.path().join("package.json"), "{}").unwrap();
        let sibling = directory.path().join("package.json");
        assert!(!is_target(&event(&[&sibling]), &absolute(&target)));
    }

    #[test]
    fn ignores_files_with_the_same_name_elsewhere() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("package-lock.json");
        std::fs::write(&target, "{}").unwrap();
        let other_folder = directory.path().join("nested");
        std::fs::create_dir(&other_folder).unwrap();
        let other = other_folder.join("package-lock.json");
        std::fs::write(&other, "{}").unwrap();
        assert!(!is_target(&event(&[&other]), &absolute(&target)));
    }
}
