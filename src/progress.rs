//! One line of feedback for a tree audit. stderr and a terminal only: stdout
//! belongs to the report, and CI logs do not want carriage returns.

use std::io::Write;

/// The line for `done` of `total`. Pure so the wording is testable without a
/// terminal.
pub fn line(done: usize, total: usize) -> String {
    format!("  auditing {done}/{total} packages…")
}

pub struct Progress {
    total: usize,
    done: usize,
    enabled: bool,
}

impl Progress {
    pub fn new(total: usize, enabled: bool) -> Self {
        let progress = Self {
            total,
            done: 0,
            // An empty list finishes before it starts; drawing "0/0" is noise.
            enabled: enabled && total > 0,
        };
        progress.render();
        progress
    }

    /// Count one finished package and repaint. Repainting is a no-op when
    /// disabled, but the count keeps moving so tests can assert it.
    pub fn advance(&mut self) {
        self.done = (self.done + 1).min(self.total);
        self.render();
    }

    #[cfg(test)]
    fn done(&self) -> usize {
        self.done
    }

    #[cfg(test)]
    fn visible(&self) -> bool {
        self.enabled
    }

    fn render(&self) {
        if !self.enabled {
            return;
        }
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\r{}", line(self.done, self.total));
        let _ = stderr.flush();
    }

    /// Erase the line so the report starts on a clean terminal.
    pub fn clear(&self) {
        if !self.enabled {
            return;
        }
        let width = line(self.done, self.total).chars().count() + 1;
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\r{}\r", " ".repeat(width));
        let _ = stderr.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_advances_and_stops_at_the_total() {
        let mut progress = Progress::new(2, false);
        assert_eq!(progress.done(), 0);
        progress.advance();
        assert_eq!(progress.done(), 1);
        progress.advance();
        progress.advance();
        assert_eq!(progress.done(), 2, "never past the total");
    }

    #[test]
    fn an_empty_audit_draws_nothing() {
        let progress = Progress::new(0, true);
        assert!(!progress.visible());
    }

    #[test]
    fn formats_the_count() {
        assert_eq!(line(0, 245), "  auditing 0/245 packages…");
        assert_eq!(line(1, 1), "  auditing 1/1 packages…");
        assert_eq!(line(245, 245), "  auditing 245/245 packages…");
    }
}
