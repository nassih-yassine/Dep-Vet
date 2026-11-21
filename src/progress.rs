//! One line of feedback for a tree audit. stderr and a terminal only: stdout
//! belongs to the report, and CI logs do not want carriage returns.

use std::io::Write;

const BAR_WIDTH: usize = 20;

/// The line for `done` of `total`. Pure so the wording is testable without a
/// terminal. Blocks are single-width, and `TERM=dumb` never reaches here.
pub fn line(done: usize, total: usize) -> String {
    let filled = (done.min(total) * BAR_WIDTH)
        .checked_div(total)
        .unwrap_or(0);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(BAR_WIDTH - filled));
    format!("  auditing [{bar}] {done}/{total}")
}

/// Whether a run should draw. A terminal is not enough: CI runners often
/// allocate a pseudo-TTY, and `TERM=dumb` means the terminal cannot take it.
pub fn should_draw(is_terminal: bool, ci: bool, term_dumb: bool) -> bool {
    is_terminal && !ci && !term_dumb
}

pub struct Progress {
    total: usize,
    done: usize,
    enabled: bool,
}

impl Drop for Progress {
    fn drop(&mut self) {
        // A panic or Ctrl-C must not leave half a line in the terminal.
        self.clear();
    }
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
        let _ = self.render_to(&mut stderr);
        let _ = stderr.flush();
    }

    pub(crate) fn render_to(&self, writer: &mut impl Write) -> std::io::Result<()> {
        write!(writer, "\r{}", line(self.done, self.total))
    }

    /// Erase the line so the report starts on a clean terminal.
    pub fn clear(&self) {
        if !self.enabled {
            return;
        }
        let mut stderr = std::io::stderr();
        let _ = self.clear_to(&mut stderr);
        let _ = stderr.flush();
    }

    pub(crate) fn clear_to(&self, writer: &mut impl Write) -> std::io::Result<()> {
        let width = line(self.done, self.total).chars().count() + 1;
        write!(writer, "\r{}\r", " ".repeat(width))
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
    fn ci_runners_and_dumb_terminals_do_not_draw() {
        assert!(should_draw(true, false, false));
        assert!(!should_draw(false, false, false));
        assert!(!should_draw(true, true, false), "CI with a pty");
        assert!(!should_draw(true, false, true), "TERM=dumb");
    }

    #[test]
    fn render_and_clear_produce_exact_bytes() {
        let progress = Progress::new(2, true);
        let mut buffer = Vec::new();
        progress.render_to(&mut buffer).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "\r  auditing [░░░░░░░░░░░░░░░░░░░░] 0/2"
        );

        let mut erased = Vec::new();
        progress.clear_to(&mut erased).unwrap();
        let text = String::from_utf8(erased).unwrap();
        assert!(text.starts_with('\r'), "{text:?}");
        assert!(text.ends_with('\r'), "{text:?}");
        assert!(text.trim_matches(['\r', ' ']).is_empty(), "{text:?}");
    }

    #[test]
    fn formats_the_bar_and_count() {
        assert_eq!(line(0, 4), "  auditing [░░░░░░░░░░░░░░░░░░░░] 0/4");
        assert_eq!(line(2, 4), "  auditing [██████████░░░░░░░░░░] 2/4");
        assert_eq!(line(1, 1), "  auditing [████████████████████] 1/1");
        assert_eq!(line(245, 245), "  auditing [████████████████████] 245/245");
        assert_eq!(line(0, 0), "  auditing [░░░░░░░░░░░░░░░░░░░░] 0/0");
    }
}
