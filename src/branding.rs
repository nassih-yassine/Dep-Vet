//! The wordmark, shared by `--help` and the interactive report.

use owo_colors::OwoColorize;

/// The one copy of the wordmark. Edit `assets/banner.txt`; both `--help` and
/// interactive reports read this included text.
pub const LOGO_BLOCKS: &str = include_str!("../assets/banner.txt");

/// Header printed above `--help`. Same source as the banner.
pub const HELP_HEADER: &str = LOGO_BLOCKS;

pub fn banner(color: bool) -> String {
    if color {
        format!("{}", LOGO_BLOCKS.cyan())
    } else {
        LOGO_BLOCKS.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordmark_is_the_trust_protocol() {
        assert!(LOGO_BLOCKS.contains("THE DEPENDENCY TRUST PROTOCOL"));
        assert!(LOGO_BLOCKS.contains("ZERO BLIND TRUST"));
        assert!(LOGO_BLOCKS.lines().count() >= 20);
    }

    #[test]
    fn help_uses_the_same_text_as_the_banner() {
        assert_eq!(HELP_HEADER, LOGO_BLOCKS);
        assert!(!HELP_HEADER.trim().is_empty(), "assets/banner.txt is empty");
    }

    #[test]
    fn banner_color_is_opt_in() {
        assert!(!banner(false).contains('\u{1b}'));
        assert!(banner(true).contains('\u{1b}'));
    }
}
