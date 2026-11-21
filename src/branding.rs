//! The wordmark, shared by `--help` and the interactive report.

use owo_colors::OwoColorize;

/// ASCII-only, for terminals that mangle box glyphs.
pub const LOGO_ASCII: &str = r#"    #                                 #
    #                                ###
 ####  ###  ####        #   #  ###    #
#   # #   # #   #  ###  #   # #   #   #
#   # ##### ####        #   # #####   #
#   # #     #            # #  #       #
 ####  ###  #             #    ###    ##"#;

pub const LOGO_BLOCKS: &str = r#"    █                                 █
    █                                ███
 ████  ███  ████        █   █  ███    █
█   █ █   █ █   █  ███  █   █ █   █   █
█   █ █████ ████        █   █ █████   █
█   █ █     █            █ █  █       █
 ████  ███  █             █    ███    ██"#;

pub const TAGLINE: &str = "dependency risk, checked before install";

/// Header printed above `--help`. Kept as a literal because `concat!` only
/// accepts literals; `help_header_matches_the_logo` guards against drift.
pub const HELP_HEADER: &str = r#"    #                                 #
    #                                ###
 ####  ###  ####        #   #  ###    #
#   # #   # #   #  ###  #   # #   #   #
#   # ##### ####        #   # #####   #
#   # #     #            # #  #       #
 ####  ###  #             #    ###    ##

dependency risk, checked before install"#;

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

    fn width(logo: &str) -> usize {
        logo.lines().map(|line| line.chars().count()).max().unwrap()
    }

    #[test]
    fn logo_lines_up() {
        for logo in [LOGO_ASCII, LOGO_BLOCKS] {
            assert_eq!(logo.lines().count(), 7);
            assert!(width(logo) <= 41, "logo is too wide: {}", width(logo));
        }
    }

    #[test]
    fn ascii_logo_stays_ascii() {
        assert!(LOGO_ASCII.is_ascii());
    }

    #[test]
    fn help_header_matches_the_logo() {
        assert_eq!(HELP_HEADER, format!("{LOGO_ASCII}\n\n{TAGLINE}"));
    }

    #[test]
    fn banner_color_is_opt_in() {
        assert!(!banner(false).contains('\u{1b}'));
        assert!(banner(true).contains('\u{1b}'));
    }
}
