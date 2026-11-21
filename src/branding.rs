//! The wordmark, shared by `--help` and the interactive report.

use owo_colors::OwoColorize;

pub const LOGO_BLOCKS: &str = r#"██████╗ ███████╗██████╗       ██╗   ██╗███████╗████████╗
██╔══██╗██╔════╝██╔══██╗      ██║   ██║██╔════╝╚══██╔══╝
██║  ██║█████╗  ██████╔╝█████╗██║   ██║█████╗     ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════╝╚██╗ ██╔╝██╔══╝     ██║
██████╔╝███████╗██║             ╚████╔╝ ███████╗   ██║
╚═════╝ ╚══════╝╚═╝              ╚═══╝  ╚══════╝   ╚═╝

        ┌────────────────────────────────────────────────┐
        │                                                │
        │       THE DEPENDENCY TRUST PROTOCOL             │
        │                                                │
        │   ◈  INSPECT       Dependency intelligence     │
        │   ◈  ANALYZE       Malicious code detection    │
        │   ◈  VERIFY        Publisher provenance        │
        │   ◈  DIFF          Release behavior changes    │
        │   ◈  ENFORCE       Supply-chain security       │
        │                                                │
        └────────────────────────────────────────────────┘

        ZERO BLIND TRUST. FULL SUPPLY-CHAIN VISIBILITY.

        [ SYSTEM READY ]  [ RUST POWERED ]  [ SECURITY FIRST ]"#;

/// Header printed above `--help`. Kept as a literal because `concat!` only
/// accepts literals; `help_header_matches_the_logo` guards against drift.
pub const HELP_HEADER: &str = r#"██████╗ ███████╗██████╗       ██╗   ██╗███████╗████████╗
██╔══██╗██╔════╝██╔══██╗      ██║   ██║██╔════╝╚══██╔══╝
██║  ██║█████╗  ██████╔╝█████╗██║   ██║█████╗     ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════╝╚██╗ ██╔╝██╔══╝     ██║
██████╔╝███████╗██║             ╚████╔╝ ███████╗   ██║
╚═════╝ ╚══════╝╚═╝              ╚═══╝  ╚══════╝   ╚═╝

        ┌────────────────────────────────────────────────┐
        │                                                │
        │       THE DEPENDENCY TRUST PROTOCOL             │
        │                                                │
        │   ◈  INSPECT       Dependency intelligence     │
        │   ◈  ANALYZE       Malicious code detection    │
        │   ◈  VERIFY        Publisher provenance        │
        │   ◈  DIFF          Release behavior changes    │
        │   ◈  ENFORCE       Supply-chain security       │
        │                                                │
        └────────────────────────────────────────────────┘

        ZERO BLIND TRUST. FULL SUPPLY-CHAIN VISIBILITY.

        [ SYSTEM READY ]  [ RUST POWERED ]  [ SECURITY FIRST ]"#;

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
    fn help_header_matches_the_logo() {
        assert_eq!(HELP_HEADER, LOGO_BLOCKS);
    }

    #[test]
    fn banner_color_is_opt_in() {
        assert!(!banner(false).contains('\u{1b}'));
        assert!(banner(true).contains('\u{1b}'));
    }
}
