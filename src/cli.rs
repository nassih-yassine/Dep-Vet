//! Command-line surface. Kept separate from `main` so it can be parsed in
//! tests without launching a binary.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "dep-vet",
    version,
    about = "Check a package's risk before it enters your lockfile",
    before_help = crate::branding::HELP_HEADER,
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Never emit ANSI colors
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Bypass the on-disk HTTP cache
    #[arg(long, global = true)]
    pub no_cache: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Vet an npm package before adding it
    Npm {
        /// Package name with optional exact version or dist-tag: express@5.1.0
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_command() {
        let cli = Cli::try_parse_from(["dep-vet", "npm", "express@5.1.0"]).unwrap();
        match cli.command {
            Command::Npm { package, json } => {
                assert_eq!(package, "express@5.1.0");
                assert!(!json);
            }
        }
        assert!(!cli.no_color);
    }

    #[test]
    fn parses_json_flag() {
        let cli = Cli::try_parse_from(["dep-vet", "npm", "express", "--json"]).unwrap();
        match cli.command {
            Command::Npm { json, .. } => assert!(json),
        }
    }

    #[test]
    fn no_color_is_global() {
        let cli = Cli::try_parse_from(["dep-vet", "--no-color", "npm", "express"]).unwrap();
        assert!(cli.no_color);
    }

    #[test]
    fn no_cache_is_global() {
        let cli = Cli::try_parse_from(["dep-vet", "npm", "express", "--no-cache"]).unwrap();
        assert!(cli.no_cache);
        assert!(!cli.no_color);
    }

    #[test]
    fn requires_a_subcommand() {
        assert!(Cli::try_parse_from(["dep-vet"]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommands() {
        assert!(Cli::try_parse_from(["dep-vet", "pypi", "requests"]).is_err());
    }

    #[test]
    fn rejects_unknown_flags() {
        assert!(Cli::try_parse_from(["dep-vet", "npm", "express", "--pretty"]).is_err());
    }
}
