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

    /// Ignore the nearest package-lock.json when checking one package
    #[arg(long, global = true)]
    pub no_local: bool,
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

    /// Vet a PyPI package before adding it
    Pypi {
        /// Package name with optional exact version: requests==2.31.0
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Vet a crates.io crate before adding it
    Crates {
        /// Crate name with optional exact version: serde@1.0.229
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Vet a Go module before adding it
    Go {
        /// Module path with optional version: github.com/gin-gonic/gin@v1.9.1
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Audit every package installed by a lockfile
    Audit {
        /// Path to package-lock.json
        lockfile: std::path::PathBuf,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Audit every dependency a lockfile change adds
    Lock {
        /// Path to package-lock.json
        lockfile: std::path::PathBuf,

        /// Git revision to compare against
        #[arg(long, default_value = "main")]
        base: String,

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
            _ => panic!("expected npm command"),
        }
        assert!(!cli.no_color);
    }

    #[test]
    fn parses_json_flag() {
        let cli = Cli::try_parse_from(["dep-vet", "npm", "express", "--json"]).unwrap();
        match cli.command {
            Command::Npm { json, .. } => assert!(json),
            _ => panic!("expected npm command"),
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
    fn parses_pypi_command() {
        let cli = Cli::try_parse_from(["dep-vet", "pypi", "requests==2.31.0"]).unwrap();
        match cli.command {
            Command::Pypi { package, json } => {
                assert_eq!(package, "requests==2.31.0");
                assert!(!json);
            }
            _ => panic!("expected pypi command"),
        }
    }

    #[test]
    fn parses_audit_command() {
        let cli = Cli::try_parse_from(["dep-vet", "audit", "package-lock.json"]).unwrap();
        match cli.command {
            Command::Audit { lockfile, json } => {
                assert_eq!(lockfile, std::path::PathBuf::from("package-lock.json"));
                assert!(!json);
            }
            _ => panic!("expected audit command"),
        }
    }

    #[test]
    fn parses_go_command() {
        let cli =
            Cli::try_parse_from(["dep-vet", "go", "github.com/gin-gonic/gin@v1.9.1"]).unwrap();
        match cli.command {
            Command::Go { package, json } => {
                assert_eq!(package, "github.com/gin-gonic/gin@v1.9.1");
                assert!(!json);
            }
            _ => panic!("expected go command"),
        }
    }

    #[test]
    fn parses_crates_command() {
        let cli = Cli::try_parse_from(["dep-vet", "crates", "serde@1.0.229"]).unwrap();
        match cli.command {
            Command::Crates { package, json } => {
                assert_eq!(package, "serde@1.0.229");
                assert!(!json);
            }
            _ => panic!("expected crates command"),
        }
    }

    #[test]
    fn parses_lock_command() {
        let cli = Cli::try_parse_from(["dep-vet", "lock", "package-lock.json"]).unwrap();
        match cli.command {
            Command::Lock {
                lockfile,
                base,
                json,
            } => {
                assert_eq!(lockfile, std::path::PathBuf::from("package-lock.json"));
                assert_eq!(base, "main");
                assert!(!json);
            }
            _ => panic!("expected lock command"),
        }
    }

    #[test]
    fn lock_base_and_json_can_be_overridden() {
        let cli = Cli::try_parse_from([
            "dep-vet",
            "lock",
            "package-lock.json",
            "--base",
            "origin/main",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Lock { base, json, .. } => {
                assert_eq!(base, "origin/main");
                assert!(json);
            }
            _ => panic!("expected lock command"),
        }
    }

    #[test]
    fn no_local_is_global() {
        let cli = Cli::try_parse_from(["dep-vet", "npm", "express", "--no-local"]).unwrap();
        assert!(cli.no_local);
        assert!(!cli.no_cache);
    }

    #[test]
    fn requires_a_subcommand() {
        assert!(Cli::try_parse_from(["dep-vet"]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommands() {
        assert!(Cli::try_parse_from(["dep-vet", "maven", "org.example:thing"]).is_err());
    }

    #[test]
    fn rejects_unknown_flags() {
        assert!(Cli::try_parse_from(["dep-vet", "npm", "express", "--pretty"]).is_err());
    }
}
