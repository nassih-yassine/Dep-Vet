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

    /// Path to a .depvet.toml allowlist (default: nearest, walking up)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    /// Allow DEPVET_*_BASE overrides (development only)
    #[arg(long, global = true)]
    pub dev_registry: bool,

    /// Lowest severity that fails the run (audit, lock, and single-package checks; default: warn)
    #[arg(long, global = true, value_enum)]
    pub fail_on: Option<FailOn>,
}

/// The severity threshold behind `--fail-on`. `warn` is the historical
/// behaviour: 0 clean, 1 warnings, 2 high risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FailOn {
    Info,
    Warn,
    High,
}

impl FailOn {
    pub fn threshold(self) -> crate::model::Severity {
        match self {
            Self::Info => crate::model::Severity::Info,
            Self::Warn => crate::model::Severity::Warn,
            Self::High => crate::model::Severity::High,
        }
    }
}

/// Report serialization. `--json` remains an alias for `--format json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

/// SBOM serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SbomFormat {
    Cyclonedx,
    Spdx,
}

#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Serve a Claude Code PreToolUse hook on stdin
    Claude {
        /// Deny warnings and unchecked installs instead of asking/allowing
        #[arg(long)]
        strict: bool,
    },

    /// Merge the hook into Claude settings
    Install {
        /// Hook target (claude)
        target: String,

        /// Project settings: .claude/settings.json
        #[arg(long)]
        project: bool,

        /// User settings: ~/.claude/settings.json
        #[arg(long)]
        user: bool,

        /// Deny warnings and unchecked installs
        #[arg(long)]
        strict: bool,

        /// Actually write; without this only the diff is printed
        #[arg(long)]
        write: bool,
    },

    /// Remove the hook from Claude settings
    Uninstall {
        /// Hook target (claude)
        target: String,

        /// Project settings: .claude/settings.json
        #[arg(long)]
        project: bool,

        /// User settings: ~/.claude/settings.json
        #[arg(long)]
        user: bool,

        /// Actually write; without this only the diff is printed
        #[arg(long)]
        write: bool,
    },
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

    /// AI agent hooks
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Serve the Model Context Protocol over stdio
    Mcp {
        /// Print a ready .mcp.json snippet and the `claude mcp add` line
        #[arg(long)]
        print_config: bool,
    },

    /// Vet the packages an install command would fetch
    Guard {
        /// Audit the packages (otherwise only parse the command)
        #[arg(long)]
        check: bool,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,

        /// Read the command from stdin instead of argv
        #[arg(long)]
        stdin: bool,

        /// The command to inspect, after `--`
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Audit every package installed by a lockfile
    Audit {
        /// Path to package-lock.json
        lockfile: std::path::PathBuf,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,

        /// Report format (--json is an alias for --format json)
        #[arg(long, value_enum, conflicts_with = "json")]
        format: Option<OutputFormat>,

        /// Write the report to a file instead of stdout
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },

    /// Resolve a dependency tree without installing it
    Plan {
        /// Ecosystem: npm or maven
        ecosystem: String,

        /// Package with optional version or range (express@5), or a pom.xml path
        package: String,

        /// Print machine-readable JSON instead of a human tree
        #[arg(long)]
        json: bool,
    },

    /// Write a CycloneDX or SPDX inventory from a lockfile
    Sbom {
        /// Lockfile to read (default: nearest package-lock.json)
        lockfile: Option<std::path::PathBuf>,

        /// SBOM format
        #[arg(long, value_enum, default_value = "cyclonedx")]
        format: SbomFormat,

        /// Write the SBOM to a file instead of stdout
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },

    /// Re-audit a lockfile every time it changes on disk
    Watch {
        /// Lockfile to watch (default: nearest package-lock.json)
        lockfile: Option<std::path::PathBuf>,
    },

    /// Show the dependency graph a lockfile already resolved
    Tree {
        /// Lockfile to read (default: nearest package-lock.json)
        lockfile: Option<std::path::PathBuf>,

        /// Print machine-readable JSON instead of a human tree
        #[arg(long)]
        json: bool,
    },

    /// Vet a JSR package before adding it
    Jsr {
        /// Scoped package with optional exact version: @std/assert@1.0.19
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Vet a RubyGems gem before adding it
    Gem {
        /// Gem name with optional exact version: rack@3.2.9
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Vet a NuGet package before adding it
    Nuget {
        /// Package id with optional exact version: Newtonsoft.Json@13.0.3
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Vet a Maven artifact before adding it
    Maven {
        /// group:artifact with optional exact version: org.slf4j:slf4j-api@2.0.17
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Vet a Composer package before adding it
    Composer {
        /// vendor/package with optional exact version: monolog/monolog@3.13.0
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Scan MCP server configs without starting the servers
    McpConfig {
        /// Config file or directory (default: the known names in this directory)
        path: Option<std::path::PathBuf>,

        /// Also scan the per-user Claude, Cursor, Windsurf, VS Code, and Cline configs
        #[arg(long)]
        user: bool,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Scan GitHub Actions workflows for supply-chain risks
    Workflows {
        /// Workflow file or directory (default: .github/workflows)
        path: Option<std::path::PathBuf>,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Inspect a release archive without installing it
    Inspect {
        /// Ecosystem: npm, pypi, crates, go, jsr, gem, nuget, maven, composer
        ecosystem: String,

        /// Package with optional exact version: lodash@4.17.20
        package: String,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Report the latest release and how to update this install
    Update {
        /// Exit 1 when a newer release exists, 0 when current, 3 on failure
        #[arg(long)]
        check: bool,

        /// Print machine-readable JSON instead of a human report
        #[arg(long)]
        json: bool,
    },

    /// Compare two releases of the same package by archive contents
    Diff {
        /// Ecosystem: npm, pypi, crates, go, jsr, gem, nuget, maven, composer
        ecosystem: String,

        /// Older release, with an exact version
        from: String,

        /// Newer release, with an exact version
        to: String,

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

impl Cli {
    /// `--fail-on` resolved against its default. `None` in the parsed struct is
    /// what lets an explicit `--fail-on warn` be told apart from no flag.
    pub fn fail_threshold(&self) -> crate::model::Severity {
        self.fail_on.unwrap_or(FailOn::Warn).threshold()
    }

    /// The commands whose exit code comes from findings. Everything else owns
    /// its exit code (`guard` has the hook contract, `update` means "newer",
    /// `plan`/`tree`/`sbom` report structure), so `--fail-on` is rejected
    /// instead of silently ignored.
    pub fn honours_fail_on(&self) -> bool {
        matches!(
            &self.command,
            Command::Audit { .. }
                | Command::Lock { .. }
                | Command::Npm { .. }
                | Command::Pypi { .. }
                | Command::Crates { .. }
                | Command::Go { .. }
                | Command::Jsr { .. }
                | Command::Gem { .. }
                | Command::Nuget { .. }
                | Command::Maven { .. }
                | Command::Composer { .. }
        )
    }

    /// True when this invocation prints a human report a hint may follow.
    /// Machine formats, hooks, MCP, watch and update are excluded.
    pub fn human_report(&self) -> bool {
        match &self.command {
            Command::Npm { json, .. }
            | Command::Pypi { json, .. }
            | Command::Crates { json, .. }
            | Command::Go { json, .. }
            | Command::Plan { json, .. }
            | Command::Tree { json, .. }
            | Command::Jsr { json, .. }
            | Command::Gem { json, .. }
            | Command::Nuget { json, .. }
            | Command::Maven { json, .. }
            | Command::Composer { json, .. }
            | Command::Workflows { json, .. }
            | Command::McpConfig { json, .. }
            | Command::Inspect { json, .. }
            | Command::Diff { json, .. }
            | Command::Lock { json, .. } => !*json,
            Command::Audit {
                json,
                format,
                output,
                ..
            } => !*json && format.is_none() && output.is_none(),
            Command::Hook { .. }
            | Command::Mcp { .. }
            | Command::Guard { .. }
            | Command::Sbom { .. }
            | Command::Watch { .. }
            | Command::Update { .. } => false,
        }
    }
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
    fn parses_diff_command() {
        let cli =
            Cli::try_parse_from(["dep-vet", "diff", "npm", "lodash@4.17.20", "lodash@4.17.21"])
                .unwrap();
        match cli.command {
            Command::Diff {
                ecosystem,
                from,
                to,
                json,
            } => {
                assert_eq!(ecosystem, "npm");
                assert_eq!(from, "lodash@4.17.20");
                assert_eq!(to, "lodash@4.17.21");
                assert!(!json);
            }
            _ => panic!("expected diff command"),
        }
    }

    #[test]
    fn parses_inspect_command() {
        let cli = Cli::try_parse_from(["dep-vet", "inspect", "npm", "lodash@4.17.20"]).unwrap();
        match cli.command {
            Command::Inspect {
                ecosystem,
                package,
                json,
            } => {
                assert_eq!(ecosystem, "npm");
                assert_eq!(package, "lodash@4.17.20");
                assert!(!json);
            }
            _ => panic!("expected inspect command"),
        }
    }

    #[test]
    fn parses_composer_command() {
        let cli = Cli::try_parse_from(["dep-vet", "composer", "monolog/monolog@3.13.0"]).unwrap();
        match cli.command {
            Command::Composer { package, json } => {
                assert_eq!(package, "monolog/monolog@3.13.0");
                assert!(!json);
            }
            _ => panic!("expected composer command"),
        }
    }

    #[test]
    fn parses_maven_command() {
        let cli = Cli::try_parse_from(["dep-vet", "maven", "org.slf4j:slf4j-api@2.0.17"]).unwrap();
        match cli.command {
            Command::Maven { package, json } => {
                assert_eq!(package, "org.slf4j:slf4j-api@2.0.17");
                assert!(!json);
            }
            _ => panic!("expected maven command"),
        }
    }

    #[test]
    fn parses_nuget_command() {
        let cli = Cli::try_parse_from(["dep-vet", "nuget", "Newtonsoft.Json@13.0.3"]).unwrap();
        match cli.command {
            Command::Nuget { package, json } => {
                assert_eq!(package, "Newtonsoft.Json@13.0.3");
                assert!(!json);
            }
            _ => panic!("expected nuget command"),
        }
    }

    #[test]
    fn parses_gem_command() {
        let cli = Cli::try_parse_from(["dep-vet", "gem", "rack@3.2.9"]).unwrap();
        match cli.command {
            Command::Gem { package, json } => {
                assert_eq!(package, "rack@3.2.9");
                assert!(!json);
            }
            _ => panic!("expected gem command"),
        }
    }

    #[test]
    fn parses_jsr_command() {
        let cli = Cli::try_parse_from(["dep-vet", "jsr", "@std/assert@1.0.19"]).unwrap();
        match cli.command {
            Command::Jsr { package, json } => {
                assert_eq!(package, "@std/assert@1.0.19");
                assert!(!json);
            }
            _ => panic!("expected jsr command"),
        }
    }

    #[test]
    fn parses_watch_command() {
        let cli = Cli::try_parse_from(["dep-vet", "watch", "Cargo.lock"]).unwrap();
        match cli.command {
            Command::Watch { lockfile } => {
                assert_eq!(lockfile, Some(std::path::PathBuf::from("Cargo.lock")));
            }
            _ => panic!("expected watch command"),
        }
        let cli = Cli::try_parse_from(["dep-vet", "watch"]).unwrap();
        assert!(matches!(cli.command, Command::Watch { lockfile: None }));
    }

    #[test]
    fn parses_audit_command() {
        let cli = Cli::try_parse_from(["dep-vet", "audit", "package-lock.json"]).unwrap();
        match cli.command {
            Command::Audit {
                lockfile,
                json,
                format,
                output,
            } => {
                assert_eq!(lockfile, std::path::PathBuf::from("package-lock.json"));
                assert!(!json);
                assert!(format.is_none());
                assert!(output.is_none());
            }
            _ => panic!("expected audit command"),
        }
    }

    #[test]
    fn parses_plan_command() {
        let cli = Cli::try_parse_from(["dep-vet", "plan", "npm", "express@^5"]).unwrap();
        match cli.command {
            Command::Plan {
                ecosystem,
                package,
                json,
            } => {
                assert_eq!(ecosystem, "npm");
                assert_eq!(package, "express@^5");
                assert!(!json);
            }
            _ => panic!("expected plan command"),
        }
    }

    #[test]
    fn parses_sbom_command() {
        let cli = Cli::try_parse_from(["dep-vet", "sbom", "package-lock.json"]).unwrap();
        match cli.command {
            Command::Sbom {
                lockfile,
                format,
                output,
            } => {
                assert_eq!(
                    lockfile,
                    Some(std::path::PathBuf::from("package-lock.json"))
                );
                assert_eq!(format, SbomFormat::Cyclonedx);
                assert!(output.is_none());
            }
            _ => panic!("expected sbom command"),
        }
        let cli =
            Cli::try_parse_from(["dep-vet", "sbom", "--format", "spdx", "-o", "bom.json"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Sbom {
                format: SbomFormat::Spdx,
                output: Some(_),
                ..
            }
        ));
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
    fn config_path_is_global() {
        let cli = Cli::try_parse_from(["dep-vet", "npm", "express", "--config", "x.toml"]).unwrap();
        assert_eq!(cli.config, Some(std::path::PathBuf::from("x.toml")));
    }

    #[test]
    fn requires_a_subcommand() {
        assert!(Cli::try_parse_from(["dep-vet"]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommands() {
        assert!(Cli::try_parse_from(["dep-vet", "sbt", "com.example:thing"]).is_err());
    }

    #[test]
    fn rejects_unknown_flags() {
        assert!(Cli::try_parse_from(["dep-vet", "npm", "express", "--pretty"]).is_err());
    }
}
