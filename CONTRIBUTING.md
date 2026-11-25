# Contributing to dep-vet

Bug reports, false-positive reports, and missing ecosystems are the most useful
contributions. A finding you believe is wrong is worth an issue on its own.

## Before you start

- **Security issue?** Report it privately, per [SECURITY.md](SECURITY.md). Never
  open a public issue for one.
- **Bug?** Include the output of `dep-vet --version`, the exact command, what
  you expected, what happened, and the exit code.
- **New ecosystem, new signal, or a behaviour change?** Open an issue first. It
  changes scope, and a rule that cannot cite evidence does not ship.

## Set up

Rust 1.88 or newer (`rust-version` in `Cargo.toml`). Then:

```sh
git config core.hooksPath .githooks   # once per clone
cargo build
```

The hooks vet staged lockfiles on commit, and run fmt, clippy, tests, plus the
workflow and MCP self-scans on push. Do not use `--no-verify`; fix the failure.

## Checks

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Clippy warnings are errors. CI runs the tests on Linux, macOS, and Windows, so
anything that spawns `sh`, sets Unix permissions, or relies on inotify needs
`#[cfg(unix)]` or `#[cfg(target_os = "linux")]`.

## Tests

Every change ships with tests. For a bug, write the failing test first and
watch it fail.

Tests must not touch the network or the real cache. `tests/cli.rs` starts a
local fake registry and points `DEPVET_REGISTRY_BASE`, `DEPVET_DOWNLOADS_BASE`,
and `DEPVET_OSV_BASE` at it, with `DEPVET_NO_CACHE=1` except in cache tests. A
test that reaches npmjs.org, osv.dev, or `~/.cache/dep-vet` is a bug.

Actively try to break it: malformed registry JSON, future timestamps, path
traversal in specs, huge packuments, closed pipes, missing fields.

## Rules that shape the code

These are not style preferences. A change that breaks one of them will be
declined.

- **Exit codes are a contract.** `0` clean, `1` warnings, `2` high risk, and
  `3` means the check could not run. Never fold `3` into a verdict. Never call
  `Cli::parse()`, which exits `2` on usage errors.
- **Every finding cites a URL.** A rule that cannot link its evidence does not
  ship.
- **No score, and no LLM in a verdict.** Evidence and severity, nothing to hide
  behind.
- **A missing signal is `not checked`, never clean.** Coverage differs per
  registry, and the report has to say so.
- **A failed advisory check is an INFO finding**, not silence and not exit `3`.

## Style

- Keep `signals.rs` pure: `PackageMeta` plus `now` in, findings out.
- Small modules with one job, matching the existing layout.
- No new dependency without a stated reason in the PR, and ledger entries in
  `Cargo.lock` are reviewed like code.
- Update `README.md`, `SECURITY.md`, and `CHANGELOG.md` in the same change that
  moves a limit. A feature is not done while the docs still state an old one.

## Commits and pull requests

- Conventional commit subjects: `feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`, `perf:`, `ci:`.
- One logical change per pull request, with its tests and a `CHANGELOG.md` entry
  under `Unreleased` when behaviour is user-facing.
- Fill in the pull request template: what changed, why, and the commands you ran
  with their result.

By contributing you agree that your contribution is licensed under the
project's MIT license, and that you will follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
