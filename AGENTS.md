# dep-vet

Rust CLI that checks an npm package's risk **before** it enters the lockfile.
v0.1 ships `dep-vet npm <name>[@version]` only. `README.md` is the user-facing
doc; `docs/brief.md` is the product rationale and evidence.

## Working agreements

These override convenience. Do not shortcut them.

1. Feature work happens on its own branch, and merges only after approval.
2. Every change ships with tests. Actively try to break the app: malformed
   registry JSON, future timestamps, path traversal in specs, huge packuments,
   closed pipes, missing fields.
3. Bug found → write the failing test first, watch it fail, then fix. See
   `ci_publishers_are_not_maintainer_mismatches` in `src/signals.rs` for the
   shape of a regression test.
4. Before writing code against a crate, fetch its docs with Context7. The ureq
   3 API and the 10 MB default body limit both came from docs, not memory.
5. Every finding must cite evidence with a URL. A rule that cannot be linked
   does not ship, and no LLM belongs in a verdict.

## Commands

```sh
cargo test                              # 84 unit + 13 end-to-end tests
cargo test signals::                    # one module
cargo test --test cli fresh_package     # one end-to-end case
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Clippy warnings are errors. Do not commit unformatted code.

## Layout

| File | Owns |
|------|------|
| `src/model.rs` | `PackageSpec` parsing/validation, `Severity`, `Finding`, `PackageReport` |
| `src/registry.rs` | packument fetch + parsing, download counts, repo URL normalization |
| `src/signals.rs` | the rules: `PackageMeta` + `now` in, `Vec<Finding>` out (no I/O) |
| `src/typosquat.rs` | Levenshtein, homoglyph folding, curated popular-name seed |
| `src/report.rs` | human rendering and JSON envelope |
| `src/date.rs` | hand-rolled RFC 3339 → epoch (deliberately no date crate) |
| `src/main.rs` | wiring, color decision, exit codes |
| `tests/cli.rs` | real binary against a local fake registry |

## Traps

- **Exit code 3** means the check could not run. Never fold it into 0/1/2;
  CI depends on the difference (`main.rs`, README).
- **Tests must not touch the network.** `tests/cli.rs` starts a `TcpListener`
  and overrides `DEPVET_REGISTRY_BASE` / `DEPVET_DOWNLOADS_BASE`. A test that
  reaches npmjs.org is a bug.
- **ureq caps bodies at 10 MB.** `registry.rs` raises the limit to 64 MB; the
  `aws-sdk` packument proves why. Removing it silently truncates large packages.
- **Automation publishers** (`GitHub Actions`, `[bot]` accounts) are not
  maintainer handoffs. They must not raise `publisher-not-maintainer`.
- **Publisher is not a maintainer history.** `_npmUser` is one version's
  publisher; the maintainer list is current. The signal is a proxy, so word it
  as one and never claim ownership changed.
- **Typosquat list is a seed**, not a download ranking. Never source candidates
  from npm's search endpoint. Names under 4 chars are intentionally skipped.
- **`signals.rs` stays pure.** Time enters as `now: i64` (Unix seconds) so
  freshness rules are deterministic in tests.

## Not built yet

`dep-vet lock`, OSV advisories, caching, the GitHub Action, PyPI/crates.io.
Roadmap only: do not describe these as existing in code, README, or help text.
