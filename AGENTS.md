# dep-vet

Rust CLI that checks an npm package's risk **before** it enters the lockfile.
v0.1 ships `dep-vet npm <name>[@version]` only. `README.md` is the user-facing
doc. `docs/` holds the product brief and design specs but is **gitignored and
not published**: never link to it from README or the wiki, and never `git add -f`
it without asking.

## Working agreements

These override convenience. Do not shortcut them.

1. Feature work happens on its own branch. Merge to `main` automatically once the
   work is complete and `cargo fmt --check`, `cargo clippy --all-targets -- -D
   warnings`, and `cargo test` all pass. Do not open pull requests. Stop and ask
   only when a decision would change scope, or when a green build needs a
   judgement call.
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
cargo test --locked                      # 142 unit + 36 end-to-end tests
cargo test signals::                    # one module
cargo test --test cli fresh_package     # one end-to-end case
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Clippy warnings are errors. Do not commit unformatted code.

A tracked pre-push hook (`.githooks/pre-push`) runs fmt, clippy, and tests.
Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

Do not push with `--no-verify` to get past a failure; fix the failure.

## Layout

| File | Owns |
|------|------|
| `src/model.rs` | `PackageSpec` parsing/validation, `Severity`, `Finding`, `PackageReport` |
| `src/lockfile.rs` | `package-lock.json` v2/v3 parsing, flat diff against a git ref |
| `src/registry.rs` | packument fetch + parsing, download counts, repo URL normalization |
| `src/osv.rs` | advisory IDs from `querybatch`, details per advisory, severity mapping |
| `src/http.rs` | one agent, 64 MB body limit, the cache read/write policy |
| `src/cache.rs` | SQLite cache: TTL, stale fallback, key/value entries |
| `src/signals.rs` | the rules: `PackageMeta` + `now` in, `Vec<Finding>` out (no I/O) |
| `src/typosquat.rs` | Levenshtein, homoglyph folding, curated popular-name seed |
| `src/report.rs` | human rendering and JSON envelope |
| `src/date.rs` | hand-rolled RFC 3339 → epoch (deliberately no date crate) |
| `src/main.rs` | wiring, color decision, exit codes |
| `tests/cli.rs` | real binary against a local fake registry |
| `.github/workflows/ci.yml` | fmt, clippy, tests on push and PR |
| `.github/workflows/dep-vet.yml` | reusable PR workflow: run `lock`, update one sticky comment |

## Traps

- **Exit code 3** means the check could not run. Never fold it into 0/1/2;
  CI depends on the difference (`main.rs`, README).
- **Never call `Cli::parse()`.** clap exits `2` on usage errors, which means
  "high risk" here. `main.rs` uses `try_parse()` and remaps to 3, keeping
  `--help`/`--version` at 0.
- **Tests must not touch the network or the real cache.** `tests/cli.rs` starts
  a `TcpListener` and overrides `DEPVET_REGISTRY_BASE`, `DEPVET_DOWNLOADS_BASE`,
  and `DEPVET_OSV_BASE`, with `DEPVET_NO_CACHE=1` except in cache tests. A test
  that reaches npmjs.org, osv.dev, or `~/.cache/dep-vet` is a bug.
- **The cache policy is deliberate.** Fresh entry skips the network; stale
  entries are used for network errors, 5xx, and 429; a 404 never falls back, or
  deleted packages would look alive. See `HttpError::is_transient`.
- **Cache lifecycle:** entries older than `RETENTION_SECONDS` (30 days) are
  deleted on open, and `PRAGMA user_version` drops the table when the schema
  changes. Never add a column without bumping `SCHEMA_VERSION`.
- **`querybatch` returns advisory IDs only.** Summary, aliases, and severity
  come from `GET /v1/vulns/{id}`. Treating the batch as full records shows
  "advisory without a summary" for every real advisory.
- **Advisory failure is an INFO finding**, not silence and not exit 3. "We
  could not check" must never read as "nothing found".
- **The 25-advisory cap must be disclosed.** `OsvClient::query` returns an
  `AdvisoryList { advisories, hidden }`; `hidden > 0` becomes an INFO finding.
  Never truncate without saying so.
- **`lock` exits 3 when any added package could not be checked**, even if the
  rest is clean. An incomplete audit is not a pass. Per-package failures are
  collected in `LockReport.errors`.
- **`lock` diffs `name@version` pairs**, so a version bump is "new" and gets
  audited. It reads `package-lock.json` v2/v3 only; v1 is rejected instead of
  approximated.
- **Aliases resolve to the real package.** For `"x": "npm:real-pkg@1"`, npm
  keys the path `node_modules/x` but stores `"name": "real-pkg"` in the entry.
  Use `Entry::name` first and fall back to the path segment; auditing the alias
  name 404s and hides the real advisories.
- **`docs/` is local-only.** It is in `.gitignore` on purpose; do not track it,
  link to it from user-facing docs, or delete it from disk.
- **CI uses `--locked`.** Keep it on clippy and test commands, or CI can pass on
  crate versions that are not in `Cargo.lock`.
- **The action's `ref` input is the real pin.** `uses: ...@v1` pins the workflow
  file, not the binary; the install step builds `ref` (tag or branch).
- **PR comments are capped at 60,000 bytes** because GitHub rejects bodies over
  65,536 characters. The full report is printed to the job log as well.
- **Workflow YAML is not covered by `cargo test`.** Validate it with
  `ruby -ryaml -e 'YAML.load_file(...)'`, and exercise the embedded shell with a
  stubbed `gh` and `dep-vet` before pushing. Third-party actions are avoided on
  purpose: this repo should not add supply-chain surface to a supply-chain tool.
- **`lockfile::at_ref` must run git in the lockfile's directory.** A bare
  filename has `parent() == Some("")`, which git rejects; the empty-parent case
  falls back to `.` and has a regression test.
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
- **Branding lives in `src/branding.rs`.** `HELP_HEADER` is a literal copy of
  the logo because `concat!` only takes literals; a test keeps it in sync with
  `LOGO_ASCII`. The banner prints only on a terminal, never in JSON or pipes.

## Not built yet

Release binaries, PyPI/crates.io, tree-wide advisory lookups, and non-npm
lockfiles (yarn, pnpm, bun). Roadmap only: do not describe these as existing in
code, README, or help text.
