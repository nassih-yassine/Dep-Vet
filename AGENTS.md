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
3. Keep `README.md` and the GitHub repository About description in sync with
   what ships. A feature is not done until both describe it: update the About
   with `gh repo edit ... --description` in the same pass as the README.
4. Bug found → write the failing test first, watch it fail, then fix. See
   `ci_publishers_are_not_maintainer_mismatches` in `src/signals.rs` for the
   shape of a regression test.
5. Before writing code against a crate, fetch its docs with Context7. The ureq
   3 API and the 10 MB default body limit both came from docs, not memory.
6. Every finding must cite evidence with a URL. A rule that cannot be linked
   does not ship, and no LLM belongs in a verdict.

## Commands

```sh
cargo test --locked                      # 244 unit + 78 end-to-end tests
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
| `src/allowlist.rs` | `.depvet.toml` parsing, validation, finding downgrades |
| `src/lockfile.rs` | npm/PyPI/Cargo/Go lockfile parsing, flat diff against a git ref |
| `src/registry.rs` | npm packument fetch + parsing, download counts, repo URL normalization |
| `src/pypi.rs` | PyPI JSON API, version resolution, sdist-only detection, yanked releases |
| `src/crates.rs` | crates.io API, owner list, publisher, yanked releases |
| `src/go.rs` | deps.dev Go module index, versions, publish times, deprecation |
| `src/osv.rs` | advisory IDs from `querybatch`, details per advisory, severity mapping |
| `src/http.rs` | one agent, 64 MB body limit, the cache read/write policy |
| `src/cache.rs` | SQLite cache: TTL, stale fallback, key/value entries |
| `src/signals.rs` | the rules: `PackageMeta` + `now` in, `Vec<Finding>` out (no I/O) |
| `src/typosquat.rs` | Levenshtein, homoglyph folding, per-ecosystem candidate lists |
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
- **Ecosystem drives seeds and honesty.** npm uses `typosquat::POPULAR`, PyPI
  uses `POPULAR_PYPI`, and `Profile::PYPI` disables maintainers and downloads so
  they show as `not checked`. The `PackageSource` trait is still deferred: two
  sources share only `PackageMeta` and the auditor, which is not yet enough
  duplication to justify it.
- **Go can check almost nothing structural.** No install hooks, owner list,
  downloads, or repository in the module index: `Profile::GO` disables all four
  and the report says `not checked`. Go advisories still work through OSV.
- **deps.dev wants the module path case-preserved and slash-encoded** as one
  segment (`github.com%2FBurntSushi%2Ftoml`). The proxy's `!`-escaping is for
  proxy.golang.org only; do not use it here.
- **crates.io execution is not checkable.** The API has no file list, so
  `build.rs` cannot be detected; `Profile::CRATES` disables execution and the
  report says `not checked`. Do not infer build scripts from metadata.
- **crates.io owners can fail.** A missing or unreadable owner list sets
  `maintainers_known = false`, which becomes an INFO "maintainer list
  unavailable" finding. Never treat it as agreement.
- **PyPI "build from source" is WARN, not an install hook.** An sdist-only
  version runs a PEP 517 backend at build time; it must never inherit npm's
  HIGH escalation (install script + another signal).
- **`Profile` drives honesty, not exit codes.** Disabled signals produce no
  finding and appear in `PackageReport.not_checked` (human line "not checked",
  JSON field, omitted when empty). Never turn a missing signal into a clean one.
- **Typosquat candidates = seed ∪ local lockfile names.** `closest()` takes the
  caller's local list. `lock` passes base lockfile names; `npm` finds the nearest
  `package-lock.json` by walking up (`lockfile::nearest`) unless `--no-local`.
  An unreadable lockfile degrades to the seed silently; do not fail the check
  because of an unrelated file. A name that is itself in the seed is never
  flagged for resembling a local one (`preact` vs `react`) — keep that guard
  and its test.
- **Human review links come from `Ecosystem::package_url`.** Never hardcode
  npmjs.com in a renderer; a PyPI report shipped with an npm link once. Clean
  reports include the link too.
- **`audit` is the whole tree, `lock` is the diff.** `audit` passes an empty
  local typosquat list on purpose (every package in a tree resembles another),
  and its cold cost is one audit per package. It shares `audit_packages` with
  `lock`, so concurrency and error collection stay identical.
- **Lockfile audits run 4 packages at a time.** `MAX_CONCURRENT_AUDITS` in
  `main.rs` bounds the burst; output order still follows the sorted diff, and
  per-package failures stay in `errors`.
- **The npm candidate list is generated, not hand-edited.**
  `data/popular-npm.txt` comes from `scripts/refresh-popular-npm.py` (downloads
  ranking, unioned with the previous seed). `popular_npm()` loads it once via
  `include_str!` + `OnceLock`. Tests require `cross-env`, `preact`, and `moment`
  to stay present, so refresh with the script, never by deleting lines. PyPI,
  crates.io, and Go lists are still curated constants.
- **Refresh is automated.** `.github/workflows/refresh-popular.yml` runs weekly
  (Monday 04:00 UTC) or by dispatch: validates the data with `cargo test`,
  pushes `bot/refresh-popular-npm`, opens or updates a PR, enables auto-merge,
  then approves the bot PR's parked `pull_request` run. `ci.yml` skips that job
  for bot-authored PRs, and GitHub counts a SKIPPED check as satisfied.
  Do not replace approval with `gh workflow run`: a dispatched check does not
  attach to the PR's rollup and auto-merge waits forever.
  Repo settings required: Actions may create pull requests
  (`can_approve_pull_request_reviews=true`), auto-merge enabled,
  `delete_branch_on_merge=true` (auto-merge does not honor `--delete-branch`
  from the workflow), and the job has `actions: write`. If auto-merge is off,
  the PR waits for a human.
  Do not commit generated data by hand outside the script.
- **Advisories are deduplicated by alias.** OSV lists one issue as PYSEC, GHSA,
  and CVE records. `dedupe` unions records whose id/alias sets overlap, keeps the
  highest severity, prefers a real summary over the placeholder, and preserves
  first-occurrence order. Do not remove it: finding counts double otherwise.
- **Advisory details are fetched 8 at a time.** `MAX_CONCURRENT_FETCHES` caps
  in-flight OSV requests; 25 at once invited 429s, and a 429 mid-list turns
  every remaining advisory into "details unavailable".
- **The 25-advisory cap must be disclosed.** `OsvClient::query` returns an
  `AdvisoryList { advisories, hidden }`; `hidden > 0` becomes an INFO finding.
  Never truncate without saying so.
- **`lock` exits 3 when any added package could not be checked**, even if the
  rest is clean. An incomplete audit is not a pass. Per-package failures are
  collected in `LockReport.errors`.
- **`lock` diffs `name@version` pairs**, so a version bump is "new" and gets
  audited. The parser is chosen by file name (`package-lock.json`,
  `requirements*.txt`, `Cargo.lock`, `go.mod`, `poetry.lock`, `uv.lock`,
  `bun.lock`, `pnpm-lock.yaml`, `yarn.lock`, `deno.lock`); npm v1 is rejected instead of
  approximated. Unpinned pip lines, git crates, and
  unreadable go.mod lines become `errors`, so an incomplete tree exits 3.
- **Allowlists downgrade, never delete.** `Allowlist::apply` runs after a
  report exists, sets `allowed`, forces `Severity::Info`, prefixes the reason,
  and re-sorts (severity changed). Tree views must show allowed entries or the
  reason disappears. Missing reasons and unknown finding ids are config errors
  (exit 3). `KNOWN_FINDINGS` must stay in step with `signals.rs`.
- **Deno: npm audited, JSR noted.** `deno.lock` npm entries go through the npm
  auditor; JSR entries become `LockContents.notes` and never fail the run. Notes
  are a third channel beside findings and errors — use them for deliberate,
  safe omissions only.
- **JS lockfile quirks that bite.** `bun.lock` is JSONC (comments and trailing
  commas) and `strip_jsonc` must keep `//` inside strings (URLs). pnpm keys are
  `name@ver` (v9), `/name@ver` (v6), or `/name/ver` (v5), with `(peer@x)` suffixes
  to strip. Yarn Berry workspace entries use `0.0.0-use.local` and are skipped.
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

## Branch protection

`main` requires the CI `test` check and blocks force pushes and deletion.
Repository admins bypass these rules, because this repo pushes branches and
merges locally instead of using PRs. Do not force push; the real gate is the
pre-push hook plus CI on every push.

## Releases

- `cargo-dist` owns `.github/workflows/release.yml`, `dist-workspace.toml`, and
  the `[profile.dist]` section of `Cargo.toml`. Change config in
  `dist-workspace.toml`, then run `dist generate`; never hand-edit the generated
  workflow. Validate with `dist plan`.
- A release is a tag `vX.Y.Z` matching the version in `Cargo.toml`. The workflow
  builds archives plus shell and PowerShell installers and publishes them.
- Tagging publishes publicly and cannot be quietly undone: ask before tagging.
- After a release, bump the reusable workflow's default `ref` to the new tag;
  `main` moving is not a version. The action downloads the prebuilt installer
  for that ref and only builds from source when no release exists.

## Not built yet

JSR support and other remaining formats. Roadmap only: do not describe these
as existing in code, README, or help text.
