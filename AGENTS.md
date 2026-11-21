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

## Dogfooding

CI runs `dep-vet audit Cargo.lock` on this repository (the `dogfood` job). Any
finding fails the build, including warnings. When it fires:

1. Fix the dependency if possible (replacing `serde_yaml_ng` removed
   `unsafe-libyaml`).
2. If the risk is accepted, add a `.depvet.toml` entry **with a reason**; the
   report keeps showing it as `[ALLOWED]`.
3. If it is a false positive, fix the rule and add a regression test. Legitimate
   crates close to another seed entry (`inotify`/`notify`, `rustix`/`rustls`,
   `shlex`/`sqlx`) are pinned in `legitimate_neighbours_are_not_suspects`.

Never make the job non-blocking to get a merge through.

## Commands

```sh
cargo test --locked                      # 496 unit + 124 end-to-end tests
cargo test signals::                    # one module
cargo test --test cli fresh_package     # one end-to-end case
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Clippy warnings are errors. Do not commit unformatted code.

Two tracked hooks live in `.githooks/`: `pre-commit` vets staged lockfiles in
every supported format (`lock --base HEAD`, full `audit` for newly added files;
blocks on exit 2/3, warnings pass) and prefers this checkout's `target/` build so
a stale `dep-vet` on PATH cannot judge new rules with an old seed, and `pre-push` runs fmt, clippy, and tests. Enable both once per
clone:

```sh
git config core.hooksPath .githooks
```

Do not use `--no-verify` to get past a failure; fix the failure.

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
| `src/jsr.rs` | JSR meta/package APIs, repository, archived flag |
| `src/rubygems.rs` | RubyGems versions, timestamps, source URL, yank flag |
| `src/nuget.rs` | NuGet flat container, registration pages, times, deprecation |
| `src/maven.rs` | Maven Central search: versions, timestamps |
| `src/composer.rs` | Packagist p2 versions, maintainers, abandoned flag |
| `src/osv.rs` | advisory IDs from `querybatch`, details per advisory, severity mapping |
| `src/http.rs` | one agent, 64 MB body limit, the cache read/write policy |
| `src/cache.rs` | SQLite cache: TTL, stale fallback, key/value entries |
| `src/signals.rs` | the rules: `PackageMeta` + `now` in, `Vec<Finding>` out (no I/O) |
| `src/typosquat.rs` | Levenshtein, homoglyph folding, per-ecosystem candidate lists |
| `src/watch.rs` | `watch` command: notify watcher, target filtering, debounce |
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
- **Findings carry rule-level confidence.** `Finding::confidence()` maps the
  finding id to high/medium/low and is serialized next to `severity` by
  `report::serialize_findings`. Advisories and install scripts are high;
  typosquats, publisher changes, added dependencies, dormancy, stale advisory
  data, and missing checks are medium. Adding a finding id means adding it to this mapping and to
  `KNOWN_FINDINGS`; the allowlist completeness test covers the latter.
- **The cache policy is deliberate.** Fresh entry skips the network; stale
  entries are used for network errors, 5xx, and 429; a 404 never falls back, or
  deleted packages would look alive. See `HttpError::is_transient`.
- **Progress is stderr and TTY only.** `src/progress.rs` draws one
  `auditing [████░░░░] N/M` bar for `audit`/`lock`; it must never touch stdout,
  never appear in pipes or CI (including CI runners with a pseudo-TTY, hence the
  `CI`/`TERM=dumb` gate), and must be cleared by `Drop` before the report, even
  on a panic. An empty list draws nothing. A mixed Deno tree restarts the count
  at the JSR pass; that is two lists, not a retry.
- **Transient failures retry with bounded backoff.** Network errors, 429, and
  5xx get up to `MAX_ATTEMPTS` (3) tries with exponential backoff (150ms, 300ms)
  and a server `Retry-After` capped at 5s. 404 never retries. Statuses are
  handled as data (`http_status_as_error(false)`) so `Retry-After` is readable.
  Tests for failed requests therefore take a few hundred milliseconds; do not
  remove the sleeps to make them fast.
- **Advisories use a five-minute TTL.** `http.rs` picks `ADVISORY_TTL_SECONDS`
  when the key contains the configured OSV base (`DEPVET_OSV_BASE`, default
  `https://api.osv.dev`), not a literal host; everything else uses
  `DEPVET_CACHE_TTL_SECONDS` (24h default). `cached` returns
  `(body, Source)` so callers can tell `Fresh` from `Network` from
  `Stale { age_seconds }`. Advisory stale fallback stops at
  `ADVISORY_MAX_STALE_SECONDS` (24h); past it the error is returned so the
  existing "advisory check unavailable" INFO fires. Serving stale advisory data
  adds INFO `advisories-stale` with its human age.
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
- **`packages.config` is parsed line-wise, not with an XML crate.** Each
  `<package id="..." version="..." />` start tag is read by a tiny attribute
  scanner; a missing id or version is reported, never invented. Like pnpm,
  this avoids adding a parser dependency for one flat file.
- **Pipfile.lock is JSON, not TOML.** `default` and `develop` entries hold
  `version: "==1.2.3"`. A missing/`*` version or a path/git/URL entry is
  reported as an error (an incomplete tree exits 3), matching `poetry.lock`;
  do not silently drop them.
- **Gradle locking is Maven.** `gradle.lockfile` lines are
  `group:artifact:version=configurations`; the `empty=` line and `#` comments
  are skipped, and `buildscript-gradle.lockfile` / `settings-gradle.lockfile`
  map to the same parser. The ecosystem is Maven, so audits reuse `audit_maven`.
  A project without dependency locking has no file: never infer versions from
  build scripts.
- **Composer has two endpoints.** `repo.packagist.org/p2/{vendor}/{name}.json`
  lists versions and times (minified entries may omit fields); the package
  endpoint at `packagist.org/packages/...` adds maintainers and the abandoned
  flag. Maintainer failures must set `maintainers_known = false` (INFO "list
  unavailable"), never look like agreement. Composer names are lowercase and
  `parse_composer` lowercases them for OSV. Downloads are monthly-only on
  Packagist, so the weekly download signal stays `not checked`.
- **Google Maven is a second source, not an ecosystem.** AndroidX, AGP,
  Firebase, and Play groups (`androidx.`, `com.android.`, `com.google.android.`,
  `com.google.firebase`, `com.google.mlkit`, `com.google.ar.`) are looked up in
  `dl.google.com/dl/android/maven2` first; everything else goes to Central and
  falls back to Google on not-found. Google's `maven-metadata.xml` has versions
  but no timestamps, so those reports add `freshness` to `not_checked` and carry
  a `review_url` pointing at maven.google.com instead of search.maven.org.
  `PackageMeta.review_url` is the one override the renderer honors; every other
  ecosystem leaves it `None` and uses `Ecosystem::package_url`. OSV's Maven
  index only covers Central, so a Google-sourced report carries an INFO
  "advisory coverage may be incomplete" note even when OSV returned no hits.
- **Maven Central 403 is a rate limit, not a missing package.** Sonatype's WAF
  answers 403 when a client bursts the search API; `MavenError::Throttled` says
  so instead of "not found". Tree audits therefore run Maven one package at a
  time (`MAVEN_CONCURRENCY`), and those 403s are never cached as empty results.
  Do not lower the 200-row page by asking for more rows: it is capped.
- **Maven search returns at most 200 rows.** `spring-core` has 300+ versions, so
  an exact version is filtered in the query (`AND v:"3.2.0.RELEASE"`), and a
  truncated page triggers one extra request for the last row so "first seen" is
  the real oldest release. `rows=1000` is silently capped to 20: do not raise
  the number, paginate or filter. "Latest" skips milestones, RCs, and
  snapshots; Maven has no stable flag.
- **Maven has no lockfile.** `dep-vet maven group:artifact[@version]` audits a
  single coordinate via the Central search API (timestamps are milliseconds).
  No owners, downloads, repository, or deprecation exist; `Profile::MAVEN`
  disables all four. There is no tree to audit until a Maven lockfile format
  ships, so do not claim one.
- **NuGet basics.** IDs are case-insensitive, so URLs lowercase them but the
  canonical name keeps the caller's casing for OSV. Registration pages may be
  inline or linked (`@id`); both are handled and best-effort. `1900-01-01` is
  NuGet's "unknown" date and must be filtered out of freshness. `packages.lock.json`
  resolves per target framework; `type: Project` entries are skipped.
- **RubyGems hides yanked versions.** `/api/v1/versions/{gem}.json` omits them,
  so an exact yanked version reports VersionNotFound, not "deprecated". Gemfile
  versions may carry a platform suffix (`1.16.0-x86_64-linux`); `Release::matches`
  resolves it to the registry number. Only the `GEM` section is auditable;
  `PATH`/`GIT` are local sources.
- **JSR has no advisory source.** `Profile::JSR` sets `advisories: false`; the
  report emits an INFO "advisory coverage unavailable" instead of querying OSV.
  No owners, downloads, or execution either. `deno.lock` keeps npm and JSR
  entries in separate lists (`LockContents.packages` vs `.jsr`) because a Deno
  lockfile mixes registries; both are audited.
- **Go can check almost nothing structural.** No install hooks, owner list,
  downloads, or repository in the module index: `Profile::GO` disables all four
  and the report says `not checked`. Go advisories still work through OSV.
- **deps.dev wants the module path case-preserved and slash-encoded** as one
  segment (`github.com%2FBurntSushi%2Ftoml`). The proxy's `!`-escaping is for
  proxy.golang.org only; do not use it here.
- **crates.io execution is not checkable.** The API has no file list, so
  `build.rs` cannot be detected; `Profile::CRATES` disables execution and the
  report says `not checked`. Do not infer build scripts from metadata.
- **crates.io publisher mismatches are INFO, not WARN.** Owner lists contain
  users, not GitHub org members, so crates published by org teams look
  mismatched. Keep this severity per ecosystem; do not "fix" it back to WARN.
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
  and its test. Depth: a package with at least `ESTABLISHED_WEEKLY_DOWNLOADS`
  (1,000,000) weekly downloads is never reported as a typosquat, and gets no
  replacement advice. The generated seed always has holes (`next` was missing
  and matched `jest` at distance 2, advising a test runner in place of a
  framework), so this is the safety net; `ANCHORS` in the refresh script is the
  source fix.
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
- **Archive inspection is download-only.** `src/archive` extracts in memory with
  `Limits` (25 MB compressed, 100 MB total, 10k entries, 5 MB/file); nothing is
  written to disk and nothing is executed. Absolute paths, `..`, symlinks,
  hardlinks, and non-file entries are skipped and counted. `src/inspect` resolves
  per-ecosystem archive URLs and trusted checksums; a mismatch is a HIGH finding
  (`ARCHIVE-CHECKSUM-001`). JSR has no documented tarball URL; Maven without a
  sources jar and NuGet compiled packages report source analysis as not checked.
  `Extracted.truncated` must never be read as a boolean without its reasons:
  `oversize_files` (paths capped at 50), `entries_over_cap`, and
  `total_over_cap` feed `rules::partially_scanned`, which emits
  `archive-partially-scanned` (WARN when a skipped path is scannable or entries
  were never read, INFO otherwise) in both `inspect` and `diff`. A cap stop is
  a disclosed gap, never a clean result.
  Rules in `src/rules.rs`: a lone API match is WARN with medium confidence;
  network plus credential access, or an encoded payload passed to `eval`, is
  HIGH. Every rule carries a description and at least one reference URL, and a
  test fails when either is missing. Dynamic imports are intentionally WARN:
  frameworks use them legitimately. Comments are
  skipped with `rules::strip_comments` (C-style for JS/TS/Go/Rust/PHP, `#` for
  Python/shell/Ruby), which tracks string literals so URLs are not comments and
  keeps code after `*/`. Patterns run over the whole stripped file, so a call
  split across lines matches; line numbers come from the stripped text and
  evidence from the original line. `Extracted` keeps any file with a scannable
  extension and decodes it lossily, so a trailing `0xFF` or NUL cannot hide
  code; only non-source files with NUL/invalid UTF-8 become binary. Findings
  sort by (file, line, rule) for reproducible output.
  `diff` compares two extracted releases by content: added/removed/modified
  paths, findings matched by (rule, file) because line numbers shift, and a
  `DIFF-NEW-SCRIPT-001` WARN for added shell/shebang files, and
  `DIFF-INSTALL-SCRIPTS-001` compares parsed npm install hooks (WARN, HIGH when
  `signals::risky_install_command` matches). Added binaries become
  `DIFF-NEW-BINARY-001` INFO from `Extracted.binaries` (capped at 200); they are
  never scanned as text. Both specs must name the same package with exact
  versions. A NuGet `.signature.p7s` entry sets `Extracted.signature_file`,
  which renders as `signature: file present (not verified)` and JSON
  `package_signature`; absence is not reported, and the signature itself is
  never checked. The same `.depvet.toml` carries `[inspect]` limits and
  `disabled_rules`; unknown rule ids and zero caps are configuration errors
  (exit 3), and `disabled_rules` is applied to both `inspect` and `diff`.
  Verified archives are cached under
  `~/.cache/dep-vet/archives/` keyed by their checksum, re-verified on every
  load, swept after 30 days; unverified archives are never cached, and
  `--no-cache` bypasses the lookup. Never cache a file whose checksum did not
  verify.
- **Provenance is presence, never verification.** npm sets `Present` when
  `dist.attestations` carries `provenance` or a URL (`provenance` holds only
  `predicateType`; the URL sits on `attestations`); PyPI HEADs
  `/integrity/{project}/{version}/{filename}/provenance` for the sdist-first
  file. Everything else stays `Unavailable`. `Missing` is not a finding, and
  no report may claim a signature, builder, or source commit was verified.
  npm's `attestation_subject_matches` compares the in-toto subject's sha512
  hex with the `dist.integrity` tarball digest: a mismatch is HIGH
  (`attestation-subject-mismatch`), unreadable stays `None`. The SLSA v1
  predicate supplies claimed builder/source/commit/workflow (`AttestationClaims`),
  rendered with `(claimed)`; a claimed source repository differing from the
  package repository is INFO `attestation-source-mismatch`. Audits never claim
  cryptographic verification.
- **Sigstore verification is offline and inspect-only.** `src/provenance.rs`
  verifies npm bundles with `sigstore-verify` against the embedded PublicGood
  root (`TrustedRoot::from_embedded`); no TUF, no network beyond the registry's
  attestation response, no tokio. Keep `sigstore-trust-root` on
  `default-features = false`, or the TUF feature pulls tokio back in. Status is
  exactly `verified` or `unverified`; managed-key bundles have no Fulcio
  certificate and must stay unverified with a reason. Tests use a real signed
  fixture (`tests/fixtures/semver-7.8.6.*`), because verification cannot be
  faked; one test flips a tarball byte and expects a rejection. A failed
  verification is never a finding, since format or root changes are not the
  package's fault.
- **Release-transition signals are history-based and gated.** `HISTORY_WINDOW_DAYS`
  (30) bounds them: PyPI and crates.io fetch two extra documents only for a
  version inside it. `previous_release` picks by timestamp, never list order.
  `release-after-dormancy` is INFO on its own (routine maintenance produces
  year-long gaps; it failed dep-vet's own dogfood as WARN) and never escalates.
  `install-scripts-changed` compares hook commands with the previous release and
  escalates to HIGH only for known execution patterns; unchanged scripts stay
  under the ordinary install-script finding. `dependency-added` is INFO unless
  an added name resembles a seed name. `publisher-changed` is INFO and only for
  accounts already on the maintainer list; a new account remains the existing
  WARN, enriched with the previous publisher. Composer platform packages
  (`php`, `ext-*`, `lib-*`, `composer-*`) and crates `dev` dependencies never
  count. Typosquat suppression compares the package's downloads with the
  looked-alike name's and falls back to 1,000,000. Age suppresses only a weak
  resemblance (distance 2 or more, not a homoglyph): a nine-year-old one-edit
  lookalike such as `crossenv` must stay flagged.
- **Tree audits batch, single packages do not.** `advisories_for` sends one
  `querybatch` per 500 packages (JSR excluded); `downloads_for` sends one npm
  request per 128 unscoped names, with scoped names fetched singly because the
  bulk endpoint rejects them. Names are validated before either becomes a URL.
  Failure is per chunk: only that chunk's packages become `None` (unavailable,
  never clean), and a short server answer rejects the chunk rather than filling
  it with empty lists. Gemfile.lock platform suffixes are stripped with
  `rubygems::osv_version` before the OSV query, or native gems lose advisories.
  Keep the per-package `Pre` path so `dep-vet npm foo` stays unchanged.
- **Upgrade advice is evidence-shaped.** `Upgrade.fixed` comes only from OSV's
  `affected[].ranges[].events[].fixed`, filtered to the audited package's name;
  `newest` is a hint and never a fix. Never derive a fix from `latest_version`,
  never say "no fixed version published" when the advisory could not be hydrated
  (`fix_unknown`), and produce no line for packages whose findings are only
  install scripts, deprecation, or freshness. Advice never changes a verdict or
  an exit code. The version helper only labels majors; it never orders versions.
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
- **`watch` watches the file, not the folder.** `is_target` ignores sibling
  files and same-named files elsewhere; events are debounced 300 ms. The
  watcher is registered before `on_start` runs, so an edit during the first
  report is not lost. The end-to-end test spawns the binary, edits the lockfile,
  and waits for a second report, so it touches inotify - keep timeouts generous.
  Any lockfile format works; the default is the nearest `package-lock.json`.
- **Allowlists downgrade, never delete.** `Allowlist::apply` runs after a
  report exists, sets `allowed`, forces `Severity::Info`, prefixes the reason,
  and re-sorts (severity changed). Tree views must show allowed entries or the
  reason disappears. Missing reasons and unknown finding ids are config errors
  (exit 3). `KNOWN_FINDINGS` must stay in step with `signals.rs`.
- **Deno: npm audited, JSR noted.** `deno.lock` npm entries go through the npm
  auditor; JSR entries become `LockContents.notes` and never fail the run. Notes
  are a third channel beside findings and errors — use them for deliberate,
  safe omissions only.
- **pnpm is parsed line-wise, with no YAML dependency.** Only direct children
  (two-space indent) of the top-level `packages:` section are entries; nested
  resolution keys and `snapshots:` are ignored. This removed
  `serde_yaml_ng`, which pulled the unmaintained `unsafe-libyaml` advisory into
  dep-vet's own tree. Do not reintroduce a YAML crate for pnpm.
- **JS lockfile quirks that bite.** `bun.lock` is JSONC (comments and trailing
  commas) and `strip_jsonc` must keep `//` inside strings (URLs). pnpm keys are
  `name@ver` (v9), `/name@ver` (v6), or `/name/ver` (v5), with `(peer@x)` suffixes
  to strip. Yarn Berry workspace entries use `0.0.0-use.local` and are skipped;
  its `__metadata` block is not a package and must stay out of `skipped`, or
  every Berry audit exits 3.
- **`.depvet.toml` denies unknown keys.** A typo like `[[allows]]` must fail the
  run, not silently allow nothing.
- **NuGet and Maven names keep the caller's casing.** URLs lowercase NuGet ids;
  OSV matches the published casing (or `group:artifact`), so lowercasing the
  stored name broke advisory lookups once.
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
  stubbed `gh` and `dep-vet` before pushing. Inputs reach the script only through
  quoted `env:` values (`LOCKFILE`, `BASE_INPUT`, `PR_BASE`, `PR_NUMBER`,
  `REPOSITORY`); never interpolate `inputs.*` into shell text. The report is
  written to `$GITHUB_STEP_SUMMARY` before any comment attempt, a read-only
  token prints `::warning::` and continues, and the job exits only on status >=
  2 so warnings still pass. A `vX.Y.Z` ref installs with `--tag`, other refs
  with `--branch`. Third-party actions are avoided on purpose: this repo should
  not add supply-chain surface to a supply-chain tool.
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

Remaining ecosystems and lockfile formats (e.g. Gradle). Roadmap only: do not
describe these as existing in code, README, or help text.
