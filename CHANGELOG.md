# Changelog

## Unreleased

- **Archive inspection.** `dep-vet inspect <ecosystem> <pkg>[@version]`
  downloads the release, verifies its checksum when published, extracts it in
  memory under hard caps, and scans source text for suspicious behavior (JS,
  Python, shell, Rust `build.rs`, Go, PHP). Path traversal, absolute paths,
  symlinks, hardlinks, oversized archives, and decompression bombs are rejected
  or bounded. Checksum mismatch is HIGH. Nothing is executed.
- **Release diff.** `dep-vet diff <ecosystem> <pkg@old> <pkg@new>` compares two
  archives by content: added, removed, and modified files, new and resolved rule
  findings, and a warning for newly added executable scripts.
- **Rules cover more ground.** JavaScript credential paths, Python and PHP
  encoded payloads, Python dynamic imports, and Go network plus environment
  access. Every finding now carries a description and reference links.
- **Rule findings** carry rule id, severity, confidence, file, and line, and are
  deterministic across runs.

- **Retries with backoff.** Network errors, 429, and 5xx now retry up to three
  times with exponential backoff, and `Retry-After` is honoured up to five
  seconds. Statuses are read as data, so a rate-limit hint is not lost.
- **Advisories stay fresh.** OSV responses are cached for five minutes while
  registry metadata keeps the 24-hour TTL.
- **Confidence in JSON.** Every finding carries `confidence` next to
  `severity`, so a weak signal is not read as a certainty. Existing fields are
  unchanged.

- **Release-transition signals.** dep-vet now flags the shape of a compromised
  release: a version published after a year of dormancy (INFO, all ecosystems),
  changed install scripts in npm (HIGH when they fetch or decode code),
  dependencies added by the new version (npm, Composer, NuGet, PyPI, crates.io),
  and a different publisher from the previous release. History is only fetched
  for versions published in the last 30 days, so older audits cost nothing
  extra.
- **Typosquats judged by registry facts.** npm compares the package's weekly
  downloads with the downloads of the name it resembles, and weak
  (two-or-more-edit) lookalikes are dismissed after five years of history. The generated seed
  now only supplies candidate names, so a gap in it can no longer recommend
  replacing a framework with an unrelated package.

- **No typosquat warnings for established packages.** A package with at least
  1,000,000 weekly downloads is no longer reported as a lookalike, and no
  longer suggests replacing it. `next` was matched to `jest` at two edits
  because the generated seed was missing it; the refresh script now anchors
  recent frameworks so the seed stops losing them.

- **Batched audit lookups.** A tree audit sends one OSV `querybatch` per 500
  packages (across ecosystems) and one npm downloads request per 128 names,
  instead of one of each per package. A shared advisory is hydrated once, and
  each package still gets its own fixed-version filtering. On a 122-package npm
  tree this is 20.2 s → 4.9 s cold and 3.2–4.2 s → 0.07 s cached. A failed
  batch marks only its own packages "advisory check unavailable", never clean.
  npm's bulk downloads endpoint rejects scoped packages, so those stay one at a
  time, and a failed download chunk loses up to 128 figures. Gemfile.lock
  platform suffixes are stripped before the OSV lookup, so a native gem gets
  the same advisories as its registry version.

- **Progress bar.** The stderr progress line for `audit`/`lock` now fills a
  20-cell bar as packages finish, next to the count.

## 0.9.0 — 2026-11-21

- **Progress while auditing.** `audit` and `lock` print `auditing N/M packages…`
  on stderr when it is a terminal, then clear the line before the report.
  Pipes and CI logs are unchanged, and `--json` stdout is untouched.

## 0.8.0 — 2026-11-21

- **Upgrade advice.** Reports end with what to do: the version OSV says fixes the
  advisory (or `no fixed version published` / `fix unknown`), the newest
  published version as a labelled hint, and the real package behind a lookalike
  name. `audit` and `lock` close with one worst-first block. Advice never changes
  a verdict or an exit code.
- **Google Maven.** AndroidX, AGP, Firebase, and Play artifacts are read from
  `dl.google.com/dl/android/maven2`, so `gradle.lockfile` audits work for
  Android projects instead of failing on every AndroidX dependency. Google
  publishes no timestamps, so those reports list freshness as not checked and
  note that OSV only indexes Maven Central.
- **Maven fixes.** Versions beyond the search API's 200-row page are no longer
  reported as missing, "first seen" is the real oldest release, and "latest"
  skips milestones, RCs, and snapshots. Central's burst rate limit is reported
  as rate limiting, not a missing package, and Maven tree audits run one
  package at a time.
- **Parser fixes.** Composer without publish times picks the first listed
  release; `packages.config` no longer reads `developmentDependency` as `id`.

## 0.7.1 — 2026-11-21

Maven version-window fixes, Composer latest ordering, and the `packages.config`
attribute boundary.

## 0.7.0 — 2026-11-21

- **Legacy NuGet:** `packages.config` audits its `<package id version />`
  elements through the NuGet auditor. Elements missing a version are reported
  as unchecked.
- **Pipenv:** `Pipfile.lock` audits the `default` and `develop` pins through
  PyPI. Path, git, and URL references and `*` versions are reported as
  unchecked rather than ignored.

## 0.6.0 — 2026-11-21

- **One retry for flaky networks.** A timeout or dropped connection is retried
  once before dep-vet falls back to stale cache or reports "could not check".
  404 and 429 are never retried. Previously a single slow response failed the
  whole audit.
- **Gradle:** `gradle.lockfile`, `buildscript-gradle.lockfile`, and
  `settings-gradle.lockfile` are audited through the Maven ecosystem. Projects
  that do not enable dependency locking have no file, so there is nothing to
  check and nothing is guessed.

## 0.5.0 — 2026-11-21

- **Composer:** `dep-vet composer vendor/package[@version]` and `composer.lock`
  auditing for both `packages` and `packages-dev`. Packagist supplies versions,
  publish times, maintainers, a source repository, and the abandoned flag.
  There is no install-time file list and its download figure is monthly, so
  those stay `not checked`.

## 0.4.0 — 2026-11-21

- **Maven:** `dep-vet maven group:artifact[@version]` reads Maven Central for
  versions and publish times, plus OSV advisories. Maven has no standard
  lockfile and no owners, downloads, repository, or deprecation metadata, so
  those are `not checked` and only the single coordinate is vetted.

## 0.3.0 — 2026-11-21

Three more ecosystems and their lockfiles.

- **JSR:** `dep-vet jsr @scope/name`, plus JSR entries inside `deno.lock`.
  Versions, publish times, repository, archived-as-deprecated. OSV has no JSR
  coverage, so JSR reports say "advisory coverage unavailable" instead of
  implying a clean result.
- **RubyGems:** `dep-vet gem rack@3.2.9` and `Gemfile.lock` auditing. Platform
  suffixes resolve to registry versions; yanked versions vanish from the API.
- **NuGet:** `dep-vet nuget Newtonsoft.Json` and `packages.lock.json`. Flat
  container versions, registration times/deprecation, case-insensitive IDs,
  1900-01-01 sentinel dates ignored.
- `.depvet.toml` rejects unknown keys; Yarn Berry `__metadata` no longer makes
  audits exit 3; pnpm parsing dropped the unmaintained `unsafe-libyaml`.

## 0.2.1 — 2026-11-21

Fixes found by auditing dep-vet's own repositories.

- crates.io publisher mismatches are INFO: owner lists omit GitHub org members,
  so `regex` and `pkg-config` looked like handoffs.
- Legitimate neighbour crates (`inotify`, `rustix`, `shlex`) are in the ranked
  seed, so they are no longer typosquats of `notify`, `rustls`, `sqlx`.
- pnpm lockfiles are parsed without a YAML dependency, removing unmaintained
  `unsafe-libyaml` (RUSTSEC-2024-0449) from dep-vet's own tree.
- CI now audits dep-vet's own `Cargo.lock` on every push.
- Yarn Berry's `__metadata` block is no longer reported as an unreadable
  package, which made every Berry audit exit 3.
- `.depvet.toml` rejects unknown keys instead of silently ignoring typos.

## 0.2.0 — 2026-11-21

First release with more than npm.

- **Ecosystems:** PyPI (`dep-vet pypi`), crates.io (`dep-vet crates`), and Go
  modules (`dep-vet go`), alongside npm. Per-ecosystem `Profile` flags report
  signals a registry cannot provide as `not checked`.
- **Lockfiles:** `package-lock.json`, `bun.lock`, `pnpm-lock.yaml`, `yarn.lock`,
  `deno.lock`, `requirements*.txt`, `Cargo.lock`, `go.mod`, `poetry.lock`,
  `uv.lock`, for both `lock` and `audit`.
- **Whole-tree audit:** `dep-vet audit <lockfile>` vets every installed package,
  four at a time, with warm-cache reruns around 20 ms.
- **Allowlists:** `.depvet.toml` entries need a reason; allowed findings stay
  visible as `[ALLOWED]` and stop affecting the exit code.
- **Watch mode:** `dep-vet watch <lockfile>` re-audits on every saved change,
  debounced.
- **Typosquats:** compared against your own lockfile as well as a
  download-ranked npm list that CI refreshes weekly.
- **Advisories:** OSV records that share an alias (PYSEC/GHSA/CVE) are merged
  into one finding.
- **Hooks:** a tracked pre-commit hook vets staged lockfiles before commit.

## 0.1.0 — 2026-11-21

- npm vetting: install scripts, typosquats, freshness, publisher, deprecation,
  repository, OSV advisories.
- SQLite cache with stale fallback, `dep-vet lock`, JSON output, GitHub Action.
