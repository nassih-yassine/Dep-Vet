# Changelog

## Unreleased

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
