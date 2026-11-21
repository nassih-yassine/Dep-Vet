# Changelog

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
