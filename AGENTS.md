# dep-vet

Local CLI (+ GitHub Action) answering "should I accept this package?" *before*
it enters the lockfile. Status: **idea only — no code, no manifest, nothing to
build or run yet.** Product brief: `docs/brief.md`.

## First rule

Do not scaffold Rust code unprompted. The brief's stated next step is: answer
the open questions, then write a design doc. Confirm direction before creating
`Cargo.toml`.

## Decisions already made — don't re-litigate

- Rust, single static binary, no Node runtime. Crates: `clap`, `serde`,
  `reqwest`, `tokio`, `rusqlite`. Releases via `cargo-dist`.
- npm first; crates.io and PyPI come later.
- Standalone command, not a package-manager shell wrapper.
- Plain text output with `--json` first; TUI later.
- Exit codes: `0` clean, `1` warnings, `2` high-risk.
- No LLM in the verdict. Every flag links to raw evidence.
- Optional `.depvet.toml` for allowlists only; no required config file.

## The signals are the product

Implement these, each with a cited evidence link:

1. Install scripts present (`preinstall`/`install`/`postinstall`) from registry
   metadata — the exact vector in the axios compromise.
2. Freshness: first publish < 7 days old, or version newer than the dependent's
   lockfile date.
3. Maintainer churn: maintainer set changed within 90 days of a release.
4. Ownership transfer / repo vanished (`repository` field removed or 404).
5. Typosquat distance: Levenshtein ≤ 2 vs top-5000 by downloads, or homoglyph
   variant (`l`/`1`).
6. Advisories via OSV batch, grouped by severity.
7. Popularity cliff: dependency of a popular package, tiny own downloads.
8. Republished version: same version string, different tarball hash.

Plumbing is not the differentiator; the rule set and the report are.

## Data sources (keyless, live-checked 2026-11-21)

- `POST https://api.osv.dev/v1/querybatch` — vulns, 1000 queries/request.
- `https://api.deps.dev/v3/systems/npm/packages/{pkg}` — versions, licenses,
  dependency graph, OpenSSF scorecard; `/dependencies` for the full graph.
- `https://registry.npmjs.org/{pkg}` — maintainers, `scripts`, publish times,
  deprecation; fetch `/{pkg}/{version}` instead of the whole packument.
- `https://api.npmjs.org/downloads/point/last-week/{pkg}` — weekly downloads.
- `https://api.github.com/...` — repo activity, advisories: 60/h anonymous.

Gotchas:

- crates.io 403s without a `User-Agent`.
- Never use npm search for typosquats; rank popular names by download counts.
- OSV/deps.dev rate limits are undocumented: cache aggressively, back off on 429.
- Registry metadata is incomplete for some packages — degrade gracefully.

## Non-goals

No CVE dashboard, no SBOM generator, no accounts, no hosted service, no
telemetry in v1, not a Dependabot replacement. See `docs/brief.md` for the full
scope and evidence.

## Bias

False positives destroy trust faster than misses. Few, loud, well-explained
rules. If a rule cannot cite evidence, it does not ship.
