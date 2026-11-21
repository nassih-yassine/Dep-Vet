# dep-vet — dependency risk check *before* install

Status: idea only. No code yet.

A local CLI (and GitHub Action) that answers "should I accept this package?"
*before* it enters your lockfile. It reports the dependency surface, install
scripts, maintainer history, typosquat proximity, and known vulnerabilities —
with evidence links, not a score out of 100.

## The problem

Installing a package is remote code execution by design. `npm install` runs
`postinstall` hooks, resolves transitive dependencies the developer never
reads, and trusts maintainer accounts that can change hands overnight.

Existing tools answer the wrong question at the wrong time:

| Tool | Question it answers | When |
|------|--------------------|------|
| `npm audit` | is a version in my tree vulnerable? | after install |
| Dependabot / Renovate | is an installed dep outdated/vulnerable? | after commit |
| OSV-Scanner | are my lockfiles vulnerable? | after lockfile exists |
| Socket / Snyk | is this package risky? | paid, hosted, CI-centric |

Nothing cheap and local answers, at decision time: *what will this pull in, does
it run code on install, who maintains it now, and is this name one typo away
from a popular package?*

## Evidence this is a live problem

- 2025-09-08: 18 widely used npm packages compromised in one campaign
  (Palo Alto Networks breakdown).
- 2025-09-23: CISA alert on a widespread npm supply-chain compromise.
- `axios@1.14.1` compromise: single added dependency
  `plain-crypto-js`, present only to fire a postinstall hook; persisted as a
  detached process. Transitive, invisible in `package.json`.
- 2026-05-29: Microsoft Threat Intelligence reports 33 malicious npm packages
  using dependency confusion against corporate scopes.
- 2026: "Mini Shai-Hulud" campaign affecting npm and PyPI packages (NHS cyber
  alert CC-4781).

Pattern: the attack is *silent, transitive, and install-time*. A scanner that
runs after the lockfile is written misses the moment of trust.

## Who has this problem

- Anyone running `npm i <new-package>` weekly (most JS devs).
- Small teams with no Socket/Snyk budget who still need a reviewable answer.
- Maintainers reviewing PRs that add a dependency — the reviewer has 30
  seconds and no tool.

## Jobs to be done

1. **Before adding**: `dep-vet npm express@5.1.0` → what comes with it, does it
   run scripts, how old, how popular, who maintains it, is the name a
   near-duplicate of a popular package, any advisories.
2. **Before merging**: `dep-vet lock ./package-lock.json` → audit everything
   newly added vs `main`.
3. **Weekly, silently**: alert on *trust drift* in already-installed deps —
   maintainer added/removed, new install script, version republished, package
   transferred to a new owner.

## Why now

The 2025–2026 attack wave made "dependency review" a mainstream concern, and
the free data needed to do it well is finally good: OSV, deps.dev, and registry
metadata are all keyless. AI-assisted coding also inflates the rate at which
new packages enter codebases.

## Free APIs (live-checked 2026-11-21, all HTTP 200, no key)

| API | What it gives | Notes |
|-----|---------------|-------|
| `POST https://api.osv.dev/v1/querybatch` | vulns for `{ecosystem, name, version}` batches | 1000 queries/request; also `GET /v1/vulns/{id}` (3.8 KB, 0.6 s) |
| `https://api.deps.dev/v3/systems/npm/packages/{pkg}` | versions, licenses, advisories, dependency graph, OpenSSF scorecard | 56 KB, 0.6 s; also `/dependencies` for full graph |
| `https://registry.npmjs.org/{pkg}` | maintainers, `scripts`, publish times, deprecation, repo link | large; fetch `/{pkg}/{version}` for one version |
| `https://api.npmjs.org/downloads/point/last-week/{pkg}` | weekly download count | 83 B, 0.16 s |
| `https://pypi.org/pypi/{pkg}/json` | PyPI metadata | keyless |
| `https://crates.io/api/v1/crates/{name}` | crates metadata | set a User-Agent or it 403s |
| `https://api.github.com/...` | repo activity, advisories (GraphQL) | 60/h anonymous, 5000/h with token |

Do **not** depend on npm's search endpoint for typosquat detection; build the
popular-name list from download counts instead.

## Signals worth implementing (each must cite its evidence)

1. **Install scripts present** (`preinstall`, `install`, `postinstall`) — from
   registry metadata. This is the exact vector used in the axios compromise.
2. **Freshness**: first publish < 7 days old, or version published after the
   dependent's lockfile date.
3. **Maintainer churn**: maintainer set changed within 90 days of a release.
4. **Ownership transfer / repo vanished**: `repository` field removed or 404.
5. **Typosquat distance**: Levenshtein ≤ 2 vs top-5000 by downloads, or
   homoglyph variant (e.g. `l`/`1`).
6. **Advisories**: OSV batch, grouped by severity.
7. **Popularity cliff**: dependency of a popular package but its own downloads
   are tiny (a common malware pattern).
8. **Republished version**: same version string with a different tarball hash.

## Non-goals

- Not a CVE dashboard or SBOM generator.
- No accounts, no hosted service, no telemetry in v1.
- Not a replacement for Dependabot; it complements it at a different moment.
- No LLM guessing in the verdict. Every flag links to raw evidence.

## MVP (v0.1)

1. Rust binary, single static release artifact, no Node runtime needed.
2. `dep-vet npm <pkg>[@version]` → human report + `--json`.
3. `dep-vet lock <lockfile>` → diff against a base ref in CI.
4. Exit codes: `0` clean, `1` warnings, `2` high-risk (install scripts +
   fresh + maintainer churn).
5. Caching layer (SQLite or on-disk JSON) so repeated runs are offline-capable.
6. GitHub Action wrapper with sticky PR comment.

## Success looks like

- You run it before every new dependency, unprompted.
- Three external users file issues they care about.
- A reviewer can read the PR comment and decide in under a minute.

Stars are a lagging signal; do not optimize for them directly.

## Risks

- **False positives** destroy trust faster than misses. Start with few, loud,
  well-explained rules.
- Registry metadata is incomplete for some packages; degrade gracefully.
- API rate limits are undocumented for OSV/deps.dev — cache aggressively and
  back off on 429.
- Rust + HTTP + JSON parsing is a solved problem; the differentiator is the
  rule set and the report, not the plumbing.

## Open questions

- npm first, or npm + crates from day one? (Recommendation: npm first, crates
  second — the attack wave is npm-shaped.)
- Should the "add" path hook into the package manager (shell wrapper) or stay a
  separate command? (Recommendation: separate command; wrappers are fragile.)
- Human output: plain text with color, or an interactive TUI list?
  (Recommendation: plain text first, TUI later.)

## Suggested stack

Rust (`clap`, `serde`, `reqwest`, `tokio`, `rusqlite`), `cargo-dist` for
releases, GitHub Actions for CI and the wrapped action. Single binary, no
config file required; optional `.depvet.toml` for allowlists.

## Next step

Answer the open questions, then write the design doc before any code.
