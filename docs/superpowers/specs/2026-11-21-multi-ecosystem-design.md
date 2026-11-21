# Multi-ecosystem support — design spec

Date: 2026-11-21
Status: design only. The npm MVP continues; nothing in this document is built.
Scope owner: whoever picks up the next ecosystem.

## Intent

`dep-vet` answers one question — "should I accept this package?" — at the moment
trust is granted, with evidence instead of a score. Today it answers for npm
only. This spec describes how to add PyPI, crates.io, and Go **without**
forking the signal logic, the report format, or the cache.

The npm path must not degrade while this happens. Every change here is additive:
`dep-vet npm <pkg>` keeps its output shape, exit codes, and evidence links.

## Goals

- One binary, one report format, one exit-code contract across ecosystems.
- Registry access behind a trait so a new ecosystem is a new module, not edits
  to `signals.rs`.
- Per-ecosystem honesty: a signal that does not exist in an ecosystem is
  absent, never "clean". Go has no install scripts; saying "no install scripts"
  there is true but useless, and must not read as a green light.
- Advisories work for every ecosystem through OSV with no new API work.
- Cache keys namespaced per ecosystem so entries never collide.

## Non-goals

- Tree-wide scanning of lockfiles (that is `dep-vet lock`, separate spec).
- Ecosystems without a keyless metadata API.
- A universal risk score. Severity stays per-signal.
- Cross-ecosystem typosquat detection (a Rust crate named `express` is not a
  typosquat of the npm package).

## What is npm-shaped today

These are the seams to generalize. Each is small individually; the risk is
letting any of them leak into new ecosystems.

| Location | npm assumption |
|---|---|
| `PackageSpec` | no `ecosystem` field; parsing treats `@scope/name@1.0.0` as the only grammar |
| `PackageReport.ecosystem` | `&'static str`, hardcoded `"npm"` in `signals::report` |
| `registry.rs` | one packument shape: `dist-tags`, `maintainers`, `_npmUser`, `scripts`, `time` |
| `signals.rs` | install scripts, maintainer list, publisher, deprecation, repository are all assumed present |
| `typosquat.rs` | one global `POPULAR` list of npm names |
| `osv.rs` | `"ecosystem": "npm"` literal in the query body |
| `cache` keys | bare URLs and POST bodies; fine today, ambiguous once two registries share a path shape |
| CLI | `dep-vet npm <pkg>`, with `npm` as the only subcommand |

## Target architecture

### 1. `Ecosystem`

```rust
// model.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    CratesIo,
    Go,
}

impl Ecosystem {
    /// The string OSV expects in `package.ecosystem`.
    pub fn osv_name(self) -> &'static str;
    /// CLI subcommand and JSON value.
    pub fn cli_name(self) -> &'static str;
}
```

Parsing moves out of `PackageSpec::parse` into per-ecosystem parsers:
`PackageSpec::parse(ecosystem, input)`. npm keeps today's grammar
(`@scope/name@version`); PyPI uses `name==version` and `name[extra]==version`
(strip extras, ignore them for v1); crates uses `name@version`; Go accepts a
module path with optional `@version`, including pseudo-versions and `/v2` major
suffixes.

Rejection rules stay strict: no whitespace, no path traversal, no `%`, nothing
that changes the registry URL path unexpectedly. Every ecosystem gets the same
"never reaches the network" test that npm has.

### 2. `PackageSource`

```rust
// source/mod.rs
pub trait PackageSource {
    fn ecosystem(&self) -> Ecosystem;
    /// Resolve a spec to one version. Ranges are rejected with guidance.
    fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, SourceError>;
    /// Weekly downloads; `None` when the ecosystem has no such number.
    fn weekly_downloads(&self, name: &str) -> Option<u64>;
    /// Names used for typosquat comparison. Empty disables the signal.
    fn popular_names(&self) -> &'static [&'static str];
    /// Which signals this source can support at all.
    fn profile(&self) -> &'static Profile;
}
```

`PackageMeta` keeps its shape but two fields change meaning and must be
documented at the type level:

- `install_scripts: Vec<InstallScript>` becomes `execution: Vec<Execution>` where
  `Execution { when: ExecutionTime, mechanism: String, detail: String }` and
  `ExecutionTime` is `Install | Build | None`.
  - npm: `Install` (`preinstall`/`install`/`postinstall`).
  - crates.io: `Build` (`build.rs`).
  - PyPI: `Build` when only an sdist is published (PEP 517 backend runs on
    install), `None` when a wheel exists for the platform.
  - Go: none — the vector is empty **and** `Profile::execution_signals` is
    false, so the report does not imply a check happened.
- `publisher` is `Option<String>` and stays optional. PyPI has no equivalent of
  npm's `_npmUser`; crates.io has `published_by`; Go has none.

`Profile` is the honesty mechanism:

```rust
pub struct Profile {
    pub execution_signals: bool,
    pub maintainer_signals: bool,
    pub download_counts: bool,
    pub deprecation_signal: bool,   // npm deprecated, crates yanked, PyPI yanked
    pub typosquat_signals: bool,
    pub freshness_signal: bool,     // always true, but kept explicit
}
```

`signals::assess` takes the `Profile`. A signal whose profile flag is false
produces no finding, and the human report prints a line under "not checked
here" so the absence is visible. That line is part of the contract, not a
footer.

For v1 of each new ecosystem, prefer a false flag over a weak proxy. A rule
that cannot cite evidence does not ship (existing project rule).

### 3. Wiring

```
main.rs
  └─ Command::Npm | Pypi | Crates | Go  ->  Box<dyn PackageSource>
        ├─ NpmSource    (registry.npmjs.org packument)
        ├─ PypiSource   (pypi.org/pypi/{name}/json)
        ├─ CratesSource (crates.io/api/v1/crates/{name})
        └─ GoSource     (proxy.golang.org + deps.dev)
  └─ OsvClient::query(ecosystem.osv_name(), name, version)
  └─ signals::report(meta, downloads, advisories, profile, now)
```

Sources share `HttpClient` (agent, body limit, cache). No source builds its own
agent.

## Per-ecosystem notes

Treat every endpoint below as "verify before implementing". Record the actual
response size and shape in the source module's tests, the way npm's packument
was verified.

### PyPI

- Metadata: `GET https://pypi.org/pypi/{name}/json` (also per-version:
  `/pypi/{name}/{version}/json`). Keyless.
- Version resolution: `info.version`. `info.requires_python` matters for whether
  a wheel can be used, but do not guess the user's interpreter in v1.
- Execution surface: `urls[]` lists files for the version. If only `.tar.gz`
  exists, installation builds it and runs the backend. If a `.whl` exists, the
  install is a file copy. This is a weaker claim than npm's `postinstall`, so it
  maps to `Build`, not `Install`, and must not escalate to HIGH on its own.
- Maintainers: not exposed as a set. `info.author` / `info.author_email` are
  free text. Do **not** fabricate a maintainer-churn signal; set
  `maintainer_signals: false`.
- Deprecation/yank: per-file `yanked` and `yanked_reason`; project-level yank is
  surfaced through files. Report "this release is yanked".
- Downloads: pypistats (keyless, rate-limited, undocumented) or omit. Omitting
  is acceptable in v1; it only weakens typosquat ranking.
- Typosquat: seed list of top PyPI names, separate from npm's.
- OSV ecosystem: `PyPI`.

### crates.io

- Metadata: `GET https://crates.io/api/v1/crates/{name}`. **Requires a
  `User-Agent`**, same trap as the brief records.
- Version resolution: `versions[]` with `num`, `yanked`, `created_at`.
  `crate.max_version` is the default; `+` build metadata and pre-releases need
  the same "exact version or tag, not a range" rejection as npm.
- Execution surface: `build.rs` runs arbitrary code at build time. It is not
  install-time, but it is the closest analogue and the highest-value signal in
  this ecosystem. Map to `Build`.
- Maintainers: crate owners endpoint. Verify whether it is keyless before
  promising the signal; if it needs a token, set `maintainer_signals: false`.
- Deprecation: `yanked` per version.
- Downloads: `crate.downloads` (all-time) and recent fields; weekly may need a
  different endpoint. Mark `download_counts` true only if a weekly number is
  available; all-time counts skew typosquat ranking toward old packages.
- OSV ecosystem: `crates.io`.

### Go

Go is a deliberate redesign, not a port:

- Metadata: `https://proxy.golang.org/{module}/@v/{version}.info` and
  `@v/list`; `deps.dev` (`/v3/systems/go/packages/{module}`) for versions,
  licenses, and advisories. Module paths are case-sensitive and
  case-encoded (`!` prefix escaping) — get this right or requests 404.
- Version resolution: semantic versions plus pseudo-versions
  (`v0.0.0-20240101120000-abcdef123456`). `latest` and `+incompatible` exist.
  Reject ranges (`v1.2.x`, `>=1.2`) with the same guidance message.
- Execution surface: **none.** Modules do not run code at install. There is no
  equivalent of `postinstall` or `build.rs` in the module graph. The install-
  script signal does not exist here and must be printed as "not applicable",
  not as an empty check.
- What matters instead: typosquat distance on module paths (the dominant Go
  attack), abandoned-maintainer heuristics from deps.dev/VCS activity, and
  advisories.
- Downloads: none. `download_counts: false`; typosquat ranking uses an import-
  count proxy from deps.dev if it proves stable, otherwise a seed list.
- OSV ecosystem: `Go`. Note OSV expects the module path, not the repository URL.

## OSV across ecosystems

No new client. The only change is that `OsvClient::query` takes an ecosystem
string, and the cache key includes it. Advisory severity mapping, the
`/v1/vulns/{id}` hydration, the 25-advisory cap, and the INFO-on-failure rule
carry over unchanged.

One caveat to test per ecosystem: the Go and PyPI records use different
`database_specific` shapes (not every advisory has a `severity` label). The
existing fallback — an advisory without a label is a WARN — is the intended
behavior and must be covered by a fixture per ecosystem.

## Cache

- Keys become `{ecosystem}:{kind}:{identifier}` (for example
  `pypi:json:pkg==1.2.3`), with the POST body retained for OSV.
- TTL stays 24h. Per-ecosystem TTLs are not worth the complexity in v1.
- Stale fallback rules do not change: network errors and 5xx only; a 404 never
  falls back.
- Cache versioning: add a `schema` column (or a `PRAGMA user_version`). A cache
  written by an older binary must be ignored, not misread. This is the first
  thing the refactor should land, because changing key formats without it
  poisons existing caches.

## Report and JSON

- `ecosystem` becomes a real value instead of `"npm"`.
- Add `"not_checked": ["execution", "maintainers"]` to the JSON, and the
  matching line in the human report. Consumers must be able to tell "clean"
  from "not applicable".
- No schema version bump yet: adding fields is backward compatible. Document
  the fields in the README table instead of freezing a version.
- Exit codes do not change. A HIGH advisory still exits 2; a missing signal
  never raises severity.

## Testing strategy

1. **Contract tests per source.** One test module per ecosystem asserting the
   trait surface: resolves latest, resolves exact version, rejects ranges,
   rejects invalid names without network access, degrades on missing fields.
2. **Fixture-driven parsing.** JSON fixtures checked into the test file (not
   the network), plus one recorded live response summarized in a comment with
   its size.
3. **Shared fake server.** Generalize `tests/cli.rs` into a helper that serves
   any path → (status, body) map, so each ecosystem's end-to-end test is a
   routes table, not a new server.
4. **Hermetic proof stays mandatory.** `unshare -rn sh -c 'ip link set lo up &&
   cargo test'` must pass. Any test that reaches a real registry is a bug.
5. **Golden report.** One human report and one JSON report per ecosystem,
   asserted for structure (fields, ordering, "not checked" line), not exact
   strings.

## Phases

**Phase 0 — npm hardening (current, no new ecosystem).**
Finish the npm MVP: `dep-vet lock`, the GitHub Action, a download-ranked
popular-name list. Do not start Phase 1 until npm's report is the shape every
ecosystem should copy.

**Phase 1 — abstraction, npm-only.**
Introduce `Ecosystem`, `PackageSource`, `Profile`, cache namespacing, and the
`not_checked` output. Ship with only `NpmSource`. Acceptance: every existing
test passes unchanged except for the `report()` signature; `dep-vet npm`
output is byte-identical apart from the new "not checked" line, which is empty
for npm.

**Phase 2 — PyPI.**
`PypiSource` with freshness, yanked, sdist-build signal, typosquat seed, OSV.
Acceptance: `dep-vet pypi requests` and a known-vulnerable old release produce
correct exit codes; a wheel-only release shows no execution finding; the
maintainer line is absent, not empty.

**Phase 3 — crates.io.**
`CratesSource` with `build.rs`, yanked, downloads if weekly is available, owners
if keyless. Acceptance: a `build.rs` crate produces a Build finding; a yanked
version produces a deprecation finding.

**Phase 4 — Go.**
`GoSource` with module-path parsing (pseudo-versions, `/v2`, case escaping),
deps.dev, no execution signal, module-path typosquat. Acceptance: Go reports
include "execution: not applicable"; a typosquatted module path is HIGH.

Each phase is its own branch, merged only when the full gate is green, per
`AGENTS.md`.

## Risks

- **False positives** remain the top risk, and ecosystem mapping multiplies
  them. A `build.rs` finding on a popular crate must not read like npm's
  escalation rule; the wording has to be per-mechanism.
- **Signal drift in naming.** `install_scripts` is already wrong for crates;
  renaming it later gets expensive. Do the rename in Phase 1, while only npm
  exists.
- **Undocumented rate limits** on pypistats and crates.io owners. Cache or
  omit; never let a missing signal break a verdict.
- **Go's module-path grammar** is the easiest place to ship a URL-encoding bug.
  Escaping tests come before features.
- **The report gets crowded.** Four ecosystems' worth of findings in one format
  will tempt a summary line; resist adding a score.

## Open questions

1. `dep-vet pypi` subcommands vs `dep-vet --ecosystem pypi`: subcommands match
   the existing surface and get shell completion for free. Recommend
   subcommands.
2. PyPI extras (`requests[security]`): strip and warn, or reject? Recommend
   strip in v1; extras can pull different metadata and need their own spec.
3. Go module path vs package path: Go's security surface is the module, not the
   package. Confirm OSV matches on module paths for the queries we send.
4. Should `not_checked` be part of exit-code reasoning at all? Recommend no:
   absence of a check never changes the code, only the report.
