<div align="center">

<pre>
    █                                 █
    █                                ███
 ████  ███  ████        █   █  ███    █
█   █ █   █ █   █  ███  █   █ █   █   █
█   █ █████ ████        █   █ █████   █
█   █ █     █            █ █  █       █
 ████  ███  █             █    ███    ██
</pre>

**Check a package's risk before it enters your lockfile.**

<p>
<img alt="ci" src="https://github.com/nassih-yassine/Dep-Vet/actions/workflows/ci.yml/badge.svg">
<img alt="license MIT" src="https://img.shields.io/badge/license-MIT-blue.svg">
<img alt="single static binary" src="https://img.shields.io/badge/binary-static%2C%20no%20runtime-success.svg">
<img alt="no telemetry" src="https://img.shields.io/badge/telemetry-none-success.svg">
<img alt="ecosystem npm" src="https://img.shields.io/badge/ecosystem-npm-cb3837.svg">
</p>

<code>dep-vet npm express@5.3.0</code>

</div>

---

`npm install` runs code. `dep-vet` reads public registry metadata and OSV
advisories, then tells you what a package will do at that moment: whether it
runs install scripts, how old it is, who published this version, whether its
name is one typo away from a popular package, what vulnerabilities apply to this
exact version, and whether it is deprecated. Every finding links to the raw
evidence it came from.

```console
$ dep-vet npm crossenv
npm/crossenv@0.0.2-security

  verdict      HIGH (exit 2)
  first seen   2017-07-19
  published    2017-08-02
  downloads    2,039/week
  maintainers  npm
  repository   https://github.com/npm/security-holder.git

  1 finding

  [HIGH]  name is close to a popular package
        'crossenv' is 1 edit(s) away from the popular package 'cross-env'
        this package: crossenv
        -> https://www.npmjs.com/package/crossenv/v/0.0.2-security
        popular package: cross-env
        -> https://www.npmjs.com/package/cross-env
```

No account, no API key, no telemetry, no score out of 100. One binary.

## Why before install

| | dep-vet | `npm audit` | Dependabot |
|---|---|---|---|
| Question | should this tarball run on my machine? | is an installed version vulnerable? | is an installed dependency outdated or vulnerable? |
| Moment | before `npm install` | after install | after commit |
| Input | a package name you are considering | a lockfile | a repository |

The gap is the moment trust is granted. The `axios@1.14.1` compromise added a
single dependency whose only job was a `postinstall` hook — invisible in
`package.json`, transitive, and already running by the time an audit exists.

## Install

From source:

```sh
cargo install --git https://github.com/nassih-yassine/Dep-Vet.git
```

Prebuilt binaries and the GitHub Action are on the roadmap.

## Usage

```sh
dep-vet npm express              # latest
dep-vet npm express@5.3.0        # exact version
dep-vet npm express@next         # dist-tag
dep-vet npm @types/node          # scoped names
```

Vetting is read-only: `dep-vet` never installs the package, never writes a
lockfile, and never executes package code. It fetches the registry packument,
the weekly download count, and the OSV advisory list, then applies local rules.

### Audit a lockfile change

```sh
dep-vet lock package-lock.json --base main
```

Reads the lockfile now and the same file at `main`, then vets every package the
change adds. A version bump counts as new: the new tarball has not been reviewed.
Unchanged packages are never fetched.

```console
$ dep-vet lock package-lock.json --base HEAD
package-lock.json vs HEAD

  1 new package

  crossenv@0.0.2-security                      HIGH
...
  verdict HIGH (exit 2)
```

`package-lock.json` v2/v3 only. A v1 lockfile is rejected with the upgrade
command rather than guessed at. If any added package cannot be checked — an
unpublished version, a network failure — the report lists it and exits `3`,
because an incomplete audit must not read as clean.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | clean, or informational findings only |
| `1`  | warnings: review before adding |
| `2`  | high risk: install scripts plus another signal, or a near-identical name |
| `3`  | the check could not run or could not finish (bad input, unknown subcommand, network failure, unreadable response, a lockfile package that could not be fetched) |

`3` exists so CI can tell "this package is risky" from "the scanner broke or was
called wrong". clap's own exit code for usage errors is `2`, which would read as
"high risk", so parse failures are remapped to `3`; `--help` and `--version`
still exit `0`.

### JSON

```sh
dep-vet npm crossenv --json
```

```json
{
  "ecosystem": "npm",
  "name": "crossenv",
  "version": "0.0.2-security",
  "weekly_downloads": 2039,
  "maintainers": ["npm"],
  "findings": [
    {
      "id": "typosquat",
      "severity": "high",
      "title": "name is close to a popular package",
      "detail": "'crossenv' is 1 edit(s) away from the popular package 'cross-env'",
      "evidence": [
        {
          "label": "popular package",
          "value": "cross-env",
          "url": "https://www.npmjs.com/package/cross-env"
        }
      ]
    }
  ],
  "verdict": "high",
  "exit_code": 2
}
```

Timestamps are Unix seconds. `verdict` and `exit_code` are derived from the
findings, so consumers do not re-implement the severity rules. JSON output never
contains the wordmark or ANSI colors.

`dep-vet lock ... --json` returns the same per-package objects plus the diff:

```json
{
  "lockfile": "package-lock.json",
  "base": "main",
  "new_packages": [{ "name": "...", "findings": [] }],
  "errors": [{ "package": "ghost@1.0.0", "message": "package 'ghost' was not found on npm" }],
  "verdict": "high",
  "exit_code": 2
}
```

### Cache

Responses are cached in SQLite at `~/.cache/dep-vet/http-cache.db` (or
`$XDG_CACHE_HOME/dep-vet`). A warm run makes zero network calls:

```console
$ time dep-vet npm lodash@4.17.15
real    0m0.009s
```

Entries live for 24 hours. A network failure or 5xx falls back to the stale
entry, so a warmed cache keeps working offline; a 404 never falls back, because
a deleted package must not look alive. `--no-cache` bypasses the cache for one
run.

| Variable | Effect |
|---|---|
| `DEPVET_CACHE_DIR` | Where the cache database lives |
| `DEPVET_CACHE_TTL_SECONDS` | Entry lifetime, default `86400` |
| `DEPVET_NO_CACHE` | Disable the cache entirely |

### GitHub Action

A reusable workflow reviews the lockfile change on every pull request and keeps
one comment updated with the report:

```yaml
name: dependency review
on: pull_request

jobs:
  dep-vet:
    uses: nassih-yassine/Dep-Vet/.github/workflows/dep-vet.yml@main
    permissions:
      contents: read
      pull-requests: write
```

It diffs the lockfile against `origin/<base>`, comments the report, and fails
the job on high risk (exit 2) or an incomplete audit (exit 3). Warnings (exit 1)
pass with the findings visible in the comment. Because there are no release
binaries yet, the action builds dep-vet from source — expect roughly a minute
and a half per run.

### Color

Color is enabled only on a terminal. `--no-color` and `NO_COLOR` turn it off,
`FORCE_COLOR` turns it on.

### Registry and API overrides

For mirrors, proxies, and tests:

```sh
DEPVET_REGISTRY_BASE=https://registry.npmjs.org dep-vet npm express
DEPVET_DOWNLOADS_BASE=https://api.npmjs.org/downloads/point dep-vet npm express
DEPVET_OSV_BASE=https://api.osv.dev dep-vet npm express
```

## Signals

| Signal | Severity | Meaning |
|--------|----------|---------|
| Advisories | High/Warn/Info from OSV | Known vulnerabilities for this exact version, one finding per advisory, linking to its OSV record and CVE aliases. An advisory whose details cannot be fetched still surfaces as a warning. If OSV is unreachable, the report says so as an INFO finding instead of implying the package is clean. |
| Install scripts | WARN, HIGH when combined | `preinstall`/`install`/`postinstall` run during `npm install`. Combined with a fresh package, an unexpected publisher, or a typosquat name, this is the shape of a supply-chain attack. |
| Typosquat | HIGH at ≤1 edit or homoglyph, WARN at 2 | Levenshtein distance to a curated list of popular names, after folding lookalikes (`1`/`l`, `0`/`o`, `rn`/`m`). Names shorter than 4 characters are skipped to avoid noise. |
| Fresh package | WARN | First publish less than 7 days ago: no track record. |
| Fresh version | INFO | Old package, version published in the last week. |
| Publisher not a maintainer | WARN | This version's publisher is absent from the current maintainer list, a proxy for ownership handoff. CI identities such as `GitHub Actions` are ignored. |
| Deprecated | WARN | The registry carries a deprecation notice; the message is shown verbatim. |
| No repository | INFO | No source repository declared, so the tarball cannot be traced to source. |

Every finding carries evidence, and a finding whose claim cannot be linked to a
raw source does not ship.

## Scope and limits

- **npm only.** Bun, pnpm, and yarn install from the same registry, so package
  vetting is accurate for them; lockfile commands and manager-specific script
  policy are not implemented.
- **Advisories describe this version, not your tree.** `dep-vet npm` answers for
  the package you named; `dep-vet lock` covers only the `name@version` pairs the
  lockfile change adds, not the pre-existing tree.
- **Lockfiles:** npm `package-lock.json` v2/v3 only. Yarn, pnpm, and bun
  lockfiles are not parsed yet.
- Not an SBOM generator or a Dependabot replacement.
- No LLM in the verdict, no risk score, no hosted service, no accounts.
- One batch query plus one request per advisory on a cold cache; bounded at 25
  advisories per run, and the report says how many were skipped.
- The popular-name list is a curated seed, not a download ranking.

## Development

```sh
cargo test                              # unit + CLI tests
cargo test signals::                    # one signal's tests
cargo test --test cli fresh_package     # one end-to-end case
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Enable the pre-push gate once per clone:

```sh
git config core.hooksPath .githooks
```

It runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
`cargo test` before anything leaves the machine. It checks the working tree, so
an unformatted scratch edit also blocks the push — commit or revert first.
`git push --no-verify` bypasses it, and should stay rare enough to notice.

Tests never touch the public registry: `tests/cli.rs` starts a local HTTP server
and points the binary at it through `DEPVET_REGISTRY_BASE`, so encoding, status
handling, and output are exercised end to end.

### Layout

```
src/cli.rs        clap surface
src/model.rs      PackageSpec, Severity, Finding, PackageReport
src/lockfile.rs   package-lock v2/v3 parsing, git-ref diff
src/registry.rs   packument fetch + parsing, download counts
src/osv.rs        advisory IDs from querybatch, details per advisory
src/http.rs       one agent, body limit, cache read/write policy
src/cache.rs      SQLite cache with TTL and stale fallback
src/signals.rs    the rules: metadata in, findings out
src/typosquat.rs  Levenshtein, homoglyph folding, popular-name seed
src/branding.rs   the wordmark in --help and interactive reports
src/report.rs     human and JSON rendering
src/date.rs       RFC 3339 parsing, no date crate
src/main.rs       wiring, color choice, exit codes
```

Feature work happens on a branch and merges once the push gate is green. Bug
fixes start with a failing test, as the `GitHub Actions` publisher false positive
did.

## Roadmap

1. Prebuilt binaries via `cargo-dist`, so the GitHub Action stops compiling
   from source and users stop needing a Rust toolchain.
2. Popular-name list built from download counts instead of a seed.
3. PyPI, crates.io, and Go. The design is kept locally (`docs/`), not published.
4. Advisory lookups for the whole installed tree, not one package.

## License

MIT. See [LICENSE](LICENSE).
