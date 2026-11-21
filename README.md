# dep-vet

**Check a package's risk before it enters your lockfile.**

`npm install` runs code. `dep-vet` reads public registry metadata and tells you
what a package will do at that moment: whether it runs install scripts, how old
it is, who published this version, whether its name is one typo away from a
popular package, and whether it is deprecated. Every finding links to the raw
evidence it came from.

```
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

## Why

A scanner that runs after the lockfile is written answers "is this vulnerable?".
The moment that matters is earlier: *should this tarball run on my machine at
all?* Attacks like the `axios@1.14.1` compromise added a single dependency whose
only job was a `postinstall` hook, invisible in `package.json` and transitive.
`dep-vet` puts that fact, plus the package's history, in front of you before you
type `npm install`.

## Install

From source:

```sh
cargo install --git https://github.com/nassih-yassine/Dep-Vet.git
```

Prebuilt binaries and the GitHub Action are on the roadmap.

## Usage

### Vet a package

```sh
dep-vet npm express              # latest
dep-vet npm express@5.3.0        # exact version
dep-vet npm express@next         # dist-tag
dep-vet npm @types/node          # scoped names
```

Vetting is read-only: `dep-vet` never installs the package, never writes a
lockfile, and never executes package code. It fetches the registry packument and
the weekly download count, then applies local rules.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | clean, or informational findings only |
| `1`  | warnings: review before adding |
| `2`  | high risk: install scripts plus another signal, or a near-identical name |
| `3`  | the check could not run (bad input, unknown subcommand or flag, network failure, unreadable response) |

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
findings, so consumers do not have to re-implement the severity rules.

### Color

Color is enabled only on a terminal. `--no-color` and `NO_COLOR` turn it off,
`FORCE_COLOR` turns it on.

### Registry overrides

For mirrors, proxies, and tests:

```sh
DEPVET_REGISTRY_BASE=https://registry.npmjs.org dep-vet npm express
DEPVET_DOWNLOADS_BASE=https://api.npmjs.org/downloads/point dep-vet npm express
```

## What it checks

| Signal | Severity | Meaning |
|--------|----------|---------|
| Install scripts | WARN, HIGH when combined | `preinstall`/`install`/`postinstall` run during `npm install`. Combined with a fresh package, an unexpected publisher, or a typosquat name, this is the shape of a supply-chain attack. |
| Typosquat | HIGH at ≤1 edit or homoglyph, WARN at 2 | Levenshtein distance to a curated list of popular names, after folding lookalikes (`1`/`l`, `0`/`o`, `rn`/`m`). Names shorter than 4 characters are skipped to avoid noise. |
| Fresh package | WARN | First publish less than 7 days ago: no track record. |
| Fresh version | INFO | Old package, version published in the last week. |
| Publisher not a maintainer | WARN | This version's publisher is absent from the current maintainer list, a proxy for ownership handoff. CI identities such as `GitHub Actions` are ignored. |
| Deprecated | WARN | The registry carries a deprecation notice; the message is shown verbatim. |
| No repository | INFO | No source repository declared, so the tarball cannot be traced to source. |

Every finding carries evidence, and a finding whose claim cannot be linked to a
raw source does not ship.

## What it does not do

- Not a CVE scanner. OSV advisories are the next feature, not this release.
- Not an SBOM generator or a Dependabot replacement.
- No LLM in the verdict, no risk score, no hosted service, no accounts.
- No cache yet: each run makes two HTTP requests. Expected in v0.2.
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

Tests never touch the public registry. `tests/cli.rs` starts a local HTTP server
and points the binary at it through `DEPVET_REGISTRY_BASE`, so encoding, status
handling, and output are all exercised end to end.

Layout:

```
src/cli.rs        clap surface
src/model.rs      PackageSpec, Severity, Finding, PackageReport
src/registry.rs   packument fetch + parsing, download counts
src/signals.rs    the rules: metadata in, findings out
src/typosquat.rs  Levenshtein, homoglyph folding, popular-name seed
src/report.rs     human and JSON rendering
src/date.rs       RFC 3339 parsing, no date crate
src/main.rs       wiring, color choice, exit codes
```

Feature work happens on a branch and merges only after review. Bug fixes start
with a failing test, as the `GitHub Actions` publisher false positive did.

## Roadmap

1. OSV advisories via `POST /v1/querybatch`, grouped by severity.
2. Offline cache (SQLite) so repeated and CI runs do not refetch.
3. `dep-vet lock <lockfile>`: diff new dependencies against a base ref.
4. GitHub Action wrapping `lock` with a sticky PR comment.
5. Popular-name list built from download counts instead of a seed.
6. PyPI and crates.io.

## License

MIT
