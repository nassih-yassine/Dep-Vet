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
<img alt="release" src="https://img.shields.io/github/v/release/nassih-yassine/Dep-Vet">
<img alt="license MIT" src="https://img.shields.io/badge/license-MIT-blue.svg">
<img alt="single static binary" src="https://img.shields.io/badge/binary-static%2C%20no%20runtime-success.svg">
<img alt="no telemetry" src="https://img.shields.io/badge/telemetry-none-success.svg">
<img alt="ecosystem npm" src="https://img.shields.io/badge/ecosystem-npm-cb3837.svg">
</p>

<code>dep-vet npm express@5.3.0</code>

</div>

---

`npm install` runs code, and so does a Python sdist build. `dep-vet` reads
public registry metadata and OSV advisories for **npm, PyPI, crates.io, Go modules, JSR, RubyGems, NuGet, Maven, and Composer**, then tells you
what a package will do at that moment: whether it runs install-time code, how
old it is, who published this version, whether its name is one typo away from a
package you trust, what vulnerabilities apply to this exact version, and whether
it is deprecated. Every finding links to the raw
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

Linux and macOS:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nassih-yassine/Dep-Vet/releases/latest/download/dep-vet-installer.sh | sh
```

Windows (PowerShell):

```powershell
irm https://github.com/nassih-yassine/Dep-Vet/releases/latest/download/dep-vet-installer.ps1 | iex
```

With a Rust toolchain, from source:

```sh
cargo install --git https://github.com/nassih-yassine/Dep-Vet.git
```

Releases are checksummed (`sha256.sum`) and built for Linux and macOS on
aarch64 and x86_64, plus Windows x86_64.

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

If the current directory or a parent contains `package-lock.json`, its dependency
names join the typosquat list, so a package one edit from something you already
use is flagged. `--no-local` ignores it.

### Allowlists

```toml
# .depvet.toml
[[allow]]
package = "crossenv"
finding = "typosquat"   # optional; omit to allow every finding
reason = "internal fork, reviewed 2026-11"
```

`dep-vet` reads the nearest `.depvet.toml` walking up from the working
directory, or the file passed to `--config`. An allowed finding stays in the
report as `[ALLOWED]` with its reason and evidence, and stops affecting the exit
code. A missing reason or an unknown finding id is a configuration error
(exit `3`), never a silent pass.

### Audit an installed tree

```sh
dep-vet audit package-lock.json      # npm
dep-vet audit requirements.txt       # PyPI, exact pins only
dep-vet audit Cargo.lock             # crates.io
dep-vet audit go.mod                 # Go
dep-vet audit poetry.lock            # PyPI via Poetry
dep-vet audit uv.lock                # PyPI via uv
dep-vet audit bun.lock               # Bun
dep-vet audit pnpm-lock.yaml         # pnpm
dep-vet audit yarn.lock              # Yarn classic and Berry
dep-vet audit deno.lock              # Deno: npm and JSR entries
dep-vet audit Gemfile.lock           # RubyGems
dep-vet audit packages.lock.json     # NuGet
dep-vet audit composer.lock          # Composer
dep-vet audit gradle.lockfile        # Gradle dependency locking
```

Vets **every** package the lockfile installs, not just the diff, and reports the
worst verdict. A cold run costs one audit per package (four at a time); warm
caches make a rerun instant. It exits `3` when any package could not be checked.

What each format contributes, and what it cannot:

| File | Audited | Reported as incomplete |
|---|---|---|
| `package-lock.json` v2/v3 | every `node_modules` entry | v1 lockfiles (upgrade with `npm install`) |
| `requirements*.txt` | `name==version` pins, extras stripped | unpinned lines, URLs, `-r`/`-e` options |
| `Cargo.lock` | registry packages | git dependencies (not on crates.io) |
| `go.mod` | `require` entries, blocks and single lines | unreadable require lines; `replace` is ignored |
| `poetry.lock` | PyPI packages | git/path/URL sources |
| `uv.lock` | PyPI packages, editable/virtual entries ignored | git/URL sources |
| `bun.lock` | `packages` tuples (JSON with comments) | unreadable entries |
| `pnpm-lock.yaml` | v5, v6, and v9 package keys; peer suffixes stripped | unrecognized keys |
| `yarn.lock` | classic and Berry entries | entries without a version; workspace links ignored |
| `deno.lock` | `npm` and `jsr` entries | JSR advisories, which OSV does not publish |
| `Gemfile.lock` | remote `GEM` specs | `PATH`/`GIT` sections; yanked versions are absent from the API |
| `packages.lock.json` | resolved dependencies for every target framework | unresolved entries; project references |
| `composer.lock` | `packages` and `packages-dev` | dev-only advisories are still reported |
| `gradle.lockfile` | `group:artifact:version` lines, including `buildscript-`/`settings-` variants | unlocked configurations; Gradle without dependency locking |

Typosquat comparison uses the seed list for a whole tree: every dependency would
resemble some other dependency.

### Watch mode

```sh
dep-vet watch package-lock.json     # or Cargo.lock, go.mod, requirements.txt, ...
```

Audits the lockfile once, then again every time it changes on disk. Saves are
debounced (300 ms), so an editor writing the file several times produces one
rerun. `Ctrl-C` stops it. Without an argument it watches the nearest
`package-lock.json`.

### Check a JSR package

```sh
dep-vet jsr @std/assert             # latest
dep-vet jsr @std/assert@1.0.19      # exact version
```

JSR gives versions, publish times, a GitHub repository, and an archived flag.
It has no owner list, download figure, install hooks, or OSV advisories; the
report lists those as `not checked`, and says advisory coverage is unavailable
instead of implying the package is clean.

### Check a PyPI package

```sh
dep-vet pypi requests              # latest
dep-vet pypi requests==2.31.0      # exact version
dep-vet pypi "requests[security]"  # extras are dropped in v1
```

PyPI exposes no maintainer set or download figure, so those appear under
`not checked` rather than being guessed. When a version has only an sdist, pip
builds it and runs the project's build backend: that is reported as a warning,
never as a high-risk install script.

### Check a crate

```sh
dep-vet crates serde             # latest stable
dep-vet crates serde@1.0.229     # exact version
```

crates.io exposes a publisher per version and an owner list, so publisher
agreement is checked. It does **not** expose the file list, so whether a crate
has a `build.rs` cannot be seen from metadata: execution is reported as
`not checked` rather than guessed. Yanked versions are warnings.

### Check a Go module

```sh
dep-vet go github.com/gin-gonic/gin            # default version
dep-vet go github.com/gin-gonic/gin@v1.9.1     # exact version
dep-vet go github.com/user/repo/v2             # major-version suffix
```

Go modules have no install hooks, no owner list, no download figure, and no
repository link in the module index, so those appear as `not checked`. What is
checked: advisories (OSV ecosystem `Go`), deprecation, publish times, and
module-path typosquatting.

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
  "hidden_advisories": 0,
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

`hidden_advisories` is non-zero when the advisory list was truncated at the
25-per-package cap; the report also carries an INFO finding saying so.

Timestamps are Unix seconds. `verdict` and `exit_code` are derived from the
findings, so consumers do not re-implement the severity rules. JSON output never
contains the wordmark or ANSI colors.

`dep-vet audit ... --json` returns `lockfile`, `packages`, `errors`, and the
derived `verdict`/`exit_code`.

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

Entries live for 24 hours and are deleted after 30 days, so the database stays
bounded (large packuments are stored whole). A network failure, 5xx, or 429
falls back to the stale entry, so a warmed cache keeps working offline; a 404
never falls back, because a deleted package must not look alive. `--no-cache`
bypasses the cache for one run. A cache written by an older schema is dropped
instead of misread.

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
pass with the findings visible in the comment. Very long reports are truncated
in the comment; the full output always lands in the job log.

The action installs the prebuilt binary for the `ref` input (default `v0.5.0`)
and falls back to building from source when that ref has no release. Pinning
`uses:` alone does not pin the binary: set `ref` to the tag you reviewed.

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
| Build from source | WARN | PyPI only: no wheel exists for this version, so installing runs the project's PEP 517 build backend as your user. |
| Advisories | High/Warn/Info from OSV | Known vulnerabilities for this exact version, one finding per vulnerability, linking to its OSV record and aliases. Records that share an alias (PYSEC/GHSA/CVE) are merged, with the highest severity kept. An advisory whose details cannot be fetched still surfaces as a warning. If OSV is unreachable, the report says so as an INFO finding instead of implying the package is clean. |
| Install scripts | WARN, HIGH when combined | `preinstall`/`install`/`postinstall` run during `npm install`. Combined with a fresh package, an unexpected publisher, or a typosquat name, this is the shape of a supply-chain attack. |
| Typosquat | HIGH at ≤1 edit or homoglyph, WARN at 2 | Levenshtein distance to a download-ranked list of npm names (union of ranked names and the carried-over hand seed) and, when a lockfile is available, to the dependency names you already have. Lookalikes are folded (`1`/`l`, `0`/`o`, `rn`/`m`); names under 4 characters are skipped to avoid noise. A package that is itself popular is never flagged for resembling something nearby (`preact` is not a `react` typo). |
| Fresh package | WARN | First publish less than 7 days ago: no track record. |
| Fresh version | INFO | Old package, version published in the last week. |
| Publisher not a maintainer | WARN | This version's publisher is absent from the current maintainer list, a proxy for ownership handoff. CI identities such as `GitHub Actions` are ignored. |
| Deprecated / yanked | WARN | The registry marks this version deprecated, or crates.io/PyPI mark it yanked; the message is shown verbatim. |
| No repository | INFO | No source repository declared, so the tarball cannot be traced to source. |

Every finding carries evidence, and a finding whose claim cannot be linked to a
raw source does not ship. Signals an ecosystem cannot support are reported as
`not_checked` (in JSON, omitted when everything ran) — absence never means
clean.

## Scope and limits

- **npm, PyPI, crates.io, Go, JSR, RubyGems, NuGet, Maven, and Composer**, for
  both `audit` and `lock`, including
  `bun.lock`, `pnpm-lock.yaml`, `yarn.lock`, `deno.lock`, `poetry.lock`, and
  `uv.lock`, `Gemfile.lock`, `packages.lock.json`, `composer.lock`,
  `gradle.lockfile`. JSR has no advisory source,
  so JSR reports say advisory coverage is unavailable. RubyGems has no owner
  list, weekly downloads, or install-time file data; yanked versions disappear
  from its API, so asking for one reports "not found" rather than "yanked".
  NuGet exposes no owners, downloads, repository, or build-time file data; its
  1900-01-01 "unknown" publish dates are ignored. Maven Central has no owners,
  downloads, repository, or deprecation concept, and no standard lockfile, so
  `dep-vet maven` only vets a single coordinate. Composer has maintainers,
  repository metadata, and an abandoned flag, but no install-time file list and
  no weekly download figure.
- **Missing signals are labelled, not guessed.** PyPI has no maintainer list or
  download count; crates.io has no file list, so `build.rs` cannot be detected;
  Go modules have no execution, owners, downloads, or repository link in the
  index. Those appear as `not checked`. If crates.io's owner endpoint fails, the
  report says "maintainer list unavailable" instead of implying agreement.
- **Typosquat context depends on what is on disk.** `dep-vet lock` compares
  against the base lockfile; `dep-vet npm` uses the nearest `package-lock.json`
  when one exists, and `--no-local` turns that off. Either way the seed list is
  also consulted.
- **Advisories describe this version, not your tree.** `dep-vet npm` answers for
  the package you named, `dep-vet lock` for the `name@version` pairs a change
  adds, and `dep-vet audit` for every installed package — never for the
  transitive install scripts a package would execute.
- **Gradle needs dependency locking.** `gradle.lockfile` (and its `buildscript-`
  and `settings-` variants) is audited as Maven coordinates; a build that never
  ran `--write-locks` has no file to check, and dep-vet will not invent one.
- Not an SBOM generator or a Dependabot replacement.
- No LLM in the verdict, no risk score, no hosted service, no accounts.
- One batch query plus one request per advisory on a cold cache, at most 8 in
  flight; bounded at 25 advisories per run, and the report says how many were
  skipped. Lockfile audits run 4 packages at a time.
- The npm popular-name list is download-ranked; a weekly workflow runs
  `scripts/refresh-popular-npm.py`, opens a bot PR, and auto-merges after CI.
  PyPI, crates.io, Go, JSR, RubyGems, NuGet, Maven, and Composer seeds are
  curated.

## Development

```sh
cargo test                              # unit + CLI tests
cargo test signals::                    # one signal's tests
cargo test --test cli fresh_package     # one end-to-end case
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Enable both git hooks once per clone:

```sh
git config core.hooksPath .githooks
```

- **pre-commit** vets staged lockfiles. Existing files are diffed against `HEAD`
  with `dep-vet lock`; a newly added lockfile is audited in full. High risk (2)
  or an incomplete check (3) blocks the commit; warnings (1) print and pass.
  Uses `dep-vet` from PATH, or `cargo run --quiet --` when it is not installed.
- **pre-push** runs `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, and `cargo test`. It checks the working tree, so an unformatted
  scratch edit also blocks the push — commit or revert first.

`--no-verify` bypasses either hook (for a commit or a push respectively), and
should stay rare enough to notice.

Tests never touch the public registry: `tests/cli.rs` starts a local HTTP server
and points the binary at it through `DEPVET_REGISTRY_BASE`, so encoding, status
handling, and output are exercised end to end.

### Layout

```
src/cli.rs        clap surface
src/model.rs      PackageSpec, Severity, Finding, PackageReport
src/lockfile.rs   npm/PyPI/Cargo/Go lockfile parsing, git-ref diff
src/registry.rs   npm packument fetch + parsing, download counts
src/pypi.rs       PyPI JSON API, sdist-only detection, yanked releases
src/crates.rs     crates.io API, owner list, yanked releases
src/go.rs         Go module index, versions, publish times, deprecation
src/jsr.rs        JSR versions, repository, archived flag
src/rubygems.rs   RubyGems versions, timestamps, source URL, yank flag
src/nuget.rs      NuGet flat container, registration times, deprecation
src/osv.rs        advisory IDs from querybatch, details per advisory
src/http.rs       one agent, body limit, cache read/write policy
src/cache.rs      SQLite cache with TTL and stale fallback
src/signals.rs    the rules: metadata in, findings out
src/typosquat.rs  Levenshtein, homoglyph folding, per-ecosystem candidate lists
src/branding.rs   the wordmark in --help and interactive reports
src/report.rs     human and JSON rendering
src/date.rs       RFC 3339 parsing, no date crate
src/main.rs       wiring, color choice, exit codes
```

Feature work happens on a branch and merges once the push gate is green. Bug
fixes start with a failing test, as the `GitHub Actions` publisher false positive
did.

## Roadmap

1. Remaining ecosystems and lockfile formats (e.g. Gradle).

## License

MIT. See [LICENSE](LICENSE).
