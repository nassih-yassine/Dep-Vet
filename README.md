<div align="center">

<pre>
██████╗ ███████╗██████╗       ██╗   ██╗███████╗████████╗
██╔══██╗██╔════╝██╔══██╗      ██║   ██║██╔════╝╚══██╔══╝
██║  ██║█████╗  ██████╔╝█████╗██║   ██║█████╗     ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════╝╚██╗ ██╔╝██╔══╝     ██║
██████╔╝███████╗██║             ╚████╔╝ ███████╗   ██║
╚═════╝ ╚══════╝╚═╝              ╚═══╝  ╚══════╝   ╚═╝

        ┌────────────────────────────────────────────────┐
        │                                                │
        │       THE DEPENDENCY TRUST PROTOCOL             │
        │                                                │
        │   ◈  INSPECT       Dependency intelligence     │
        │   ◈  ANALYZE       Malicious code detection    │
        │   ◈  VERIFY        Publisher provenance        │
        │   ◈  DIFF          Release behavior changes    │
        │   ◈  ENFORCE       Supply-chain security       │
        │                                                │
        └────────────────────────────────────────────────┘

        ZERO BLIND TRUST. FULL SUPPLY-CHAIN VISIBILITY.

        [ SYSTEM READY ]  [ RUST POWERED ]  [ SECURITY FIRST ]
</pre>

**Check a package's risk before it enters your lockfile.**

<p>
<img alt="ci" src="https://github.com/nassih-yassine/Dep-Vet/actions/workflows/ci.yml/badge.svg">
<img alt="release" src="https://img.shields.io/github/v/release/nassih-yassine/Dep-Vet">
<img alt="license MIT" src="https://img.shields.io/badge/license-MIT-blue.svg">
<img alt="no runtime" src="https://img.shields.io/badge/runtime-none%20(linux%20musl%3A%20static)-success.svg">
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

Releases are checksummed (`sha256.sum`), carry SLSA provenance attestations,
and are built for Linux (glibc and static musl), macOS (aarch64 and x86_64),
and Windows x86_64.

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

Archive inspection is configured in the same file:

```toml
[inspect]
max_download_mb = 25      # default
max_total_mb = 100
max_entries = 10000
max_file_mb = 5
max_decompressed_mb = 200
disabled_rules = ["PY-IMPORT-001"]
```

A disabled rule id must be one dep-vet knows, and every cap must be greater than
zero; a typo is a configuration error (exit `3`), never a silent no-op.

`dep-vet` reads the nearest `.depvet.toml` walking up from the working
directory, or the file passed to `--config`. An allowed finding stays in the
report as `[ALLOWED]` with its reason and evidence, and stops affecting the exit
code. A missing reason or an unknown finding id is a configuration error
(exit `3`), never a silent pass.

### Audit an installed tree

```sh
dep-vet audit package-lock.json      # npm
dep-vet audit requirements.txt       # PyPI, exact pins only
dep-vet audit Pipfile.lock           # PyPI via Pipenv
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
dep-vet audit packages.config        # legacy NuGet
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
| `Pipfile.lock` | `default` and `develop` pins | path/git/URL entries, `*` versions |
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
| `packages.config` | `<package id version />` elements | elements without a version; unrelated XML |
| `composer.lock` | `packages` and `packages-dev` | dev-only advisories are still reported |
| `gradle.lockfile` | `group:artifact:version` lines, including `buildscript-`/`settings-` variants | unlocked configurations; Gradle without dependency locking |

### What to do about a finding

Reports with advisories end with the fix, not just the problem:

```console
$ dep-vet audit composer.lock

  what to do

    guzzlehttp/guzzle 7.9.2    → 7.14.2   fixes GHSA-94pj-82f3-465w, ... (+6)
    crossenv 0.0.2-security    → cross-env
```

`fixed in` is the version OSV says fixes the advisory; the advisory ids point
back to the linked findings above. When no fix was published the line says so; when OSV would not return
the advisory's details it says `fix unknown`, never "no fix". `newest` is a
separate hint and never claims the new version is safe. A lookalike name
suggests the package it resembles, never a version. Advice never changes the
verdict or the exit code, and packages with no advisory or lookalike finding get
no line.

Typosquat comparison uses the seed list for a whole tree: every dependency would
resemble some other dependency.

### Inspect a release archive

Metadata cannot show what a release actually contains. `inspect` downloads the
archive, verifies its checksum, extracts it in memory, and scans source text:

```sh
dep-vet inspect npm lodash@4.17.20
dep-vet inspect pypi flask==2.0.0
dep-vet inspect maven org.slf4j:slf4j-api@2.0.17   # sources jar when published
dep-vet inspect nuget Newtonsoft.Json@12.0.1      # compiled: reports that
```

For NuGet, a `.signature.p7s` entry is reported as `signature: file present
(not verified)`. That is presence, not a valid signature, and unsigned packages
simply omit the line.

Nothing is executed and nothing is extracted to disk. Downloads with a known
checksum are cached for 30 days and re-verified before use; unverified archives
are never cached, and `--no-cache` always re-downloads. Limits are 25 MB
compressed, 100 MB uncompressed, 200 MB decompressed, 10,000 entries, and 5 MB
per file. A gzip or zip stream that expands past its cap is stopped while
reading and reported as HIGH `archive-decompression-bomb`; it is never scanned
partially and called clean. Entries
with absolute paths, `..`, symlinks, or hardlinks are skipped. A checksum
mismatch is a HIGH finding, not a warning.

A cap that stops the scan is disclosed as `archive-partially-scanned`: WARN when
a skipped path looks like source code, INFO otherwise, naming the skipped files.
A partial scan is never presented as a clean one, in `inspect` or `diff`.

Rules are deliberately conservative: one suspicious API call is a WARN, and
only a combination (network plus credential access in one file, or an encoded
payload passed to `eval`) reaches HIGH. Comments are stripped per language
family (`//` and `/* */` for JS/TS/Go/Rust/PHP, `#` for Python/shell/Ruby)
without removing code after `*/`, string literals are respected so a URL is not
mistaken for a comment, and regex literals are skipped so `/[//]/` cannot open a
comment. Shell `#` is a comment only at line start or after whitespace, so `$#`
and `${#v}` stay code. Patterns run over the whole file, so a call split across
lines still matches. Source extensions are scanned even when the bytes are not
valid UTF-8; only files that are not source are treated as binary. The 16 starter rules cover JavaScript
(dynamic execution, child processes, credential paths, encoded payloads),
Python (exec/eval, dynamic imports, shell calls, encoded payloads), shell
pipe-to-shell, Rust `build.rs`, Go (exec, network plus environment access), and
PHP (exec family, encoded payloads). Every finding carries a description, a
recommendation, and at least one reference link. Maven jars and NuGet packages
contain compiled artifacts, so their source analysis is reported as not
checked; JSR archives are not available yet.

### Compare two releases

```sh
dep-vet diff npm lodash@4.17.20 lodash@4.17.21
```

Both archives are fetched, verified, and compared by file content: added,
removed, and modified paths, plus rule findings that appear or disappear. A
newly added shell script or shebang file gets its own warning, because that is
where install-time behaviour usually enters. For npm it also diffs the
`preinstall`/`install`/`postinstall` commands themselves: a changed hook is WARN,
and HIGH when the new command fetches or decodes code. Newly shipped binary
files are listed as INFO, since they cannot be read as text. The diff is
text-based; a minified rewrite can look large without being suspicious, and
line numbers shift, so rule findings are matched by rule and file, not line.

### Release transitions

A compromised package rarely looks like a typosquat. The exploitable moment is
a release that changes what the package runs or pulls in, and registry metadata
describes it:

- **Dormant then published** (INFO): this version arrived in the last 30 days
  after at least a year with no release. Every ecosystem.
- **Install scripts changed** (WARN, HIGH when the new command runs inline
  code or fetches and decodes it): npm only, compared with the previous release,
  so a package that always had a build script is not blamed. Commands are
  tokenised, so `node scripts/evaluate.js` is a normal build step while
  `node -e`, `python3 -c`, `perl -e`, `ruby -e`, `php -r`, `bash/sh -c` with a
  URL, `curl`, `wget`, `nc`, `base64`, `powershell`, `pwsh`, `iex`, `iwr`,
  `irm`, `certutil`, `bitsadmin`, and `mshta` are execution patterns. Commands
  are matched by basename after dropping `.exe`/`.cmd`/`.bat`, so
  `powershell.exe`, `/usr/bin/curl`, and `C:\Windows\System32\curl.exe` count.
- **Dependencies added** (INFO, WARN when an added name looks like a typo):
  npm, Composer, NuGet, and — for releases inside the 30-day window — PyPI and
  crates.io.
- **Publisher changed** (INFO): a different existing maintainer shipped this
  version. A brand-new account is the stronger "not a maintainer" warning.
- **Release burst** (INFO): five or more releases inside 30 days on a package
  with history.
- **Repository changed** (INFO): the source repository differs from the previous
  release. Renames are common, so this is context, not a verdict.
- **Provenance dropped** (WARN): the previous release carried an attestation and
  this one does not, which usually means a publishing-pipeline change.

History is only fetched for versions published in the last 30 days; older
releases are covered by advisories and cost no extra requests. This still
cannot read the new version's code: a same-publisher release with no new
scripts or dependencies passes until an advisory exists.

### Provenance

An audit says whether a release publishes provenance; `inspect npm` can verify
it. Presence is reported for:

- **npm** — an attestation is present when the version publishes a provenance
  attestation (`dist.attestations`).
- **PyPI** — present when the Integrity API serves provenance for the release's
  first file (a HEAD request).
- **Everything else** — `unavailable`; these registries publish no provenance
  this tool can read.

For npm, dep-vet reads the attestation during an audit: it compares the in-toto
subject digest with the tarball checksum and reports the SLSA predicate's
claimed builder, workflow, source repository, and commit. A subject mismatch is
HIGH, because the tarball is then not the one that was attested. If the claimed
source repository differs from package metadata, that is an INFO finding. The
claims are labelled `(claimed)`.

`dep-vet inspect npm <pkg>@<version>` goes further: with the tarball in hand it
verifies the Sigstore bundle **offline** against the trusted root embedded in
the binary. A passing result means the DSSE signature, Fulcio certificate
chain, certificate transparency entry, and Rekor inclusion all verified, and
the bundle names those exact bytes. The report shows the signer identity and
OIDC issuer. Bundles signed with a managed key instead of a Fulcio certificate
are reported as `not verified` with the reason: they cannot be checked without
that key. Nothing is fetched to verify.

In an audit, `present` means the attestation exists, **not** that its signature
was verified; `inspect npm` is where verification happens. `missing` is not
suspicious on its own: most packages do not publish provenance.

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

### Check a Maven artifact

```sh
dep-vet maven org.slf4j:slf4j-api           # latest stable
dep-vet maven org.slf4j:slf4j-api@2.0.17    # exact version
dep-vet maven androidx.core:core-ktx        # Google Maven, transparently
```

Maven Central and Google Maven are both read. AndroidX, the Android Gradle
Plugin, Firebase, and Play artifacts live on Google Maven, so those coordinates
are looked up there first and everything else goes to Central, falling back to
Google when the artifact is not there. Google publishes no timestamps, so those
reports list `freshness` as `not checked`, and they carry an INFO note that OSV
only indexes Maven Central. Maven has no owner list, download figure, source
repository, or deprecation concept, and no standard lockfile of its own.

### Check an Android dependency

Android projects are audited through Gradle's dependency locking:

```kotlin
// app/build.gradle.kts
configurations
    .matching { it.name.endsWith("RuntimeClasspath") || it.name.endsWith("CompileClasspath") }
    .configureEach { resolutionStrategy.activateDependencyLocking() }
```

```sh
./gradlew :app:dependencies --write-locks
dep-vet audit app/gradle.lockfile
```

Remove the block and the next build rewrites the lockfile empty. If the
Gradle output contains `FAILURE`, lock only the configurations that resolve.

### Check a RubyGems gem

```sh
dep-vet gem rack                 # latest
dep-vet gem rack@3.2.9           # exact version
```

RubyGems exposes versions, publish times, and a source URL. It has no owner
list, weekly download figure, or install-time file list. Yanked versions
disappear from its API, so asking for one reports "not found" rather than
"yanked", and `Gemfile.lock` platform suffixes resolve to the registry number.

### Check a NuGet package

```sh
dep-vet nuget Newtonsoft.Json           # latest stable
dep-vet nuget Newtonsoft.Json@13.0.1    # exact version
```

NuGet ids are case-insensitive, so the API path is lowercased while the report
keeps the caller's casing for advisory matching. There is no owner list,
download figure, repository, or build-time file data. `1900-01-01` is NuGet's
"unknown" publish date and is filtered out. Both `packages.lock.json` and
legacy `packages.config` are audited.

### Check a Composer package

```sh
dep-vet composer monolog/monolog           # latest
dep-vet composer monolog/monolog@3.13.0    # exact version
```

Packagist supplies versions, publish times, maintainers, a source repository,
and an abandoned flag. It has no install-time file list, and its download figure
is monthly, so the weekly download signal stays `not checked`. `composer.lock`
audits both `packages` and `packages-dev`.

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
`$XDG_CACHE_HOME/dep-vet`; on Windows, `%LOCALAPPDATA%\dep-vet`). A warm run makes zero network calls:

```console
$ time dep-vet npm lodash@4.17.15
real    0m0.009s
```

Entries live for 24 hours and are deleted after 30 days, so the database stays
bounded (large packuments are stored whole). A network failure, 5xx, or 429
falls back to the stale entry, so a warmed cache keeps working offline; a 404
never falls back, because a deleted package must not look alive. Advisory
answers are the exception: they are used only up to 24 hours past their fetch
time, and serving one adds an INFO `advisories-stale` finding with the age of the
oldest stale answer, whether it came from the batch or an advisory detail. An
older advisory answer is refused, so the normal "advisory check unavailable"
finding appears instead of week-old data passing as today's. `--no-cache`
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
pass with the findings visible in the report. Very long reports are truncated in
the comment; the full output always lands in the job log **and the step
summary**, so a read-only token (Dependabot and fork PRs) only loses the comment
and emits a warning, never the report or dep-vet's exit code.

`lockfile` and `base` are passed as quoted environment values, so paths with
spaces and an explicit base revision work. The action installs the prebuilt
binary for the `ref` input (default `v0.11.0`) and falls back to a source build
when that ref has no release; a `vX.Y.Z` ref is installed with `--tag`, other
refs with `--branch`. Pinning `uses:` alone does not pin the binary: set `ref`
to the tag you reviewed.

### Agent hooks

`dep-vet guard --check -- npm i foo` parses an install command, audits the
packages it names, and exits with the normal verdict codes. `dep-vet hook claude`
turns that into a Claude Code `PreToolUse` hook:

```sh
dep-vet hook install claude              # print the diff; writes nothing
dep-vet hook install claude --write      # .claude/settings.json
dep-vet hook install claude --user --write
dep-vet hook uninstall claude --write
```

The generated handler matches `Bash`, runs the absolute path of `dep-vet`, and
gets `timeout: 30` so dep-vet's own 8-second budget finishes first. HIGH denies,
WARN asks (deny with `--strict`), clean allows silently, and an audit that
cannot run is allowed unless `--strict`. The hook always exits 0 and prints one
documented `hookSpecificOutput` object, because Claude treats exit 2 as BLOCK
while dep-vet uses it for HIGH.

What this protects against: a hallucinated package name, a typosquat, and a
direct package whose metadata looks wrong. What it does not protect against:
transitive dependencies, a bare `npm install` with no named package, URLs, VCS
and path specs, `$(...)`, `eval`, nested shells, `xargs`, absolute paths, or a
hostile, prompt-injected agent. It is advisory against a hostile agent and
useful against an honest one.

There are two bypasses: an allow entry in `.depvet.toml` with a reason, and
removing the hook. The hook ignores agent-settable `DEPVET_*` overrides
(registry/OSV bases, cache, timeout) so the command string cannot redirect the
audit; only `DEPVET_CACHE_DIR` and `DEPVET_DEBUG` pass through.

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
  `uv.lock`, `Pipfile.lock`, `Gemfile.lock`, `packages.lock.json`,
  `composer.lock`, `gradle.lockfile`, `packages.config`. JSR has no advisory
  source,
  so JSR reports say advisory coverage is unavailable. RubyGems has no owner
  list, weekly downloads, or install-time file data; yanked versions disappear
  from its API, so asking for one reports "not found" rather than "yanked".
  NuGet exposes no owners, downloads, repository, or build-time file data; its
  1900-01-01 "unknown" publish dates are ignored. Maven Central has no owners,
  downloads, repository, or deprecation concept, and no standard lockfile, so
  `dep-vet maven` only vets a single coordinate. AndroidX, AGP, Firebase, and
  Play artifacts come from Google Maven, which has no publish timestamps, so
  their `freshness` signal is reported as `not checked`. Composer has maintainers,
  repository metadata, and an abandoned flag, but no install-time file list and
  no weekly download figure.
- **Release transitions are metadata only.** Dormancy, changed install
  scripts, added dependencies, and publisher changes come from the registry;
  dep-vet never unpacks a release. History is requested only for versions from
  the last 30 days.
- **Provenance: presence in audits, verification in inspect.** `present` means
  the registry publishes an attestation. An audit checks the subject digest
  only; `inspect npm` performs full offline Sigstore verification. Neither
  decides whether the signer is trustworthy for that package. `missing` is never a finding, and `unavailable` means the ecosystem
  has no provenance dep-vet can read.
- **Release diffs are text-based.** `diff` compares extracted files by content
  and rule hits by (rule, file). Install hooks are compared as parsed commands,
  not as a `package.json` text diff. It does not decompile compiled artifacts;
  added binaries are reported as INFO and never scanned, and a minified rewrite
  can produce a large but harmless diff.
- **Archive inspection never executes a package.** It downloads, verifies,
  extracts in memory, and reads text. No install hooks run, no script is
  sourced, and no file is written outside the process.
- **Advice is a pointer, not a guarantee.** `fixed in` is what OSV publishes for
  that advisory; `newest` is the highest published version and may be a breaking
  major or still vulnerable. dep-vet never upgrades, rewrites, or tests anything.
- **Missing signals are labelled, not guessed.** PyPI has no maintainer list or
  download count; crates.io has no file list, so `build.rs` cannot be detected;
  Go modules have no execution, owners, downloads, or repository link in the
  index. Those appear as `not checked`. If crates.io's owner endpoint fails, the
  report says "maintainer list unavailable" instead of implying agreement.
- **Typosquat context depends on what is on disk.** `dep-vet lock` compares
  against the base lockfile; `dep-vet npm` uses the nearest `package-lock.json`
  when one exists, and `--no-local` turns that off. Either way the seed list is
  also consulted.
- **Network failures are retried with backoff.** Network errors, 429, and 5xx
  get up to three attempts with exponential backoff, and a registry's
  `Retry-After` is honoured up to five seconds. Advisories are cached for five
  minutes, not the 24 hours used for registry metadata.
- **Findings carry confidence.** JSON findings include `confidence`
  (`high`/`medium`/`low`) next to `severity`: how sure the rule is, as opposed
  to how bad the finding would be.
- **Tree audits batch their lookups.** One OSV query per 500 packages and one
  npm downloads request per 128 names; a failed batch makes those packages
  "could not check" rather than clean. Single-package commands still fetch
  their own.
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
src/archive/      bounded in-memory tar.gz/zip/gem extraction
src/rules.rs      static rules over extracted source, comment stripping
src/inspect.rs    archive resolution, checksums, release diff
src/provenance.rs offline Sigstore verification for npm
src/maven.rs      Maven Central and Google Maven metadata
src/composer.rs   Packagist versions, maintainers, abandoned flag
src/cli.rs        command-line surface
src/progress.rs   stderr-only progress bar
src/version.rs    version comparison helper for advice
src/main.rs       wiring, color choice, exit codes
```

Feature work happens on a branch and merges once the push gate is green. Bug
fixes start with a failing test, as the `GitHub Actions` publisher false positive
did.

## Roadmap

1. More ecosystems and lockfile formats (Maven dependency trees).
2. SARIF and SBOM output for CI consumers.
3. Publisher history beyond the immediately previous release.

## License

MIT. See [LICENSE](LICENSE).
