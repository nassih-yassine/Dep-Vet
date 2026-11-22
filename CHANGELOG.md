# Changelog

## Unreleased

- **Dependency tree.** `dep-vet tree package-lock.json` shows the graph npm
  already resolved: nodes, parent-to-child edges (normal, dev, optional, peer),
  and direct flags, as a human tree or `--json`. Nested versions resolve to the
  nearest `node_modules`; cycles are cut; a dependency named but absent from the
  lockfile is listed, never dropped. No network, no install, no execution.
- **Typosquat regression set and stronger lookalikes.** Adjacent transpositions
  now count as one edit, so `lodahs` is a HIGH finding instead of a weak
  distance-2 match that age could suppress. Cyrillic, Greek, and fullwidth
  lookalikes fold to ASCII before comparison. A 56-case regression set
  (`tests/fixtures/typosquat-cases.tsv`) covers documented attacks, synthetic
  mutations, and legitimate neighbours; tests require precision and recall
  floors and catch every documented attack.
- **SBOM output.** `dep-vet sbom <lockfile> --format cyclonedx|spdx` writes a
  CycloneDX 1.5 or SPDX 2.3 inventory from the resolved lockfile, offline. npm
  adds PURLs, SHA checksums from `integrity`, the project component, and
  dependency edges; other formats list PURLs without edges. Skipped entries are
  disclosed as properties/annotations, and metadata the lockfile does not carry
  is omitted or `NOASSERTION`. Both formats validate against their schemas.
- **Opt-in publisher trust policy.** `[provenance]` can require an attestation
  or a verified source, and `[trusted_publishers]` can allow GitHub
  organizations, repositories, or workflow paths. `inspect npm` compares the
  verified signer identity and OIDC issuer against the policy and emits WARN
  findings (`PROVENANCE-TRUST-001/002/003`); a valid signature alone is not
  trust. Defaults are off, and non-npm ecosystems report the policy as not
  checked instead of claiming an attestation is missing.
- **SARIF 2.1.0 output.** `audit --format sarif -o results.sarif` emits one
  result per finding with stable rule ids, SARIF severity levels, evidence
  URLs, package/version/confidence properties, dependency paths when known,
  and an unsuccessful invocation when any package could not be checked. The
  exit code is unchanged. `--json` remains, and conflicts with `--format`.
- **Dependency paths on npm findings.** A `package-lock.json` audit now fills
  `dependency_paths` on each package (up to three root-to-package chains,
  shortest first) and the human report shows the shortest transitive chain as
  `via express@5.1.0 > body-parser@2.2.0`. Paths come from the lockfile, never
  from resolution, and are omitted when no root reaches the package.
- **MCP input is bounded before allocation.** The stdio loop reads at most the
  line limit plus two bytes, drains oversized lines without storing them, and
  recovers for the next request. A multi-megabyte newline-free request can no
  longer exhaust memory.
- **Release workflow hardening.** Every third-party action is pinned to a
  verified commit SHA with a version comment, the workflow defaults to
  `contents: read`, and only the `host` job that creates the release gets
  `contents: write`.
- **Archive downloads retry transient failures.** Tarballs now use the same
  backoff, `Retry-After`, and jitter policy as metadata requests, reject a
  declared `Content-Length` over the cap before reading, and never cache a
  failed or unverified download.

## 0.12.1 — 2026-11-22

- **Windows hook fix.** The guard child now receives the command on stdin
  instead of one argv element, because Windows caps a process command line at
  about 32,767 characters; a long command failed to spawn and was allowed as
  "could not check".
- **CI:** the 60-case parser table test counts rows per line, so a CRLF checkout
  no longer reports 44 cases.
## 0.12.0 — 2026-11-22

- **MCP server.** `dep-vet mcp` speaks newline-delimited JSON-RPC over stdio
  with three tools: `vet_package`, `vet_command`, and `vet_lockfile_change`.
  stdout stays pure, paths are confined to the working directory, and
  `--print-config` prints a ready `.mcp.json` snippet.
- **Agent install guard.** `dep-vet guard --check -- <command>` parses npm,
  PyPI, crates.io, Go, RubyGems, NuGet, Composer, and ephemeral runner installs,
  audits the named packages, and names anything it could not check. The parser
  is pure, bounded at 64 KiB on a UTF-8 boundary, follows one level of
  `sh -c`/`bash -lc`, and never executes anything.
- **Claude Code hook.** `dep-vet hook claude` maps HIGH to deny, WARN to ask
  (`--strict` denies), and unavailable audits to allow (`--strict` denies), always
  exiting 0 with the documented `hookSpecificOutput`. It spawns the guard with a
  fixed 8-second deadline, drains the report while the child runs, and strips
  agent-settable registry/OSV overrides. `hook install claude` merges an
  idempotent handler into project or user settings, prints a diff, and writes
  only with `--write`.
- **Trust-protocol banner.** One text source (`assets/banner.txt`) for `--help`
  and interactive reports; the README uses `assets/banner.png`.

- **Comment stripping recognises regex literals and shell `$#`.** `/[//]/` and
  `/\/*/` no longer blank the rest of the line, and shell `#` is a comment only
  at line start or after whitespace, so `$#` and `${#v}` stay code and are
  scanned.
- **Install commands match by basename.** `powershell.exe`, `curl.exe`,
  `/usr/bin/curl`, and Windows paths are risky; `certutil`, `bitsadmin`,
  `mshta`, `iwr`, and `irm` joined the list.
- **Zip archives share the decompression bound.** Every entry charges
  `Extracted.decompressed_bytes`, so a zip bomb is rejected and reported as
  `archive-decompression-bomb` before it fills the total budget.
- **Advisory detail staleness is folded in.** Batch and detail responses report
  their source, and `advisories-stale` states the oldest age used.

- **Decompression is time- and size-bounded.** A gzip stream that expands past
  `max_decompressed` (200 MB by default, `[inspect] max_decompressed_mb`) is
  stopped while reading, reported as HIGH `archive-decompression-bomb`, and
  excluded from the "clean" claim.
- **Install-command classification is token-based.** The risky-command check
  matches whole words instead of substrings, so `node scripts/evaluate.js` is no
  longer treated as `eval`, while `python3 -c`, `perl -e`, `pwsh -c`,
  `node --eval`, `nc`, `iex`, and `bash/sh -c` with a URL now are.
- **Windows and macOS.** The cache honours `%LOCALAPPDATA%` on Windows, nested
  lockfiles are read with forward-slash git paths and `--end-of-options`, refs
  that look like flags are refused, and CI now runs the test suite on ubuntu,
  macOS, and Windows. Shell- and inotify-dependent tests are gated.
- **Release hygiene.** Linux musl targets and SLSA attestations in releases, a
  `rust-version`, SHA-pinned actions in hand-written workflows, a pinned
  cargo-audit, Dependabot for cargo and actions, `SECURITY.md`, and a refresh
  guard that fails when the typosquat seed loses an anchor or changes more than
  200 lines.
- **The Action survives read-only tokens.** Inputs flow through quoted `env:`
  values, the report is written to the step summary before commenting, a
  read-only token (Dependabot/fork PRs) emits a warning instead of failing, and
  dep-vet's exit code is preserved (warnings pass). A `vX.Y.Z` ref now installs
  with `--tag` instead of `--branch`.
- **Stale advisory data is bounded and disclosed.** OSV answers served from
  cache after a failed refresh are refused beyond 24 hours, and anything served
  within that window adds an INFO `advisories-stale` finding with its age. The
  five-minute advisory TTL now follows `DEPVET_OSV_BASE`, so self-hosted
  mirrors and tests get the same policy.
- **Rule evasions closed.** Comment detection is now a per-language stripper
  that keeps code after `*/` and does not mistake `https://` for a comment;
  patterns run over whole files so calls split across lines match; and source
  files with NUL or invalid UTF-8 bytes are lossily decoded and scanned instead
  of being silently treated as binary.
- **Partial scans are disclosed.** Archive limits used to skip oversize files
  and entries past the cap silently. They now record why, and `inspect`/`diff`
  report `archive-partially-scanned` (WARN when skipped paths look like source,
  INFO otherwise), naming up to 50 skipped files.
- **Offline Sigstore verification.** `inspect npm` now verifies provenanced
  releases against the embedded Sigstore trust root: DSSE signature, Fulcio
  chain, SCT, Rekor inclusion, and artifact binding. Reports show the signer
  identity and issuer, or why verification was not possible. No network beyond
  the registry.
- **NuGet signature presence.** `inspect nuget` reports a `.signature.p7s` entry
  as present-and-unverified; absence stays silent.
- **Attestations are checked against the artifact.** For npm, dep-vet reads the
  published attestation and compares its subject digest with the tarball
  checksum; a mismatch is HIGH. It also reports the SLSA predicate's claimed
  builder, workflow, source repository, and commit, flagging a source
  repository that differs from package metadata. Signatures are still not
  verified, and every claim is labelled as such.
- **Richer release diffs.** npm install hooks are compared as commands (WARN,
  HIGH when the new one fetches or decodes code), and newly shipped binary
  files are listed as INFO.
- **Publisher intelligence.** Release bursts (INFO), source-repository changes
  (INFO), and provenance disappearing between releases (WARN).

## 0.10.0 — 2026-11-21

- **Provenance presence.** Reports say whether a release publishes provenance:
  npm attestations and PyPI via the Integrity API. `present` is explicitly not
  a verification, `missing` is not suspicious, and other ecosystems report
  `unavailable`.
- **Archive inspection.** `dep-vet inspect <ecosystem> <pkg>[@version]`
  downloads the release, verifies its checksum when published, extracts it in
  memory under hard caps, and scans source text for suspicious behavior (JS,
  Python, shell, Rust `build.rs`, Go, PHP). Path traversal, absolute paths,
  symlinks, hardlinks, oversized archives, and decompression bombs are rejected
  or bounded. Checksum mismatch is HIGH. Nothing is executed.
- **Release diff.** `dep-vet diff <ecosystem> <pkg@old> <pkg@new>` compares two
  archives by content: added, removed, and modified files, new and resolved rule
  findings, and a warning for newly added executable scripts.
- **Verified archives are cached.** A downloaded release with a trusted
  checksum is kept for 30 days and re-verified before reuse; unverified
  archives are never cached, and `--no-cache` re-downloads.
- **Inspection is configurable.** `.depvet.toml` gains an `[inspect]` section
  for archive caps and disabled rule ids. Unknown or zero values fail with
  exit 3 instead of changing nothing.
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
