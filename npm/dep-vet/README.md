# dep-vet

Check a dependency's risk **before** it enters your lockfile. Nine ecosystems,
no code execution.

```sh
npx @nassihyas/dep-vet npm crossenv
```

```
crossenv 0.0.2-security
  HIGH  advisory  crossenv is malware
        advisory: GHSA-c2m4-w5hm-vqjw
        also known as: CVE-2017-16074
        fixes: use cross-env instead
```

## What it checks

- Advisories (OSV) with fixes, plus EPSS scores and CISA KEV "exploited in the wild" warnings, and typosquat names
- OpenSSF Scorecard for the source repository, with weak checks called out
- License and install-policy thresholds configured in `.depvet.toml`
- Install scripts, publisher changes, deprecation, freshness, recent release history
- Provenance: whether an attestation exists, verified offline for npm
- Invisible characters and text aimed at an AI reader, in code and readmes
- Lockfile diffs, dependency trees, archive inspection, release diffs, GitHub Actions workflow scan

Ecosystems: npm, PyPI, crates.io, Go, JSR, RubyGems, NuGet, Maven/AndroidX,
Composer.

## Common commands

```sh
dep-vet npm express@5.3.0            # one package
dep-vet audit package-lock.json      # the whole tree
dep-vet lock package-lock.json       # only what changed
dep-vet tree package-lock.json       # resolved graph
dep-vet inspect npm lodash@4.17.21   # download, verify, scan the archive
dep-vet diff npm lodash@4.17.20 lodash@4.17.21
dep-vet mcp                          # MCP server for AI agents
```

Exit codes: `0` clean, `1` warnings, `2` high risk, `3` the check could not run.

## MCP server

`dep-vet mcp` speaks stdio JSON-RPC with three tools: `vet_package`,
`vet_command`, and `vet_lockfile_change`. Listed in the official MCP Registry as
`io.github.nassih-yassine/dep-vet`.

```sh
dep-vet mcp --print-config   # .mcp.json snippet and claude mcp add line
```

## Install

This package bundles the binary for Linux (x64, arm64), macOS (x64, arm64), and
Windows x64, and picks the right one at runtime. It has no install script and
downloads nothing during install.

```sh
npx @nassihyas/dep-vet --version
npm install --global @nassihyas/dep-vet
```

Other channels: `cargo install dep-vet`, `brew install nassih-yassine/tap/dep-vet`,
`docker run --rm -v "$PWD:/work" -w /work ghcr.io/nassih-yassine/dep-vet:v0.13.6`,
and prebuilt archives on the releases page.

## Verify what you downloaded

```sh
dep-vet inspect npm @nassihyas/dep-vet@0.13.6
```

GitHub release archives carry a `.sha256` sidecar and a SLSA attestation
(`gh attestation verify`); the Docker image is signed with cosign. `SECURITY.md`
in the repository lists what each channel proves.

## Links

- Source, issues, and full documentation: https://github.com/nassih-yassine/Dep-Vet
- Changelog: https://github.com/nassih-yassine/Dep-Vet/blob/main/CHANGELOG.md
- Security policy: https://github.com/nassih-yassine/Dep-Vet/blob/main/SECURITY.md

MIT licensed. It never executes package code during `audit`, `lock`, `guard`,
`inspect`, or `diff`.
