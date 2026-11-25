# Showcase: OWASP NodeGoat

A real project, pinned to one commit, so the output can be reproduced instead of
invented.

- Project: [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) (Apache-2.0)
- Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (2023-06-21)
- Transcript recorded: 2026-11-25, dep-vet 0.14.0

NodeGoat is an intentionally vulnerable Node.js application used for security
training. Its dependencies are old on purpose, which makes the advisory path
visible. Its workflows were written years ago, which makes the workflow path
visible too. Neither repository nor lockfile is modified: the script clones the
project into a temporary directory and runs dep-vet there.

## Run it

```sh
# install a current dep-vet first (npm, cargo, Homebrew, ...)
examples/nodegoat/run.sh
```

The first `audit` is a cold run over a 1,479-entry lockfile and takes a few
minutes. A warm cache makes a rerun quick. Advisories come from OSV, so a future
run can list more or fewer findings than the excerpts below.

## What each step shows

### 1. One package with published advisories

```sh
dep-vet npm lodash@4.17.11
```

```console
npm/lodash@4.17.11

  verdict      HIGH (exit 2)
  first seen   2012-04-23
  downloads    210,512,318/week
  maintainers  jdalton
  license      MIT
  scorecard    7.5/10 (OpenSSF, 2026-08-24)

  6 findings

  [HIGH]  GHSA-35jh-r3h4-6jhm affects this version
        Command Injection in lodash
        also known as: CVE-2021-23337
        EPSS: 0.202 (98th percentile)
```

Every advisory links to its OSV record. The EPSS score and the OpenSSF
Scorecard are context; the advisory's own severity decides the verdict.

### 2. The project's GitHub Actions workflows

```sh
dep-vet workflows .github/workflows
```

```console
workflow scan: 2 files

  6 findings

  [WARN]  action is not pinned to a commit
        'actions/checkout' uses 'v2', which can move; pin the full commit SHA
        .github/workflows/e2e-test.yml:16
```

All six findings are actions referenced by a moving tag (`@v1`, `@v2`) instead
of a commit SHA. The scan exits `1`; it does not need a lockfile or network.

### 3. The archive behind one version

```sh
dep-vet inspect npm marked@0.3.5
```

```console
inspection: npm/marked@0.3.5

  archive      tar.gz verified, 21,102 bytes
  files        16 scanned, 0 skipped

  no findings: no rule matched the files in this archive
  verdict INFO (exit 0)
```

A clean inspection means the checksum matched and no archive rule fired. It does
not mean the code is safe: the rules look for specific patterns, and the
disclaimer is printed with every report.

### 4. The whole installed tree

```sh
dep-vet audit package-lock.json
```

The audit resolves every package the lockfile installs, applies the same rules,
and reports the worst verdict. On this pinned lockfile it audited 1,090 packages
and found dozens of advisories, including HIGH ones.

It exits `3`, not `2`, because `grunt-if@0.2.0` in this 2023 lockfile is no
longer on npm: 1,090 of 1,091 packages could be checked, and dep-vet refuses to
call a partially checked tree clean. That is the exit-code contract doing its
job. A run against a lockfile whose versions all exist exits `2` when it finds
HIGH risk.

This is the difference from `lock`: `audit` tells you about the tree you already
have.

## Reading the output

- Severity is the risk if the finding is true; confidence is how sure the rule
  is. Both are in the JSON output.
- Exit `0` means nothing above INFO, `1` warnings, `2` high risk, and `3` means
  dep-vet could not finish. Exit `3` is never a pass, even when the checked part
  is clean or contains HIGH findings.
- `not checked` lists the signals the ecosystem cannot provide (for example,
  PyPI has no maintainer list). Silence is never treated as agreement.

## Limits of this showcase

- NodeGoat is vulnerable on purpose. Its findings are real registry facts, but
  the project is a teaching target, not a production dependency.
- Advisories, download counts, EPSS scores, and Scorecard results change. Only
  the source commit and the commands are fixed.
- The workflow scan is a text pass, not a YAML engine. See the main README for
  what it does not catch.
