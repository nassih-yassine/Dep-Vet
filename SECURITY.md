# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's
[security advisory form](https://github.com/nassih-yassine/Dep-Vet/security/advisories/new).
Do not open a public issue for a vulnerability in dep-vet itself.

Include the version (`dep-vet --version`), the platform, the command, and the
smallest input that reproduces it. If the issue is a missed detection, include
the package, version, and the behaviour that should have been reported. Please
do not attach malware; a hash, a URL, and a description are enough.

Expect an acknowledgement within a few days. Once a fix ships, the advisory
credits you unless you ask otherwise.

## Scope

In scope: the CLI and its parsing of untrusted input (registry responses,
lockfiles, archives, config), archive extraction, the reusable GitHub Action,
and the release artifacts.

Out of scope: a verdict you disagree with when the evidence is accurate (open a
regular issue), vulnerabilities in the packages being audited, and findings that
require executing untrusted package code, which dep-vet deliberately never does.

## What dep-vet will not do

- It does not execute package code during `audit`, `lock`, `guard`, `inspect`,
  or `diff`.
- Agent hooks are advisory against a hostile agent. Absolute paths, `python -c`,
  nested subprocesses, and unparsed installs can bypass the command parser, and
  transitive dependencies are not checked. The hook fails open unless
  `--strict`.
- It does not extract archives to disk.
- It does not verify Sigstore signatures during an audit; `inspect npm` verifies
  them offline, and its report says exactly what was checked.

## Supported versions

The latest release receives fixes. Older releases are not patched; upgrade
instead.
