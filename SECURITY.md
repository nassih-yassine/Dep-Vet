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

## Outbound URL policy

Registry JSON is untrusted input. Before dep-vet fetches an archive or a
provenance document, the URL must pass `src/netpolicy.rs`:

- `https` only. Userinfo, non-default ports, and non-ASCII hosts are rejected.
- The host must be on the ecosystem allowlist below, matched exactly or as a
  subdomain suffix:

  | Ecosystem | Allowed hosts |
  |---|---|
  | npm | `registry.npmjs.org` |
  | PyPI | `files.pythonhosted.org`, `pypi.org` |
  | crates.io | `static.crates.io`, `crates.io` |
  | Go | `proxy.golang.org` |
  | RubyGems | `rubygems.org` |
  | NuGet | `api.nuget.org`, `globalcdn.nuget.org` |
  | Maven | `repo.maven.apache.org`, `dl.google.com` |
  | Composer | `repo.packagist.org`, `dist.packagist.org`, plus `github.com`/`api.github.com`/`codeload.github.com`, `gitlab.com`, or `bitbucket.org` only when `source.url` names the same provider; GitHub URLs must name the same owner/repo |
  | JSR | no archive URL is supported |

- Composer code hosts are source-bound. The origin is read only from
  `source.url`; the dist URL never declares itself. Outside the two Packagist
  hosts, the dist host must be exactly `github.com`, `api.github.com`,
  `codeload.github.com`, `gitlab.com`, or `bitbucket.org` (no subdomains), and
  the source host must be the same provider (`github.com` for the GitHub
  family). GitHub archive paths must contain the source owner/repo,
  case-insensitively, with a trailing `.git` stripped. The source claim is not
  independently verified: the downloaded archive must contain a `composer.json`
  whose `name` matches the requested package, or inspection exits `3`.
- IP-literal hosts must be globally routable. Loopback, RFC 1918, link-local
  (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), ULA (`fc00::/7`),
  unspecified, multicast, broadcast, documentation (`2001:db8::/32`,
  `3fff::/20`), reserved, Teredo (`2001::/32`), discard-only (`100::/64`),
  local-use NAT64 (`64:ff9b:1::/48`), benchmarking (`2001:2::/48`), ORCHID
  (`2001:10::/28`, `2001:20::/28`), Drone (`2001:30::/28`), SRv6 (`5f00::/8`),
  the deprecated 6to4 relay (`192.88.99.0/24`), and IPv4-mapped IPv6 forms of
  all of these are refused. NAT64 (`64:ff9b::/96`), IPv4-compatible, and 6to4
  (`2002::/16`) addresses are judged by their embedded IPv4 address. This blocks the cloud metadata address
  (`169.254.169.254`) and local services.
- Archive fetches do not follow redirects automatically. dep-vet follows at
  most three, resolves relative `Location` values, revalidates every hop, and
  refuses an `https` to `http` downgrade. It never attaches an `Authorization`
  header.
- DNS is resolved once through a custom ureq resolver. Every non-public answer
  is discarded before the connection is made, and a hostname with no public
  answer fails with a clear error instead of falling back. This closes the
  resolve-then-rebind window.

### Development overrides

`DEPVET_REGISTRY_BASE`, `DEPVET_OSV_BASE`, and the other `DEPVET_*_BASE`
variables are for local mirrors and tests. They are rejected unless
`DEPVET_ALLOW_INSECURE_BASES=1` or `--dev-registry` is passed. The gate allows
`http` and the exact configured host and port only; it does not add that host to
the production allowlist. An active override prints one stderr warning and adds
`unofficial_registry: true` to JSON reports.

Any refusal is a tool error (exit `3`) with the offending host named; it is
never a clean result. The reusable GitHub Action does not set or forward these
variables.

## Supported versions

The latest release receives fixes. Older releases are not patched; upgrade
instead.
