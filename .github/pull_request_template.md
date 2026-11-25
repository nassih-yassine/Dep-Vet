## What changed

<!-- One or two sentences. The diff says how; this says what and why. -->

## Why

<!-- The problem this solves, or the issue it closes. "Closes #123". -->

## How it was verified

<!-- Paste the commands and the result, not just "tests pass". -->

```console
$ cargo fmt --check
$ cargo clippy --locked --all-targets -- -D warnings
$ cargo test --locked
```

## Checklist

- [ ] A failing test came first for a bug fix.
- [ ] New behaviour is covered by tests that do not touch the network or the real cache.
- [ ] `CHANGELOG.md` has an entry under `Unreleased` (user-facing changes only).
- [ ] `README.md` / `SECURITY.md` updated if a documented limit moved.
- [ ] The exit-code contract is intact: `0` clean, `1` warnings, `2` high risk, `3` could not check.
- [ ] Any new finding cites an evidence URL and is listed in `KNOWN_FINDINGS`.
- [ ] No new dependency without a stated reason.
