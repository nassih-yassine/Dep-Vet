# Benchmark: cold vs warm audit

One real lockfile, one machine, fixed commit. The script clones OWASP NodeGoat at
`c5cb68a`, clears an isolated cache, and times a cold `dep-vet audit` followed by
a warm one.

```sh
DEPVET_BIN=./target/release/dep-vet examples/benchmark/run.sh
```

Measured 2026-11-25 with dep-vet 0.16.0 (release build, 19 MB binary) on an
11th-gen Intel i7-11800H, Linux 7.2.15, 16 threads:

| Run | Wall time | Exit | Packages | Cache |
|---|---:|---:|---:|---:|
| Cold | 118.26 s | 3 | 1,090 | 1,866 entries, 115 MiB |
| Warm | 1.45 s | 3 | 1,090 | no new entries |

Warm is ~82x faster because every packument, advisory, EPSS/KEV lookup, and
download count comes from the local SQLite cache. Registry metadata is cached
for 24 hours; advisories for five minutes, so a warm run more than five minutes
later will refresh advisory answers.

Both runs exit `3`: one dependency in the pinned 2023 lockfile
(`grunt-if@0.2.0`) no longer exists on npm. The audit still reports the 1,090
packages it could check, including 101 packages with HIGH findings and 305
advisories. An incomplete check is not a pass.
