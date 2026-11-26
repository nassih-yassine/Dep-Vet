# Benchmark: cold vs warm audit

One real lockfile, one machine, fixed commit. The script clones OWASP NodeGoat at
`c5cb68a`, clears an isolated cache, and times a cold `dep-vet audit` followed by
a warm one.

```sh
DEPVET_BIN=./target/release/dep-vet examples/benchmark/run.sh
```

Measured 2026-11-26 with the `--jobs` build (release binary) on an 11th-gen
Intel i7-11800H, Linux, 16 threads. Each cold run cleared the cache first:

| Run | Wall time | Exit | Packages | Cache |
|---|---:|---:|---:|---:|
| Cold, `--jobs 4` | 56.61 s | 3 | 1,090 | 1,864 entries, 115 MiB |
| Cold, `--jobs 8` (default) | 47.21 s | 3 | 1,090 | 1,864 entries, 115 MiB |
| Cold, `--jobs 16` | 27.90 s | 3 | 1,090 | 1,864 entries |
| Cold, `--jobs 32` | 21.88 s | 3 | 1,090 | 1,864 entries |
| Warm | 0.74 s | 3 | 1,090 | no new entries |

All four cold runs report the same 1,090 packages and 305 advisories. The
pre-`--jobs` build, which audited four at a time, took 118.26 s on the same
machine and lockfile.

The script also runs two cold audits, at `--jobs 4` and `--jobs 8`, with the
cache cleared between them, and prints the speedup. See `--jobs` in the main
README for what the value means.

Warm is ~64x faster because every packument, advisory, EPSS/KEV lookup, and
download count comes from the local SQLite cache. Registry metadata is cached
for 24 hours; advisories for five minutes, so a warm run more than five minutes
later will refresh advisory answers.

Both runs exit `3`: one dependency in the pinned 2023 lockfile
(`grunt-if@0.2.0`) no longer exists on npm. The audit still reports the 1,090
packages it could check, including 101 packages with HIGH findings and 305
advisories. An incomplete check is not a pass.
