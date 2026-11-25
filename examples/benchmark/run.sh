#!/bin/sh
# Measure a cold and a warm `dep-vet audit` on a real lockfile (OWASP NodeGoat).
#
#   DEPVET_BIN=./target/release/dep-vet examples/benchmark/run.sh
#
# The cache is isolated under a temporary directory, so the run does not touch
# your normal ~/.cache/dep-vet. Results are printed, not stored.
set -eu

BIN="${DEPVET_BIN:-dep-vet}"
COMMIT=c5cb68a7084e4ae7dcc60e6a98768720a81841e8
PROJECT=https://github.com/OWASP/NodeGoat
workdir="${TMPDIR:-/tmp}/dep-vet-bench-nodegoat"
cache="${TMPDIR:-/tmp}/dep-vet-bench-cache"

command -v "$BIN" >/dev/null 2>&1 || {
    echo "dep-vet not found; set DEPVET_BIN=/path/to/dep-vet" >&2
    exit 1
}

if [ ! -d "$workdir/.git" ]; then
    git clone --quiet "$PROJECT" "$workdir"
fi
git -C "$workdir" checkout --quiet "$COMMIT"
rm -rf "$cache"
mkdir -p "$cache"

cd "$workdir"

measure() {
    label="$1"
    output="$2"
    start=$(date +%s%N)
    set +e
    DEPVET_CACHE_DIR="$cache" "$BIN" audit package-lock.json >"$output" 2>&1
    status=$?
    set -e
    end=$(date +%s%N)
    printf '%s: %s ms, exit %s\n' "$label" "$(( (end - start) / 1000000 ))" "$status"
    grep -m1 'packages audited' "$output" || true
}

measure "cold" "/tmp/dep-vet-bench-cold.txt"
entries_after_cold=0
if command -v sqlite3 >/dev/null 2>&1; then
    db=$(find "$cache" -name '*.db' | head -1)
    if [ -n "$db" ]; then
        entries_after_cold=$(sqlite3 "$db" 'select count(*) from http_cache;' 2>/dev/null || echo 0)
        printf 'cache entries after cold: %s\n' "$entries_after_cold"
        printf 'cache size after cold: %s KB\n' "$(( $(du -sk "$cache" | cut -f1) ))"
    fi
fi

measure "warm" "/tmp/dep-vet-bench-warm.txt"

if command -v sqlite3 >/dev/null 2>&1; then
    db=$(find "$cache" -name '*.db' | head -1)
    if [ -n "$db" ]; then
        printf 'cache entries after warm: %s\n' "$(sqlite3 "$db" 'select count(*) from http_cache;')"
    fi
fi
