#!/bin/sh
# Reproducible dep-vet showcase on a real, intentionally vulnerable project:
# OWASP NodeGoat, pinned to one commit. Nothing in this repository is modified.
#
#   examples/nodegoat/run.sh
#
# The first audit is a cold run over ~1,500 packages and takes a few minutes;
# a warm cache (the tool's normal 24-hour cache) makes the rerun quick. Every
# later version of OSV data can change the advisory list, so the README records
# the date and dep-vet version the transcript came from.
set -eu

COMMIT=c5cb68a7084e4ae7dcc60e6a98768720a81841e8
PROJECT=https://github.com/OWASP/NodeGoat
workdir="${TMPDIR:-/tmp}/dep-vet-nodegoat"

if ! command -v dep-vet >/dev/null 2>&1; then
    echo "dep-vet is not on PATH; install it first: https://github.com/nassih-yassine/Dep-Vet#install" >&2
    exit 1
fi
if [ ! -d "$workdir/.git" ]; then
    git clone --quiet "$PROJECT" "$workdir"
fi
git -C "$workdir" checkout --quiet "$COMMIT"
cd "$workdir"

# Exit 0/1/2 are a result; 3 means the check could not run and should stop the
# showcase. `|| status=$?` keeps the demo going after a warned/HIGH result.
run() {
    printf '\n== %s ==\n\n' "$*"
    set +e
    "$@"
    status=$?
    set -e
    if [ "$status" -ge 3 ]; then
        echo "dep-vet could not finish (exit $status)" >&2
        exit "$status"
    fi
}

run dep-vet npm lodash@4.17.11
run dep-vet workflows .github/workflows
run dep-vet inspect npm marked@0.3.5
run dep-vet audit package-lock.json

printf '\nDone. Project: %s at %s\n' "$PROJECT" "$COMMIT"
