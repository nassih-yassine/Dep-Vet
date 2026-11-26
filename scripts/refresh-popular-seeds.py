#!/usr/bin/env python3
"""Refresh data/popular-{crates,nuget,pypi}.txt from public ranking APIs.

Only ecosystems with a documented, keyless ranking endpoint are generated:

  crates   https://crates.io/api/v1/crates?sort=downloads   (all-time downloads)
  nuget    https://azuresearch-usnc.nuget.org/query         (totalDownloads)
  pypi     https://hugovk.github.io/top-pypi-packages/       (30-day downloads)

RubyGems removed its top-downloads endpoint, Packagist publishes totals only,
and Maven/Go/JSR have no ranking that matches a dependency name, so those seeds
stay curated. Anchors are always part of the written seed, and the previous
file is unioned back in, so a hand-picked name never silently disappears.

Usage: python3 scripts/refresh-popular-seeds.py [crates|nuget|pypi|all]
"""

import json
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
LIMIT = 500
UA = {"User-Agent": "dep-vet-refresh/0.1 (typosquat seed)"}

ALLOWED = re.compile(r"^[a-z0-9][a-z0-9._-]{2,}$")

ECOSYSTEMS = {
    "crates": {
        "anchors": [
            "anyhow",
            "clap",
            "inotify",
            "log",
            "quote",
            "rand",
            "regex",
            "rustix",
            "serde",
            "serde_json",
            "shlex",
            "syn",
            "thiserror",
            "tokio",
        ],
        "header": (
            "# crates.io typosquat candidates, ranked by all-time downloads.\n"
            "# Regenerate with: python3 scripts/refresh-popular-seeds.py crates\n"
        ),
    },
    "nuget": {
        "anchors": [
            "automapper",
            "dapper",
            "entityframework",
            "mediatr",
            "moq",
            "newtonsoft.json",
            "nunit",
            "polly",
            "serilog",
            "system.text.json",
            "xunit",
        ],
        "header": (
            "# NuGet typosquat candidates, ranked by total downloads.\n"
            "# Regenerate with: python3 scripts/refresh-popular-seeds.py nuget\n"
        ),
    },
    "pypi": {
        "anchors": [
            "boto3",
            "django",
            "fastapi",
            "flask",
            "numpy",
            "pandas",
            "pydantic",
            "pytest",
            "requests",
            "setuptools",
            "urllib3",
        ],
        "header": (
            "# PyPI typosquat candidates, ranked by 30-day downloads.\n"
            "# Regenerate with: python3 scripts/refresh-popular-seeds.py pypi\n"
        ),
    },
}


def get_json(url):
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def clean(name, ecosystem):
    name = name.strip().lower()
    if ecosystem == "pypi":
        # PEP 503: runs of -, _, . are one separator.
        name = re.sub(r"[-_.]+", "-", name)
    return name if ALLOWED.match(name) else None


def fetch_crates(_limit):
    names = []
    page = 1
    while len(names) < LIMIT:
        payload = get_json(
            f"https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={page}"
        )
        crates = payload.get("crates", [])
        if not crates:
            break
        names.extend(crate.get("name", "") for crate in crates)
        page += 1
    return names


def fetch_nuget(_limit):
    payload = get_json(
        "https://azuresearch-usnc.nuget.org/query"
        "?orderby=totalDownloads&take=1000&prerelease=false"
    )
    return [entry.get("id", "") for entry in payload.get("data", [])]


def fetch_pypi(_limit):
    payload = get_json(
        "https://hugovk.github.io/top-pypi-packages/"
        "top-pypi-packages-30-days.min.json"
    )
    rows = sorted(
        payload.get("rows", []),
        key=lambda row: -int(row.get("download_count", 0)),
    )
    return [row.get("project", "") for row in rows]


FETCHERS = {"crates": fetch_crates, "nuget": fetch_nuget, "pypi": fetch_pypi}


def load_current(path):
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def merge_seed(ranked, current, anchors):
    """Ranked names first, then carried-over seed names, deduplicated."""
    seen = set()
    merged = []
    for name in list(ranked)[:LIMIT] + sorted(set(current) | set(anchors)):
        if name not in seen:
            seen.add(name)
            merged.append(name)
    return merged


def refresh(ecosystem):
    config = ECOSYSTEMS[ecosystem]
    path = DATA / f"popular-{ecosystem}.txt"
    current = load_current(path)
    ranked = []
    for raw in FETCHERS[ecosystem](LIMIT):
        name = clean(raw, ecosystem)
        if name:
            ranked.append(name)
    if len(ranked) < 100:
        raise SystemExit(f"{ecosystem}: ranking returned only {len(ranked)} names")
    final = merge_seed(ranked, current, config["anchors"])
    path.write_text(config["header"] + "\n".join(final) + "\n")
    print(f"{ecosystem}: wrote {len(final)} names to {path.name}")


def self_test():
    assert clean("System.Text.Json ", "nuget") == "system.text.json"
    assert clean("Foo_Bar", "pypi") == "foo-bar"
    assert clean("ab", "crates") is None
    assert clean("bad name", "crates") is None
    merged = merge_seed(["a", "b", "a"], ["b", "c"], ["d"])
    assert merged == ["a", "b", "c", "d"], merged
    print("self-test ok")


def main(argv):
    if "--self-test" in argv:
        self_test()
        return
    targets = [arg for arg in argv[1:] if not arg.startswith("-")] or ["all"]
    if targets == ["all"]:
        targets = list(ECOSYSTEMS)
    for target in targets:
        if target not in ECOSYSTEMS:
            raise SystemExit(f"unknown ecosystem: {target}")
        refresh(target)


if __name__ == "__main__":
    main(sys.argv)
