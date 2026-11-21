#!/usr/bin/env python3
"""Refresh data/popular-npm.txt from real download counts.

Candidate universe: the current list plus the direct dependencies of every
current entry (registry `latest` documents). Downloads come from the public
npm downloads API in batches; the top 500 are kept, then the previous list is
unioned back in so hand-curated names never silently disappear.

Keyless, no scraping, no ranking service. Takes a minute or two.
"""

import json
import pathlib
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "popular-npm.txt"
LIMIT = 500
UA = {"User-Agent": "dep-vet-refresh/0.1"}


def get_json(url):
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def load_current():
    names = []
    for line in DATA.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def main():
    seed = load_current()
    candidates = set(seed)

    for name in seed:
        encoded = urllib.parse.quote(name, safe="@")
        try:
            latest = get_json(f"https://registry.npmjs.org/{encoded}/latest")
        except Exception:
            continue
        for dependency in latest.get("dependencies", {}):
            candidates.add(dependency)

    downloads = {}
    unscoped = sorted(name for name in candidates if not name.startswith("@"))
    scoped = sorted(name for name in candidates if name.startswith("@"))

    for start in range(0, len(unscoped), 100):
        batch = unscoped[start : start + 100]
        try:
            payload = get_json(
                "https://api.npmjs.org/downloads/point/last-week/" + ",".join(batch)
            )
        except Exception:
            continue
        for name, entry in payload.items():
            downloads[name] = entry.get("downloads", 0)

    for name in scoped:
        try:
            payload = get_json(
                "https://api.npmjs.org/downloads/point/last-week/"
                + urllib.parse.quote(name, safe="@")
            )
            downloads[name] = payload.get("downloads", 0)
        except Exception:
            continue

    ranked = [
        name
        for name, _ in sorted(downloads.items(), key=lambda item: (-item[1], item[0]))
    ][:LIMIT]
    # Ranked names keep download order; carried-over seed names follow.
    final = ranked + sorted(set(seed) - set(ranked))

    DATA.write_text(
        "# npm typosquat candidates, ranked by weekly downloads.\n"
        "# Regenerate with: python3 scripts/refresh-popular-npm.py\n"
        + "\n".join(final)
        + "\n"
    )
    print(f"wrote {len(final)} names ({len(ranked)} ranked + carried-over seed)")


if __name__ == "__main__":
    main()
