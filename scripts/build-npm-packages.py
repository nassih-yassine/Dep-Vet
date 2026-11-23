#!/usr/bin/env python3
"""Assemble the dep-vet npm package from verified GitHub release assets.

One package bundles every platform binary and selects one at runtime. There is
no install script and no download during install.
"""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tarfile
import zipfile

PACKAGES = {
    "linux-x64": ("x86_64-unknown-linux-musl", "tar.xz", "dep-vet"),
    "linux-arm64": ("aarch64-unknown-linux-musl", "tar.xz", "dep-vet"),
    "darwin-x64": ("x86_64-apple-darwin", "tar.xz", "dep-vet"),
    "darwin-arm64": ("aarch64-apple-darwin", "tar.xz", "dep-vet"),
    "win32-x64": ("x86_64-pc-windows-msvc", "zip", "dep-vet.exe"),
}


def verify(asset: pathlib.Path) -> None:
    checksum = asset.with_name(asset.name + ".sha256")
    if not checksum.is_file():
        raise SystemExit(f"missing checksum for {asset}")
    expected = checksum.read_text().split()[0].lower()
    actual = hashlib.sha256(asset.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch for {asset}")


def extract(asset: pathlib.Path, binary_name: str, output: pathlib.Path) -> None:
    verify(asset)
    if asset.suffix == ".zip":
        with zipfile.ZipFile(asset) as archive:
            for member in archive.namelist():
                if member.endswith(binary_name):
                    output.write_bytes(archive.read(member))
                    return
    else:
        with tarfile.open(asset, "r:xz") as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name.endswith(binary_name):
                    output.write_bytes(archive.extractfile(member).read())
                    return
    raise SystemExit(f"{binary_name} not found in {asset}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--assets", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.output = args.output.resolve()

    package = args.output / "dep-vet"
    if args.output.exists():
        shutil.rmtree(args.output)
    package.mkdir(parents=True)
    shutil.copytree("npm/dep-vet", package, dirs_exist_ok=True)
    shutil.copy("LICENSE", package / "LICENSE")

    data = json.loads((package / "package.json").read_text())
    data["version"] = args.version
    (package / "package.json").write_text(json.dumps(data, indent=2) + "\n")

    for key, (target, extension, binary_name) in PACKAGES.items():
        binary = package / "binaries" / key / binary_name
        binary.parent.mkdir(parents=True)
        extract(args.assets / f"dep-vet-{target}.{extension}", binary_name, binary)
        binary.chmod(0o755)

    subprocess.run(
        ["npm", "pack", "--pack-destination", str(args.output)],
        cwd=package,
        check=True,
        stdout=subprocess.DEVNULL,
    )


if __name__ == "__main__":
    main()
