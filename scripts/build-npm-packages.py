#!/usr/bin/env python3
"""Assemble npm packages from a GitHub release's verified assets.

The launcher has no install script: each platform binary is an optional
dependency selected by npm's os/cpu fields. Run after a release, then publish
the generated packages in dependency order.
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
OS_CPU = {
    "linux-x64": (["linux"], ["x64"]),
    "linux-arm64": (["linux"], ["arm64"]),
    "darwin-x64": (["darwin"], ["x64"]),
    "darwin-arm64": (["darwin"], ["arm64"]),
    "win32-x64": (["win32"], ["x64"]),
}


def verify(asset: pathlib.Path) -> None:
    checksum = asset.with_name(asset.name + ".sha256")
    if not checksum.is_file():
        raise SystemExit(f"missing checksum for {asset}")
    expected = checksum.read_text().split()[0].lower()
    actual = hashlib.sha256(asset.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch for {asset}")


def extract(asset: pathlib.Path, target: str, binary_name: str, output: pathlib.Path) -> pathlib.Path:
    verify(asset)
    if asset.suffix == ".zip":
        with zipfile.ZipFile(asset) as archive:
            for member in archive.namelist():
                if member.endswith(binary_name):
                    output.write_bytes(archive.read(member))
                    return output
    else:
        with tarfile.open(asset, "r:xz") as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name.endswith(binary_name):
                    output.write_bytes(archive.extractfile(member).read())
                    return output
    raise SystemExit(f"{binary_name} not found in {asset}")


def package_json(name: str, version: str, key: str, executable: str) -> dict:
    os_values, cpu_values = OS_CPU[key]
    return {
        "name": name,
        "version": version,
        "description": "Platform binary for dep-vet",
        "license": "MIT",
        "repository": {
            "type": "git",
            "url": "https://github.com/nassih-yassine/Dep-Vet.git",
        },
        "homepage": "https://github.com/nassih-yassine/Dep-Vet",
        "os": os_values,
        "cpu": cpu_values,
        "files": [f"bin/{executable}"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--assets", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    if args.output.exists():
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)

    launcher = args.output / "dep-vet"
    shutil.copytree("npm/dep-vet", launcher)
    data = json.loads((launcher / "package.json").read_text())
    data["version"] = args.version
    for key in PACKAGES:
        data["optionalDependencies"][f"dep-vet-{key}"] = args.version
    (launcher / "package.json").write_text(json.dumps(data, indent=2) + "\n")
    shutil.copy("LICENSE", launcher / "LICENSE")

    for key, (target, extension, binary_name) in PACKAGES.items():
        package = args.output / f"dep-vet-{key}"
        binary = package / "bin" / binary_name
        binary.parent.mkdir(parents=True)
        asset = args.assets / f"dep-vet-{target}.{extension}"
        extract(asset, target, binary_name, binary)
        binary.chmod(0o755)
        (package / "package.json").write_text(
            json.dumps(
                package_json(f"dep-vet-{key}", args.version, key, binary_name),
                indent=2,
            )
            + "\n"
        )
        shutil.copy("LICENSE", package / "LICENSE")

    for directory in [launcher, *sorted(args.output.glob("dep-vet-*"))]:
        if directory == launcher or directory.is_dir():
            subprocess.run(
                ["npm", "pack", "--pack-destination", str(args.output)],
                cwd=directory,
                check=True,
                stdout=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
