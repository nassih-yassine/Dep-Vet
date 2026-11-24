#!/usr/bin/env python3
"""Assemble the dep-vet npm package from verified GitHub release assets.

One package bundles every platform binary and selects one at runtime. There is
no install script and no download during install.

Each asset must pass two independent checks before it is extracted:

1. its ``.sha256`` sidecar (integrity: the file is the one the release lists),
2. ``gh attestation verify`` pinned to the release workflow (authenticity: the
   release workflow in this repository built it).

Extraction matches the archive member by exact basename so an archive cannot
smuggle a same-suffixed path from another directory, and more than one match is
an error rather than a coin flip.
"""

import argparse
import hashlib
import json
import os
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

REPO = "nassih-yassine/Dep-Vet"


def verify_checksum(asset: pathlib.Path) -> None:
    checksum = asset.with_name(asset.name + ".sha256")
    if not checksum.is_file():
        raise SystemExit(f"missing checksum for {asset}")
    expected = checksum.read_text().split()[0].lower()
    actual = hashlib.sha256(asset.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch for {asset}: {actual} != {expected}")


def verify_attestation(asset: pathlib.Path, version: str) -> None:
    """Require a SLSA attestation from this repository's release workflow, at this tag."""
    command = [
        "gh",
        "attestation",
        "verify",
        str(asset),
        "--repo",
        REPO,
        "--signer-workflow",
        f"{REPO}/.github/workflows/release.yml",
        "--source-ref",
        f"refs/tags/v{version}",
    ]
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    except FileNotFoundError:
        raise SystemExit("gh is required to verify release attestations") from None
    except subprocess.CalledProcessError:
        raise SystemExit(f"attestation verification failed for {asset}") from None


def members(asset: pathlib.Path):
    """Yield (name, bytes) for every file. Reading eagerly keeps the archive open."""
    if asset.suffix == ".zip":
        with zipfile.ZipFile(asset) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                yield info.filename, archive.read(info)
    else:
        with tarfile.open(asset, "r:xz") as archive:
            for info in archive.getmembers():
                if not info.isfile():
                    continue
                yield info.name, archive.extractfile(info).read()


def extract(asset: pathlib.Path, binary_name: str, output: pathlib.Path) -> None:
    matches = [
        (name, data)
        for name, data in members(asset)
        if pathlib.PurePosixPath(name).name == binary_name
    ]
    if not matches:
        raise SystemExit(f"{binary_name} not found in {asset}")
    if len(matches) > 1:
        names = ", ".join(name for name, _ in matches)
        raise SystemExit(f"ambiguous {binary_name} in {asset}: {names}")
    output.write_bytes(matches[0][1])


def npm_command(*arguments: str) -> list[str]:
    """npm is a .cmd shim on Windows, which CreateProcess cannot start directly."""
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm is required to pack the package")
    if os.name == "nt":
        return ["cmd", "/c", npm, *arguments]
    return [npm, *arguments]


def npm_tarball_stem(name: str) -> str:
    """npm names scoped tarballs ``scope-name``, without the leading ``@``."""
    return name.lstrip("@").replace("/", "-")


def verify_tarball_contents(tarball: pathlib.Path, windows: bool = False) -> None:
    """The tarball must carry a readme and executable binaries.

    npm renders the readme from the tarball root, so a package without one shows
    an empty page. Every bundled binary except the Windows one must keep its
    executable bit.

    Windows cannot store a Unix mode, so a tarball packed there always has 0644
    entries. That build is only used for the install smoke test; the published
    package is packed on Linux, where a lost mode is fatal. The launcher also
    restores the bit at run time.
    """
    with tarfile.open(tarball) as archive:
        names = archive.getnames()
        readme = f"package/README.md"
        if readme not in names:
            raise SystemExit(f"{tarball} has no {readme}; npm would show an empty page")
        if archive.getmember(readme).size < 200:
            raise SystemExit(f"{readme} is too short to be a readme")
        for info in archive.getmembers():
            if not info.name.startswith("package/binaries/"):
                continue
            if info.name.endswith(".exe"):
                continue
            if not info.mode & 0o111:
                if windows:
                    print(
                        f"warning: {info.name} has no executable bit on this "
                        "platform; the launcher restores it"
                    )
                    continue
                raise SystemExit(
                    f"{info.name} is not executable in {tarball} (mode {info.mode:o})"
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--assets", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--skip-attestation",
        action="store_true",
        help="skip gh attestation verify (local builds without a token)",
    )
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
        asset = args.assets / f"dep-vet-{target}.{extension}"
        verify_checksum(asset)
        if not args.skip_attestation:
            verify_attestation(asset, args.version)
        binary = package / "binaries" / key / binary_name
        binary.parent.mkdir(parents=True)
        extract(asset, binary_name, binary)
        binary.chmod(0o755)

    subprocess.run(
        npm_command("pack", "--pack-destination", str(args.output)),
        cwd=package,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    tarball = args.output / f"{npm_tarball_stem(data['name'])}-{args.version}.tgz"
    if not tarball.is_file():
        raise SystemExit(f"npm pack did not produce {tarball}")
    verify_tarball_contents(tarball, windows=os.name == "nt")
    print(f"built {tarball}")


if __name__ == "__main__":
    main()
