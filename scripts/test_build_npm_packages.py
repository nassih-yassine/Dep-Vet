#!/usr/bin/env python3
"""Tests for the npm packaging script. Run: python3 -m unittest discover scripts."""

import importlib.util
import io
import pathlib
import sys
import tarfile
import tempfile
import unittest
import zipfile

SCRIPT = pathlib.Path(__file__).with_name("build-npm-packages.py")
spec = importlib.util.spec_from_file_location("build_npm_packages", SCRIPT)
packaging = importlib.util.module_from_spec(spec)
sys.modules["build_npm_packages"] = packaging
spec.loader.exec_module(packaging)


def make_tar(path: pathlib.Path, members: dict, modes: dict | None = None) -> None:
    modes = modes or {}
    with tarfile.open(path, "w:xz") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = modes.get(name, 0o644)
            archive.addfile(info, io.BytesIO(payload))


def make_zip(path: pathlib.Path, members: dict) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_extracts_exact_basename(self):
        archive = self.root / "dep-vet.tar.xz"
        make_tar(archive, {"dep-vet-1.0.0/dep-vet": b"binary", "dep-vet-1.0.0/README.md": b"x"})
        out = self.root / "out"
        packaging.extract(archive, "dep-vet", out)
        self.assertEqual(out.read_bytes(), b"binary")

    def test_duplicate_basename_is_an_error(self):
        archive = self.root / "dup.tar.xz"
        make_tar(archive, {"a/dep-vet": b"one", "b/dep-vet": b"two"})
        with self.assertRaises(SystemExit) as caught:
            packaging.extract(archive, "dep-vet", self.root / "out")
        self.assertIn("ambiguous", str(caught.exception))

    def test_similar_names_do_not_match(self):
        archive = self.root / "similar.tar.xz"
        make_tar(archive, {"dep-vet-1.0.0/notdep-vet": b"nope", "dep-vet-1.0.0/dep-vet.bak": b"nope"})
        with self.assertRaises(SystemExit) as caught:
            packaging.extract(archive, "dep-vet", self.root / "out")
        self.assertIn("not found", str(caught.exception))

    def test_zip_uses_exact_basename(self):
        archive = self.root / "win.zip"
        make_zip(archive, {"nested/dep-vet.exe": b"exe", "nested/notes.txt": b"x"})
        out = self.root / "dep-vet.exe"
        packaging.extract(archive, "dep-vet.exe", out)
        self.assertEqual(out.read_bytes(), b"exe")

    def test_zip_duplicate_is_an_error(self):
        archive = self.root / "dup.zip"
        make_zip(archive, {"a/dep-vet.exe": b"one", "b/dep-vet.exe": b"two"})
        with self.assertRaises(SystemExit):
            packaging.extract(archive, "dep-vet.exe", self.root / "out")


class ChecksumTests(unittest.TestCase):
    def test_missing_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = pathlib.Path(directory) / "asset.tar.xz"
            asset.write_bytes(b"x")
            with self.assertRaises(SystemExit) as caught:
                packaging.verify_checksum(asset)
            self.assertIn("missing checksum", str(caught.exception))

    def test_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = pathlib.Path(directory) / "asset.tar.xz"
            asset.write_bytes(b"x")
            asset.with_name(asset.name + ".sha256").write_text("0" * 64 + "  asset.tar.xz\n")
            with self.assertRaises(SystemExit) as caught:
                packaging.verify_checksum(asset)
            self.assertIn("checksum mismatch", str(caught.exception))


class TarballModeTests(unittest.TestCase):
    def build(self, mode, name="package/binaries/linux-x64/dep-vet"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tarball = pathlib.Path(directory.name) / "pkg.tgz"
        with tarfile.open(tarball, "w:gz") as archive:
            info = tarfile.TarInfo(name)
            info.size = 1
            info.mode = mode
            archive.addfile(info, io.BytesIO(b"x"))
        return tarball

    def test_executable_binary_passes(self):
        packaging.verify_tarball_modes(self.build(0o755))

    def test_non_executable_binary_fails(self):
        with self.assertRaises(SystemExit) as caught:
            packaging.verify_tarball_modes(self.build(0o644))
        self.assertIn("not executable", str(caught.exception))

    def test_windows_binary_may_be_non_executable(self):
        packaging.verify_tarball_modes(
            self.build(0o644, "package/binaries/win32-x64/dep-vet.exe")
        )

    def test_windows_build_warns_instead_of_failing(self):
        # Windows cannot store Unix modes, so the packed tarball is 0644 there.
        packaging.verify_tarball_modes(self.build(0o644), windows=True)

    def test_files_outside_binaries_are_ignored(self):
        packaging.verify_tarball_modes(self.build(0o644, "package/bin/dep-vet.js"))


if __name__ == "__main__":
    unittest.main()
