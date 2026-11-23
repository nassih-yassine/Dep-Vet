"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const { binaryPath, ensureExecutable, SUPPORTED } = require("../bin/dep-vet.js");

test("resolves a binary for every supported platform", () => {
  for (const key of SUPPORTED) {
    const [platform, arch] = key.split("-");
    const resolved = binaryPath(platform, arch, "/base");
    assert.equal(resolved, path.join("/base", "binaries", key, platform === "win32" ? "dep-vet.exe" : "dep-vet"));
  }
});

test("rejects an unsupported platform instead of guessing", () => {
  assert.throws(() => binaryPath("freebsd", "x64", "/base"), /unsupported platform/);
  assert.throws(() => binaryPath("linux", "arm", "/base"), /unsupported platform/);
});

test("restores the executable bit that npm may drop", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dep-vet-launcher-"));
  const file = path.join(directory, "fake-binary");
  fs.writeFileSync(file, "#!/bin/sh\nexit 0\n", { mode: 0o644 });
  if (process.platform !== "win32") {
    fs.chmodSync(file, 0o644);
    assert.equal(fs.statSync(file).mode & 0o111, 0, "precondition: not executable");
  }

  assert.equal(ensureExecutable(file), true);

  if (process.platform !== "win32") {
    assert.notEqual(fs.statSync(file).mode & 0o111, 0, "executable bit restored");
  }
  fs.rmSync(directory, { recursive: true, force: true });
});

test("a missing file is reported, not thrown", () => {
  assert.equal(ensureExecutable(path.join(os.tmpdir(), "dep-vet-does-not-exist")), false);
});
