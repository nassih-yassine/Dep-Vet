#!/usr/bin/env node
"use strict";

// No shell, no install-time download: every release binary is bundled and the
// launcher picks the one for this platform.
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const SUPPORTED = new Set([
  "linux-x64",
  "linux-arm64",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64",
]);

function binaryPath(platform, arch, baseDir) {
  const key = `${platform}-${arch}`;
  if (!SUPPORTED.has(key)) {
    throw new Error(`unsupported platform ${platform}/${arch}`);
  }
  return path.join(
    baseDir,
    "binaries",
    key,
    platform === "win32" ? "dep-vet.exe" : "dep-vet"
  );
}

// npm can drop the executable bit when it unpacks, so restore it before the
// spawn. A read-only install is not fatal: the spawn reports the real error.
function ensureExecutable(file) {
  try {
    if (process.platform !== "win32") {
      fs.chmodSync(file, 0o755);
    }
    return true;
  } catch {
    return false;
  }
}

function main() {
  let binary;
  try {
    binary = binaryPath(
      process.platform,
      process.arch,
      path.join(__dirname, "..")
    );
  } catch {
    console.error(
      `dep-vet: unsupported platform ${process.platform}/${process.arch}. ` +
        "Install the binary from https://github.com/nassih-yassine/Dep-Vet/releases instead."
    );
    process.exit(3);
  }

  if (!fs.existsSync(binary)) {
    console.error(
      `dep-vet: missing bundled binary at ${binary}; reinstall the package.`
    );
    process.exit(3);
  }

  ensureExecutable(binary);

  const child = spawn(binary, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });

  child.on("error", (error) => {
    console.error(`dep-vet: could not run ${binary}: ${error.message}`);
    process.exit(3);
  });

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => child.kill(signal));
  }

  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code === null ? 3 : code);
    }
  });
}

if (require.main === module) {
  main();
}

module.exports = { binaryPath, ensureExecutable, SUPPORTED };
