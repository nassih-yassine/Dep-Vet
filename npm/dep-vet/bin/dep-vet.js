#!/usr/bin/env node
"use strict";

// No shell, no install-time download: every release binary is bundled and the
// launcher picks the one for this platform.
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const key = `${process.platform}-${process.arch}`;
const supported = new Set([
  "linux-x64",
  "linux-arm64",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64",
]);

if (!supported.has(key)) {
  console.error(
    `dep-vet: unsupported platform ${process.platform}/${process.arch}. ` +
      "Install the binary from https://github.com/nassih-yassine/Dep-Vet/releases instead."
  );
  process.exit(3);
}

const binary = path.join(
  __dirname,
  "..",
  "binaries",
  key,
  process.platform === "win32" ? "dep-vet.exe" : "dep-vet"
);

if (!fs.existsSync(binary)) {
  console.error(`dep-vet: missing bundled binary at ${binary}; reinstall the package.`);
  process.exit(3);
}

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
