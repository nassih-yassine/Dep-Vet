#!/usr/bin/env node
"use strict";

// No shell, no install-time download: the platform binary is an optional
// dependency selected by npm's os/cpu fields.
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const packages = {
  "linux-x64": "dep-vet-linux-x64",
  "linux-arm64": "dep-vet-linux-arm64",
  "darwin-x64": "dep-vet-darwin-x64",
  "darwin-arm64": "dep-vet-darwin-arm64",
  "win32-x64": "dep-vet-win32-x64",
};

const key = `${process.platform}-${process.arch}`;
const packageName = packages[key];
if (!packageName) {
  console.error(
    `dep-vet: unsupported platform ${process.platform}/${process.arch}. ` +
      "Install the binary from https://github.com/nassih-yassine/Dep-Vet/releases instead."
  );
  process.exit(3);
}

let binary;
try {
  const packageRoot = path.dirname(require.resolve(`${packageName}/package.json`));
  binary = path.join(
    packageRoot,
    "bin",
    process.platform === "win32" ? "dep-vet.exe" : "dep-vet"
  );
} catch {
  console.error(
    `dep-vet: the ${packageName} optional package was not installed. ` +
      "Record the install method from https://github.com/nassih-yassine/Dep-Vet and retry."
  );
  process.exit(3);
}

if (!fs.existsSync(binary)) {
  console.error(`dep-vet: missing binary at ${binary}; reinstall the package.`);
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
