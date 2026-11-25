# npm packaging

The package bundles every platform binary and selects one at runtime. It has no
install script and downloads nothing during install.

Publishing runs in CI (`.github/workflows/npm-publish.yml`) with
`--provenance`; do not publish from a workstation.

## Build

1. Download the release assets and checksums:

   ```sh
   gh release download v0.15.0 --dir /tmp/dep-vet-assets \
     --pattern 'dep-vet-*.tar.xz' \
     --pattern 'dep-vet-*.tar.xz.sha256' \
     --pattern 'dep-vet-*.zip' \
     --pattern 'dep-vet-*.zip.sha256'
   ```

2. Build the package. Every archive must pass its `.sha256` check and
   `gh attestation verify` pinned to `release.yml` and the tag:

   ```sh
   python3 scripts/build-npm-packages.py \
     --version 0.15.0 \
     --assets /tmp/dep-vet-assets \
     --output dist-npm
   ```

   `--skip-attestation` exists for local builds without a GitHub token. Never
   use it for a published package.

3. Test the launcher and the packaged modes:

   ```sh
   node --test npm/dep-vet/test/*.test.js
   node dist-npm/dep-vet/bin/dep-vet.js --version
   ```

## Publish

CI publishes `@nassihyas/dep-vet`, normally right after the Release workflow.
Dispatch it once npm has nothing to do with it:

```sh
gh workflow run npm-publish.yml -f tag=v0.15.0
```

Trusted publishing (OIDC) is preferred and needs no secret: configure a trusted
publisher for the package on npmjs.com with repository `nassih-yassine/Dep-Vet`,
workflow `npm-publish.yml`, environment `npm-publish`. The fallback is an
automation token stored as `NPM_TOKEN` in the protected `npm-publish`
environment.

The workflow finishes by installing the published version and requiring
`dep-vet inspect npm` to report a verified signature, so a package without
provenance fails the run.
