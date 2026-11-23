# npm packaging

The package bundles every platform binary and selects one at runtime. It has no
install script and downloads nothing during install.

## Build

1. Download the release assets and checksums:

   ```sh
   gh release download v0.13.1 --dir /tmp/dep-vet-assets \
     --pattern 'dep-vet-*.tar.xz' \
     --pattern 'dep-vet-*.tar.xz.sha256' \
     --pattern 'dep-vet-*.zip' \
     --pattern 'dep-vet-*.zip.sha256'
   ```

2. Build and verify the package:

   ```sh
   python3 scripts/build-npm-packages.py \
     --version 0.13.1 \
     --assets /tmp/dep-vet-assets \
     --output dist-npm
   ```

3. Test the launcher:

   ```sh
   node dist-npm/dep-vet/bin/dep-vet.js --version
   node dist-npm/dep-vet/bin/dep-vet.js npm crossenv
   ```

## Publish

```sh
npm publish dist-npm/dep-vet --access public
```

The package name is `@nassihyas/dep-vet`. `NODE_AUTH_TOKEN` or `npm login` is
required. Use npm provenance when publishing from CI.
