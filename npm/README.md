# npm packaging

The npm launcher has no install script and downloads nothing during install.
Each platform binary is an optional dependency selected by npm's `os`/`cpu`
fields.

## Build

1. Download the release assets and checksums:

   ```sh
   gh release download v0.13.0 --dir /tmp/dep-vet-assets \
     --pattern 'dep-vet-*.tar.xz' \
     --pattern 'dep-vet-*.tar.xz.sha256' \
     --pattern 'dep-vet-*.zip' \
     --pattern 'dep-vet-*.zip.sha256'
   ```

2. Build and verify the packages:

   ```sh
   python3 scripts/build-npm-packages.py \
     --version 0.13.0 \
     --assets /tmp/dep-vet-assets \
     --output dist-npm
   ```

3. Test the launcher against the matching platform package:

   ```sh
   npm pack --pack-destination dist-npm npm/dep-vet
   node npm/dep-vet/bin/dep-vet.js --version
   ```

## Publish

Publish the platform packages first, then the launcher:

```sh
for package in dist-npm/dep-vet-linux-x64 dist-npm/dep-vet-linux-arm64 \
  dist-npm/dep-vet-darwin-x64 dist-npm/dep-vet-darwin-arm64 \
  dist-npm/dep-vet-win32-x64; do
  npm publish "$package" --access public
done
npm publish dist-npm/dep-vet --access public
```

`NODE_AUTH_TOKEN` or `npm login` is required. Keep every package on the same
version. Use npm provenance when publishing from CI.
