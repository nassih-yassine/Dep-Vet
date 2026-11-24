# AUR: dep-vet-bin

The AUR package installs the published static binary, so no Rust toolchain is
needed on the user's machine.

## Publish (one time)

1. Create the package on https://aur.archlinux.org/submit/ with name
   `dep-vet-bin`. Add your SSH key under **My Account** first.
2. Then:

```sh
git clone ssh://aur@aur.archlinux.org/dep-vet-bin.git
cp PKGBUILD dep-vet-bin/
cd dep-vet-bin
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "dep-vet-bin 0.13.3-1"
git push
```

After that, `yay -S dep-vet-bin` (or any AUR helper) works.

## Update (every release)

```sh
# 1. bump pkgver
# 2. replace both sha256sums lines with the new release checksums:
gh release view "v$pkgver" --json assets --jq '.assets[] | select(.name|endswith("linux-musl.tar.xz.sha256")) | .name'

# 3. regenerate metadata and push
makepkg --printsrcinfo > .SRCINFO
git commit -am "dep-vet-bin $pkgver-1"
git push
```

Verify locally before pushing:

```sh
makepkg -f --nodeps
./dep-vet-bin-*/usr/bin/dep-vet --version
```

`provides=('dep-vet')` and `conflicts=('dep-vet')` mean users never end up with
two binaries on `PATH`.
