# syntax=docker/dockerfile:1
# Static musl binary on distroless: no shell, no package manager, no libc
# dependency, and the same definition builds for every CPU architecture.
# Pinned by digest so a retagged base image cannot change what ships.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH
COPY bin/${TARGETARCH}/dep-vet /usr/local/bin/dep-vet

# The binary needs no HOME; this only gives it a writable cache directory.
ENV XDG_CACHE_HOME=/tmp/dep-vet-cache

WORKDIR /work
ENTRYPOINT ["dep-vet"]
