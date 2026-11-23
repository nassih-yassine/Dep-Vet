# syntax=docker/dockerfile:1
# Static musl binary on distroless: no shell, no package manager, no libc
# dependency, and the same image definition builds for every CPU architecture.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH
COPY bin/${TARGETARCH}/dep-vet /usr/local/bin/dep-vet

# The binary needs no HOME; this only gives it a writable cache directory.
ENV XDG_CACHE_HOME=/tmp/dep-vet-cache

WORKDIR /work
ENTRYPOINT ["dep-vet"]
