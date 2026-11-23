FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 depvet

COPY dep-vet /usr/local/bin/dep-vet
USER depvet
WORKDIR /work
ENTRYPOINT ["dep-vet"]
