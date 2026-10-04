# syntax=docker/dockerfile:1.7
#
# Hardened roxy image: a static musl binary on distroless/static (no shell,
# no package manager), running as UID 65532 and compatible with a read-only
# root filesystem.
#
#   docker build -t roxy .
#   docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
#     -v roxy-ca:/var/lib/roxy/ca -p 3128:3128 -p 3130:3130 roxy
#
# Base images are pinned by digest (multi-arch index digests); bump them
# deliberately.

# ---- toolchain ---------------------------------------------------------------
# rust:1.99-alpine3.22. Alpine's native target is *-unknown-linux-musl, which
# links statically by default, so the same Dockerfile builds amd64 and arm64
# natively on each platform's runner.
FROM rust:1.99-alpine3.22@sha256:d0486f70555afb827c0cafecb4052d6139e1bc7b3f7170c79307884c6af32e90 AS toolchain
RUN apk add --no-cache musl-dev
# cargo-auditable embeds the crate dependency list in the binary, so image
# scanners (Trivy) and the SBOM see the Rust dependencies, not just the base.
# cargo-chef splits the dependency build into its own layer (below).
RUN cargo install --locked cargo-auditable@0.7.7 cargo-chef@0.1.78
WORKDIR /src

# ---- plan --------------------------------------------------------------------
# The dependency recipe: Cargo.toml/Cargo.lock skeletons only, so it changes
# only when dependencies do.
FROM toolchain AS plan
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- compile -----------------------------------------------------------------
FROM toolchain AS compile
# Symbols are stripped here rather than in Cargo.toml so local release
# builds keep them. Set before the dependency build: it is part of the
# release profile, so a change would rebuild every dependency.
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
# Dependencies only, in an ordinary layer (not a cache mount) so the CI
# layer cache (type=gha, mode=max) keeps it: a source-only change reuses it
# and compiles just the workspace crates. cargo-auditable wraps only
# workspace crates, so plain cargo builds the same dependency artifacts.
COPY --from=plan /src/recipe.json recipe.json
RUN cargo chef cook --release --locked -p roxy --recipe-path recipe.json
COPY . .
RUN cargo auditable build --release --locked -p roxy \
    && cp target/release/roxy /roxy
# Fail the build if the binary is not fully static.
RUN if ldd /roxy 2>&1 | grep -q '=>'; then ldd /roxy; exit 1; fi
# The runtime filesystem, staged here because the runtime image has no
# shell: a root-owned, read-only config, and the directories roxy writes,
# owned by the runtime user. /var/lib/roxy/capture is not a VOLUME (capture
# is off by default); it exists so a volume mounted there inherits the
# ownership.
RUN install -D -m 0444 examples/docker/roxy.yaml /out/etc/roxy/roxy.yaml \
    && install -d -m 0755 -o 65532 -g 65532 /out/var/lib/roxy /out/var/log/roxy \
    && install -d -m 0700 -o 65532 -g 65532 /out/var/lib/roxy/ca /out/var/lib/roxy/capture

# ---- artifact ----------------------------------------------------------------
# Only the binary, for the release tarballs (.github/workflows/release.yml):
#   docker buildx build --target artifact --output type=local,dest=out .
FROM scratch AS artifact
COPY --from=compile /roxy /roxy

# ---- runtime -----------------------------------------------------------------
# distroless/static-debian12:nonroot: /etc/passwd with nonroot (65532),
# tzdata and nothing else (~2 MB). roxy needs no system CA bundle: upstream
# TLS trusts the embedded webpki-roots plus `tls.upstream.extra_roots`.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="roxy" \
      org.opencontainers.image.description="Extensible TLS-inspecting HTTP proxy and egress firewall" \
      org.opencontainers.image.source="https://github.com/roxy-proxy/roxy-proxy" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=compile --chown=0:0 --chmod=0555 /roxy /roxy
COPY --from=compile /out/ /

USER 65532:65532
# CA key and certificate (generated on first start; keep them across
# restarts or every client must re-trust a new CA), and the flow log
# directory for configs that log to a file.
VOLUME ["/var/lib/roxy/ca", "/var/log/roxy"]
# 3128: proxy listener. 3130: ca_server (/roxy-ca.pem, /healthz).
EXPOSE 3128 3130

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/roxy", "health", "--url", "http://127.0.0.1:3130/healthz"]

ENTRYPOINT ["/roxy"]
CMD ["run", "--config", "/etc/roxy/roxy.yaml"]
