# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# roxy with the quickstart's WASM addons at /etc/roxy/addons/. Build it from
# the repo root (the addons depend on crates/roxy-addon):
#   docker build -f examples/quickstart/addons/Dockerfile .
# compose.yaml does so with --build.

# Declared before the first FROM so the build arg reaches the base image.
ARG ROXY_IMAGE=ghcr.io/roxy-proxy/roxy:edge

# rust:1.99-alpine3.22, as the root Dockerfile uses; pinned by digest.
FROM rust:1.99-alpine3.22@sha256:d0486f70555afb827c0cafecb4052d6139e1bc7b3f7170c79307884c6af32e90 AS build
RUN apk add --no-cache musl-dev && rustup target add wasm32-wasip2
WORKDIR /src
# roxy-addon takes its version and lints from the root workspace, so the
# whole tree comes along; .dockerignore keeps target/ and the docs out.
COPY . .
WORKDIR /src/examples/quickstart/addons
RUN cargo build --release --locked --target wasm32-wasip2 \
    && install -D -m 0444 -t /out \
       target/wasm32-wasip2/release/auth_gate.wasm target/wasm32-wasip2/release/token_quota.wasm

FROM ${ROXY_IMAGE}
# Files only (--chmod would also strip the directory's search bit).
COPY --from=build --chown=0:0 /out/ /etc/roxy/addons/
