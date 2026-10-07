# Releasing roxy

A release is a `vX.Y.Z` tag on `main` whose version equals
`workspace.package.version` in `Cargo.toml`. Pushing the tag runs two
workflows:

- **`release.yml`** builds the binaries, checks them and publishes a GitHub
  release with generated notes.
- **`image.yml`** publishes `ghcr.io/roxy-proxy/roxy:vX.Y.Z`, `:X.Y` and
  `:latest` ([run roxy](https://roxy-proxy.github.io/roxy-proxy/guides/run)).

## Steps

1. On a branch, bump the version in the root `Cargo.toml`:

   ```toml
   [workspace.package]
   version = "0.2.0"
   ```

   Also bump the internal crates' `version = "…"` entries under
   `[workspace.dependencies]` to match. Then run `cargo check` so `Cargo.lock`
   picks up the new version. Commit both files and merge the PR to `main`
   with CI green.

2. Optional: do a dry run. Run the **Release** workflow by hand
   (`workflow_dispatch`) on `main`. It builds, checks and uploads every
   artifact (download the `release` artifact) but publishes nothing.

3. Tag the merge commit and push the tag:

   ```sh
   git switch main && git pull
   git tag -a v0.2.0 -m "roxy 0.2.0"
   git push origin v0.2.0
   ```

   The workflow fails before building anything if the tag does not equal
   `v` + the workspace version. A version with a pre-release suffix
   (`0.2.0-rc.1`, tag `v0.2.0-rc.1`) is published as a GitHub pre-release,
   and its image gets only the `v0.2.0-rc.1` tag (not `X.Y` or `latest`).

4. Check the release page. The notes are generated from the merged PRs;
   edit them if needed.

## What a release contains

| file | contents |
|---|---|
| `roxy-<version>-x86_64-unknown-linux-musl.tar.gz` | static Linux binary (amd64) |
| `roxy-<version>-aarch64-unknown-linux-musl.tar.gz` | static Linux binary (arm64) |
| `roxy-<version>-aarch64-apple-darwin.tar.gz` | macOS binary (Apple silicon) |
| `SHA256SUMS` | checksums of the tarballs |

Each tarball holds a `roxy-<version>-<target>/` directory with `roxy`,
`LICENSE-MIT`, `LICENSE-APACHE` and `README.md`.

- **Linux builds.** They come from the `Dockerfile`'s build stage, so they
  are byte-for-byte the build that goes into the container image: Alpine,
  musl, `cargo auditable build --release --locked`, stripped. Each runs on a
  native amd64 or arm64 runner.
- **Static linking.** The binaries are static-pie: no program interpreter
  and no shared libraries, while keeping ASLR. `ldd` reports "statically
  linked" and `file` reports "static-pie linked".
- **What CI checks.** That the binaries are static, and that
  `roxy --version` prints the release version.

## Verifying a download

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify roxy-0.2.0-x86_64-unknown-linux-musl.tar.gz --repo roxy-proxy/roxy-proxy
```

Every tarball has a build provenance attestation
(`actions/attest-build-provenance`) tying it to the workflow run and commit
that built it.
