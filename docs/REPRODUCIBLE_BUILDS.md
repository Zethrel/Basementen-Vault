# Reproducible builds & artifact verification

Goal: let anyone independently confirm that a published Basementen Vault artifact
was built from the published source — not tampered with in transit or at the
build host. Two complementary mechanisms:

1. **Build provenance (enabled on a public repository).** The release workflow
   attaches a signed [SLSA] provenance attestation to every artifact — desktop
   bundles and the server image — cryptographically binding it to the source
   commit and the workflow that produced it. This is the primary, strongest
   verification and does not require you to rebuild anything.

   > **Note:** GitHub's attestation API is **not available for user-owned
   > *private* repositories**, so the attestation step is gated on the repo
   > being public and is skipped while the repository is private. It activates
   > automatically once the repository is public (or moved to an organization
   > with the feature enabled). Until then, verify releases with the
   > `SHA256SUMS` file, which is always published.
2. **Reproducibility (in progress).** Pinning the toolchain and dependencies so a
   from-source rebuild yields the *same* artifact. Fully achieved for the library
   crates and targeted for the server image; the desktop GUI bundles are not
   bit-for-bit reproducible yet (see the status table).

## Verifying provenance (recommended)

Requires the GitHub CLI (`gh`), authenticated.

**A desktop bundle** (after downloading it and its entry in `SHA256SUMS`):

```sh
# 1. Integrity: the file matches the published checksum.
sha256sum -c SHA256SUMS --ignore-missing

# 2. Provenance: it was built from this repo by the release workflow.
gh attestation verify ./Basementen.Vault_<version>_amd64.AppImage \
  --repo Zethrel/Basementen-Vault
```

**The server image** (by digest):

```sh
gh attestation verify oci://ghcr.io/zethrel/basementen-vault-server:<version> \
  --repo Zethrel/Basementen-Vault
```

A passing check proves the artifact's provenance predicate — the source repo,
commit SHA, and workflow — signed via Sigstore and logged in the public
transparency log. A failing or missing attestation means **do not trust the
artifact**.

## Reproducibility status

| Artifact | Reproducible? | Notes |
|----------|---------------|-------|
| Library crates (`vault-core`, `vault-sync`, `desktop-core`) | **Yes** | Pinned toolchain (`rust-toolchain.toml`) + committed `Cargo.lock`; `--locked` builds. |
| Server image (`vault-server`) | **Targeted** | Built from a pinned `rust:<ver>-slim` base with `--locked`. To reach bit-for-bit, pin the base images by `@sha256:` digest and set `SOURCE_DATE_EPOCH` (below). |
| Desktop bundles (dmg / NSIS / deb / rpm / AppImage) | **Not yet** | The bundlers embed build timestamps and package metadata that vary per run. Provenance attestation (above) is the verification path for these until the bundlers are made deterministic. |

## What is pinned

- **Rust toolchain** — `rust-toolchain.toml` fixes the exact `rustc`/`cargo`
  version. CI, the release workflow, and the server `Dockerfile` all use it, so a
  reproduction must use the same version (rustup honours the file automatically).
- **Dependencies** — `Cargo.lock` is committed and all release/image builds pass
  `--locked`, so the exact dependency graph is fixed.
- **Docker base** — `server/Dockerfile` pins the compiler image to an exact
  patch version. For a hardened build, replace the tags with `@sha256:` digests.

## Reproducing the server image locally

```sh
# Pin the build clock for deterministic timestamps, then build from a clean tree
# at the release tag.
git checkout v<version>
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
  docker buildx build --file server/Dockerfile \
  --platform linux/amd64 --load -t bv-server-repro .

# Compare the image digest / contents against the published one
# (ghcr.io/zethrel/basementen-vault-server:<version>).
```

## Known gaps / roadmap

- **Path canonicalization.** Cargo's `trim-paths` profile option (strips absolute
  build paths from binaries) is not yet stable in the pinned toolchain; adopt it
  on the next toolchain bump that stabilizes it, or apply
  `--remap-path-prefix` via `RUSTFLAGS` in the build environments.
- **Base-image digest pinning** and `SOURCE_DATE_EPOCH` wiring in the release
  workflow (currently a manual local step, above).
- **Deterministic desktop bundlers** — the largest remaining item; tracked
  against upstream Tauri bundler support.

[SLSA]: https://slsa.dev/
