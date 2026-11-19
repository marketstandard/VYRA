# Kani Rust Verifier for the VYRA bounded model checking harnesses.
# Build context: tools/kani (this directory only; the repository is mounted
# read-only at run time, never copied into the image).
#
# Base: rust:1-bookworm, pinned by the multi-arch index digest recorded from
# the Docker Hub API on 2026-11-18 (tag last updated 2026-11-12;
# linux/amd64 manifest sha256:198cd28b4ba92b20fe849d5d8b119ace1bd28423d9e82e9c4de5ee1300d453a0).
# Kani: kani-verifier 0.68.0 (crates.io max stable on 2026-11-18). Kani pins
# its own nightly toolchain and CBMC; `cargo kani setup` downloads them.
FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea

ARG KANI_VERSION=0.68.0
RUN cargo install --locked kani-verifier --version "${KANI_VERSION}" \
 && cargo kani setup \
 && cargo kani --version

WORKDIR /work
