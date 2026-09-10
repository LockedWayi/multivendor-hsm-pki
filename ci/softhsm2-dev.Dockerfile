# Dev/test environment for internal/pkcs11: Go plus a real SoftHSM2 module,
# so `go test ./internal/pkcs11/...` runs against an actual PKCS#11 backend
# with zero vendor hardware.
# This is not the shipped service image (see /deploy/docker for that). It
# exists so the SoftHSM2-backed test suite is reproducible from code,
# on a laptop or in CI, without every contributor hand-installing softhsm2.
# Pinned by digest, and to the SAME digest as deploy/docker/Dockerfile's
# build stage. ci.yml's header claims every third-party ref
# here is pinned to an immutable identifier, and until 2026-09-08 this line
# was the exception -- a tag, on the image that runs the entire test suite
# and the coverage floor, that `run-local.sh` runs the CA in, and that
# deploy/docker/provision-signing-keys.sh generates the supply-chain
# signing keys inside. An unpinned image is a moved tag away from being a
# different toolchain, and this was the one place where that would have
# changed how a private key was generated.
#
# One digest across both files rather than two: a dev image whose Go differs
# from the builder's is a suite that passes against a toolchain the shipped
# binary is not compiled with. Bump them together.
FROM golang:1.27-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 opensc ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
WORKDIR /repo
