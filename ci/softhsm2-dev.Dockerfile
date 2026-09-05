# Dev/test environment for internal/pkcs11: Go plus a real SoftHSM2 module,
# so `go test ./internal/pkcs11/...` runs against an actual PKCS#11 backend
# with zero vendor hardware.
# This is not the shipped service image (see /deploy/docker for that) — it
# exists purely so the SoftHSM2-backed test suite is reproducible from code,
# on a laptop or in CI, without every contributor hand-installing softhsm2.
FROM golang:1.27-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 opensc ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
WORKDIR /repo
