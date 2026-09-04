# The environment the official cosign release binary runs in, so that the
# signing steps of Phase 4.9 and 4.10 need nothing installed on the host.
#
# Why cosign gets an image of its own rather than joining ci/softhsm2-dev
# .Dockerfile, which already plays "operator workstation" for hsm-pki-keytool:
# that image is what `go test ./...` runs in. The machine that holds a
# session on the supply-chain token should not also be the machine that
# executes arbitrary test code, and keeping them apart costs one small image.
#
# The binary itself is NOT copied in. It is fetched and verified by
# ci/cosign.sh into .local/bin/ and mounted at run time, for two reasons: a
# 140 MB layer would be rebuilt on every version bump, and the binary's
# provenance should be checked by a script a reader can follow rather than
# buried in a build cache.
FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Two distinct needs, and neither is obvious from "run a Go binary":
#
#   libpcsclite1  cosign's PKCS#11-capable asset is the *pivkey*-pkcs11key
#                 build. The two build tags ship as one artifact, so taking
#                 the PKCS#11 capability means taking PIV's smart-card
#                 dependency with it -- a hard DT_NEEDED, so without this the
#                 binary does not start at all (measured: `error while
#                 loading shared libraries: libpcsclite.so.1`).
#
#   libssl3       A PKCS#11 module is dlopen'ed into *this* process, so it
#   libstdc++6    resolves its dependencies against this filesystem, not the
#                 one it was built on. libsofthsm2.so is C++ and links
#                 libcrypto: the same measured table that chose distroless/cc
#                 over distroless/base for the service image (4.1), applied
#                 to the signing side. libstdc++6 brings libgcc_s.so.1.
#
# No PKCS#11 module is installed here, deliberately. The module arrives as a
# read-only mount exactly as it does for the service (4.3's decision), so
# there is no second copy that could quietly become the one in use.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite1 libssl3 libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/cosign"]
