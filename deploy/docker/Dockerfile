# The CA service image.
#
# Two properties of this file are decisions rather than conventions, and both
# are recorded in:
#
#  1. No PKCS#11 module ships here -- not the proprietary vendor ones, and not
#     SoftHSM2 either. Every module arrives as a read-only mount at run time,
#     so the CI backend and a vendor backend are delivered by one mechanism
#     instead of two, and the published artifact contains no key store.
#
#  2. The runtime base is distroless/cc rather than distroless/base, and that
#     is a consequence of (1) measured rather than assumed. A mounted module is
#     dlopen'ed into *this* process, so its link-time dependencies have to
#     resolve inside *this* filesystem. libsofthsm2.so is C++ and needs
#     libstdc++.so.6 and libgcc_s.so.1, which distroless/base does not carry
#     and distroless/cc does. The vendor module (libctsw.so) needs only glibc,
#     so cc covers both.
#
# Both stages are pinned by digest. The tag beside each digest is there for a
# human reading the file; Docker resolves the digest and ignores it.

# ---- build stage -------------------------------------------------------
# cgo is not optional. github.com/miekg/pkcs11 binds the C PKCS#11 API, so a
# CGO_ENABLED=0 build does not merely produce a static binary -- it does not
# compile. That is what forces a runtime base with a dynamic loader, and it is
# why "scratch" was never available to this service.
FROM golang:1.27-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build

ENV CGO_ENABLED=1

WORKDIR /src

# Dependencies first, as their own layer: the module graph changes far less
# often than the source, so an unchanged go.mod/go.sum reuses this layer and
# the download is skipped entirely.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# -trimpath keeps absolute build paths out of the binary, so the same source
# builds byte-identically from any directory. -buildvcs=false because the
# build context excludes .git (see .dockerignore) and Go would otherwise fail
# rather than silently omit the stamp.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -buildvcs=false -ldflags='-s -w' \
        -o /out/hsm-pki-server ./cmd/hsm-pki-server

# ---- runtime stage -----------------------------------------------------
# distroless/cc: glibc, libssl, libstdc++, ca-certificates. No shell, no
# package manager, no compiler -- verified by test, not by trust
# (deploy/docker/README.md).
#
# cmd/hsm-pki-keytool is deliberately NOT copied here. It is the offline
# ceremony tool: it is the one binary in this repository that knows how to
# reach a root token, and the whole point of the two-tier hierarchy is that
# nothing running online can. An operator tool in the online image would put
# it one exec away from a compromised pod.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

COPY --from=build /out/hsm-pki-server /usr/local/bin/hsm-pki-server

# Fixed, non-zero UID. The nonroot base already sets it; stating it here means
# a base image change cannot silently return this container to root.
USER 65532:65532

# The only port served. server.listen_addr must agree with it.
EXPOSE 8080

# The binary probes itself. A HEALTHCHECK normally shells out to curl or
# wget, and this image has neither, nor a shell to run them from -- which is
# the property worth keeping, so the check adapts to the image rather than
# the image to the check. Exec form: there is no shell to parse a string.
#
# It probes /healthz (liveness), never /readyz. Readiness here touches the
# HSM, and a container marked unhealthy gets restarted -- so wiring
# readiness to this would turn a transient HSM failure into a restart loop
# against a dependency that restarting cannot fix.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/hsm-pki-server", "-healthcheck", "-config", "/etc/hsm-pki/config.yaml"]

ENTRYPOINT ["/usr/local/bin/hsm-pki-server"]
CMD ["-config", "/etc/hsm-pki/config.yaml"]
