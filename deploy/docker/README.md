# The service image

How the CA service is containerized, and — more importantly — how a PKCS#11
module reaches it, which is the decision the rest of this file follows from.

## The decision: no module ships in the image

The image contains the service binary, glibc, libssl and the C++ runtime.
It contains **no PKCS#11 module at all** — not the proprietary vendor ones,
and not SoftHSM2 either. Every module is mounted in at run time.

The licensing constraint only forces half of that. ProtectToolkit may not be
redistributed, so it could never have been baked in; SoftHSM2 is BSD-2-Clause
and could have been. Mounting both anyway buys three things:

- **One delivery mechanism, so the backends cannot diverge in the image.**
  If SoftHSM2 were baked in and vendors mounted, the backend CI exercises
  would be delivered differently from the backend production uses. The whole
  reason this repository runs every token-touching test against every backend
  (`CLAUDE.md` §2.4) is that a difference between backends is where defects
  hide. Introducing one in the packaging would be self-defeating.
- **The published artifact holds no key store.** An image that cannot hold or
  emulate a private key is a smaller claim to defend and a smaller `trivy`
  surface.
- **Adding a vendor changes a mount and a config value**, not a Dockerfile.

The cost is that the image cannot start on its own. `CLAUDE.md` §1 promises a
reader can reproduce this repository with no hardware and no proprietary SDK,
so that burden moved to [`run-local.sh`](run-local.sh) rather than
disappearing.

## Why `distroless/cc` and not `distroless/base`

Measured, not assumed. A mounted module is `dlopen`ed into the service's own
address space, so its dependencies must resolve inside the service's
filesystem:

| Module | Needs |
|---|---|
| `libsofthsm2.so` | `libcrypto.so.3`, **`libstdc++.so.6`**, **`libgcc_s.so.1`**, libc, libm |
| `libctsw.so` (ProtectToolkit) | libdl, libpthread, libc — all glibc |

`distroless/base` carries glibc and libcrypto but neither `libstdc++.so.6`
nor `libgcc_s.so.1`; `distroless/cc` adds exactly those two, and neither has
a shell or a package manager. On `base`, SoftHSM2 would fail at `dlopen`
while the vendor module loaded fine — a backend divergence caused by the
image, which is the thing the mount decision exists to prevent.

The service's own binary would have been happy on `base`: cgo needs a dynamic
loader and glibc, nothing more. The base image is sized for what gets mounted
into it, not for what it ships.

## The mount contract

Four mounts, and the distinction between them is the point.

| Path | Mode | What it is |
|---|---|---|
| `/pkcs11/<module>.so` | read-only | The PKCS#11 module. Code. |
| `/etc/hsm-pki/` | read-only | `config.yaml`, the intermediate certificate, the root certificate and root CRL. No key material, no PIN. |
| `/var/lib/softhsm/tokens/` | **writable** | SoftHSM2's token store. Only when using SoftHSM2. |
| `/var/lib/hsm-pki/` | **writable** | The CA's SQLite store: issued/revoked records and the CRL number. |

Everything else is read-only: the container runs with
`--read-only`, and the two writable paths above are the complete list of
what the service writes. Verified by running it that way, not by reading the
code — see "Verifying" below.

The PIN is never in any of these. `config.yaml` carries `pin_env`, the *name*
of the environment variable the PIN is read from at startup, so a leaked
config file leaks nothing (`CLAUDE.md` §3.1, §3.2).

### Two traps found while building this

- **Debian's module path is a symlink.** `/usr/lib/softhsm/libsofthsm2.so`
  points at `../x86_64-linux-gnu/softhsm/libsofthsm2.so`. Bind-mounting the
  link reproduces a dangling link inside the container, and the failure reads
  `failed to load module` — identical to the module being absent. Mount the
  target.
- **SoftHSM2 token directories are `0700`, owned by whoever initialized
  them.** A process that is neither that user nor root sees an empty store
  rather than a permission error, so the token simply "does not exist".

## The health check probes the service with the service

`HEALTHCHECK` normally shells out to `curl` or `wget`. This image has
neither, nor a shell to run them from — and that is the property worth
keeping, so the check adapts to the image instead of the image to the check.
`hsm-pki-server -healthcheck` probes its own `/healthz` and exits 0 or 1.

It probes **liveness, never readiness**. Readiness here touches the HSM, and
a container that fails its health check gets restarted — so wiring readiness
into it would turn a transient HSM failure into a restart loop against a
dependency that restarting cannot fix.

## Verifying

```sh
# Build.
docker build -f deploy/docker/Dockerfile -t hsm-pki-server:local .

# No shell, no package manager, no compiler.
docker run --rm --entrypoint /bin/sh hsm-pki-server:local -c 'echo reached'   # fails

# No PKCS#11 module in any layer, of any kind.
cid=$(docker create hsm-pki-server:local)
docker export "$cid" | tar -t | grep -icE 'softhsm|pkcs11|libctsw|cknfast'    # 0
docker rm -f "$cid"

# The whole thing, on a machine with no HSM: two tokens, a root ceremony,
# the root token moved out of reach, then the service read-only and non-root.
deploy/docker/run-local.sh
```

```sh
# Vulnerability gate plus SBOM. Exits non-zero on any HIGH or CRITICAL, so a
# pipeline that ignores its status is the only way to ship a known-vulnerable
# image.
ci/scan-image.sh
```

Baseline for this image, to defend against later growth: **53.8 MB, 19
layers**, UID 65532, one exposed port, **11 OS packages**, and **zero
HIGH/CRITICAL** findings (trivy 0.67.0, 2026-09-04). The package count is
the interesting one: most of what an image scanner normally reports is
absent because the shell, the package manager and the toolchain are absent.

## What has actually been run

Both backends, in this image, with only `config.yaml` changing between them —
which is the claim the mount decision has to earn:

- **SoftHSM2**: full startup, `connected to HSM`, a certificate issued over
  HTTP (`201`), the SQLite store written on a read-only root filesystem, and
  the root CRL served as DER and parsed by `openssl crl -inform DER`.
- **ProtectToolkit 7.3.3**: `connected to HSM` — module loaded, token
  resolved by label, user login established — then a clean stop at the
  missing intermediate certificate, since no ceremony has been run against
  those tokens.

### An open constraint on the vendor path, measured but not yet explained

Running the vendor path as **UID 1000 fails at `C_Initialize` with
`CKR_DEVICE_ERROR`**, while UID 0 succeeds with identical mounts, identical
`$HOME`, and a token store that UID 1000 owns. The variable is the UID
alone: with `HOME` pointed at the same mounted store, root works and 1000
does not.

The leading hypothesis is that the module resolves something through the
passwd database — a distroless image defines only `root`, `nonroot` (65532)
and `nobody`, so UID 1000 exists to the kernel but not to `getpwuid`. That is
a hypothesis, not a finding: it has not been tested, because the test needs a
token store readable by a UID that *is* in passwd, and copying the
maintainer's emulator store around to get one is not worth it yet.

It matters because the pod runs as 65532 (Phase 4.5), so it is recorded as an
item to settle there rather than left as folklore here. It does not affect
SoftHSM2, which runs happily as 65532 — and SoftHSM2 is what CI runs
(`CLAUDE.md` §2.3).
