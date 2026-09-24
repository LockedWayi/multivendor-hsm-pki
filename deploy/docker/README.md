# The service image

How the CA service is containerized, and how a PKCS#11 module reaches it.
The second decision is the one the rest of this file follows from.

## The decision: no module ships in the image

The image contains the service binary, glibc, libssl and the C++ runtime.
It contains **no PKCS#11 module at all**. Not the proprietary vendor ones,
and not SoftHSM2 either. Every module is mounted in at run time.

The licensing constraint only forces part of that. ProtectToolkit and the
Luna client may not be redistributed, so they could never have been baked
in. SoftHSM2 is BSD-2-Clause and could have been. Mounting every module
buys three things:

- **One delivery mechanism, so the backends cannot diverge in the image.**
  If SoftHSM2 were baked in and vendors mounted, the backend CI exercises
  would be delivered differently from the backend production uses. This
  repository runs every token-touching test against every backend because
  a difference between backends is where defects hide. The packaging must
  not add one.
- **The published artifact holds no key store.** An image that cannot hold
  or emulate a private key is a smaller claim to defend and a smaller
  `trivy` surface.
- **Adding a vendor changes a mount and a config value**, not a Dockerfile.
  Luna added one more thing of the same kind: an environment variable,
  `ChrystokiConfigurationPath`, because its module reads a configuration
  directory of its own, and that directory (with the client's certificates)
  is a second read-only mount beside the module.

The cost is that the image cannot start on its own. A reader must be able
to reproduce this repository with no hardware and no proprietary SDK, so
that burden moved to [`run-local.sh`](run-local.sh).

## Why `distroless/cc` and not `distroless/base`

A mounted module is `dlopen`ed into the service's own address space, so its
dependencies must resolve inside the service's filesystem:

| Module | Needs |
|---|---|
| `libsofthsm2.so` | `libcrypto.so.3`, **`libstdc++.so.6`**, **`libgcc_s.so.1`**, libc, libm |
| `libctsw.so` (ProtectToolkit) | libdl, libpthread, libc, all glibc |
| `libCryptoki2.so` (Luna HSM Client 10.9.4) | libdl, libpthread, librt, libm, **`libstdc++.so.6`**, **`libgcc_s.so.1`**, libc. Loads and connects in this image (2026-09-24, "What has been run") |

`distroless/base` carries glibc and libcrypto but neither `libstdc++.so.6`
nor `libgcc_s.so.1`. `distroless/cc` adds exactly those two, and neither has
a shell or a package manager. On `base`, SoftHSM2 would fail at `dlopen`
while the vendor module loaded. That is a backend divergence caused by the
image, which the mount decision exists to prevent.

The service's own binary would run on `base`. cgo needs a dynamic loader and
glibc. The base image is sized for what gets mounted into it.

## The mount contract

Four mounts, five with Luna.

| Path | Mode | What it is |
|---|---|---|
| `/pkcs11/<module>.so` | read-only | The PKCS#11 module. Code. For Luna, the client's configuration directory (`Chrystoki.conf`, the NTLS certificates) is mounted read-only beside it and named by `ChrystokiConfigurationPath` in the environment. |
| `/etc/hsm-pki/` | read-only | `config.yaml`, the intermediate certificate, the root certificate and root CRL, and the service's TLS certificate (`tls.pem`, a public leaf; its key is on the token). No key material, no PIN. |
| `/var/lib/softhsm/tokens/` | **writable** | SoftHSM2's token store. Only when using SoftHSM2. |
| `/var/lib/hsm-pki/` | **writable** | The CA's SQLite store: issued and revoked records and the CRL number. |

Everything else is read-only. The container runs with `--read-only`, and
the two writable paths above are the complete list of what the service
writes. This was verified by running it that way. See "Verifying" below.

The PIN is never in any of these. `config.yaml` carries `pin_env`, the name
of the environment variable the PIN is read from at startup, so a leaked
config file leaks nothing.

### Two traps found while building this

- **Debian's module path is a symlink.** `/usr/lib/softhsm/libsofthsm2.so`
  points at `../x86_64-linux-gnu/softhsm/libsofthsm2.so`. Bind-mounting the
  link reproduces a dangling link inside the container, and the failure
  reads `failed to load module`, identical to the module being absent.
  Mount the target.
- **SoftHSM2 token directories are `0700`, owned by whoever initialized
  them.** A process that is neither that user nor root sees an empty store
  rather than a permission error, so the token "does not exist".

## The health check probes the service with the service

`HEALTHCHECK` normally shells out to `curl` or `wget`. This image has
neither, nor a shell to run them from. `hsm-pki-server -healthcheck` probes
its own `/healthz` and exits 0 or 1.

It probes **liveness, never readiness**. Readiness here touches the HSM,
and a container that fails its health check gets restarted. Wiring
readiness into it would turn a transient HSM failure into a restart loop
against a dependency that restarting cannot fix.

## Verifying

```sh
# Build.
docker build -f deploy/docker/Dockerfile -t hsm-pki-server:local .

# No shell, no package manager, no compiler.
docker run --rm --entrypoint /bin/sh hsm-pki-server:local -c 'echo reached'   # fails

# No PKCS#11 module in any layer, of any kind.
cid=$(docker create hsm-pki-server:local)
docker export "$cid" | tar -t | grep -icE 'softhsm|pkcs11|libctsw|cryptoki2|cknfast'    # 0
docker rm -f "$cid"

# The whole thing, on a machine with no HSM: two tokens, a root ceremony,
# the root token moved out of reach, the TLS identity and an operator
# certificate minted, then the service read-only and non-root on two ports.
deploy/docker/run-local.sh
```

```sh
# Vulnerability gate plus SBOM. Exits non-zero on any HIGH or CRITICAL.
ci/scan-image.sh
```

Baseline for this image: **53.8 MB, 19 layers**, UID 65532, two exposed
ports (public and mutual TLS), **11 OS packages**, and **zero HIGH/CRITICAL** findings (trivy
0.67.0, 2026-09-04; the pin is 0.74.0 now and the tree is still clean,
2026-09-15). Most of what an image scanner normally reports is
absent because the shell, the package manager and the toolchain are absent.

## What has been run

All three backends, in this image, with only `config.yaml` changing
between them:

- **SoftHSM2**: full startup, `connected to HSM`, a certificate issued
  (`201`; over plain HTTP at the time, over mutual TLS since the write
  endpoints moved behind it), the SQLite store written on a read-only
  root filesystem, and the root CRL served as DER and parsed by `openssl
  crl -inform DER`. `run-local.sh` repeats the whole path on every run,
  the OCSP query included.
- **ProtectToolkit-C 7.3.3 software emulation**: `connected to HSM`. The
  module loaded, the token resolved by label, the user login was
  established. Then a clean stop at the missing intermediate certificate,
  since no ceremony has been run against those tokens.
- **Luna Network HSM 7** (client 10.9.4, firmware 7.8.7, two partitions
  of the maintainer's appliance, 2026-09-24): the whole path. A ceremony
  on the two partitions, the TLS identity, the OCSP key and the first
  operator certificate from the dev image; then this image, read-only
  root filesystem, every capability dropped, the client directory mounted
  at its own absolute path (the paths in `Chrystoki.conf` are absolute)
  and `ChrystokiConfigurationPath` in the environment: `connected to
  HSM`, `intermediate CA ready`, `OCSP responder ready` with its key on
  the partition, both listeners up. Over mutual TLS a certificate was
  issued (`201`) and verified against the ceremony root by openssl, the
  OCSP responder said `good`, a revocation (`204`) turned that into
  `revoked` with the reason, and the leaf CRL served as DER carried the
  one entry; the same request without a client certificate was refused at
  the handshake. Afterwards `ci/token-cleanup -adapter luna` returned both
  partitions to zero objects. Two notes on the mounts: the client
  directory is mounted read-write, because the module keeps a lock file
  under `MutexFolder`, and a read-only root filesystem was otherwise
  enough; and the container ran as **UID 1000**, the owner of the client's
  key file, not the image's 65532, because that key is `0400` and a copy
  of a client identity was not going to be made for a test. UID 1000 is
  not in the image's passwd database and the Luna module did not mind,
  which is a point of contrast with the constraint below.

### An open constraint on the vendor path, measured but not explained

Running the vendor path as **UID 1000 fails at `C_Initialize` with
`CKR_DEVICE_ERROR`**, while UID 0 succeeds with identical mounts, identical
`$HOME`, and a token store that UID 1000 owns. The variable is the UID
alone.

The leading hypothesis is that the module resolves something through the
passwd database. A distroless image defines only `root`, `nonroot` (65532)
and `nobody`, so UID 1000 exists to the kernel but not to `getpwuid`. That
is a hypothesis. It has not been tested, because the test needs a token
store readable by a UID that is in passwd.

It matters because the pod runs as 65532. It does not affect SoftHSM2,
which runs as 65532, and SoftHSM2 is what CI runs. Nor does it affect
Luna: the run above was UID 1000, absent from the image's passwd, and
`libCryptoki2.so` initialized and connected regardless, so whatever
ProtectToolkit-C resolves through the passwd database, the Luna client
does not need it.
