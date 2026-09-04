# Dev overlay (K3s, SoftHSM2)

Runs the CA on a local K3s cluster against SoftHSM2, in a namespace that
enforces Pod Security Admission at `restricted`.

## What you must create first, and why it is not in this repository

Two objects are deliberately absent from the manifests.

**The PIN Secret.** No secret enters this repository, ever (`CLAUDE.md`
§3.2). `secret.example.yaml` documents the shape:

```sh
kubectl -n hsm-pki-dev create secret generic hsm-pki-pin \
    --from-file=intermediate-pin=/path/to/pin-file
```

`--from-file` rather than `--from-literal`: a literal on a command line
reaches the shell history and the process list.

**The config ConfigMap.** It carries the ceremony's output, which is
produced by running the ceremony, not by anything checked in. None of it is
key material — the certificates and the CRL are public artifacts, and
`config.yaml` names the environment variable the PIN comes from rather than
holding a PIN:

```sh
kubectl -n hsm-pki-dev create configmap hsm-pki-config \
    --from-file=config.yaml \
    --from-file=softhsm2.conf \
    --from-file=intermediate.pem \
    --from-file=root.pem \
    --from-file=root-crl.pem
```

`deploy/docker/run-local.sh` produces all five of those in `.local/dev/etc/`,
so the fastest way to get a working set is to run it once.

`config.yaml` must point at the paths this overlay mounts:

```yaml
pkcs11:
  softhsm2:
    module_path: "/pkcs11/libsofthsm2.so"
ca:
  intermediate_cert_path: "/etc/hsm-pki/intermediate.pem"
  root_cert_path: "/etc/hsm-pki/root.pem"
  root_crl_path: "/etc/hsm-pki/root-crl.pem"
  store_path: "/var/lib/hsm-pki/ca.db"
```

and `softhsm2.conf` must set `directories.tokendir = /var/lib/softhsm/tokens`.

## The node prerequisite

No PKCS#11 module ships in the image, so the node has to hold one. On the
node this pod schedules to:

```sh
sudo mkdir -p /opt/hsm-pki/pkcs11 /opt/hsm-pki/tokens
sudo cp /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /opt/hsm-pki/pkcs11/
sudo chown -R 65532:65532 /opt/hsm-pki/tokens
sudo chmod 0770 /opt/hsm-pki/tokens
```

Copy the **real object**, not `/usr/lib/softhsm/libsofthsm2.so`, which on
Debian is a symlink — mounting a symlink reproduces a dangling link inside
the container and fails exactly like an absent module.

The token store must also actually contain the intermediate's token, and
must **not** contain the root's. On hardware that separation is a token in a
safe; here it is which directories you copy.

## Why the module arrives as a PersistentVolumeClaim

`restricted` forbids a pod from declaring a `hostPath` volume, and the
module has to come from the node. The resolution is not to weaken the
namespace: a pod may use a PVC whose PersistentVolume is node-local, and
that is the distinction the rule draws rather than a loophole. A `hostPath`
in a pod spec means whoever can create a pod can mount any path on the node
— the authority sits with the workload author. A PersistentVolume is
cluster-scoped and only an administrator can create one; the workload
receives a claim to something already chosen for it. Same bytes on the node,
authority in the right place.

## Applying

```sh
kubectl apply -k deploy/k8s/overlays/dev
kubectl -n hsm-pki-dev rollout status deploy/hsm-pki
kubectl -n hsm-pki-dev get endpoints hsm-pki
```

## Reading a failure

The service fails closed at startup by design, so a misconfiguration is a
pod that exits rather than one that serves errors. The distinctions worth
knowing:

| Symptom | Cause |
|---|---|
| Pod `Pending`, PVC unbound | The node-local PVs are missing — the prerequisite above was not run |
| `failed to load module` | `/pkcs11` has no module, or the copied file was the symlink |
| `CKR_SLOT_ID_INVALID` / workspace not found | The token store on the node does not hold a token with the configured label |
| `CKR_PIN_INCORRECT` | The Secret's value is not the token's user PIN |
| `reading CA certificate` | The ConfigMap is missing the ceremony artifacts |

## Two constraints that are not negotiable here

- **`replicas: 1` and `strategy: Recreate`.** Not capacity choices. The
  store is single-writer, and the CRL is cached per process — a second pod
  would serve a CRL missing another pod's revocations until `nextUpdate`,
  which is a wrong security answer rather than an error. `deployment.yaml`
  has the full reasoning.
- **`kubectl drain` on this node will block.** The PodDisruptionBudget is
  `minAvailable: 1` against a single replica, so taking the only CA offline
  is a deliberate act rather than a side effect of node maintenance. Scale
  to zero first if that is what you mean.
