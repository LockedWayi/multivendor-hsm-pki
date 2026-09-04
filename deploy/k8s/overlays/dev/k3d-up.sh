#!/usr/bin/env bash
#
# Bring up the dev cluster: k3d, the node prerequisite, the operator-created
# objects, and the overlay.
#
# THE REASON THIS IS A SCRIPT AND NOT A README STEP. k3d runs the node as a
# container, so everything the node holds dies with `k3d cluster delete` --
# including the CA's SQLite store. That reintroduces, at the cluster level,
# exactly the regression Phase 3b.3 removed at the process level: a
# certificate revoked during an incident comes back valid, because the store
# that remembered the revocation is gone. A host-backed node directory plus
# fixed-path PersistentVolumes move that state out of the cluster, and
# getting that right by hand every time is not something to rely on.
#
#   deploy/k8s/overlays/dev/k3d-up.sh            create (or reuse) and apply
#   deploy/k8s/overlays/dev/k3d-up.sh --recreate delete the cluster first,
#                                               KEEPING the host-side state
#
# `--recreate` is the interesting one: it destroys the cluster and brings it
# back, and the CA's issued and revoked records survive, because they were
# never in the cluster.
#
# Prerequisite: deploy/docker/run-local.sh has been run once, which produces
# the ceremony artifacts and the tokens this reads from .local/dev.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CLUSTER="${HSM_PKI_K3D_CLUSTER:-hsm-pki}"
NODE="k3d-${CLUSTER}-server-0"
NS=hsm-pki-dev
LOCAL="$REPO_ROOT/.local/dev"

# One host directory backs everything that must outlive the cluster: the
# module, the token store and the CA's SQLite store. All three reach the pod
# as fixed-path PersistentVolumes, because a dynamically provisioned volume
# is keyed to its PVC's UID and so does not survive a rebuild -- see
# module-mount.yaml.
NODE_STATE="$REPO_ROOT/.local/k3d/node"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

for tool in k3d kubectl docker; do
    command -v "$tool" >/dev/null || { echo "$tool not on PATH" >&2; exit 1; }
done
[ -f "$LOCAL/etc/intermediate.pem" ] || {
    echo "run deploy/docker/run-local.sh first -- no ceremony artifacts in $LOCAL/etc" >&2
    exit 1
}

if [ "${1:-}" = "--recreate" ]; then
    log "deleting cluster $CLUSTER (host-side state in .local/k3d is kept)"
    k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
fi

if k3d cluster list "$CLUSTER" >/dev/null 2>&1; then
    log "cluster $CLUSTER already exists"
else
    log "creating cluster $CLUSTER with host-backed state"
    mkdir -p "$NODE_STATE/pkcs11" "$NODE_STATE/tokens" "$NODE_STATE/store"
    k3d cluster create "$CLUSTER" \
        --agents 0 --no-lb \
        --k3s-arg "--disable=traefik@server:0" \
        --volume "$NODE_STATE:/opt/hsm-pki@server:0" >/dev/null
fi

log "staging the node prerequisite"
# Idempotent: re-copying the module is harmless, and the token store is only
# seeded when empty so a running CA's tokens are never overwritten.
docker exec "$NODE" mkdir -p /opt/hsm-pki/pkcs11 /opt/hsm-pki/tokens /opt/hsm-pki/store
docker cp "$LOCAL/pkcs11/libsofthsm2.so" "$NODE:/opt/hsm-pki/pkcs11/"
if [ -z "$(ls -A "$NODE_STATE/tokens" 2>/dev/null)" ]; then
    echo "    seeding the token store (intermediate only -- the root's token is not copied)"
    docker run --rm -v "$LOCAL/tokens":/t alpine:3 tar -C /t -cf - . \
        | docker exec -i "$NODE" tar -C /opt/hsm-pki/tokens -xf -
else
    echo "    token store already populated, left alone"
fi
docker exec "$NODE" sh -c 'chown -R 65532:65532 /opt/hsm-pki/tokens /opt/hsm-pki/store; chmod 0770 /opt/hsm-pki/tokens /opt/hsm-pki/store'

log "importing the image"
docker image inspect hsm-pki-server:local >/dev/null 2>&1 || {
    echo "build it first: docker build -f deploy/docker/Dockerfile -t hsm-pki-server:local ." >&2
    exit 1
}
k3d image import hsm-pki-server:local -c "$CLUSTER" 2>&1 | tail -1
# Confirm it landed rather than assuming the import said so. Applying while
# the node lacks the image sends the pod into ImagePullBackOff, and kubelet's
# backoff then outlives the rollout wait even after the image arrives -- so
# the failure reads as "the deployment is broken" long after it is fixed.
for _ in $(seq 1 10); do
    if docker exec "$NODE" crictl images 2>/dev/null | grep -q 'hsm-pki-server'; then
        echo "    present on the node"
        break
    fi
    sleep 2
done
docker exec "$NODE" crictl images 2>/dev/null | grep -q 'hsm-pki-server' || {
    echo "image did not reach the node; not applying" >&2; exit 1; }

log "applying the overlay"
kubectl apply -k "$REPO_ROOT/deploy/k8s/overlays/dev" >/dev/null

log "creating the two operator-supplied objects"
# Neither can live in the repository: one is the ceremony's output, the other
# is a PIN. Recreated on every cluster because they are cluster state, unlike
# the CA store, which deliberately is not.
kubectl -n "$NS" delete configmap hsm-pki-config --ignore-not-found >/dev/null
kubectl -n "$NS" create configmap hsm-pki-config \
    --from-file=config.yaml="$LOCAL/etc/config.yaml" \
    --from-file=softhsm2.conf="$LOCAL/etc/softhsm2.conf" \
    --from-file=intermediate.pem="$LOCAL/etc/intermediate.pem" \
    --from-file=root.pem="$LOCAL/etc/root.pem" \
    --from-file=root-crl.pem="$LOCAL/etc/root-crl.pem" >/dev/null

pinfile="$(mktemp)"; trap 'rm -f "$pinfile"' EXIT
printf '%s' "${HSM_PKI_DEV_PIN:-1234}" > "$pinfile"
kubectl -n "$NS" delete secret hsm-pki-pin --ignore-not-found >/dev/null
kubectl -n "$NS" create secret generic hsm-pki-pin \
    --from-file=intermediate-pin="$pinfile" >/dev/null

kubectl -n "$NS" rollout restart deploy/hsm-pki >/dev/null 2>&1 || true
# Clear any pod already stuck in image-pull backoff from an earlier attempt;
# its backoff timer does not care that the image is now present.
kubectl -n "$NS" delete pod -l app.kubernetes.io/name=hsm-pki \
    --field-selector status.phase!=Running --ignore-not-found >/dev/null 2>&1 || true
log "waiting for the service"
kubectl -n "$NS" rollout status deploy/hsm-pki --timeout=180s

cat <<EOF

  kubectl -n $NS get endpoints hsm-pki
  kubectl -n $NS port-forward svc/hsm-pki 18080:8080

State that survives 'k3d cluster delete', all under $NODE_STATE:
  store/    the CA's issued and revoked records and its CRL number
  tokens/   the intermediate's SoftHSM2 token
  pkcs11/   the module
EOF
