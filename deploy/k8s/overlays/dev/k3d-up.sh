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

# The registry exists because cosign stores an image signature *in the
# registry* -- there is no local-only signing path -- so Phase 4.10 cannot
# verify anything at admission without one. It is k3d-managed and separate
# from the cluster, so `k3d cluster delete` leaves the signed image alone.
REGISTRY_NAME="${HSM_PKI_K3D_REGISTRY:-hsm-pki-registry}"
REGISTRY_HOST_PORT=5000
# Two names for one registry, and the difference matters exactly once. The
# host pushes and signs through localhost; the cluster pulls through the
# container name on the k3d network. Same registry, so a signature written
# through one is found through the other -- what a signature is stored under
# is the repository path and the digest, not the hostname used to reach it.
REGISTRY_FROM_HOST="localhost:$REGISTRY_HOST_PORT"
REGISTRY_IN_CLUSTER="k3d-$REGISTRY_NAME:$REGISTRY_HOST_PORT"
IMAGE_REPO="hsm-pki-server"

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

if k3d registry list "k3d-$REGISTRY_NAME" >/dev/null 2>&1; then
    log "registry k3d-$REGISTRY_NAME already exists"
else
    log "creating registry k3d-$REGISTRY_NAME"
    k3d registry create "$REGISTRY_NAME" --port "$REGISTRY_HOST_PORT" >/dev/null
fi

if k3d cluster list "$CLUSTER" >/dev/null 2>&1; then
    log "cluster $CLUSTER already exists"
else
    log "creating cluster $CLUSTER with host-backed state"
    mkdir -p "$NODE_STATE/pkcs11" "$NODE_STATE/tokens" "$NODE_STATE/store"
    # --registry-use writes the node's registries.yaml. Without it
    # containerd tries HTTPS against a plain-HTTP registry and the pod sits
    # in ImagePullBackOff with a TLS error that says nothing about the cause.
    k3d cluster create "$CLUSTER" \
        --agents 0 --no-lb \
        --k3s-arg "--disable=traefik@server:0" \
        --registry-use "k3d-$REGISTRY_NAME:$REGISTRY_HOST_PORT" \
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

log "publishing the image to the registry, by digest"
docker image inspect "$IMAGE_REPO:local" >/dev/null 2>&1 || {
    echo "build it first: docker build -f deploy/docker/Dockerfile -t $IMAGE_REPO:local ." >&2
    exit 1
}
docker tag "$IMAGE_REPO:local" "$REGISTRY_FROM_HOST/$IMAGE_REPO:local"
docker push -q "$REGISTRY_FROM_HOST/$IMAGE_REPO:local" >/dev/null

# The digest is read back from the registry rather than taken from the local
# image, because what the cluster will pull is what the registry holds. They
# agree today; asking the registry means they cannot silently stop agreeing.
DIGEST="$(docker inspect "$REGISTRY_FROM_HOST/$IMAGE_REPO:local" \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | grep "^$REGISTRY_FROM_HOST/" | head -1 | cut -d@ -f2)"
[ -n "$DIGEST" ] || { echo "could not resolve the pushed image's digest" >&2; exit 1; }
IMAGE_REF="$REGISTRY_IN_CLUSTER/$IMAGE_REPO@$DIGEST"
echo "    $IMAGE_REF"

log "applying the overlay"
kubectl apply -k "$REPO_ROOT/deploy/k8s/overlays/dev" >/dev/null

# The manifest carries a tag, and the deployment runs a digest. That is not
# a contradiction to tidy away: a digest is build output and changes with
# every build, so it cannot be a committed value, while a tag is a mutable
# pointer and so cannot be what is deployed. The reference
# is therefore resolved here, at deploy time, from the registry.
#
# The tag in the manifest is a placeholder that is never pulled, and the
# admission policy in deploy/k8s/policy/image-signature.yaml refuses a
# by-tag reference outright -- so applying the overlay without this step
# fails closed rather than quietly running an unverifiable image.
kubectl -n "$NS" set image deployment/hsm-pki "hsm-pki-server=$IMAGE_REF" >/dev/null

log "installing the admission policies"
# Part of bringing the cluster up, not a separate ritual: a cluster whose
# guardrails are applied by hand is a cluster that has run without them.
kubectl apply --server-side -f \
    "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION:-v1.19.0}/install.yaml" >/dev/null
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=300s >/dev/null
kubectl apply -f "$REPO_ROOT/deploy/k8s/policy/kyverno-rbac.yaml" >/dev/null
kubectl apply -f "$REPO_ROOT/deploy/k8s/policy/pod-hardening.yaml" >/dev/null

# The image-signature policy is applied only once the image it will demand a
# signature for actually has one. Applying it first would leave the cluster
# correctly refusing its own workload, which reads as a broken policy rather
# than as an unsigned image.
#
# Signing needs the supply-chain token's PIN, which is deliberately not
# something this script can invent. With it, the chain runs end to end in one
# command; without it, the cluster comes up with pod hardening enforced and
# the image rule absent, and says so rather than pretending.
if [ -n "${COSIGN_PKCS11_PIN:-}" ]; then
    log "signing the image and installing the image-signature policy"
    "$REPO_ROOT/ci/sign-image.sh" "$REGISTRY_FROM_HOST/$IMAGE_REPO@$DIGEST" >/dev/null
    # Rendered here rather than applied from the repository, because the k3d
    # registry speaks plaintext HTTP and the committed policy deliberately
    # does not carry that concession. Measured before this line existed: with
    # the committed policy, Kyverno spoke HTTPS to the HTTP registry, could
    # not verify, and refused the pod -- `ReplicaFailure: ... http: server
    # gave HTTP response to HTTPS client`. Fail-closed and correct, and the
    # cluster does not start, so the concession is made explicitly and only
    # here.
    devpolicy="$(mktemp)"
    go run "$REPO_ROOT/ci/generate-image-policy" -allow-insecure-registry \
        -inventory "$REPO_ROOT/docs/keys/key-inventory.json" > "$devpolicy"
    kubectl apply -f "$devpolicy" >/dev/null
    rm -f "$devpolicy"
    echo "    require-signed-images and require-image-digest are enforcing"
else
    echo
    echo "    NOTE: COSIGN_PKCS11_PIN is not set, so the image was not signed and"
    echo "    deploy/k8s/policy/image-signature.yaml was NOT applied. Pod hardening"
    echo "    is enforcing; the 'an unsigned image cannot run here' half is not."
    echo "    To close it:  COSIGN_PKCS11_PIN=... $0"
fi

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
