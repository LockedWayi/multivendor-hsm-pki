# Admission policy

Two mechanisms guard what may run on this cluster. They are not redundant
copies of each other.

| | Pod Security Admission | Kyverno |
|---|---|---|
| What it is | A fixed profile built into the API server | An admission webhook running rules this repository writes |
| Where it applies | Namespaces labelled for it | Every namespace except the ones named in the policy |
| What it can say | The `restricted` profile, exactly | Anything expressible in CEL |
| How it is turned off | A flag on the API server | Deleting a webhook |
| Evidence here | `testdata/insecure-pod.rejected.txt` | `testdata/insecure-pod.kyverno-rejected.txt` |

## Why both

**PSA is opt-in per namespace.** `hsm-pki-dev` carries
`pod-security.kubernetes.io/enforce: restricted`, so pods there are
constrained. A namespace created tomorrow without that label is constrained
by nothing, and nothing about `kubectl create namespace` prompts anyone to
add it. The Kyverno policy has the opposite default: everything, minus the
namespaces it names.

**PSA cannot be extended.** `restricted` is a profile the Kubernetes project
defines. It says nothing about resource limits, image references, or
anything else outside the pod security standard. The memory-limit rule in
`pod-hardening.yaml` is the plain example. A pod can satisfy `restricted`
completely and still take a node down by consuming all of its memory. The
image-signature rule matters more.

**Two mechanisms means two things to disable.** Neither is subtle to turn
off. A control that can be removed by one action is a control with a single
point of failure.

## Which Kyverno API, and why

Kyverno 1.19.0 serves two policy APIs and **both are v1**. This was measured
against the running cluster with `kubectl api-resources`:

```
kyverno.io/v1            ClusterPolicy      (validate, mutate, generate, verifyImages)
policies.kyverno.io/v1   ValidatingPolicy, ImageValidatingPolicy, MutatingPolicy, …
```

This repository targets `policies.kyverno.io/v1`. Two reasons:

- The rules are **CEL**, the same expression language as Kubernetes' own
  `ValidatingAdmissionPolicy`. The expressions say what they mean to a
  reader who has never used Kyverno, and most of them would transfer to a
  cluster that does not run it.
- Image-signature verification is a kind of its own in that group
  (`ImageValidatingPolicy`, with `attestors[].cosign.key` for the
  published-public-key path this platform uses) rather than a mode of a
  general-purpose policy.

`ClusterPolicy` was the alternative. It has far more prior art, and it is
**not marked deprecated** in the CRD. It lost because choosing it would
mean writing these rules twice, once now and once when the newer kinds
become the path Kyverno documents first.

## Proving it rejects

```sh
deploy/k8s/policy/policy-selftest.py
```

Nineteen cases, mostly **near misses**: a pod satisfying every rule except
one, asserted to be refused with the message belonging to that rule. Three
cases must be admitted, and one attaches a container to a running pod. The
insecure pod in `testdata/` breaks every rule at once, so admission reports
the first and the other eight go untested. A rule with a typo in its CEL
would pass everything until somebody wrote a pod that broke only it.

Four of the cases exist because the policy was **wrong** and the suite did
not notice:

- A container may override the pod's `securityContext`. The first version
  of two rules read "the pod says so **or** every container says so", so a
  pod declaring `runAsNonRoot: true` with a container setting it to `false`
  was admitted. The pod-level clause was true and the `or` short-circuited
  before the container was examined. Both rules now compute the effective
  value per container.
- Ephemeral containers do not arrive as a pod update. They go to
  `pods/ephemeralcontainers`, which the match rules did not name, so
  `kubectl debug` attached a privileged root container to a running pod
  with every rule in force and none of them run.

Neither is expressible as an obviously insecure manifest, which is why the
`testdata/` pod could not have found them.

The self-test creates `kyverno-policy-selftest`, a namespace with **no** PSA
labels. In `hsm-pki-dev`, PSA refuses these pods before Kyverno sees them,
so every case would pass while proving nothing about the policy under test.
`testdata/insecure-pod.kyverno-rejected.txt` avoids the same trap, and that
is why it is a separate file from the PSA refusal beside it.

Everything runs as a server-side dry run. Nothing is scheduled.

## Image signatures

`image-signature.yaml` is **generated**, never edited:

```sh
go run ./ci/generate-image-policy -out deploy/k8s/policy/image-signature.yaml
```

It renders every key the published inventory calls `active` or
`verify-only` for the image purpose, so rotation is a regeneration rather
than a breaking change to the cluster. The generator verifies the
inventory's signature, refuses an expired inventory, and refuses an
inventory whose version is lower than the one its existing rendering was
produced from. A key pasted in by hand is the hard-coded verifier the key
lifecycle forbids.

Two things took measurement to get right:

- **cosign v3 and Kyverno v1.19 disagree about where a signature lives.**
  v3 attaches it as an OCI referrers artifact. Kyverno looks for
  `sha256-<digest>.sig`, which is what cosign **v2** writes. This repository
  pins both versions, v3 for keyless signing and release artifacts, v2 for
  PKCS#11 image signatures, and `ci/cosign.sh` verifies each by the same
  four checks.
- **Kyverno rewrites a tag-named image** to `repo:tag@sha256:<digest>`
  before the validating policy runs. A `contains('@sha256:')` rule passes
  on a manifest that named a tag, satisfied by the mutation rather than by
  the author. `require-image-digest` matches the shape an author writes.

```sh
deploy/k8s/policy/image-policy-selftest.py
```

Six cases, written from the ways "an image nobody signed cannot run here"
can be false: unsigned; signed by the artifact key instead of the image
key; named by tag; unsigned as an init container; unsigned attached to a
running pod through `pods/ephemeralcontainers`; and the platform's own
signed image, which must be admitted. Fixtures come from
`ci/regen-image-fixtures.sh`. Three of them are the same bytes in different
repositories. A cosign signature is stored per repository, so that varies
what is signed without varying the image.

Only the durable signature made with `image-signing-key-v1` is accepted.
The pipeline's keyless signature is not in the inventory, so admission
ignores it.

## Installing Kyverno

```sh
kubectl apply --server-side -f \
  https://github.com/kyverno/kyverno/releases/download/v1.19.0/install.yaml
kubectl apply -f deploy/k8s/policy/kyverno-rbac.yaml
kubectl apply -f deploy/k8s/policy/pod-hardening.yaml
kubectl apply -f deploy/k8s/policy/image-signature.yaml
```

`deploy/k8s/overlays/dev/k3d-up.sh` does all of this, and renders the image
policy with `-allow-insecure-registry` because the local k3d registry speaks
plaintext HTTP. The committed policy does not carry that concession.

`--server-side` is required. Kyverno's CRDs exceed the annotation size limit
that client-side apply uses to store the last-applied configuration.

The version is pinned. `latest` on an admission controller means the thing
that decides what may run in the cluster can change without anyone
deciding.

## The cost, stated

`failurePolicy: Fail`. If the webhook cannot be reached, pod creation stops
rather than proceeding unchecked. That is the right trade for a cluster
whose job is custody of signing keys. It is a real availability cost on a
single-node cluster where Kyverno and the workload share a node.
