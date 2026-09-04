# Admission policy

Two mechanisms guard what may run on this cluster, and they are not
redundant copies of each other.

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
defines; it says nothing about resource limits, image references, or
anything else outside the pod security standard. The memory-limit rule in
`pod-hardening.yaml` is the plain example — a pod can satisfy `restricted`
completely and still take a node down by consuming all of its memory. Phase
4.10's image-signature rule is the one that matters more.

**Two mechanisms means two things to disable.** Neither is subtle to turn
off, and that is the point: a control that can be removed by one action is a
control with a single point of failure.

## Which Kyverno API, and why

Kyverno 1.19.0 serves two policy APIs and **both are v1** — measured against
the running cluster with `kubectl api-resources`, not read from a blog:

```
kyverno.io/v1            ClusterPolicy      (validate, mutate, generate, verifyImages)
policies.kyverno.io/v1   ValidatingPolicy, ImageValidatingPolicy, MutatingPolicy, …
```

This repository targets `policies.kyverno.io/v1`. Two reasons:

- The rules are **CEL**, the same expression language as Kubernetes' own
  `ValidatingAdmissionPolicy`. The expressions say what they mean to a
  reader who has never used Kyverno, and most of them would transfer to a
  cluster that does not run it.
- Phase 4.10 needs image-signature verification, and that group gives it a
  kind of its own (`ImageValidatingPolicy`, with `attestors[].cosign.key`
  for the published-public-key path this platform uses) rather than a mode
  of a general-purpose policy.

`ClusterPolicy` was the alternative and it is not a bad one: far more prior
art, and — checked, not assumed — **not marked deprecated** in the CRD. It
lost because choosing it would mean writing these rules twice, once now and
once when the newer kinds become the path Kyverno documents first.

## Proving it rejects

```sh
deploy/k8s/policy/policy-selftest.py
```

Fourteen cases, mostly **near misses**: a pod satisfying every rule except one,
asserted to be refused with the message belonging to that rule — plus the
compliant baseline, which must be admitted. The insecure pod in `testdata/`
breaks every rule at once, so admission reports the first and the other
seven go untested; a rule with a typo in its CEL would pass everything until
somebody wrote a pod that broke only it.

The self-test creates `kyverno-policy-selftest`, a namespace with **no** PSA
labels. In `hsm-pki-dev`, PSA refuses these pods before Kyverno sees them,
so every case would pass while proving nothing about the policy under test.
That is the same trap `testdata/insecure-pod.kyverno-rejected.txt` avoids,
and the reason it is a separate file from the PSA refusal beside it.

Everything runs as a server-side dry run: nothing is scheduled.

## Installing Kyverno

```sh
kubectl apply --server-side -f \
  https://github.com/kyverno/kyverno/releases/download/v1.19.0/install.yaml
kubectl apply -f deploy/k8s/policy/pod-hardening.yaml
```

`--server-side` is not optional: Kyverno's CRDs exceed the annotation size
limit that client-side apply uses to store the last-applied configuration.

The version is pinned. `latest` on an admission controller means the thing
that decides what may run in the cluster can change without anyone
deciding.

## The cost, stated

`failurePolicy: Fail`. If the webhook cannot be reached, pod creation stops
rather than proceeding unchecked (CLAUDE.md §3.4). That is the right trade
for a cluster whose job is custody of signing keys, and it is a real
availability cost on a single-node cluster where Kyverno and the workload
share a node.
