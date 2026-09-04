#!/usr/bin/env python3
"""Prove that each rule in pod-hardening.yaml rejects, one rule at a time.

Run:  deploy/k8s/policy/policy-selftest.py

A policy that has only ever been shown to reject the deliberately-insecure
pod has been shown very little. That manifest violates every rule at once,
so admission reports the first one and the other seven are untested -- a
rule with a typo in its CEL would sit there passing everything for as long
as nobody wrote a pod that breaks only that rule.

So each case here is a *near miss*: a pod that satisfies every rule except
one, asserted to be refused with the message belonging to that rule. Plus
the baseline itself, which must be admitted -- a policy that rejects
everything is not a working policy, and without this case the suite would
be green if the CEL were simply `false`.

Two shapes of gap this is careful about, beyond one case per rule. A rule
that names several fields needs a case for each of them -- the host-namespace
rule covers hostNetwork, hostPID and hostIPC, and testing only the first
leaves two fields whose message claims coverage it has not demonstrated. And
a rule written as "on the pod OR on every container" has a second arm that is
never reached while the first is satisfied, so it gets a case that must be
*admitted*: a rule rejecting a correctly hardened pod is how an over-strict
policy gets switched off rather than fixed.

Three further things, each learned by getting it wrong first:

  * The namespace has no Pod Security Admission labels. In hsm-pki-dev, PSA
    refuses these pods before Kyverno sees them, so every case would pass
    while proving nothing about the policy under test.

  * `privileged: true` cannot be tested in isolation. The API server rejects
    it alongside `allowPrivilegeEscalation: false` as an invalid pod, so the
    request never reaches admission at all -- the first version of this
    suite reported that as a policy failure. The case therefore breaks both
    rules and relies on the policy's rule order to decide which is reported.

  * Init containers are a case, not an afterthought. A privileged init
    container has the same access as a privileged container, and a policy
    that walks only `spec.containers` is the usual way this is wrong.

All but one case runs as a server-side dry run, so nothing is scheduled.
The exception is the ephemeral-container case: `pods/ephemeralcontainers`
is a subresource of a pod that exists, so that one creates a compliant pod,
tries to attach a privileged container to it, and deletes it again.
"""

import copy
import json
import subprocess
import sys

NAMESPACE = "kyverno-policy-selftest"

# A signed image, by digest. Once deploy/k8s/policy/image-signature.yaml is
# installed, every pod here also passes through the image rules -- so an
# unsigned `busybox:1.36` makes each case fail for a reason that has nothing
# to do with the rule under test. Produced by ci/regen-image-fixtures.sh.
IMAGE = "k3d-hsm-pki-registry:5000/signed@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"

BASE = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "near-miss", "namespace": NAMESPACE},
    "spec": {
        "securityContext": {
            "runAsNonRoot": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "c",
                "image": IMAGE,
                "command": ["sh", "-c", "sleep 1"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"limits": {"memory": "64Mi"}, "requests": {"memory": "64Mi"}},
            }
        ],
    },
}


def drop(node, key):
    del node[key]


def case_host_network(p):
    p["spec"]["hostNetwork"] = True


def case_host_pid(p):
    p["spec"]["hostPID"] = True


def case_host_ipc(p):
    p["spec"]["hostIPC"] = True


def case_privileged(p):
    # Both flags, deliberately: see the module docstring.
    p["spec"]["containers"][0]["securityContext"].update(
        {"privileged": True, "allowPrivilegeEscalation": True}
    )


def case_escalation_unset(p):
    drop(p["spec"]["containers"][0]["securityContext"], "allowPrivilegeEscalation")


def case_writable_rootfs(p):
    p["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = False


def case_capabilities_kept(p):
    drop(p["spec"]["containers"][0]["securityContext"], "capabilities")


def case_run_as_root_allowed(p):
    drop(p["spec"]["securityContext"], "runAsNonRoot")


def case_seccomp_unset(p):
    drop(p["spec"]["securityContext"], "seccompProfile")


def case_no_memory_limit(p):
    drop(p["spec"]["containers"][0], "resources")


def case_runasnonroot_on_the_container(p):
    """The other arm of an `or`: satisfied per container, not on the pod."""
    drop(p["spec"]["securityContext"], "runAsNonRoot")
    p["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] = True


def case_seccomp_on_the_container(p):
    """As above, for the seccomp rule."""
    drop(p["spec"]["securityContext"], "seccompProfile")
    p["spec"]["containers"][0]["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}


def case_container_overrides_runasnonroot(p):
    """The pod looks hardened; the container quietly undoes it.

    This is the bypass the first version of the policy had. A container's
    securityContext overrides the pod's, so a rule written as "the pod says
    so OR every container says so" is satisfied by the pod-level clause and
    never looks at the container that overrode it.
    """
    p["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] = False


def case_container_overrides_seccomp(p):
    """As above, with Unconfined -- every syscall the kernel offers."""
    p["spec"]["containers"][0]["securityContext"]["seccompProfile"] = {"type": "Unconfined"}


def case_container_runs_as_uid_zero(p):
    p["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0


def case_pod_runs_as_uid_zero(p):
    p["spec"]["securityContext"]["runAsUser"] = 0


def case_privileged_init_container(p):
    p["spec"]["initContainers"] = [
        {
            "name": "i",
            "image": IMAGE,
            "command": ["true"],
            "securityContext": {
                "privileged": True,
                "allowPrivilegeEscalation": True,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
            "resources": {"limits": {"memory": "32Mi"}},
        }
    ]


CASES = [
    ("the compliant baseline, which must be ADMITTED", None, None),
    # One rule, three fields. Testing only the first would leave two
    # untested and the rule's message claiming all three.
    ("hostNetwork", case_host_network, "host namespaces"),
    ("hostPID", case_host_pid, "host namespaces"),
    ("hostIPC", case_host_ipc, "host namespaces"),
    ("a privileged container", case_privileged, "privileged container"),
    ("allowPrivilegeEscalation left unset", case_escalation_unset, "allowPrivilegeEscalation"),
    ("a writable root filesystem", case_writable_rootfs, "readOnlyRootFilesystem"),
    ("capabilities not dropped", case_capabilities_kept, "drop ALL"),
    ("runAsNonRoot left unset", case_run_as_root_allowed, "runAsNonRoot"),
    ("no seccomp profile", case_seccomp_unset, "seccomp"),
    ("no memory limit", case_no_memory_limit, "memory limit"),
    ("a privileged INIT container", case_privileged_init_container, "privileged container"),
    # The pod-versus-container override. Each of these was ADMITTED by the
    # first version of this policy: the pod-level clause of an `or` was
    # true, so the container that overrode it was never examined.
    ("a container overriding the pod's runAsNonRoot", case_container_overrides_runasnonroot, "runAsNonRoot"),
    ("a container overriding the pod's seccomp with Unconfined", case_container_overrides_seccomp, "seccomp"),
    ("a container running as UID 0", case_container_runs_as_uid_zero, "runAsUser 0"),
    ("the pod running as UID 0", case_pod_runs_as_uid_zero, "runAsUser 0"),
    # Two rules say "on the pod OR on every container", and the second arm
    # of an `or` is never reached while the first is satisfied. Both cases
    # must be ADMITTED: a rule that rejected them would be rejecting a pod
    # that is correctly hardened, which is how an over-strict policy gets
    # switched off rather than fixed.
    ("runAsNonRoot set per container, not on the pod", case_runasnonroot_on_the_container, None),
    ("seccomp set per container, not on the pod", case_seccomp_on_the_container, None),
]


def ensure_namespace():
    """Create the label-free namespace, if it is not already there."""
    manifest = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": NAMESPACE,
            # Named in the object so nobody has to guess why a namespace
            # with no Pod Security Admission labels is allowed to exist.
            "annotations": {
                "hsm-pki.io/purpose": "deliberately unlabelled, so Kyverno is "
                "the only thing that can refuse a pod here"
            },
        },
    }
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=json.dumps(manifest),
        capture_output=True,
        text=True,
        check=True,
    )


def apply_dry_run(pod):
    result = subprocess.run(
        ["kubectl", "apply", "--dry-run=server", "-f", "-"],
        input=json.dumps(pod),
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, (result.stderr or result.stdout).strip().replace("\n", " ")


COMPLIANT_POD = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "ephemeral-target", "namespace": NAMESPACE},
    "spec": {
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [
            {
                "name": "c",
                "image": IMAGE,
                "command": ["sh", "-c", "sleep 600"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "runAsUser": 65532,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"limits": {"memory": "64Mi"}},
            }
        ],
    },
}


def check_ephemeral_container_subresource():
    """Attach a privileged ephemeral container to a *running* pod.

    The one case that cannot be a dry run. Ephemeral containers are not
    added by updating a pod -- they go to `pods/ephemeralcontainers`, a
    subresource that exists only on a pod that exists. A policy matching
    only `pods` never sees the request, which is what `kubectl debug` uses.

    Measured before the policy matched the subresource: this succeeded. A
    privileged, root container was attached to a running pod in a namespace
    the policy covers, with every rule in force and none of them run.
    """
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=json.dumps(COMPLIANT_POD), capture_output=True, text=True, check=True,
    )
    try:
        subprocess.run(
            ["kubectl", "wait", "--for=condition=Ready",
             f"pod/{COMPLIANT_POD['metadata']['name']}", "-n", NAMESPACE, "--timeout=120s"],
            capture_output=True, text=True, check=True,
        )
        live = json.loads(subprocess.run(
            ["kubectl", "get", "pod", COMPLIANT_POD["metadata"]["name"], "-n", NAMESPACE, "-o", "json"],
            capture_output=True, text=True, check=True,
        ).stdout)
        live["spec"]["ephemeralContainers"] = [
            {
                "name": "debugger",
                "image": IMAGE,
                "command": ["sh", "-c", "sleep 300"],
                "targetContainerName": "c",
                "terminationMessagePolicy": "File",
                "imagePullPolicy": "IfNotPresent",
                "securityContext": {
                    "privileged": True,
                    "runAsUser": 0,
                    "allowPrivilegeEscalation": True,
                },
            }
        ]
        result = subprocess.run(
            ["kubectl", "replace", "--raw",
             f"/api/v1/namespaces/{NAMESPACE}/pods/{COMPLIANT_POD['metadata']['name']}/ephemeralcontainers",
             "-f", "-"],
            input=json.dumps(live), capture_output=True, text=True,
        )
        message = (result.stderr or result.stdout).strip().replace("\n", " ")
        if result.returncode == 0:
            return False, "ATTACHED — the subresource is not matched by the policy"
        if "privileged container" in message:
            return True, "refused, naming its own rule"
        return False, f"refused for the wrong reason: {message[:110]}"
    finally:
        subprocess.run(
            ["kubectl", "delete", "pod", COMPLIANT_POD["metadata"]["name"],
             "-n", NAMESPACE, "--wait=false", "--ignore-not-found"],
            capture_output=True, text=True,
        )


def check_compliant_ephemeral_container():
    """A hardened ephemeral container must be ADMITTED.

    The rule this guards is the memory limit, and the trap is that
    Kubernetes *forbids* `resources` on an ephemeral container. Applying the
    limit rule to them therefore demanded a field the API server rejects,
    and refused every compliant `kubectl debug` in any covered namespace --
    for no security reason at all. Measured, after the rule had been in
    place and the suite had been green: the case that would have caught it
    did not exist, because every ephemeral case here was deliberately
    insecure.
    """
    target = dict(COMPLIANT_POD)
    target["metadata"] = dict(COMPLIANT_POD["metadata"], name="hardening-eph-target")
    subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(target),
                   capture_output=True, text=True, check=True)
    try:
        subprocess.run(["kubectl", "wait", "--for=condition=Ready",
                        "pod/hardening-eph-target", "-n", NAMESPACE, "--timeout=180s"],
                       capture_output=True, text=True, check=True)
        live = json.loads(subprocess.run(
            ["kubectl", "get", "pod", "hardening-eph-target", "-n", NAMESPACE, "-o", "json"],
            capture_output=True, text=True, check=True).stdout)
        live["spec"]["ephemeralContainers"] = [{
            "name": "debugger", "image": COMPLIANT_POD["spec"]["containers"][0]["image"],
            "command": ["sh", "-c", "sleep 30"], "targetContainerName": "c",
            "terminationMessagePolicy": "File", "imagePullPolicy": "IfNotPresent",
            "securityContext": {
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "runAsUser": 65532, "capabilities": {"drop": ["ALL"]},
            },
        }]
        r = subprocess.run(
            ["kubectl", "replace", "--raw",
             f"/api/v1/namespaces/{NAMESPACE}/pods/hardening-eph-target/ephemeralcontainers", "-f", "-"],
            input=json.dumps(live), capture_output=True, text=True)
        if r.returncode == 0:
            return True, "admitted"
        msg = (r.stderr or r.stdout).strip().replace("\n", " ")
        return False, f"REFUSED: {msg[:110]}"
    finally:
        subprocess.run(["kubectl", "delete", "pod", "hardening-eph-target", "-n", NAMESPACE,
                        "--wait=false", "--ignore-not-found"], capture_output=True, text=True)


def main():
    ensure_namespace()
    failures = 0
    for name, mutate, want in CASES:
        pod = copy.deepcopy(BASE)
        if mutate is not None:
            mutate(pod)
        admitted, message = apply_dry_run(pod)

        if want is None:
            ok = admitted
            detail = "admitted" if ok else f"REFUSED: {message[:110]}"
        elif admitted:
            ok = False
            detail = "ADMITTED — this rule does not fire"
        elif want in message:
            ok = True
            detail = "refused, naming its own rule"
        else:
            ok = False
            detail = f"refused for the wrong reason: {message[:110]}"

        print(f"  {'ok  ' if ok else 'FAIL'}  {name:46s} {detail}")
        failures += 0 if ok else 1

    ok, detail = check_ephemeral_container_subresource()
    print(f"  {'ok  ' if ok else 'FAIL'}  "
          f"{'a privileged EPHEMERAL container via kubectl debug':46s} {detail}")
    failures += 0 if ok else 1

    ok, detail = check_compliant_ephemeral_container()
    print(f"  {'ok  ' if ok else 'FAIL'}  "
          f"{'a HARDENED ephemeral container, which must be ADMITTED':46s} {detail}")
    failures += 0 if ok else 1

    total = len(CASES) + 2
    print(f"\n{total - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
