#!/usr/bin/env python3
"""Prove that image-signature.yaml rejects, one violation at a time.

Run:  deploy/k8s/policy/image-policy-selftest.py

The claim this policy makes is "an image nobody signed cannot run here".
The cases below are the ways that claim can be false, written before the
tests were: an image with no signature at all; one signed by a key the
inventory does not vouch for *for this purpose*; one named by a tag, where
the signature is over a digest the tag can be repointed away from; and the
same three arriving as an init container or attached to a running pod,
which is where a policy that only walks spec.containers stops looking.

Plus the platform's own signed image, which must be **admitted** -- without
it a policy that refuses everything would pass.

The fixtures live in the k3d registry and are set up by
ci/regen-image-fixtures.sh. Two of them share a digest and differ only in
repository, which demonstrates something worth seeing: a cosign signature is
stored per repository, so the same bytes are signed in one place and unsigned
in another.
"""

import copy
import json
import subprocess
import sys

NAMESPACE = "kyverno-policy-selftest"
REGISTRY = "k3d-hsm-pki-registry:5000"

SIGNED = f"{REGISTRY}/hsm-pki-server@sha256:c0a5d12e7a002ebad4a7ea6068d2a28586788d1e88e9705f411e865da7be18b8"
SIGNED_BY_TAG = f"{REGISTRY}/hsm-pki-server:local"
UNSIGNED = f"{REGISTRY}/unsigned@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"
# A signed image that has a shell. The service's own image is distroless, so
# a probe pod cannot run `sleep` in it -- the first version of the ephemeral
# case used it and the target pod never became Ready, which the suite
# reported as a policy failure rather than as its own broken fixture.
SIGNED_BUSYBOX = f"{REGISTRY}/signed@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"
WRONG_KEY = f"{REGISTRY}/wrongkey@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"

HARDENED_CONTAINER = {
    "name": "c",
    "command": ["sh", "-c", "sleep 1"],
    "securityContext": {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsUser": 65532,
        "capabilities": {"drop": ["ALL"]},
    },
    "resources": {"limits": {"memory": "64Mi"}},
}


def pod(image, *, init=None):
    """A pod that satisfies pod-hardening.yaml completely.

    That matters: a pod failing the hardening policy is refused before the
    image policy is consulted, and the suite would then be measuring the
    wrong rule while looking green.
    """
    p = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "image-probe", "namespace": NAMESPACE},
        "spec": {
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [dict(HARDENED_CONTAINER, image=image)],
        },
    }
    if init is not None:
        p["spec"]["initContainers"] = [dict(HARDENED_CONTAINER, name="i", image=init, command=["true"])]
    return p


CASES = [
    ("the platform's own signed image, which must be ADMITTED", pod(SIGNED), None),
    ("an image with no signature", pod(UNSIGNED), "signature by a key"),
    ("an image signed by the artifact key, not the image key", pod(WRONG_KEY), "signature by a key"),
    ("the signed image named by tag rather than digest", pod(SIGNED_BY_TAG), "written by digest alone"),
    ("an unsigned image as an INIT container", pod(SIGNED, init=UNSIGNED), "signature by a key"),
]


def apply_dry_run(manifest):
    r = subprocess.run(
        ["kubectl", "apply", "--dry-run=server", "-f", "-"],
        input=json.dumps(manifest), capture_output=True, text=True,
    )
    return r.returncode == 0, (r.stderr or r.stdout).strip().replace("\n", " ")


def check_ephemeral_unsigned():
    """Attach an unsigned image to a running pod through kubectl debug's path.

    The subresource again. A signed workload can be joined by an unsigned
    container after admission has approved the pod, and a policy matching
    only 'pods' never sees it.
    """
    target = pod(SIGNED_BUSYBOX)
    target["metadata"]["name"] = "image-ephemeral-target"
    target["spec"]["containers"][0]["command"] = ["sh", "-c", "sleep 600"]
    subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(target),
                   capture_output=True, text=True, check=True)
    try:
        subprocess.run(["kubectl", "wait", "--for=condition=Ready",
                        "pod/image-ephemeral-target", "-n", NAMESPACE, "--timeout=180s"],
                       capture_output=True, text=True, check=True)
        live = json.loads(subprocess.run(
            ["kubectl", "get", "pod", "image-ephemeral-target", "-n", NAMESPACE, "-o", "json"],
            capture_output=True, text=True, check=True).stdout)
        live["spec"]["ephemeralContainers"] = [{
            "name": "debugger", "image": UNSIGNED, "command": ["sh", "-c", "sleep 60"],
            "targetContainerName": "c", "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "runAsUser": 65532, "capabilities": {"drop": ["ALL"]},
            },

        }]
        r = subprocess.run(
            ["kubectl", "replace", "--raw",
             f"/api/v1/namespaces/{NAMESPACE}/pods/image-ephemeral-target/ephemeralcontainers", "-f", "-"],
            input=json.dumps(live), capture_output=True, text=True)
        msg = (r.stderr or r.stdout).strip().replace("\n", " ")
        if r.returncode == 0:
            return False, "ATTACHED — an unsigned image joined a running pod"
        if "signature by a key" in msg:
            return True, "refused, naming the signature rule"
        return False, f"refused for the wrong reason: {msg[:110]}"
    finally:
        subprocess.run(["kubectl", "delete", "pod", "image-ephemeral-target", "-n", NAMESPACE,
                        "--wait=false", "--ignore-not-found"], capture_output=True, text=True)


def ensure_namespace():
    """Create the label-free namespace, if it is not already there.

    No Pod Security Admission labels, for the same reason as
    policy-selftest.py: PSA would refuse some of these pods first and the
    suite would be measuring PSA while reporting on Kyverno.
    """
    manifest = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {
            "name": NAMESPACE,
            "annotations": {
                "hsm-pki.io/purpose": "deliberately unlabelled, so Kyverno is "
                "the only thing that can refuse a pod here"
            },
        },
    }
    subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(manifest),
                   capture_output=True, text=True, check=True)


def main():
    ensure_namespace()
    failures = 0
    for name, manifest, want in CASES:
        admitted, message = apply_dry_run(manifest)
        if want is None:
            ok, detail = admitted, ("admitted" if admitted else f"REFUSED: {message[:110]}")
        elif admitted:
            ok, detail = False, "ADMITTED — this rule does not fire"
        elif want in message:
            ok, detail = True, "refused, naming its own rule"
        else:
            ok, detail = False, f"refused for the wrong reason: {message[:110]}"
        print(f"  {'ok  ' if ok else 'FAIL'}  {name:56s} {detail}")
        failures += 0 if ok else 1

    ok, detail = check_ephemeral_unsigned()
    print(f"  {'ok  ' if ok else 'FAIL'}  {'an unsigned image as an EPHEMERAL container':56s} {detail}")
    failures += 0 if ok else 1

    total = len(CASES) + 1
    print(f"\n{total - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
