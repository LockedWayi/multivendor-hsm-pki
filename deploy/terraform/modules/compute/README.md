# `modules/compute`

Wraps the single `hostinger_vps` resource this platform manages: the
maintainer's own, already-existing Hostinger VPS -- the same machine this
repository is developed on. See "Provider and blast-radius control" in
[](../../../../)
for the full reasoning; this README covers the module itself.

This module never provisions a new VPS. It only ever *imports* one that
already exists.

## Scope boundary: no network/firewall resource

Confirmed before deciding, not assumed: the Hostinger provider ships no
firewall or network resource type. There is nothing else on this provider
for OpenTofu to manage, so this module stops at compute. Firewall rules
and the K3s install are applied outside OpenTofu's resource graph -- via a
`remote-exec`/`null_resource` provisioner (or run by hand) against the
imported VPS's IP address once it is in state. That is a stated scope
boundary, not a missing sub-task.

## Root password is deliberately unmanaged

`hostinger_vps` accepts an optional `password` argument, but the
provider's own resource docs describe only `hostname`, `template`, and
SSH keys as updatable after creation -- password is not among them. For a
VPS that already exists, is already the maintainer's daily-use machine,
and whose current password the Hostinger API does not expose for
comparison, setting `password` here would mean one of two bad outcomes:
OpenTofu perpetually wants to "fix" a value it can never actually verify,
or the provider silently ignores it and the argument is dead weight that
misleads a reader into thinking this module rotates credentials it does
not. Both are worse than the alternative taken here: this module never
sets `password`, full stop. Root access continues to be managed the way
it already is (SSH keys), outside this module. Consequently, no output of
this module carries a secret either -- see `outputs.tf`.

## Import

This resource already exists, so it enters state by import, never by
`apply` creating it. Only the maintainer can run this step -- it needs a
real Hostinger API token and the real VPS ID, neither of which this
repository or its CI ever holds:

```
export TF_VAR_hostinger_api_token=...   # never write it to a file in this repo
tofu -chdir=deploy/terraform/environments/dev import \
  'module.compute.hostinger_vps.primary' <real-vps-id>
```

After import, run `tofu -chdir=deploy/terraform/environments/dev plan`
and confirm the plan is empty -- or only the attribute changes actually
intended -- before ever running `apply` against this resource. This step
is **maintainer-verified, not CI-verified**: CI has no
path to the maintainer's real Hostinger account, and none should be given
one.

## Inputs / outputs

See `variables.tf` and `outputs.tf` -- every environment-varying value
this module needs is a typed, described variable; nothing is hardcoded.
