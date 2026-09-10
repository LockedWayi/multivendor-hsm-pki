# `modules/compute`

Wraps the single `hostinger_vps` resource this platform manages: the
maintainer's own, already-existing Hostinger VPS, the same machine this
repository is developed on. See "Provider and blast-radius control" in
[the tree README](../../README.md) for the full reasoning. This README
covers the module itself.

This module never provisions a new VPS. It only imports one that already
exists.

## Scope boundary: no network or firewall resource

The Hostinger provider ships no firewall or network resource type. This was
checked before deciding. There is nothing else on this provider for
OpenTofu to manage, so this module stops at compute. Firewall rules and the
K3s install are applied outside OpenTofu's resource graph, through a
`remote-exec` or `null_resource` provisioner or by hand, against the
imported VPS's IP address once it is in state. That is a stated scope
boundary.

## Root password is unmanaged

`hostinger_vps` accepts an optional `password` argument. The provider's own
resource docs describe only `hostname`, `template` and SSH keys as
updatable after creation. Password is not among them. For a VPS that
already exists, is the maintainer's daily-use machine, and whose current
password the Hostinger API does not expose for comparison, setting
`password` here would mean one of two outcomes. Either OpenTofu wants to
"fix" a value it can never verify on every plan, or the provider ignores
it and the argument misleads a reader into thinking this module rotates
credentials. So this module never sets `password`. Root access continues
to be managed by SSH keys, outside this module. No output of this module
carries a secret. See `outputs.tf`.

## Import

This resource already exists, so it enters state by import, never by
`apply` creating it. Only the maintainer can run this step. It needs a real
Hostinger API token and the real VPS ID, neither of which this repository
or its CI ever holds:

```
export TF_VAR_hostinger_api_token=...   # never write it to a file in this repo
tofu -chdir=deploy/terraform/environments/dev import \
  'module.compute.hostinger_vps.primary' <real-vps-id>
```

After import, run `tofu -chdir=deploy/terraform/environments/dev plan` and
confirm the plan is empty, or shows only the intended attribute changes,
before running `apply` against this resource. This step is
**maintainer-verified, not CI-verified**. CI has no path to the
maintainer's Hostinger account, and none should be given to it.

## Inputs and outputs

See `variables.tf` and `outputs.tf`. Every environment-varying value this
module needs is a typed, described variable. Nothing is hardcoded.
