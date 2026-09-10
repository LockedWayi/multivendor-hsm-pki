# `deploy/terraform`

Infrastructure for this platform, described as OpenTofu. HashiCorp's BSL
relicensing is the reason it is not Terraform. See `docs/architecture.md`,
"OpenTofu on Hostinger". The directory keeps the name `terraform` because it
holds HCL infrastructure code. The tool is recorded in `versions.tf`.

## If you don't have the maintainer's Hostinger VPS

Read this first. This tree manages one specific machine: the maintainer's
own Hostinger VPS, imported into state, never created from scratch (see
"Why an imported VPS" below). Without access to that account and that VPS's
ID, you cannot run `tofu apply` here. A plan against `environments/dev`
without the real state behind it would try to create a VPS this
configuration was never designed to create.

What is reproducible with only this repo and your own Hostinger account:

- `tofu init`, `validate`, and `fmt -check` against either environment. The
  skeleton, the module, and the provider resolution do not depend on any
  real resource existing.
- `environments/staging`'s `tofu plan`. Staging is plan-only. One real VPS
  exists, and a second was not worth its monthly cost to prove a mechanism
  that `tofu plan` already proves.
- The whole thing against **your own** VPS: point `terraform.tfvars` and
  `backend.tfvars` at your own values (copy the `*.example` files), run
  your own `tofu import` (see `modules/compute/README.md`, "Import"), and
  everything from there behaves as it does in the maintainer's setup.
- `ci/terraform-scan.sh`: static analysis, no credentials needed.

## Prerequisites

- OpenTofu **>= 1.10.0**. The S3 backend's native `use_lockfile` locking
  requires it. See `environments/*/versions.tf` and `backend.tf`.
- A Hostinger account and API token, if you intend to `import`, `plan` or
  `apply` against a real VPS of your own.
- A reachable S3-compatible endpoint for state. The maintainer's setup is
  self-hosted MinIO; see `docs/terraform-state-backend-setup.md`. Any
  S3-compatible store works, since `backend.tf` only hardcodes the
  non-secret shape.
- [`trivy`](https://trivy.dev) if you want to run `ci/terraform-scan.sh`
  outside its container.

## Quickstart

```bash
# Credentials and secrets: environment variables, never a file.
export AWS_ACCESS_KEY_ID=...              # state backend
export AWS_SECRET_ACCESS_KEY=...
export TF_VAR_hostinger_api_token=...
export TF_VAR_state_encryption_passphrase=...   # a real, high-entropy passphrase

# Deployment-specific but non-secret values: a gitignored file each.
cp environments/dev/backend.tfvars.example   environments/dev/backend.tfvars
cp environments/dev/terraform.tfvars.example environments/dev/terraform.tfvars
# edit both to match your endpoint and your VPS's real attributes

tofu -chdir=environments/dev init -backend-config=backend.tfvars
tofu -chdir=environments/dev import 'module.compute.hostinger_vps.primary' <your-real-vps-id>
tofu -chdir=environments/dev plan     # confirm it is empty, or only what you intend
tofu -chdir=environments/dev apply    # only after the plan looks right
```

`environments/staging` follows the same `init` and `plan` steps and is never
applied.

## Layout

```
deploy/terraform/
  modules/
    compute/          wraps the imported hostinger_vps
  environments/
    dev/              real environment, the only one ever applied
    staging/          plan-only
```

`environments/dev` and `environments/staging` are each an independent
OpenTofu root module. They are composed from the same `modules/` and differ
only in their `.tfvars` and in `backend.tf`'s state `key`. That one field is
a structural exception: two environments cannot share a state object.
OpenTofu has no built-in mechanism for one root module to include another's
configuration, so each environment carries its own copy of `versions.tf`,
`backend.tf`, and `encryption.tf`, kept identical by convention. Diff them
when changing one.

## Modules

### `modules/compute`

Wraps the single resource this tree manages: `hostinger_vps`. Full reasoning
lives in `modules/compute/README.md`. Two points bear repeating.

**Why an imported VPS.** The Hostinger provider's only real resource is a
full VM. Managing nothing would leave no compute resource under code.
Provisioning a second, disposable VPS costs money every month for a risk
`prevent_destroy` already closes. The maintainer's existing VPS is imported
instead.

**Why `prevent_destroy` is not optional.** This VPS is also the machine this
repository is developed on. `lifecycle { prevent_destroy = true }` on
`hostinger_vps.primary` (`modules/compute/main.tf`) turns any plan that would
destroy or replace it into a hard error. If a plan ever wants to destroy or
replace this resource, something upstream is wrong. Removing the safeguard
to get past it is never the answer.

## Conventions

**Naming.** A resource's local name describes its role, never its
environment: `hostinger_vps.primary`, never `hostinger_vps.dev`. The
environment is expressed by the root module the resource is declared under
and the `.tfvars` it is planned with. Module directory names are nouns for
what they provision (`compute`), never the provider (`hostinger`).

**Tagging.** The `hostinger_vps` resource has no tag or label attribute.
This was checked against the provider's resource schema
(`hostinger/terraform-provider-hostinger`, `docs/resources/vps.md`). There
is nothing in the Hostinger API to attach a tag to. Where a tag would carry
metadata, this tree uses the resource's `hostname` (an FQDN can carry
environment and role) or a comment on the resource block.

**Variables.** No environment-varying value (VPS plan, hostname, data
center, template, backend credentials, the encryption passphrase) is
hardcoded in a module. Each is a typed variable with a `description`, and a
default only when the default is environment-independent.
`environments/<name>/terraform.tfvars` supplies the real values and is
gitignored. A committed `terraform.tfvars.example` documents the shape.

## Remote state

State lives in a self-hosted, S3-compatible MinIO bucket (`backend.tf`). It
is locked via OpenTofu's native S3 conditional-write locking
(`use_lockfile`) and encrypted client-side before it leaves the `tofu`
process (`encryption.tf`, OpenTofu's `encryption` block, independent of what
the storage backend does). Reasoning, provisioning steps, and why MinIO is
bound to `127.0.0.1` rather than exposed publicly:
`docs/terraform-state-backend-setup.md`.

## Policy scanning

```
$ ci/terraform-scan.sh
```

Runs `tofu fmt -check`, `tofu validate`, and `trivy config` against
`deploy/terraform`, failing on any HIGH or CRITICAL finding, plus Trivy's
secret scanner over the same tree. tfsec is deprecated and merged into
Trivy, so `trivy config` is the maintained tool. The script runs as a
required check in CI.

A clean `trivy config` run here is a narrower claim than it looks. Trivy
ships no rules for `hostinger_vps`. This was confirmed by scanning a
throwaway public `aws_s3_bucket` alongside this tree: Trivy flagged it while
the Hostinger resources produced zero findings regardless of content. "0
misconfigurations" here means Trivy has nothing to say about this
provider's resource surface.

No suppression exists anywhere in this tree. If one is ever added, it
carries an inline comment explaining why it was accepted.

### Proof the scanner catches something

Since `trivy config` has no reachable finding on this provider, the
demonstration uses Trivy's secret scanner. It pattern-matches file contents
regardless of provider. Two commits show it working end to end on a
realistic mistake, a hardcoded-looking token left in a variable's `default`:

- [`85f4ebb`](https://github.com/LockedWayi/multivendor-hsm-pki/commit/85f4ebb) introduces the mistake. `ci/terraform-scan.sh` exits 1, Trivy flags it `CRITICAL` (`github-pat`).
- [`45f802f`](https://github.com/LockedWayi/multivendor-hsm-pki/commit/45f802f) reverts it. `ci/terraform-scan.sh` exits 0 again.

## Provider verification

The `hostinger/hostinger` provider's own README states a Terraform >= 1.3.0
requirement and does not mention OpenTofu. `tofu init` was run against the
bare skeleton to confirm OpenTofu resolves it. Both tools speak the same
Terraform-registry protocol, and this provider embeds no HashiCorp-SDK
licensing gate that would block a non-Terraform client. It **succeeds**.
`hostinger/hostinger` resolves from `registry.terraform.io` and installs
under OpenTofu. `.terraform.lock.hcl` records the resolved version and
hashes. One caveat: the registry has no GPG key for this provider, so
`tofu init` falls back to checksum-only verification, not full
publisher-signature verification. That is a fact about Hostinger's own
publishing.
