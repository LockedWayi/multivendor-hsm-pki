# `deploy/terraform`

Infrastructure for this platform, described as OpenTofu (not Terraform —
see "Terraform vs. OpenTofu" in
[`docs/phases/phase-3-infrastructure.md`](../../docs/phases/phase-3-infrastructure.md)
for why HashiCorp's BSL relicensing is the reason). The directory keeps
the name `terraform`: it holds HCL infrastructure code, and the tool
identity is a version/registry detail recorded in `versions.tf`, not
something worth encoding into a path.

## If you don't have the maintainer's Hostinger VPS

Read this first — it changes what you can actually run. This tree manages
one specific, real machine: the maintainer's own Hostinger VPS, imported
into state, never created from scratch (see "Why an imported VPS, not a
fresh one" below). Without access to that account and that VPS's ID, you
cannot run `tofu apply` here — there is nothing for OpenTofu to create; a
plan against `environments/dev` without the real state behind it would
try to *create* a VPS this configuration was never designed to create,
which is unlikely to be what you want.

What *is* reproducible with only this repo and your own Hostinger
account:

- `tofu init`, `validate`, and `fmt -check` against either environment —
  the skeleton, the module, and the provider resolution do not depend on
  any real resource existing.
- `environments/staging`'s `tofu plan` — it is plan-only by design (see
  the phase file's "Dev/staging with only one real VPS" decision), so it
  never needs a real second VPS to demonstrate the mechanism.
- The whole thing against **your own** VPS: point `terraform.tfvars` and
  `backend.tfvars` at your own values (copy the `*.example` files), run
  your own `tofu import` (see `modules/compute/README.md`, "Import"), and
  everything from there behaves identically to the maintainer's own setup.
- `ci/terraform-scan.sh` — pure static analysis, no credentials needed.

## Prerequisites

- OpenTofu **>= 1.10.0** (the S3 backend's native `use_lockfile` locking
  requires it — see `environments/*/versions.tf` and `backend.tf`).
- A Hostinger account and API token, if you intend to `import`/`plan`/
  `apply` against a real VPS of your own.
- A reachable S3-compatible endpoint for state (self-hosted MinIO in the
  maintainer's setup — see `docs/terraform-state-backend-setup.md`; any
  S3-compatible store works, since `backend.tf` only hardcodes the
  non-secret shape).
- [`trivy`](https://trivy.dev) if you want to run `ci/terraform-scan.sh`.

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

`environments/staging` follows the same `init`/`plan` steps but is never
`apply`-ed in this phase (see above).

## Layout

```
deploy/terraform/
  modules/
    compute/          wraps the imported hostinger_vps — see below
  environments/
    dev/              real environment — the only one ever `tofu apply`-ed
    staging/          plan-only, see "Dev/staging with only one real VPS"
                       in phase-3-infrastructure.md
```

`environments/dev` and `environments/staging` are each an independent
OpenTofu root module — composed from the same `modules/`, differing only
in their `.tfvars` (and, unavoidably, `backend.tf`'s state `key` — see
sub-task 3.3's record for why that one field is a structural exception,
not a violation of "differ only in tfvars"). OpenTofu has no built-in
mechanism for one root module to include another's configuration, so each
environment carries its own copy of `versions.tf`, `backend.tf`, and
`encryption.tf`, kept identical by convention; sub-task 3.3 diffs them as
an explicit check that they *stay* identical.

## Modules

### `modules/compute`

Wraps the single resource this phase manages: `hostinger_vps`. Full
reasoning lives in `modules/compute/README.md`; the two points worth
repeating here:

**Why an imported VPS, not a fresh one.** The Hostinger provider's only
real resource is a full VM. Managing *nothing* (leaving the VPS entirely
outside OpenTofu) would give sub-task 3.2 no real compute resource to
speak of; provisioning a *second, disposable* VPS costs real money every
month for a risk `prevent_destroy` already closes. The maintainer's
existing, already-in-use VPS is imported instead — real infrastructure,
real risk, real control, zero added cost.

**Why `prevent_destroy` is not optional.** This VPS is also the machine
this repository is developed on. `lifecycle { prevent_destroy = true }`
on `hostinger_vps.primary` (`modules/compute/main.tf`) turns any plan
that would destroy or replace it into a hard error instead of a live
risk — the one structural safeguard that makes managing a personally-used
machine with infrastructure-as-code an acceptable decision at all. If a
plan ever wants to destroy or replace this resource, that is a signal
something upstream is wrong and needs investigating — never a reason to
remove the safeguard to get past it.

## Conventions

**Naming.** A resource's local name describes its role, not its
environment — `hostinger_vps.primary`, never `hostinger_vps.dev`. Which
environment it belongs to is expressed by the root module it is declared
under and the `.tfvars` it is planned or applied with, never by encoding
the environment into the resource name itself. Module directory names are
nouns for what they provision (`compute`), not the provider (`hostinger`).

**Tagging.** The `hostinger_vps` resource has no tag or label attribute —
confirmed against the provider's resource schema
(`hostinger/terraform-provider-hostinger`, `docs/resources/vps.md`), not
assumed. Unlike an AWS/GCP-style provider, there is nothing in the
Hostinger API to attach a tag to. Where a tag would normally carry
metadata, this tree uses the resource's `hostname` (an FQDN can carry
environment/role) or a comment on the resource block instead.

**Variables.** No environment-varying value (VPS plan, hostname, data
center, template, backend credentials, the encryption passphrase) is ever
hardcoded in a module; each is a typed variable with a `description`, and
a default only when the default is genuinely environment-independent.
`environments/<name>/terraform.tfvars` supplies the real values and is
gitignored; a committed `terraform.tfvars.example` documents the shape.

## Remote state

State lives in a self-hosted, S3-compatible MinIO bucket (`backend.tf`),
locked via OpenTofu's native S3 conditional-write locking
(`use_lockfile`) and encrypted client-side before it ever leaves the
`tofu` process (`encryption.tf`, OpenTofu's `encryption` block —
independent of whatever the storage backend can or cannot do). Full
reasoning, provisioning steps, and why MinIO is bound to `127.0.0.1`
rather than exposed publicly: `docs/terraform-state-backend-setup.md`.
Verification record: `docs/phases/phase-3-infrastructure.md`, sub-task
3.4.

## Policy scanning

```
$ ci/terraform-scan.sh
```

Runs `trivy config` (not `tfsec` — tfsec is deprecated and merged into
Trivy, so "tfsec (or trivy config)" resolves to the maintained tool)
against `deploy/terraform`, failing on any HIGH/CRITICAL finding, plus
Trivy's secret scanner over the same tree. Not yet wired into CI (that is
Phase 5); this is the local, maintainer-run form for now.

A clean `trivy config` run here is a narrower claim than it looks. Trivy
ships no rules for `hostinger_vps` — confirmed by scanning a throwaway,
deliberately public `aws_s3_bucket` alongside this tree and watching
Trivy flag it correctly (proving the scanner itself works) while the real
Hostinger resources produce zero findings regardless of content. So "0
misconfigurations" here means "Trivy has nothing to say about this
provider's narrow resource surface," not "this configuration is provably
free of every misconfiguration class." Full record: sub-task 3.5 in
`docs/phases/phase-3-infrastructure.md`.

No suppression exists anywhere in this tree — there is nothing to
document a reason for. If one is ever added, it carries an inline comment
explaining why it was accepted, per this project's rule that an
unexplained suppression is worse than the finding.

### Proof the scanner catches something (sub-task 3.6)

Since `trivy config` has no reachable finding on this provider, the
demonstration uses Trivy's secret scanner instead — reachable regardless
of provider, since it pattern-matches file contents rather than resource
schemas, and directly on-topic for CLAUDE.md §3.2. Two commits show it
working end-to-end on a realistic mistake: a hardcoded-looking token left
in a variable's `default`.

- [`2f37c6f`](https://github.com/LockedWayi/hsm-pki-platform/commit/2f37c6f) — introduces the mistake; `ci/terraform-scan.sh` exits 1, Trivy flags it `CRITICAL` (`github-pat`)
- [`357496c`](https://github.com/LockedWayi/hsm-pki-platform/commit/357496c) — reverts it; `ci/terraform-scan.sh` exits 0 again

## Provider verification (sub-task 3.1)

The `hostinger/hostinger` provider's own README states a Terraform ≥ 1.3.0
requirement and does not mention OpenTofu. `tofu init` was run against the
bare skeleton to confirm OpenTofu resolves it anyway (both tools speak the
same Terraform-registry protocol, and this provider embeds no
HashiCorp-SDK licensing gate that would block a non-Terraform client):
**succeeds.** `hostinger/hostinger` resolves from `registry.terraform.io`
and installs cleanly under OpenTofu; `.terraform.lock.hcl` records the
resolved version and hashes. One caveat worth carrying forward: the
registry has no GPG key for this provider, so `tofu init` falls back to
checksum-only verification, not full publisher-signature verification —
a fact about Hostinger's own publishing, not something fixable from this
repo.
