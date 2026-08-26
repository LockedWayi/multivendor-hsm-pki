# `deploy/terraform`

Infrastructure for this platform, described as OpenTofu (not Terraform —
see the "Terraform vs. OpenTofu" note in
[`docs/phases/phase-3-infrastructure.md`](../../docs/phases/phase-3-infrastructure.md)
for why). The directory keeps the name `terraform`: it holds HCL
infrastructure code, and the tool identity is a version/registry detail
recorded in `versions.tf`, not something worth encoding into a path.

Prerequisites, `init`/`plan`/`apply` walkthrough, and a description of each
module land here as sub-task 3.7 completes the phase. This file currently
covers what sub-task 3.1 establishes: layout and conventions, written down
before any resource exists.

## Layout

```
deploy/terraform/
  modules/            reusable pieces, no environment-specific values
    compute/          (3.2) wraps the imported hostinger_vps
  environments/
    dev/              real environment — the only one ever `tofu apply`-ed
    staging/          plan-only, see "Dev/staging with only one real VPS"
                       in phase-3-infrastructure.md
```

`environments/dev` and `environments/staging` are each an independent
OpenTofu root module — composed from the same `modules/`, differing only
in their `.tfvars`. OpenTofu has no built-in mechanism for one root module
to include another's configuration, so each environment carries its own
`versions.tf`; the two are kept identical by convention, and sub-task 3.3
diffs them as an explicit check that they *stay* identical.

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
environment/role) or a comment on the resource block instead. Recorded
here so a reader does not go looking for a `tags = {}` block that cannot
exist on this provider.

**Variables.** No environment-varying value (VPS plan, hostname, data
center, template, and — from 3.4 — backend credentials) is ever hardcoded
in a module; each is a typed variable with a `description`, and a default
only when the default is genuinely environment-independent.
`environments/<name>/terraform.tfvars` supplies the real values and is
gitignored; a committed `terraform.tfvars.example` documents the shape.

## Policy scanning

```
$ ci/terraform-scan.sh
```

Runs `trivy config` (not `tfsec` — tfsec is deprecated and merged into
Trivy, so "tfsec (or trivy config)" resolves to the maintained tool)
against `deploy/terraform`, failing on any HIGH/CRITICAL finding. Not yet
wired into CI (that is Phase 5); this is the local, maintainer-run form
for now.

A clean run here is a narrower claim than it looks. Trivy ships no rules
for `hostinger_vps` — confirmed by scanning a throwaway, deliberately
public `aws_s3_bucket` alongside this tree and watching Trivy flag it
correctly (proving the scanner itself works) while the real Hostinger
resources produce zero findings either way. So "0 misconfigurations" here
means "Trivy has nothing to say about this provider's narrow resource
surface," not "this configuration is provably free of every
misconfiguration class." See sub-task 3.5 in
[`docs/phases/phase-3-infrastructure.md`](../../docs/phases/phase-3-infrastructure.md)
for the full record, and 3.6 for how this phase demonstrates the scanner
catches something real despite that.

No suppression exists anywhere in this tree yet — there is nothing to
document a reason for. If one is ever added, it carries an inline comment
explaining why it was accepted, per this project's rule that an
unexplained suppression is worse than the finding.

## Provider verification (sub-task 3.1)

The `hostinger/hostinger` provider's own README states a Terraform ≥ 1.3.0
requirement and does not mention OpenTofu. `tofu init` was run against this
skeleton to confirm OpenTofu resolves it anyway (both tools speak the same
Terraform-registry protocol, and this provider embeds no HashiCorp-SDK
licensing gate that would block a non-Terraform client):

```
$ tofu -chdir=deploy/terraform/environments/dev init
```

Result: **succeeds.** `hostinger/hostinger` (latest at the time, `0.1.22`)
resolves from `registry.terraform.io` and installs cleanly under OpenTofu
1.12.6; `.terraform.lock.hcl` records the resolved version and hashes. No
fallback (a Terraform-registry mirror, or reopening the provider/platform
decision) was needed.
