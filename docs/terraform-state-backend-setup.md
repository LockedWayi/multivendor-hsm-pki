# OpenTofu state backend: self-hosted MinIO

Sub-task 3.4 of `docs/phases/phase-3-infrastructure.md`. This document is
the maintainer's setup guide for the real MinIO instance the S3 backend
in `deploy/terraform/environments/*/backend.tf` talks to. Provisioning it
is a step only the maintainer can do (it touches the real VPS); this file
is what makes that step reproducible and reviewable rather than tribal
knowledge.

## Why MinIO, self-hosted, on the same VPS

Decided 2026-08-26. State needs a remote backend with locking and
encryption at rest (CLAUDE.md-adjacent acceptance criteria, phase-3
sub-task 3.4). The options considered:

- **Self-hosted MinIO on the existing Hostinger VPS (chosen).** S3-
  compatible, so OpenTofu's mature `s3` backend works against it
  unmodified. No new commercial account -- consistent with this
  project's existing "the maintainer's own, already-owned infrastructure"
  posture (see `docs/phases/phase-3-infrastructure.md`, "Provider and
  blast-radius control"). Tradeoff accepted: one more service to run and
  secure on that VPS.
- **Cloudflare R2** -- rejected: zero-ops, but adds a second external
  commercial account for a single-VPS project that otherwise has exactly
  one (Hostinger).
- **HCP Terraform / Terraform Cloud free tier** -- rejected: this project
  moved from Terraform to OpenTofu specifically over HashiCorp's BSL
  relicensing (see the "Terraform vs. OpenTofu" note in the phase file);
  routing state through HashiCorp's own SaaS the moment after making that
  point would read as inconsistent, and OpenTofu's support for the legacy
  TFC remote-state protocol was not going to be verified against a real
  account in this session anyway.

## Why MinIO is bound to localhost, not exposed publicly

The strongest access restriction available for a single-VPS setup is not
exposing the state backend to the network at all. This VPS is *both* the
machine `tofu` commands are run from/against (directly, or the maintainer
tunnels in over SSH) *and* the machine being managed -- so there is no
legitimate reason for MinIO's S3 API to be reachable from the public
internet. Bind it to `127.0.0.1` (or a private/VPN-only interface) and
never open its port on the public firewall. `backend.tfvars.example`
defaults to `http://127.0.0.1:9000` for exactly this reason -- running
`tofu` from anywhere other than the VPS itself means going through an SSH
tunnel (`ssh -L 9000:127.0.0.1:9000 <vps>`) or a private network path, not
punching a public hole for it.

## Provisioning MinIO

On the VPS (adjust paths/user to taste):

```bash
docker run -d --name minio-tfstate --restart unless-stopped \
  -p 127.0.0.1:9000:9000 \
  -v /srv/minio-tfstate/data:/data \
  -e MINIO_ROOT_USER=<root-user> \
  -e MINIO_ROOT_PASSWORD=<strong-generated-password> \
  minio/minio server /data
```

The root credentials are for bootstrapping only -- create a scoped user
and policy for OpenTofu to actually use (least privilege, and a
compromised `tofu` credential can only ever touch this one bucket):

```bash
mc alias set local http://127.0.0.1:9000 <root-user> <strong-generated-password>
mc mb local/hsm-pki-platform-tfstate
mc version enable local/hsm-pki-platform-tfstate   # see "Bucket versioning" below

mc admin user add local <tofu-access-key> <tofu-secret-key>
mc admin policy create local tfstate-rw ./tfstate-policy.json
mc admin policy attach local tfstate-rw --user <tofu-access-key>
```

`tfstate-policy.json` -- scoped to exactly this bucket, nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::hsm-pki-platform-tfstate",
        "arn:aws:s3:::hsm-pki-platform-tfstate/*"
      ]
    }
  ]
}
```

## Bucket versioning

OpenTofu's own S3-backend documentation recommends enabling bucket
versioning: the native `use_lockfile` locking does frequent small
writes/reads of a lock object right next to the state object, and
versioning is what lets a corrupted or wrongly-overwritten state be rolled
back. `mc version enable` above turns it on. If MinIO's storage cost ever
matters, a lifecycle rule capping the number of retained versions on the
lock object is the documented mitigation -- not disabling versioning.

## Using it

```bash
export AWS_ACCESS_KEY_ID=<tofu-access-key>
export AWS_SECRET_ACCESS_KEY=<tofu-secret-key>
export TF_VAR_hostinger_api_token=...
export TF_VAR_state_encryption_passphrase=...   # a real, high-entropy passphrase -- see encryption.tf

cp deploy/terraform/environments/dev/backend.tfvars.example \
   deploy/terraform/environments/dev/backend.tfvars
# edit backend.tfvars if MinIO is not reachable at 127.0.0.1:9000

tofu -chdir=deploy/terraform/environments/dev init \
  -backend-config=backend.tfvars
```

`environments/staging` uses the same MinIO instance with a different
state `key` (`staging/terraform.tfstate`) -- see backend.tf. Since staging
stays plan-only for this phase, its state will simply hold nothing beyond
plan-time provider negotiation; no separate MinIO setup is needed for it.

This whole document is **maintainer-verified, not CI-verified**
(CLAUDE.md §2.3): CI has no path to the maintainer's real VPS, and
building the S3 backend + locking + client-side encryption mechanics
themselves were verified locally against a throwaway MinIO container
(`docs/phases/phase-3-infrastructure.md`, sub-task 3.4) -- that proves the
*mechanism*, not that this specific production instance is correctly
provisioned. The maintainer confirms the real instance separately.
