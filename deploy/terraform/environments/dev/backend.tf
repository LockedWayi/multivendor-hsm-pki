# Remote state: self-hosted MinIO (S3-compatible) on the same Hostinger
# VPS this platform runs on. Decided 2026-08-26 by the maintainer -- no
# new commercial account, consistent with this project's existing
# provider decisions (see "Provider and blast-radius control" in
#). Locking uses OpenTofu's native
# S3 conditional-write lock (`use_lockfile`, OpenTofu >= 1.10.0, see
# versions.tf), not DynamoDB -- MinIO supports the conditional-PUT
# semantics this depends on. Verified, not assumed: two concurrent
# `tofu apply` runs against a local MinIO container -- the first
# succeeded, the second failed with HTTP 412 PreconditionFailed on the
# lock object instead of racing it (,
# 3.4).
#
# `encrypt = false` is deliberate. Self-hosted MinIO has no KMS backend
# configured here, so requesting S3 server-side encryption either errors
# outright or is a no-op -- confirmed by testing (`encrypt = true`
# produced "NotImplemented: Server side encryption specified but KMS is
# not configured"). State confidentiality does not depend on it anyway:
# encryption.tf encrypts the state client-side, before any byte reaches
# MinIO, which is the stronger guarantee of the two -- see that file.
#
# `bucket`, `key`, and the `skip_*`/path-style flags are not secrets and
# are fixed here. The MinIO endpoint and credentials are deployment-
# specific and never hardcoded: supply the endpoint via
# `-backend-config=backend.tfvars` (copy backend.tfvars.example, which is
# gitignored) and credentials via the AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY environment variables. See
# docs/terraform-state-backend-setup.md for provisioning MinIO itself,
# including why it is bound to localhost rather than exposed publicly.
terraform {
  backend "s3" {
    bucket                      = "hsm-pki-platform-tfstate"
    key                         = "dev/terraform.tfstate"
    region                      = "us-east-1"
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
    use_lockfile                = true
    encrypt                     = false
  }
}
