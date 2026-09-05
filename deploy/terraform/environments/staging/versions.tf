terraform {
  # >= 1.10.0: this environment's backend.tf uses the S3 backend's native
  # `use_lockfile` locking (conditional writes), added in OpenTofu 1.10.0 --
  # verified against the OpenTofu release notes and against a local MinIO
  # instance (see backend.tf and).
  required_version = ">= 1.10.0"

  required_providers {
    hostinger = {
      source  = "hostinger/hostinger"
      version = "~> 0.1.22"
    }
  }
}
