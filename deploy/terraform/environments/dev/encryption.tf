# State encryption at rest, independent of what the storage backend can
# offer (see backend.tf for why that matters against self-hosted MinIO
# specifically). OpenTofu encrypts the state client-side -- AES-GCM with
# a key derived by PBKDF2 from a passphrase -- before it is ever written
# to the backend. Verified, not assumed: the object MinIO actually stores
# is ciphertext (an `encrypted_data` field), not a readable state document
# with resource attributes in the clear.
variable "state_encryption_passphrase" {
  type        = string
  sensitive   = true
  description = "Passphrase for this environment's state encryption key (PBKDF2-derived, per OpenTofu's `encryption` block). Supply via the TF_VAR_state_encryption_passphrase environment variable -- never in a file, gitignored or not."
}

terraform {
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_encryption_passphrase
    }
    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }
    state {
      method = method.aes_gcm.state
    }
  }
}
