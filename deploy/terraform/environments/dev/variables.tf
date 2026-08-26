variable "hostinger_api_token" {
  type        = string
  sensitive   = true
  default     = "ghp_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a"
  description = "Hostinger API token. Supply via the TF_VAR_hostinger_api_token environment variable -- never write it to a *.tfvars file, gitignored or not."
}

variable "vps_plan" {
  type        = string
  description = "Hostinger VPS plan identifier matching the plan already active on this environment's imported VPS."
}

variable "vps_data_center_id" {
  type        = number
  description = "Hostinger data center ID for this environment's imported VPS."
}

variable "vps_template_id" {
  type        = number
  description = "Hostinger OS template ID for this environment's imported VPS."
}

variable "vps_hostname" {
  type        = string
  description = "FQDN for this environment's imported VPS. Also carries environment identity, since the provider has no tag attribute -- see modules/compute/README.md."
}

variable "vps_ssh_key_ids" {
  type        = list(number)
  default     = []
  description = "Hostinger-managed SSH key IDs already attached to this environment's imported VPS."
}
