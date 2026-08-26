variable "plan" {
  type        = string
  description = "Hostinger VPS plan identifier (e.g. \"hostingercom-vps-kvm2-usd-1m\"). Must match the plan already active on the imported VPS -- this module never provisions a new one."
}

variable "data_center_id" {
  type        = number
  description = "ID of the Hostinger data center the imported VPS runs in."
}

variable "template_id" {
  type        = number
  description = "OS template ID the imported VPS was provisioned with."
}

variable "hostname" {
  type        = string
  description = "Fully qualified domain name for the VPS. Also the place environment/role identity is recorded, since this provider has no tag attribute -- see this module's README."
}

variable "ssh_key_ids" {
  type        = list(number)
  default     = []
  description = "IDs of Hostinger-managed SSH public keys already attached to the VPS. Empty if SSH access to this VPS is not managed through the Hostinger provider."
}
