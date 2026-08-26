output "vps_id" {
  value       = hostinger_vps.primary.id
  description = "Hostinger's internal ID for the managed VPS."
}

output "hostname" {
  value       = hostinger_vps.primary.hostname
  description = "The VPS's fully qualified domain name."
}

output "ipv4_address" {
  value       = hostinger_vps.primary.ipv4_address
  description = "Public IPv4 address of the VPS."
}

output "ipv6_address" {
  value       = hostinger_vps.primary.ipv6_address
  description = "Public IPv6 address of the VPS."
}

output "status" {
  value       = hostinger_vps.primary.status
  description = "Hostinger-reported provisioning status of the VPS."
}

# No output here carries a secret: `password` is deliberately not one of
# this module's managed attributes (see the README), so there is nothing
# sensitive to mark. This is a design consequence, not an oversight --
# recorded so a reader does not go looking for a `sensitive = true` that
# has nothing to attach to.
