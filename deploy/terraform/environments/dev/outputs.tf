output "vps_id" {
  value       = module.compute.vps_id
  description = "Hostinger's internal ID for the managed VPS."
}

output "hostname" {
  value       = module.compute.hostname
  description = "The VPS's fully qualified domain name."
}

output "ipv4_address" {
  value       = module.compute.ipv4_address
  description = "Public IPv4 address of the VPS."
}

output "ipv6_address" {
  value       = module.compute.ipv6_address
  description = "Public IPv6 address of the VPS."
}

output "status" {
  value       = module.compute.status
  description = "Hostinger-reported provisioning status of the VPS."
}
