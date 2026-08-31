provider "hostinger" {
  api_token = var.hostinger_api_token
}

module "compute" {
  source = "../../modules/compute"

  plan           = var.vps_plan
  data_center_id = var.vps_data_center_id
  template_id    = var.vps_template_id
  hostname       = var.vps_hostname
  ssh_key_ids    = var.vps_ssh_key_ids
}
