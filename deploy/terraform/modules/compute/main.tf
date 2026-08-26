# The VPS already exists -- it is the maintainer's own machine and, not
# incidentally, the machine this repository is developed on. It enters
# OpenTofu's state by `tofu import`, never by this resource creating one
# (see this module's README, "Import"). `prevent_destroy` is the control
# that makes managing a live, in-use resource an acceptable decision at
# all: it turns an accidental destroy/replace plan into a hard error
# instead of a live risk. Do not remove it to get past a blocked plan --
# a plan that wants to destroy or replace this resource means something
# upstream is wrong and needs investigating (CLAUDE.md, phase-3
# "Critical decision notes").
resource "hostinger_vps" "primary" {
  plan           = var.plan
  data_center_id = var.data_center_id
  template_id    = var.template_id
  hostname       = var.hostname
  ssh_key_ids    = var.ssh_key_ids

  lifecycle {
    prevent_destroy = true
  }
}
