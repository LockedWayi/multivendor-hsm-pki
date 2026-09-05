# `modules/`

Reusable OpenTofu modules, each describing *what* the platform needs, not
*which provider* happens to supply it — module directory names are nouns
for a role (`compute`), never a provider name (`hostinger`).

A module here holds no environment-specific value: every value that
differs between `environments/dev` and `environments/staging` is a
variable, supplied by that environment's `.tfvars`.

Modules land in this directory as sub-tasks 3.2+ give them real content.
The first is `compute/`, wrapping the imported `hostinger_vps` (see
, and the
"Provider and blast-radius control" decision for why this resource is
imported rather than created, and why it carries
`lifecycle { prevent_destroy = true }`).
