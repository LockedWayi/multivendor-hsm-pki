# `modules/`

Reusable OpenTofu modules. Each describes what the platform needs, not
which provider supplies it. Module directory names are nouns for a role
(`compute`), never a provider name (`hostinger`).

A module holds no environment-specific value. Every value that differs
between `environments/dev` and `environments/staging` is a variable,
supplied by that environment's `.tfvars`.

The first module is `compute/`, wrapping the imported `hostinger_vps`. See
"Provider and blast-radius control" in [the tree README](../README.md) for
why that resource is imported rather than created, and why it carries
`lifecycle { prevent_destroy = true }`.
