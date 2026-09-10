# The identity every keyless signature from this repository's pipeline
# carries. Sourced by the scripts that verify or re-attest keyless material.
#
# Fulcio writes the workflow reference into the certificate's subject
# alternative name. A push to main produces the first form, a release tag
# the second:
#
#   https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/heads/main
#   https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/tags/v<x.y.z>
#
# The issuer is GitHub's OIDC provider. Both values are checked by
# cosign verify with --certificate-identity and --certificate-oidc-issuer.

KEYLESS_OIDC_ISSUER="https://token.actions.githubusercontent.com"
KEYLESS_IDENTITY_MAIN="https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/heads/main"
KEYLESS_IDENTITY_REGEXP='^https://github\.com/LockedWayi/multivendor-hsm-pki/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$'
