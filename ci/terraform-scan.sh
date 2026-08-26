#!/usr/bin/env bash
# Static misconfiguration scan for the OpenTofu tree, using `trivy config`.
#
# trivy, not tfsec: tfsec is deprecated and merged into Trivy (Aqua
# Security), so `trivy config` is the maintained tool the phase file's
# "tfsec (or trivy config)" choice resolves to.
#
# A clean run here is a narrower claim than it looks for this repo:
# Hostinger's `hostinger_vps` is not a resource type Trivy ships rules
# for (confirmed empirically, not assumed — see
# docs/phases/phase-3-infrastructure.md, sub-task 3.5), so a zero-finding
# run proves the tool executed and found nothing to say about *this*
# provider, not that the configuration is free of every possible
# misconfiguration class.
#
# Usage: ci/terraform-scan.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

trivy config --exit-code 1 --severity HIGH,CRITICAL "${REPO_ROOT}/deploy/terraform"
