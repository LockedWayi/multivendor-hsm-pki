package main

import (
	"strings"
	"text/template"
)

// policyTemplate renders both objects. The comments are part of the output
// deliberately: the file lands in the repository and is read in diffs, and a
// generated policy with no explanation is one a reviewer approves without
// understanding.
var policyTemplate = template.Must(
	template.New("policy").
		Funcs(template.FuncMap{"indentPEM": indentPEM, "singular": singular}).
		Parse(policyTemplateText),
)

// indentPEM puts a PEM block where a YAML block scalar expects it. The key
// is public, so this is formatting rather than handling.
func indentPEM(pem string) string {
	var b strings.Builder
	for i, line := range strings.Split(strings.TrimRight(pem, "\n"), "\n") {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("            ")
		b.WriteString(line)
	}
	return b.String()
}

// singular turns a container-list name into what one of them is called, so
// the message reads "every init container image" rather than
// "every initContainers image".
func singular(list string) string {
	switch list {
	case "containers":
		return "container"
	case "initContainers":
		return "init container"
	case "ephemeralContainers":
		return "ephemeral container"
	}
	return list
}

const policyTemplateText = `# GENERATED FILE -- do not edit.
#
#   go run ./ci/generate-image-policy -out deploy/k8s/policy/image-signature.yaml
#
# Rendered from {{ .Source }} (version {{ .InventoryVer }}) by
# ci/generate-image-policy. Edit the inventory and regenerate; a key pasted
# in here by hand is exactly the hard-coded verifier the key lifecycle forbids,
# and it would make the next rotation a breaking change to the cluster.
#
# The inventory's signature was verified against
#   {{ .Anchor }}
# before this was rendered, and the document was inside its stated validity
# window (valid_until {{ .ValidUntil }}). A rendering the generator refuses
# to produce -- bad signature, expired document, version rollback -- never
# reaches this file.
#
# Trusted image keys in this rendering:
{{- range .Attestors }}
#   {{ printf "%-28s" .Label }}{{ .Status }}
{{- end }}
#
{{- if .Insecure }}
# WARNING: rendered with -allow-insecure-registry. See the credentials block.
{{- end }}
#
# Both statuses are here on purpose. "active" signs new images; "verify-only"
# signs nothing but still verifies what it signed before it was rolled. A
# policy able to hold only one key cannot express a transition window, so the
# day a new key appears is the day every running image becomes unverifiable.
---
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: require-signed-images
spec:
  # Fail, not Ignore: an image whose signature could not be checked -- an
  # unreachable registry, a policy that will not compile -- must not run
  #
  failurePolicy: Fail
  validationActions:
    - Deny
  evaluation:
    mode: Kubernetes
{{- if .Insecure }}
  credentials:
    # DEVELOPMENT ONLY. Rendered with -allow-insecure-registry, so this
    # policy will fetch signatures over plaintext HTTP. Over plaintext there
    # is no way to tell the registry from anyone able to answer on its
    # address, so the signature checked is whatever that party served. It is
    # here because the local k3d registry speaks HTTP; a real one must not.
    allowInsecureRegistry: true
{{- end }}
  matchConstraints:
    resourceRules:
      # pods/ephemeralcontainers for the same measured reason as
      # pod-hardening.yaml: ` + "`kubectl debug`" + ` attaches a container to a
      # running pod through a subresource, and a policy matching only pods
      # never sees the request. An unsigned debug image is still an unsigned
      # image running in the cluster.
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods", "pods/ephemeralcontainers"]
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
{{- range .ExcludedNS }}
            - {{ . }}
{{- end }}
  attestors:
{{- range .Attestors }}
    # {{ .Label }} ({{ .Status }})
    - name: {{ .Name }}
      cosign:
        # This platform signs with a long-lived key published in a signed
        # inventory and deliberately writes no transparency-log entry
        # (sub-task 4.9): Rekor exists to bound the lifetime of an ephemeral
        # Fulcio certificate, and a log entry here would put a record of
        # every internal release in public without changing the trust
        # decision. Kyverno checks the log by default, so it has to be told
        # -- otherwise it finds the signature and rejects it for lacking
        # something that was never meant to exist.
        #
        # "insecure" is Kyverno's word for the flag, and it is right about
        # the keyless model it defaults to. It is not right about this one,
        # where trust comes from a pinned public key that this policy
        # carries and not from a log.
        ctlog:
          insecureIgnoreTlog: true
          insecureIgnoreSCT: true
        key:
          data: |
{{ .PEM | indentPEM }}
{{- end }}
  validations:
{{- range .Lists }}
    - expression: >-
        images.{{ . }}.map(image, verifyImageSignatures(image,
          [{{ range $i, $a := $.Attestors }}{{ if $i }}, {{ end }}attestors.{{ $a.Name }}{{ end }}])).all(e, e > 0)
      message: >-
        every {{ . | singular }} image must carry a signature by a key the
        published inventory vouches for. Sign it with
        ci/sign-image.sh, or check docs/keys/key-inventory.json for which
        keys are trusted.
{{- end }}
---
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: require-image-digest
spec:
  failurePolicy: Fail
  validationActions:
    - Deny
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods", "pods/ephemeralcontainers"]
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
{{- range .ExcludedNS }}
            - {{ . }}
{{- end }}
  variables:
    - name: allContainers
      expression: >-
        object.spec.containers +
        (has(object.spec.initContainers) ? object.spec.initContainers : []) +
        (has(object.spec.ephemeralContainers) ? object.spec.ephemeralContainers : [])
  validations:
    # A signature is made over a digest. A tag is a mutable pointer, so a
    # tag-named image says nothing durable about what will run: the registry
    # can repoint it after admission approved what it resolved to.
    #
    # The regex is not decoration, and a plain contains('@sha256:') is not
    # enough. Measured: when the image policy verifies a tag-named image,
    # Kyverno rewrites the pod to repo:tag@sha256:<digest> BEFORE this
    # policy is evaluated. A substring test therefore passes on a manifest
    # whose author wrote a tag -- satisfied by Kyverno's own mutation rather
    # than by anyone's intent, and it would go on passing if image
    # verification were ever narrowed or removed, at which point the tag is
    # unpinned again and nothing says so.
    #
    # This requires the last path segment before the digest to carry no tag,
    # which is the shape an author writes and not the shape the mutation
    # produces.
    - expression: >-
        variables.allContainers.all(c,
          c.image.matches('^(.+/)?[^/:@]+@sha256:[a-f0-9]{64}$'))
      message: >-
        every image must be written by digest alone (repo@sha256:...), with
        no tag. A tag is a pointer somebody can move; a digest is the
        content. repo:tag@sha256:... is what Kyverno rewrites a tag-named
        image to, so seeing that here means the manifest named a tag.
`
