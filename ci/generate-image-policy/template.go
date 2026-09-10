package main

import (
	"strings"
	"text/template"
)

// policyTemplate renders both objects. The comments are part of the
// output: the file is committed and read in diffs.
var policyTemplate = template.Must(
	template.New("policy").
		Funcs(template.FuncMap{"indentPEM": indentPEM, "singular": singular}).
		Parse(policyTemplateText),
)

// indentPEM indents a PEM block for a YAML block scalar.
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

// singular turns a container-list name into what one of them is called.
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
# ci/generate-image-policy. Edit the inventory and regenerate. A key pasted
# in here by hand is a hard-coded verifier, and it would make the next
# rotation a breaking change to the cluster.
#
# The inventory's signature was verified against
#   {{ .Anchor }}
# before this was rendered, and the document was inside its stated validity
# window (valid_until {{ .ValidUntil }}). A rendering the generator refuses
# to produce, for a bad signature, an expired document or a version
# rollback, never reaches this file.
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
# Both statuses are listed. "active" signs new images; "verify-only" signs
# nothing but still verifies what it signed before it was rolled. A policy
# that can hold only one key cannot express a transition window.
---
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: require-signed-images
spec:
  # Fail, not Ignore: an image whose signature could not be checked must
  # not run.
  failurePolicy: Fail
  validationActions:
    - Deny
  evaluation:
    mode: Kubernetes
{{- if .Insecure }}
  credentials:
    # DEVELOPMENT ONLY. Over plaintext there is no way to tell the registry
    # from anyone able to answer on its address. The local k3d registry
    # speaks HTTP; a real one must not.
    allowInsecureRegistry: true
{{- end }}
  matchConstraints:
    resourceRules:
      # kubectl debug attaches a container to a running pod through the
      # pods/ephemeralcontainers subresource. A policy matching only pods
      # never sees that request.
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
        # The durable signature is made with a long-lived key published in
        # a signed inventory, with no transparency-log entry. Kyverno
        # checks the log by default, so it has to be told. "insecure" is
        # Kyverno's word for the flag; here trust comes from a pinned
        # public key, not from a log.
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
    # A signature is made over a digest. A tag can be repointed after
    # admission approved what it resolved to.
    #
    # A plain contains('@sha256:') is not enough. When the image policy
    # verifies a tag-named image, Kyverno rewrites the pod to
    # repo:tag@sha256:<digest> before this policy runs, so a substring test
    # passes on a manifest whose author wrote a tag. This requires the last
    # path segment before the digest to carry no tag, which is the shape an
    # author writes.
    - expression: >-
        variables.allContainers.all(c,
          c.image.matches('^(.+/)?[^/:@]+@sha256:[a-f0-9]{64}$'))
      message: >-
        every image must be written by digest alone (repo@sha256:...), with
        no tag. A tag is a pointer somebody can move; a digest is the
        content. repo:tag@sha256:... is what Kyverno rewrites a tag-named
        image to, so seeing that here means the manifest named a tag.
`
