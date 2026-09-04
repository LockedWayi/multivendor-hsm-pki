# Test matrix: what runs where, and what a new backend must provide

Every test that touches a token runs against every backend the environment
provides (CLAUDE.md §2.4). This document is the inventory behind that rule:
what is being proved, where it lives, and what a vendor has to supply before
it can join the rotation.

It exists because the rotation is about to grow. SoftHSM2 and ProtectServer
run today; nShield and Luna are Phase 7, making four. The cost of adding the
third and fourth must be a registry entry and an adapter — not a survey of
every test file — and that only stays true if the inventory is written down.

---

## 1. Why more than one backend, in one paragraph

An abstraction exercised against one implementation is a guess. The
concrete version of that: this platform generated every private key,
including the CA root, with `CKA_SENSITIVE` explicitly false. PKCS#11 lets a
token disclose such a key in plaintext. SoftHSM2 declines to; ProtectToolkit
7.3.3 hands over all 32 bytes. Both are conformant, so for the entire life
of the project the claim "private keys never leave the HSM" was false on the
vendor backend and true on the one CI runs — under a green suite. A second
implementation is what turned that into a fixed defect
([`pkcs11-vendor-notes.md`](pkcs11-vendor-notes.md)). A third, fourth and
fifth are worth what they cost for the same reason.

---

## 2. The harness

`internal/hsmtest` owns backend selection, token provisioning and the skip
policy. A test asks for a backend and gets one:

```go
hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
    // b.Adapter, b.Primary, b.Secondary, b.PrimaryPIN, b.SecondaryPIN,
    // b.ModulePath, b.AdapterName, b.Label("key-v1")
})
```

Three properties of the harness matter for a new vendor:

- **Two tokens, always.** The CA hierarchy needs the root and the
  intermediate on separate tokens (Phase 3b), so `Backend` resolves
  `Primary` (intermediate) and `Secondary` (root). A single-token test uses
  `Primary` and ignores the other.
- **Run-scoped labels.** `b.Label(...)` folds a per-run id into every object
  name. Vendors whose tokens persist between runs would otherwise collide
  with their own previous run and trip the ceremony's overwrite guard.
- **One adapter at a time per module.** A PKCS#11 library permits one
  `C_Initialize` per process. Backends are constructed per subtest and
  closed by cleanup; `b.Release()` hands the module over early for tests
  that drive a CLI which opens its own adapter.

---

## 3. What runs on every backend today

| Suite | Tests | Proves |
|---|---:|---|
| `internal/pkcs11` `TestConformance` | 1 group, ~20 subtests | The `VendorAdapter` contract: sessions, login lifecycle, key generation and **key protection attributes**, sign/verify, encrypt/decrypt, wrap/unwrap, find/attributes, error mapping |
| `internal/ca` ceremony + intermediate | 12 | Two-token root ceremony, token-identity checks, fail-closed parameter validation, concurrency, `LoadIntermediate`'s startup gates |
| `internal/ca` issuance + signer | 15 | `crypto.Signer` over PKCS#11, CSR validation through to a signed leaf, CRL building, distribution points |
| `internal/api` HTTP surface | 27 | Issuance, revocation, CRL generation and caching, the DER artifact endpoints, readiness |
| `internal/signingkey` | 10 | Supply-chain key provisioning: protection attributes read back off the token, versioned-label enforcement, refusal of a taken label, HSM signature cross-checked in `crypto/ecdsa`, exported PEM parsed through `x509.ParsePKIXPublicKey`, and the refusal to provision onto a token that already holds a CA-hierarchy key |
| `cmd/hsm-pki-keytool` | 15 | The ceremony, the supply-chain key provisioning, and the signed key-inventory generation as an operator runs them, through the CLI's own adapter — including the two-token refusal and the openssl check of an HSM-made inventory signature |
| `cmd/hsm-pki-server` | — | Startup: workspace resolution, anchor login, ambiguous-label refusal |

Counted per backend, a full run executes **80 vendor-parameterised subtests
on each configured backend**, plus the conformance suite — 81 top-level
`Test.../<backend>` subtests in all. Re-measured 2026-09-04 after Phase
4.8's keytool subcommands landed (67 + 1 before that group, then 73 + 1
after the provisioning command), rather than maintained by hand:

```sh
go test -race -p 1 -v ./... | grep -cE '^=== RUN +Test[A-Za-z0-9_]+/SoftHSM2$'
```

The anchor matters. `--- PASS:` lines carry a timing suffix, so an
end-anchored pattern against them matches nothing and reports zero; and an
unanchored pattern counts nested subtests too, which is a different number
(124) measuring a different thing.

## 4. What deliberately does not multiply

These touch no token, so running them per vendor would cost time and prove
nothing:

- `internal/config` — YAML parsing and validation
- `internal/inventory` — the key inventory is a *document*. The key that
  signs it lives on an HSM, but the format, its validation rules and its
  signature verification are pure logic, and the openssl cross-check there
  needs no token
- `internal/store` — SQLite records, revocation, CRL counter
- `cmd/hsm-pki-server`'s health-check probe (`healthcheck_test.go`) — HTTP
  against a local test server and listen-address rewriting; it never opens a
  token, and `/healthz` is deliberately the endpoint that does not
- `internal/ca` white-box certificate checks (`intermediate_internal_test.go`)
  — properties of a certificate, built in software
- URL composition, error mapping, PEM/DER handling in `internal/api`

Two tests are **SoftHSM2-specific on purpose**, because they are about a
token layout no well-behaved backend would hand a test: the ambiguous-label
refusals in `cmd/hsm-pki-server` and `cmd/hsm-pki-keytool` provision two
tokens sharing one label. They use `hsmtest.SoftHSM2` and say why.

---

## 5. Adding a backend

What a vendor must provide before it can join `hsmtest`'s registry:

1. **An adapter** implementing `pkcs11.VendorAdapter`. If the existing core
   suffices — it did for ProtectServer, which needed zero vendor-specific
   overrides — this is a constructor and a name.
2. **Two user tokens**, provisioned out of band by the maintainer, each with
   a label and a user PIN. Two, not one: the ceremony refuses to put root
   and intermediate on the same token.
3. **A token serial number** reported by `C_GetTokenInfo`. The ceremony
   compares serials, not labels (CLAUDE.md §3.8); a backend that reports no
   serial cannot run the two-token tests and the harness says so explicitly.
4. **Environment variables** following the existing shape, so nothing is
   hard-coded: `<VENDOR>_MODULE`, `<VENDOR>_ROOT_WORKSPACE`,
   `<VENDOR>_INTERMEDIATE_WORKSPACE`, `<VENDOR>_ROOT_PIN`,
   `<VENDOR>_INTERMEDIATE_PIN`. Unset means skip, never fail.
5. **A setup document** in `docs/`, in the shape of
   [`protectserver-setup.md`](protectserver-setup.md): installation, token
   initialization, how to verify the module loads, and how to run the suite
   against it.
6. **Provenance confirmed** before a single test runs: the entitlement is
   the maintainer's own, never an employer's (CLAUDE.md §2.1, §2.2). This is
   a gate, not a formality — it is the reason this repository can be shown
   to anyone.

Then: one entry in `hsmtest`'s `registry`, and every test in §3 runs against
it. Nothing else should need to change. If something does, that is a defect
in the harness and belongs here as a finding.

`internal/signingkey` joined §3 in Phase 4.8 without touching the harness,
which is the property this section claims: a new suite reaches every
backend by calling `hsmtest.ForEach`, and a new backend reaches every suite
by adding a registry entry. Neither edits the other.

### Expected divergences to look for

The two backends run so far disagreed in ways worth checking on any new one,
because each was found the hard way:

| Behaviour | What to check |
|---|---|
| Disclosure of a non-sensitive private key | Generate with `CKA_SENSITIVE=false` and try to read `CKA_VALUE`. SoftHSM2 refuses, ProtectToolkit discloses. The platform now forces the attribute true; the check is whether the vendor honours it |
| Second `C_Initialize` in one process | SoftHSM2 tolerates it through a separate dlopen handle; ProtectToolkit rejects it with `CKR_CRYPTOKI_ALREADY_INITIALIZED` |
| Slot renumbering | Creating a slot renumbered existing ones on ProtectToolkit while serials held |
| Concurrency | `C_GetSlotList` deadlocked under concurrent callers on ProtectToolkit despite `CKF_OS_LOCKING_OK` |
| Digest handling | ProtectToolkit's `C_Verify` rejects an all-zero ECDSA digest its own `C_Sign` accepted |
| Protection attributes on generation | Ask the token, not the template: generate with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, then read both back with `C_GetAttributeValue`. Both current backends honour them on generation — but ProtectToolkit ignores `CKA_EXTRACTABLE=false` on *unwrap*, so the two paths must be checked separately |
| RNG reseeding across `C_Initialize` | Generate a key pair, close the library, reopen it, generate another. ProtectToolkit-C 7.3.3 **in software emulation** returns the same key pair both times — the RNG is seeded identically per `C_Initialize`, `C_GenerateRandom` included — so two keys provisioned by two runs are one key. SoftHSM2 reseeds. Check this on any new backend *before* trusting it with a key ([`lessons.md`](lessons.md) §8) |
| Object accumulation | Tokens that persist between runs accumulate test keys. The harness now destroys everything a run created (`hsmtest.Backend.Cleanup`), which took the residue from +215 objects per full run to +23. Historical litter from before that — roughly 3,000 objects on the maintainer's ProtectServer store — is deliberately left alone: a suite that deletes objects it did not create is a destructive operation aimed at somebody else's token, and clearing it is an operator's call |

---

## 6. Running it

SoftHSM2 alone, which is what CI does:

```sh
docker run --rm -v "$PWD":/repo -w /repo hsm-pki-dev go test -race ./...
```

Inside the container, not on the host — including for `ci/coverage.sh`. A
host with no SoftHSM2 skips every token-touching test, exactly as §2.4's
skip policy intends, and the suite is still green; what changes is that the
coverage those tests would have produced is gone. Measured 2026-09-04:
**34.2% on the host against 79.1% in the container**, from the same commit.
The coverage gate then goes red for a reason that has nothing to do with the
code it is measuring.

Every configured backend — note `-p 1`, which is required rather than
advisable when a vendor's token store is shared between package test
binaries ([`protectserver-setup.md`](protectserver-setup.md) §5):

```sh
docker run --rm -v "$PWD":/repo -w /repo \
  -v /opt/safenet:/opt/safenet:ro -v "$HOME/.cryptoki:/root/.cryptoki" \
  -e PROTECTSERVER_MODULE=... \
  -e PROTECTSERVER_ROOT_WORKSPACE=... -e PROTECTSERVER_INTERMEDIATE_WORKSPACE=... \
  -e PROTECTSERVER_ROOT_PIN -e PROTECTSERVER_INTERMEDIATE_PIN \
  hsm-pki-dev go test -race -p 1 ./...
```

To see which backends actually ran — worth checking, since a missing
variable skips silently by design:

```sh
go test -race -p 1 -v ./... | grep -oE '/(SoftHSM2|ProtectServer)$' | sort | uniq -c
```
