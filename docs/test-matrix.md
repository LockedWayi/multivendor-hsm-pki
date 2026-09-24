# Test matrix: what runs where, and what a new backend must provide

Every test that touches a token runs against every backend the environment
provides. This document is the inventory behind that rule: what is being
proved, where it lives, and what a vendor has to supply before it can join
the rotation.

SoftHSM2, ProtectServer and, since 2026-09-23, Luna run today; nShield is
planned, making four. The cost of adding the third and fourth must be a
registry entry and an adapter, and that only stays true if the inventory
is written down. For Luna it held: a constructor, one registry entry in
each of the two lists below, and two findings absorbed without a branch on
the vendor's name (§5).

---

## 1. Why more than one backend, in one paragraph

An abstraction exercised against one implementation is a guess. The
concrete version of that: this platform generated every private key,
including the CA root, with `CKA_SENSITIVE` explicitly false. PKCS#11 lets
a token disclose such a key in plaintext. SoftHSM2 declines to.
ProtectToolkit-C 7.3.3 software emulation hands over all 32 bytes. Both
are conformant. For the entire life of the project the claim "private
keys never leave the HSM" was false on the vendor backend and true on the
one CI runs, under a green suite. A second implementation is what turned
that into a fixed defect.

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
  intermediate on separate tokens, so `Backend` resolves `Primary`
  (intermediate) and `Secondary` (root). A single-token test uses
  `Primary` and ignores the other.
- **Run-scoped labels.** `b.Label(...)` folds a per-run id into every
  object name. Vendors whose tokens persist between runs would otherwise
  collide with their own previous run and trip the ceremony's overwrite
  guard.
- **One adapter at a time per module.** A PKCS#11 library permits one
  `C_Initialize` per process. Backends are constructed per subtest and
  closed by cleanup. `b.Release()` hands the module over early for tests
  that drive a CLI or a server which opens its own adapter.

---

## 3. What runs on every backend today

| Suite | Tests | Proves |
|---|---:|---|
| `internal/pkcs11` `TestConformance` | 1 group, 26 cases | The `VendorAdapter` contract: sessions, login lifecycle, key generation and **key protection attributes**, sign/verify, encrypt/decrypt, wrap/unwrap, find/attributes, error mapping |
| `internal/ca` ceremony, re-issue + intermediate | 16 | Two-token root ceremony, token-identity checks, fail-closed parameter validation, concurrency, intermediate re-issue under an existing root, `LoadIntermediate`'s startup gates |
| `internal/ca` issuance, signer, service + profiles | 25 | `crypto.Signer` over PKCS#11, CSR validation through to a signed leaf, CRL building, distribution points, the profile deciding the certificate and a request without one refused |
| `internal/api` HTTP surface | 46 | Issuance, revocation, CRL generation and caching, the DER artifact endpoints, readiness (27); **mutual TLS on the write endpoints** over an HSM-held TLS identity, with the handshake, the store lookup and the identity lists each refusing on their own (8); the profile query parameter (2); the per-identity binding of profiles and names, every deny path (5); and the OCSP responder over both transports, its error responses, its absence without a key, the AIA pointer in new leaves and `openssl ocsp` agreeing with it (4) |
| `internal/signingkey` | 18 | Supply-chain key provisioning and destruction: protection attributes read back off the token, versioned-label enforcement, refusal of a taken label, the duplicate-key check, HSM signature cross-checked in `crypto/ecdsa`, exported PEM parsed through `x509.ParsePKIXPublicKey`, and the refusal to provision onto a token that already holds a CA-hierarchy key |
| `cmd/hsm-pki-keytool` | 24 | The ceremony, the supply-chain key provisioning, its retirement against the inventory, the signed key-inventory generation (18), and the three credential commands (6): the TLS identity, the first client certificate and the OCSP responder key, as an operator runs them through the CLI's own adapter, including the openssl-made request the runbook tells an operator to make and a real mutual handshake against the service |
| `cmd/hsm-pki-server` | 3 | Startup: workspace resolution and anchor login, an unknown workspace refused, a wrong PIN refused |

**133** per-backend subtests in total, measured 2026-09-23 inside the
container from the run that produced the per-suite numbers above, with:

```sh
go test -race -p 1 -v ./... | grep -cE '^=== RUN +Test[A-Za-z0-9_]+/SoftHSM2$'
```

The same command with `ProtectServer` or `Luna` in place of `SoftHSM2`
gives 133 for each (2026-09-24): every top-level per-backend subtest runs
on every registered backend. This is the top-level count, the one
`tools/bootstrap-workstation.sh` reports. Counting every nested subtest
under a backend as well (`--- PASS`/`SKIP` lines at any depth, the
conformance suite's 26 cases and the ceremony suite's inner cases
included) gives 196 per backend on the same run, which is what the
"passed" figure of a whole-run summary in §4 counts.

The count was 96 on 2026-09-10; the difference is the retirement
command, the credential commands, mutual TLS, profiles, the binding and
the responder.

The anchor matters. `--- PASS:` lines carry a timing suffix, so an
end-anchored pattern against them matches nothing and reports zero. An
unanchored pattern counts nested subtests too, which is a different number
measuring a different thing.

## 4. What does not multiply

These touch no token, so running them per vendor would cost time and
prove nothing:

- `internal/config`: YAML parsing and validation
- `internal/keyaudit`: reads the repository's own configuration files and
  compares them against the published inventory. It is a check on the
  repository, not on a token
- `internal/inventory`: the key inventory is a document. The key that
  signs it lives on an HSM, but the format, its validation rules, its
  validity window and its signature verification are pure logic, and the
  openssl cross-check there needs no token
- `internal/store`: SQLite records, revocation, CRL counter
- `internal/profile` and `internal/entitlement`: a profile is a
  vocabulary and a set of rules over a request, and a binding is a set
  of glob patterns over names; both are decided before a key is touched
- `internal/responder`: the OCSP responder's logic (status from the
  store, the cache and its invalidation, the error responses, the
  renewal half-life, `tryLater` under an expired certificate) over
  software keys. The HSM-signed path is `internal/api`'s OCSP tests,
  which run on every backend
- `internal/artifactsig`: the release-artifact verifier reads a bundle
  and a public key; nothing in it opens a token
- `cmd/hsm-pki-server`'s health-check probe (`healthcheck_test.go`): HTTP
  against a local test server and listen-address rewriting. It never opens
  a token, and `/healthz` is the endpoint that does not
- `internal/ca` white-box certificate checks
  (`intermediate_internal_test.go`): properties of a certificate, built in
  software
- URL composition, error mapping, PEM/DER handling in `internal/api`

Two tests are **SoftHSM2-only**, because they need a token layout no
vendor backend provides. The ambiguous-label refusals in
`cmd/hsm-pki-server` and `cmd/hsm-pki-keytool` provision two tokens
sharing one label. The server test provisions them through
`hsmtest.NewSoftHSM2Tokens` and says why in its comment. That is the one
exception to the every-backend rule in `cmd/`.

Three more run on every backend and **skip on ProtectToolkit-C software
emulation** after asserting a refusal: the TLS identity, the client
credential round trip and the OCSP key
(`TestCredentials_TheServiceAcceptsWhatTheKeytoolIssues`,
`TestRunProvisionTLSIdentityCmd_RefusesASecondKeyUnderTheSameLabel`,
`TestRunProvisionOCSPKeyCmd_ProvisionsAKeyTheServiceCanSignWith`). The
emulator's RNG restarts with every `C_Initialize` (§5), so the first key
pair a fresh process generates is one the token has handed out before,
and the command refuses to provision a duplicate. The test checks that
the refusal wrote nothing and freed the label, then skips with the
reason in the log, because what it exists to measure cannot be measured
on a token that is not a key source. The last full run on that backend,
before public #51 on 2026-09-23, reported 192 passed, 3 skipped, 0
failed, and those three are the skips; that figure counts subtests at
every depth, not the 133 top-level ones of §3 (196 at every depth on
2026-09-24, with the tests added since).

---

## 5. Adding a backend

What a vendor must provide before it can join `hsmtest`'s registry:

1. **An adapter** implementing `pkcs11.VendorAdapter`. If the shared
   implementation suffices, as it did for SoftHSM2 and ProtectToolkit-C
   software emulation, this is a constructor and a name. It was for Luna
   too (2026-09-23): what differed was absorbed in the shared path or
   declared per backend in the suite, not in the adapter. Expect nShield
   to need more.
2. **Two user tokens**, provisioned out of band by the maintainer, each
   with a label and a user PIN. Two, because the ceremony refuses to put
   root and intermediate on the same token.
3. **A token serial number** reported by `C_GetTokenInfo`. The ceremony
   compares serials, not labels. A backend that reports no serial cannot
   run the two-token tests, and the harness says so.
4. **Environment variables** following the existing shape, so nothing is
   hard-coded. For the harness: `<VENDOR>_MODULE`,
   `<VENDOR>_ROOT_WORKSPACE`, `<VENDOR>_INTERMEDIATE_WORKSPACE`,
   `<VENDOR>_ROOT_PIN`, `<VENDOR>_INTERMEDIATE_PIN`. For the conformance
   suite, which needs one token and a wrong PIN: `<VENDOR>_WORKSPACE` and
   `<VENDOR>_PIN`. Plus whatever the module itself reads from the process
   environment: `ET_PTKC_SW_DATAPATH` for the ProtectToolkit emulator,
   `ChrystokiConfigurationPath` for Luna, and `LUNA_ROLE` (`co`, `lco`,
   `cu`) for the role the conformance suite logs in as. **`<VENDOR>_MODULE`
   unset means skip.** Set, with any of the others missing, means fail:
   a half-configured backend is a configuration error, not an absent
   backend, and a run that quietly dropped the vendor is the run this
   file exists to prevent. Luna's harness and both conformance backends
   do this today; the ProtectServer harness still skips on a missing
   workspace or PIN, a gap recorded in the backlog.
5. **A setup document** the maintainer keeps outside this repository:
   installation, token or partition initialization, how to verify the
   module loads, and how to run the suite against it. It stays out of the
   public tree because it names the maintainer's own installation; the
   measurements it produces come here, into §5's table and the vendor
   notes.
6. **Provenance confirmed** before a single test runs: the entitlement is
   the maintainer's own, never an employer's. This is the reason this
   repository can be shown to anyone.

Then: one entry in `hsmtest`'s `registry`, and every test in §3 runs
against it. Nothing else should need to change. If something does, that is
a defect in the harness and belongs here as a finding.

**It is currently two entries, not one.** `internal/pkcs11`'s own
`TestConformance` predates the harness and keeps a backend list of its
own, so a new vendor today edits `hsmtest`'s `registry` and that list. No
import cycle forces this. `conformance_test.go` is an external test
package (`package pkcs11_test`) and could import `hsmtest`. Folding it in
would rework the conformance-specific setup (the wrong-PIN cases, the
reopen hook, its single-token layout) for modest gain, so the duplication
is accepted and recorded here.

The duplication is enforced against drift. `hsmtest.Vendors()` exports
the registry's names and `TestConformanceCoversEveryRegisteredVendor`
fails when the two lists disagree, by name and in order, so a rename or a
reorder is caught too. A vendor added to the harness and forgotten here
would run in every suite except the conformance one, the suite whose
purpose is finding vendor divergence, and everything would stay green.
This was verified by adding a third vendor to the registry alone and
watching the test go red.

The merge itself is not done. It is left for the vendor that makes it
necessary. Luna paid the two-entry cost first (2026-09-23): one entry in
each list, and the conformance entry also carries what the harness has no
shape for (a login identity per run, and two per-token declarations the
suite measures). nShield will be the second, and the point to decide
whether the merge is worth it.

`internal/signingkey` joined §3 without touching the harness, which is the
property this section claims: a new suite reaches every backend by calling
`hsmtest.ForEach`, and a new backend reaches every suite by adding a
registry entry. Neither edits the other.

### Expected divergences to look for

The backends run so far disagreed in these ways. Check each on any new
backend. The Luna column is Luna Network HSM 7 (firmware 7.8.7, Luna HSM
Client 10.9.4, password authentication), measured 2026-09-23 by the
maintainer; "not measured" means exactly that.

| Behaviour | What to check | Luna, measured |
|---|---|---|
| Disclosure of a non-sensitive private key | Generate with `CKA_SENSITIVE=false` and try to read `CKA_VALUE`. SoftHSM2 refuses, ProtectToolkit-C software emulation discloses. The platform now forces the attribute true. The check is whether the vendor honours it | Honours the forced `CKA_SENSITIVE=true` (read back). A non-sensitive request was not tried for private keys |
| Non-sensitive secret key | Generate an AES key with `CKA_SENSITIVE=false` | **Refused**, `CKR_ATTRIBUTE_VALUE_INVALID`, whatever `CKA_EXTRACTABLE` says. SoftHSM2 and ProtectToolkit-C create it. The platform now forces `CKA_SENSITIVE=true` on secret keys too, and the suite reads it back on every backend |
| Second `C_Initialize` in one process | SoftHSM2 tolerates it through a separate dlopen handle. ProtectToolkit-C rejects it with `CKR_CRYPTOKI_ALREADY_INITIALIZED` | Not measured separately; the suite's release-then-reopen paths pass |
| Slot renumbering | Creating a slot renumbered existing ones on ProtectToolkit-C while serials held | A partition deleted and another created: the new partition took the freed slot ID, under a new serial. The same slot ID named a different token before and after |
| Concurrency | `C_GetSlotList` deadlocked under concurrent callers on ProtectToolkit-C despite `CKF_OS_LOCKING_OK` | Not measured under concurrent callers (the adapter holds the exclusive lock). No hang in any run |
| Digest handling | ProtectToolkit-C's `C_Verify` rejects an all-zero ECDSA digest its own `C_Sign` accepted | Not measured |
| Object handle scope | SoftHSM2 2.6.1 answers `CKR_OBJECT_HANDLE_INVALID` when a handle found in one session is used in another. The base specification scopes a handle to the application, so this is a lookup per session on every backend | The per-session lookup passes; cross-session handle reuse not measured |
| Protection attributes on generation | Ask the token, not the template. Generate with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, then read both back with `C_GetAttributeValue`. Both current backends honour them on generation. ProtectToolkit-C ignores `CKA_EXTRACTABLE=false` on unwrap, so the two paths must be checked separately | Honoured on generation. The unwrap path could not be measured for private keys (next row) |
| Private-key wrapping | Wrap an extractable EC private key under an AES key | **Refused**, `CKR_KEY_NOT_WRAPPABLE`: partition policy "Allow private key wrapping" is off by default. Secret keys wrap. The suite declares the refusal and asserts it, failing if the wrap ever succeeds. The wrap-based backup in `key-ceremony-and-recovery.md` §5 needs that policy changed on Luna |
| Unwrap template for a secret key | Unwrap an AES key with and without `CKA_VALUE_LEN` | **Requires** it, and reports its absence as `CKR_ATTRIBUTE_TYPE_INVALID`. SoftHSM2 refuses the same attribute as `CKR_ATTRIBUTE_READ_ONLY`; ProtectToolkit-C takes either. No single template serves all three; the suite declares it per backend |
| Login identity | Which user type the credential logs in as | The Crypto Officer is `CKU_USER`; the Limited Crypto Officer is the vendor type `0x80000003` (`pkcs11.LunaRoleLimitedCryptoOfficer`). The conformance suite ran identically as either. A newly initialized role's password is expired: `C_Login` succeeds and the *next* call fails `CKR_PIN_EXPIRED` |
| RNG reseeding across `C_Initialize` | Generate a key pair, close the library, reopen it, generate another. ProtectToolkit-C 7.3.3 **in software emulation** returns the same key pair both times. The RNG is seeded identically per `C_Initialize`, `C_GenerateRandom` included, so two keys provisioned by two runs are one key. SoftHSM2 reseeds. Check this on any new backend before trusting it with a key | Reseeds (`TestTokenRNG_ReseedsAcrossInitializeOrTheDuplicateCheckCatchesIt` passes, and the three tests that skip on the emulator for this reason run) |
| Object accumulation | Tokens that persist between runs accumulate test keys. Both cleanups, `hsmtest.Backend.Cleanup` and the conformance suite's, destroy what a run created, and both **retry through a fresh connection** when the adapter has been closed by a test that closes it on purpose. With that retry, a full run on every backend leaves zero objects, measured on both software backends. Litter from before is not the suite's to delete. `ci/token-cleanup` is the operator's tool for that, dry by default | Zero objects on both partitions after a full run, checked with `ci/token-cleanup -adapter luna` |

---

## 6. Running it

Clearing what earlier runs left, when a persistent vendor token needs it.
This is an operator action, never something a test does:

```sh
go run ./ci/token-cleanup -adapter protectserver -module <path> \
    -workspace <label> -pin-env <VAR>            # dry run: lists, destroys nothing
go run ./ci/token-cleanup ... -confirm           # removes them
```

SoftHSM2 alone, which is what CI does:

```sh
docker run --rm -v "$PWD":/repo -w /repo hsm-pki-dev go test -race ./...
```

Inside the container, not on the host, including for `ci/coverage.sh`. A
host with no SoftHSM2 skips every token-touching test, as the skip policy
intends, and the suite is still green. The coverage those tests would have
produced is gone. Measured 2026-09-04: **34.2% on the host against 79.1%
in the container**, from the same commit. The coverage gate then goes red
for a reason that has nothing to do with the code it is measuring.

Every configured backend. `-p 1` is required: the package test binaries
would otherwise open the same vendor token store in parallel. All seven
ProtectServer variables, not the five the ceremony harness reads: with
`PROTECTSERVER_MODULE` set and `PROTECTSERVER_PIN` unset, the conformance
suite fails closed on a half-configured backend rather than skipping. For
Luna, all of `LUNA_MODULE`, `ChrystokiConfigurationPath`,
`LUNA_ROOT_WORKSPACE`, `LUNA_INTERMEDIATE_WORKSPACE`, `LUNA_ROOT_PIN`,
`LUNA_INTERMEDIATE_PIN`, `LUNA_WORKSPACE` and `LUNA_PIN`; `LUNA_ROLE` is
optional and defaults to the Crypto Officer. The Luna client directory is
mounted at the same path inside the container as outside, because
`ChrystokiConfigurationPath` and the certificate paths in `Chrystoki.conf`
are absolute; the container reaches the appliance through the host's
address, so the client registered for the host covers it.

```sh
docker run --rm -v "$PWD":/repo -w /repo \
  -v /opt/safenet:/opt/safenet:ro -v "$HOME/.cryptoki:/root/.cryptoki" \
  -v "$HOME/luna:$HOME/luna" \
  -e PROTECTSERVER_MODULE=... -e PROTECTSERVER_WORKSPACE=... -e PROTECTSERVER_PIN \
  -e PROTECTSERVER_ROOT_WORKSPACE=... -e PROTECTSERVER_INTERMEDIATE_WORKSPACE=... \
  -e PROTECTSERVER_ROOT_PIN -e PROTECTSERVER_INTERMEDIATE_PIN \
  -e ChrystokiConfigurationPath -e LUNA_MODULE -e LUNA_ROLE \
  -e LUNA_ROOT_WORKSPACE -e LUNA_INTERMEDIATE_WORKSPACE -e LUNA_WORKSPACE \
  -e LUNA_ROOT_PIN -e LUNA_INTERMEDIATE_PIN -e LUNA_PIN \
  hsm-pki-dev go test -race -p 1 -timeout 180s ./...
```

`tools/bootstrap-workstation.sh --with-protectserver --with-luna` runs
the same command with the same mounts, refusing when a variable is unset.

`-timeout 180s` because the ProtectToolkit-C software emulator blocks
forever inside `C_OpenSession` in some runs: three of six measured on
2026-09-23, under a single caller, at the 18th, 21st and 18th conformance
subtest, so not one input; not yet narrowed further. The slowest package takes
seconds, so the limit costs nothing on a healthy run and turns a hang into
three minutes and a goroutine dump. Keep the dump: it is the evidence, so
do not stop a hung run by hand. A test binary killed by its timeout runs
no `t.Cleanup`, which leaves that run's `conf-` objects on the persistent
emulator token, and because the emulator's RNG restarts from the same
seed, the next run's provisioning tests then fail their duplicate-key
check against those leftovers, in packages that did nothing wrong. After
any timed-out run, before the next one:

```sh
go run ./ci/token-cleanup -adapter protectserver -module "$PROTECTSERVER_MODULE" \
    -workspace "$PROTECTSERVER_WORKSPACE" -pin-env PROTECTSERVER_PIN -prefix conf-
go run ./ci/token-cleanup ... -prefix conf- -confirm
```

inside the dev image, with the same mounts and variables as the suite.

To see which backends ran, since a missing variable skips silently:

```sh
go test -race -p 1 -v ./... | grep -oE '/(SoftHSM2|ProtectServer|Luna)$' | sort | uniq -c
```

On 2026-09-24, on the tree that added Luna, that gave 133 for each of the
three, with 20 packages ok; ProtectServer's 133 include the three named
emulator skips, and Luna's conformance run has one skip whose refusal is
measured (the private-key wrap under the default partition policy).
