# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- **The service image** (`deploy/docker/Dockerfile`): multi-stage, cgo-enabled
  build onto a digest-pinned `distroless/cc` base — 53.8 MB, no shell, no
  package manager, non-root UID 65532, read-only-root-filesystem compatible.
  `cmd/hsm-pki-keytool` is deliberately not in it: it is the only binary here
  that can reach a root token.
- **`hsm-pki-server -healthcheck`**, a self-probe against the process's own
  `/healthz`, so the image can carry a `HEALTHCHECK` without gaining a shell
  or an HTTP client. Liveness only — readiness touches the HSM, and a failed
  health check causes a restart.
- **`deploy/docker/run-local.sh`**: the whole platform on a machine with no
  HSM and no vendor SDK. Initializes two SoftHSM2 tokens, runs the real root
  ceremony, moves the root's token out of the store the service can reach,
  and starts the service read-only and non-root.

### Changed
- **No PKCS#11 module ships in any image.** Every module, SoftHSM2 included,
  is mounted at run time, so the backend CI exercises and the backend
  production uses are delivered by one mechanism rather than two. The image
  therefore contains no key store, and the same image runs against SoftHSM2
  and ProtectToolkit with only `config.yaml` changing — verified both ways.
  The cost, recorded rather than glossed: the image cannot start alone, which
  is what `run-local.sh` above exists to answer.

### Fixed
- **`FindObjects` silently truncated every search to 50 objects.** The
  pagination loop broke on the boolean `miekg/pkcs11` returns, which that
  library documents as "deprecated and should be ignored" and computes as
  `ulCount > max` — a condition `C_FindObjects` can never satisfy. Every
  search therefore returned at most one batch, with no error and a
  well-formed short list, which is invisible on a token holding fewer than
  50 objects. It now loops until a batch comes back empty.
  Consequences beyond the immediate: any future key inventory, rotation or
  audit that enumerates a populated token would have seen a truncated view.

### Added
- **`VendorAdapter.DestroyObject`** and per-run object cleanup in the test
  harnesses, pulled forward from Phase 4.8. A full both-backend run left
  +215 objects on a persistent token before this and +23 after. It takes an
  object handle rather than a label, because `CKA_LABEL` cannot identify an
  object (CLAUDE.md §3.8).

### Security
- **Private keys were generated with `CKA_SENSITIVE` explicitly false, and on
  ProtectToolkit 7.3.3 the private scalar was readable in plaintext by any
  authenticated session.** `KeyPairRequest` carried a `Sensitive` field no
  caller ever set, so the zero value went into every template — every CA key
  this platform had ever created, root included. PKCS#11 permits a token to
  reveal a non-sensitive private key through `C_GetAttributeValue`, and
  `CKA_EXTRACTABLE=false` does not cover that: it governs `C_WrapKey`, a
  different door.
  Measured on both backends, which disagreed: SoftHSM2 2.6.1 refuses the read
  (`CKR_ATTRIBUTE_SENSITIVE`) even though the attribute permits it, while
  ProtectToolkit returned all 32 bytes. Both are conformant, so the platform's
  central claim — private keys never leave the HSM — was false on the vendor
  backend and true on the one CI runs, with a green suite throughout.
  Fixed by removing the choice rather than correcting the call sites:
  `GenerateKeyPair` now forces `CKA_SENSITIVE=true` and the field is gone.
  `TestConformance/GenerateKeyPair_PrivateKeyIsSensitiveAndNonExtractable`
  reads both attributes back off the token on every configured backend.
  **Keys generated before this fix should be treated as exposed and rotated**
  if they were ever created on a token whose module discloses them; for the
  maintainer's ProtectServer development tokens, that is all of them.

### Added
- **`internal/hsmtest`**, the single registry every HSM-touching test now
  acquires its backend from, and **`docs/test-matrix.md`**, the inventory of
  what runs where. Before this, `internal/ca` and `internal/api` each carried
  their own copy of "provision a SoftHSM2 token, build an adapter, find the
  workspace", which is why 65 tests across the CA, the HTTP surface and both
  commands ran against SoftHSM2 alone. They now run against every configured
  backend as a subtest per vendor: a full run executes 59 vendor-parameterised
  subtests on each of SoftHSM2 and ProtectServer, up from 12.
  Adding nShield and Luna (Phase 7) is one registry entry and an adapter.
- **`docs/threat-model.md`** (Phase 3b sub-task 3b.5): assets ordered by what
  their loss costs, six trust boundaries, eight attacker classes, and for
  each one what a compromise yields *and* what it still does not. The
  centrepiece is the compromised-service-process case, since that is the
  compromise the two-tier hierarchy was built against. Seven explicit
  non-goals, including the two that matter most — the online tier is not
  defended against host root, and ceremonies in this repository have no
  separation of duties.
  It states plainly that `POST /certificates` has no authentication until
  Phase 5.5, so the deployment boundary is currently the authentication
  boundary.
  Two findings came out of writing it: that a PKCS#11 token login
  authenticates a *token* and not a key, so purpose-separated signing keys
  need separated tokens to deliver what CLAUDE.md §3.6 claims (now a
  "decide before provisioning" item in Phase 4.8); and that the revocation
  channel's *availability* is a security property, since a blocked CRL fetch
  and an unparseable CRL produce the same "proceed anyway" at the relying
  party.
- **CRL distribution point and AIA CA-Issuers extensions on every issued
  certificate** (`internal/ca`, Phase 3b sub-task 3b.4). A leaf now states
  where its revocation status is published (`<ca.base_url>/crl`) and where
  the certificate that signed it can be fetched
  (`<ca.base_url>/intermediate.crt`), so a relying party holding only the
  leaf can both build the path and check revocation. The intermediate's own
  equivalents were set at ceremony time in 3b.1 and point one tier up, at the
  offline root's CRL and certificate.
  `(*ca.CA).Issue` **fails closed** when it has no distribution points
  (`ca.ErrNoDistributionPoints`), checked before the CSR is parsed: an
  extension is fixed by the signature, so a certificate issued without a CDP
  can never gain one — it can only be revoked into a CRL nobody was told to
  fetch. No OCSP responder URL is written anywhere, and `ca.LeafDistribution`
  has no field for one, until the responder exists in Phase 5b.
- `GET /intermediate.crt` (`internal/api`): the service's own intermediate
  certificate, which is what every leaf's AIA CA-Issuers URL now points at.
  Without it the platform would have shipped certificates naming an endpoint
  that 404s — the same fail-honest violation it refuses for OCSP, one tier
  down. A server constructed without an issuer answers 503 rather than an
  empty 200, since a successful empty response is indistinguishable from a
  zero-length certificate to whoever fetched it.
- `ca.base_url` (`internal/config`): required, no default. The externally
  reachable origin of the service, which behind an ingress is not
  `server.listen_addr`. Validated as a URL that could actually be fetched,
  through the same check the ceremony's own distribution URLs use, and
  additionally rejected if it carries a query string or fragment, since the
  route paths are appended to it.
- **Anchor login** (`internal/pkcs11/tokenlogin.go`): `LoginToken` /
  `LogoutToken` / `TokenLoggedIn`. The service authenticates its token once
  at startup and stays authenticated until shutdown; sessions opened
  afterward inherit that authentication and perform no login of their own.
  This fixes a real defect — PKCS#11 authenticates a token for the whole
  application, not per session, so the previous login-and-logout-around-
  every-operation pattern broke with two requests in flight (the second
  `C_Login` returned `CKR_USER_ALREADY_LOGGED_IN`; the first caller's
  `C_Logout` de-authenticated the second mid-signature). Serializing the
  calls could not fix it, because the interference happened between them.
  Reproduced identically on SoftHSM2 2.6.1 and ProtectToolkit 7.3.3, which
  is what established it as the spec's model rather than a vendor bug; every
  test through Phase 2 was sequential, which is why it survived that long.
  The anchor session is held outside the janitor's tracking so it can never
  expire — an expiring anchor would drop authentication out from under
  in-flight requests. Verified with 10 concurrent `POST /certificates`
  against the maintainer's real ProtectServer token: all 201, all
  `openssl verify` OK, all serials distinct, zero login errors.
- `internal/pkcs11/conformance_test.go`: `LoginToken_AnchorLifecycle` and
  `LoginToken_ConcurrentCallsSerializeToOneWinner`, pinning `LoginToken` /
  `LogoutToken` / `TokenLoggedIn` directly at the layer that implements
  them. Previously these were only reached indirectly through
  `internal/ca` / `internal/api` tests, which is why `internal/pkcs11`'s
  own coverage profile showed 0.0% on all three despite the anchor-login
  fix above being otherwise fully verified — found during a maintainer
  double-check of the whole phase before starting Phase 3. Raised
  `internal/pkcs11`'s package coverage from 74.7% to 82.8% and
  `ci/coverage.sh`'s overall figure from 73.2% to 77.0%.
- Failure-path coverage completing Phase 2: `TestSigner_Sign_ExpiredSessionFailsClosed`
  (a white-box test — `Signer.Sign` opens its own session per call, so an
  already-expired budget can only be forced after a normal, successful
  construction, not from outside the package) and
  `TestIssueCertificate_AdapterErrorDoesNotLeakDetail` (an adapter-level
  failure surfaces as a 500 whose body never contains internal error text).
  `ci/coverage.sh` reports 76.0%.
- `GET /healthz` / `GET /readyz` (`internal/api`): liveness never touches
  the HSM; readiness probes it with an open+close session (no PIN needed)
  and reports not-ready once the adapter is closed. Every request now logs
  through a request-scoped `log/slog` logger with consistent field names
  (`request_id`, `method`, `path`, `status`, `duration_ms`).
- `POST /certificates/{serial}/revoke` and `GET /crl` (`internal/api`,
  `(*ca.CA).BuildCRL`): revocation is idempotent (re-revoking succeeds
  without error — a one-way state transition has no security effect from
  being requested twice) and 404s on an unknown serial. The CRL is signed
  through the same HSM-backed `Signer` as certificate issuance, cached
  until its configured `nextUpdate` (`ca.crl_validity_hours`), and
  invalidated immediately on every revocation rather than waiting for that
  cache to expire naturally. Verified with real `openssl crl -verify`.
- `POST /certificates` (`internal/api`): accepts a PEM or DER CSR and
  returns a signed certificate, or a 4xx with a specific reason for a
  malformed body, an unparseable CSR, or any rejection `internal/ca.CA.Issue`
  itself raises (bad signature, empty subject, disallowed key type) — never
  partially processed, and never recorded in `internal/api.Registry` on
  rejection. A 64 KiB body limit and a 15s request timeout are enforced at
  the HTTP transport layer (`http.MaxBytesReader`, `http.TimeoutHandler`);
  the timeout cannot be threaded into the underlying HSM call because
  `crypto.Signer`, the standard interface `Signer` implements, has no
  context parameter — documented as a real, stated constraint rather than
  papered over. Verified as a live process: `curl` against a running
  `cmd/hsm-pki-server` with real `openssl req`-generated CSRs, not only
  `httptest`.
- `internal/ca.CA`, `internal/ca.Bootstrap`: CA domain logic on top of the
  Phase 2 signer. `Bootstrap` decides between loading an existing CA and
  creating a new one by checking two independent signals — an HSM key under
  `ca.key_label` and a certificate file at `ca.cert_path` (new config
  fields) — and refuses to guess when only one is present, rather than risk
  signing under a mismatched key or duplicating a label meant to be unique.
  `Issue` validates a CSR's signature, subject, and key type (EC
  P-256/P-384/P-521 or RSA ≥ 2048 bits) before building a certificate;
  serials are 128 bits of `crypto/rand`, never sequential. Verified with
  `openssl verify` against a real issued certificate, not just Go's own
  `crypto/x509` round trip.
- `internal/ca.Signer`: a `crypto.Signer` backed by an HSM-resident EC key
  pair, reached through `VendorAdapter`. Every `Sign` call opens its own
  session and closes it again — it never holds one
  for its lifetime (`pkcs11.Session` fails closed on idle timeout / max TTL,
  so a service-lifetime session would eventually start failing every call
  for reasons unrelated to the request). `pkcs11.DecodeECPoint` moved from a
  test-only helper into the `pkcs11` package proper, fixing a long-form DER
  length bug the test-only version had for any EC point ≥128 bytes.
  Verified: `x509.CreateCertificate` produces a certificate over a
  SoftHSM2-resident key, and `cert.CheckSignatureFrom` accepts it.
- `cmd/hsm-pki-server`, `internal/config`, `internal/api`: the Phase 2 service
  skeleton. `internal/config` loads `config.yaml`, validates the selected
  adapter and its module path/workspace label/PIN-env-var name, and fails
  fast on an unknown adapter or a PIN environment variable that isn't set —
  before any HSM call is attempted. The PIN's value itself is never held on
  the `Config` struct; it is read once, at the point of use. `main.go`
  proves the configured adapter can actually open a session and log in
  before serving any traffic, and shuts down gracefully (drain, then close
  the adapter) on `SIGTERM`/`SIGINT`. Verified against both SoftHSM2 and the
  maintainer's ProtectServer token.
- Project scaffolding: `CLAUDE.md` engineering contract, architecture document,
  and phase specifications (Phases 1–7), centered on a multi-vendor PKCS#11 core.
- `internal/pkcs11`: vendor-agnostic `VendorAdapter` interface (session
  open/close, login/logout, key generation, find objects, sign/verify,
  encrypt/decrypt, get attribute, wrap/unwrap, generate random) and a
  SoftHSM2-backed implementation. Sessions enforce an idle timeout and a
  maximum TTL; PINs are held in a C-heap buffer we control and zeroize,
  never as a Go-heap string (see docs/phases/phase-1-pkcs11-core.md).
- `ci/softhsm2-dev.Dockerfile`: reproducible dev/test environment so the
  SoftHSM2-backed test suite runs the same way on any machine or in CI.
- `internal/pkcs11/protectserver.go`: `ProtectServerAdapter`, a full,
  independently-written second implementation of `VendorAdapter` against
  Thales ProtectToolkit-C. Every operation in the interface — session
  lifecycle, key generation, sign/verify, encrypt/decrypt, wrap/unwrap,
  generate random, find/get-attributes, close — is confirmed working
  against the maintainer's own ProtectToolkit installation by the
  conformance suite below.
- `internal/pkcs11/conformance_test.go`: `TestConformance`, one behavioral
  suite parameterized over a `VendorAdapter` factory, run against both
  backends. SoftHSM2's subtests run whenever its module is present (CI);
  ProtectServer's run only when `PROTECTSERVER_MODULE` is set and skip
  cleanly otherwise — the suite stays green either way. Every test vector is
  a real digest, plaintext, or key, never a degenerate stand-in — the earlier
  false "ProtectServer cannot verify" divergence (below) came from exactly
  that shortcut.
- `docs/protectserver-setup.md`: manual setup for the Thales ProtectToolkit
  backend — module paths, user-token initialization, and why this path is
  local-only and never in CI.
- `ci/coverage.sh` and `ci/coverage-exclude.txt`: the coverage floor,
  computed over CI-reachable code only. `ProtectServerAdapter` now contains
  real, non-trivial logic that CI structurally cannot execute (no
  proprietary SDK), so a blanket `go test ./... -cover` no longer measures
  what it used to — it conflates "untested" with "untestable here." The
  excluded files are validated instead by the conformance suite passing
  against real hardware, and that claim stays labelled maintainer-verified,
  never blended into a CI-reported percentage (CLAUDE.md §2.3).
- `docs/pkcs11-vendor-notes.md`: a living record of where PKCS#11
  implementations differ and of the portability traps (`CK_ULONG` width,
  `CKA_EC_POINT` encoding, raw `r||s` signatures, digest-vs-message
  mechanisms) that are easy to write and hard to notice. Every adapter reads
  it before being written and adds to it afterwards.
- First cross-vendor comparison run: pointing the SoftHSM2 adapter at the
  ProtectToolkit module showed the entire exercised surface — sessions, login,
  key generation, signing, verification, object lookup, attributes —
  transfers unchanged. One narrow divergence recorded: ProtectToolkit's
  `C_Verify` rejects a signature over an all-zero digest that its own
  `C_Sign` produced, where SoftHSM2 accepts it. Benign, since a real digest is
  never all-zero.
- **The signing layer, as a platform-wide principle** (documentation only in
  this change; the build lands in Phases 4 and 5). The PKCS#11 core is now
  stated as the platform's single signing foundation rather than only the CA's
  key store: certificates, container images, and release artifacts are each
  signed by their own HSM-held key over the same custody boundary. Recorded as
  a non-negotiable rule in `CLAUDE.md` §3.6 (three purpose-separated keys —
  `ca-root-key`, `image-signing-key`, `artifact-signing-key` — never
  interchangeable, fail-closed on anything unsigned) and explained in
  `docs/architecture.md` under "The signing layer: one core, three purposes",
  with the two design decisions behind it: purpose-separated keys rather than
  one platform key, and cosign rather than a first-party signing tool.
  The delivery checklist follows the dependency line: `docs/phases/
  phase-4-container-k8s.md` gains 4.8 (key provisioning through the Phase 1
  core via `cmd/hsm-pki-keytool`), 4.9 (release-artifact signing with
  `cosign sign-blob` over PKCS#11, cross-checked independently in Go with
  `crypto/ecdsa`), and 4.10 (image signing by digest, verified at admission by
  the Kyverno installed in 4.7); `docs/phases/phase-5-cicd.md` gains 5.9,
  which turns all of it into a blocking pipeline gate.
  Two facts established by reading cosign's own source rather than assuming
  them, and recorded where they will be needed: PKCS#11 support sits behind
  cosign's `pkcs11key` build tag, so the `pivkey-pkcs11key` release build is
  required and the default binary cannot open a token at all; and cosign opens
  the token through its own PKCS#11 binding, not through this repository's
  `VendorAdapter` — so what the CA path and the signing path share is the token
  and the standard, not our Go code, and the documentation says exactly that
  instead of implying more.

### Changed
- **Breaking (API, `internal/api`):** the artifacts behind the URLs embedded
  in certificates are served as **DER**, not PEM — `/root.crt`,
  `/root.crl` and `/intermediate.crt`, under `application/pkix-cert` and
  `application/pkix-crl` (RFC 2585 §3). `api.RootArtifacts` carries
  `CertDER`/`CRLDER` accordingly. PEM remains the on-disk format the
  ceremony writes and an operator copies; the conversion happens once at
  startup. See the Fixed entry below for why this is a correctness change
  rather than a preference.
- **Breaking (config):** `ca.base_url` is now required. Defaulting it, or
  omitting the extensions when it is unset, would mean the service silently
  issues certificates whose revocation cannot be discovered — and would do so
  most readily in exactly the deployment that forgot to configure it.
- **Breaking (API, `internal/ca`):** `NewCA` takes a fourth argument, a
  `ca.LeafDistribution`, and `ca.LoadIntermediateParams` gains a
  `Distribution` field. `LoadIntermediate` validates it before touching the
  token, so a service that could only reject every issuance fails at startup
  where an operator is watching instead.
- `internal/pkcs11/base.go`: the shared PKCS#11 plumbing (`pkcs11Adapter`)
  extracted from `SoftHSM2Adapter` and `ProtectServerAdapter` now that both
  have been run against real hardware. Every operation the conformance
  suite exercises turned out to need zero vendor-specific code — the one
  real divergence found (an all-zero-digest `Verify` rejection, ProtectServer
  only) is HSM behavior, not adapter logic, so it stays a documented fact in
  `protectserver.go` rather than a branch. `SoftHSM2Adapter` and
  `ProtectServerAdapter` are now each a named type embedding
  `*pkcs11Adapter` plus a constructor. Phase 1 sub-task 1.8; completes
  Phase 1.
- Phase files now carry a `Sub-tasks` checklist with observable **Done when**
  criteria, so progress mid-phase is readable from the document rather than
  inferred from commit history. All seven phases are broken down; where a
  choice is the maintainer's to make, it is recorded as an explicit
  "Decide before starting" item rather than defaulted silently.
- `CLAUDE.md` §7 gained the tracking discipline this depends on: discovered
  work — prerequisites, workarounds, defects found in passing, work belonging
  to a later phase — is added to the relevant checklist rather than silently
  absorbed, and a decision the agent cannot make blocks its sub-task rather
  than the phase.
- ProtectServer environment prepared: Admin token PINs initialized and a
  labelled user token created on slot 0. `docs/protectserver-setup.md` now
  documents the sequence that actually works, including the mid-run label
  prompt that is easy to answer with a PIN by mistake.
- Phase 1 scope now includes a second, real-vendor adapter (ProtectServer)
  alongside SoftHSM2, and its acceptance criteria are split into CI-verifiable
  and maintainer-verified halves so a reader can tell which claims an automated
  run backs.
- `config.example.yaml` gained per-adapter blocks and now references PINs by
  environment-variable *name* rather than carrying any value.
- README and architecture docs state which vendor backends actually exist
  today rather than implying all four are working.

### Fixed
- **A relying party could not parse the CRL at the intermediate's
  distribution point.** `/root.crl` served PEM, and a client following a CRL
  distribution point expects a single DER object (RFC 5280 §4.2.1.13,
  RFC 2585 §3). Measured against OpenSSL 3.x, the PEM body fails with
  "No supported data to decode. Input type: DER" — which a verifier is most
  likely to treat as "revocation unavailable" and carry on past. This
  affected the one channel by which anyone learns the *intermediate* has
  been revoked, and the URL was fixed by the offline root at ceremony time.
  `/root.crt` and `/intermediate.crt` had the same defect for AIA
  CA-Issuers.
- **The intermediate's `keyUsage` was never checked at startup.** A
  compliant verifier enforces `keyUsage` independently of
  `basicConstraints` (RFC 5280 §4.2.1.3), so an intermediate lacking
  `keyCertSign` issued certificates this platform accepted and everything
  else rejected. `cRLSign` is required too, since this service publishes the
  CRL. `basicConstraints` presence is now asserted explicitly alongside it.
- **Neither the intermediate nor the issuer was checked against its own
  validity window.** `ca.LoadIntermediate` refuses an expired or not-yet-valid
  certificate at startup and `ca.CA.Issue` re-checks per issuance — a service
  that started before the expiry is still running after it. New sentinel
  `ca.ErrIssuerNotValid`.
- **A leaf could be issued that outlives its issuer** (`ca.ErrValidityExceedsIssuer`).
  `ca.cert_ttl_hours` knows nothing about when the intermediate expires.
  Rejected rather than clamped, matching the ceremony's existing rule for an
  intermediate outliving its root: the consequence is that a service stops
  issuing one TTL before its intermediate expires, which is a loud prompt to
  re-issue it rather than a quiet shortening of everything it signs.
- **A CRL could claim authority past its issuer's expiry.** `nextUpdate` is
  clamped to the intermediate's `NotAfter`.
- **The service resolved its HSM workspace by first label match.**
  PKCS#11 places no uniqueness constraint on `CKA_LABEL`, so the driver's
  enumeration order decided which token held the CA key — possibly
  differently on the next boot (CLAUDE.md §3.8). It now lists the colliding
  serials and refuses. `cmd/hsm-pki-keytool` already behaved this way.
- **The ceremony's root CRL carried no clock-skew backdate** while the
  certificates signed beside it did, so a verifier with a trailing clock
  could fetch the root CDP and find a CRL that is not valid yet.
- **A multi-block PEM file was silently reduced to its first block**, in
  both `ca.intermediate_cert_path` and the root artifact paths — a chain
  pasted in by an operator would have had file order decide which
  certificate the CA ran as. Both reject now, and the root artifacts are
  parsed at startup rather than trusted for having a well-formed envelope.
- **`http.Server` had no timeouts**, leaving connections that never finish
  sending to hold a goroutine and a descriptor indefinitely (Slowloris).
  `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` and `IdleTimeout` are
  set well above the handler deadline, so they catch only a client making no
  progress.
- **Three config values parsed but were never sanity-checked:** a PIN
  environment variable that is set but empty, a negative
  `ca.crl_number_floor` (RFC 5280 §5.2.3 makes CRL numbers non-negative),
  and a zero or negative PKCS#11 session budget.
- Certificate `KeyUsage` now follows the subject's key algorithm.
  `keyEncipherment` was asserted unconditionally, which describes an RSA
  operation an EC key cannot perform (RFC 5480 §3) — and P-256 is this CA's
  default curve, so every ECDSA certificate it issued carried a capability
  claim that was simply false.
- `ca.GenerateSerial` redraws rather than returning a zero serial. RFC 5280
  §4.1.2.2 requires a positive serial number; the probability is 2^-128, but
  "cannot happen" and "must not be emitted" are different claims and only
  one is enforceable.
- `(*ca.CA).BuildCRL` rejects an inverted or empty validity window and a
  non-positive CRL number, instead of signing a CRL that is expired the
  moment it is issued.
- CRL numbers are now monotonic across a service restart. The counter
  started from zero on every start, so a restarted service reissued low
  numbers while verifiers held a higher-numbered CRL — which they may then
  keep, ignoring every later update and the revocations in it. With no
  persistent storage in Phase 2 (deliberately), the wall clock supplies the
  monotonic component. Milliseconds, not seconds: a test written for this
  caught a same-second restart reissuing an identical number.
- A CRL's `thisUpdate` is backdated by the same clock-skew allowance
  `Issue` applies to `NotBefore`.
- `newRequestID` handles a `crypto/rand` failure instead of discarding it.
  A failed read left the buffer zeroed, giving every concurrent request the
  id `0000000000000000` — the one outcome that defeats a correlation id
  entirely, arriving exactly when logs matter most.
- The logging middleware's `ResponseWriter` wrapper ignores a second
  `WriteHeader` (so the access log cannot disagree with the wire) and
  implements `Unwrap`, so `http.ResponseController` can still reach
  `Flusher`/`Hijacker` beneath it rather than having them silently stripped.
- Self-signed CA certificates now carry an `AuthorityKeyIdentifier` equal to
  their own `SubjectKeyIdentifier`. RFC 5280 §4.2.1.1 permits omitting it,
  but path builders look for it unconditionally.
- `pkcs11.Login` now zeroes the caller's PIN slice on every return path, not
  only once execution reaches `NewSecurePIN`. The guard clauses ahead of it
  (cancelled context, expired session) previously returned with the
  caller's PIN still readable in the Go heap — the one copy this package can
  deterministically wipe, left unwiped (CLAUDE.md §3.1).
- `pkcs11.CloseSession` no longer removes a session from the adapter's map
  before the token has actually released it. A failed `C_CloseSession`
  used to leave a session open on the token that neither the janitor nor
  `Close` could ever reclaim, since both work from that map.
- `pkcs11.GenerateSecretKey` validates `KeyBits` against 128/192/256
  instead of passing `bits/8` to the token. Integer division silently
  turned a wrong-but-plausible request (200 bits) into a non-standard
  25-byte key that some tokens accept rather than reject; a negative value
  was worse.
- `pkcs11.DecodeECPoint` (introduced in sub-task 2.2) tried the ASN.1
  OCTET-STRING-unwrap interpretation of a `CKA_EC_POINT` value before the
  raw-point one. An uncompressed point's leading byte (`0x04`) collides
  with ASN.1's OCTET STRING tag, so a bare, unwrapped point could be
  misparsed roughly 1 time in 256 (whenever the point's second byte matched
  the remaining byte count) — a public-key-reconstruction failure with no
  vendor trigger, just unlucky key material. Caught by an intermittent
  `TestDecodeECPoint_BareUnwrapped` failure during Phase 2 sub-task 2.6's
  full-suite verification run, not by the function's own tests, since the
  original tests never exercised the colliding byte value. Fixed by trying
  the raw interpretation first; added a test that deterministically
  reproduces the exact collision instead of depending on chance.
- `.gitignore` did not exclude `config.yaml`, despite `config.example.yaml`
  stating that it did — the file intended to hold real values was trackable.
  Also added guards against committing proprietary vendor SDK binaries.
- `(*server).nextCRLNumber`'s doc comment still said "Unix seconds" after
  the underlying implementation had already switched to `UnixMilli()` to
  fix the same-second-restart collision (see the CRL-monotonicity entry
  above) — the code was correct, only the comment had gone stale. Caught
  during a maintainer double-check of the whole phase before starting
  Phase 3.

<!--
Tag v0.1.0 once Phase 1 (PKCS#11 core) lands. Each phase producing a user-visible
capability bumps at least the minor version.
-->
