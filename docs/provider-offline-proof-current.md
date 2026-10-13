# Offline Provider signature diagnostic

`internal/providerproof` independently verifies Core's local synthetic RSA3072
signature domain against explicitly provisioned public trust. It returns a
bounded signature diagnostic and hashes of original signed bytes. It never
returns decoded credentials, an auth snapshot or a usage grant, and always
reports `admission_granted=false`. Default Node Service and kernel paths do not
import the package.

Trust construction accepts one or two fixed public keys with key ID, positive
decimal epoch, exact SPKI digest and bounded time metadata. No key URL/JWK or
untrusted payload key can select material. The parsed trust is immutable; refresh
requires a new verifier. Historical expired/revoked-key signatures remain
diagnosable, with revocation explicit and window/live/business validation marked
not evaluated. This is distinct from authorization or lease enforcement.

Run `go test -race -count=1 ./internal/providerproof` and
`go vet ./internal/providerproof`. Go1.26.3 passed7 main/30 subtests with one
explicit opt-in interoperability skip. The independent actual Core fixture is
run from the monorepo root:

```sh
cd api
CORE_PROVIDER_GO_PROOF_INTEROP=1 php artisan test \
  --filter=test_go_offline_signature_diagnostic_interoperates_with_actual_core_binding
```

Use only local/testing with synthetic data, supported PHP/Go toolchains, locked
Composer dependencies and the normal local fixture Redis service. The fixture
uses in-memory SQLite, an actual Core initial-binding transaction and original
Core signature, then passes only public metadata to Go. Private fixtures are
removed by the existing teardown. Root `ci-provider-proof.yml` runs this path
separately from image publication.

The current slice does not validate nested business semantics, intended Node
recipient, live Core state, clock health, secret delivery, finite runtime lease
or revocation convergence. See the [contract](../../contracts/v2/credential-provider/node-offline-signature-proof-v1.md)
and [verification record](../../docs/architecture/v2/provider-offline-proof-verification.json).
