# Offline Provider finite-window diagnostic

Status: verified isolated library slice. The [window proof contract](../../contracts/v2/credential-provider/node-offline-window-proof-v1.md)
adds public methods to `internal/providerproof` for Node-module code:

```go
verifier, err := providerproof.New(operatorProvisionedPublicKeys)
// Handle err before continuing; these keys are not extracted from the JWS.
window, err := verifier.OpenWindow(originalSignedStatement)
// Handle err before continuing. Current trust must be independently refreshed.
observation, err := window.Check(currentVerifier)
window.Close()
```

Only tests currently call this API. There is no CLI, HTTP/WSS route, Service
import, credential parser, I/O admission hook, metering binding or usage-v2 grant
consumer. A returned observation always denies admission and does not validate
nested business metadata or live Core eligibility. This is process-local
signature/time/trust evidence, not a permission to install credentials.

Opening samples private UTC and monotonic clocks around signature validation.
Checks reject exact UTC/subsecond or monotonic expiry, any observed regression,
revoked/removed/replaced trust and invalid samples. A refusal or Close permanently
terminates that instance. Replacing trust means constructing a new immutable
verifier; it does not rewrite the original signature. History verification remains
available independently for expired or revoked signatures.

Run the pure suite with `go test -race -count=1 ./internal/providerproof` and
`go vet ./internal/providerproof` from `node/`. The actual-Core-only Go case is
explicitly skipped without its public fixture. The existing Core opt-in fixture
runs the real initial-binding transaction/full PHP validator, then passes the
original signed bytes and public trust to the same Go test. Its controlled time
assertions do not prove a production clock, runtime authorization or restore
fence. Linux race passed fourteen main tests and fifty-six subtests; the separate
actual Core test passed with six PHP assertions. Dependency locks are unchanged.

See the [precise snapshots, source hashes and logs](provider-window-verification.json).
Default v1 reporting and locally unattributable usage-event storage remain at
their existing boundaries. Durable clock/denial recovery, refresh transport,
secret delivery, lease enforcement, revocation ACK and Node convergence remain
separate implementation gates.
