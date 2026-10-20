# Fixed Core Machine Contract Gate

This is an Actions-only, exclusive MySQL/Redis/Workerman integration fixture.
Do not execute its network, database, race, or runtime checks on a workstation.
The runner and transparent TLS proxy were recovered from TXBoard commit
`52ae0ba`; the executed Core application revision must equal
`compatibility/core.v1.json`. The fixture lives in the candidate Node repository
and does not patch Core application source.

The Core runs its existing **legacy installation mode** Machine contract. The
Node uses only the `txnode` kernel, and VLESS/VMess clients use Node's native
outbound implementation. This gate does not add or attest Machine support in
Core native installation mode. It complements the separate native account,
Provider, authorization and settlement C2 gate.

## Coverage

- Two real nodes managed by the production Orchestrator and one shared
  Workerman WebSocket; real VLESS and VMess TCP traffic.
- Genuine admin configuration delivery while REST config/users reads are held,
  with the sibling node's established stream continuing.
- WebSocket disconnection, four gateway 503 responses, reconnect and successor
  heartbeat/device facts sourced from actual protocol sockets.
- Cross-machine HTTP/WebSocket authorization matrix and isolated node disable
  and re-enable, preserving the sibling's listener and stream.
- Machine token rotation: all child listeners join, terminal traffic remains
  durable, old credentials fail restart, and fresh credentials replay original
  batch IDs and payloads before listeners reopen.
- Actual SQL uniqueness for replayed batches. Independent billing
  reconciliation, physical-host operation, production PKI and Core native
  installation Machine admission remain outside this gate.

## Actions Invocation

Provide Linux, Go with `CGO_ENABLED=1` and a C compiler, PHP 8.2 with Core's
Composer dependencies and `pdo_mysql`/Redis extensions, OpenSSL, a MySQL or
MariaDB client, and dedicated MySQL/Redis services. Start from a clean database;
the runner refuses a nonempty schema. Allocate the fixture databases solely to
this job. It migrates the exclusive database and writes credentials only inside
its private evidence directory.

```sh
APP_ENV=testing \
DB_CONNECTION=mysql DB_HOST=127.0.0.1 DB_PORT=3306 \
DB_DATABASE=txboard_native_machine_test DB_USERNAME=txboard_native_machine \
DB_PASSWORD="$NATIVE_MACHINE_DB_PASSWORD" \
REDIS_PORT=6379 REDIS_DB=14 REDIS_CACHE_DB=15 \
python3 scripts/tests/node-native-machine/run.py \
  .compat/core/api . "$RUNNER_TEMP/native-machine-evidence"
```

The database user needs privileges only on `txboard_native_machine_test`.
Create the empty schema and user using the CI database service administrator
before invoking the runner. The evidence directory must not exist beforehand.
No credentials from another application database or Redis logical database are
needed.

Upload only `sources.json` and `result.json` from the evidence directory.
`sources.json` records candidate Node SHA/tree, fixed Core SHA/tree, kernel and
installation mode. `result.json` records the assertions and observations hash.
On failure, `result.json` records `failed_stage`, the test process exit code,
test source line numbers and predefined diagnostic labels. Raw log lines and
exception messages are excluded from this public summary.
Keep fixture tokens, private keys, `fixture.json`, stage acknowledgement files,
spools and process logs private; they are not public CI artifacts.

The runner requires the exact `TestNativeCoreMachineLive` test to pass and
rejects a skipped or missing test. Local static syntax checking and Linux
compile-only checks do not establish runtime acceptance.
