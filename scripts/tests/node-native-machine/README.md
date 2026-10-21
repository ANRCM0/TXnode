# Fixed Core Machine Contract Gate

This is an Actions-only, exclusive MySQL/Redis/Workerman integration fixture.
Do not execute its network, database, race, or runtime checks on a workstation.
The runner and transparent TLS proxy were recovered from TXBoard commit
`52ae0ba`; the executed Core application revision must equal
`compatibility/core.v1.json`. The fixture lives in the candidate Node repository
and does not patch Core application source.

The Node-owned fixture is prepared for **native installation mode** with a real
Credential Provider process, mTLS client identities, Core signing seed, native
activation and period-bound Usage V2. This is source preparation only; its
positive whole Machine chain has not passed acceptance. The static compatibility
preflight now fails before database probes, migrations, seed or application
startup and publishes an explicit `compatibility_preflight` failure. See
`docs/CORE-MACHINE-COMPATIBILITY.zh.md` for the exact pinned owner chain and
required independent Core adaptation. A future native admission inventory pass
alone is insufficient: the fixture must execute real native activation and
Provider trust/material flow. The Node uses the `txnode` kernel, and VLESS/VMess
clients use Node's native outbound implementation.

`native_setup.py` provisions private CA/server/Core/Node certificates and starts
the production `cmd/credential-provider` binary. `fixture.php` calls
`InstallationAuthority.initialize(native)`, publishes offers, registers that
Provider, checks readiness and activates the real installation at open epoch 2.
The machine recipient map binds both protocol nodes and the foreign machine's
node to the real Node client certificate fingerprint. HTTP registration,
idempotent free checkout and `core:native-work` produce subscriptions and
Provider-issued subjects; the pinned Core's native subscription client renders
recipient-bound VLESS/VMess credentials. User UUID/token columns remain empty.
The Go fixture consumes private signing trust and Provider mTLS configuration
through `Authorization`, together with `UsageV2`; no authority is mocked.

## Assertion Owner Mapping And Remaining Blocks

| Original assertion | Native owner and preserved assertion |
| --- | --- |
| Legacy terminal `reporting.Batch` | Native `usagev2.Record` with original node, source epoch, batch ID, payload digest, entries and usage period IDs |
| Terminal file remains intact after denial/old restart | Whole-file SHA-256 remains unchanged before authorized recovery |
| Removed terminal slot replayed before listener | Original native submission receives a matching durable persisted receipt before listener admission; retained receipt records replace file deletion |
| Original traffic batch and SQL uniqueness | Exactly one `tx_usage_batch` row for node/source epoch/batch ID, matching payload digest, canonical payload and original period IDs; real worker settlement must reach `settled` |
| Config update while all REST config/users reads are held | Existing real Workerman WS-only assertion remains required; signatures and REST barriers are not bypassed |

The pinned Core still lacks the native runtime inventory entries for
`ws-server`, GET/PUT/PATCH `network-nodes` and POST machine token rotation.
Preflight continues to fail before any database or process work. No Core source,
pin, runtime admission rule or gate success criterion is changed by this fixture.

Three Node-owned source gaps also remain pending runtime acceptance. Native signed
WS refresh currently polls config/users REST, conflicting with the preserved
all-REST-held WS-only configuration requirement. Native usage currently starts
the kernel before its asynchronous first replay, conflicting with the preserved
receipt-before-listener requirement. These assertions intentionally remain
strict and can fail after the external Core contract is repaired; this fixture
does not establish that these production gaps are fixed. Native authorization
refresh also drains/stops the kernel and recreates its meter on every changed
signed revision; the preserved sibling established-stream continuity requirement
therefore remains unaccepted across that refresh.

## Intended Coverage (Not Yet Accepted)

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
Composer dependencies and `pdo_mysql`/Redis/bcmath/curl/sodium/fileinfo extensions,
Node.js for the pinned native recipient-render client, OpenSSL, a MySQL or
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

Upload only `sources.json`, `result.json` and `compatibility-preflight.json`
from the evidence directory.
`sources.json` records candidate Node SHA/tree, fixed Core SHA/tree, kernel and
installation mode. `result.json` records the assertions and observations hash.
On failure, `result.json` records `failed_stage`, the test process exit code,
test source line numbers and predefined diagnostic labels. Raw log lines and
exception messages are excluded from this public summary. Static preflight
failures instead contain fixed contract gap codes and public route/command
names; `compatibility-preflight.json` explicitly records `runtime_verified=false`.
Keep fixture tokens, private keys, `fixture.json`, stage acknowledgement files,
spools and process logs private; they are not public CI artifacts.

The runner requires the exact `TestNativeCoreMachineLive` test to pass and
rejects a skipped or missing test. Local static syntax checking and Linux
compile-only checks do not establish runtime acceptance.
