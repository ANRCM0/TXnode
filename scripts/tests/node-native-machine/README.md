# Fixed Core Machine Contract Gate

This is an Actions-only, exclusive MySQL/Redis/Workerman integration fixture.
Do not execute its network, database, race, or runtime checks on a workstation.
The runner and transparent TLS proxy were recovered from TXBoard commit
`52ae0ba`; the executed Core application revision must equal
`compatibility/core.v1.json`. The fixture lives in the candidate Node repository
and does not patch Core application source. For a separate Core pull request,
`--candidate-core-sha <40-hex-SHA>` selects that exact committed Core checkout;
the supported baseline remains recorded separately in the source evidence.
This explicit candidate mode also requires the three native connection operations
in preflight and executes their real pagination, foreign-node rejection,
idempotent workflow replay, target EOF and other-stream continuity assertions.
The default gate enables these assertions only after the reviewed Core baseline
advertises `node-connections/v1`; it never infers support from a passing old run.

The Node-owned fixture is prepared for **native installation mode** with a real
Credential Provider process, mTLS client identities, Core signing seed, native
activation and period-bound Usage V2. Completed candidate runs and retained
failures are recorded separately in `docs/CORE-MACHINE-COMPATIBILITY.zh.md`;
the final source still needs its own Actions evidence. The static compatibility
preflight fails before database probes, migrations, seed or application startup
when required contracts are missing and publishes a `compatibility_preflight`
failure. An admission inventory pass alone is insufficient: the fixture must
execute real native activation and Provider trust/material flow.
The Node uses the `txnode` kernel, and VLESS/VMess
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

The required Core baseline admits the real `ws-server` command. The former four
raw admin HTTP paths are replaced by the canonical Core browser
operations: `network.nodes.configuration.get`, `.configuration.replace`, `.patch`,
`network.machines.token.rotate` and `.credentials.get`. Each uses the original
admin Bearer, same-origin HTTPS, `X-Core-Admin-Path`, an explicit current actor
grant and the compiled schema. Writes use UUID idempotency keys; full replacement
retains the current expected revision. Rotation receipts contain only `ok`;
credentials are read separately and rotation replay must not rotate twice.
Preflight checks command and HTTP inventory plus the actual compiled operation,
owner binding, permission, idempotency mode and browser surface. It records their
Git blobs and each required contract. Missing admission still fails before any
database or process work. No Core source, pin or runtime admission rule is changed
by this fixture.

The full gate retains recovery receipts before listener admission, safe equivalent
native renewal, and a narrow WS-only port update path preserving current signed
authority. Local syntax or compile checks do not establish their behavior.

The fixture also pins `CORE_RELEASE_ID` to the exact Core revision and inspects
`InstallationAuthority.runtimeReport()` after actual activation under worker epoch
2. The approved module composition comes from the real activation receipt, without
replacing Core module readiness. Free checkout requires the durable owner row to
be `completed`, in addition to order completion and idempotent replay.

## Runtime Coverage And Evidence Boundary

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
  reconciliation, physical-host operation and production PKI remain outside
  this gate. Native installation Machine admission is an explicit live assertion.

The HTTP fixture uses the application's existing Octane/Swoole entry point with
four workers and Swoole 6.2.3, matching the Swoole version in the supported Core
image. The original PHP development-server observations remain historical facts;
they are not relabeled as production HTTP timings. The runner verifies the
extension version and bytecode-cache settings, and records request durations for
member re-enable and credential recovery. The two-second recovery page, twelve-second
listener readiness, original batch payloads and SQL uniqueness assertions remain
unchanged. A pass under this runtime does not establish the unique cause of every
earlier failure or prove actual image deployment.

## Actions Invocation

Provide Linux, Go with `CGO_ENABLED=1` and a C compiler, PHP 8.2 with Core's
Composer dependencies and `pdo_mysql`/Redis/bcmath/curl/sodium/fileinfo/OPcache
extensions plus Swoole 6.2.3,
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

Run the static contract regression suite in Actions before the live runner:

```sh
python3 -m unittest discover -s scripts/tests/node-native-machine -p 'test_preflight.py' -v
```

The runner requires the exact `TestNativeCoreMachineLive` test to pass and
rejects a skipped or missing test. Local static syntax checking and Linux
compile-only checks do not establish runtime acceptance.
