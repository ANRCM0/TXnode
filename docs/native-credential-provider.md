# Native credential Provider

This separate executable implements the C2-C1 control contract in
[`native-issuance-v1.md`](../../contracts/v2/credential-provider/native-issuance-v1.md).
It is not started by the existing TX-Node executable. Native Core activation,
Node credential consumption, subscription rendering and rotation are not
implemented by this batch.

The Provider generates real UUIDv4 material for `vless-uuid/v1` and
`vmess-uuid/v1`. Material remains in its private bbolt database; the control
endpoint exposes only non-secret issue, query and subject-revocation receipts.
There is no credential export endpoint.

## Build and run

Build from the Node module without changing its dependency lock:

```sh
go build -o /tmp/tx-credential-provider ./cmd/credential-provider
```

Provision a dedicated POSIX service account and an operator-owned private state
directory (`0700`). The database must be absent or a regular file with mode
`0600`; symlinked state directories and permissive existing files are refused.
Do not place the database on a Windows-mounted filesystem that cannot enforce
these permissions. The database is for one Provider process: a second opener
fails after a bounded exclusive-lock timeout.

Configure independently provisioned server and Core client certificates. The
client leaf fingerprint is the lowercase SHA-256 digest of the certificate DER,
not of its PEM text. Multiple authorized leaf fingerprints can be supplied as
a comma-separated list during client-certificate replacement.

```sh
/tmp/tx-credential-provider \
  --listen 127.0.0.1:9443 \
  --store /var/lib/tx-credential-provider/private/provider.db \
  --provider-id primary-provider \
  --epoch 1 \
  --tls-cert /etc/tx-credential-provider/server.pem \
  --tls-key /etc/tx-credential-provider/server.key \
  --client-ca /etc/tx-credential-provider/core-ca.pem \
  --client-fingerprint '<64-lowercase-hex-client-leaf-sha256>'
```

All file paths and listen configuration are operator inputs. API payloads
cannot select files, endpoints, credentials or commands. The executable prints
`credential_provider_listening` once the listener is established. Startup
failures print bounded error codes, without paths or raw transport errors.
SIGTERM and SIGINT stop admission and allow up to five seconds for shutdown.

Only `POST /operations` is registered. TLS 1.3, a verified client certificate,
and its configured SHA-256 leaf fingerprint are mandatory. HTTP plaintext,
TLS 1.2, an untrusted certificate, and a different certificate from the same CA
are refused. Core must independently verify the server CA and hostname.

## Core registration

Configure the matching operator-owned entry in Core's environment:

```dotenv
CORE_CREDENTIAL_PROVIDER_ID=primary-provider
CORE_CREDENTIAL_PROVIDER_ENDPOINT=https://provider.internal:9443/operations
CORE_CREDENTIAL_PROVIDER_EPOCH=1
CORE_CREDENTIAL_PROVIDER_CA_FILE=/etc/tx-core/provider-ca.pem
CORE_CREDENTIAL_PROVIDER_CERT_FILE=/etc/tx-core/provider-client.pem
CORE_CREDENTIAL_PROVIDER_KEY_FILE=/etc/tx-core/provider-client.key
CORE_CREDENTIAL_PROVIDER_PROFILES=vless-uuid/v1,vmess-uuid/v1
```

The endpoint hostname must match the server certificate. Provision certificates
and private keys separately; do not put their contents in environment files or
request bodies. Apply configuration through the existing Core configuration
cache and worker restart procedure.

From an already initialized native Core installation, run:

```sh
php artisan core:provider-register primary-provider --key=primary-provider-registration
```

Registration is idempotent for the same business key and public configuration
digest. It stores only non-secret identity, profile and certificate/configuration
hashes, and does not call the Provider or prove it is reachable. Changing the
endpoint, epoch, profiles, CA or client certificate requires a future explicit
registration lifecycle; editing the environment alone cannot rebind a durable
registration. The runtime allowlist supports multiple client fingerprints, but
this batch does not implement Core certificate rotation.

Registration is a preparation operation and leaves native authority in
`initializing`. No production activation command is provided in C2-C1.

## Persistence and retry behavior

Provider ID and epoch bind permanently to the store at initialization. A
restart with either value changed refuses the store. Each mutation commits its
private subject state, immutable public result and operation/idempotency index
in one bbolt transaction. A crash after commit but before response is recovered
by querying or replaying the same operation and business key.

Only one generation is issued. The provider subject reference binds the
installation, access subject, subscription and profile. A different operation
cannot issue another credential for that subject. Subject-scope revocation
works before issue and leaves a permanent tombstone. Lower revocation facts
cannot replace higher facts; a repeated fact version with different effective
time or reason is rejected.

Revocation removes the live credential value from the current subject record.
It is not a secure erasure guarantee for old database pages or backups. Treat
all Provider database files, snapshots, backups and filesystem storage as
secret material, with separate access and retention policies. Copying a live
bbolt file is not a supported backup procedure; stop the process before an
operator-managed filesystem backup.

Historical issue receipts remain replayable after revocation. Such a receipt
proves a past Provider operation; it is never current entitlement or Node
convergence evidence. Query is read-only and cannot extend credential lifetime.

## Limits and verification

Requests and responses are bounded to 64 KiB. Duplicate JSON keys, unknown or
missing fields, noncanonical decimal strings, fractional/exponent time fields,
invalid input hashes, mismatched Provider identity and request deadlines
outside `(now, now + 30 seconds]` are rejected. The fixed public error vocabulary
does not include payloads, material, paths or raw TLS/database diagnostics.

Run the focused package suite on the POSIX runtime:

```sh
go test ./internal/credentialprovider ./cmd/credential-provider
```

The suite covers real TLS handshakes, leaf fingerprint denial, TLS downgrade
denial, private random UUID persistence, restart replay, exclusive ownership,
identity binding, concurrent idempotency, permanent pre-issue tombstones,
revocation monotonicity, closed-wire validation, body limits and secret-free
response diagnostics. Core-to-Provider process interoperability is validated
separately at the batch integration boundary.
