# Provider-backed native Node consumption

The C2-C2 consumer uses the
[native Node delivery contract](../../contracts/v2/credential-provider/native-node-delivery-v1.md).
Core signs current native entitlement and credential SHA-256 commitments.
Node retrieves UUIDs directly from a separate Provider, checks their hashes,
then passes them to the existing runtime. Core never receives plaintext
proxy credentials. This is the required TXBoard user-delivery path. Bare UUID snapshots,
unsigned user caching, old signed User UUID delivery and native user delta
pushes are retired. Xboard transport remains an independent provider.

## Provisioned identities

Provision a separate Node client certificate and key. Its SHA-256 fingerprint
is computed over the certificate DER. The Provider must trust its issuing CA,
but CA membership alone does not authorize access: its leaf fingerprint must
be on the Node allowlist and in the signed Core snapshot. Core and Node
fingerprint sets cannot overlap.

Provide the Provider a public JSON trust file with exactly these fields:

```json
{
  "protocol_version": 1,
  "core_instance_id": "<native-installation-UUID>",
  "key_id": "<Core-signing-key-id>",
  "key_epoch": "1",
  "algorithm": "Ed25519",
  "public_key": "<canonical-base64url-32-byte-Core-public-key>"
}
```

Add both flags to the existing Provider invocation:

```sh
--delivery-trust /etc/tx-credential-provider/core-trust.json \
--node-client-fingerprint '<64-lowercase-hex-Node-leaf-sha256>'
```

`--client-fingerprint` continues to select Core control identities. The new
Node identities can call only the delivery endpoint. `/credential-metadata`
returns non-secret commitments to Core; `/credentials` releases typed UUID
material only to a matching Node certificate and signed grant. Both endpoints
are disabled when the new options are absent.

## Core preparation

The registered Provider configuration from C2-C1 stays authoritative. Set
`NATIVE_NODE_AUTHORIZATION_POLICY_VERSION=native-provider-authorization/v1`
and `NATIVE_PROVIDER_NODE_PROVIDER_ID` to that registration. The existing
dedicated signing seed and public identity are reused, but
`NATIVE_NODE_AUTHORIZATION_CORE_INSTANCE_ID` must equal the persisted native
installation UUID.

Provision `native_provider_node.recipients` in operator-owned Core
configuration before caching it, for example:

```php
'recipients' => [
    42 => [
        'machine_id' => null,
        'recipient_sha256' => '<64-lowercase-hex-Node-leaf-sha256>',
    ],
],
```

Use the exact integer Machine ID instead of null for a Machine child. Missing
recipients, changed membership, disabled Machine or changed bearer credentials
refuse issuance. Core rechecks the authenticated credential against locked
current storage after Provider metadata retrieval, avoiding a stale request
cache during rotation. Neither an HTTP caller nor Provider response selects
the endpoint, recipient or trust key.

These settings do not activate native Core. Its persisted authority remains
`initializing` until the remaining production integration gates are complete.

## Node configuration

Keep the existing Node/Machine bearer configuration and provision an explicit
authorization block inside each instance:

```yaml
authorization:
  enabled: true
  state_dir: /var/lib/tx-node/authorization
  core_instance_id: "<native-installation-UUID>"
  key_id: "<Core-signing-key-id>"
  key_epoch: "1"
  public_key: "<canonical-base64url-Core-public-key>"
  policy_version: native-provider-authorization/v1
  refresh_interval: 30
  max_clock_skew: 5
  provider:
    endpoint: https://provider.internal:9443
    provider_id: primary-provider
    provider_instance_epoch: "1"
    ca_file: /etc/tx-node/provider-ca.pem
    client_cert: /etc/tx-node/provider-client.pem
    client_key: /etc/tx-node/provider-client.key
```

`endpoint` is an HTTPS origin, without a path, query or user information.
Private keys belong in protected files, not YAML, URLs or logs. Node verifies
Core signature, target and revision before contacting the Provider, verifies
every returned commitment and profile, and repeats verification at the kernel
application boundary. An inconsistent Node protocol cannot reuse a cohort.
Persistent authorization state records only non-secret digests and revisions.
No empty, partial or unverified response can supply substitute credentials.

## Operation and limits

- One configured Provider and one VLESS/VMess profile per Node snapshot.
- Up to 128 authorized users per complete snapshot; overflow refuses rather
  than returning partial authority. Core separately bounds candidate scanning.
- Maximum grant lifetime is 120 seconds and also capped by credential,
  Subscription expiry and next reset. Provider allows at most 30 seconds of
  issuance/not-before skew; expiry has no grace period.
- An empty verified snapshot closes users without contacting an unavailable
  Provider. Core/Provider outages cannot renew the last accepted deadline.
- WebSocket user/config changes trigger a complete signed refresh. Unsigned
  user frames cannot supply credentials under this policy.
- Revocation or expiry closes existing flows and new admission through the
  existing watchdog; original unreported traffic is retained.

Native traffic settlement is not enabled by this consumer. Core refuses the
old traffic billing path in native mode. A retained unacknowledged recovery
batch continues to block reopening under existing recovery rules; never delete
or acknowledge it just to make a consumption test pass. Subscription rendering,
rotation, native usage settlement and production readiness remain subsequent
work. `node_provider_credential_delivery_v1` means consumer support only.

## CI verification

The `native-provider-node` GitHub Actions workflow runs focused Core/Node
regressions, MySQL 8.4 checks, race tests, and
`scripts/verify-native-provider-node.py`. The private integration fixture uses
actual Laravel Node authentication/routes, native SQL domain services, a
separate mTLS Provider, and the existing Node Service with real VLESS traffic.
Only the not-yet-open installation admission is substituted. Two Node targets
exercise isolated lease expiry, retained traffic and sibling revocation.

Since October 16, 2026, these heavy checks run in CI by default. Local syntax,
format and diff checks do not constitute live integration acceptance.
