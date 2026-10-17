# Provider-backed native Node authorization

The [native Node delivery contract](../../contracts/v2/credential-provider/native-node-delivery-v1.md)
keeps Core entitlement authority separate from Provider secret storage. Core
signs current entitlement and credential SHA-256 commitments; Node retrieves
UUID material directly from the separate Provider, verifies every commitment
and applies it through the existing runtime. Core does not receive plaintext
proxy credentials. Bare UUID snapshots, unsigned user caches, old signed User
UUID delivery and native user deltas are not this authorization path. Xboard
remains a separate supported adapter.

## Provisioned identities and trust

Provision a separate Node client certificate/key. Its leaf fingerprint is the
lowercase SHA-256 digest of certificate DER. A trusted issuing CA alone is not
authorization: the leaf must be on the Provider Node allowlist and in the
Core-signed snapshot. Core and Node fingerprint sets cannot overlap.

Give the Provider an operator-owned public trust file with exactly these fields:

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

Add these delivery flags to the existing Provider invocation:

```sh
--delivery-trust /etc/tx-credential-provider/core-trust.json \
--node-client-fingerprint '<64-lowercase-hex-Node-leaf-sha256>'
```

`--client-fingerprint` selects Core control identities, not Node delivery.
`/credential-metadata` supplies non-secret commitments to Core; `/credentials`
releases typed material only to the matching Node certificate and signed grant.
The delivery endpoints are disabled without their explicit options. Provider
startup, private store and TLS provisioning remain in
[native-credential-provider.md](native-credential-provider.md).

## Core and Node configuration

Use the registered Provider configuration, not a caller-selected endpoint or
key. `NATIVE_PROVIDER_NODE_PROVIDER_ID` selects that registration and
`NATIVE_NODE_AUTHORIZATION_CORE_INSTANCE_ID` must equal the persisted native
installation UUID. Provision `native_provider_node.recipients` before caching
Core configuration:

```php
'recipients' => [
    42 => [
        'machine_id' => null,
        'recipient_sha256' => '<64-lowercase-hex-Node-leaf-sha256>',
    ],
],
```

Use the exact integer Machine ID for a child. Missing recipients, changed
membership, disabled Machine or changed bearer credentials refuse issuance.
Core rechecks locked current storage after Provider metadata retrieval; a stale
request cache cannot authorize rotated credentials.

Keep Node/Machine Bearer configuration and provision each instance explicitly:

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

`endpoint` is an HTTPS origin with no path, query or user information. Private
keys belong in protected files, never YAML contents, URLs or logs. The v1 policy
is credential consumption; [Subscription usage](native-subscription-usage.md)
selects `native-provider-authorization/v2` explicitly with its signed UsageV2
Session. Neither setting alone activates an unready Core installation.

## Finite authority and anti-rollback

Node checks Core signature, current pinned trust/key epoch, target Node/Machine,
protocol/profile, completeness and revision before contacting Provider. Every
returned profile and credential commitment is verified, then checked again at
kernel application. Partial, empty-unverified or inconsistent material cannot
substitute credentials.

Persist revision high-water before admission. Authorization storage contains
non-secret identities, digests and revisions, not UUID material. Lower revisions,
changed same-revision content, lower trust epochs, scope drift and corrupt state
fail closed. Restart requires fresh online verification and a higher accepted
revision; cached content and HTTP 304 do not renew authority. Do not delete
high-water state to bypass a refusal or describe local files as hardware-backed
restore protection.

One complete snapshot has at most 128 users, one Provider and one VLESS/VMess
profile. Overflow refuses rather than truncating authority. The grant is finite:
at most 120 seconds, also capped by credential/Subscription expiry and next
reset. Provider issuance/not-before skew is at most 30 seconds; expiry has no
grace period. Runtime UTC/monotonic checks and the independent watchdog cannot
extend that deadline during blocked I/O, Core/Provider outages or refresh failure.
A verified empty snapshot closes users without requiring Provider availability.

WS user/config hints trigger complete signed refresh; unsigned frames never
install credentials or extend a lease. Revocation/expiry blocks new I/O and
closes established flows while preserving original unreported traffic. Current
trust, finite time and live entitlement are distinct from historical signature
validity. Production PKI, trust rotation, recovery and actual deployment evidence
must be checked separately from library/unit success.

## Offline proof library

`internal/providerproof` is a test-only, isolated signature/window diagnostic.
Only tests call it: no CLI, HTTP/WSS route, Service/kernel import, credential
parser or admission hook is supplied. Its observations always report
`admission_granted=false`; they do not validate live entitlement, intended Node
recipient or nested business semantics and cannot install credentials or mint
usage grants.

Trust is explicitly provisioned public material, never a key URL or payload
selected JWK. Opening/checking a finite diagnostic window rejects expiry,
clock regression and removed/revoked/replaced current trust. Close/refusal ends
that instance; refreshed trust constructs a new verifier without rewriting old
signed bytes. Historical signature diagnostics remain separate from current
permission. There is no current actual-Core interop opt-in command.

## Validation boundary

Use CI/Actions for real Core routes, dedicated SQL, a separate mTLS Provider,
race tests and actual VLESS/VMess traffic. Local syntax/diff checks do not prove
end-to-end acceptance. Linux sing-box direct TCP is the bounded C2 consumption
scope; native Subscription billing has the additional restrictions in
[native-subscription-usage.md](native-subscription-usage.md). No test result
alone proves production readiness, all protocols, HA or rollback-safe PKI.
