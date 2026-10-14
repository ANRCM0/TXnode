# Native Node authority denial and terminal traffic tail

This slice makes completed native Core authority rejections reach the Node runtime. Only bounded JSON `401 NODE_UNAUTHORIZED` and scoped `404 NODE_NOT_FOUND` responses from the native handshake/config/users or machine node-discovery endpoints become terminal denials. Network failures, TLS errors, redirects, HTML/proxy responses, other status codes and report refusals remain retryable failures.

A Node denial stops the affected listener and returns a typed error. A Machine denial cancels and joins all managed node services through the orchestrator without a child waiting on itself. A node-scoped 404 only stops that node. The denied credential is never reused for a final report.

Before stopping, native v1 collects the final cumulative meter and writes it to a separate durable terminal batch. Existing pending batches retain their original bytes and batch IDs. Terminal recovery replays pending first and terminal second using the original payloads, and a new listener is allowed only after all durable slots are acknowledged. Corrupt, missing or changed slots fail closed. Isolated Usage-v2 keeps its existing stop and receipt rules.

The verification report records full Go race, non-race, vet and Linux build results, transport adversarial parsing, real VLESS listener shutdown, machine-scope cancellation and durable terminal-tail replay. This slice does not finish ETag snapshot retry, desired/applied state confirmation, finite offline leases, Xray strong revocation or production provider delivery.

Ordinary native Core integration separately passed VLESS and VMess: actual administrator HTTP disables the SQL Node, authenticated Core returns404, the Service closes the active stream and listener, and exact43/79 decoded bytes persist in an independent terminal batch. Rejected restart preserves the tail bytes and opens no listener. Verified loopback TLS uses a trusted CA; it does not bypass verification. The [live CI workflow](../../.github/workflows/ci-node-native-authority.yml) runs both protocols on separate MySQL8.4 fixtures. Machine-wide and real Workerman WS integration still require separate acceptance.
