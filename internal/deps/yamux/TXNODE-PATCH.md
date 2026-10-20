# TX-Node yamux patch

Upstream: `github.com/hashicorp/yamux v0.1.2`. Production Go sources and the
complete MPL-2.0 `LICENSE` are copied unchanged except for the changes below.
Original module checksum: `h1:XtB8kyFOyHXYVFnwT5C3+Bdo8gArse7j2AQ0DA0Uey8=`.

## Write completion ownership

- A queued request has a dedicated cancellation/completion state. A request
  cancelled before dispatch is never read or sent, including its header. This
  replaces the upstream timeout path that copied a body which could still be
  transmitted after the caller had returned.
- Once dispatched, cancellation joins the actual header/body transport writes
  and returns the actual body byte count together with the IO and termination
  errors. `Stream.Write` preserves that count and updates its send window by
  actual accepted bytes, including tails returned with an error.
- Each request has its own completion channel; no late result can be mistaken
  for a later request using the same stream's legacy error channel.
- Active shared frames cannot be independently interrupted safely. A child
  deadline can wait for its active frame's result. Queued cancellation and
  normal child close leave the parent and siblings usable.
- The sender enforces the existing `ConnectionWriteTimeout` as a parent safety
  bound from dispatch. Only this parent timeout closes a stalled transport;
  parent shutdown still interrupts active IO immediately. A fired timeout
  callback is joined before the sender can move to another request.
- Short writes are errors. Accepted header bytes are excluded from the body
  count. The protocol and its wire format remain unchanged.

Deterministic regressions in `write_completion_test.go` cover full/partial
accepted writes gated across shutdown, queued cancellation and caller-buffer
reuse, normal child close preserving a sibling, and joining an active timeout
callback. GitHub Actions runs these tests; local validation is static only.
