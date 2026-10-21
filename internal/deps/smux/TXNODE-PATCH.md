# TX-Node smux patch

Upstream: `github.com/xtaci/smux v1.5.57`. Production Go sources and the complete
MIT `LICENSE` are copied unchanged except for the changes described here.
Original module checksum: `h1:N72VbGoSYxgcm6mPOYX0QzEZNVD3UI/JlVvAtXF+WrY=`.
The local module requires Go 1.20 for `errors.Join`; TX-Node requires Go 1.26.

## Write completion ownership

- Every queued request owns a fresh completion state. Deadline or shutdown can
  cancel it before dispatch; the sender then skips it without reading caller
  buffers. A reused caller buffer cannot appear on the wire after cancellation.
- Once the sender starts, cancellation joins the actual transport write and
  returns its payload byte count together with the write and cancellation
  errors. A complete frame is not reported as zero bytes merely because the
  session closed before its result was scheduled. Stream flow-control counters
  advance only for the actual accepted bytes.
- An active frame cannot be independently interrupted without damaging a shared
  byte stream. A child deadline can therefore wait for that frame's result;
  queued child cancellation does not close the parent or sibling streams.
- The sender uses the existing 30-second `openCloseTimeout` as the parent write
  safety bound. A stalled active transport is closed to unblock IO. Parent
  shutdown still closes transport immediately. The safety timer joins any
  callback that already fired before a subsequent request can proceed.
- Invalid counts and short successful writes are rejected rather than silently
  discarding a partial mux frame. Protocol bytes and stream wire format do not
  change. No channel pool is reused while a request can still own its result.

Deterministic regressions in `write_completion_test.go` cover full/partial
accepted writes gated across shutdown, queued cancellation and caller-buffer
reuse, normal child close preserving a sibling, and joining an active timeout
callback. These are run in GitHub Actions; local checks are static only.
