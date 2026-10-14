# TX-Node authentication snapshot patch

This directory is the complete source of `github.com/sagernet/sing-vmess` pinned at `v0.2.8-0.20250909125414-3aed155119a1` (upstream commit `3aed155119a1`). The original `LICENSE`, module metadata, protocol encoders, cryptographic algorithms and all other upstream files are preserved. Node selects this source through its local module replacement; the nested module retains the upstream module path and versions.

The production changes are limited to `service.go` and `vless/service.go`. Two new authentication snapshot test files accompany them. The caller adaptation lives in the existing local sing-box VLESS/VMess inbound and user files.

## Concurrent user publication

VMess and VLESS publish a complete immutable authentication map through `atomic.Pointer`. A connection loads exactly one map generation before reading its handshake, and uses that generation throughout authentication. User updates do not hold a lock while a client reads a handshake or carries proxy traffic.

The sing-box inbounds use a comparable authenticated identity containing the credential UUID, display name and original index. Authentication passes that same identity to the route handler. The handler does not resolve a numeric index against a newer user list. This prevents reordered or removed users from being attributed to another user, including a handshake that started before a user update.

An already-started handshake may finish authenticating against its earlier snapshot. That does not grant access under a different current user: Node's current router connection tracker validates the authenticated UUID against the current admitted user map and closes removed or reassigned TCP/UDP sessions. The leaf identity tests prove snapshot ownership; the real Node VLESS/VMess regression additionally proves removed credentials do not revive through an old delayed poll.

## VMess replay and worker lifecycle

VMess retains the same service and replay filter across every user update. Rebuilding services would reset the replay history, so this patch changes only the authentication snapshot. AEAD decoding, cipher/key derivation, request bytes and replay-window policy remain unchanged.

Legacy AlterID time-key refresh prepares and publishes an immutable map while holding a short lifecycle lock. User publication and refresh publication serialize so a refresh cannot overwrite a newer user generation. Neither operation holds the lock during network I/O. One worker is created when a started service first needs legacy keys; subsequent user updates do not create more workers. Removing all legacy users leaves at most that one bounded idle worker until shutdown.

Start is idempotent. Close stops the timer, closes its stop signal once and waits for the worker to finish outside the lifecycle lock; repeated Close calls are safe. A closed service rejects subsequent Start and user update attempts. Parallel user/UUID/AlterID list lengths are validated before a new snapshot is committed.

## Regression evidence

The isolated Go 1.26.3 race gate ran the original `TestNativeSnapshotLiveDelayedPollCannotReviveWSRemovedUUID` with its concurrent real VLESS/VMess clients unchanged, three times. All six protocol subcases passed with no data race. This is local ordinary-native Node evidence, not full Core/Workerman/Machine or production cutover acceptance.

The new leaf tests use protocol client encoders to create real authenticated request bytes. They verify:

- a previously accepted VMess AEAD authentication request remains rejected as a replay after an unrelated user addition and retained UUID/index change;
- slow authentication does not block user updates and retains its original identity, while a subsequent authentication rejects a removed UUID;
- concurrent legacy authentication, time-key refresh and user publication remain coherent;
- adding legacy users after an AEAD-only Start creates the worker, and Close waits, is idempotent and prevents further publication;
- malformed parallel user lists do not publish partial authentication state.

The original upstream source manifest and the frozen local-source diff are retained in the workspace acceptance evidence. The coordinating stage also runs the complete Node race, vet, release build, dependency consistency and prior authority-denial/Usage-v2 gates before publication.
