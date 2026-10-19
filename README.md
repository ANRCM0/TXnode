# TX-Node

Independent Go data plane and Credential Provider for TXBoard. Source history was
extracted from TXBoard's `node/` directory at Core revision `ca25f21`.
The existing Go module namespace `github.com/ANRCM0/TX-Node` is retained.

`cmd/tx-node` runs the Node runtime with embedded sing-box or Xray kernels.
`cmd/credential-provider` owns private credential storage and authorized delivery.
They remain separate processes and authorities even though they share this module.
Core owns identity, entitlement and settlement; Node consumes versioned protocols.

## Development and acceptance

Use Go 1.26 and the checked-in module locks. `make build` is a local static build.
Run functional, race, network, browser and container acceptance in GitHub Actions.
`make test` covers both commands and internal packages; `make test-runtime-stability`
repeats focused lifecycle suites. Keep local kernel replacements, licenses and
`TXNODE-PATCH.md` notes together with their sources under `internal/deps/`.

The independent workflow owns tests, actual image checks and a real native Core
compatibility test. `compatibility/core.v1.json` pins the supported Core baseline.
The compatibility fixture selects this Node candidate while leaving that Core's
application source unchanged and records both exact revisions in its artifact.
`compatibility/renderers.v1.json` owns this Node's renderer source fingerprints
and package version. Review and version it when renderer implementation changes.
Compatibility compares the declared interface with Core and runs real delivery;
Core's adoption review separately records the chosen pair's source fingerprints.

## Independent releases

Main runtime changes publish `ghcr.io/anrcm0/txboard-node:dev-sha-<12>` and promote
`dev` only if a newer runtime has not replaced the candidate. Reviewed `vX.Y.Z`
and prerelease tags publish this repository's own images and Node release binaries.
Core versions and Core releases do not create Node versions. Existing image and
configuration paths stay compatible. No new SemVer tag was created by extraction.

Core consumes an explicit Node commit as a Git submodule for integration acceptance.
Node development happens in this repository. A Node update does not change the
Core pin; adoption is a separate Core review with cross-component acceptance.

Historical upstream notices are retained under `licenses/` and in vendored source.
