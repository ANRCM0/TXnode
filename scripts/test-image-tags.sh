#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
resolver=scripts/resolve-image-tags.sh
sha=0123456789abcdef0123456789abcdef01234567

check() {
  local ref="$1" expected="$2" output
  output="$(env -u GITHUB_OUTPUT -u TXBOARD_IMAGE_ALIASES -u TXBOARD_IMAGE_REPO GITHUB_REF="$ref" GITHUB_SHA="$sha" bash "$resolver")"
  if [[ "$output" != "$expected" ]]; then
    printf 'FAIL %s\nexpected:\n%s\nactual:\n%s\n' "$ref" "$expected" "$output" >&2
    exit 1
  fi
}
reject() {
  local ref="$1"
  if env -u GITHUB_OUTPUT -u TXBOARD_IMAGE_ALIASES -u TXBOARD_IMAGE_REPO GITHUB_REF="$ref" GITHUB_SHA="$sha" bash "$resolver" >/dev/null 2>&1; then
    echo "FAIL: unsupported ref was accepted: $ref" >&2
    exit 1
  fi
}
check refs/heads/main $'channel=dev\nghcr.io/anrcm0/txnode:dev\nghcr.io/anrcm0/txnode:dev-sha-0123456789ab'
check refs/tags/v1.2.3 $'channel=stable\nghcr.io/anrcm0/txnode:latest\nghcr.io/anrcm0/txnode:v1.2.3'
check refs/tags/v1.2.3-rc.1 $'channel=preview\nghcr.io/anrcm0/txnode:preview\nghcr.io/anrcm0/txnode:v1.2.3-rc.1'
check refs/tags/v1.2.3-beta.2 $'channel=preview\nghcr.io/anrcm0/txnode:preview\nghcr.io/anrcm0/txnode:v1.2.3-beta.2'
check refs/tags/v1.2.3-preview.4 $'channel=preview\nghcr.io/anrcm0/txnode:preview\nghcr.io/anrcm0/txnode:v1.2.3-preview.4'
override="$(env -u GITHUB_OUTPUT -u TXBOARD_IMAGE_ALIASES GITHUB_REF=refs/heads/main GITHUB_SHA="$sha" TXBOARD_IMAGE_REPO=ghcr.io/example/custom-node bash "$resolver")"
if [[ "$override" != $'channel=dev\nghcr.io/example/custom-node:dev\nghcr.io/example/custom-node:dev-sha-0123456789ab' ]]; then
  echo "FAIL: explicit image repository override changed" >&2
  exit 1
fi
reject refs/heads/feature-test
reject refs/tags/v1.2
reject refs/tags/v1.2.3-hotfix.1
reject refs/tags/v1.2.3-rc.0
reject refs/tags/v01.2.3
reject refs/tags/dev
echo "Independent Node image channel resolver: all cases passed."
