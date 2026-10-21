#!/usr/bin/env bash
# Resolve the only allowed channels for GHCR publishing.
# main push          => dev + dev-sha-<12>
# vX.Y.Z Git tag     => latest + vX.Y.Z
# vX.Y.Z-rc.N (also beta / preview) => preview + exact prerelease tag
set -euo pipefail

image="${TXBOARD_IMAGE_REPO:-ghcr.io/anrcm0/txnode}"
# Keep explicit overrides compatible with callers of the extracted helper.
# The Node workflow supplies only its own repository; aliases remain opt-in.
aliases="${TXBOARD_IMAGE_ALIASES:-}"
read -r -a images <<< "${image,,} ${aliases,,}"
for repository in "${images[@]}"; do
  [[ "$repository" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$ ]] || {
    echo "Invalid image repository: $repository" >&2; exit 1;
  }
done
ref="${GITHUB_REF:?GITHUB_REF is required}"
sha="${GITHUB_SHA:?GITHUB_SHA is required}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid commit SHA" >&2; exit 1; }
short="${sha:0:12}"
channel=""
tags=""

if [[ "$ref" == "refs/heads/main" ]]; then
  channel="dev"
  versions=(dev "dev-sha-$short")
elif [[ "$ref" == refs/tags/* ]]; then
  tag="${ref#refs/tags/}"
  if [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    channel="stable"
    versions=(latest "$tag")
  elif [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(rc|beta|preview)\.([1-9][0-9]*)$ ]]; then
    channel="preview"
    versions=(preview "$tag")
  else
    echo "Unsupported release tag: $tag. Use vX.Y.Z or vX.Y.Z-{rc,beta,preview}.N." >&2
    exit 1
  fi
else
  echo "Publishing is only supported from main commits and versioned Git tags." >&2
  exit 1
fi

tags="$(for repository in "${images[@]}"; do
  for version in "${versions[@]}"; do printf '%s:%s\n' "$repository" "$version"; done
done)"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'channel=%s\n' "$channel"
    printf 'tags<<TXBOARD_IMAGE_TAGS\n%s\nTXBOARD_IMAGE_TAGS\n' "$tags"
  } >> "$GITHUB_OUTPUT"
else
  printf 'channel=%s\n%s\n' "$channel" "$tags"
fi
