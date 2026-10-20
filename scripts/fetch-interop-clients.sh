#!/usr/bin/env bash
# Fetch the third-party clients used by the interop suite into a cache
# directory. Clients are test tools only: they never enter go.mod, the image or
# a release artifact.
#
# Usage:
#   scripts/fetch-interop-clients.sh [output-dir]   # default: .clients
#   scripts/fetch-interop-clients.sh --check [dir]  # verify an existing cache
#
# Every archive is pinned by version and SHA-256. A mismatch fails closed.
set -euo pipefail
umask 022

MODE=fetch
if [[ "${1:-}" == "--check" ]]; then
  MODE=check
  shift
fi
OUT=${1:-.clients}

# name|version|url|sha256|archive member to install as the binary
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"
XRAY_SHA256="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
MIHOMO_URL="https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-compatible-v1.19.32.gz"
MIHOMO_SHA256="ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz"
SINGBOX_SHA256="e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"
MIERU_URL="https://github.com/enfein/mieru/releases/download/v3.38.1/mieru_3.38.1_linux_amd64.tar.gz"
MIERU_SHA256="f7ec3b1c2caf338803426d2b3ff32d85654ce585b391556ebe5d2ea55d72d34f"

# prebuilt binary digests, verified after extraction
XRAY_BIN_SHA256="8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"
MIHOMO_BIN_SHA256="7a0d59da2e678d56c899a3db996a2ad8963286c4f3634b0451435db248f13fa1"
SINGBOX_BIN_SHA256="768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93"
MIERU_BIN_SHA256="3529fc7190e073d89da1ea9bbf08aa481edca59866c466725b8231325b0b6577"

verify_file() { # path expected
  local path=$1 expected=$2 actual
  actual=$(sha256sum "$path" | awk '{print $1}')
  if [[ "$actual" != "$expected" ]]; then
    echo "interop: $path sha256 $actual, want $expected" >&2
    return 1
  fi
}

fetch() { # name url sha256
  local name=$1 url=$2 sha=$3 dest
  dest="$OUT/downloads/$name"
  mkdir -p "$OUT/downloads"
  if [[ -f "$dest" ]] && verify_file "$dest" "$sha"; then
    return 0
  fi
  echo "interop: downloading $name" >&2
  curl -fsSL --retry 3 --max-time 300 -o "$dest.part" "$url"
  mv "$dest.part" "$dest"
  verify_file "$dest" "$sha"
}

install_xray() {
  local dir=$OUT/xray
  mkdir -p "$dir"
  if [[ "$MODE" == check ]]; then
    verify_file "$dir/xray" "$XRAY_BIN_SHA256"
    return
  fi
  fetch xray.zip "$XRAY_URL" "$XRAY_SHA256"
  unzip -oq "$OUT/downloads/xray.zip" -d "$dir"
  chmod +x "$dir/xray"
  verify_file "$dir/xray" "$XRAY_BIN_SHA256"
}

install_mihomo() {
  local dir=$OUT/mihomo
  mkdir -p "$dir"
  if [[ "$MODE" == check ]]; then
    verify_file "$dir/mihomo" "$MIHOMO_BIN_SHA256"
    return
  fi
  fetch mihomo.gz "$MIHOMO_URL" "$MIHOMO_SHA256"
  gunzip -c "$OUT/downloads/mihomo.gz" > "$dir/mihomo"
  chmod +x "$dir/mihomo"
  verify_file "$dir/mihomo" "$MIHOMO_BIN_SHA256"
}

install_singbox() {
  local dir=$OUT/singbox
  mkdir -p "$dir"
  if [[ "$MODE" == check ]]; then
    verify_file "$dir/sing-box" "$SINGBOX_BIN_SHA256"
    return
  fi
  fetch sing-box.tar.gz "$SINGBOX_URL" "$SINGBOX_SHA256"
  tar -xzf "$OUT/downloads/sing-box.tar.gz" -C "$dir" --strip-components=1
  chmod +x "$dir/sing-box"
  verify_file "$dir/sing-box" "$SINGBOX_BIN_SHA256"
}

install_mieru() {
  local dir=$OUT/mieru
  mkdir -p "$dir"
  if [[ "$MODE" == check ]]; then
    verify_file "$dir/mieru" "$MIERU_BIN_SHA256"
    return
  fi
  fetch mieru.tar.gz "$MIERU_URL" "$MIERU_SHA256"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  tar -xzf "$OUT/downloads/mieru.tar.gz" -C "$tmp"
  # The archive layout varies by release; install the first regular mieru file.
  local bin
  bin=$(find "$tmp" -type f -name mieru | head -n1)
  if [[ -z "$bin" ]]; then
    echo "interop: mieru binary not found in the archive" >&2
    return 1
  fi
  install -m 0755 "$bin" "$dir/mieru"
  verify_file "$dir/mieru" "$MIERU_BIN_SHA256"
}

install_xray
install_mihomo
install_singbox
install_mieru

echo "interop clients ready in $OUT"
