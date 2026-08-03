#!/usr/bin/env bash
# Extract CLIENT_PRIVATE_KEY / SP_PRIVATE_KEY from FCSS-devnet tooling .env
# into client.key / sp.key for retrieval-client and sp-proxy.
#
# Usage (from repo root):
#   ./scripts/extract-keys-from-env.sh
#
# Overrides:
#   DEVNET_ROOT  FCSS-devnet root (default ../FCSS-devnet)
#   ENV_FILE     path to .env (default $DEVNET_ROOT/extern/filecoin-porep-market-tooling/.env)
#   CLIENT_KEY   output path (default ./client.key)
#   SP_KEY       output path (default ./sp.key)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVNET_ROOT="${DEVNET_ROOT:-$ROOT/../FCSS-devnet}"
ENV_FILE="${ENV_FILE:-$DEVNET_ROOT/extern/filecoin-porep-market-tooling/.env}"
CLIENT_KEY="${CLIENT_KEY:-$ROOT/client.key}"
SP_KEY="${SP_KEY:-$ROOT/sp.key}"

[[ -f "$ENV_FILE" ]] || { echo "missing .env: $ENV_FILE" >&2; exit 1; }

# Read KEY=value from .env without sourcing (avoids executing shell in values).
env_get() {
  local key="$1" line val
  line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 || true)"
  [[ -n "$line" ]] || { echo "missing ${key} in $ENV_FILE" >&2; exit 1; }
  val="${line#*=}"
  # strip surrounding quotes
  if [[ "$val" =~ ^\".*\"$ ]]; then
    val="${val:1:${#val}-2}"
  elif [[ "$val" =~ ^\'.*\'$ ]]; then
    val="${val:1:${#val}-2}"
  fi
  # trim whitespace
  val="$(printf '%s' "$val" | tr -d ' \t\r\n')"
  [[ -n "$val" ]] || { echo "empty ${key} in $ENV_FILE" >&2; exit 1; }
  printf '%s' "$val"
}

normalize_hex_key() {
  local raw="$1" hex
  hex="$(printf '%s' "$raw" | sed 's/^0x//I')"
  [[ "$hex" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "expected 32-byte hex private key (got length ${#hex})" >&2
    exit 1
  }
  # write without 0x; LoadPrivateKey accepts either form
  printf '%s\n' "$hex"
}

write_key() {
  local out="$1" hex="$2"
  umask 077
  printf '%s\n' "$hex" >"$out"
  chmod 600 "$out"
}

CLIENT_HEX="$(normalize_hex_key "$(env_get CLIENT_PRIVATE_KEY)")"
SP_HEX="$(normalize_hex_key "$(env_get SP_PRIVATE_KEY)")"

write_key "$CLIENT_KEY" "$CLIENT_HEX"
write_key "$SP_KEY" "$SP_HEX"

# Print addresses only (never the keys), if cast is available.
if command -v cast >/dev/null 2>&1; then
  echo "wrote $CLIENT_KEY  ($(cast wallet address --private-key "0x$CLIENT_HEX"))"
  echo "wrote $SP_KEY      ($(cast wallet address --private-key "0x$SP_HEX"))"
else
  echo "wrote $CLIENT_KEY"
  echo "wrote $SP_KEY"
fi
