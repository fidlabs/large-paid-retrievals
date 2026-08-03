#!/usr/bin/env bash
# Fund retrieval-client / sp-proxy wallets on a local Curio docker-devnet after a chain reset.
#
# Prerequisites: lotus + yugabyte/curio stack running; cast + jq installed; client.key + sp.key present.
#
# Usage (from repo root):
#   ./scripts/fund-devnet-wallets.sh
#
# Overrides:
#   CLIENT_KEY / SP_KEY          private key files (default ./client.key, ./sp.key)
#   DEVNET_ROOT                  FCSS-devnet root (default ../FCSS-devnet)
#   CONTRACTS_DIR                Curio contracts bootstrap dir
#                                (default $DEVNET_ROOT/extern/curio/docker/data/contracts)
#   RPC                          Lotus FEVM JSON-RPC (default http://127.0.0.1:2234/rpc/v1)
#   LOTUS_CONTAINER              docker container name (default lotus)
#   FIL_AMOUNT                   FIL to send each wallet (default 100)
#   USDFC_AMOUNT                 whole USDFC tokens for the client (default 1000)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVNET_ROOT="${DEVNET_ROOT:-$ROOT/../FCSS-devnet}"
CLIENT_KEY="${CLIENT_KEY:-$ROOT/client.key}"
SP_KEY="${SP_KEY:-$ROOT/sp.key}"
CONTRACTS_DIR="${CONTRACTS_DIR:-$DEVNET_ROOT/extern/curio/docker/data/contracts}"
RPC="${RPC:-http://127.0.0.1:2234/rpc/v1}"
LOTUS_CONTAINER="${LOTUS_CONTAINER:-lotus}"
FIL_AMOUNT="${FIL_AMOUNT:-100}"
USDFC_AMOUNT="${USDFC_AMOUNT:-1000}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need cast
need jq
need docker

for f in "$CLIENT_KEY" "$SP_KEY" "$CONTRACTS_DIR/contract_addresses.json" "$CONTRACTS_DIR/deployer.private-key"; do
  [[ -f "$f" ]] || { echo "missing file: $f" >&2; exit 1; }
done

hex_key() {
  # strip whitespace and optional 0x prefix
  tr -d ' \n\r\t' <"$1" | sed 's/^0x//'
}

pk_client="0x$(hex_key "$CLIENT_KEY")"
pk_sp="0x$(hex_key "$SP_KEY")"
CLIENT="$(cast wallet address --private-key "$pk_client")"
SP="$(cast wallet address --private-key "$pk_sp")"
USDFC="$(jq -r '.contracts.usdfc // empty' "$CONTRACTS_DIR/contract_addresses.json")"
DEPLOYER_KEY="$(tr -d '\n\r' <"$CONTRACTS_DIR/deployer.private-key")"

[[ "$USDFC" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "invalid usdfc in contract_addresses.json: $USDFC" >&2; exit 1; }
[[ "$DEPLOYER_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "invalid deployer.private-key" >&2; exit 1; }

echo "client=$CLIENT"
echo "sp=$SP"
echo "usdfc=$USDFC"
echo "rpc=$RPC"
echo "contracts=$CONTRACTS_DIR"

wait_msg() {
  local cid="$1"
  [[ -n "$cid" ]] || { echo "lotus send produced no message CID" >&2; exit 1; }
  echo "waiting for $cid"
  docker exec "$LOTUS_CONTAINER" lotus state wait-msg "$cid" >/dev/null
}

echo "sending ${FIL_AMOUNT} FIL to client and sp..."
CID_C="$(docker exec "$LOTUS_CONTAINER" lotus send "$CLIENT" "$FIL_AMOUNT" | awk '/^bafy|^bafk/{print $1; exit}')"
CID_S="$(docker exec "$LOTUS_CONTAINER" lotus send "$SP" "$FIL_AMOUNT" | awk '/^bafy|^bafk/{print $1; exit}')"
wait_msg "$CID_C"
wait_msg "$CID_S"

echo "client FIL: $(cast balance --ether --rpc-url "$RPC" "$CLIENT")"
echo "sp FIL:     $(cast balance --ether --rpc-url "$RPC" "$SP")"

# MockUSDFC uses 18 decimals (Curio contracts-bootstrap SharedMocks)
USDFC_BASE_UNITS="$(cast to-wei "$USDFC_AMOUNT" ether)"
echo "transferring ${USDFC_AMOUNT} USDFC to client..."
cast send "$USDFC" "transfer(address,uint256)" "$CLIENT" "$USDFC_BASE_UNITS" \
  --rpc-url "$RPC" \
  --private-key "$DEPLOYER_KEY" \
  >/dev/null

BAL="$(cast call "$USDFC" "balanceOf(address)(uint256)" "$CLIENT" --rpc-url "$RPC")"
echo "client USDFC (base units): $BAL"
echo "done"
