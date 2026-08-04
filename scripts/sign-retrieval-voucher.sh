#!/usr/bin/env bash
# Sign an EIP-712 PoRepPieceAccess RetrievalVoucher and print the Bearer token
# (base64url-nopad compact JSON), matching hartica-filecoin-porep-market-tooling
# sign-retrieval-voucher / pieceaccess middleware.
#
# Usage:
#   ./scripts/sign-retrieval-voucher.sh \
#     --private-key-file .task/c1.key \
#     --grantee 0x... \
#     --deal-id 12 \
#     [--deadline UNIX | --expires-in SECONDS] \
#     [--allow-past-deadline] \
#     [--rpc-url URL] \
#     [--verifying-contract 0x...]
#
# Env defaults: PAY_RPC_URL, POREP_MARKET (from sourced scripts/devnet-env.sh).
# --allow-past-deadline is for sad-path tests only.

set -euo pipefail

private_key=""
private_key_file=""
grantee=""
deal_id=""
deadline=""
expires_in="31536000"
allow_past_deadline=0
rpc_url="${PAY_RPC_URL:-http://127.0.0.1:2234/rpc/v1}"
verifying_contract="${POREP_MARKET:-}"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-key) private_key="$2"; shift 2 ;;
    --private-key-file) private_key_file="$2"; shift 2 ;;
    --grantee) grantee="$2"; shift 2 ;;
    --deal-id) deal_id="$2"; shift 2 ;;
    --deadline) deadline="$2"; shift 2 ;;
    --expires-in) expires_in="$2"; shift 2 ;;
    --allow-past-deadline) allow_past_deadline=1; shift ;;
    --rpc-url) rpc_url="$2"; shift 2 ;;
    --verifying-contract) verifying_contract="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v cast >/dev/null 2>&1 || { echo "cast (foundry) required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 1; }

if [[ -n "${private_key_file}" ]]; then
  private_key="$(tr -d ' \t\r\n' <"${private_key_file}")"
fi
private_key="${private_key#0x}"
[[ -n "${private_key}" ]] || { echo "--private-key or --private-key-file required" >&2; exit 2; }
[[ -n "${grantee}" ]] || { echo "--grantee required" >&2; exit 2; }
[[ -n "${deal_id}" ]] || { echo "--deal-id required" >&2; exit 2; }
[[ -n "${verifying_contract}" ]] || { echo "--verifying-contract or POREP_MARKET required" >&2; exit 2; }

now="$(date +%s)"
if [[ -z "${deadline}" ]]; then
  deadline="$((now + expires_in))"
fi
if [[ "${deadline}" -le "${now}" && "${allow_past_deadline}" -ne 1 ]]; then
  echo "deadline ${deadline} is not in the future (now=${now})" >&2
  exit 2
fi

chain_hex="$(curl -fsS "${rpc_url}" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' | jq -r '.result')"
[[ "${chain_hex}" =~ ^0x ]] || { echo "eth_chainId failed: ${chain_hex}" >&2; exit 1; }
chain_id="$((chain_hex))"

typed="$(mktemp)"
trap 'rm -f "${typed}"' EXIT
cat >"${typed}" <<EOF
{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "RetrievalVoucher": [
      {"name": "grantee", "type": "address"},
      {"name": "dealId", "type": "uint256"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalVoucher",
  "domain": {
    "name": "PoRepPieceAccess",
    "version": "1",
    "chainId": ${chain_id},
    "verifyingContract": "${verifying_contract}"
  },
  "message": {
    "grantee": "${grantee}",
    "dealId": ${deal_id},
    "deadline": ${deadline}
  }
}
EOF

sig="$(cast wallet sign --data --from-file "${typed}" --private-key "0x${private_key}")"
[[ "${sig}" =~ ^0x ]] || { echo "cast sign failed: ${sig}" >&2; exit 1; }

# Compact token without EIP712Domain in types (matches market-tooling output).
python3 - "${typed}" "${sig}" <<'PY'
import base64, json, sys
typed_path, sig = sys.argv[1], sys.argv[2]
typed = json.load(open(typed_path))
token = {
    "domain": typed["domain"],
    "types": {"RetrievalVoucher": typed["types"]["RetrievalVoucher"]},
    "primaryType": typed["primaryType"],
    "message": typed["message"],
    "signature": sig,
}
raw = json.dumps(token, separators=(",", ":"), sort_keys=True).encode()
print(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
PY
