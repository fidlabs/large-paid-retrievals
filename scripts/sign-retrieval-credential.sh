#!/usr/bin/env bash
# Mint a standalone RetrievalProof token: the EIP-712 typed data with its
# signature embedded (base64url-nopad compact JSON). Send it in a single
# "Authorization: RetrievalProof <token>" header. Vouchers are separate tokens
# (see sign-retrieval-voucher.sh) sent in their own "Authorization:
# RetrievalVoucher <token>" headers.
#
# The proof scope is advisory: the SP binds the deal via the piece CID. In the
# delegated case we copy scope+domain from the supplied voucher for convenience.
#
# Delegated (mint proof using a voucher's domain/scope):
#   ./scripts/sign-retrieval-credential.sh \
#     --private-key-file .task/c2.key \
#     --voucher "$CAPABILITY_TOKEN" \
#     --resource baga... \
#     [--proof-expires-in SECONDS | --proof-deadline UNIX]
#
# Owner-direct (proof only):
#   ./scripts/sign-retrieval-credential.sh \
#     --private-key-file .task/c1.key \
#     --owner-direct \
#     --scope 12 \
#     --resource baga... \
#     [--rpc-url URL] \
#     [--verifying-contract 0x...] \
#     [--proof-expires-in SECONDS]
#
# Env defaults: PAY_RPC_URL, POREP_MARKET. Proof TTL defaults to 12h (MAX_PROOF_TTL).

set -euo pipefail

private_key=""
private_key_file=""
voucher_token=""
resource=""
scope=""
owner_direct=0
proof_deadline=""
proof_expires_in="43200" # 12h
allow_past_deadline=0
allow_far_deadline=0
rpc_url="${PAY_RPC_URL:-http://127.0.0.1:2234/rpc/v1}"
verifying_contract="${POREP_MARKET:-}"

usage() {
  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-key) private_key="$2"; shift 2 ;;
    --private-key-file) private_key_file="$2"; shift 2 ;;
    --voucher) voucher_token="$2"; shift 2 ;;
    --resource) resource="$2"; shift 2 ;;
    --scope|--deal-id) scope="$2"; shift 2 ;;
    --owner-direct) owner_direct=1; shift ;;
    --proof-deadline) proof_deadline="$2"; shift 2 ;;
    --proof-expires-in) proof_expires_in="$2"; shift 2 ;;
    --allow-past-deadline) allow_past_deadline=1; shift ;;
    --allow-far-deadline) allow_far_deadline=1; shift ;;
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
[[ -n "${resource}" ]] || { echo "--resource (piece CID) required" >&2; exit 2; }

now="$(date +%s)"
if [[ -z "${proof_deadline}" ]]; then
  proof_deadline="$((now + proof_expires_in))"
fi
if [[ "${proof_deadline}" -le "${now}" && "${allow_past_deadline}" -ne 1 ]]; then
  echo "proof deadline ${proof_deadline} is not in the future (now=${now})" >&2
  exit 2
fi
max_ttl=$((12 * 3600))
if [[ "$((proof_deadline - now))" -gt "${max_ttl}" && "${allow_far_deadline}" -ne 1 ]]; then
  echo "proof deadline exceeds MAX_PROOF_TTL (${max_ttl}s); use --allow-far-deadline for sad tests" >&2
  exit 2
fi

domain_name="PoRepPieceAccess"
domain_ver="1"
chain_id=""

if [[ "${owner_direct}" -eq 1 ]]; then
  [[ -n "${scope}" ]] || { echo "--scope required with --owner-direct" >&2; exit 2; }
  [[ -n "${verifying_contract}" ]] || { echo "--verifying-contract or POREP_MARKET required for --owner-direct" >&2; exit 2; }
  chain_hex="$(curl -fsS "${rpc_url}" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' | jq -r '.result')"
  [[ "${chain_hex}" =~ ^0x ]] || { echo "eth_chainId failed: ${chain_hex}" >&2; exit 1; }
  chain_id="$((chain_hex))"
else
  [[ -n "${voucher_token}" ]] || { echo "--voucher required unless --owner-direct" >&2; exit 2; }
  # Decode the standalone voucher token; reuse its domain + scope (advisory).
  decoded="$(python3 - "${voucher_token}" <<'PY'
import base64, json, sys
tok = sys.argv[1]
pad = "=" * ((4 - len(tok) % 4) % 4)
raw = base64.urlsafe_b64decode(tok + pad)
obj = json.loads(raw)
if "domain" not in obj or "message" not in obj:
    raise SystemExit("voucher token missing domain/message")
msg = obj.get("message") or {}
scope = msg.get("scope", msg.get("dealId"))
if scope is None:
    raise SystemExit("voucher missing scope/dealId")
out = {
    "domain": obj["domain"],
    "scope": str(scope),
}
print(json.dumps(out))
PY
)"
  chain_id="$(jq -r '.domain.chainId' <<<"${decoded}")"
  verifying_contract="$(jq -r '.domain.verifyingContract' <<<"${decoded}")"
  scope="$(jq -r '.scope' <<<"${decoded}")"
fi

proof_typed="$(mktemp)"
trap 'rm -f "${proof_typed}"' EXIT
cat >"${proof_typed}" <<EOF
{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "RetrievalProof": [
      {"name": "scope", "type": "uint256"},
      {"name": "resource", "type": "string"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalProof",
  "domain": {
    "name": "${domain_name}",
    "version": "${domain_ver}",
    "chainId": ${chain_id},
    "verifyingContract": "${verifying_contract}"
  },
  "message": {
    "scope": ${scope},
    "resource": "${resource}",
    "deadline": ${proof_deadline}
  }
}
EOF

proof_sig="$(cast wallet sign --data --from-file "${proof_typed}" --private-key "0x${private_key}")"
[[ "${proof_sig}" =~ ^0x ]] || { echo "cast sign proof failed: ${proof_sig}" >&2; exit 1; }

# Emit a standalone RetrievalProof token with the signature embedded (matches
# pieceaccess EncodeSignedToken / the RetrievalVoucher token shape).
python3 - "${proof_typed}" "${proof_sig}" <<'PY'
import base64, json, sys
proof_path, proof_sig = sys.argv[1], sys.argv[2]
proof = json.load(open(proof_path))
token = {
    "domain": proof["domain"],
    "types": {"RetrievalProof": proof["types"]["RetrievalProof"]},
    "primaryType": "RetrievalProof",
    "message": proof["message"],
    "signature": proof_sig,
}
raw = json.dumps(token, separators=(",", ":"), sort_keys=True).encode()
print(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
PY
