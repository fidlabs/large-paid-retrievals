#!/usr/bin/env bash
# Sign an EIP-712 RetrievalVoucher via the FCSS-devnet porep-market-tooling
# Python CLI (parity with scripts/sign-retrieval-voucher.sh / cast).
#
# Creates (once) a local venv under .task/porep-tooling-venv, installs
# requirements from the tooling tree, then runs:
#   python porep_tooling_cli.py client sign-retrieval-voucher ...
#
# Usage (from large-paid-retrievals repo root):
#   ./scripts/sign-retrieval-voucher-tooling.sh \
#     --private-key-file .task/c1.key \
#     --grantee 0x... \
#     --scope 12 \
#     [--expires-in SECONDS | --deadline UNIX] \
#     [--issued-at UNIX] \
#     [--tooling-root PATH]
#
# Env:
#   DEVNET_ROOT   FCSS-devnet root (default ../FCSS-devnet)
#   TOOLING_ROOT  Override tooling checkout (default
#                 $DEVNET_ROOT/extern/filecoin-porep-market-tooling)
#
# The tooling .env (RPC_URL, POREP_MARKET_VIEW_HELPER, …) is loaded from
# TOOLING_ROOT. CLIENT_PRIVATE_KEY is overridden from --private-key(-file)
# so the deal owner key from seed-deals is used, not the .env default.
#
# Prints only the base64url voucher token on stdout (logs on stderr).

set -euo pipefail

private_key=""
private_key_file=""
grantee=""
scope=""
deadline=""
issued_at=""
expires_in=""
tooling_root="${TOOLING_ROOT:-}"

usage() {
  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-key) private_key="$2"; shift 2 ;;
    --private-key-file) private_key_file="$2"; shift 2 ;;
    --grantee) grantee="$2"; shift 2 ;;
    --scope|--deal-id) scope="$2"; shift 2 ;;
    --deadline) deadline="$2"; shift 2 ;;
    --issued-at) issued_at="$2"; shift 2 ;;
    --expires-in) expires_in="$2"; shift 2 ;;
    --tooling-root) tooling_root="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 1; }

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
devnet_root="${DEVNET_ROOT:-${repo_root}/../FCSS-devnet}"
if [[ -z "${tooling_root}" ]]; then
  tooling_root="${devnet_root}/extern/filecoin-porep-market-tooling"
fi
tooling_root="$(cd "${tooling_root}" && pwd)"
cli="${tooling_root}/porep_tooling_cli.py"
reqs="${tooling_root}/requirements.txt"
[[ -f "${cli}" ]] || { echo "missing tooling CLI: ${cli}" >&2; exit 1; }
[[ -f "${reqs}" ]] || { echo "missing tooling requirements: ${reqs}" >&2; exit 1; }

if [[ -n "${private_key_file}" ]]; then
  private_key="$(tr -d ' \t\r\n' <"${private_key_file}")"
fi
private_key="${private_key#0x}"
[[ -n "${private_key}" ]] || { echo "--private-key or --private-key-file required" >&2; exit 2; }
[[ -n "${grantee}" ]] || { echo "--grantee required" >&2; exit 2; }
[[ -n "${scope}" ]] || { echo "--scope (or --deal-id) required" >&2; exit 2; }
if [[ -n "${deadline}" && -n "${expires_in}" ]]; then
  echo "use either --deadline or --expires-in, not both" >&2
  exit 2
fi

venv_dir="${repo_root}/.task/porep-tooling-venv"
venv_py="${venv_dir}/bin/python"
venv_marker="${venv_dir}/.requirements.sha256"
req_hash="$(
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${reqs}" | awk '{print $1}'
  else
    sha256sum "${reqs}" | awk '{print $1}'
  fi
)"

ensure_venv() {
  if [[ -x "${venv_py}" && -f "${venv_marker}" && "$(cat "${venv_marker}")" == "${req_hash}" ]]; then
    return 0
  fi
  echo "ensuring porep-tooling venv at ${venv_dir}" >&2
  mkdir -p "${repo_root}/.task"
  python3 -m venv "${venv_dir}"
  "${venv_py}" -m pip install -q --upgrade pip
  "${venv_py}" -m pip install -q -r "${reqs}"
  printf '%s\n' "${req_hash}" >"${venv_marker}"
}
ensure_venv

log_dir="${repo_root}/.task/porep-tooling-logs"
mkdir -p "${log_dir}"

extra_args=()
[[ -n "${expires_in}" ]] && extra_args+=(--expires-in "${expires_in}")
[[ -n "${deadline}" ]] && extra_args+=(--deadline "${deadline}")
[[ -n "${issued_at}" ]] && extra_args+=(--issued-at "${issued_at}")

# Confirm prompt defaults to yes; feed "yes" so non-TTY e2e is non-interactive.
# Run from tooling root so dotenv loads RPC_URL / POREP_MARKET_VIEW_HELPER.
# Redirect tooling file logs into .task (tooling tree may not be writable).
out="$(
  cd "${tooling_root}"
  export CLIENT_PRIVATE_KEY="0x${private_key}"
  export _LOG_FILE="${log_dir}/logs.log"
  export _ERROR_LOG_FILE="${log_dir}/error.log"
  # shellcheck disable=SC2094
  printf 'yes\n' | "${venv_py}" "${cli}" client sign-retrieval-voucher \
    --grantee "${grantee}" \
    --scope "${scope}" \
    "${extra_args[@]}"
)"

token="$(printf '%s\n' "${out}" | awk 'NF {line=$0} END {print line}')"
if [[ -z "${token}" || "${token}" == *" "* || "${token}" == EIP-712* ]]; then
  echo "tooling CLI did not print a voucher token; output was:" >&2
  printf '%s\n' "${out}" >&2
  exit 1
fi
printf '%s\n' "${token}"
