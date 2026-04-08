# PoRep paid-retrievals

Small CLI tools for paid piece retrieval over HTTP using:

- Thin proxy sitting in front of Curio or Boost HTTP `.../piece/...` endpoint to broker payments
- MPP payment headers with EVM-style signing
- Filecoin Pay rails on FVM (automated creation/finding of rails)

This is primarily built for large (many TiBs) PoRep deals so relies on some basic assumptions:
- Static price per piece (easy to change, just NYI)
- Most pieces will be full ~32GB with prices in the range of $0.10 to $1.00, so transaction overheads and gas fees are sustainable
- Quote and fetch one Piece at a time - requires more client-side error handling and consumes more transactions, but has near-term advantages:
  - Copes with large data sets being spread across multiple SPs
  - Works with most existing SP software stacks

## Contents

This repo builds two binaries:

- `sp-proxy`: serves `/piece/<cid>` with 402 MPP challenge + paid GET flow
- `retrieval-client`: discovers sources, gets MPP challenges, signs proof headers, downloads CAR files

## Prerequisites

- Go `1.22+`
- A Filecoin JSON-RPC endpoint (Calibration by default in this repo)
- Funded private keys for:
  - SP settler/payee wallet
  - client payer wallet

## Build

From repo root:

```bash
go build -o bin/sp-proxy ./cmd/sp-proxy
go build -o bin/retrieval-client ./cmd/retrieval-client
```

Or install to your Go bin path:

```bash
go install ./cmd/sp-proxy
go install ./cmd/retrieval-client
```

## Generate keys

Keys are plain secp256k1 private keys as 32-byte hex strings (with or without `0x`).
As ever, these need to be funded in order to get an ActorID on the Filecoin blockchain.

### Option A: OpenSSL (simple)

```bash
# SP key
openssl rand -hex 32 > sp.key

# client key
openssl rand -hex 32 > client.key
```

### Option B: Foundry cast (if you already use it)

```bash
cast wallet new --json > sp-wallet.json
cast wallet new --json > client-wallet.json
```

Then copy the `"private_key"` values into `sp.key` and `client.key`.

### Option C: Lotus wallet (`lotus wallet new` + export)

Create secp256k1 wallets:

```bash
# SP wallet
lotus wallet new secp256k1

# client wallet
lotus wallet new secp256k1
```

Export each wallet key (replace with your addresses):

```bash
lotus wallet export f1SP_ADDRESS > sp-lotus-export.json
lotus wallet export f1CLIENT_ADDRESS > client-lotus-export.json
```

Convert Lotus export into raw 32-byte hex key files used by this project:

```bash
python3 - <<'PY'
import base64, json, re

def convert(infile, outfile):
    raw = json.load(open(infile, "r"))
    v = (raw.get("PrivateKey") or "").strip()
    if not v:
        raise SystemExit(f"{infile}: missing PrivateKey")
    if re.fullmatch(r"0x[0-9a-fA-F]+|[0-9a-fA-F]+", v):
        h = v[2:] if v.startswith("0x") else v
    else:
        h = base64.b64decode(v).hex()
    if len(h) != 64:
        raise SystemExit(f"{infile}: expected 32-byte private key, got {len(h)//2} bytes")
    open(outfile, "w").write(h + "\n")

convert("sp-lotus-export.json", "sp.key")
convert("client-lotus-export.json", "client.key")
print("wrote sp.key and client.key")
PY
```

> Keep key files out of git. Add `*.key` (or your chosen names) to `.gitignore`.

## Run the SP proxy

Minimal example:

```bash
./bin/sp-proxy \
  --listen :8787 \
  --db ./sp-proxy.db \
  --price-fil 0.01 \
  --pay-rpc-url "https://api.calibration.node.glif.io/rpc/v1" \
  --pay-private-key-file ./sp.key
```

Useful flags:

- `--listen`: HTTP listen address (default `:8787`)
- `--db`: SQLite file for deal state (default `./sp-proxy.db`)
- `--price-fil`: challenge price per Piece in FIL
- `--pay-rpc-url`: FVM RPC for Filecoin Pay interactions
- `--pay-private-key|--pay-private-key-file|--pay-private-key-env`: settler key source
- `--pay-payments-address`: optional payments contract override (empty = chain default)
- `--pay-payee-address`: optional payee 0x address advertised to clients (default = settler address)
- `--pay-debug`: verbose payment/settlement logs
- `--verbose`: debug-level structured logs

## Run the retrieval client

### Fetch by CID

```bash
./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --rpc-url "https://api.calibration.node.glif.io/rpc/v1" \
  --cid baga6ea4seaq...
  --cid baga6ea7dk3b...
```

### Use a manifest

```bash
./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --manifest ./path/to/super-manifest.json
```

`--manifest` is mutually exclusive with positional CIDs / `--cid` / `--cid-file`.
Only `pieces[].piece_cid` is used.

### Force one SP/proxy URL for testing

If you want to ignore discovered endpoints and only probe one base URL (eg your local test proxy):

```bash
./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --rpc-url "https://api.calibration.node.glif.io/rpc/v1" \
  --sp-base-url "http://127.0.0.1:8787" \
  --cid baga6ea4seaq...
```

### What `fetch` does

1. Resolve candidate providers for each piece CID (via discovery, unless `--sp-base-url` override is set).
2. Probe each location:
  - `200 OK` => free download (saved immediately)
  - `402` => parse MPP challenge and keep cheapest usable one
3. Prepare and charge Filecoin Pay rails for paid pieces.
4. Send paid GET with `Authorization: Payment <credential>`.

### `fetch` flags (most-used)

- `--cid` (repeatable), `--cid-file`, or positional CIDs
- `--manifest` (alternative input)
- `--out-dir` (default `.`)
- `--sp-base-url` (force one base URL)
- `--rpc-url` (shared RPC for FVM payments + discovery miner info lookups)
- `--pay-payments-address` (optional contract override)
- `--filpay-private-key|--filpay-private-key-file|--filpay-private-key-env` (client key source)
- `--yes` (skip confirm prompt)
- `--expires-in-sec` (MPP proof header expiry)
- `--pay-debug`, `--verbose`

## Environment variables

Defaults are wired for convenience:

- `FILPAY_PRIVATE_KEY_ENV` (default key env var name for client)
- `SP_PROXY_PAY_PRIVATE_KEY_ENV` (default key env var name for proxy)
- `SP_PROXY_PAY_RPC_URL` (default RPC URL if `--rpc-url` / `--pay-rpc-url` not set)
- `SP_PROXY_PAY_PAYMENTS_ADDRESS` (optional default payments contract override)
- `SP_PROXY_PAY_PAYEE_ADDRESS` (optional default proxy payee address)


