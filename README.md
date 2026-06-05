# PoRep paid-retrievals

HTTP tools for retrieving Filecoin **piece** data (CAR files) from storage providers (SPs), including **free** endpoints and **paid** retrievals settled on-chain via Filecoin Pay.

| If you are… | Start here |
|-------------|------------|
| **Dataset consumer** — download pieces from public or paid SPs | [For dataset consumers](#for-dataset-consumers) |
| **Storage provider** — charge for serving stored pieces | [For storage providers](#for-storage-providers) |
| **Developer** — maintain or extend this repo | [For developers](#for-developers) |

**Binaries:** `retrieval-client` (fetch) and `sp-proxy` (paid gateway in front of an SP piece server).

### Design context

This repo targets **large PoRep retrievals** (many TiBs): pieces are usually full ~32 GiB CARs, often spread across several SP HTTP bases. The workflow is deliberately **per-piece** — quote, pay, and settle once per CID — which adds client-side retry logic but keeps gas and rail usage viable at typical $0.10–$1.00 per piece. Clients **discover** endpoints, **probe** for free (`200`) vs paid (`402`), and select the cheapest valid offer. Billing is **per GiB, rounded up** ([Pricing](#pricing)).

Payments use the **Machine Payments Protocol (MPP)**: an HTTP challenge/proof flow built on the **`Payment` authentication scheme** — `402 Payment Required`, a `WWW-Authenticate: Payment` challenge quoting the charge, and a retried request with `Authorization: Payment` carrying a signed credential. The credential binds the client’s EVM identity to that specific `GET /piece/<cid>` (method, path, host, CID, price, nonce). The server verifies the proof, runs **one Filecoin Pay settlement** for the quoted USDFC on FVM, and only then proxies piece bytes (**settle-before-serve**). At the HTTP layer MPP is payment-method agnostic; this implementation uses **`method="filecoinpay"`** with Filecoin Pay rails as the settlement backend.

Typical paid flow:

1. Client `GET /piece/<cid>` → `402` + MPP challenge (`price_usdfc`, `payee_0x`, …).
2. Client funds a Filecoin Pay rail and signs the MPP credential.
3. Client retries `GET` with `Authorization: Payment …` → proxy settles on-chain → `200` + CAR stream + `Payment-Receipt`.

Wire format, challenge schema, and validation rules: [docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md) ([Protocol](#protocol)).

---

## For dataset consumers

### What you get

`retrieval-client fetch` takes piece CIDs (or a manifest), **discovers** SP HTTP endpoints, **probes** each for availability and price, then **downloads** `.car` files:

- **`200 OK`** on probe → piece is **free**; downloaded immediately.
- **`402 Payment Required`** → piece is **paid**; client funds a Filecoin Pay rail, signs an MPP credential, retries the GET, and downloads after settlement.

Paid pieces are quoted **up front** (total USDFC in the `402` challenge). You pay once per piece; there is no per-byte metering during download.

### What you need

1. **Go 1.26.4+** or a pre-built `retrieval-client` binary.
2. A **client private key** (`client.key`) — secp256k1 hex; see [Generate keys](#generate-keys).
3. **FIL** on your network (mainnet by default) for Filecoin Pay transaction gas.
4. **USDFC** in the client wallet for paid retrievals (amount depends on piece sizes and SP rates).
5. A **JSON-RPC endpoint** (`--pay-rpc-url`; mainnet default `https://api.node.glif.io/rpc/v1`).

Fund test wallets: [Beryx FIL faucet](https://beryx.io/faucet), [Calibnet USDFC faucet](https://forest-explorer.chainsafe.dev/faucet/calibnet_usdfc). Your `0x` address appears in client logs if funding is missing.

### Quick start

```bash
go build -o bin/retrieval-client ./cmd/retrieval-client

./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --cid baga6ea4seaq... \
  --out-dir ./downloads
```

Use `--yes` to skip the funding confirmation prompt (scripts/CI).

### Fetching options

**Multiple CIDs** — repeat `--cid` or pass CIDs as positional arguments:

```bash
./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --cid baga6ea4seaq... \
  --cid baga6ea7dk3b...
```

**Manifest** — JSON with `pieces[].piece_cid` (mutually exclusive with `--cid` / `--cid-file`):

```bash
./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --manifest ./super-manifest.json
```

**Single known SP/proxy** — skip discovery and probe only one base URL (testing or a curated provider):

```bash
./bin/retrieval-client fetch \
  --filpay-private-key-file ./client.key \
  --sp-base-url "https://my-sp.example.com:8787" \
  --cid baga6ea4seaq...
```

For a **local test proxy** funded on Calibration, add `--pay-rpc-url "https://api.calibration.node.glif.io/rpc/v1"`.

### Quote before you pay

**Dry run** — probe and print prices; no rails, no downloads:

```bash
./bin/retrieval-client fetch --dry-run \
  --filpay-private-key-file ./client.key \
  --cid baga6ea4seaq...
```

**Rail check** — verify Filecoin Pay operator approval and rails without fetching:

```bash
./bin/retrieval-client rail-check \
  --filpay-private-key-file ./client.key \
  --payee 0x... \
  --required-usdfc 0.5
```

### How `fetch` chooses a source

For each piece CID (unless `--sp-base-url` is set):

1. Discover candidate HTTP bases (on-chain miner info + configured RPC).
2. Probe endpoints in parallel (`HEAD` for size; `GET` without auth for free vs paid).
3. Prefer **free** if any endpoint returns `200`.
4. Among paid `402` responses, pick the **lowest** quoted `price_usdfc`.
5. Fund rails and download each paid piece with `Authorization: Payment …`.

Outputs: `<cid>.car` under `--out-dir` (default `.`).

### Understanding cost

Paid SPs bill in **USDFC per GiB** (binary `2^30` bytes), **rounded up** to whole GiB. The `402` challenge contains the **total** `price_usdfc` for that piece. Details: [Pricing](#pricing).

### Useful flags

| Flag | Purpose |
|------|---------|
| `--cid`, `--cid-file`, positional CIDs | Pieces to retrieve |
| `--manifest` | Manifest-driven piece list |
| `--out-dir` | Output directory for `.car` files |
| `--sp-base-url` | Force one provider base URL |
| `--pay-rpc-url` / `--rpc-url` | FVM RPC for payments and discovery |
| `--filpay-private-key-file` | Client identity + MPP signing |
| `--yes` | Skip confirm prompt |
| `--dry-run` | Quote only |
| `--expires-in-sec` | MPP proof expiry |
| `--pay-debug`, `--verbose` | Diagnostics |

### Troubleshooting

- **Insufficient USDFC / FIL** — fund client wallet; check logs for `0x` address and rail IDs.
- **No endpoints found** — CID may not be advertised on-chain, or RPC/discovery failed; try `--sp-base-url` if you know a working URL.
- **Paid fetch fails after quote** — run `rail-check`; ensure operator approval and rail balance.
- **Verify settlement** — note rail ID from logs; view on [Filecoin Pay](https://pay.filecoin.cloud/) (mainnet: `/rails/<id>`; Calibration: `/calibration/rails/<id>`).

---

## For storage providers

### What you provide

SPs store deal **pieces** and serve them over HTTP (typically Curio or Boost) at:

```text
GET /piece/<piece-cid>
```

**`sp-proxy`** sits in front of that upstream server. It:

1. Returns **`402`** with an MPP challenge (quoted `price_usdfc`) when a client requests a piece without payment.
2. Verifies the client’s MPP credential and **settles once** on Filecoin Pay.
3. **Proxies** the upstream `GET` only after settlement succeeds.

**Deployment rule:** publish only the `sp-proxy` base URL to clients; keep Curio/Boost on `127.0.0.1`.

Clients using `retrieval-client` discover your proxy URL and pay in USDFC; you receive settlement to your configured payee address.

### What you need

1. An **upstream piece HTTP server** on **`127.0.0.1` only** (`/piece/<cid>`), reachable from `sp-proxy` on the same machine but **not** from the public internet.
2. **`sp-proxy`** with a settler private key (`sp.key`) — pays FIL gas for on-chain settlement.
3. **FIL** on the settler wallet for gas.
4. A **payee `0x` address** (defaults to settler) that receives USDFC from Filecoin Pay rails.
5. **SQLite** path for deal/quote state (`--db`).

### Network layout (recommended)

Run **two HTTP listeners** on the SP host:

| Service | Bind address | Who connects | Role |
|---------|--------------|--------------|------|
| **Curio / Boost** | `127.0.0.1` only | `sp-proxy` on the same machine | Serves raw `/piece/<cid>` bytes; **not** payment-aware |
| **`sp-proxy`** | Public interface, e.g. `0.0.0.0:8787` | Internet clients / `retrieval-client` | Quotes, verifies MPP, settles on Filecoin Pay, then proxies to upstream |

**Do not** expose Curio/Boost on a public IP or `0.0.0.0`. Clients should only reach your **`sp-proxy`** URL (the address you publish for discovery). Upstream stays on loopback so piece data is only served after settlement.

```text
Client (retrieval-client)
       |
       |  Internet
       v
sp-proxy :8787 (0.0.0.0, SP host)
       |
       | 127.0.0.1 only
       v
Curio / Boost :8788 (localhost, same host)
```

Configure Curio/Boost to listen on **`127.0.0.1:<port>`**, then point `sp-proxy` at it with `--upstream-host 127.0.0.1` and `--upstream-port <port>`.

### Deploy `sp-proxy`

```bash
go build -o bin/sp-proxy ./cmd/sp-proxy

./bin/sp-proxy \
  --listen 0.0.0.0:8787 \
  --db ./sp-proxy.db \
  --price-usdfc-per-gb 0.01 \
  --upstream-host 127.0.0.1 \
  --upstream-port 8788 \
  --pay-private-key-file ./sp.key
```

`--listen 0.0.0.0:8787` accepts client connections on all interfaces; use a specific IP or put TLS/reverse-proxy in front in production. `--upstream-host 127.0.0.1` assumes Curio/Boost is bound to localhost on the same host.

### Pricing

Set **`--price-usdfc-per-gb`** to your USDFC rate per **billed GiB** (each GiB or fraction counts as one GiB). The proxy computes the total `price_usdfc` in each `402` from upstream `HEAD` `Content-Length`. Full rules: [Pricing](#pricing).

### Upstream requirements (important)

For paid quoting to work, upstream **`HEAD /piece/<cid>`** must:

- Return **`200`** with a positive **`Content-Length`** (identity-encoded full piece size).
- Not rely on client `Range` / `Accept-Encoding` for sizing — the proxy strips those on its internal probe.

If `HEAD` is missing, returns `405`, `Content-Length: 0`, `204`, etc., the proxy returns **`503 payment-unavailable`** (no quote). **`GET`** may still work for already-paid clients; unpaid clients cannot obtain a price.

Optional: expose **`HEAD`** on the public proxy path for client size probes (the proxy forwards client `HEAD` without charging).

### SP proxy flags

| Flag | Purpose |
|------|---------|
| `--listen` | Client-facing listen address (default `:8787` = all interfaces; use `0.0.0.0:8787` explicitly in production) |
| `--db` | SQLite deal state |
| `--price-usdfc-per-gb` | USDFC per billed GiB |
| `--upstream-host`, `--upstream-port` | Loopback Curio/Boost (`127.0.0.1` + port) |
| `--pay-rpc-url` | FVM RPC |
| `--pay-private-key-file` | Settler key |
| `--pay-payee-address` | Payee advertised in challenges (default: settler) |
| `--pay-payments-address` | Optional payments contract override |
| `--pay-debug`, `--verbose` | Diagnostics |

### Monitoring payments

After a successful retrieval, logs include the Filecoin Pay **rail ID** and settle tx. View rail status on [pay.filecoin.cloud](https://pay.filecoin.cloud/) (mainnet: `/rails/<id>`; Calibration: `/calibration/rails/<id>`).

Wire format and security model: [docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md).

---

## For developers

### Repository layout

```text
cmd/
  retrieval-client/   CLI: discovery, probe, quote, pay, download
  sp-proxy/           CLI: MPP 402 gateway + Filecoin Pay settlement + reverse proxy
internal/
  piecepayment/       Quote, 402 middleware, authorize + settle
  pieceurls/          SP discovery, parallel probe, cheapest paid selection
  filpay/             Filecoin Pay client (rails, deposit, settle)
  mpp/                MPP challenge / credential wire types
  paymentheader/      Token amounts + per-GiB price helpers
  sqlitestore/        sp-proxy deal persistence
docs/
  mpp-filecoinpay.md  HTTP + payment protocol contract
```

### `sp-proxy` design: payment as middleware

Paid retrieval is implemented as **HTTP middleware** in `internal/piecepayment`, not as ad-hoc logic inside the reverse proxy. `PiecePaymentMiddleware` wraps a `next http.Handler`: it issues `402` quotes, verifies MPP credentials, settles on Filecoin Pay, then calls `next` only when payment is satisfied.

In `cmd/sp-proxy`, that `next` handler is the upstream reverse proxy to Curio/Boost:

```text
request --> PiecePaymentMiddleware --> httputil.ReverseProxy --> upstream /piece/<cid>
```

Keeping quote, authorize, and settle in a composable middleware layer means:

- **`sp-proxy` stays thin** — wiring, flags, SQLite store, and upstream proxy only.
- **Payment behaviour is reusable** — the same middleware can wrap any handler that serves `/piece/<cid>`.
- **Future upstream integration** — Curio, Boost, or other piece servers could embed `piecepayment` directly in their HTTP stack instead of running a separate `sp-proxy` process, as long as they expose the same MPP/`402` contract ([docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md)).

Today the standalone proxy is the supported deployment path; middleware extraction is a deliberate design choice to keep that option open.

### Build and test

```bash
go build -o bin/ ./cmd/retrieval-client ./cmd/sp-proxy
go test ./...
task test          # coverage report
task ci            # fmt, vet, lint, test, vuln
```

**E2E (shell):**

- `task test:e2e:discovery` — two CIDs from public sp-tool API, mainnet fetch (free paths).
- `task test:e2e:filpay` — local nginx piece + envoy router + `sp-proxy` on `:8787`, paid fetch on Calibration (`0.0003` USDFC/GiB).

Local piece server for tests: `task nginx:piece` (32 GiB sparse dummy `/piece/<cid>` with envoy router to mock network instability).

### Protocol

Implementers and reviewers should read [docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md) for the `402` / `Authorization: Payment` flow, challenge schema, and settle-before-serve guarantees.

### Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `FILPAY_PRIVATE_KEY_ENV` | retrieval-client | Env var name for client key (default `FILPAY_PRIVATE_KEY`) |
| `SP_PROXY_PAY_PRIVATE_KEY_ENV` | sp-proxy | Env var name for settler key |
| `SP_PROXY_PAY_RPC_URL` | both CLIs | Default FVM RPC if flag unset (mainnet: `https://api.node.glif.io/rpc/v1`) |
| `SP_PROXY_PAY_PAYMENTS_ADDRESS` | sp-proxy | Optional payments contract |
| `SP_PROXY_PAY_PAYEE_ADDRESS` | sp-proxy | Optional default payee |
| `SP_PROXY_UPSTREAM_HOST` / `SP_PROXY_UPSTREAM_PORT` | sp-proxy | Default upstream |

### Generate keys

Keys are secp256k1 private keys as 32-byte hex (with or without `0x`). Both binaries need funded on-chain actors.

**OpenSSL:**

```bash
openssl rand -hex 32 > sp.key
openssl rand -hex 32 > client.key
```

**Foundry cast:**

```bash
cast wallet new --json   # copy private_key to sp.key / client.key
```

**Lotus** — create `secp256k1` wallets, `lotus wallet export`, then extract the 32-byte hex `PrivateKey` field into `sp.key` / `client.key`. Keep `*.key` out of git.

---

## Pricing

Shared reference for consumers (interpreting quotes) and SPs (setting rates).

`sp-proxy` charges in **USDFC per binary GiB** (`2^30` bytes), configured with `--price-usdfc-per-gb`.

**Billing unit:** each GiB of data, or **any fraction of a GiB**, counts as **one billed GiB** (round up). There is no proportional per-byte charge within a GiB.

**Piece size:** before returning a `402` challenge, the proxy probes the upstream piece URL with `HEAD` and reads `Content-Length`. That byte count is the piece size used for quoting. The probe does not forward client `Range` / `If-*` / `Accept-Encoding` headers, so the quoted size is the full identity-encoded object.

**Formula** (only when `HEAD` returns `200` with a positive `Content-Length`):

```text
billed_gib  = ceil(piece_bytes / 2^30)   # piece_bytes > 0
price_usdfc = price_usdfc_per_gib × billed_gib
```

**Examples** at `--price-usdfc-per-gb 0.01`:

| Upstream `Content-Length` | Billed GiB | Challenge `price_usdfc` |
|---------------------------|------------|-------------------------|
| 13 bytes                  | 1          | 0.01                    |
| 1 GiB (2^30 bytes)        | 1          | 0.01                    |
| 1 GiB + 1 byte            | 2          | 0.02                    |
| 32 GiB                    | 32         | 0.32                    |

**Settlement:** the `price_usdfc` in the MPP challenge is the **total** charge for that piece. After the client pays, the proxy runs **one** Filecoin Pay settlement for that amount, then serves the full `GET` (no metering or partial charges during download).

**No quote** (`503 payment-unavailable`): the proxy cannot obtain a positive piece size from `HEAD`, including non-`200` responses (e.g. `404`, `405 Method Not Allowed`), missing or zero `Content-Length`, `204 No Content`, or `206 Partial Content`. These cases do not use the formula above.

---

## Protocol

HTTP payment flow, challenge JSON, and settlement semantics: **[docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md)**.

**Validation:** confirm rail IDs in client/proxy logs against [Filecoin Pay rails dashboard](https://pay.filecoin.cloud/) (mainnet: `https://pay.filecoin.cloud/rails/<RAIL_ID>`; Calibration: `https://pay.filecoin.cloud/calibration/rails/<RAIL_ID>`).
