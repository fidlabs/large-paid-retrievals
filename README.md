# PoRep paid-retrievals

HTTP tools for retrieving **pieces** (CAR files) that are part of datasets stored in Filecoin **PoRep Market V2** deals, from storage providers (SPs) — including **free** endpoints and **paid** retrievals settled on-chain via Filecoin Pay.

| If you are… | Start here |
|-------------|------------|
| **Dataset consumer** — download pieces from public or paid SPs | [For dataset consumers](#for-dataset-consumers) |
| **Storage provider** — charge for serving stored pieces | [For storage providers](#for-storage-providers) |
| **Developer** — maintain or extend this repo | [For developers](#for-developers) |

**Binaries:** `retrieval-client` (fetch) and `sp-proxy` (paid gateway in front of an SP piece server).

**Authorization:** who may retrieve a piece is decided by the deal in CDP / on-chain PoRep market state — **`dealType`** (`public` or `private`) and **`clientAddress`** (deal owner). Public deals: any client may probe/quote/download (subject to payment). Private deals: only the deal owner (`clientAddress`) may; others get `403`. Piece existence and size remain public (`HEAD` is always allowed). Payment (MPP / Filecoin Pay) is separate: it settles the quoted USDFC after access is allowed. Details: [Piece access](#piece-access-public-vs-private).

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

### Paid access window (retries)

After the first successful payment for a quote (`deal_uuid`), the SP keeps **paid access** for that piece for **12 hours** (not configurable on the client). During that window you may **retry the same `GET /piece/<cid>`** with the same `Authorization: Payment` credential — to resume a large CAR download, retry after a network error, or run parallel/range requests — **without paying again**. `retrieval-client` reuses the credential automatically for paid downloads in this window.

When the window expires, paid retries stop: request a **new** `402` quote (new `deal_uuid`) and settle again before downloading. The MPP proof `expires` field in the credential is separate; once paid, an expired proof may still authorize retries until the 12h paid-access window ends.

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
2. Probe endpoints in parallel (see [Piece access (public vs private)](#piece-access-public-vs-private)): `HEAD` for size, then `GET` (anonymous, then `?client=` on `403`).
3. Prefer **free** if any endpoint returns `200`.
4. Among paid `402` responses, pick the **lowest** quoted `price_usdfc`.
5. Fund rails and download each paid piece with `Authorization: Payment …`.

Outputs: `<cid>.car` under `--out-dir` (default `.`).

### Understanding cost

Paid SPs bill in **USDFC per GiB** (binary `2^30` bytes), **rounded up** to whole GiB. The `402` challenge contains the **total** `price_usdfc` for that piece — that is exactly what you pay; there is no operator commission and no surcharge on top of the quote (you still need **FIL** for Filecoin Pay transaction gas). Details: [Pricing](#pricing).

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
- **Private piece denied at probe** — anonymous `GET` returns `403` for private deals; the client retries with `?client=`. Non-owners get no usable endpoint (see [Piece access](#piece-access-public-vs-private)).
- **Paid fetch fails after quote** — run `rail-check`; ensure operator approval and rail balance.
- **Verify settlement** — note rail ID from logs; view on [Filecoin Pay](https://pay.filecoin.cloud/) (mainnet: `/rails/<id>`).

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

Clients using `retrieval-client` discover your proxy URL, as published by Curio/Boost, and pay in USDFC; you receive settlement to your configured payee address.

### What you need

1. An **upstream piece HTTP server** on **`127.0.0.1` only** (`/piece/<cid>`), reachable from `sp-proxy` on the same machine but **not** from the public internet.
2. **`sp-proxy`** with a settler private key (`sp.key`) — pays FIL gas for on-chain settlement (Filecoin Pay payee; **not** your miner actor key).
3. **FIL** on the settler wallet for gas.
4. A **payee `0x` address** (defaults to settler) that receives USDFC from Filecoin Pay rails.
5. **SQLite** path for deal/quote state (`--db`).
6. Your **miner actor ID** for CDP piece-access filtering (`--porep-provider-id`) — see [Miner actor ID](#miner-actor-id-porep-provider-id).

### Network layout (recommended)

Run **two HTTP listeners** on the SP host:

| Service | Bind address | Who connects | Role |
|---------|--------------|--------------|------|
| **Curio / Boost** | `127.0.0.1` only | `sp-proxy` on the same machine | Serves raw `/piece/<cid>` bytes; **not** payment-aware |
| **`sp-proxy`** | Public interface, e.g. `0.0.0.0:8787` | Internet clients / `retrieval-client` | Quotes, verifies MPP, settles on Filecoin Pay, then proxies to upstream |

**Deployment rule:** configure Curio/Boost to advertise your public IP address and TCP port that route to the `sp-proxy`.

**Do not** expose Curio/Boost's HTTP service on a public IP or `0.0.0.0`. Clients should only reach your **`sp-proxy`** URL (the address published for discovery). Upstream stays on loopback so piece data is only served after settlement.

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
  --pay-private-key-file ./sp.key \
  --porep-cdp-url https://cdp.allocator.tech \
  --porep-provider-id 1234
```

Replace `1234` with **your** miner actor id (numeric part of `f01234`). `--listen 0.0.0.0:8787` accepts client connections on all interfaces; use a specific IP or put TLS/reverse-proxy in front in production. `--upstream-host 127.0.0.1` assumes Curio/Boost is bound to localhost on the same host.

### Miner actor ID (`--porep-provider-id`)

CDP can return PoRep deals for the same piece CID from **multiple** providers. `sp-proxy` must filter to **your** miner so public/private access matches the deals you actually serve. Pass the **numeric** actor id only (`1234` for `f01234` / `t01234`).

This is **not** derived from `sp.key`. The settler key is the Filecoin Pay wallet; the miner id is whichever actor Curio is running as.

**Mainnet (local Curio):** use the miner already configured for that Curio node:

1. **Curio config / UI** — the miner address you set when bringing Curio up (e.g. `Miner` / actor field showing `f0…`). Strip the `f0` / `t0` prefix for the flag.
2. **Curio CLI / Harmony** — wherever the node reports its miner identity.
3. **Lotus** (same chain Curio uses), if you know the miner address:
   ```bash
   lotus state get-actor f01234
   # or: lotus-miner info   # when talking to that miner’s API
   ```
4. **Block explorers** — search your miner on [Filfox](https://filfox.info) / similar; copy the `f0…` id and use the digits after `f0`.

Optional env: `SP_PROXY_POREP_PROVIDER_ID` (same numeric value).

**Local FCSS-devnet:** `source ./scripts/devnet-env.sh` exports `POREP_PROVIDER_ID` from `CURIO_MINER_ID` in the market-tooling `.env`.

### Pricing

Set **`--price-usdfc-per-gb`** to your USDFC rate per **billed GiB** (each GiB or fraction counts as one GiB). The proxy computes the total `price_usdfc` in each `402` from upstream `HEAD` `Content-Length`. Clients pay that quoted amount in full; Filecoin Pay deducts a **network fee** from the charge (there is **no operator commission** in this design). Your payee account receives the net proceeds — see [Pricing](#pricing) for how that maps to your rate.

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
| `--db-retention` | Max age of SQLite rows before automatic pruning (default `168h` / 1 week); must be `≥ 12h` or `0` to disable |
| `--pay-withdraw-interval` | Background batch withdraw of Filecoin Pay proceeds to the settler wallet (default `1h`); `0` disables |
| `--price-usdfc-per-gb` | USDFC per billed GiB |
| `--upstream-host`, `--upstream-port` | Loopback Curio/Boost (`127.0.0.1` + port) |
| `--pay-rpc-url` | FVM RPC |
| `--pay-private-key-file` | Settler key |
| `--pay-payee-address` | Payee advertised in challenges (default: settler) |
| `--pay-payments-address` | Optional payments contract override |
| `--porep-cdp-url` | CDP base URL for piece CID → deal (`GET /po-rep/deals?pieceCID=…`; default `https://cdp.allocator.tech`; local Curio: `http://127.0.0.1:23300`). Empty disables. |
| `--porep-provider-id` | Your miner actor id (numeric; e.g. `1234` for `f01234`). **Required** when `--porep-cdp-url` is set. Filters CDP deals to this SP — see [Miner actor ID](#miner-actor-id-porep-provider-id) |
| `--pay-debug`, `--verbose` | Diagnostics |

Piece access resolves PoRep deals via [CDP](https://cdp.allocator.tech) (`GET /po-rep/deals?pieceCID=…`), which returns deal JSON including `dealType` and `clientAddress`. When `--porep-cdp-url` is set, `--porep-provider-id` is **required** (startup fails if missing/zero) so CDP results are scoped to deals you serve. `source ./scripts/devnet-env.sh` sets `SP_PROXY_POREP_CDP_URL=http://127.0.0.1:23300` and `POREP_PROVIDER_ID` for local FCSS CDP.

### Piece access (public vs private)

Deal metadata and piece CIDs are on the public chain (and in CDP), so **existence and size are not secrets**. `pieceaccess` only restricts who may obtain a quote or download CAR bytes.

| Request | Public deal | Private deal |
|---------|-------------|--------------|
| `HEAD /piece/<cid>` | Always allowed (no client). Used for size probes. | Always allowed (no client). |
| Anonymous `GET` (no `?client=`, no `Authorization`) | Allowed → `200` (free) or `402` (paid quote). | **403 Forbidden** — probe must retry with identity. |
| `GET ?client=<0x…>` (no payment yet) | Allowed → `200` / `402`. | Allowed only if `client` is the deal owner → `200` / `402`; otherwise **403**. |
| `GET` with `?client=` **and** `Authorization: Payment …` | Allowed (after payment settles). | Allowed only if requester is the deal owner; otherwise **403**. Missing deal in CDP → **403** (default-deny). |
| Any `GET` when CDP lookup errors (network/HTTP/JSON) | **403 Forbidden** (fail closed). `HEAD` still allowed. | Same. `ErrDealNotFound` (empty result) still allows unpaid probes. |

**Client probe sequence** (`retrieval-client` / `pieceurls`):

1. `HEAD` — always anonymous; learns `Content-Length` when the SP allows it.
2. Anonymous `GET` — succeeds for public pieces (`200`/`402`).
3. On **403**, retry the same `GET` with `?client=<wallet>` (the fetch wallet). Owner of a private deal gets a quote; non-owners stay denied and that endpoint is skipped.

Paid download still sends `Authorization: Payment …` (and usually `?client=`); access is checked again before settlement and upstream proxying.

### Monitoring payments

At default log level, a successful retrieval logs `paid retrieval authorized` with `deal_uuid`, `client`, `cid`, and `pool_id` (or `paid retrieval reused` on paid-access retries). With **`--pay-debug`** or **`--verbose`**, Filecoin Pay tracing may also emit **`rail_id`** and **`payment_tx_hash`** when the proxy runs on-chain payment steps (e.g. `CreditRailPayment` when the pool balance is insufficient); drawdowns from a pre-funded pool or paid-access retries may not produce those fields. View rail status on [pay.filecoin.cloud](https://pay.filecoin.cloud/) (mainnet: `/rails/<id>`).

### Inspecting quotes and pool state (`SIGUSR1`, Unix only)

On **Unix** (Linux, macOS, etc.), `sp-proxy` handles **`SIGUSR1`** by printing all deals (quotes), settlement pools, credits, and allocations from the SQLite database to **stderr** — useful for debugging payment or pool balance issues without stopping the process. On Windows and other non-Unix platforms the binary builds, but this signal handler is a no-op.

```bash
kill -USR1 $(pidof sp-proxy)
# or: kill -USR1 <pid>
```

The dump is also noted in the startup log (`sigusr1_dump=…`).

### Database retention

A background task runs every hour (and once at startup) to prune SQLite rows older than **`--db-retention`** (default **1 week**): expired nonces, expired deal allocations, unpaid/old deals, and closed settlement pools with their credits. **`VACUUM`** runs after each prune to reclaim disk. Open pools and deals with active paid-access windows are kept. Set `--db-retention 0` to disable automatic pruning.

**`--db-retention` must be at least 12 hours** (or `0`) so `pool_credits` idempotency rows outlive the on-chain payment freshness window. `sp-proxy` rejects shorter values at startup; prune also floors closed-pool retention at 12h as defense in depth.

### Payee withdraw

A background worker withdraws available USDFC from the settler’s Filecoin Pay account to wallet on **`--pay-withdraw-interval`** (default **1 hour**), including once at startup. This batches on-chain proceeds so concurrent retrievals from multiple client rails do not race on withdraw nonces. Set `--pay-withdraw-interval 0` to disable automatic withdraw.

Wire format and security model: [docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md).

### Recommended external controls

Deploy `sp-proxy` behind infrastructure that provides:

- **TLS termination** — protect payment credentials in transit (MITM prevention).
- **Rate limiting** — the unauthenticated quote path (upstream `HEAD` probe + SQLite quote insert per anonymous `GET`) is relatively expensive; limit per client IP or API key at your reverse proxy, CDN, or API gateway (for example nginx `limit_req`, Cloudflare, or an AWS WAF rule).
- **Network policy** (optional) — restrict who can reach the public listen address if the SP should not be openly quotable.

The service intentionally does not implement TLS or rate limiting itself; those belong at the internet edge.

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
  filpay/             Filecoin Pay client (rails, deposit, rail charge verification)
  mpp/                MPP challenge / credential wire types
  paymentheader/      Token amounts + per-GiB price helpers
  sqlitestore/        sp-proxy deal persistence + settlement pools
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

### SP settlement pool

`sp-proxy` tracks paid access in a **local SQLite settlement pool** (`internal/sqlitestore`, orchestrated by `internal/piecepayment`).

For each `(payer, payee)` pair the store maintains an open **pool** with a `remaining_base_units` balance. On authorize:

1. **`TryAllocateDeal`** debits the quoted piece price from the pool (or returns insufficient balance).
2. If the pool is short, **`CreditRailPayment`** (`internal/filpay`) fetches the client’s `modifyRailPayment` receipt, rejects txs mined more than 12h ago, parses `RailOneTimePaymentProcessed`, and verifies the creditable charge (net payee + network fee, excluding client-controlled operator commission) for the payer→payee rail.
3. **`CreditPool`** credits the pool at that amount (idempotent on `payment_tx_hash` while `pool_credits` rows exist), then allocation retries.
4. After a successful allocation, the client gets a **paid-access window** (default 12h) so large downloads can retry without re-charging; nonce consumption still prevents credential replay on first settlement.

This pool bookkeeping is an **interim SP-side layer**: it ties MPP credentials to verified on-chain rail charges and enforces settle-before-serve without trusting client-reported balances. It will be **replaced** by full **Filecoin Pay Operators and Validator** in a future update.

### Build and test

```bash
go build -o bin/ ./cmd/retrieval-client ./cmd/sp-proxy
go test ./...
task test          # coverage report
task ci            # fmt, vet, lint, test, vuln
```

**E2E (shell):**

- `task test:e2e:discovery` — two CIDs from public sp-tool API, mainnet fetch (free paths).
- `task fcss-devnet:e2e` (alias `task test:e2e:fcss-devnet`) — [FCSS-devnet](https://github.com/fidlabs/FCSS-devnet) seed-deals access matrix via local `sp-proxy` with `bytecut-proxy` between proxy and Curio (TCP-RST `/piece` GETs after 0.5 MiB so Range resume is exercised). Successful fetches run `car inspect` + `car verify` on `./downloads/<cid>.car`. Requires sibling [`../FCSS-devnet`](https://github.com/fidlabs/FCSS-devnet) with `just seed-deals` summary.

### Local FCSS-devnet helpers

These tasks prepare wallets and env so you can run `sp-proxy` and `retrieval-client` against a local Curio stack from [FCSS-devnet](https://github.com/fidlabs/FCSS-devnet) (sibling checkout at [`../FCSS-devnet`](https://github.com/fidlabs/FCSS-devnet)). That stack has PoRep market deals (public and private) and piece HTTP on Curio; CDP indexes deal type and client for piece access.

| Task | Purpose |
|------|---------|
| `task fcss-devnet:env` | Sources `scripts/devnet-env.sh`: prints/exports `PAY_RPC_URL`, `PAYMENTS`, `USDFC`, `POREP_PROVIDER_ID`, `SP_PROXY_UPSTREAM_*`, `SP_PROXY_POREP_CDP_URL`, and a sample `PIECE_CID` from VerifReg claims. |
| `task fcss-devnet:keys` | Writes `./sp.key` (and related keys) from the FCSS-devnet market-tooling `.env` so the settler wallet matches the local chain. |
| `task fcss-devnet:fund` | Funds `./client.key` / `./sp.key` with FIL + USDFC on the local Curio chain (needed after a chain reset). |
| `task fcss-devnet:check` | Confirms Curio serves a seed-deals data piece (`HEAD` on upstream `/piece/<cid>`). |
| `task fcss-devnet:bytecut` | Starts `bytecut-proxy` on `:22311` in front of Curio; TCP-RST `/piece` GETs after 0.5 MiB (HEAD untouched). Point `sp-proxy --upstream-port 22311`. |
| `task fcss-devnet:bytecut:clean` | Stops `bytecut-proxy` on `:22311`. |

Typical flow after `just up` + `just seed-deals` in FCSS-devnet: `task fcss-devnet:env`, `fcss-devnet:keys`, `fcss-devnet:fund` (once), then start `sp-proxy` with the exported CDP/upstream flags and run `retrieval-client` (or `task fcss-devnet:e2e` for the full access matrix, which starts `bytecut-proxy` automatically).

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
| `SP_PROXY_POREP_CDP_URL` | sp-proxy | CDP HTTP base (default mainnet `https://cdp.allocator.tech`; local `http://127.0.0.1:23300`) |
| `SP_PROXY_POREP_PROVIDER_ID` | sp-proxy | Miner actor id (numeric) for CDP deal filter; same as `--porep-provider-id` |

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

**Lotus** — create `secp256k1` wallets, `lotus wallet export`, then extract the 32-byte hex `PrivateKey` field into `sp.key` / `client.key`. **Keep private keys out of git** — `.gitignore` covers `*.key`, `*.priv`, and `*.priv.*`, but double-check before committing, and never reuse a key that has touched a repo on mainnet.

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

**What the client pays:** the `price_usdfc` in the MPP challenge is the **gross** charge for that piece. The client pays that exact amount via Filecoin Pay `modifyRailPayment` — there is **no operator commission** in this design (the client is the rail operator and rails are created with zero commission rate), and nothing is added on top of the quote besides **FIL gas** for on-chain transactions.

**Filecoin Pay network fee:** Filecoin Pay deducts a **network fee** from each one-time rail charge. On chain, the gross charge splits into:

```text
gross (quoted price_usdfc) = net_payee_amount + network_fee
```

(`operator_commission` is zero in this design.)

- **Client** debits **gross** from rail lockup (the quoted `price_usdfc`).
- **SP payee account** receives **net** USDFC (gross minus network fee).
- **SP settlement pool** is credited at **gross** so retrieval authorization matches the quoted price; the SP absorbs the network fee as a cost of using Filecoin Pay.

There is no per-byte metering during download: one quote, one charge, one served `GET`.

**No quote** (`503 payment-unavailable`): the proxy cannot obtain a positive piece size from `HEAD`, including non-`200` responses (e.g. `404`, `405 Method Not Allowed`), missing or zero `Content-Length`, `204 No Content`, or `206 Partial Content`. These cases do not use the formula above.

---

## Protocol

HTTP payment flow, challenge JSON, and settlement semantics: **[docs/mpp-filecoinpay.md](docs/mpp-filecoinpay.md)**.

**Validation:** confirm rail IDs in client/proxy logs against [Filecoin Pay rails dashboard](https://pay.filecoin.cloud/) (mainnet: `https://pay.filecoin.cloud/rails/<RAIL_ID>`).
