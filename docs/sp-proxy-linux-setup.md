# Simple `sp-proxy` setup on regular Linux

Copy-paste recipe for the **simplest** paid-retrieval cutover when you already have Curio or Boost serving pieces on an **internet-routed IP**:

**You start with (existing system):**

- One Linux host
- Curio/Boost already answering `GET` / `HEAD` `/piece/<cid>` on a **public** host:port (ie clients can already request retrievals)

**You end with (after this guide):**

- One Linux host
- `sp-proxy` listening on that **same** public host:port
- Curio/Boost moved to **localhost only** (no longer reachable from the internet)
- Retrievals require payment (USDFC via Filecoin Pay) before pieces are served

This is an instruction on how to enable paid retrievals for deals onboarded through the Filecoin Cold Storage Service, or Peer to Pool Porep. We recommend you try to understand the mechanics, which you will find here: [README — For storage providers](../README.md#for-storage-providers) and [docs/mpp-filecoinpay.md](mpp-filecoinpay.md), but if you want to just go ahead and get started, read on.

---

## Starting point (today)

```text
Internet clients  -->  Curio/Boost :PUBLIC_PORT on PUBLIC_IP   (pieces served free / unpaid)
```

Datasets are served directly from Boost/Curio to clients over the public internet with no fencing or payment for retrieval.

---

## What you will end up with

```text
Internet clients  -->  sp-proxy :PUBLIC_PORT on PUBLIC_IP  -->  Curio/Boost :UPSTREAM_PORT on 127.0.0.1
```

Once enabled, the datasets you store will be fenced by a proxy that will request client payments and only serve the data upon receiving the payment. There is nothing you need to do to the dataset itself, no on-chain changes etc. Payments are done in USDFC through Filecoin Pay. To read about Filecoin Pay go to https://docs.filecoin.cloud/core-concepts/filecoin-pay-overview/

**There will be a short downtime** on `PUBLIC_IP:PUBLIC_PORT`, the piece retrieval server, while you move from Curio/Boost to `sp-proxy` + Curio/Boost.

---

## Before you start ensure that you

1. Are logged in to the Linux host where Curio/Boost already runs.
2. Know the public internet IP address and TCP port number of your existing Curio/Boost piece server.
3. Have the ability to change the Curio/Boost retrieval layer  **listen** address (check their published documentation).
4. Have access to some **FIL** for settlement gas (settler wallet).
5. Have root/sudo permission on the Linux host for systemd + firewall.

---

## Security caveats

| Risk | What to do |
|------|------------|
| **Leaving Curio/Boost on the public IP** | If your retrieval layer stays bound to `PUBLIC_IP` / `0.0.0.0` after installing the proxy, anyone can still download pieces **without paying** simply by guessing the new port number. When installing the proxy, the SP software retrieval layer must move to **`127.0.0.1` only**. |
| **Two listeners on the same public port** | Only one process can own `PUBLIC_IP:PUBLIC_PORT`. Stop/rebind Curio/Boost first, then start `sp-proxy` on that address. |
| **Protect your `sp.key`** | Anyone with access to it can spend FIL gas and receive/control payee proceeds. If storing it as a file, make it mode `600` and never reveal it outside of the SP software/proxy context. |
| **No rate limit** | Anonymous quote path is relatively expensive. Add edge rate limiting when you can. |
| **Not your miner actor key** | `sp.key` is a **separate** Filecoin Pay settler EOA. Do not put your miner/owner BLS key in `sp.key`. |

This recipe is made to get up and running quickly on a regular Linux-based SP. We recommend you apply your own hardening on top of this (specifically, apply the same access controls, firewall settings etc that you already do for the existing SP software running on the box.

---

## Step 0 — Prepare shell environment and confirm existing system is working

Make sure you have the following values in your shell environment:

(Replace every `REPLACE_*` value below with the actual values for your system.)

```bash
export PUBLIC_IP=REPLACE_PUBLIC_IP         # the IP address at which clients can reach your miner and retrieve dataset
export PUBLIC_PORT=REPLACE_PUBLIC_PORT     # port on which you are serving retrievals, eg 7777
export PIECE_CID=REPLACE_PIECE_CID         # any one piece CID this SP stores (for tests only)
```

Run a quick test to ensure the existing service works from a client machine on the public internet (recommended) or from the host via the public IP:

```bash
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

The test passes if you receive **HTTP 200** and a positive **`Content-Length`**.



## Step 1 — Pick a working directory

```bash
sudo mkdir -p /opt/sp-proxy
sudo chown "$USER:$USER" /opt/sp-proxy
cd /opt/sp-proxy
```

---

## Step 2 — Install Go

Need **Go 1.26.6+**.

```bash
go version
```

If missing, install from [https://go.dev/dl/](https://go.dev/dl/) (or your distro), then confirm `go version` again.

---

## Step 3 — Choose a localhost upstream port

Pick a free **local** port Curio/Boost will use after cutover (not the public port):

```bash
export UPSTREAM_PORT=8788
ss -ltn | grep ":${UPSTREAM_PORT} " || echo "port ${UPSTREAM_PORT} looks free"
```

If it is taken, pick another free port and use that everywhere below.

---

## Step 4 — Build `sp-proxy`

```bash
cd /opt/sp-proxy
git clone https://github.com/fidlabs/large-paid-retrievals.git src
cd src
git checkout v1.0   # always use a tagged version
go build -o /opt/sp-proxy/sp-proxy ./cmd/sp-proxy
cd /opt/sp-proxy
chmod 755 /opt/sp-proxy/sp-proxy
```

---

## Step 5 — Create a wallet to receive your payments

There is no on-chain “register wallet” step. A settler wallet is a secp256k1 private key; the `0x` address is derived from it. Fund that address with FIL on mainnet when you are ready.

```bash
cd /opt/sp-proxy
openssl rand -hex 32 > sp.key
chmod 600 sp.key
```

Show the wallet address (needs [Foundry `cast`](https://book.getfoundry.sh/getting-started/installation)):

```bash
cast wallet address --private-key "0x$(tr -d '\n' < sp.key)"
```

If you prefer a UI, create an account in MetaMask on **Filecoin / FEVM**, export its private key into `sp.key` (hex, with or without `0x`; one line), `chmod 600 sp.key`, then use that same `0x` address.

Fund that `0x` address with a little **FIL** on mainnet. This must happen before you proceed to the next step, otherwise the wallet will not show up on Filecoin and you will not be able to process retrieval payments.

Keep a secure offline backup of `sp.key`.

---

## Step 6 — Write env for systemd

```bash
cd /opt/sp-proxy

# USDFC per billed GiB (round up). Example: 0.01 USDFC per GiB
export PRICE_USDFC_PER_GB=0.01

# Re-export if this is a new shell:
# export PUBLIC_IP=... PUBLIC_PORT=... UPSTREAM_PORT=8788

cat > /opt/sp-proxy/sp-proxy.env <<EOF
PUBLIC_IP=${PUBLIC_IP}
PUBLIC_PORT=${PUBLIC_PORT}
UPSTREAM_PORT=${UPSTREAM_PORT}
PRICE_USDFC_PER_GB=${PRICE_USDFC_PER_GB}
EOF
chmod 600 /opt/sp-proxy/sp-proxy.env
```

---

## Step 7 — Cutover (brief downtime)

Do these in order. Aim to finish quickly.

### 7a — Rebind Curio/Boost to localhost

In Curio/Boost config, change the HTTP piece listener from the public interface to:

```text
127.0.0.1:UPSTREAM_PORT
```

(Example: `127.0.0.1:8788`.) Exact config keys differ by Curio vs Boost version — whatever controls the `/piece` HTTP bind address/port.

Restart Curio/Boost as you normally would.

### 7b — Verify Curio/Boost is local-only and still serves HEAD

```bash
# Must work on loopback:
curl -sS -D- -o /dev/null --head "http://127.0.0.1:${UPSTREAM_PORT}/piece/${PIECE_CID}"

# Listener must be localhost, not public:
ss -ltnp | grep ":${UPSTREAM_PORT}"
```

Expect `127.0.0.1:UPSTREAM_PORT`, **not** `0.0.0.0` / `PUBLIC_IP` / `*`.

```bash
# Must FAIL (connection refused / timeout) — proves unpaid bypass is closed:
curl -sS -m 3 --head "http://${PUBLIC_IP}:${UPSTREAM_PORT}/piece/${PIECE_CID}" || echo "good: upstream not reachable on public IP"
```

Also confirm the **old public port is free** so `sp-proxy` can take it:

```bash
ss -ltn | grep ":${PUBLIC_PORT} " || echo "public port ${PUBLIC_PORT} is free"
```

### 7c — Start `sp-proxy` on the old public address

Foreground smoke test first:

```bash
cd /opt/sp-proxy
set -a; source ./sp-proxy.env; set +a

./sp-proxy \
  --listen "${PUBLIC_IP}:${PUBLIC_PORT}" \
  --db /opt/sp-proxy/sp-proxy.db \
  --price-usdfc-per-gb "${PRICE_USDFC_PER_GB}" \
  --upstream-host 127.0.0.1 \
  --upstream-port "${UPSTREAM_PORT}" \
  --pay-private-key-file /opt/sp-proxy/sp.key
```

If bind fails with “address already in use”, something is still on `PUBLIC_IP:PUBLIC_PORT` (often Curio not fully rebound).

In another terminal:

```bash
set -a; source /opt/sp-proxy/sp-proxy.env; set +a

# Same URL clients already use — now via sp-proxy:
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"

# Anonymous GET should be 402 (paid quote) or 200 (if you set price to free / zero path).
# v1.0 does not enforce private-deal access; payment is the gate.
curl -sS -D- -o /dev/null "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

Stop the foreground process with Ctrl+C when this looks good, then install systemd (next step).

**If you cannot bind a specific IP**, use `--listen 0.0.0.0:${PUBLIC_PORT}` instead — still keep upstream on `127.0.0.1` only.

---

## Step 8 — Install a systemd service

```bash
sudo tee /etc/systemd/system/sp-proxy.service >/dev/null <<'EOF'
[Unit]
Description=Filecoin PoRep sp-proxy (paid piece gateway)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=REPLACE_LINUX_USER
Group=REPLACE_LINUX_USER
WorkingDirectory=/opt/sp-proxy
EnvironmentFile=/opt/sp-proxy/sp-proxy.env
ExecStart=/opt/sp-proxy/sp-proxy \
  --listen ${PUBLIC_IP}:${PUBLIC_PORT} \
  --db /opt/sp-proxy/sp-proxy.db \
  --price-usdfc-per-gb ${PRICE_USDFC_PER_GB} \
  --upstream-host 127.0.0.1 \
  --upstream-port ${UPSTREAM_PORT} \
  --pay-private-key-file /opt/sp-proxy/sp.key
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
```

Replace `REPLACE_LINUX_USER` with the user that owns `/opt/sp-proxy`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sp-proxy
sudo systemctl status sp-proxy --no-pager
sudo journalctl -u sp-proxy -f
```

---

## Step 9 — Firewall

Keep the **existing** public piece port open for clients. Do not expose the new localhost upstream port.

Example with `ufw` (adjust if you already allow `PUBLIC_PORT`):

```bash
sudo ufw allow "${PUBLIC_PORT}/tcp" comment 'sp-proxy public'
# Do NOT: ufw allow ${UPSTREAM_PORT}/tcp
sudo ufw status
```

---

## Step 10 — Discovery ads

Because `sp-proxy` took over the **same** `PUBLIC_IP:PUBLIC_PORT`, existing Curio/Boost discovery URLs usually keep working **without** changing advertised host/port.

Still verify:

1. Published HTTP retrieval base still matches `http://PUBLIC_IP:PUBLIC_PORT` (or your HTTPS front door).
2. From the public internet:

```bash
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
curl -sS -D- -o /dev/null "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

Expect HEAD `200`, and GET `402` (or `200` if free) — **not** unpaid full CAR downloads from Curio directly.

If you previously advertised a different URL than the listen address, update that advertisement to whatever clients should hit now (still the proxy, never `127.0.0.1`).

---

## Step 11 — Optional but strongly recommended

1. **TLS** — terminate HTTPS on nginx/Caddy/LB; proxy to `sp-proxy`.
2. **Rate limit** — limit requests per IP on the quote path at the edge.
3. **Separate payee** — USDFC to a cold wallet:

   ```text
   --pay-payee-address 0xREPLACE_PAYEE
   ```

   Settler (`sp.key`) still pays FIL gas and must stay online/funded.

4. **Disk** — SQLite at `/opt/sp-proxy/sp-proxy.db` grows with quotes; default retention is 1 week.

---

## Quick troubleshooting

| Symptom | Likely fix |
|---------|------------|
| Bind error on public port | Curio still listening on `PUBLIC_IP:PUBLIC_PORT` — finish Step 7a/7b |
| `503` / `payment-unavailable` | Upstream `HEAD` on `127.0.0.1:UPSTREAM_PORT` missing/not 200/no `Content-Length` |
| Clients still get free unpaid CARs | Upstream still public — re-check `ss -ltnp` and firewall |
| Settlement / tx failures | Settler needs FIL; check RPC (default mainnet Glif) |
| Process dies after reboot | `systemctl enable sp-proxy`; `journalctl -u sp-proxy` |

Inspect quote/pool dump (Unix):

```bash
sudo kill -USR1 "$(pidof sp-proxy)"
sudo journalctl -u sp-proxy -n 200 --no-pager
```

---

## What this recipe deliberately skips

- Running proxy on a different host than Curio
- Changing to a brand-new public port (possible, but then you must update discovery ads)
