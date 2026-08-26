# Simple `sp-proxy` setup on regular Linux

Copy-paste recipe for the **simplest** paid-retrieval cutover when you already have Curio or Boost serving pieces on an **internet-routed IP**:

- One Linux host
- Curio/Boost already answering `GET` / `HEAD` `/piece/<cid>` on a **public** host:port (clients already use that URL)
- Mainnet Filecoin Pay
- You insert `sp-proxy` on that **same** public host:port, and move Curio/Boost to **localhost only**

**Version:** written for **`v1.0` / `v1-maintenance`** (`sp-proxy` as a paid HTTP gateway only). That line has **no** CDP / private-deal piece-access controls and **no** `--porep-provider-id`. Newer `main` builds add those; do not mix flags from newer docs into a `v1.0` binary.

You do **not** need to understand MPP or rails internals to follow this. For full detail on the payment path, see [README — For storage providers](../README.md#for-storage-providers) and [docs/mpp-filecoinpay.md](mpp-filecoinpay.md).

---

## Starting point (today)

```text
Internet clients  -->  Curio/Boost :PUBLIC_PORT on PUBLIC_IP   (pieces served free / unpaid)
```

Record these now (you will reuse them):

```bash
export PUBLIC_IP=REPLACE_PUBLIC_IP         # internet-routed address clients already hit
export PUBLIC_PORT=REPLACE_PUBLIC_PORT     # e.g. 7777 — the port already in discovery ads
export PIECE_CID=REPLACE_PIECE_CID         # any piece CID this SP actually stores
```

Confirm it works from the public side (or from the host via the public IP):

```bash
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

You need **HTTP 200** and a positive **`Content-Length`**.

---

## What you will end up with

```text
Internet clients  -->  sp-proxy :PUBLIC_PORT on PUBLIC_IP  -->  Curio/Boost :UPSTREAM_PORT on 127.0.0.1
```

Same public URL clients already use. Upstream is no longer reachable from the internet. Clients pay in USDFC; settlement gas comes from your settler wallet (`sp.key`).

**Cutover implies a short downtime** on `PUBLIC_IP:PUBLIC_PORT` while you move the listener from Curio/Boost to `sp-proxy`.

---

## Before you start (checklist)

1. Linux host where Curio/Boost already runs (same machine as the proxy).
2. `PUBLIC_IP` / `PUBLIC_PORT` from above (what discovery already advertises).
3. Ability to change Curio/Boost **listen** address to `127.0.0.1` and pick a free **local** port (`UPSTREAM_PORT`, example **`8788`**).
4. A small amount of **FIL** for settlement gas (settler wallet).
5. Root/sudo for systemd + firewall.

Replace every `REPLACE_*` value below with yours.

---

## Security caveats (read once)

| Risk | What to do |
|------|------------|
| **Leaving Curio/Boost on the public IP** | If upstream stays on `PUBLIC_IP` / `0.0.0.0` after cutover, anyone can still download pieces **without paying** (bypass `sp-proxy`). After cutover, upstream must be **`127.0.0.1` only**. |
| **Two listeners on the same public port** | Only one process can own `PUBLIC_IP:PUBLIC_PORT`. Stop/rebind Curio first, then start `sp-proxy` on that address. |
| **`sp.key` is a funded wallet** | Anyone with the file can spend FIL gas and receive/control payee proceeds (default payee = settler). Mode `600`, owner-only; never commit it; never paste it into chat/logs/git. |
| **Plain HTTP** | This recipe keeps HTTP on the existing public port. Payment credentials travel in headers. Add **TLS** at the edge before treating this as production-hardened. |
| **No rate limit** | Anonymous quote path is relatively expensive. Add edge rate limiting when you can. |
| **Firewall** | Keep `PUBLIC_PORT` open for clients. Do **not** open `UPSTREAM_PORT` to the internet. |
| **Not your miner actor key** | `sp.key` is a **separate** Filecoin Pay settler EOA. Do not put your miner/owner BLS key in `sp.key`. |

This recipe is “works on a normal SP box.” It is **not** a full hardening guide.

---

## Step 0 — Pick a working directory

```bash
sudo mkdir -p /opt/sp-proxy
sudo chown "$USER:$USER" /opt/sp-proxy
cd /opt/sp-proxy
```

---

## Step 1 — Install Go (if building from source)

Need **Go 1.26.6+**.

```bash
go version
```

If missing, install from [https://go.dev/dl/](https://go.dev/dl/) (or your distro), then confirm `go version` again.

---

## Step 2 — Choose a localhost upstream port

Pick a free **local** port Curio/Boost will use after cutover (not the public port):

```bash
export UPSTREAM_PORT=8788
ss -ltn | grep ":${UPSTREAM_PORT} " || echo "port ${UPSTREAM_PORT} looks free"
```

If it is taken, pick another free port and use that everywhere below.

---

## Step 3 — Build `sp-proxy` (before cutover)

Do this while Curio is still serving publicly so build/key setup does not extend downtime.

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

## Step 4 — Create the settler key

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

Fund **that** `0x` address with a little **FIL** on mainnet (settlement gas only). USDFC proceeds go to the same address by default (payee = settler).

Keep a secure offline backup of `sp.key`.

---

## Step 5 — Write env for systemd

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

## Step 6 — Cutover (brief downtime)

Do these in order. Aim to finish quickly.

### 6a — Rebind Curio/Boost to localhost

In Curio/Boost config, change the HTTP piece listener from the public interface to:

```text
127.0.0.1:UPSTREAM_PORT
```

(Example: `127.0.0.1:8788`.) Exact config keys differ by Curio vs Boost version — whatever controls the `/piece` HTTP bind address/port.

Restart Curio/Boost as you normally would.

### 6b — Verify upstream is local-only and still serves HEAD

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

### 6c — Start `sp-proxy` on the old public address

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

## Step 7 — Install a systemd service

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

## Step 8 — Firewall

Keep the **existing** public piece port open for clients. Do not expose the new localhost upstream port.

Example with `ufw` (adjust if you already allow `PUBLIC_PORT`):

```bash
sudo ufw allow "${PUBLIC_PORT}/tcp" comment 'sp-proxy public'
# Do NOT: ufw allow ${UPSTREAM_PORT}/tcp
sudo ufw status
```

---

## Step 9 — Discovery ads

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

## Step 10 — Optional but strongly recommended

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
| Bind error on public port | Curio still listening on `PUBLIC_IP:PUBLIC_PORT` — finish Step 6a/6b |
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
