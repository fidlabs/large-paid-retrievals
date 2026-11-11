# Simple `sp-proxy` setup on regular Linux

Copy-paste recipe for the **simplest** paid-retrieval cutover when you already have Curio or Boost serving pieces on an **internet-routed IP**.

This is how to put `sp-proxy` in front of deals onboarded through the Filecoin Cold Storage Service or peer-to-pool PoRep. The proxy does two separate jobs:

1. **Access.** It asks [Hyperion](https://hyperion.allocator.tech) which PoRep deals this miner has for the piece. Public deals may be quoted by anyone. Private dataset pieces require a short-lived `Authorization: RetrievalProof` (the deal owner, or a delegate who also presents a matching owner-signed `Authorization: RetrievalVoucher`).
2. **Payment.** After access is allowed, paid pieces still require USDFC via Filecoin Pay before bytes are served.

Read the mechanics in [README — For storage providers](../README.md#for-storage-providers), [Piece access](../README.md#piece-access-public-vs-private), and [docs/access-vouchers-eip712.md](access-vouchers-eip712.md). Payment wire format: [docs/mpp-filecoinpay.md](mpp-filecoinpay.md). To get running, continue below.

## You start with (existing system)

- One Linux host
- Curio/Boost already answering `GET` / `HEAD` `/piece/<cid>` on a **public** host:port (clients can already request retrievals)

```text
Internet clients  -->  Curio/Boost :PUBLIC_PORT on PUBLIC_IP   (pieces served with no access check and no payment)
```

Datasets are served directly from Boost/Curio. There is no fencing, no public/private check, and no payment.

## You end with (after this guide)

- One Linux host
- `sp-proxy` listening on that **same** public host:port
- Curio/Boost moved to **localhost only** (no longer reachable from the internet)
- Every `GET` is checked against Hyperion for this miner, then payment is required before a paid piece is served

```text
Internet clients
    -->  sp-proxy :PUBLIC_PORT on PUBLIC_IP
           |  Hyperion (deal type + owner) and Filecoin Pay
           v
         Curio/Boost :UPSTREAM_PORT on 127.0.0.1
```

You do not change the dataset or the on-chain deal. The proxy reads deal type and owner from Hyperion and collects USDFC through [Filecoin Pay](https://docs.filecoin.cloud/core-concepts/filecoin-pay-overview/). Dataset owners issue retrieval vouchers separately; `sp-proxy` only verifies them.

When you move the ports and put the proxy in front of your SP software **there will be a short downtime** on `PUBLIC_IP:PUBLIC_PORT`. Plan for that if you are already serving heavy downloads.

---

## Before you start ensure that you

1. Are logged in to the Linux host where Curio/Boost already runs.
2. Know the public internet IP address and TCP port of your existing Curio/Boost piece server.
3. Know **your miner actor ID** (`f01234`, `t01234`, or the bare number). Hyperion is queried with that id. `sp-proxy` refuses to start without `--porep-provider-id`. A wrong id returns no deals, so private pieces are not recognized and fall through to a normal payment quote. This is the Curio/Boost miner, not the Filecoin Pay wallet created below. See [Miner actor ID](../README.md#miner-actor-id-porep-provider-id).
4. Can reach Hyperion from this host (`https://hyperion.allocator.tech` on mainnet). Lookup failures fail closed: `GET /piece/…` returns **403** until Hyperion answers. `HEAD` still works.
5. Can change the Curio/Boost retrieval **listen** address (see their docs) and pick a free **local** port.
6. Have some **FIL** for settlement gas (settler wallet).
7. Have root/sudo on the Linux host for systemd and the firewall.

---

## Security caveats

| Risk | What to do |
|------|------------|
| **Leaving Curio/Boost on the public IP** | If the retrieval layer stays on `PUBLIC_IP` / `0.0.0.0`, anyone who finds the new port downloads pieces **without payment and without a retrieval credential**. Move it to **`127.0.0.1` only**. |
| **Wrong or missing miner ID** | Startup fails when `--porep-provider-id` is missing or `0`. A mismatched id makes Hyperion return no deals for your pieces: private GETs are **not** denied, they are quoted (**402**) like an unknown piece. |
| **Hyperion unreachable** | GETs fail closed (**403**). Do not bypass the proxy to “keep serving.” Fix egress to Hyperion. |
| **Protect your `sp.key`** | Anyone with it can spend FIL gas and control payee proceeds. Mode `600`. Never put your miner/owner BLS key, or a dataset owner’s voucher-signing key, in `sp.key`. |
| **Vouchers are not an SP secret** | Deal owners sign `RetrievalVoucher`s for delegates. The proxy verifies them. You do not collect, store, or configure client vouchers. |
| **No rate limit** | Anonymous quote and Hyperion lookups are relatively expensive. Add edge rate limiting when you can. |

Apply the same access controls and firewall policy you already use for the SP software on this box.

---

## What clients will see

`HEAD /piece/<cid>` is always allowed. Size and existence are public.

`GET /piece/<cid>` depends on the deal Hyperion returns for **your** miner:

| Deal Hyperion returns for this miner | Anonymous `GET` (no retrieval credential) | With a valid `RetrievalProof` |
|------------------------------------------------|-------------------------------------------|-------------------------------|
| **Public** | Allowed through access, then **402** Payment Required. CAR bytes follow `Authorization: Payment` and settlement. | Same payment path. |
| **Private** | **403** Forbidden. | **402** (then the CAR after payment) when the proof signer is the deal owner, or a voucher grantee whose `RetrievalVoucher` matches that deal. Otherwise **403**. |
| **No deal** for this miner (wrong `--porep-provider-id`, or the piece is not in Hyperion) | Not an access denial. Payment still quotes: **402** when upstream `HEAD` is usable. A later paid `GET` with no deal is **403**. | Same. |
| Hyperion error (network, HTTP, bad JSON) | **403** (fail closed). | **403**. |

Payment does not replace the retrieval credential. A paid `Authorization: Payment` whose client address is not the proof signer is rejected on a private piece. Owners and delegates use `retrieval-client` (`--voucher` is repeatable; the client mints the proof). Deal owners create vouchers with [filecoin-porep-market-tooling](https://github.com/fidlabs/filecoin-porep-market-tooling) (`client sign-retrieval-voucher`). Format: [docs/access-vouchers-eip712.md](access-vouchers-eip712.md).

On mainnet and Calibration, `sp-proxy` pins the EIP-712 domain to the chain id from `--pay-rpc-url` and the built-in PoRep Market address. You do not pass `--porep-market-address` for those networks.

---

## Step 0 — Prepare the shell and confirm the existing system

Install:

1. [Go](https://go.dev/dl/) **1.26.9+** (or from your distro).
2. [Foundry `cast`](https://book.getfoundry.sh/getting-started/installation).

Put your values in the shell (replace every `REPLACE_*`):

```bash
export PUBLIC_IP=REPLACE_PUBLIC_IP             # address clients use today
export PUBLIC_PORT=REPLACE_PUBLIC_PORT         # retrieval port, e.g. 7777
export PIECE_CID=REPLACE_PIECE_CID             # one piece CID this SP stores (tests only)
export POREP_PROVIDER_ID=REPLACE_MINER_ID      # f01234, t01234, or 1234
```

From a client on the public internet (preferred) or from this host via the public IP:

```bash
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

Pass: **HTTP 200** and a positive **`Content-Length`**.

Confirm this host can reach Hyperion:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" \
  "https://hyperion.allocator.tech/po-rep/deals?pieceCid=${PIECE_CID}"
```

Any HTTP response (including 200 or 404) means egress works. Connection timeout or failure means GETs will **403** after cutover until that path is open.

---

## Step 1 — Pick a working directory

```bash
sudo mkdir -p /opt/sp-proxy
sudo chown "$USER:$USER" /opt/sp-proxy
cd /opt/sp-proxy
```

---

## Step 2 — Choose a localhost upstream port

Pick a free **local** port for Curio/Boost after cutover (not the public port):

```bash
export UPSTREAM_PORT=8788
ss -ltn | grep ":${UPSTREAM_PORT} " || echo "port ${UPSTREAM_PORT} looks free"
```

If it is taken, pick another free port and use it everywhere below.

---

## Step 3 — Build `sp-proxy`

Private-deal authorization is **not** in tags `v1.0`–`v1.2`. Those builds do not take `--porep-provider-id` and do not check Hyperion. Use `main`, or a release tag published after this guide.

```bash
cd /opt/sp-proxy
git clone https://github.com/fidlabs/large-paid-retrievals.git src
cd src
git checkout main
go build -o /opt/sp-proxy/sp-proxy ./cmd/sp-proxy
cd /opt/sp-proxy
chmod 755 /opt/sp-proxy/sp-proxy
/opt/sp-proxy/sp-proxy --help
```

`--help` must list `--porep-provider-id`, `--porep-hyperion-url`, and `--porep-market-address`. If it does not, the checkout is a v1 tag.

---

## Step 4 — Create a wallet to receive payments

There is no on-chain “register wallet” step. The settler wallet is a secp256k1 private key; `cast` prints its `0x` address. Fund that address with FIL on mainnet before you serve paid retrievals.

```bash
cd /opt/sp-proxy
openssl rand -hex 32 > sp.key
chmod 600 sp.key
cast wallet address --private-key "0x$(tr -d '\n' < sp.key)"
```

To use MetaMask instead: create an account on **Filecoin / FEVM**, export the private key into `sp.key` (hex, with or without `0x`, one line), `chmod 600 sp.key`, and fund that same `0x` address.

Keep a secure offline backup of `sp.key`.

---

## Step 5 — Write env for systemd

```bash
cd /opt/sp-proxy

# USDFC per billed GiB (round up). Example: 0.01 USDFC per GiB.
export PRICE_USDFC_PER_GB=0.01

# Re-export if this is a new shell:
# export PUBLIC_IP=... PUBLIC_PORT=... UPSTREAM_PORT=8788 POREP_PROVIDER_ID=f01234

cat > /opt/sp-proxy/sp-proxy.env <<EOF
PUBLIC_IP=${PUBLIC_IP}
PUBLIC_PORT=${PUBLIC_PORT}
UPSTREAM_PORT=${UPSTREAM_PORT}
PRICE_USDFC_PER_GB=${PRICE_USDFC_PER_GB}
POREP_PROVIDER_ID=${POREP_PROVIDER_ID}
SP_PROXY_POREP_HYPERION_URL=https://hyperion.allocator.tech
EOF
chmod 600 /opt/sp-proxy/sp-proxy.env
```

`--porep-hyperion-url` already defaults to that Hyperion URL. Setting it here makes the dependency obvious. Leave `--porep-market-address` unset on mainnet and Calibration.

---

## Step 6 — Cutover (brief downtime)

Do these in order. Finish quickly.

### 6a — Rebind Curio/Boost to localhost

In Curio/Boost config, change the HTTP piece listener from the public interface to:

```text
127.0.0.1:UPSTREAM_PORT
```

(Example: `127.0.0.1:8788`.) The exact key depends on Curio vs Boost — whichever sets the `/piece` HTTP bind address.

Restart Curio/Boost as you normally would.

### 6b — Verify Curio/Boost is local-only and still serves HEAD

```bash
# Must work on loopback:
curl -sS -D- -o /dev/null --head "http://127.0.0.1:${UPSTREAM_PORT}/piece/${PIECE_CID}"

# Listener must be localhost, not public:
ss -ltnp | grep ":${UPSTREAM_PORT}"
```

Expect `127.0.0.1:UPSTREAM_PORT`, **not** `0.0.0.0`, `PUBLIC_IP`, or `*`.

```bash
# Must FAIL (connection refused or timeout) — unpaid bypass is closed:
curl -sS -m 3 --head "http://${PUBLIC_IP}:${UPSTREAM_PORT}/piece/${PIECE_CID}" \
  || echo "good: upstream not reachable on public IP"
```

Confirm the **old public port is free** so `sp-proxy` can take it:

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
  --pay-private-key-file /opt/sp-proxy/sp.key \
  --porep-provider-id "${POREP_PROVIDER_ID}" \
  --porep-hyperion-url "${SP_PROXY_POREP_HYPERION_URL}"
```

Startup must log `porep Hyperion lookup enabled` (your provider id), `porep voucher domain pin enabled` (chain id and PoRep Market `verifyingContract`), and `sp-proxy listening`. It exits immediately if `--porep-provider-id` is missing or the pay RPC chain has no built-in PoRep Market address.

If bind fails with “address already in use”, something is still on `PUBLIC_IP:PUBLIC_PORT` (often Curio not fully rebound).

In another terminal:

```bash
set -a; source /opt/sp-proxy/sp-proxy.env; set +a

# HEAD stays public — expect 200 and Content-Length:
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"

# GET is no longer an unpaid CAR from Curio.
# Public deal: 402. Private deal, no credential: 403.
# Hyperion down: 403. No deal for this miner: 402 (payment quote only).
curl -sS -D- -o /dev/null "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

Stop the foreground process with Ctrl+C when this looks right, then install systemd.

**If you cannot bind a specific IP**, use `--listen 0.0.0.0:${PUBLIC_PORT}`. Keep upstream on `127.0.0.1` only.

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
  --pay-private-key-file /opt/sp-proxy/sp.key \
  --porep-provider-id ${POREP_PROVIDER_ID} \
  --porep-hyperion-url ${SP_PROXY_POREP_HYPERION_URL}
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

Keep the **existing** public piece port open for clients. Do not expose the localhost upstream port.

Example with `ufw` (skip the allow if `PUBLIC_PORT` is already open):

```bash
sudo ufw allow "${PUBLIC_PORT}/tcp" comment 'sp-proxy public'
# Do NOT: ufw allow ${UPSTREAM_PORT}/tcp
sudo ufw status
```

Allow **outbound HTTPS** to `hyperion.allocator.tech` if egress is restricted.

---

## Step 9 — Discovery ads

Because `sp-proxy` took over the **same** `PUBLIC_IP:PUBLIC_PORT`, existing Curio/Boost discovery URLs usually keep working **without** a new host or port.

Still verify:

1. The published HTTP retrieval base is still `http://PUBLIC_IP:PUBLIC_PORT` (or your HTTPS front door).
2. From the public internet:

```bash
curl -sS -D- -o /dev/null --head "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
curl -sS -D- -o /dev/null "http://${PUBLIC_IP}:${PUBLIC_PORT}/piece/${PIECE_CID}"
```

Expect HEAD `200`. Expect GET `402` (public, or no Hyperion deal for this miner) or `403` (private with no credential, or Hyperion down). You should **not** get an unpaid full CAR straight from Curio.

If you previously advertised a different URL than the listen address, point that advertisement at the proxy. Never advertise `127.0.0.1`.

---

## Flags this recipe sets

| Flag | In this recipe |
|------|----------------|
| `--listen` | `${PUBLIC_IP}:${PUBLIC_PORT}` (the old public piece address) |
| `--db` | `/opt/sp-proxy/sp-proxy.db` |
| `--price-usdfc-per-gb` | Your USDFC rate per billed GiB (round up) |
| `--upstream-host` / `--upstream-port` | `127.0.0.1` and `UPSTREAM_PORT` |
| `--pay-private-key-file` | `/opt/sp-proxy/sp.key` (Filecoin Pay settler) |
| `--porep-provider-id` | **Required.** Miner actor id (`f01234`, `t01234`, or bare number) |
| `--porep-hyperion-url` | `https://hyperion.allocator.tech` (also the default) |

Useful flags this recipe leaves at their defaults:

| Flag | Default | When to set it |
|------|---------|----------------|
| `--pay-rpc-url` | `https://api.node.glif.io/rpc/v1` | Another FVM RPC, or Calibration |
| `--pay-payee-address` | Settler address from `sp.key` | USDFC should land in a different `0x` account |
| `--pay-payments-address` / `--pay-token-address` | Built-in for the pay-RPC chain | Non-default Filecoin Pay deployment |
| `--porep-market-address` | Built-in PoRep Market on mainnet (chain 314) and Calibration (chain 314159) | **Required** on any other chain (devnet). Also the EIP-712 `verifyingContract` clients must use |
| `--db-retention` | `168h` (1 week); minimum `12h`, or `0` to disable | Shorter SQLite lifetime, or keep rows forever |
| `--pay-withdraw-interval` | `1h`; `0` disables | How often settled USDFC is withdrawn to the settler wallet |
| `--pay-debug` / `--verbose` | off | Settlement or Hyperion diagnostics |

Same values can be supplied with `SP_PROXY_POREP_PROVIDER_ID`, `SP_PROXY_POREP_HYPERION_URL`, `SP_PROXY_POREP_MARKET_ADDRESS` (or `POREP_MARKET`), `SP_PROXY_PAY_RPC_URL`, `SP_PROXY_PAY_PAYEE_ADDRESS`, `SP_PROXY_PAY_PAYMENTS_ADDRESS`, and `SP_PROXY_PAY_TOKEN_ADDRESS`. The full list is in the [README](../README.md#sp-proxy-flags).

---

## Quick troubleshooting

| Symptom | Likely fix |
|---------|------------|
| Process exits: `--porep-provider-id is required` or `invalid --porep-provider-id` | Set `POREP_PROVIDER_ID` to `f0…` / `t0…` / a positive number and restart |
| Process exits: `no PoRep market default for chain` | Pay RPC is not mainnet or Calibration. Set `--porep-market-address` to that chain’s PoRep Market `0x` |
| Bind error on public port | Curio still listening on `PUBLIC_IP:PUBLIC_PORT` — finish Step 6a/6b |
| `503` / `payment-unavailable` | Upstream `HEAD` on `127.0.0.1:UPSTREAM_PORT` is missing, not 200, or has no `Content-Length` |
| Every `GET` is **403**, including pieces you believe are public | Hyperion lookup is failing (egress, HTTP, or bad JSON). `HEAD` can still be 200. A wrong miner id does not look like this |
| Private piece is **403** for an anonymous curl | Expected when Hyperion lists that deal for this miner. The deal owner or a voucher grantee must send `Authorization: RetrievalProof` (and `RetrievalVoucher` when delegated) |
| Private piece is **402** for an anonymous curl | Hyperion returned no deal for `--porep-provider-id`. Check the miner id and that Hyperion lists the deal for this provider |
| Clients still get free unpaid CARs | Upstream still public — re-check `ss -ltnp` and the firewall |
| Settlement / tx failures | Settler needs FIL; check RPC (default mainnet Glif) |
| Process dies after reboot | `systemctl enable sp-proxy`; `journalctl -u sp-proxy` |

Inspect quote/pool state (Unix):

```bash
sudo kill -USR1 "$(pidof sp-proxy)"
sudo journalctl -u sp-proxy -n 200 --no-pager
```

---

## Upgrading from v1.0–v1.2

Those tags serve every piece with **no** Hyperion check. After you switch to this build, private pieces start returning **403** until the client presents a retrieval credential. Public pieces keep the `200` / `402` payment behavior.

`sp-proxy` before **v1.2** can credit the same on-chain payment twice when a client presents the settlement tx hash with different hex casing. If the SQLite file was created by v1.0 or v1.1, stop the proxy, **delete** `--db` (for example `/opt/sp-proxy/sp-proxy.db`), and start clean. Do not reuse that file. Clients pay again for any in-flight paid-access window.

---

## What this recipe deliberately skips

- Running the proxy on a different host than Curio
- Changing to a brand-new public port (possible, but then you must update discovery ads)
- Devnet / Calibration contract overrides (`--pay-rpc-url`, `--porep-market-address`, a local Hyperion)
- Issuing retrieval vouchers (dataset owners do that; the proxy only verifies them)
