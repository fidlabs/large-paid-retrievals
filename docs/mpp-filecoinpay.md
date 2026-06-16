# MPP + Filecoin Pay Protocol (Settle-Before-Serve)

This document defines the wire contract used by this project when gating piece retrievals with MPP semantics while settling payments through Filecoin Pay.

**Audience:** storage providers operating `sp-proxy`, client authors, and developers extending payment middleware. For operator setup and CLI usage, see the [README](../README.md) sections for [dataset consumers](../README.md#for-dataset-consumers), [storage providers](../README.md#for-storage-providers), and [developers](../README.md#for-developers).

## Goals

- Use MPP challenge/proof style HTTP flow (`402` -> retried paid `GET`)
- Use Filecoin Pay as the source of payment truth
- Preserve strict safety for SPs: **do not serve piece bytes before payment is confirmed on-chain**

## HTTP Flow

1. Client requests `GET /piece/<cid>` without proof.
2. Proxy returns `402 Payment Required` with `WWW-Authenticate: Payment ...` challenge params.
3. Client prepares proof and retries `GET /piece/<cid>` with `Authorization: Payment <credential>`.
4. Proxy verifies proof and request binding.
5. Client includes `payment_tx_hash` (the mined `modifyRailPayment` tx) in the signed credential.
6. Proxy verifies that tx on-chain, parses `RailOneTimePaymentProcessed` for the payer→payee rail, credits the settlement pool, allocates paid access, and serves the piece.

## Challenge Schema (`402` response)

`WWW-Authenticate: Payment ...` auth-params:

```text
WWW-Authenticate: Payment id="<challenge_id>", realm="piece:<host>", method="filecoinpay", intent="charge", request="<base64url-no-pad-json>", expires="<RFC3339>"
```

Where `request` decodes to:

```json
{
  "deal_uuid": "uuid",
  "cid": "baga...",
  "price_usdfc": "0.01",
  "payee_0x": "0x...",
  "method": "GET",
  "path": "/piece/<cid>",
  "host": "example.com:8787"
}
```

Optional auth-params handled:
- `description="Filecoin piece retrieval charge"`
- `opaque="<base64url-no-pad-json>"` where decoded JSON is a flat string map:
  - `deal_uuid`
  - `cid`
- `digest` is minimally supported - the field unwraps but nothing is done with it.

Notes:
- `challenge_id` is unique per quote and currently equals `deal_uuid`.
- `expires` is RFC3339 and is a short challenge TTL.
- `price_usdfc` is the total decimal USDFC charge for the piece (SP computes it as `price_usdfc_per_gib * ceil(piece_bytes / 2^30)` from upstream HEAD `Content-Length` when the challenge is issued—each GiB or part thereof is one billed GiB). It is converted to base units server-side before pool allocation.

## Paid Proof Schema (`Authorization: Payment ...`)

Header value is `base64url-no-pad(json(Credential))`.

```json
{
  "challenge": {
    "id": "uuid",
    "realm": "piece:example.com:8787",
    "method": "filecoinpay",
    "intent": "charge",
    "request": "<base64url-no-pad-json>",
    "expires": "2026-04-08T12:00:00Z",
    "description": "Filecoin piece retrieval charge",
    "opaque": "<base64url-no-pad-json>"
  },
  "payload": {
    "version": "mpp-v1",
    "challenge_id": "uuid",
    "deal_uuid": "uuid",
    "client": "0x...",
    "cid": "baga...",
    "method": "GET",
    "path": "/piece/<cid>",
    "host": "example.com:8787",
    "nonce": "uuid",
    "expires_unix": 1735689600,
    "payment_tx_hash": "0x...",
    "sig_type": "evm",
    "sig": "hex-65-byte-secp256k1-signature"
  }
}
```

## Canonical Message For Signature

The signed bytes are:

```text
mpp-v1
challenge_id=<challenge_id>
deal_uuid=<deal_uuid>
cid=<cid>
client=<client lowercased>
method=<method uppercased>
path=<path>
host=<host lowercased>
nonce=<nonce>
expires_unix=<expires_unix>
payment_tx_hash=<payment_tx_hash lowercased>
```

Signature rules:
- `sig_type` must be `evm`
- Signature is ECDSA secp256k1 over `keccak256(canonical_message)`
- Recovered address must equal `client`

## Validation Rules

For a paid request, proxy must verify:
- proof is syntactically valid; `expires_unix` must be in the future on the **first-settlement** path — paid-access retries may reuse the same credential (even if `expires_unix` has passed) while an active allocation exists
- `method/path/host/cid/client` bind to this HTTP request and stored deal
- `challenge_id/deal_uuid` match an existing quoted deal
- nonce is unused for that deal (`used_nonces` table) on the **first-settlement** path; retries within an active paid-access allocation may reuse the same credential (including nonce) without consuming the nonce again
- Credential includes `payment_tx_hash` bound in the signed canonical message
- `payment_tx_hash` refers to a `modifyRailPayment` tx mined within the last 12 hours (chain block timestamp)
- Verified `RailOneTimePaymentProcessed` creditable charge (`netPayeeAmount + networkFee`, excluding client-controlled `operatorCommission`) covers quoted `price_usdfc`; the SP absorbs the network fee

If any check fails:
- reject with `402` and a fresh `WWW-Authenticate: Payment ...` challenge
- include `application/problem+json` body using problem types under `https://paymentauth.org/problems/`

## Security Notes

- On-chain rail charge receipts are authoritative; the SP does not trust client-reported balances.
- Payment txs older than 12 hours are rejected, so an immutable on-chain payment cannot re-fund a pool after SQLite rows are pruned. `pool_credits`/`pools` prune is floored at 12h and `sp-proxy` rejects `--db-retention` shorter than that (defense in depth).
- Nonce replay is blocked on first settlement; paid-access retries within the allocation window skip nonce consumption.
- On first settlement, piece bytes are served only after nonce consume, then a pool allocation attempt; if the pool balance is insufficient, verified rail receipt and pool credit, then a second allocation attempt — to avoid concurrent drain or similar. Paid-access retries require an active allocation and skip nonce consumption and pool drawdown.
- Successful paid responses return a `Payment-Receipt` (base64url-no-pad JSON).

### Recommended external controls

Deploy the gateway behind TLS termination and per-IP (or per-API-key) rate limiting at the reverse proxy or CDN. The unauthenticated quote path triggers an upstream `HEAD` probe and a database insert per request; that workload belongs at the network edge, not in application code.

## Conformance Gaps / Awkward Bits

- **Method and intent identifiers:** `method="filecoinpay"` and `intent="charge"` are local conventions; they are not currently backed by a published IANA registry entry.
- **Challenge binding style:** the implementation uses stateful challenge IDs (DB-backed `deal_uuid`) rather than stateless HMAC binding from the draft's recommendation.
- **JCS canonicalization:** request JSON is encoded from fixed structs and base64url-no-pad, but strict RFC8785 JCS canonicalization is not enforced via a dedicated JCS library.
- **Fresh-challenge behavior on very early failures:** when Authorization parsing fails before we can recover deal context, we return `402`; challenge regeneration may be limited compared to fully contextual failures.