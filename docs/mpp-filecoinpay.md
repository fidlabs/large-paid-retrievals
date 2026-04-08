# MPP + Filecoin Pay Protocol (Settle-Before-Serve)

This document defines the wire contract used by this project when gating piece retrievals with MPP semantics while settling payments through Filecoin Pay.

## Goals

- Use MPP challenge/proof style HTTP flow (`402` -> retried paid `GET`)
- Use Filecoin Pay as the source of payment truth
- Preserve strict safety for SPs: **do not serve piece bytes before settle succeeds**

## HTTP Flow

1. Client requests `GET /piece/<cid>` without proof.
2. Proxy returns `402 Payment Required` with `WWW-Authenticate: Payment ...` challenge params.
3. Client prepares proof and retries `GET /piece/<cid>` with `Authorization: Payment <credential>`.
4. Proxy verifies proof and request binding.
5. Proxy executes Filecoin Pay `SettleIfFunded(...)`.
6. If settle succeeds, proxy consumes nonce, marks deal paid, serves piece.

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
  "price_fil": "0.01",
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
- `price_fil` is decimal FIL string and is converted to wei server-side before settle.

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
```

Signature rules:
- `sig_type` must be `evm`
- Signature is ECDSA secp256k1 over `keccak256(canonical_message)`
- Recovered address must equal `client`

## Validation Rules

For a paid request, proxy must verify:
- proof is syntactically valid and not expired
- `method/path/host/cid/client` bind to this HTTP request and stored deal
- `challenge_id/deal_uuid` match an existing quoted deal
- nonce is unused for that deal (`used_nonces` table)
- Filecoin Pay settle succeeds for quoted `price_fil`

If any check fails:
- reject with `402` and a fresh `WWW-Authenticate: Payment ...` challenge
- include `application/problem+json` body using problem types under `https://paymentauth.org/problems/`

## Security Notes

- Settlement is authoritative, not proof-of-funds checks.
- Nonce replay is blocked server-side.
- Piece bytes are served only after settle + nonce consume + mark paid to avoid concurrent drain or similar.
- Successful paid responses return a `Payment-Receipt` (base64url-no-pad JSON).

## Conformance Gaps / Awkward Bits

- **Method and intent identifiers:** `method="filecoinpay"` and `intent="charge"` are local conventions; they are not currently backed by a published IANA registry entry.
- **Challenge binding style:** the implementation uses stateful challenge IDs (DB-backed `deal_uuid`) rather than stateless HMAC binding from the draft's recommendation.
- **JCS canonicalization:** request JSON is encoded from fixed structs and base64url-no-pad, but strict RFC8785 JCS canonicalization is not enforced via a dedicated JCS library.
- **Fresh-challenge behavior on very early failures:** when Authorization parsing fails before we can recover deal context, we return `402`; challenge regeneration may be limited compared to fully contextual failures.