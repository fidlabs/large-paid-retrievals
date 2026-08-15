# Access credentials (EIP-712): voucher + proof of possession

**Status:** implemented in `internal/pieceaccess`. Two **separate** standalone tokens, each an
EIP-712 typed-data object with its **signature embedded inside** the object, presented in their own
`Authorization` headers. `retrieval-client --voucher` forwards long-lived vouchers verbatim and mints
one per-CID `RetrievalProof`; owner-direct minting needs only the EIP-712 domain (no client-side CDP
lookup — the SP binds the deal from the piece CID). FCSS e2e covers proof and voucher happy/sad paths.

Delegated access to **private** PoRep dataset pieces uses two EIP-712 typed-data objects — never a
voucher alone:

- **`RetrievalVoucher`** — *capability*. The deal **owner** (`clientAddress` / payer) signs it
  **once, offline**, delegating a *scope* (PoRep `dealId`) to a **grantee** address. Reusable,
  long-lived, freely storable/transferable. A client MAY present **many** vouchers on one request
  (it need not know which deal a piece belongs to).
- **`RetrievalProof`** — *proof of possession (PoP)*. The **requester** signs it **per retrieval
  session**, binding the **exact piece CID** and a deadline within **`MAX_PROOF_TTL`** (same as the
  paid retry window — 12h).

A gated request MUST carry exactly one `RetrievalProof`. For delegated access it MUST also carry at
least one matching `RetrievalVoucher`. Owner-direct access MAY omit vouchers: the recovered proof
signer MUST equal the deal owner.

Deal owners can create vouchers with the
[filecoin-porep-market-tooling](https://github.com/fidlabs/filecoin-porep-market-tooling) CLI
(`client sign-retrieval-voucher`) or `scripts/sign-retrieval-voucher.sh`. Clients mint proofs at
request time (`scripts/sign-retrieval-credential.sh`, or `retrieval-client --voucher`) and send the
proof and every voucher in separate headers.

> **Why not a voucher alone.** A voucher presented by itself is a bearer token: anyone who captures
> it can retrieve until its deadline; `grantee` is then decorative. Requiring a fresh,
> resource-bound proof signed by the grantee key means **a stolen voucher is useless** without the
> grantee key. The grantee is typically offline when the voucher is issued — this is capability
> delegation, not an interactive grant. Proof deadlines align with the **12h paid-access / retry
> TTL** so large CARs can resume without re-signing mid-window.

**Payment is separate.** MPP / Filecoin Pay (`Authorization: Payment`) still settles quoted USDFC
after access is allowed. Access credentials do not replace payment.

---

## Notation & primitives

- Signatures are secp256k1 ECDSA over the EIP-712 digest (EIP-191 `0x19 0x01` prefix), recovered via
  `ecrecover`. 65-byte `r‖s‖v`, `v ∈ {27,28}` (implementations MUST also accept `{0,1}`).
- Verification is **off-chain** in `sp-proxy` / `pieceaccess`. `verifyingContract` is for domain
  separation only; no on-chain call is required to verify a credential.
- Portable across any secp256k1 signer (`viem`, MetaMask `eth_signTypedData_v4`, go-ethereum,
  headless agents). A human delegates once (voucher); software mints proofs per request.

---

## EIP-712 domain

```
EIP712Domain(string name, string version, uint256 chainId, address verifyingContract)
```

| Field | Value |
|---|---|
| `name` | `"PoRepPieceAccess"` |
| `version` | `"1"` |
| `chainId` | FEVM chain id (e.g. `314159` Calibration, `314` mainnet) |
| `verifyingContract` | **PoRep Market** contract address |

Both voucher and proof MUST use the **same** domain. Pinning `chainId` + `verifyingContract` on
`sp-proxy` prevents cross-network and cross-market replay.

---

## Structures

### RetrievalVoucher (capability)

```
RetrievalVoucher(address grantee, uint256 scope, uint256 issuedAt, uint256 deadline)
```

| Field | Meaning |
|---|---|
| `grantee` | Delegate address; the proof signer for this voucher MUST recover to it |
| `scope` | Access unit — for PoRep, the monotonic **deal id** |
| `issuedAt` | Unix seconds (audit) |
| `deadline` | Unix seconds; voucher valid while `now ≤ deadline` (MAY be long-lived) |

Signed by the scope’s **owner** (deal `clientAddress`).

### RetrievalProof (proof of possession)

```
RetrievalProof(uint256 scope, string resource, uint256 deadline)
```

| Field | Meaning |
|---|---|
| `scope` | **Advisory.** Signed but not authoritative: the SP binds the deal from `resource` (piece CID → CDP), so a client need not know the deal id to mint a proof. A client SHOULD set it to a voucher’s `scope` when known, or `0`. |
| `resource` | Requested piece CID **exactly as in the path** (`GET /piece/{cid}`) |
| `deadline` | Unix seconds; MUST satisfy `now ≤ deadline ≤ now + MAX_PROOF_TTL` |

Signed by the requester (grantee, or owner for owner-direct access). Clients MAY reuse the same
proof across retries until `deadline` (≤ `now_at_sign + MAX_PROOF_TTL`).

**`MAX_PROOF_TTL` MUST equal the paid retrieval retry window** — `dealstore.PaidAccessTTL` (**12 hours**).
That is the same TTL used for paid-access allocations, on-chain payment freshness, and
`--db-retention` floor. Clients MAY reuse one Retrieval credential (same proof) across Range /
network retries for a large CAR for up to that window, matching `Authorization: Payment` reuse
after settle. A shorter proof TTL would force re-signing mid-download while payment retries are
still valid; a longer one would outlive the payment/access window.

Clients SHOULD set `proof.deadline` to `now + PaidAccessTTL` (or slightly less) when starting a
fetch they expect to retry within that window.

---

## Scope, resource, and deal binding

- **`scope`** is a `uint256`. For PoRep market deals it is the **deal id**. CDP /
  `--porep-provider-id` scoped lookup maps `pieceCID` → deal(s) with `dealType` and
  `clientAddress` (owner).
- **`resource`** is the CID string from `GET /piece/{cid}` (byte-exact match to the proof).
- A piece MAY appear on multiple deals. The credential names the scope it claims; the gate verifies
  the piece is on that deal for this provider. **Public-wins:** if any matching deal is public,
  serve without a retrieval credential (payment may still apply).

---

## Wire token & presentation

Each token is an independent, self-contained EIP-712 object: `domain`, `types`, `primaryType`,
`message`, **and its own `signature`** — the signature lives **inside** the object (not a sibling,
not a separate header). Each token is serialized as **base64url(JSON), no padding**, and sent in its
own `Authorization` header. There is no combined/enclosing token and no `scheme` field.

**RetrievalProof** (exactly one per request):

```json
{
  "domain": {
    "name": "PoRepPieceAccess",
    "version": "1",
    "chainId": 314159,
    "verifyingContract": "0x1234567890abcdef1234567890abcdef12345678"
  },
  "types": {
    "RetrievalProof": [
      {"name": "scope", "type": "uint256"},
      {"name": "resource", "type": "string"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalProof",
  "message": {
    "scope": "1001",
    "resource": "bafk…",
    "deadline": "1767225600"
  },
  "signature": "0x…"
}
```

**RetrievalVoucher** (zero or more per request):

```json
{
  "domain": {
    "name": "PoRepPieceAccess",
    "version": "1",
    "chainId": 314159,
    "verifyingContract": "0x1234567890abcdef1234567890abcdef12345678"
  },
  "types": {
    "RetrievalVoucher": [
      {"name": "grantee", "type": "address"},
      {"name": "scope", "type": "uint256"},
      {"name": "issuedAt", "type": "uint256"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalVoucher",
  "message": {
    "grantee": "0xabc0000000000000000000000000000000000123",
    "scope": "1001",
    "issuedAt": "1767139200",
    "deadline": "1767744000"
  },
  "signature": "0x…"
}
```

Notes:

- Vouchers are **omitted for owner-direct access** (the proof signer is the deal owner).
- Every token’s `domain` MUST match the `sp-proxy` domain pin (`chainId` + PoRep Market
  `verifyingContract`).
- uint256 fields in `message` are **decimal strings** (prefer strings above `2^53 − 1`); addresses
  and signatures are `0x`-hex; `resource` is the CID string.
- `types` MAY omit `EIP712Domain` (verifiers synthesize it from the present `domain` fields). Field
  lists MUST match [Structures](#structures).

### Presentation

- **`Authorization: RetrievalProof <token>`** — exactly one per request; the recovered signer is the
  requester identity.
- **`Authorization: RetrievalVoucher <token>`** — **repeatable**. A client presents all of its
  vouchers; the SP verifies them **best-effort** and uses whichever authorizes the resolved deal.
  A single invalid/expired voucher is a non-fatal diagnostic, not a request failure.

Header scheme names are case-insensitive. Gated responses SHOULD use `Cache-Control: private,
no-store`.

Paid downloads MAY send `Authorization: Payment …` **and** the Retrieval headers on the same
request. Access is evaluated before payment settle. For paid GETs, the MPP `ClientAddress` MUST
equal the recovered proof signer.

Anonymous probes (no proof / no vouchers) omit access tokens. Private pieces return `403` so the
client can retry with a fresh proof (+ vouchers if delegated). A missing/invalid proof yields a JSON
`invalid_voucher` diagnostic.

---

## Verification algorithm

For a request on piece CID `R`, parse the single `RetrievalProof` header `P` and every
`RetrievalVoucher` header `V₀…Vₙ`:

1. **Proof (fatal).** If a `RetrievalProof` header is present it MUST verify, else the request is
   rejected with a `403` JSON `invalid_voucher` diagnostic:
   - complete EIP-712 object, `primaryType` = `RetrievalProof`, `signature` present;
   - `P.message.resource == R` (byte-exact);
   - `now ≤ P.message.deadline ≤ now + MAX_PROOF_TTL`;
   - `P.domain` matches the `sp-proxy` pin (pay-RPC chain id + PoRep Market address);
   - `requester = ecrecover(EIP712(P), P.signature)`.
   - `P.message.scope` is parsed but **advisory** (the deal is bound from `R`, next step).
2. **Vouchers (best-effort).** Each `Vᵢ` is verified independently: complete EIP-712 object,
   `primaryType` = `RetrievalVoucher`, domain pin match, `now ≤ deadline`, valid signature →
   `owner = ecrecover(EIP712(Vᵢ), Vᵢ.signature)`. A voucher that fails any check is dropped and kept
   only as a denial diagnostic; it never fails the request on its own.
3. Resolve deals for `R` (CDP / provider scope). If any deal is **public** → **allow** (public-wins;
   payment path unchanged). Else let `PRIV` be the set of private deals for this provider.
4. For each private deal `d ∈ PRIV`, the request is **authorized** if either:
   - **owner-direct:** `requester == d.clientAddress`; or
   - **delegated:** some verified voucher `V` has `V.owner == d.clientAddress`,
     `V.grantee == requester`, and `V.scope == d.dealId`.
5. If Payment is also present, `Payment.ClientAddress` MUST equal `requester`.
6. Else **deny**.

**Response codes:** missing/invalid proof, or a voucher that failed verification, on a private piece
→ **403** with a JSON `invalid_voucher` body (per-token `details`). A structurally valid proof/voucher
that simply does not authorize the deal → plain **403**. CDP / lookup failure → fail closed (never
serve a private piece on error).

---

## SP pinning (`sp-proxy`)

CDP deal lookup remains **always enabled**. `--porep-cdp-url` defaults to
`https://cdp.allocator.tech`. `--porep-provider-id` is **required**.

`sp-proxy` **always** pins EIP-712 `chainId` (from the pay RPC) and `verifyingContract` (PoRep
Market). Startup fails if the market address cannot be resolved:

- **Mainnet / Calibration:** built-in chain defaults (`internal/pieceaccess/porep_market.go`).
- **Devnet / other:** `--porep-market-address` or `SP_PROXY_POREP_MARKET_ADDRESS` / `POREP_MARKET`.

Credentials are rejected if the domain pin is missing (fail closed).

> **TODO (BIG):** Mainnet and Calibration defaults are **placeholders** until real PoRep Market
> deployments are known. Replace `PorepMarketMainnetPlaceholder` /
> `PorepMarketCalibrationPlaceholder` before relying on production domain pinning.

---

## Security considerations

- **Theft resistance.** The voucher alone authorizes nothing; every request needs a grantee-signed
  (or owner-signed), resource-bound proof. A stolen *voucher* remains useless without the grantee
  key. A stolen *full request* (proof+voucher, or owner proof) is replayable for that `resource`
  until `proof.deadline` (at most `MAX_PROOF_TTL` = 12h).
- **Residual replay window.** Bound by `MAX_PROOF_TTL` (= paid-access / retry TTL, 12h) and the
  named `resource` only — aligned with how long a paid GET may be retried without re-settling.
  An optional server-side `(signer, resource, deadline)` seen-cache can shrink the window further;
  v1 MAY stay stateless.
- **Contract / multisig owners (EIP-1271).** v1 assumes an EOA owner (`ecrecover`). EIP-1271 is a
  follow-up.
- **Revocation.** No pre-expiry revocation in v1; voucher `deadline` is the kill switch. A later
  `nonce` + deny-list is deferred until needed.
- **Domain separation.** Shared `verifyingContract` (PoRep Market) + `chainId` prevent cross-market
  / cross-network replay.

---

## Worked example

Owner `0x47cc…` delegates private deal `1001` to grantee `0xabc…`, then the grantee retrieves piece
`bafk…`.

**Voucher (signed once, offline, by the owner):**

```json
{
  "domain": {
    "name": "PoRepPieceAccess",
    "version": "1",
    "chainId": 314159,
    "verifyingContract": "0x<PoRepMarket>"
  },
  "types": {
    "RetrievalVoucher": [
      {"name": "grantee", "type": "address"},
      {"name": "scope", "type": "uint256"},
      {"name": "issuedAt", "type": "uint256"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalVoucher",
  "message": {
    "grantee": "0xabc…",
    "scope": "1001",
    "issuedAt": "1767139200",
    "deadline": "1767744000"
  }
}
```

**Proof (signed by the grantee for the retrieval session; reusable within `MAX_PROOF_TTL`):**

```json
{
  "domain": {
    "name": "PoRepPieceAccess",
    "version": "1",
    "chainId": 314159,
    "verifyingContract": "0x<PoRepMarket>"
  },
  "types": {
    "RetrievalProof": [
      {"name": "scope", "type": "uint256"},
      {"name": "resource", "type": "string"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalProof",
  "message": {
    "scope": "1001",
    "resource": "bafk…",
    "deadline": "1767225600"
  }
}
```

Each object embeds its own secp256k1 `signature`, is base64url(JSON)-encoded, and is sent in its own
header — `Authorization: RetrievalProof <proof-token>` plus one
`Authorization: RetrievalVoucher <voucher-token>` per voucher (and optionally
`Authorization: Payment …` after quote).

---

## Migration from today’s voucher-only token

Current `sp-proxy` / `retrieval-client` accept a single signed `RetrievalVoucher` (fields
`grantee`, `dealId`, `deadline`) as the entire Retrieval token. Target changes:

| Today | Target |
|---|---|
| Voucher alone authorizes | Voucher + **required** `RetrievalProof` PoP |
| Field `dealId` | Field **`scope`** (same numeric deal id; advisory on the proof) |
| No `issuedAt` | Add **`issuedAt`** on voucher |
| Requester from `?client=` / Payment | Requester from **proof `ecrecover`** (Payment MUST match) |
| One header, one token | **Two schemes**: one `Authorization: RetrievalProof` + repeatable `Authorization: RetrievalVoucher`, each a standalone EIP-712 object with an **embedded `signature`** |

`rail-check --voucher` and multi-`--voucher` probe/fetch flows carry every voucher header verbatim
and mint one proof per piece (the proof’s scope is advisory; the SP binds the deal from the piece
CID, so a client can present many vouchers without knowing which deal a piece is in).

---

## Open questions

1. Whether a proof seen-cache is wanted for v1 (replay within the 12h `MAX_PROOF_TTL` window).
2. Whether anonymous private probes keep returning **403** (today) or switch to **401** when no
   credential is present.
3. EIP-1271 timeline for contract/multisig deal owners.
4. CLI UX: `--voucher` (repeatable) forwards long-lived capabilities and the client mints the proof
   locally; whether to also accept a pre-minted proof token flag is open.
