# Access voucher design (EIP-712)

For delegated access to private dataset pieces (deal owner authorizes another wallet), use an EIP-712 typed-data voucher.

Deal owners can create vouchers suitable for authorizing third-party access with the [filecoin-porep-market-tooling](https://github.com/fidlabs/filecoin-porep-market-tooling) CLI (`client sign-retrieval-voucher`). Pass the resulting Bearer token to `retrieval-client fetch --voucher …`.

## Domain

- `name`: `PoRepPieceAccess`
- `version`: `1`
- `chainId`: active network chain id
- `verifyingContract`: PoRep Market contract address

## Primary type

- `RetrievalVoucher`

## Message fields

- `grantee` (`address`) — wallet allowed to retrieve
- `dealId` (`uint256`) — monotonic PoRep deal id being delegated
- `deadline` (`uint256`) — unix timestamp after which voucher is invalid

## Typed-data payload (JSON)

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
      {"name": "dealId", "type": "uint256"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "RetrievalVoucher",
  "message": {
    "grantee": "0xabc0000000000000000000000000000000000123",
    "dealId": 1001,
    "deadline": 1767225600
  },
  "signature": "0x..."
}
```

## Transport

Transport is `Authorization: Bearer <token>`, where `<token>` is base64url-without-padding of compact JSON (`domain`, `types`, `primaryType`, `message`, `signature`). For retrievals that may map to several private dataset-piece deals, pass all vouchers to `retrieval-client fetch` by repeating `--voucher`.

`retrieval-client` sends vouchers only together with a client identity (`?client=` on probe retry and download). Anonymous probes omit Bearers. Paid downloads send `Authorization: Payment` plus the same Bearers when `?client=` is set.

On `sp-proxy`, Bearer vouchers are ignored unless a requester is present. Requester is taken from `Authorization: Payment` `ClientAddress` when Payment is present; otherwise from `?client=` / the client header. The Payment address is preferred so a spoofed query cannot override the authenticated payer for voucher or owner checks.

`rail-check --voucher` uses the same probe path to discover MPP challenges / payees on private delegated pieces; it does not settle or download. Without a matching voucher, private pieces return 403 and never contribute payees.

## SP pinning (`sp-proxy`)

CDP deal lookup is **always enabled** in `sp-proxy` (public/private piece access cannot be disabled). `--porep-cdp-url` defaults to mainnet `https://cdp.allocator.tech` (empty falls back to that default). `--porep-provider-id` is **required**.

`sp-proxy` **always** pins voucher EIP-712 `chainId` (from the pay RPC) and `verifyingContract` (PoRep Market). Startup fails if the market address cannot be resolved:

- **Mainnet / Calibration:** built-in chain defaults (see `internal/pieceaccess/porep_market.go`).
- **Devnet / other:** set `--porep-market-address` or `SP_PROXY_POREP_MARKET_ADDRESS` / `POREP_MARKET` (FCSS-devnet exports `POREP_MARKET`).

Bearer vouchers are rejected if the authorizer has no domain pin (fail closed).

> **TODO (BIG):** Mainnet and Calibration defaults are **placeholders** until the real PoRep Market deployments are known. Replace `PorepMarketMainnetPlaceholder` / `PorepMarketCalibrationPlaceholder` (and update this note) before relying on production voucher pinning on those networks.
