# EIP-3074 AUTH / AUTHCALL Simulator

A pure-Python simulator of [EIP-3074](https://eips.ethereum.org/EIPS/eip-3074):
sponsored transactions where an EOA delegates control of its account to an
*invoker* contract for a single transaction.

## How it works

1. **Authorize (off-chain).** The EOA signs a commit over
   `keccak256(0x03 || chain_id || nonce || invoker)` — the `0x03` magic byte,
   the chain id (replay protection across chains) and a one-time nonce
   (replay protection within a chain).
2. **AUTH.** The invoker presents the signature; the chain recovers the
   signer with `ecrecover`, checks it matches the EOA, consumes the nonce,
   and records the invoker as authorized for this transaction only.
3. **AUTHCALL.** The authorized invoker calls contracts or sends ETH *as*
   the EOA, spending the EOA's balance. The invoker pays the gas, so the EOA
   never needs ETH for fees — this is the sponsored-transaction pattern.
4. **End of transaction.** The authorization is wiped. Nothing persists to
   the next transaction.

## What's inside

- Self-contained **Keccak-256** (verified against the empty / `"abc"` vectors)
  and **secp256k1** sign / `ecrecover` (RFC 6979 deterministic nonces, low-S)
- **EIP-55** checksummed addresses
- `Chain` — accounts, a contract registry, and the per-transaction AUTH frame
- `SimpleStore` — a toy target contract used by the demo
- Attack cases in the demo: **signature replay** (same nonce) and
  **cross-chain replay** (signed for chain 1, tried on chain 137) — both rejected

## Run it

```bash
python3 eip3074.py --demo   # sponsored transaction + replay attacks
python3 eip3074.py --test   # doctests
```

No dependencies, no network access. Python 3.8+.

## Demo output (abridged)

```
Alice (EOA): 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
AUTH: True
AUTHCALL set(42): (True, 42)
AUTHCALL send 0.1 ETH to Bob: (True, 100000000000000000)
Replay attack: same signature, same nonce...
AUTH (replayed): False
Wrong-chain authorization (signed for chain 1, replayed on 137)...
AUTH on chain 137: False
```

## Why EIP-3074 matters

It is the predecessor to EIP-7702 (which shipped in the Pectra upgrade):
same idea — let EOAs act like smart-contract wallets for one transaction —
but via a trusted invoker instead of setting delegation code on the account.
Batching, gas sponsorship, and custom validity logic (e.g. social recovery,
spending limits enforced by the invoker) all become possible without
migrating funds to a new wallet.
