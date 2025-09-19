### verify_in_batch: Target, Assumptions, and Why It Is Safe

This document explains what `verify_in_batch` is designed to do, the assumptions it relies on, and why the procedure is safe under those assumptions.

## Target (What verify_in_batch checks)

Given a set of tuples per entry i:
- `z_i`: message hash as scalar
- `r_i`: x-coordinate of `R_i` as scalar
- `s_i`: signature scalar
- `Q_i`: public key point
- `R_i`: nonce point

`verify_in_batch` checks the batch verification equation using random linear combination, assuming the tuples are supplied by an untrusted party and must be internally consistent:

```
(Σ a_i · z_i) · G + Σ (a_i · r_i) · Q_i + Σ (a_i · (-s_i)) · R_i = 0
```

where `a_i` are per-entry random coefficients, and `G` is the secp256k1 generator. If and only if all entries satisfy the ECDSA verification equation `z_i·G + r_i·Q_i - s_i·R_i = 0`, the sum will evaluate to the point at infinity (with overwhelming probability).

We also compute and store `v_i`, the recovery flag, as the parity of `R_i.y` (0 for even, 1 for odd). This allows downstream callers to match Ethereum-style `ecrecover` inputs `(r, s, v, z)` against the batch-validated tuples and return the corresponding `Q` when they match.

## Inputs and invariants we enforce

Before running the batch equation, `sanity_check` enforces that for each entry (even though inputs are untrusted):
- `R_i` and `Q_i` are on the curve and not the point at infinity.
- `s_i` is in canonical (low-S) form, `1 ≤ s_i < n/2`.
- `r_i` is nonzero and a valid scalar, `1 ≤ r_i < n`.
- Binding: `r_i == x(R_i) mod n`.

These invariants ensure the tuple components are self-consistent and mathematically valid on secp256k1. During `verify_in_batch`, we fill `recovery_flags[i] = parity(R_i.y)` so callers can use it as `v_i`.

## Assumptions

- We do not have an external trusted source of public keys. Therefore, the goal is to verify that each provided tuple `(Q_i, R_i, r_i, s_i, z_i)` is internally consistent with ECDSA, not that `Q_i` matches some external identity.
- The batch coefficients `a_i` are derived from a secret/unpredictable `multiplier` provided to `verify_in_batch`. The adversary should not be able to choose or adapt entries after learning the `a_i` values.
- The `recover_data` container is untrusted input, but is validated by `sanity_check` before use.

## Why batch verification is safe

- Soundness (per-entry invalidity is caught): If any entry fails the ECDSA equation, the combined sum will be nonzero except with negligible probability. With random, independent coefficients modulo the curve order `n`, the chance that invalid terms cancel out coincidentally is at most about `1/n` (≈ 2⁻²⁵⁶), which is cryptographically negligible.
- Forgery resistance against crafted cancellations: Random coefficients prevent an attacker from arranging cross-entry cancellations unless they know the coefficients in advance. Our API requires a caller-supplied unpredictable `multiplier`, which is expanded into the `a_i` sequence inside the function, ensuring the adversary cannot prearrange cancellations.
- Internal consistency is enforced: `sanity_check` binds `r_i` to `R_i` via `r_i = x(R_i) mod n` and ensures all points/scalars are valid. This blocks simple malformed-input attacks.

## What this does not claim

- Identity binding: We do not assert that `Q_i` matches a specific external identity or an external public key. If you require identity binding, you must compare `Q_i` to a trusted source outside this function.
- Per-entry proof output: We do not produce per-entry pass/fail; the batch returns a single boolean for the set. If you need per-entry diagnostics, use the one-by-one verifier.

## Caller responsibilities

- Provide a fresh, unpredictable `multiplier` for each batch to derive the `a_i`. If an attacker can predict or influence `a_i` before committing entries, they may increase the probability of undetected cancellation.
- If you need to bind to known public keys, compare each `Q_i` to your expected keys prior to or after calling `verify_in_batch`.
- When implementing `ecrecover` plumbing, perform a lookup by `(r, s, v, z)` against the prevalidated set and return the associated `Q`.

## In-place updates

For performance, the implementation overwrites `r_values[i]` and `s_values[i]` with the combined terms `(a_i·r_i)` and `(a_i·(-s_i))` during batch setup. Do not reuse `recover_data` for other purposes after `verify_in_batch` unless you reconstruct these arrays.

## Summary

- Goal: Efficiently verify many ECDSA tuples for internal consistency in a single equation.
- Safety comes from: (1) strict on-curve/range checks and `r ↔ x(R)` binding; (2) random linear combination with unpredictable `a_i`, which makes cross-entry cancellation attacks negligibly probable.
- Scope: Consistency-only. External identity binding, if needed, must be layered on top by the caller.


## End-to-end workflow (untrusted tuples → ecrecover)

1) Receive untrusted precomputed tuples
- Inputs per entry i: `(r_i, s_i, z_i, Q_i, R_i)`.
- Goal: validate these tuples for internal ECDSA consistency and make them queryable via `(r, s, v, z)`.

2) Compute v and enforce invariants
- Compute `v_i := parity(R_i.y)` and store it (we expose this as `recovery_flags[i]`).
- Run `sanity_check` on all entries to ensure:
  - `Q_i`, `R_i` are on-curve and not infinity.
  - `r_i != 0`, `s_i` is low (`s_i < n/2`).
  - Binding `r_i == x(R_i) mod n`.

3) Batch-check consistency of Q and R with r, s, z
- Run `verify_in_batch` with random coefficients `a_i` to check
  `(Σ a_i·z_i)·G + Σ (a_i·r_i)·Q_i + Σ (a_i·(-s_i))·R_i = 0`.
- If the sum equals the point at infinity, then with overwhelming probability each tuple satisfies `z_i·G + r_i·Q_i − s_i·R_i = 0`.

4) Serve ecrecover queries
- For an ecrecover request `(r, s, v, z)` at a specific index `i`:
  - Check the i-th entry only: `(r_i == r, s_i == s, v_i == v, z_i == z)`.
  - If it matches (and the batch verification above has succeeded), return `Q_i`.
  - Otherwise, reject the request for index `i`.

Minimal pseudo-API
```c
// After verify_in_batch succeeds:
// lookup_ecrecover(i, r, s, v, z) checks only entry i → Q | NULL
// r, s, z are 32-byte big-endian values
const secp256k1_ge* lookup_ecrecover(
    const recover_data_t* rd,
    size_t i,
    const unsigned char r_be32[32],
    const unsigned char s_be32[32],
    unsigned char v,
    const unsigned char z_be32[32]
);
```

Operational notes
- Use a fresh, unpredictable multiplier per batch to derive `a_i`.
- Store `(r, s, v, z) → index` for O(1) lookups, or scan linearly if the set is small.
- If identity binding is required, additionally check the looked-up `Q` against your trusted directory of keys.


