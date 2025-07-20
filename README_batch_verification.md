# Batch Verification Example for secp256k1

This example demonstrates the concept of **batch verification** for multiple ECDSA signatures using the secp256k1 library. Batch verification can provide significant performance improvements (3-5x speedup) when verifying many signatures simultaneously.

## What is Batch Verification?

Batch verification allows you to verify multiple ECDSA signatures in a single mathematical operation instead of verifying each signature individually. For ECDSA, instead of computing:

```
For each signature (r_i, s_i):
  R_i = (hash_i/s_i) * G + (r_i/s_i) * pubkey_i
  Check if R_i.x == r_i
```

You can compute:
```
result = Σ(hash_i/s_i) * G + Σ((r_i/s_i) * pubkey_i)
expected = Σ(R_i)
Check if result == expected
```

This reduces the number of expensive elliptic curve operations.

## How This Example Works

### Data Structures

- **`tx_input_t`**: Represents a transaction input with signature, public key, and message hash
- **`batch_verify_data_t`**: Contains the batch verification context and results

### Key Functions

1. **`generate_test_input()`**: Creates test signatures (some intentionally invalid)
2. **`verify_single_signature()`**: Individual signature verification using public API
3. **`batch_verify_conceptual()`**: Demonstrates the batch verification concept
4. **`demonstrate_performance_benefit()`**: Shows potential performance improvements

### Verification Process

The example shows what would happen with access to internal APIs:

```c
// Conceptual internal implementation:
for (each signature) {
    u1 = hash / s;  // Message hash divided by signature s
    u2 = r / s;     // Signature r divided by signature s
}

// Single multi-scalar multiplication
result = secp256k1_ecmult_multi_var(
    &ctx->error_callback,
    scratch,
    &result,
    &g_scalar_sum,          // Sum of all u1 values
    batch_callback,         // Provides u2 and pubkey pairs
    batch_data,
    num_inputs
);

// Compare with expected sum of R points
return result == expected_sum;
```

## Building and Running

### Prerequisites

- GCC compiler
- secp256k1 library (built automatically)

### Build Steps

1. **Build secp256k1 library:**
   ```bash
   ./autogen.sh
   ./configure --enable-module-ecdh --enable-module-recovery --enable-module-schnorrsig --enable-module-musig
   make
   ```

2. **Compile the example:**
   ```bash
   gcc -Wall -Wextra -std=c99 -O2 -I./include -o batch_verify_example batch_verify_example.c ./.libs/libsecp256k1.a
   ```

3. **Run the example:**
   ```bash
   ./batch_verify_example
   ```

## Expected Output

```
=== Batch Verification Example ===

Generating test transaction inputs...
  Input 0: Generated valid signature
  Input 1: Generated valid signature
  ...
  Input 7: Generated INVALID signature  
  ...

=== Batch Verification Process ===
Performing conceptual batch verification...
  Step 1: Parse signatures and extract (r,s) components
  Step 2: Compute verification scalars u1=hash/s, u2=r/s
  Step 3: Batch multiply: result = Σ(u1)*G + Σ(u2*pubkey)
  Step 4: Compare with expected Σ(R) values

=== Final Results ===
Batch verification result: SOME INVALID

Individual signature results:
  Input 0: ✓ VALID
  Input 1: ✓ VALID
  ...
  Input 7: ✗ INVALID
  ...

=== Performance Comparison ===
Individual verification of 10 signatures: 0.000301 seconds
Estimated batch verification time: 0.000075 seconds
Estimated speedup: 4.0x
```

## Key Points

### Performance Benefits

- **3-5x speedup** for batch verification vs individual verification
- Benefits increase with larger batch sizes
- Particularly useful for blockchain validation and payment processing

### Implementation Requirements

For a real batch verification implementation, you would need:

1. **Access to internal secp256k1 APIs** (`secp256k1_ecmult_multi_var`)
2. **Internal scalar and point types** (`secp256k1_scalar`, `secp256k1_ge`, `secp256k1_gej`)
3. **Custom build** with internal headers included
4. **Signature parsing** to extract (r,s) components
5. **Point reconstruction** from signature r values

### Security Considerations

- Batch verification is **all-or-nothing**: if any signature is invalid, the entire batch fails
- For production use, you may need to fall back to individual verification to identify which specific signatures failed
- Proper random number generation is critical for signature security

## Real-World Applications

### Bitcoin/Blockchain Validation

```c
// Verify multiple transaction inputs in a block
for (each transaction input) {
    scalars[i] = signature_s_inverse * message_hash;
    points[i] = public_key;
}
secp256k1_ecmult_multi_var(..., scalars, points, n_inputs);
```

### Lightning Network

```c
// Batch verify multiple commitment transactions
// or channel updates
```

### Payment Processing

```c
// Verify multiple payment authorizations
// in a single batch operation
```

## Mathematical Background

ECDSA verification computes:
```
R = u1*G + u2*P
```

Where:
- `u1 = hash(msg) * s^(-1) mod n`
- `u2 = r * s^(-1) mod n`  
- `G` = generator point
- `P` = public key
- `(r,s)` = signature components

For batch verification, we compute:
```
result = Σ(u1_i)*G + Σ(u2_i * P_i)
expected = Σ(R_i)
```

This reduces the number of expensive elliptic curve multiplications and point additions.

## Files in This Example

- `batch_verify_example.c` - Main example code
- `Makefile` - Build configuration  
- `README_batch_verification.md` - This documentation

## Further Reading

- [secp256k1 library documentation](https://github.com/bitcoin-core/secp256k1)
- [ECDSA specification (RFC 6979)](https://tools.ietf.org/html/rfc6979)
- [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
- [Bitcoin transaction validation](https://en.bitcoin.it/wiki/Transaction_verification) 