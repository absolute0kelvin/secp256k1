# Schnorr Signature Batch Verification

A high-performance implementation of batch verification for BIP-340 Schnorr signatures using the secp256k1 library.

## Table of Contents

- [Overview](#overview)
- [What is Batch Verification?](#what-is-batch-verification)
- [Mathematical Foundation](#mathematical-foundation)
- [Why Our Method is Correct](#why-our-method-is-correct)
- [Performance Results](#performance-results)
- [Implementation Details](#implementation-details)
- [Usage](#usage)
- [Building](#building)
- [Technical Details](#technical-details)

## Overview

This implementation provides **up to 3x faster** Schnorr signature verification when processing multiple signatures simultaneously. Instead of verifying each signature individually, batch verification processes all signatures in a single cryptographic operation.

**Key Features:**
- ✅ **BIP-340 Compatible**: Full support for Bitcoin Taproot Schnorr signatures
- ✅ **Memory Optimized**: Flat array structures for optimal cache performance  
- ✅ **Cryptographically Secure**: Uses random linear combinations to prevent forgery attacks
- ✅ **Performance Tested**: Real-world benchmarks showing significant speedup

## What is Batch Verification?

Batch verification is a cryptographic technique that allows verifying multiple signatures simultaneously rather than one-by-one. Instead of performing `n` separate verification operations, batch verification combines all signatures into a single mathematical equation.

### Traditional Approach (Individual Verification)
```
For each signature (R_i, s_i) with public key P_i and message m_i:
  1. Compute e_i = H(R_i || P_i || m_i)
  2. Check: s_i * G = R_i + e_i * P_i
```

### Batch Verification Approach
```
For all signatures simultaneously:
  1. Generate random coefficients a_i
  2. Check: (Σ s_i * a_i) * G = Σ a_i * R_i + Σ (e_i * a_i) * P_i
```

## Mathematical Foundation

### Schnorr Verification Equation

Each Schnorr signature satisfies: **s*G = R + e*P**

Where:
- `s`: signature scalar component
- `G`: secp256k1 generator point
- `R`: signature point component  
- `e`: challenge hash `e = H(R || P || m)`
- `P`: public key point
- `m`: message being signed

### Batch Verification Formula

We rearrange the verification equation to: **s*G - e*P - R = 0** (point at infinity)

For batch verification with random coefficients `a_i`:

```
Σ (s_i * a_i) * G - Σ (e_i * a_i) * P_i - Σ a_i * R_i = 0
```

This can be computed efficiently using multi-scalar multiplication:
- **Generator term**: `(Σ s_i * a_i) * G`
- **Public key terms**: `Σ ((-e_i) * a_i) * P_i`  
- **R point terms**: `Σ ((-a_i) * R_i)`

## Why Our Method is Correct

### 1. Mathematical Equivalence
If all individual signatures are valid, the batch equation will equal the point at infinity. If any signature is invalid, the result will be a non-infinity point with overwhelming probability.

### 2. Forgery Prevention
The random coefficients `a_i` prevent attackers from crafting fake signatures that pass batch verification. Without knowing the random coefficients in advance, an attacker cannot create forgeries that satisfy the combined equation.

### 3. BIP-340 Compliance
Our implementation correctly computes challenges using BIP-340 tagged hashes:
```c
tagged_hash("BIP0340/challenge", R_x || P_x || m)
```

This ensures compatibility with Bitcoin Taproot and other BIP-340 implementations.

### 4. Cryptographic Security
The verification relies on the discrete logarithm problem in secp256k1, the same assumption underlying individual Schnorr signature security.

## Performance Results

### Benchmarked on 100 Schnorr signatures:

| Method | Time per Signature | Relative Speed |
|--------|-------------------|----------------|
| Standard `secp256k1_schnorrsig_verify` | 0.019880 ms | 1.00x (baseline) |
| Individual `s*G - e*P - R = 0` | 0.019990 ms | 0.99x |
| **Batch Verification** | **0.011070 ms** | **1.80x faster** |

### Benchmarked on 1000 Schnorr signatures:

| Method | Time per Signature | Relative Speed |
|--------|-------------------|----------------|
| Standard `secp256k1_schnorrsig_verify` | 0.013690 ms | 1.00x (baseline) |
| Individual `s*G - e*P - R = 0` | 0.013917 ms | 0.98x |
| **Batch Verification** | **0.005569 ms** | **2.46x faster** |

### Benchmarked on 10,000 Schnorr signatures:

| Method | Time per Signature | Relative Speed |
|--------|-------------------|----------------|
| Standard `secp256k1_schnorrsig_verify` | 0.012771 ms | 1.00x (baseline) |
| Individual `s*G - e*P - R = 0` | 0.012954 ms | 0.99x |
| **Batch Verification** | **0.004171 ms** | **3.06x faster** |

### Speedup Analysis
- **3.06x faster** than standard verification at 10,000 signatures
- **Excellent scalability**: larger batches achieve dramatically better performance
- **Sweet spot**: Performance gains continue increasing substantially with larger batch sizes

### Scalability Demonstration

The performance improvement scales with batch size, demonstrating the true power of batch verification:

| Batch Size | Standard Verification (ms/sig) | Batch Verification (ms/sig) | Speedup Factor |
|------------|-------------------------------|---------------------------|---------------|
| 100 signatures | 0.019880 | 0.011070 | **1.80x** |
| 1000 signatures | 0.013690 | 0.005569 | **2.46x** |
| 10,000 signatures | 0.012771 | 0.004171 | **3.06x** |

**Key Insight**: Larger batches show dramatically better performance gains, making this technique especially valuable for applications processing many signatures simultaneously (blockchain validation, certificate verification, etc.). The speedup continues to improve with larger batch sizes!

### Real Performance Output (10,000 signatures)
```
=== Schnorr Performance Comparison ===
Testing 10000 Schnorr signatures...

1. Testing schnorr_verify_sig_one_by_one (standard Schnorr verification)...
   Result: PASS
   Time: 0.127713 seconds
   Time per signature: 0.012771 ms

2. Testing schnorr_verify_one_by_one (s*G - e*P - R = 0 formula)...
   Result: PASS
   Time: 0.129542 seconds
   Time per signature: 0.012954 ms

3. Testing schnorr_verify_in_batch (batch verification with random coefficients)...
   Result: PASS
   Time: 0.041711 seconds
   Time per signature: 0.004171 ms
```

**Performance Highlight**: Batch verification completed 10,000 signatures in just **0.04 seconds** compared to **0.13 seconds** for individual verification - that's a **3.06x speedup**!

## Implementation Details

### Memory Layout
The implementation uses flat arrays for optimal memory access patterns:

```c
typedef struct {
    size_t num_entries;
    secp256k1_ge *public_key_points;    // Array of public keys as group elements
    secp256k1_scalar *s_values;        // Array of signature 's' values as scalars
    secp256k1_scalar *e_values;        // Array of challenge hashes as scalars
    secp256k1_ge *r_points;            // Array of signature R points
} schnorr_recover_data_t;
```

### Key Functions

1. **`schnorr_extract_components`**: Extracts and validates all cryptographic components
2. **`schnorr_verify_in_batch`**: Performs batch verification using random linear combinations
3. **`bip340_tagged_hash`**: Implements BIP-340 tagged hash for challenge computation

### Algorithm Flow

1. **Generate Test Data**: Create Schnorr signatures using `secp256k1_schnorrsig_sign32`
2. **Extract Components**: Parse signatures and compute challenges with BIP-340 tagged hash
3. **Validate Components**: Ensure all points are on curve and scalars are valid
4. **Batch Verify**: Use multi-scalar multiplication to verify all signatures simultaneously

## Usage

### Command Line
```bash
# Compile the program
make -f Makefile_batch_verifier local SOURCE=batch_verifier_schnorr.c TARGET=batch_verifier_schnorr

# Run with default 1000 signatures
./batch_verifier_schnorr

# Run with custom number of signatures
./batch_verifier_schnorr 5000
```

### Programming Interface

```c
// Generate test data
schnorr_test_data_t *test_data = generate_schnorr_test_data(num_signatures);

// Extract cryptographic components
schnorr_recover_data_t *recover_data = schnorr_extract_components(test_data);

// Perform batch verification
secp256k1_scalar multiplier;
// ... initialize multiplier ...
int result = schnorr_verify_in_batch(recover_data, &multiplier);

// Clean up
free_schnorr_recover_data(recover_data);
free_schnorr_test_data(test_data);
```

## Building

### Prerequisites
- GCC or Clang compiler
- secp256k1 library (included in repository)
- POSIX-compliant system (Linux, macOS, BSD)

### Compilation
```bash
# Using the provided Makefile
make -f Makefile_batch_verifier local SOURCE=batch_verifier_schnorr.c TARGET=batch_verifier_schnorr

# Manual compilation
gcc -O2 -Wall -Wextra -std=c99 -I. -I./include -I./src -DHAVE_CONFIG_H \
    batch_verifier_schnorr.c -L. -lsecp256k1 -o batch_verifier_schnorr
```

## Technical Details

### BIP-340 Tagged Hash Implementation
```c
static void bip340_tagged_hash(unsigned char *output, const char *tag, size_t tag_len, 
                               const unsigned char *msg, size_t msg_len) {
    secp256k1_sha256 sha;
    unsigned char tag_hash[32];
    
    // Compute SHA256(tag)
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, (const unsigned char*)tag, tag_len);
    secp256k1_sha256_finalize(&sha, tag_hash);
    
    // Compute SHA256(tag_hash || tag_hash || msg)
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, tag_hash, 32);
    secp256k1_sha256_write(&sha, tag_hash, 32);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, output);
}
```

### Multi-Scalar Multiplication
The implementation uses `secp256k1_ecmult_multi_var` which automatically selects:
- **Strauss algorithm** for smaller batches (< 88 points)
- **Pippenger algorithm** for larger batches (≥ 88 points)

### Security Features
- **Random coefficient generation** using cryptographically secure RNG
- **Input validation** ensuring all points are on curve
- **Memory clearing** for sensitive scalar values
- **Overflow handling** for challenge hash computation

### Memory Usage
For `n` signatures:
- **Input data**: ~180 bytes per signature (keys, messages, signatures)
- **Extracted components**: ~240 bytes per signature (scalars and points)
- **Total memory**: ~420 bytes per signature

**Real Memory Usage Examples:**
- 100 signatures: ~42 KB total memory
- 1,000 signatures: ~420 KB total memory
- 10,000 signatures: ~4.2 MB total memory

The memory usage scales linearly and remains very reasonable even for large batches.

## Limitations and Considerations

1. **All-or-nothing**: Batch verification only tells you if ALL signatures are valid, not which specific signatures might be invalid
2. **Memory usage**: Scales linearly with batch size
3. **Preprocessing cost**: Component extraction has upfront cost, beneficial for larger batches

## References

- [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [Batch Verification of Digital Signatures](https://www.iacr.org/archive/asiacrypt2007/48330347/48330347.pdf)
- [secp256k1 Library Documentation](https://github.com/bitcoin-core/secp256k1)

## License

This implementation follows the same license as the secp256k1 library. 