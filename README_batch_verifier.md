# Batch ECDSA Signature Verification with secp256k1

This repository contains `batch_verifier.c`, a comprehensive demonstration of ECDSA signature batch verification using the secp256k1 cryptographic library. The program showcases advanced cryptographic techniques for efficiently verifying multiple signatures simultaneously.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Batch Verification Deep Dive](#batch-verification-deep-dive)
- [Performance Analysis](#performance-analysis)
- [Mathematical Foundation](#mathematical-foundation)
- [Usage](#usage)
- [Implementation Details](#implementation-details)
- [Security Considerations](#security-considerations)

## Overview

The batch verifier demonstrates three different approaches to ECDSA signature verification:

1. **Standard Verification** (`verify_sig_one_by_one`) - Using secp256k1's built-in verification
2. **Manual Formula Verification** (`verify_one_by_one`) - Direct implementation of the ECDSA equation
3. **Batch Verification** (`verify_in_batch`) - Optimized batch processing using random linear combinations

The program generates cryptographically secure test data, recovers all signature components, and benchmarks the performance of each verification method.

## Key Features

- **Complete ECDSA Lifecycle**: Key generation, signing, recovery, and verification
- **Cross-Platform Security**: Secure random number generation for all supported platforms
- **Memory-Optimized Design**: Flat array structures for optimal cache performance
- **Comprehensive Validation**: Mathematical verification of all cryptographic components
- **Performance Benchmarking**: Real-time comparison of verification methods
- **Recovery Demonstration**: Complete component recovery from signatures and messages

## Batch Verification Deep Dive

### What `verify_in_batch` Does

The `verify_in_batch` function verifies multiple ECDSA signatures simultaneously using a mathematical technique called **random linear combination**. Instead of verifying each signature individually, it combines all signatures into a single mathematical equation that proves the validity of the entire batch.

### Mathematical Foundation

**Standard ECDSA Verification (per signature):**
```
For signature (r, s) on message hash z with public key Q:
1. Compute u₁ = z × s⁻¹ mod n
2. Compute u₂ = r × s⁻¹ mod n  
3. Compute point (x, y) = u₁×G + u₂×Q
4. Signature is valid if x ≡ r (mod n)
```

**Batch Verification Formula:**
```
For signatures {(rᵢ, sᵢ, zᵢ, Qᵢ)} where i = 1 to n:
1. Generate random coefficients {aᵢ} for i = 1 to n
2. Compute: (Σ zᵢ × aᵢ) × G + Σ (rᵢ × aᵢ × Qᵢ) + Σ ((-sᵢ) × aᵢ × Rᵢ) = O
3. All signatures are valid if the result equals the point at infinity (O)
```

Where:
- `G` is the secp256k1 generator point
- `Qᵢ` is the public key for signature i
- `Rᵢ` is the recovered R point for signature i
- `aᵢ` are cryptographically secure random coefficients
- `O` is the point at infinity (zero element)

### Why Batch Verification is Correct

The mathematical foundation relies on the **linearity of elliptic curve operations**:

1. **Individual Verification**: Each valid signature satisfies `zᵢ×G + rᵢ×Qᵢ - sᵢ×Rᵢ = O`
2. **Linear Combination**: If we multiply each equation by a random coefficient `aᵢ` and sum them:
   ```
   Σ aᵢ × (zᵢ×G + rᵢ×Qᵢ - sᵢ×Rᵢ) = Σ aᵢ × O = O
   ```
3. **Distributive Property**: This expands to:
   ```
   (Σ zᵢ×aᵢ)×G + Σ (rᵢ×aᵢ×Qᵢ) + Σ ((-sᵢ)×aᵢ×Rᵢ) = O
   ```

**Security**: The random coefficients prevent **Wagner's attack** and other forgery attempts that could fool naive batch verification. An attacker cannot predict the random coefficients, making it cryptographically infeasible to create forgeries that pass batch verification.

### Performance Analysis

Based on benchmarks with 5,000 and 10,000 signatures:

#### 5,000 Signatures Performance:
| Method | Total Time | Time per Signature | Speedup vs Standard |
|--------|------------|-------------------|-------------------|
| `verify_sig_one_by_one` (Standard) | 63.18 ms | 0.01264 ms | 1.0× (baseline) |
| `verify_one_by_one` (Manual) | 82.21 ms | 0.01644 ms | 0.77× (23% slower) |
| `verify_in_batch` (Batch) | **24.02 ms** | **0.00481 ms** | **2.63× faster** |

#### 10,000 Signatures Performance:
| Method | Total Time | Time per Signature | Speedup vs Standard |
|--------|------------|-------------------|-------------------|
| `verify_sig_one_by_one` (Standard) | 125.66 ms | 0.01257 ms | 1.0× (baseline) |
| `verify_one_by_one` (Manual) | 165.21 ms | 0.01652 ms | 0.76× (24% slower) |
| `verify_in_batch` (Batch) | **42.88 ms** | **0.00429 ms** | **2.93× faster** |

#### Key Performance Insights:

1. **Batch verification is ~3× faster** than standard verification
2. **Performance scales excellently** - the speedup increases with batch size
3. **Consistent per-signature timing** - shows excellent algorithmic efficiency
4. **Memory efficiency** - Uses optimized multi-scalar multiplication algorithms

### Why Batch Verification is Faster

1. **Reduced Elliptic Curve Operations**: Instead of n individual point multiplications, performs one large multi-scalar multiplication
2. **Optimized Algorithms**: Uses Pippenger's algorithm for large batches (≥50 terms) and Strauss algorithm for smaller batches
3. **Cache Efficiency**: Flat array structures optimize memory access patterns
4. **Amortized Costs**: Setup costs are amortized across all signatures in the batch

## Usage

### Compilation
```bash
make -f Makefile_batch_verifier
```

### Running the Program
```bash
# Default: 1,000 signatures
./batch_verifier

# Custom number of signatures
./batch_verifier 5000
./batch_verifier 10000
```

### Example Output
```
=== Performance Comparison ===
Testing 5000 signatures...

1. Testing verify_sig_one_by_one (standard ECDSA verification)...
   Result: PASS
   Time: 0.063181 seconds
   Time per signature: 0.012636 ms

2. Testing verify_one_by_one (z*G + r*Q - s*R = 0 formula)...
   Result: PASS
   Time: 0.082205 seconds
   Time per signature: 0.016441 ms

3. Testing verify_in_batch (batch verification with random coefficients)...
   Result: PASS
   Time: 0.024024 seconds
   Time per signature: 0.004805 ms
```

## Implementation Details

### Data Structures

- **`test_data_t`**: Holds generated cryptographic test data using flat arrays
- **`recover_data_t`**: Contains recovered signature components as mathematical objects
- **Memory Design**: Optimized for cache locality and minimal fragmentation

### Key Functions

- **`generate_test_data()`**: Creates secure test dataset with private keys, messages, and signatures
- **`recover_components()`**: Extracts and validates all cryptographic components
- **`verify_in_batch()`**: Performs optimized batch verification
- **`sanity_check()`**: Validates all mathematical constraints and curve properties

### Cryptographic Components

1. **Signature Recovery**: Recovers public keys and R points from signatures
2. **Scalar Operations**: Converts byte arrays to mathematical scalars
3. **Point Operations**: Validates curve points and performs multi-scalar multiplication
4. **Random Generation**: Cross-platform cryptographically secure randomness

## Security Considerations

### Strong Security Features

1. **Cryptographically Secure Randomness**: Platform-specific secure random number generation
2. **Wagner Attack Prevention**: Random coefficients prevent batch verification forgeries
3. **Complete Validation**: Comprehensive mathematical verification of all components
4. **Memory Security**: Explicit clearing of sensitive scalar data

### secp256k1-Specific Properties

- **Recovery ID Constraints**: Only values 0 and 1 are produced (never 2 or 3)
- **Canonical Signatures**: All signatures use low-s values (s < n/2)
- **Curve Validation**: All points verified to lie on the secp256k1 curve

## Real-World Applications

Batch verification is particularly valuable for:

- **Blockchain Validation**: Verifying blocks with hundreds or thousands of transactions
- **Payment Processing**: Validating large batches of financial transactions
- **Certificate Validation**: Bulk verification of digital certificates
- **Message Authentication**: Validating signed message batches in secure communications

The ~3× performance improvement makes batch verification essential for high-throughput cryptographic applications requiring ECDSA signature validation.

## Mathematical Verification Example

For a batch of 3 signatures, the verification equation becomes:
```
(z₁×a₁ + z₂×a₂ + z₃×a₃) × G + 
(r₁×a₁×Q₁ + r₂×a₂×Q₂ + r₃×a₃×Q₃) + 
((-s₁)×a₁×R₁ + (-s₂)×a₂×R₂ + (-s₃)×a₃×R₃) = O
```

If this equation equals the point at infinity, all three signatures are mathematically guaranteed to be valid.
