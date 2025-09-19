/*
 * Copyright (c) 2025
 *
 * Optional batch verification API for precomputed ECDSA tuples.
 *
 * This module is EXPERIMENTAL/OPTIONAL. It verifies sets of tuples (r,s,z,Q,R)
 * supplied by an untrusted party using random linear combination, and supports
 * looking up Q by (r,s,v,z) for ecrecover-style workflows.
 */

#ifndef SECP256K1_BATCHVERIFY_H
#define SECP256K1_BATCHVERIFY_H

#include <stddef.h>
#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One precomputed tuple (all big-endian encodings) */
typedef struct {
    unsigned char Q65[65];     /* uncompressed pubkey */
    unsigned char R65[65];     /* uncompressed R */
    unsigned char r32[32];
    unsigned char s32[32];
    unsigned char z32[32];
    unsigned char v;           /* 0 even, 1 odd */
} secp256k1_batch_entry;

/* Zero-copy batch verify from RDAT v1 buffer. Validates header and size, then
 * treats the per-entry region as an array of secp256k1_batch_entry without copying.
 */
SECP256K1_API int secp256k1_verify_in_batch_rdat(
    const secp256k1_context* ctx,
    const unsigned char* in,
    size_t in_size,
    const unsigned char* multiplier32
);

/* Parse RDAT v1 and return a zero-copy view of entries. Validates magic,
 * version, and size. Returns 1 on success and sets outputs, 0 on failure.
 * Note: This function does not require a context.
 */
SECP256K1_API int secp256k1_rdat_view_parse(
    const unsigned char* in,
    size_t in_len,
    const secp256k1_batch_entry** entries_view_out,
    size_t* n_out
);

/* Batch verify: returns 1 if all entries pass, 0 otherwise. */
SECP256K1_API int secp256k1_verify_in_batch(
    const secp256k1_context* ctx,
    const secp256k1_batch_entry* entries,
    size_t n,
    const unsigned char* multiplier32
);

/* Lookup the i-th entry by (r,s,v,z); writes Q65 on success, returns 1/0. */
SECP256K1_API int secp256k1_lookup_ecrecover_i(
    const secp256k1_batch_entry* entries,
    size_t n,
    size_t i,
    const unsigned char r32[32],
    const unsigned char s32[32],
    unsigned char v,
    const unsigned char z32[32],
    unsigned char Q65_out[65]
);

/* Serialization size for n entries in RDAT v1 format. */
SECP256K1_API size_t secp256k1_recover_data_serialized_size(size_t n);

/* Serialize/deserialize arrays of entries to/from the RDAT v1 format. */
SECP256K1_API int secp256k1_recover_data_serialize(
    const secp256k1_context* ctx,
    const secp256k1_batch_entry* entries,
    size_t n,
    unsigned char* out,
    size_t out_size,
    size_t* written
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_BATCHVERIFY_H */


