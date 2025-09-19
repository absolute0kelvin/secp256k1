#ifndef SECP256K1_MODULE_BATCHVERIFY_MAIN_IMPL_H
#define SECP256K1_MODULE_BATCHVERIFY_MAIN_IMPL_H

/*
 * Batch verification (optional module) - detailed documentation
 *
 * Overview
 * --------
 * This module provides a zero-copy batch verification flow for precomputed
 * ECDSA tuples as well as a convenience API to serialize entries into a
 * compact binary format (RDAT v1). Inputs are considered untrusted; the
 * verifier enforces invariant checks before executing a single multi-scalar
 * multiplication (MSM) that ensures all tuples are jointly valid with
 * overwhelming probability.
 *
 * Data model (public API)
 * -----------------------
 * - secp256k1_batch_entry: one tuple per signature containing:
 *   Q65 (uncompressed pubkey), R65 (uncompressed R), r32, s32, z32, v.
 *   All scalars are 32-byte big-endian. v is 1 byte (parity of R.y: 0 even,
 *   1 odd). The r32 MUST equal x(R) mod n; we additionally re-bind and check
 *   this inside verification.
 *
 * Binary wire format (RDAT v1)
 * ----------------------------
 * Header (16 bytes):
 *   - Magic: 'R''D''A''T' (4 bytes)
 *   - Version: 0x00000001 (4 bytes, BE)
 *   - Count: n (8 bytes, BE)
 * Entries (n * 227 bytes):
 *   - Q65 (65)
 *   - R65 (65)
 *   - r32 (32)  [defined as x(R) mod n; serialize derives r from R]
 *   - s32 (32)
 *   - z32 (32)
 *   - v (1)
 *
 * Zero-copy verification path
 * ---------------------------
 * - secp256k1_verify_in_batch_rdat(ctx, in, in_size, multiplier32)
 *   Validates header and expected size, then casts (in+16) to an array of
 *   secp256k1_batch_entry and calls secp256k1_verify_in_batch. This avoids
 *   any memcpy of entries.
 *
 * Invariants enforced before MSM
 * ------------------------------
 * - Q and R are on-curve and not infinity
 * - r != 0, s is canonical (low-S), z is parsed into scalar
 * - r == x(R) mod n (re-binding check, independent of serialized r32)
 * - v matches parity(R.y)
 *
 * MSM equation and security
 * -------------------------
 * We check with random linear combination (a_i derived from multiplier):
 *   (Σ a_i z_i)·G + Σ (a_i r_i)·Q_i + Σ (a_i (-s_i))·R_i = 0
 * If any tuple is invalid, the combined result is non-zero except with
 * negligible probability (~1/n). The caller must provide an unpredictable
 * 32-byte multiplier to derive the a_i sequence.
 *
 * Serialization notes
 * -------------------
 * - secp256k1_recover_data_serialize derives r32 from R65 for consistency.
 * - The zero-copy reader (rdat) therefore never needs to trust an external r32.
 *
 * Lookup helper
 * -------------
 * - secp256k1_lookup_ecrecover_i matches the i-th entry by (r, s, v, z) and
 *   returns Q if it matches. This is suitable for ecrecover-style workflows
 *   that rely on (r, s, v, z) binding without an external pubkey directory.
 *
 * Optional module
 * ---------------
 * The entire functionality is compiled only when ENABLE_MODULE_BATCHVERIFY is
 * defined. Public declarations reside in include/secp256k1_batchverify.h.
 */

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_batchverify.h"
/* Ensure RDAT entry layout matches the struct exactly for zero-copy */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(secp256k1_batch_entry) == 227, "secp256k1_batch_entry must be 227 bytes");
#endif
#include "../../util.h"
#include "../../eckey_impl.h"
#include "../../scalar_impl.h"
#include "../../group_impl.h"
#include "../../ecmult_impl.h"
#include "../../scratch_impl.h"

SECP256K1_API int secp256k1_lookup_ecrecover_i(
    const secp256k1_context* ctx,
    const secp256k1_batch_entry* entries,
    size_t n,
    size_t i,
    const unsigned char r32[32],
    const unsigned char s32[32],
    unsigned char v,
    const unsigned char z32[32],
    unsigned char Q65_out[65]
) {
    int overflow = 0;
    secp256k1_scalar r_in, s_in, z_in, r_ref, s_ref, z_ref;
    (void)ctx;
    if (!entries || !Q65_out || !r32 || !s32 || !z32 || i >= n) return 0;

    secp256k1_scalar_set_b32(&r_in, r32, &overflow); if (overflow || secp256k1_scalar_is_zero(&r_in)) return 0;
    secp256k1_scalar_set_b32(&s_in, s32, &overflow); if (overflow || secp256k1_scalar_is_zero(&s_in)) return 0;
    secp256k1_scalar_set_b32(&z_in, z32, &overflow); if (overflow) return 0;
    secp256k1_scalar_set_b32(&r_ref, entries[i].r32, &overflow);
    secp256k1_scalar_set_b32(&s_ref, entries[i].s32, &overflow);
    secp256k1_scalar_set_b32(&z_ref, entries[i].z32, &overflow);

    if (entries[i].v != (unsigned char)(v ? 1 : 0)) return 0;
    if (!secp256k1_scalar_eq(&r_in, &r_ref)) return 0;
    if (!secp256k1_scalar_eq(&s_in, &s_ref)) return 0;
    if (!secp256k1_scalar_eq(&z_in, &z_ref)) return 0;

    memcpy(Q65_out, entries[i].Q65, 65);
    return 1;
}

SECP256K1_API size_t secp256k1_recover_data_serialized_size(size_t n) {
    return (size_t)16 + n * (size_t)227;
}

SECP256K1_API int secp256k1_recover_data_serialize(
    const secp256k1_context* ctx,
    const secp256k1_batch_entry* entries,
    size_t n,
    unsigned char* out,
    size_t out_size,
    size_t* written
) {
    size_t need;
    size_t offset;
    size_t i;
    secp256k1_ge r_ge;
    secp256k1_fe r_x;
    unsigned char r_xb[32];
    secp256k1_scalar r_scalar;
    unsigned char r_be32[32];
    int ok;
    int of2 = 0;
    (void)ctx;
    if (!entries || !out) return 0;
    need = secp256k1_recover_data_serialized_size(n);
    if (out_size < need) return 0;
    offset = 0;
    out[offset++] = 'R'; out[offset++] = 'D'; out[offset++] = 'A'; out[offset++] = 'T';
    out[offset++] = 0x00; out[offset++] = 0x00; out[offset++] = 0x00; out[offset++] = 0x01;
    out[offset++] = (unsigned char)((n >> 56) & 0xFF);
    out[offset++] = (unsigned char)((n >> 48) & 0xFF);
    out[offset++] = (unsigned char)((n >> 40) & 0xFF);
    out[offset++] = (unsigned char)((n >> 32) & 0xFF);
    out[offset++] = (unsigned char)((n >> 24) & 0xFF);
    out[offset++] = (unsigned char)((n >> 16) & 0xFF);
    out[offset++] = (unsigned char)((n >> 8) & 0xFF);
    out[offset++] = (unsigned char)(n & 0xFF);

    for (i = 0; i < n; i++) {
        memcpy(&out[offset], entries[i].Q65, 65); offset += 65;
        memcpy(&out[offset], entries[i].R65, 65); offset += 65;
        /* Derive r from R65 (ignore entries[i].r32) */
        ok = secp256k1_eckey_pubkey_parse(&r_ge, entries[i].R65, 65);
        if (!ok) return 0;
        r_x = r_ge.x;
        secp256k1_fe_normalize_var(&r_x);
        secp256k1_fe_get_b32(r_xb, &r_x);
        secp256k1_scalar_set_b32(&r_scalar, r_xb, &of2);
        secp256k1_scalar_get_b32(r_be32, &r_scalar);
        memcpy(&out[offset], r_be32, 32); offset += 32;
        memcpy(&out[offset], entries[i].s32, 32); offset += 32;
        memcpy(&out[offset], entries[i].z32, 32); offset += 32;
        out[offset++] = (unsigned char)(entries[i].v ? 1 : 0);
    }
    if (written) *written = offset;
    return 1;
}

/* removed secp256k1_recover_data_deserialize: zero-copy RDAT path supersedes it */

/* Parse RDAT v1 and return a zero-copy view of entries */
SECP256K1_API int secp256k1_rdat_view_parse(
    const unsigned char* in,
    size_t in_len,
    const secp256k1_batch_entry** entries_view_out,
    size_t* n_out
) {
    size_t n2;
    size_t need;
    if (!in || in_len < 16) return 0;
    if (in[0] != 'R' || in[1] != 'D' || in[2] != 'A' || in[3] != 'T') return 0;
    if (!(in[4] == 0x00 && in[5] == 0x00 && in[6] == 0x00 && in[7] == 0x01)) return 0;
    n2 = ((size_t)in[8] << 56) | ((size_t)in[9] << 48) | ((size_t)in[10] << 40) | ((size_t)in[11] << 32) |
         ((size_t)in[12] << 24) | ((size_t)in[13] << 16) | ((size_t)in[14] << 8) | (size_t)in[15];
    need = (size_t)16 + n2 * (size_t)227;
    if (in_len < need) return 0;
    if (entries_view_out) *entries_view_out = (const secp256k1_batch_entry*)(in + 16);
    if (n_out) *n_out = n2;
    return 1;
}

/* Zero-copy verify from RDAT v1 buffer */
SECP256K1_API int secp256k1_verify_in_batch_rdat(
    const secp256k1_context* ctx,
    const unsigned char* in,
    size_t in_size,
    const unsigned char multiplier32[32]
) {
    size_t n;
    size_t need;
    const secp256k1_batch_entry* entries;
    if (!in || in_size < 16) return 0;
    if (in[0] != 'R' || in[1] != 'D' || in[2] != 'A' || in[3] != 'T') return 0;
    if (!(in[4] == 0x00 && in[5] == 0x00 && in[6] == 0x00 && in[7] == 0x01)) return 0;
    n = ((size_t)in[8] << 56) | ((size_t)in[9] << 48) | ((size_t)in[10] << 40) | ((size_t)in[11] << 32) |
        ((size_t)in[12] << 24) | ((size_t)in[13] << 16) | ((size_t)in[14] << 8) | (size_t)in[15];
    need = (size_t)16 + n * (size_t)227;
    if (in_size < need) return 0;
    entries = (const secp256k1_batch_entry*)(in + 16);
    return secp256k1_verify_in_batch(ctx, entries, n, multiplier32);
}

/* ================== Batch verification implementation ================== */

typedef struct {
    const secp256k1_scalar *r_combined;
    const secp256k1_scalar *s_combined;
    const secp256k1_ge *Q_points;
    const secp256k1_ge *R_points;
    size_t num_entries;
} secp256k1_batch_cb_data;

static int secp256k1_batch_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_batch_cb_data *d = (secp256k1_batch_cb_data*)data;
    if (idx < d->num_entries) {
        *sc = d->r_combined[idx];
        *pt = d->Q_points[idx];
        return 1;
    } else if (idx < 2 * d->num_entries) {
        size_t j = idx - d->num_entries;
        *sc = d->s_combined[j];
        *pt = d->R_points[j];
        return 1;
    }
    return 0;
}

SECP256K1_API int secp256k1_verify_in_batch(
    const secp256k1_context* ctx,
    const secp256k1_batch_entry* entries,
    size_t n,
    const unsigned char multiplier32[32]
) {
    int overflow = 0;
    secp256k1_scalar multiplier;
    secp256k1_ge *Q = NULL;
    secp256k1_ge *R = NULL;
    secp256k1_scalar *r = NULL;
    secp256k1_scalar *s = NULL;
    secp256k1_scalar *z = NULL;
    secp256k1_scalar *r_comb = NULL;
    secp256k1_scalar *s_comb = NULL;
    size_t i;
    size_t i2;
    size_t num_terms;
    size_t scratch_size;
    secp256k1_scratch *scratch;
    secp256k1_scalar combined_z;
    unsigned char seed[32] = {0x42};
    secp256k1_scalar seed_scalar;
    secp256k1_scalar a;
    secp256k1_batch_cb_data cbd;
    secp256k1_gej outj;
    int ret;
    int ok;
    (void)ctx;
    if (!entries || n == 0 || !multiplier32) return 0;

    secp256k1_scalar_set_b32(&multiplier, multiplier32, &overflow);
    if (overflow) return 0;

    Q = (secp256k1_ge*)checked_malloc(&default_error_callback, n * sizeof(*Q));
    R = (secp256k1_ge*)checked_malloc(&default_error_callback, n * sizeof(*R));
    r = (secp256k1_scalar*)checked_malloc(&default_error_callback, n * sizeof(*r));
    s = (secp256k1_scalar*)checked_malloc(&default_error_callback, n * sizeof(*s));
    z = (secp256k1_scalar*)checked_malloc(&default_error_callback, n * sizeof(*z));
    r_comb = (secp256k1_scalar*)checked_malloc(&default_error_callback, n * sizeof(*r_comb));
    s_comb = (secp256k1_scalar*)checked_malloc(&default_error_callback, n * sizeof(*s_comb));
    if (!Q || !R || !r || !s || !z || !r_comb || !s_comb) {
        free(Q); free(R); free(r); free(s); free(z); free(r_comb); free(s_comb);
        return 0;
    }

    for (i = 0; i < n; i++) {
        if (!secp256k1_eckey_pubkey_parse(&Q[i], entries[i].Q65, 65)) { overflow = 1; break; }
        if (!secp256k1_eckey_pubkey_parse(&R[i], entries[i].R65, 65)) { overflow = 1; break; }
        if (!secp256k1_ge_is_valid_var(&Q[i]) || secp256k1_ge_is_infinity(&Q[i])) { overflow = 1; break; }
        if (!secp256k1_ge_is_valid_var(&R[i]) || secp256k1_ge_is_infinity(&R[i])) { overflow = 1; break; }
        {
            unsigned char yb[32];
            int y_is_odd;
            secp256k1_fe y = R[i].y;
            secp256k1_fe_normalize_var(&y);
            secp256k1_fe_get_b32(yb, &y);
            y_is_odd = (yb[31] & 1);
            if ((entries[i].v ? 1 : 0) != y_is_odd) { overflow = 1; break; }
        }
        secp256k1_scalar_set_b32(&r[i], entries[i].r32, &overflow); if (overflow || secp256k1_scalar_is_zero(&r[i])) { overflow = 1; break; }
        secp256k1_scalar_set_b32(&s[i], entries[i].s32, &overflow); if (overflow || secp256k1_scalar_is_zero(&s[i]) || secp256k1_scalar_is_high(&s[i])) { overflow = 1; break; }
        secp256k1_scalar_set_b32(&z[i], entries[i].z32, &overflow); if (overflow) { overflow = 1; break; }
        {
            secp256k1_fe x; unsigned char xb[32]; secp256k1_scalar r_from_R; int of2 = 0;
            x = R[i].x;
            secp256k1_fe_normalize_var(&x); secp256k1_fe_get_b32(xb, &x); secp256k1_scalar_set_b32(&r_from_R, xb, &of2);
            if (!secp256k1_scalar_eq(&r_from_R, &r[i])) { overflow = 1; break; }
        }
    }
    if (overflow) {
        for (i2 = 0; i2 < n; i2++) { secp256k1_scalar_clear(&r[i2]); secp256k1_scalar_clear(&s[i2]); secp256k1_scalar_clear(&z[i2]); }
        free(Q); free(R); free(r); free(s); free(z); free(r_comb); free(s_comb);
        return 0;
    }

    num_terms = 2 * n;
    if (num_terms >= ECMULT_PIPPENGER_THRESHOLD) {
        int bucket_window = secp256k1_pippenger_bucket_window(num_terms);
        scratch_size = secp256k1_pippenger_scratch_size(num_terms * 2, bucket_window);
    } else {
        scratch_size = secp256k1_strauss_scratch_size(num_terms) + STRAUSS_SCRATCH_OBJECTS * 16;
    }
    scratch = secp256k1_scratch_create(&default_error_callback, scratch_size);
    if (!scratch) {
        for (i = 0; i < n; i++) { secp256k1_scalar_clear(&r[i]); secp256k1_scalar_clear(&s[i]); secp256k1_scalar_clear(&z[i]); }
        free(Q); free(R); free(r); free(s); free(z); free(r_comb); free(s_comb);
        return 0;
    }

    secp256k1_scalar_set_int(&combined_z, 0);
    secp256k1_scalar_set_b32(&seed_scalar, seed, &overflow);
    a = seed_scalar; secp256k1_scalar_mul(&a, &a, &multiplier);
    for (i = 0; i < n; i++) {
        secp256k1_scalar tmp;
        secp256k1_scalar_mul(&tmp, &z[i], &a); secp256k1_scalar_add(&combined_z, &combined_z, &tmp);
        secp256k1_scalar_mul(&r_comb[i], &r[i], &a);
        secp256k1_scalar_negate(&tmp, &s[i]); secp256k1_scalar_mul(&s_comb[i], &tmp, &a);
        if (i + 1 < n) secp256k1_scalar_mul(&a, &a, &multiplier);
    }

    cbd.r_combined = r_comb; cbd.s_combined = s_comb; cbd.Q_points = Q; cbd.R_points = R; cbd.num_entries = n;
    ret = secp256k1_ecmult_multi_var(&default_error_callback, scratch, &outj, &combined_z, secp256k1_batch_ecmult_callback, &cbd, num_terms);
    ok = (ret && secp256k1_gej_is_infinity(&outj)) ? 1 : 0;

    secp256k1_scalar_clear(&combined_z); secp256k1_scalar_clear(&seed_scalar); secp256k1_scalar_clear(&a);
    for (i = 0; i < n; i++) { secp256k1_scalar_clear(&r[i]); secp256k1_scalar_clear(&s[i]); secp256k1_scalar_clear(&z[i]); secp256k1_scalar_clear(&r_comb[i]); secp256k1_scalar_clear(&s_comb[i]); }
    secp256k1_scratch_destroy(&default_error_callback, scratch);
    free(Q); free(R); free(r); free(s); free(z); free(r_comb); free(s_comb);
    return ok;
}

#endif /* SECP256K1_MODULE_BATCHVERIFY_MAIN_IMPL_H */


