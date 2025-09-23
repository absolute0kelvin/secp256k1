
/* One precomputed tuple (all big-endian encodings) */
typedef struct {
    unsigned char Q65[65];     /* uncompressed pubkey */
    unsigned char R65[65];     /* uncompressed R */
    unsigned char r32[32];
    unsigned char s32[32];
    unsigned char z32[32];
    unsigned char v;           /* 0 even, 1 odd */
} secp256k1_batch_entry;

/* Return codes for secp256k1_verify_in_batch */
#define SECP256K1_BATCHVERIFY_OK                        1
#define SECP256K1_BATCHVERIFY_ERR_INVALID_ARGS         -1
#define SECP256K1_BATCHVERIFY_ERR_QR_PARSE_OR_INVALID  -2
#define SECP256K1_BATCHVERIFY_ERR_V_MISMATCH           -3
#define SECP256K1_BATCHVERIFY_ERR_R_SCALAR             -4
#define SECP256K1_BATCHVERIFY_ERR_S_SCALAR             -5
#define SECP256K1_BATCHVERIFY_ERR_Z_SCALAR             -6
#define SECP256K1_BATCHVERIFY_ERR_R_BINDING            -7
#define SECP256K1_BATCHVERIFY_ERR_ALLOC                -8
#define SECP256K1_BATCHVERIFY_ERR_SCRATCH              -9
#define SECP256K1_BATCHVERIFY_ERR_ECMULT               -10
#define SECP256K1_BATCHVERIFY_ERR_NOT_INFINITY         -11

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

//static secp256k1_scratch* secp256k1_scratch_create(const secp256k1_callback* error_callback, size_t size) {
//    const size_t base_alloc = ROUND_TO_ALIGN(sizeof(secp256k1_scratch));
//    void *alloc = checked_malloc(error_callback, base_alloc + size);
//    secp256k1_scratch* ret = (secp256k1_scratch *)alloc;
//    if (ret != NULL) {
//        memset(ret, 0, sizeof(*ret));
//        memcpy(ret->magic, "scratch", 8);
//        ret->data = (void *) ((char *) alloc + base_alloc);
//        ret->max_size = size;
//    }
//    return ret;
//}
//
//static void secp256k1_scratch_destroy(const secp256k1_callback* error_callback, secp256k1_scratch* scratch) {
//    if (scratch != NULL) {
//        if (secp256k1_memcmp_var(scratch->magic, "scratch", 8) != 0) {
//            secp256k1_callback_call(error_callback, "invalid scratch space");
//            return;
//        }
//        VERIFY_CHECK(scratch->alloc_size == 0); /* all checkpoints should be applied */
//        memset(scratch->magic, 0, sizeof(scratch->magic));
//        free(scratch);
//    }
//}

SECP256K1_API int secp256k1_verify_in_batch(
    const secp256k1_context* ctx,
    const secp256k1_batch_entry* entries,
    size_t n,
    const unsigned char* multiplier32
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
    int fail_code = 0;
    (void)ctx;
    if (!entries || n == 0 || !multiplier32) return SECP256K1_BATCHVERIFY_ERR_INVALID_ARGS;

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
        return SECP256K1_BATCHVERIFY_ERR_ALLOC;
    }

    for (i = 0; i < n; i++) {
        if (!secp256k1_eckey_pubkey_parse(&Q[i], entries[i].Q65, 65)) { fail_code = SECP256K1_BATCHVERIFY_ERR_QR_PARSE_OR_INVALID; break; }
        if (!secp256k1_eckey_pubkey_parse(&R[i], entries[i].R65, 65)) { fail_code = SECP256K1_BATCHVERIFY_ERR_QR_PARSE_OR_INVALID; break; }
        if (!secp256k1_ge_is_valid_var(&Q[i]) || secp256k1_ge_is_infinity(&Q[i])) { fail_code = SECP256K1_BATCHVERIFY_ERR_QR_PARSE_OR_INVALID; break; }
        if (!secp256k1_ge_is_valid_var(&R[i]) || secp256k1_ge_is_infinity(&R[i])) { fail_code = SECP256K1_BATCHVERIFY_ERR_QR_PARSE_OR_INVALID; break; }
        {
            unsigned char yb[32];
            int y_is_odd;
            secp256k1_fe y = R[i].y;
            secp256k1_fe_normalize_var(&y);
            secp256k1_fe_get_b32(yb, &y);
            y_is_odd = (yb[31] & 1);
            if ((entries[i].v ? 1 : 0) != y_is_odd) { fail_code = SECP256K1_BATCHVERIFY_ERR_V_MISMATCH; break; }
        }
        secp256k1_scalar_set_b32(&r[i], entries[i].r32, &overflow); if (overflow || secp256k1_scalar_is_zero(&r[i])) { fail_code = SECP256K1_BATCHVERIFY_ERR_R_SCALAR; break; }
        secp256k1_scalar_set_b32(&s[i], entries[i].s32, &overflow); if (overflow || secp256k1_scalar_is_zero(&s[i]) || secp256k1_scalar_is_high(&s[i])) { fail_code = SECP256K1_BATCHVERIFY_ERR_S_SCALAR; break; }
        secp256k1_scalar_set_b32(&z[i], entries[i].z32, &overflow); if (overflow) { fail_code = SECP256K1_BATCHVERIFY_ERR_Z_SCALAR; break; }
        {
            secp256k1_fe x; unsigned char xb[32]; secp256k1_scalar r_from_R; int of2 = 0;
            x = R[i].x;
            secp256k1_fe_normalize_var(&x); secp256k1_fe_get_b32(xb, &x); secp256k1_scalar_set_b32(&r_from_R, xb, &of2);
            if (!secp256k1_scalar_eq(&r_from_R, &r[i])) { fail_code = SECP256K1_BATCHVERIFY_ERR_R_BINDING; break; }
        }
    }
    if (fail_code) {
        for (i2 = 0; i2 < n; i2++) { secp256k1_scalar_clear(&r[i2]); secp256k1_scalar_clear(&s[i2]); secp256k1_scalar_clear(&z[i2]); }
        free(Q); free(R); free(r); free(s); free(z); free(r_comb); free(s_comb);
        return fail_code;
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
        return SECP256K1_BATCHVERIFY_ERR_SCRATCH;
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
    if (ret == 0) {
        return SECP256K1_BATCHVERIFY_ERR_ECMULT;
    }
    if (!ok) {
        return SECP256K1_BATCHVERIFY_ERR_NOT_INFINITY;
    }
    return SECP256K1_BATCHVERIFY_OK;
}

//SECP256K1_API int secp256k1_verify_in_batch_rdat(
//    const secp256k1_context* ctx,
//    const unsigned char* in,
//    size_t in_size,
//    const unsigned char* multiplier32
//) {
//    size_t n;
//    size_t need;
//    const secp256k1_batch_entry* entries;
//    if (!in || in_size < 16) return 0;
//    if (in[0] != 'R' || in[1] != 'D' || in[2] != 'A' || in[3] != 'T') return 0;
//    if (!(in[4] == 0x00 && in[5] == 0x00 && in[6] == 0x00 && in[7] == 0x01)) return 0;
//    n = ((size_t)in[8] << 56) | ((size_t)in[9] << 48) | ((size_t)in[10] << 40) | ((size_t)in[11] << 32) |
//        ((size_t)in[12] << 24) | ((size_t)in[13] << 16) | ((size_t)in[14] << 8) | (size_t)in[15];
//    need = (size_t)16 + n * (size_t)227;
//    if (in_size < need) return 0;
//    entries = (const secp256k1_batch_entry*)(in + 16);
//    return secp256k1_verify_in_batch(ctx, entries, n, multiplier32);
//}

