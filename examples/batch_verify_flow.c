#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_batchverify.h"
#include "secp256k1_recovery.h"

/* Demo of:
 * - secp256k1_verify_in_batch
 * - secp256k1_lookup_ecrecover_i
 * - secp256k1_recover_data_serialize
 *
 * NOTE: This example fills placeholder data. For a successful verification
 * you must populate entries with real (Q65, R65, r32, s32, z32, v) tuples.
 */

#if defined(_WIN32)
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
static int fill_random(unsigned char* data, size_t size) {
    NTSTATUS res = BCryptGenRandom(NULL, data, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (res == STATUS_SUCCESS) ? 1 : 0;
}
#elif defined(__linux__) || defined(__FreeBSD__)
#include <sys/random.h>
static int fill_random(unsigned char* data, size_t size) {
    ssize_t res = getrandom(data, size, 0);
    return (res == (ssize_t)size) ? 1 : 0;
}
#elif defined(__APPLE__) || defined(__OpenBSD__)
#include <sys/random.h>
static int fill_random(unsigned char* data, size_t size) {
    return getentropy(data, size) == 0 ? 1 : 0;
}
#else
#error "Unsupported OS for random generation in example"
#endif

static int generate_valid_entries(secp256k1_context* ctx, secp256k1_batch_entry *entries, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char seckey[32];
        unsigned char msg32[32];
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_recoverable_signature sig_rec;
        unsigned char sig64[64];
        int recid = 0;
        size_t qlen = 65;

        /* Generate random valid secret key */
        do {
            if (!fill_random(seckey, 32)) return 0;
        } while (!secp256k1_ec_seckey_verify(ctx, seckey));

        /* Random message */
        if (!fill_random(msg32, 32)) return 0;

        /* Public key */
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) return 0;
        if (!secp256k1_ec_pubkey_serialize(ctx, entries[i].Q65, &qlen, &pubkey, SECP256K1_EC_UNCOMPRESSED)) return 0;
        if (qlen != 65) return 0;

        /* Recoverable signature */
        if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig_rec, msg32, seckey, NULL, NULL)) return 0;
        if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig64, &recid, &sig_rec)) return 0;

        /* s32 and z32 */
        memcpy(entries[i].s32, sig64 + 32, 32);
        memcpy(entries[i].z32, msg32, 32);
        entries[i].v = (unsigned char)(recid & 1);

        /* Reconstruct R from (r_x, v) using compressed form and public parse */
        {
            unsigned char r_xb[32];
            unsigned char comp33[33];
            secp256k1_pubkey R_pub;
            size_t rlen = 65;

            memcpy(r_xb, sig64, 32);
            comp33[0] = (entries[i].v ? 0x03 : 0x02);
            memcpy(&comp33[1], r_xb, 32);
            if (!secp256k1_ec_pubkey_parse(ctx, &R_pub, comp33, 33)) return 0;
            if (!secp256k1_ec_pubkey_serialize(ctx, entries[i].R65, &rlen, &R_pub, SECP256K1_EC_UNCOMPRESSED)) return 0;
            if (rlen != 65) return 0;

            /* r32 = x(R) mod n */
            memcpy(entries[i].r32, sig64, 32);
        }
    }
    return 1;
}

/* 2) Deserialize (zero-copy view) via library helper */

int main(void) {
    int ok;
    size_t n = 2;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    /* Prepare entries */
    secp256k1_batch_entry *entries = (secp256k1_batch_entry*)malloc(n * sizeof(*entries));
    if (!entries) {
        fprintf(stderr, "OOM\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    if (!generate_valid_entries(ctx, entries, n)) {
        fprintf(stderr, "Failed to generate valid entries\n");
        free(entries);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* Multiplier for random coefficients (caller-provided 32-byte scalar) */
    unsigned char multiplier32[32];
    fill_random(multiplier32, sizeof(multiplier32));

    /* 1) Serialize to RDAT v1 */
    {
        size_t out_size = secp256k1_recover_data_serialized_size(n);
        unsigned char *out = (unsigned char*)malloc(out_size);
        size_t written = 0;
        if (!out) {
            fprintf(stderr, "OOM\n");
            free(entries);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        ok = secp256k1_recover_data_serialize(ctx, entries, n, out, out_size, &written);
        printf("recover_data_serialize: %s, bytes=%zu\n", ok ? "ok" : "fail", written);
        if (!ok) {
            free(out);
            free(entries);
            secp256k1_context_destroy(ctx);
            return 1;
        }

        /* 2) Deserialize (zero-copy view) */
        {
            const secp256k1_batch_entry* entries_view;
            size_t n2;
            if (!secp256k1_rdat_view_parse(out, written, &entries_view, &n2)) {
                free(out);
                free(entries);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (n2 != n) {
                fprintf(stderr, "RDAT size/count mismatch\n");
                free(out);
                free(entries);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* 3) Batch verify on deserialized view */
            ok = secp256k1_verify_in_batch(ctx, entries_view, n2, multiplier32);
            printf("verify_in_batch (from RDAT): %s\n", ok ? "success" : "failure");

            /* 4) lookup_ecrecover_i on deserialized view */
            {
                unsigned char Q65_out[65];
                int match = secp256k1_lookup_ecrecover_i(
                    ctx, entries_view, n2, 0,
                    entries_view[0].r32, entries_view[0].s32, entries_view[0].v, entries_view[0].z32,
                    Q65_out
                );
                printf("lookup_ecrecover_i (i=0, RDAT): %s\n", match ? "matched Q" : "no match");
            }
        }

        free(out);
    }

    free(entries);
    secp256k1_context_destroy(ctx);
    return 0;
}


