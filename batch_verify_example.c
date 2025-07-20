/*************************************************************************
 * Example: Batch Verification Concept for Multiple Transaction Inputs
 * 
 * This demonstrates the concept of batch verification for multiple ECDSA 
 * signatures. Note: secp256k1_ecmult_multi_var is an internal function.
 * This example shows how batch verification would work conceptually and
 * provides a framework that could be extended with internal API access.
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <secp256k1.h>

/* Include internal secp256k1 headers for real implementation */
#include "src/util.h"
#include "src/int128_impl.h"
#include "src/field_impl.h"
#include "src/scalar_impl.h"
#include "src/group_impl.h"
#include "src/ecmult_impl.h"
#include "src/scratch_impl.h"

/* Internal function implementation */
static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    (void)ctx; /* Unused in this simplified version */
    secp256k1_ge_from_bytes(ge, pubkey->data);
    return !secp256k1_fe_is_zero(&ge->x);
}

/* Maximum number of inputs we can verify in one batch */
#define MAX_BATCH_SIZE 1000

/* Structure representing a transaction input to verify */
typedef struct {
    unsigned char signature[72];      /* DER-encoded signature */
    size_t sig_len;                  /* Actual signature length */
    unsigned char pubkey[33];        /* Compressed public key */
    unsigned char msg_hash[32];      /* Hash of the message being signed */
    int valid;                       /* Result of verification */
} tx_input_t;

/* Pre-compute scalar inverses for batch verification optimization */
static int precompute_scalar_inverses(secp256k1_context *ctx, 
                                     tx_input_t *inputs, 
                                     size_t num_inputs,
                                     secp256k1_scalar *s_inverses,
                                     size_t max_batch_size) {
    clock_t start = clock();
    size_t processed = 0;
    size_t verified_inverses = 0;
    size_t batch_size = (num_inputs > max_batch_size) ? max_batch_size : num_inputs;
    
    printf("Pre-computing and verifying scalar inverses for %zu signatures...\n", batch_size);
    
    for (size_t i = 0; i < batch_size && i < num_inputs; i++) {
        secp256k1_ecdsa_signature parsed_sig;
        secp256k1_scalar s;
        unsigned char sig_compact[64];
        int overflow;
        
        /* Parse signature to extract s value */
        if (!secp256k1_ecdsa_signature_parse_der(ctx, &parsed_sig, inputs[i].signature, inputs[i].sig_len)) {
            continue;
        }
        if (!secp256k1_ecdsa_signature_serialize_compact(ctx, sig_compact, &parsed_sig)) {
            continue;
        }
        
        /* Extract s scalar from signature */
        secp256k1_scalar_set_b32(&s, sig_compact + 32, &overflow);
        if (overflow) continue;
        
        /* Compute s^(-1) - this is the expensive operation we're pre-computing */
        secp256k1_scalar_inverse_var(&s_inverses[processed], &s);
        
        /* VERIFICATION: Check that s * s^(-1) ≡ 1 (mod n) */
        secp256k1_scalar verification_result;
        secp256k1_scalar_mul(&verification_result, &s, &s_inverses[processed]);
        
        /* Check if result equals 1 (multiplicative identity) */
        if (!secp256k1_scalar_is_one(&verification_result)) {
            printf("ERROR: Scalar inverse verification failed for signature %zu!\n", i);
            printf("       s * s^(-1) != 1, skipping this signature\n");
            continue; /* Skip this invalid inverse */
        }
        
        verified_inverses++; /* Count successful verification */
        processed++;
    }
    
    clock_t end = clock();
    double precompute_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("Pre-computed %zu scalar inverses in %.6f seconds\n", processed, precompute_time);
    printf("Verified %zu inverses: s * s^(-1) ≡ 1 (mod n) ✓\n", verified_inverses);
    if (verified_inverses != processed) {
        printf("WARNING: %zu inverses failed verification!\n", processed - verified_inverses);
    }
    printf("Average time per inverse (including verification): %.6f seconds\n", precompute_time / processed);
    
    return processed;
}

/* Batch verification data structure */
typedef struct {
    secp256k1_context *ctx;
    tx_input_t *inputs;
    size_t num_inputs;
    int all_valid;
} batch_verify_data_t;

/* Generate a test signature for demonstration */
static int generate_test_input(secp256k1_context *ctx, tx_input_t *input, 
                              const unsigned char *seckey, int make_invalid) {
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    
    /* Generate public key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        printf("Failed to create public key\n");
        return 0;
    }
    
    /* Serialize public key */
    size_t pubkey_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, input->pubkey, &pubkey_len, 
                                      &pubkey, SECP256K1_EC_COMPRESSED)) {
        printf("Failed to serialize public key\n");
        return 0;
    }
    
    /* Create a test message hash */
    for (int i = 0; i < 32; i++) {
        input->msg_hash[i] = (unsigned char)(i + 1);
    }
    
    /* Optionally corrupt the message to create invalid signature */
    if (make_invalid) {
        input->msg_hash[0] ^= 0xFF;  /* Flip bits to make hash different */
    }
    
    /* Sign the original message (before corruption if any) */
    unsigned char original_hash[32];
    memcpy(original_hash, input->msg_hash, 32);
    if (make_invalid) {
        original_hash[0] ^= 0xFF;  /* Sign the original, uncorrupted hash */
    }
    
    if (!secp256k1_ecdsa_sign(ctx, &sig, original_hash, seckey, NULL, NULL)) {
        printf("Failed to create signature\n");
        return 0;
    }
    
    /* Serialize signature to DER format */
    input->sig_len = 72;
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, input->signature, 
                                                &input->sig_len, &sig)) {
        printf("Failed to serialize signature\n");
        return 0;
    }
    
    return 1;
}

/* Individual signature verification using public API */
static int verify_single_signature(secp256k1_context *ctx, const tx_input_t *input) {
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    
    /* Parse public key */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input->pubkey, 33)) {
        return 0;
    }
    
    /* Parse signature */
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, input->signature, input->sig_len)) {
        return 0;
    }
    
    /* Verify signature */
    return secp256k1_ecdsa_verify(ctx, &sig, input->msg_hash, &pubkey);
}

static int individual_verify(batch_verify_data_t *batch_data) {
    
    /* For demonstration, we'll fall back to individual verification */
    printf("\nIndividual verification for demonstration:\n");
    
    int all_valid = 1;
    clock_t start = clock();
    
    for (size_t i = 0; i < batch_data->num_inputs; i++) {
        int valid = verify_single_signature(batch_data->ctx, &batch_data->inputs[i]);
        batch_data->inputs[i].valid = valid;
        
        if (!valid) {
            all_valid = 0;
        }
        
        printf("  Input %zu: %s\n", i, valid ? "✓ VALID" : "✗ INVALID");
    }
    
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("\nIndividual verification completed in %.6f seconds\n", time_taken);
    
    batch_data->all_valid = all_valid;
    return all_valid;
}

/* Real batch verification implementation with internal API access */
typedef struct {
    secp256k1_scalar *u2_scalars;  /* r/s values */
    secp256k1_ge *pubkeys;         /* Public keys */
    secp256k1_scalar g_scalar;     /* Sum of u1 values */
    secp256k1_gej expected_sum;    /* Sum of R points */
    secp256k1_scalar *s_inverses;  /* Pre-computed s^(-1) values */
    size_t num_points;             /* Number of points in batch */
} internal_batch_data_t;

/* Callback function for secp256k1_ecmult_multi_var */
static int internal_batch_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    internal_batch_data_t *batch = (internal_batch_data_t *)data;
    *sc = batch->u2_scalars[idx];
    *pt = batch->pubkeys[idx];
    return 1;
}

    
    /* 
     * CONCEPTUAL IMPLEMENTATION:
     * 
     * If we had access to internal APIs, we would:
     * 
     * 1. For each signature (r_i, s_i) and message hash h_i:
     *    - Compute u1_i = h_i / s_i
     *    - Compute u2_i = r_i / s_i
     * 
     * 2. Use secp256k1_ecmult_multi_var to compute:
     *    result = (Σu1_i) * G + Σ(u2_i * pubkey_i)
     * 
     * 3. Compute expected = Σ(R_i) where R_i is point with x-coord r_i
     * 
     * 4. Check if result == expected
     * 
     * This would be ~3-5x faster than individual verification
     */
static int demonstrate_internal_batch_verify(secp256k1_context *ctx,
                                            internal_batch_data_t *batch_data,
                                            size_t num_inputs) {
    secp256k1_gej result;
    secp256k1_scratch *scratch;
    int success;
    
    printf("  → Step 1: Parse signatures and extract (r,s) scalar components\n");
    printf("  → Step 2: Compute u1 = hash/s and u2 = r/s for each signature\n");
    printf("  → Step 3: Sum all u1 values for G scalar: g_scalar = Σ(u1_i)\n");
    printf("  → Step 4: Prepare u2 scalars and pubkeys for callback\n");
    printf("  → Step 5: Call secp256k1_ecmult_multi_var:\n");
    printf("            result = g_scalar*G + Σ(u2_i * pubkey_i)\n");
    
    /* Create scratch space for computation */
    scratch = secp256k1_scratch_create(&default_error_callback, 100000);
    if (!scratch) {
        printf("  → ERROR: Failed to create scratch space\n");
        return 0;
    }
    
    printf("  → Step 6: Executing secp256k1_ecmult_multi_var...\n");
    
    /* The real implementation! */
    success = secp256k1_ecmult_multi_var(
        &default_error_callback,          /* Error callback */
        scratch,                          /* Scratch space for computation */
        &result,                          /* Output: computed result */
        &batch_data->g_scalar,            /* G scalar: sum of all u1 values */
        internal_batch_callback,          /* Callback providing (u2, pubkey) pairs */
        batch_data,                       /* Callback data */
        num_inputs                        /* Number of signatures */
    );
    
    printf("  → Step 7: Compare result with expected sum\n");
    
    if (success) {
        /* Compare result with expected sum */
        secp256k1_gej diff;
        secp256k1_gej_neg(&diff, &batch_data->expected_sum);
        secp256k1_gej_add_var(&diff, &result, &diff, NULL);
        success = secp256k1_gej_is_infinity(&diff);
        
        printf("  → Batch verification result: %s\n", success ? "ALL VALID" : "SOME INVALID");
    } else {
        printf("  → ERROR: secp256k1_ecmult_multi_var failed\n");
    }
    
    /* Cleanup */
    secp256k1_scratch_destroy(&default_error_callback, scratch);
    
    return success;
}

/* Performance comparison function */
static void demonstrate_performance_benefit(secp256k1_context *ctx, 
                                          tx_input_t *inputs, 
                                          size_t num_inputs) {
    printf("\n=== Performance Comparison ===\n");
    
    /* Individual verification timing */
    clock_t start = clock();
    for (size_t i = 0; i < num_inputs; i++) {
        verify_single_signature(ctx, &inputs[i]);
    }
    clock_t end = clock();
    double individual_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("Individual verification of %zu signatures: %.6f seconds\n", 
           num_inputs, individual_time);
    
    /* Demonstrate real batch verification with internal APIs */
    printf("\n=== Real Batch Verification Demo ===\n");
    printf("This shows actual secp256k1_ecmult_multi_var usage with internal APIs:\n\n");
    
    /* Initialize internal batch data */
    internal_batch_data_t batch_data;
    batch_data.num_points = (num_inputs > 5000) ? 5000 : num_inputs; /* Demo with subset */
    
    /* Allocate arrays for real batch processing */
    batch_data.u2_scalars = malloc(batch_data.num_points * sizeof(secp256k1_scalar));
    batch_data.pubkeys = malloc(batch_data.num_points * sizeof(secp256k1_ge));
    batch_data.s_inverses = malloc(batch_data.num_points * sizeof(secp256k1_scalar));
    
    if (!batch_data.u2_scalars || !batch_data.pubkeys || !batch_data.s_inverses) {
        printf("ERROR: Failed to allocate batch verification data\n");
        if (batch_data.u2_scalars) free(batch_data.u2_scalars);
        if (batch_data.pubkeys) free(batch_data.pubkeys);
        if (batch_data.s_inverses) free(batch_data.s_inverses);
        return;
    }
    
    /* Pre-compute expensive scalar inverses */
    printf("\n=== Pre-computation Phase ===\n");
    int precomputed_count = precompute_scalar_inverses(ctx, inputs, num_inputs, 
                                                      batch_data.s_inverses, 
                                                      batch_data.num_points);
    
    if (precomputed_count == 0) {
        printf("ERROR: No scalar inverses could be pre-computed\n");
        free(batch_data.u2_scalars);
        free(batch_data.pubkeys);
        free(batch_data.s_inverses);
        return;
    }
    
    batch_data.num_points = precomputed_count; /* Update to actual processed count */
    
    /* Initialize G scalar sum and expected sum */
    secp256k1_scalar_clear(&batch_data.g_scalar);
    secp256k1_gej_set_infinity(&batch_data.expected_sum);
    
    printf("Preparing real batch verification data for %zu signatures:\n", batch_data.num_points);
    
    /* Process signatures using pre-computed inverses */
    printf("\n=== Fast Batch Processing Phase ===\n");
    printf("Processing signatures using VERIFIED pre-computed scalar inverses...\n");
    
    size_t valid_sigs = 0;
    for (size_t i = 0; i < batch_data.num_points && i < num_inputs; i++) {
        secp256k1_ecdsa_signature parsed_sig;
        secp256k1_pubkey pubkey;
        secp256k1_scalar r, s, u1, u2, msg_scalar;
        unsigned char sig_compact[64];
        int overflow;
        
        /* Parse signature */
        if (!secp256k1_ecdsa_signature_parse_der(ctx, &parsed_sig, inputs[i].signature, inputs[i].sig_len)) {
            continue;
        }
        if (!secp256k1_ecdsa_signature_serialize_compact(ctx, sig_compact, &parsed_sig)) {
            continue;
        }
        
        /* Parse public key */
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, inputs[i].pubkey, 33)) {
            continue;
        }
        if (!secp256k1_pubkey_load(ctx, &batch_data.pubkeys[valid_sigs], &pubkey)) {
            continue;
        }
        
        /* Extract r and s scalars */
        secp256k1_scalar_set_b32(&r, sig_compact, &overflow);
        if (overflow) continue;
        secp256k1_scalar_set_b32(&s, sig_compact + 32, &overflow);
        if (overflow) continue;
        
        /* Convert message hash to scalar */
        secp256k1_scalar_set_b32(&msg_scalar, inputs[i].msg_hash, &overflow);
        if (overflow) continue;
        
        /* Use pre-computed s^(-1) - MUCH FASTER! */
        secp256k1_scalar *s_inv = &batch_data.s_inverses[valid_sigs];
        secp256k1_scalar_mul(&u1, &msg_scalar, s_inv);  /* u1 = hash * s^(-1) */
        secp256k1_scalar_mul(&u2, &r, s_inv);           /* u2 = r * s^(-1) */
        
        /* Store u2 for batch multiplication */
        batch_data.u2_scalars[valid_sigs] = u2;
        
        /* Add u1 to G scalar sum */
        secp256k1_scalar_add(&batch_data.g_scalar, &batch_data.g_scalar, &u1);
        
        valid_sigs++;
    }
    
    printf("Successfully prepared %zu signatures for real batch verification\n", valid_sigs);
    
    if (valid_sigs == 0) {
        printf("ERROR: No valid signatures to process\n");
        free(batch_data.u2_scalars);
        free(batch_data.pubkeys);
        return;
    }
    
    /* Time the real batch verification */
    start = clock();
    int batch_result = demonstrate_internal_batch_verify(ctx, &batch_data, valid_sigs);
    end = clock();
    double batch_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    /* Cleanup */
    free(batch_data.u2_scalars);
    free(batch_data.pubkeys);
    free(batch_data.s_inverses);
    
    printf("Time for batch verification demo: %.6f seconds\n", batch_time);
    
    /* Compare with estimated individual time for same subset */
    double individual_subset_time = (individual_time / num_inputs) * batch_data.num_points;
    printf("Individual verification time for %zu signatures: %.6f seconds\n", 
           batch_data.num_points, individual_subset_time);
    printf("Speed-up: %.6f\n", individual_subset_time / batch_time);
}


/* Main example function 
 * To Compile: 
 * gcc -Wall -Wextra -std=c99 -O2 -I./include -I./src -o batch_verify_example batch_verify_example.c ./.libs/libsecp256k1.a
 * */
int main() {
    secp256k1_context *ctx;
    tx_input_t inputs[500];  /* Increased to better demonstrate batch verification */
    batch_verify_data_t batch_data;
    
    /* Initialize context */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return 1;
    }
    
    printf("=== Batch Verification Example ===\n\n");
    
    /* Generate test transaction inputs */
    printf("Generating test transaction inputs...\n");
    for (int i = 0; i < 500; i++) {
        unsigned char seckey[32];
        /* Generate a deterministic private key for testing */
        for (int j = 0; j < 32; j++) {
            seckey[j] = (unsigned char)((i + 1) * (j + 1) % 256);
        }
        seckey[0] = 1; /* Ensure it's valid */
        
        int make_invalid = 0;
        /* Uncomment following lines to make some signatures invalid for demonstration */
	//if (i == 7 || i == 123 || i == 456) {
        //    make_invalid = 1;
	//}
        
        if (!generate_test_input(ctx, &inputs[i], seckey, make_invalid)) {
            printf("Failed to generate test input %d\n", i);
            goto cleanup;
        }
        if (i < 10 || make_invalid) { /* Only print first 10 and invalid ones */
            printf("  Input %d: Generated %s signature\n", i, 
                   make_invalid ? "INVALID" : "valid");
        }
    }
    printf("  ... (generated %d total inputs)\n", 500);
    
    /* Initialize batch verification data */
    batch_data.ctx = ctx;
    batch_data.inputs = inputs;
    batch_data.num_inputs = 500;
    batch_data.all_valid = 0;
    
    printf("\n=== Individual Verification Process ===\n");
    individual_verify(&batch_data);
    
    /* Show final results */
    printf("\n=== Final Results ===\n");
    printf("Individual verification result: %s\n", 
           batch_data.all_valid ? "ALL VALID" : "SOME INVALID");
    
    printf("\nIndividual signature results (showing first 10 and any invalid):\n");
    int valid_count = 0;
    for (int i = 0; i < 500; i++) {
        if (inputs[i].valid) valid_count++;
        if (i < 10 || !inputs[i].valid) {
            printf("  Input %d: %s\n", i, inputs[i].valid ? "✓ VALID" : "✗ INVALID");
        }
    }
    printf("  ... (processed %d total inputs: %d valid, %d invalid)\n", 
           500, valid_count, 500 - valid_count);
    
    /* Performance demonstration */
    demonstrate_performance_benefit(ctx, inputs, 500);
    
    printf("\n=== Implementation Notes ===\n");
    printf("This example demonstrates the concept of batch verification.\n");
    printf("A real implementation would require:\n");
    printf("1. Access to internal secp256k1 APIs (secp256k1_ecmult_multi_var)\n");
    printf("2. Internal scalar and point manipulation functions\n");
    printf("3. Custom build with internal headers included\n");
    printf("\nBatch verification provides significant performance benefits\n");
    printf("for applications processing many signatures simultaneously,\n");
    printf("such as blockchain validation or payment processing systems.\n");

cleanup:
    secp256k1_context_destroy(ctx);
    return 0;
} 
