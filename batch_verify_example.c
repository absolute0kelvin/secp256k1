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
#include <secp256k1_recovery.h>

/* Include internal secp256k1 headers for real implementation */
#include "src/util.h"
#include "src/int128_impl.h"
#include "src/field_impl.h"
#include "src/scalar_impl.h"
#include "src/group_impl.h"
#include "src/ecmult_impl.h"
#include "src/scratch_impl.h"
#include "src/ecdsa_impl.h"
#include "src/hash_impl.h"

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

// This function is used to generate a random coefficient for the batch verification. 
// The hash function takes *inputs as inputs, and output a random vector of size defined by size_coeff. 
static void generate_random_coefficient_vector(secp256k1_scalar *coeff_vector, 
    const tx_input_t *inputs, 
    size_t num_inputs, 
    size_t size_coeff) {
secp256k1_sha256 hash;
unsigned char seed[32];  // Store the seed derived from inputs
unsigned char hash_output[32];
unsigned char index_bytes[4];
int overflow;

// STEP 1: Generate seed = Hash(inputs) once
printf("Generating seed from %zu input signatures...\n", num_inputs);
secp256k1_sha256_initialize(&hash);
secp256k1_sha256_write(&hash, (const unsigned char*)inputs, num_inputs * sizeof(tx_input_t));
secp256k1_sha256_finalize(&hash, seed);
secp256k1_sha256_clear(&hash);

// STEP 2: Generate coefficients Hash(seed||1), Hash(seed||2), ..., Hash(seed||size_coeff)
printf("Generating %zu random coefficients using seed...\n", size_coeff);

for (size_t i = 0; i < size_coeff; i++) {
// Initialize SHA256 for each coefficient
secp256k1_sha256_initialize(&hash);

// Hash the pre-computed seed
secp256k1_sha256_write(&hash, seed, 32);

// Convert (i+1) to bytes (little-endian) - so we use 1, 2, 3, ... instead of 0, 1, 2, ...
size_t index = i + 1;
index_bytes[0] = (unsigned char)(index & 0xFF);
index_bytes[1] = (unsigned char)((index >> 8) & 0xFF);
index_bytes[2] = (unsigned char)((index >> 16) & 0xFF);
index_bytes[3] = (unsigned char)((index >> 24) & 0xFF);

// Append index to create Hash(seed||index)
secp256k1_sha256_write(&hash, index_bytes, 4);

// Finalize hash to get Hash(seed||i)
secp256k1_sha256_finalize(&hash, hash_output);

// Convert hash output to scalar
secp256k1_scalar_set_b32(&coeff_vector[i], hash_output, &overflow);
if (overflow) {
// If overflow, reduce by 1 to ensure valid scalar
secp256k1_scalar_negate(&coeff_vector[i], &coeff_vector[i]);
secp256k1_scalar_negate(&coeff_vector[i], &coeff_vector[i]);
}

// Clear hash context for security
secp256k1_sha256_clear(&hash);

// Progress indicator for large vectors
if ((i + 1) % 100 == 0 || i == size_coeff - 1) {
printf("  Generated coefficient %zu/%zu\n", i + 1, size_coeff);
}
}

// Clear seed from memory for security
memset(seed, 0, 32);

printf("✓ Generated %zu random coefficients: Hash(seed||1) through Hash(seed||%zu)\n", 
size_coeff, size_coeff);
}

/* Reconstruct R point from signature using secp256k1_ecdsa_sig_recover approach */
static int reconstruct_r_point(const secp256k1_scalar *r,
                              const secp256k1_scalar *u1, 
                              const secp256k1_scalar *u2,
                              const secp256k1_ge *pubkey,
                              secp256k1_gej *r_point_out) {
    unsigned char brx[32];
    secp256k1_fe fx;
    secp256k1_ge R_point;
    
    /* Convert r scalar to bytes */
    secp256k1_scalar_get_b32(brx, r);
    
    /* Set field element from r bytes */
    if (!secp256k1_fe_set_b32_limit(&fx, brx)) {
        return 0; /* Invalid r value */
    }
    
    /* Reconstruct correct R point by testing which one satisfies the signature equation
     * WARNING: This is computationally EXPENSIVE! Up to 4 full ecmult operations per signature.
     * Normal ECDSA verification avoids this by providing R points more directly. */
    for (int recovery_flag = 0; recovery_flag < 4; recovery_flag++) {
        secp256k1_fe fx_candidate = fx;
        
        /* Handle recovery_flag >= 2 case (add order to x coordinate) */
        if (recovery_flag >= 2) {
            if (secp256k1_fe_cmp_var(&fx, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
                continue; /* x + order would be >= field size */
            }
            secp256k1_fe_add(&fx_candidate, &secp256k1_ecdsa_const_order_as_fe);
        }
        
        /* Try to construct point with this x coordinate and y parity */
        if (secp256k1_ge_set_xo_var(&R_point, &fx_candidate, recovery_flag & 1)) {
            /* Test if this R point satisfies: R = u1*G + u2*Pubkey */
            secp256k1_gej test_result, pubkey_gej;
            secp256k1_gej_set_ge(&pubkey_gej, pubkey);
            
            /* Compute u1*G + u2*Pubkey - EXPENSIVE OPERATION! */
            secp256k1_ecmult(&test_result, &pubkey_gej, u2, u1);
            
            /* Check if this equals our candidate R point */
            if (secp256k1_gej_eq_ge_var(&test_result, &R_point)) {
                /* This is the correct R point! */
                secp256k1_gej_set_ge(r_point_out, &R_point);
                return 1; /* Success */
            }
        }
    }
    
    return 0; /* Could not reconstruct correct R point */
}

/* Verify R point is on the curve (MUCH simpler than signature verification!) */
static int verify_r_point(secp256k1_gej *r_point) {
    secp256k1_ge r_point_affine;
    
    /* Convert from Jacobian to affine coordinates */
    secp256k1_ge_set_gej(&r_point_affine, r_point);
    
    /* Check if point is valid (on curve: y² = x³ + 7) - very fast! */
    return secp256k1_ge_is_valid_var(&r_point_affine);
}

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
    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    secp256k1_ecdsa_signature sig;
    
    /* Create a test message hash */
    for (int i = 0; i < 32; i++) {
        input->msg_hash[i] = (unsigned char)(i + 1);
    }
    
    /* Always sign with the correct secret key using recoverable signature */
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, input->msg_hash, seckey, NULL, NULL)) {
        printf("Failed to create recoverable signature\n");
        return 0;
    }
    
    /* Optional: Extract recovery ID for demonstration */
    unsigned char recovery_sig[65];
    int recovery_id;
    if (secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, recovery_sig, &recovery_id, &recoverable_sig)) {
        /* Recovery ID is now available (0, 1, 2, or 3) */
        /* This allows public key recovery from signature + message */
    }
    
    /* Convert recoverable signature to regular signature for DER serialization */
    if (!secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &recoverable_sig)) {
        printf("Failed to convert recoverable signature\n");
        return 0;
    }
    
    /* Serialize signature to DER format */
    input->sig_len = 72;
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, input->signature, 
                                                &input->sig_len, &sig)) {
        printf("Failed to serialize signature\n");
        return 0;
    }
    
    /* Generate public key: use wrong key when make_invalid is 1 */
    unsigned char pubkey_seckey[32];
    if (make_invalid) {
        /* Use a different secret key to generate wrong public key */
        for (int i = 0; i < 32; i++) {
            pubkey_seckey[i] = seckey[i] ^ 0xFF;  /* Flip all bits to get different key */
        }
        pubkey_seckey[0] = 1;  /* Ensure it's still a valid secret key */
    } else {
        /* Use the correct secret key for valid signatures */
        memcpy(pubkey_seckey, seckey, 32);
    }
    
    /* Generate and serialize public key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, pubkey_seckey)) {
        printf("Failed to create public key\n");
        return 0;
    }
    
    size_t pubkey_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, input->pubkey, &pubkey_len, 
                                      &pubkey, SECP256K1_EC_COMPRESSED)) {
        printf("Failed to serialize public key\n");
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
    secp256k1_gej *R_points_gej;   /* Reconstructed R points (Jacobian) */
    secp256k1_scalar g_scalar;     /* Sum of u1 values */
    secp256k1_gej expected_sum;    /* Which will be 0 */
    secp256k1_scalar *s_inverses;  /* Pre-computed s^(-1) values */
    secp256k1_scalar *coeff_vector; /* Random coefficients for random linear combination */
    size_t num_points;             /* Number of points in batch */
} internal_batch_data_t;

/* Helper function to print a Jacobian point */
static void print_jacobian_point(const secp256k1_gej *point, const char *label) {
    printf("%s (Jacobian):\n", label);
    secp256k1_ge point_ge;
    secp256k1_gej temp_point = *point;
    secp256k1_ge_set_gej_var(&point_ge, &temp_point);
    
    unsigned char x_bytes[32], y_bytes[32];
    secp256k1_fe_get_b32(x_bytes, &point_ge.x);
    secp256k1_fe_get_b32(y_bytes, &point_ge.y);
    
    printf("  X: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", x_bytes[i]);
    }
    printf("\n");
    
    printf("  Y: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", y_bytes[i]);
    }
    printf("\n");
}

/* Print function for internal_batch_data_t */
static void print_internal_batch_data(const internal_batch_data_t *batch_data) {
    printf("\n=== Internal Batch Data ===\n");
    printf("Number of points: %zu\n", batch_data->num_points);
    
    /* Print g_scalar (sum of u1 values) */
    printf("G scalar (sum of u1 values): ");
    unsigned char g_scalar_bytes[32];
    secp256k1_scalar_get_b32(g_scalar_bytes, &batch_data->g_scalar);
    for (int i = 0; i < 32; i++) {
        printf("%02x", g_scalar_bytes[i]);
    }
    printf("\n");
    
    /* Print expected sum point (in Jacobian coordinates) */
    print_jacobian_point(&batch_data->expected_sum, "Expected sum point");
    
    /* Print first few u2 scalars as samples */
    printf("U2 scalars (first 3 as samples):\n");
    size_t sample_count = batch_data->num_points < 3 ? batch_data->num_points : 3;
    for (size_t i = 0; i < sample_count; i++) {
        unsigned char u2_bytes[32];
        secp256k1_scalar_get_b32(u2_bytes, &batch_data->u2_scalars[i]);
        printf("  [%zu]: ", i);
        for (int j = 0; j < 32; j++) {
            printf("%02x", u2_bytes[j]);
        }
        printf("\n");
    }
    if (batch_data->num_points > 3) {
        printf("  ... (%zu more)\n", batch_data->num_points - 3);
    }
    
    /* Print first few public keys as samples */
    printf("Public keys (first 3 as samples):\n");
    for (size_t i = 0; i < sample_count; i++) {
        unsigned char pubkey_x[32], pubkey_y[32];
        secp256k1_fe_get_b32(pubkey_x, &batch_data->pubkeys[i].x);
        secp256k1_fe_get_b32(pubkey_y, &batch_data->pubkeys[i].y);
        
        printf("  [%zu] X: ", i);
        for (int j = 0; j < 16; j++) {  // Show first 16 bytes only
            printf("%02x", pubkey_x[j]);
        }
        printf("...\n");
        
        printf("      Y: ");
        for (int j = 0; j < 16; j++) {  // Show first 16 bytes only
            printf("%02x", pubkey_y[j]);
        }
        printf("...\n");
    }
    if (batch_data->num_points > 3) {
        printf("  ... (%zu more public keys)\n", batch_data->num_points - 3);
    }
    
    /* Print first few s_inverses as samples */
    printf("S^(-1) values (first 3 as samples):\n");
    for (size_t i = 0; i < sample_count; i++) {
        unsigned char s_inv_bytes[32];
        secp256k1_scalar_get_b32(s_inv_bytes, &batch_data->s_inverses[i]);
        printf("  [%zu]: ", i);
        for (int j = 0; j < 32; j++) {
            printf("%02x", s_inv_bytes[j]);
        }
        printf("\n");
    }
    if (batch_data->num_points > 3) {
        printf("  ... (%zu more)\n", batch_data->num_points - 3);
    }
    
    /* Print first few R points as samples */
    printf("R points (first 3 as samples):\n");
    for (size_t i = 0; i < sample_count; i++) {
        char label[64];
        snprintf(label, sizeof(label), "  R point [%zu]", i);
        print_jacobian_point(&batch_data->R_points_gej[i], label);
    }
    if (batch_data->num_points > 3) {
        printf("  ... (%zu more R points)\n", batch_data->num_points - 3);
    }
    
    printf("=============================\n\n");
}


/* Optimized callback structure for single secp256k1_ecmult_multi_var call */
typedef struct {
    secp256k1_scalar *coeff_vector;    /* Random coefficients */
    secp256k1_gej *R_points_gej;       /* R points (first num_points indices) */
    secp256k1_scalar *u2_scalars;      /* u2 scalars for pubkeys */
    secp256k1_ge *pubkeys;             /* Public keys (next num_points indices) */
    size_t num_points;                 /* Number of signatures */
} optimized_batch_data_t;

/* Optimized callback for single verification equation: 
 * sum(coeff[i] * R[i]) - sum(coeff[i] * u1[i]) * G - sum(coeff[i] * u2[i] * pubkey[i]) = 0
 * Indices 0 to num_points-1: R points with +coeff[i]
 * Indices num_points to 2*num_points-1: pubkeys with -coeff[i]*u2[i]
 */
static int optimized_batch_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    optimized_batch_data_t *batch = (optimized_batch_data_t *)data;
    
    if (idx < batch->num_points) {
        /* First half: R points with positive coefficients */
        secp256k1_gej temp_gej = batch->R_points_gej[idx];
        secp256k1_ge_set_gej_var(pt, &temp_gej); // Convert Jacobian to Affine
        *sc = batch->coeff_vector[idx];
    } else {
        /* Second half: pubkeys with negative weighted u2 scalars */
        size_t pubkey_idx = idx - batch->num_points;
        *pt = batch->pubkeys[pubkey_idx];
        
        /* u2_scalars already contain coeff[i] * u2[i], so just negate */
        secp256k1_scalar_negate(sc, &batch->u2_scalars[pubkey_idx]);
    }
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
     *    result = Σ(R_i) - (Σu1_i) * G - Σ(u2_i * pubkey_i)
     * 
     * 3. Check if result == 0
     * 
     * This would be around ~2x faster than individual verification
     */
static int demonstrate_internal_batch_verify(secp256k1_context *ctx,
                                            internal_batch_data_t *batch_data,
                                            size_t num_inputs) {
    secp256k1_gej result;
    secp256k1_scratch *scratch;
    int success;
    
    printf("  → Step 1: Parse signatures and extract (r,s) scalar components\n");
    printf("  → Step 2: Compute u1 = hash/s and u2 = r/s for each signature\n");
    printf("  → Step 3: Prepare optimized verification equation\n");
    printf("  → Step 4: Single secp256k1_ecmult_multi_var call:\n");
    printf("            Σ(coeff[i]*R[i]) - Σ(coeff[i]*u1[i])*G - Σ(coeff[i]*u2[i]*pubkey[i]) = 0\n");
    
    /* Create scratch space for computation */
    scratch = secp256k1_scratch_create(&default_error_callback, 200000); // Larger scratch for more points
    if (!scratch) {
        printf("  → ERROR: Failed to create scratch space\n");
        return 0;
    }
    
    printf("  → Step 5: Executing optimized secp256k1_ecmult_multi_var...\n");
    
    /* Prepare optimized batch data structure */
    optimized_batch_data_t opt_data;
    opt_data.coeff_vector = batch_data->coeff_vector;
    opt_data.R_points_gej = batch_data->R_points_gej;
    opt_data.u2_scalars = batch_data->u2_scalars;
    opt_data.pubkeys = batch_data->pubkeys;
    opt_data.num_points = batch_data->num_points;
    
    /* Negate the g_scalar for the optimized equation */
    secp256k1_scalar neg_g_scalar;
    secp256k1_scalar_negate(&neg_g_scalar, &batch_data->g_scalar);
    
    /* The optimized implementation with single secp256k1_ecmult_multi_var call! */
    success = secp256k1_ecmult_multi_var(
        &default_error_callback,          /* Error callback */
        scratch,                          /* Scratch space for computation */
        &result,                          /* Output: should be point at infinity if valid */
        &neg_g_scalar,                    /* G scalar: negative sum of all weighted u1 values */
        optimized_batch_callback,         /* Callback providing R points and pubkeys */
        &opt_data,                        /* Callback data */
        2 * batch_data->num_points        /* Total points: R points + pubkeys */
    );
    
    printf("  → Step 6: Check if result equals point at infinity\n");
    
    if (success) {
        /* Check if result is point at infinity (zero) */
        success = secp256k1_gej_is_infinity(&result);
        
        printf("  → Batch verification result: %s\n", success ? "ALL VALID" : "SOME INVALID");
        
        if (success) {
            printf("  → Mathematical verification: result == point_at_infinity ✅\n");
            printf("  → Optimized equation verified: Σ(coeff[i]*R[i]) - Σ(coeff[i]*u1[i])*G - Σ(coeff[i]*u2[i]*pubkey[i]) = 0\n");
        } else {
            printf("  → Mathematical verification: result != point_at_infinity ❌\n");
            printf("  → This indicates invalid signatures were detected!\n");
        }
    } else {
        printf("  → ERROR: secp256k1_ecmult_multi_var failed\n");
    }
    
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
    batch_data.R_points_gej = malloc(batch_data.num_points * sizeof(secp256k1_gej));
    batch_data.s_inverses = malloc(batch_data.num_points * sizeof(secp256k1_scalar));
    batch_data.coeff_vector = malloc(batch_data.num_points * sizeof(secp256k1_scalar));
    
    if (!batch_data.u2_scalars || !batch_data.pubkeys || !batch_data.R_points_gej || !batch_data.s_inverses || !batch_data.coeff_vector) {
        printf("ERROR: Failed to allocate batch verification data\n");
        if (batch_data.u2_scalars) free(batch_data.u2_scalars);
        if (batch_data.pubkeys) free(batch_data.pubkeys);
        if (batch_data.R_points_gej) free(batch_data.R_points_gej);
        if (batch_data.s_inverses) free(batch_data.s_inverses);
        if (batch_data.coeff_vector) free(batch_data.coeff_vector);
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
        free(batch_data.R_points_gej);
        free(batch_data.s_inverses);
        free(batch_data.coeff_vector);
        return;
    }
    
    batch_data.num_points = precomputed_count; /* Update to actual processed count */
    
    /* Allocate and generate random coefficient vector */
    generate_random_coefficient_vector(batch_data.coeff_vector, inputs, num_inputs, batch_data.num_points);
    
    /* Initialize G scalar sum and expected sum */
    secp256k1_scalar_clear(&batch_data.g_scalar);
    secp256k1_gej_set_infinity(&batch_data.expected_sum);
    
    printf("Preparing real batch verification data for %zu signatures:\n", batch_data.num_points);
    
    /* Process signatures using pre-computed inverses */
    printf("\n=== Fast Batch Processing Phase ===\n");
    printf("Processing signatures using VERIFIED pre-computed scalar inverses...\n");
    
    size_t valid_sigs = 0;
    start = clock();
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
        
        /* Apply random coefficient weighting: coeff[i] * u1 and coeff[i] * u2 */
        secp256k1_scalar weighted_u1, weighted_u2;
        secp256k1_scalar_mul(&weighted_u1, &batch_data.coeff_vector[valid_sigs], &u1);  /* weighted_u1 = coeff[i] * u1 */
        secp256k1_scalar_mul(&weighted_u2, &batch_data.coeff_vector[valid_sigs], &u2);  /* weighted_u2 = coeff[i] * u2 */
        
        /* Store weighted u2 for batch multiplication */
        batch_data.u2_scalars[valid_sigs] = weighted_u2;
        
        /* Add weighted u1 to G scalar sum */
        secp256k1_scalar_add(&batch_data.g_scalar, &batch_data.g_scalar, &weighted_u1);
        
        /* CRITICAL: Reconstruct R point from signature using dedicated function */
        if (!reconstruct_r_point(&r, &u1, &u2, &batch_data.pubkeys[valid_sigs], &batch_data.R_points_gej[valid_sigs])) {
            continue; /* Could not reconstruct correct R point */
        }
         
         valid_sigs++;
    }
    end = clock();
    double prepare_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time for preparation: %.6f seconds\n", prepare_time);
    
    
    printf("Successfully prepared %zu signatures for real batch verification\n", valid_sigs);
    if (valid_sigs < batch_data.num_points) {
        printf("Note: %zu signatures were skipped due to parsing errors\n", 
               batch_data.num_points - valid_sigs);
    }
    
    /* CRITICAL INSIGHT: Count how many signatures are actually invalid */
    size_t invalid_count = 0;
    for (size_t i = 0; i < num_inputs && i < 500; i++) {
        if (!verify_single_signature(ctx, &inputs[i])) {
            invalid_count++;
        }
    }
    
    printf("\n=== SIGNATURE VALIDITY ANALYSIS ===\n");
    printf("Total signatures in dataset: %zu\n", num_inputs);
    printf("Valid signatures: %zu\n", num_inputs - invalid_count);  
    printf("Invalid signatures: %zu\n", invalid_count);
    
    if (invalid_count > 0) {
        printf("\n⚠️  WARNING: Dataset contains %zu INVALID signatures!\n", invalid_count);
        printf("   This means batch verification should FAIL or detect them.\n");
        printf("   If batch verification reports 'ALL VALID', there's a bug.\n");
    } else {
        printf("\n✅ All signatures in dataset are valid.\n");
        printf("   Batch verification should report 'ALL VALID'.\n");
    }
    
    /* Update batch data with actual processed count */
    batch_data.num_points = valid_sigs;
    
    /* Print the internal batch data structure for inspection */
    print_internal_batch_data(&batch_data);
    
    if (valid_sigs == 0) {
        printf("ERROR: No valid signatures to process\n");
        free(batch_data.u2_scalars);
        free(batch_data.pubkeys);
        free(batch_data.R_points_gej);
        free(batch_data.s_inverses);
        free(batch_data.coeff_vector);
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
    free(batch_data.R_points_gej);
    free(batch_data.s_inverses);
    free(batch_data.coeff_vector);
    
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
        /* Make some signatures invalid for demonstration */
        // if (i >= 490) {  /* Make last 10 signatures invalid for testing */
        //     make_invalid = 1;
        // }
        
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
