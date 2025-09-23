/*************************************************************************
 * Batch Signature Verification Test Data Generator for secp256k1
 * 
 * This program demonstrates complete ECDSA signature lifecycle using secp256k1:
 * 1. Generation of cryptographic test data (keys, messages, signatures)
 * 2. Recovery of cryptographic components from signatures
 * 3. Validation of recovered components against originals
 * 
 * Key Features:
 * - Generates test datasets with configurable number of entries
 * - Creates recoverable ECDSA signatures using secp256k1
 * - Recovers all cryptographic components (public keys, scalars, R points)
 * - Uses memory-efficient flat arrays for optimal cache performance
 * - Cross-platform secure random number generation
 * 
 * Technical Implementation:
 * - Uses secp256k1 library for all cryptographic operations
 * - Implements proper memory management with flat array structures
 * - Provides comprehensive error handling and validation
 * - Demonstrates proper scalar arithmetic and point recovery
 * 
 * Recovery ID Constraints (secp256k1-specific):
 * - secp256k1_ecdsa_sign_recoverable only produces recovery_id of 0 or 1
 * - Bit 1 of recovery_id is always 0 (no support for values 2 or 3)
 * - This is because secp256k1 curve parameters ensure y-coordinate recovery
 *   never requires the higher recovery_id values used by other curves
 * 
 * Data Structures:
 * - test_data_t: Holds generated cryptographic test data using flat arrays
 * - recover_data_t: Holds recovered cryptographic components as scalars/points
 * 
 * Memory Design:
 * - Uses flat arrays instead of pointer arrays for better memory locality
 * - Simplifies allocation/deallocation with single malloc/free per array
 * - Reduces memory fragmentation and improves cache performance
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdint.h>

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
#include "src/eckey_impl.h"

/* Ensure STRAUSS_SCRATCH_OBJECTS is defined - should be 5 from ecmult_impl.h */
#ifndef STRAUSS_SCRATCH_OBJECTS
#define STRAUSS_SCRATCH_OBJECTS 5
#endif

#if defined(_WIN32)
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif

/**
 * secp256k1_pubkey_load - Load a secp256k1_pubkey into a group element
 * 
 * This function converts a secp256k1_pubkey structure to a secp256k1_ge
 * (group element) for use in internal secp256k1 operations. The function
 * provides access to the internal representation of public keys.
 * 
 * @param ctx secp256k1 context (unused but required for API consistency)
 * @param ge Output group element to store the public key
 * @param pubkey Input public key to convert
 * @return 1 on success, 0 on failure
 */
static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    secp256k1_ge_from_bytes(ge, pubkey->data);
    return 1;
}

/* Structure to hold all generated test data */
/**
 * test_data_t - Complete test dataset for ECDSA signature verification
 * 
 * This structure holds all cryptographic test data using flat arrays for
 * optimal memory performance. Each entry i corresponds to:
 * - private_keys[i*32 : (i+1)*32-1] : 32-byte private key
 * - messages[i*32 : (i+1)*32-1]     : 32-byte message hash
 * - public_keys[i]                  : secp256k1_pubkey structure
 * - serialized_signatures[i*65 : (i+1)*65-1] : 65-byte recoverable signature
 * - recovery_ids[i]                 : Recovery ID (0 or 1 for secp256k1)
 * 
 * Memory Layout Design:
 * - Flat arrays eliminate pointer indirection overhead
 * - Contiguous memory improves cache locality during batch operations
 * - Single allocation per array type simplifies memory management
 * 
 * Signature Format (65 bytes):
 * - Bytes 0-31:  r component (32 bytes, big-endian)
 * - Bytes 32-63: s component (32 bytes, big-endian) 
 * - Byte 64:     Recovery ID (stored for convenience, also in recovery_ids array)
 */
typedef struct {
    size_t num_entries;                                    /* Number of entries */
    unsigned char *private_keys;                           /* Flat array: num_entries * 32 bytes */
    unsigned char *messages;                               /* Flat array: num_entries * 32 bytes */
    secp256k1_pubkey *public_keys;                        /* Array of public keys */
    unsigned char *serialized_signatures;                 /* Flat array: num_entries * 65 bytes */
    int *recovery_ids;                                     /* Array of recovery IDs */
} test_data_t;

/* Structure to hold recovered cryptographic data */
/**
 * recover_data_t - Recovered cryptographic components from signatures
 * 
 * This structure contains all cryptographic components recovered from 
 * ECDSA signatures, converted to their mathematical representations:
 * 
 * Components:
 * - recovered_pubkeys[i] : Public key recovered from signature[i] and message[i]
 * - s_values[i]          : Signature 's' component as secp256k1_scalar
 * - z_values[i]          : Message hash as secp256k1_scalar (mod curve order n)
 * - r_points[i]          : Signature 'r' point as secp256k1_ge (group element)
 * - r_values[i]          : Signature 'r' x-coordinate as secp256k1_scalar (extracted from r_points)
 * 
 * Batch Verification Workspace (allocated only when needed):
 * - combined_r_values[i] : Workspace for r_i * a_i scalars during batch verification
 * - combined_s_values[i] : Workspace for (-s_i) * a_i scalars during batch verification
 * 
 * Mathematical Context:
 * - s_values: Direct conversion from signature bytes to scalar mod n
 * - z_values: Message interpreted as big-endian 256-bit integer, reduced mod n
 * - r_points: Recovered from (r_x, recovery_id) using curve equation
 * - r_values: x-coordinate of r_points converted to scalar mod n (for verification efficiency)
 * 
 * Recovery Process:
 * 1. Parse recoverable signature to extract (r, s, recovery_id)
 * 2. Use secp256k1_ecdsa_recover to get public key from (r, s, recovery_id, message)
 * 3. Convert 's' bytes to scalar using secp256k1_scalar_set_b32
 * 4. Convert message to scalar z using secp256k1_scalar_set_b32 with mod n reduction
 * 5. Recover R point from r_x coordinate and y-parity (recovery_id & 1)
 * 6. Extract r_x coordinate from R point and convert to scalar for verification use
 * 
 * Note on Batch Verification:
 * During batch verification (verify_in_batch), the r_values and s_values arrays
 * are modified in-place to store the combined values (r_i * a_i) and (-s_i * a_i)
 * respectively, where a_i are random coefficients. The original values are lost.
 */
typedef struct {
    size_t num_entries;                     /* Number of entries */
    secp256k1_ge *recovered_pubkeys;       /* Array of recovered public keys as group elements */
    secp256k1_scalar *s_values;            /* Array of signature 's' values as scalars */
    secp256k1_scalar *z_values;            /* Array of message hashes as scalars */
    secp256k1_ge *r_points;                /* Array of recovered R points */
    secp256k1_scalar *r_values;            /* Array of signature 'r' x-coordinates as scalars */
    unsigned char *recovery_flags;          /* Array of recovery flags (0: even y, 1: odd y) */
} recover_data_t;

/**
 * fill_random - Cross-platform cryptographically secure random number generation
 * 
 * This function provides secure random number generation across different platforms
 * using each platform's cryptographically secure random number generator (CSPRNG).
 * Critical for generating unpredictable private keys and ensuring signature security.
 * 
 * Platform-specific implementations:
 * - Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
 * - Linux/FreeBSD: getrandom() system call (uses kernel entropy pool)
 * - macOS/OpenBSD: getentropy() (secure system entropy source)
 * 
 * Security properties:
 * - Cryptographically secure (unpredictable, unbiased)
 * - Properly seeded from system entropy
 * - Suitable for cryptographic key generation
 * - Blocks if insufficient entropy available (Linux/BSD)
 * 
 * @param data Buffer to fill with random bytes
 * @param size Number of random bytes to generate
 * @return 1 on success, 0 on failure
 */
static int fill_random(unsigned char* data, size_t size) {
#if defined(_WIN32)
    NTSTATUS res = BCryptGenRandom(NULL, data, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (res != STATUS_SUCCESS || size > ULONG_MAX) {
        return 0;
    } else {
        return 1;
    }
#elif defined(__linux__) || defined(__FreeBSD__)
    ssize_t res = getrandom(data, size, 0);
    if (res < 0 || (size_t)res != size ) {
        return 0;
    } else {
        return 1;
    }
#elif defined(__APPLE__) || defined(__OpenBSD__)
    int res = getentropy(data, size);
    if (res == 0) {
        return 1;
    } else {
        return 0;
    }
#endif
    return 0;
}

/**
 * allocate_test_data - Allocate memory for test data structure
 * 
 * This function allocates all memory required for a test_data_t structure
 * and its component arrays. Uses flat array allocation for optimal memory
 * access patterns and simplified memory management.
 * 
 * Memory Allocation:
 * - Structure itself: sizeof(test_data_t)
 * - Private keys: num * 32 bytes (32 bytes per private key)
 * - Messages: num * 32 bytes (32 bytes per message hash)
 * - Public keys: num * sizeof(secp256k1_pubkey)
 * - Serialized signatures: num * 65 bytes (64 bytes + recovery_id)
 * - Recovery IDs: num * sizeof(int)
 * 
 * Error Handling:
 * If any allocation fails, all previously allocated memory is freed
 * and NULL is returned to prevent memory leaks.
 * 
 * @param num Number of test entries to allocate space for
 * @return Pointer to allocated test_data_t structure, or NULL on failure
 */
static test_data_t* allocate_test_data(size_t num) {
    test_data_t *data = malloc(sizeof(test_data_t));
    if (!data) return NULL;
    
    data->num_entries = num;
    
    /* Allocate flat arrays */
    data->private_keys = malloc(num * 32);  /* 32 bytes per private key */
    data->messages = malloc(num * 32);      /* 32 bytes per message */
    data->public_keys = malloc(num * sizeof(secp256k1_pubkey));
    data->serialized_signatures = malloc(num * 65);  /* 65 bytes per serialized signature */
    data->recovery_ids = malloc(num * sizeof(int));
    
    if (!data->private_keys || !data->messages || !data->public_keys || 
        !data->serialized_signatures || !data->recovery_ids) {
        free(data->private_keys);
        free(data->messages);
        free(data->public_keys);
        free(data->serialized_signatures);
        free(data->recovery_ids);
        free(data);
        return NULL;
    }
    
    return data;
}

/**
 * free_test_data - Free all allocated memory for test data structure
 * 
 * This function safely deallocates all memory associated with a test_data_t
 * structure, including all component arrays. Handles NULL pointers gracefully.
 * 
 * Security Note:
 * This function does not explicitly clear sensitive data (private keys)
 * before freeing. For production use, consider clearing private key memory
 * with explicit_bzero() or similar before calling free().
 * 
 * @param data Pointer to test_data_t structure to free (may be NULL)
 */
static void free_test_data(test_data_t *data) {
    if (!data) return;
    
    /* Free flat arrays directly */
    free(data->private_keys);
    free(data->messages);
    free(data->public_keys);
    free(data->serialized_signatures);
    free(data->recovery_ids);
    free(data);
}

/**
 * allocate_recover_data - Allocate memory for recover data structure
 * 
 * This function allocates all memory required for a recover_data_t structure
 * and its component arrays. Each array holds mathematical representations
 * of cryptographic components recovered from ECDSA signatures.
 * 
 * Memory Allocation:
 * - Structure itself: sizeof(recover_data_t)
 * - Recovered public keys: num * sizeof(secp256k1_ge) 
 * - S values: num * sizeof(secp256k1_scalar)
 * - Z values: num * sizeof(secp256k1_scalar)
 * - R points: num * sizeof(secp256k1_ge)
 * - R values: num * sizeof(secp256k1_scalar)
 * 
 * Error Handling:
 * If any allocation fails, all previously allocated memory is freed
 * and NULL is returned to prevent memory leaks.
 * 
 * @param num Number of recovery entries to allocate space for
 * @return Pointer to allocated recover_data_t structure, or NULL on failure
 */
static recover_data_t* allocate_recover_data(size_t num) {
    recover_data_t *data = malloc(sizeof(recover_data_t));
    if (!data) return NULL;
    
    data->num_entries = num;
    
    /* Allocate arrays */
    data->recovered_pubkeys = malloc(num * sizeof(secp256k1_ge));
    data->s_values = malloc(num * sizeof(secp256k1_scalar));
    data->z_values = malloc(num * sizeof(secp256k1_scalar));
    data->r_points = malloc(num * sizeof(secp256k1_ge));
    data->r_values = malloc(num * sizeof(secp256k1_scalar));
    data->recovery_flags = malloc(num * sizeof(unsigned char));
    
    if (!data->recovered_pubkeys || !data->s_values || !data->z_values || !data->r_points || !data->r_values || !data->recovery_flags) {
        free(data->recovered_pubkeys);
        free(data->s_values);
        free(data->z_values);
        free(data->r_points);
        free(data->r_values);
        free(data->recovery_flags);
        free(data);
        return NULL;
    }
    
    return data;
}

/**
 * free_recover_data - Free all allocated memory for recover data structure
 * 
 * This function safely deallocates all memory associated with a recover_data_t
 * structure, including all component arrays. Handles NULL pointers gracefully.
 * 
 * Security Features:
 * - Explicitly clears all scalar values before freeing memory
 * - Uses secp256k1_scalar_clear() to securely overwrite sensitive data
 * - Prevents potential information leakage from deallocated memory
 * 
 * Scalar Clearing:
 * The function clears s_values, z_values, and r_values arrays which contain
 * sensitive cryptographic material that should not remain in memory after use.
 * 
 * @param data Pointer to recover_data_t structure to free (may be NULL)
 */
static void free_recover_data(recover_data_t *data) {
    if (!data) return;
    
    /* Clear sensitive scalar data before freeing */
    if (data->s_values) {
        for (size_t i = 0; i < data->num_entries; i++) {
            secp256k1_scalar_clear(&data->s_values[i]);
        }
    }
    if (data->z_values) {
        for (size_t i = 0; i < data->num_entries; i++) {
            secp256k1_scalar_clear(&data->z_values[i]);
        }
    }
    if (data->r_values) {
        for (size_t i = 0; i < data->num_entries; i++) {
            secp256k1_scalar_clear(&data->r_values[i]);
        }
    }
    
    free(data->recovered_pubkeys);
    free(data->s_values);
    free(data->z_values);
    free(data->r_points);
    free(data->r_values);
    free(data->recovery_flags);
    free(data);
}

/**
 * recover_components - Extract and recover all cryptographic components from ECDSA signatures
 * 
 * This function implements the complete recovery process for ECDSA signatures,
 * extracting and validating all mathematical components used in the signature algorithm.
 * 
 * Algorithm Overview:
 * For each signature (r, s, recovery_id) and message z:
 * 1. Recover public key P using: P = (z/s)G + (r/s)R, where R is recovered from r
 * 2. Extract scalar s from signature bytes 32-63
 * 3. Convert message to scalar z = message mod n (curve order n)
 * 4. Recover R point from r coordinate and y-parity
 * 5. Validate recovered public key against original
 * 
 * secp256k1-Specific Implementation Details:
 * - recovery_id is always 0 or 1 (bit 1 never set due to curve properties)
 * - R point recovery uses y-parity from recovery_id bit 0
 * - No need to check for r coordinate overflow (secp256k1 field size)
 * - Scalar conversion handles automatic modular reduction
 * 
 * Error Handling:
 * - Validates all signature parsing operations
 * - Checks for scalar overflow in s and z values
 * - Verifies R point recovery from coordinates
 * - Compares recovered vs original public keys
 * 
 * @param test_data Input test data containing signatures and messages
 * @return recover_data_t* Allocated structure with recovered components, or NULL on failure
 * 
 * Memory: Caller must free returned structure using free_recover_data()
 */
recover_data_t* recover_components(const test_data_t *test_data) {
    if (!test_data) return NULL;
    
    secp256k1_context *ctx = NULL;
    recover_data_t *recover_data = NULL;
    int all_valid = 1;
    
    printf("Recovering cryptographic components from %zu signatures...\n", test_data->num_entries);
    
    /* Create secp256k1 context */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return NULL;
    }
    
    /* Allocate recover data structure */
    recover_data = allocate_recover_data(test_data->num_entries);
    if (!recover_data) {
        printf("Failed to allocate memory for recover data\n");
        goto cleanup;
    }
    
    /* Process each signature */
    for (size_t i = 0; i < test_data->num_entries; i++) {
        unsigned char *current_message = &test_data->messages[i * 32];
        unsigned char *current_serialized_sig = &test_data->serialized_signatures[i * 65];
        int recovery_id = test_data->recovery_ids[i];
        
        /* Step 1: Recover public key using secp256k1_ecdsa_recover */
        secp256k1_ecdsa_recoverable_signature recoverable_sig;
        if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
                ctx, &recoverable_sig, current_serialized_sig, recovery_id)) {
            printf("Failed to parse recoverable signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* Recover to temporary pubkey first, then convert to ge */
        secp256k1_pubkey temp_pubkey;
        if (!secp256k1_ecdsa_recover(ctx, &temp_pubkey, 
                                   &recoverable_sig, current_message)) {
            printf("Failed to recover public key %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* Convert secp256k1_pubkey to secp256k1_ge */
        if (!secp256k1_pubkey_load(ctx, &recover_data->recovered_pubkeys[i], &temp_pubkey)) {
            printf("Failed to convert public key to group element %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* Step 2: Extract 's' value from signature and convert to scalar */
        unsigned char s_bytes[32];
        memcpy(s_bytes, &current_serialized_sig[32], 32);  /* s is bytes 32-63 */
        int overflow;
        secp256k1_scalar_set_b32(&recover_data->s_values[i], s_bytes, &overflow);
        if (overflow) {
            printf("Invalid s value in signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* 
         * Step 3: Convert message to scalar z (message hash as scalar mod n)
         * 
         * ECDSA requires the message hash to be treated as a scalar in the
         * finite field defined by the curve order n. The conversion process:
         * 
         * 1. Interpret 32-byte message as big-endian 256-bit integer
         * 2. Reduce modulo n (secp256k1 curve order) to get valid scalar
         * 3. Handle potential overflow when message >= n
         * 
         * Mathematical context:
         * - n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
         * - Any 256-bit value >= n will overflow and be reduced mod n
         * - This reduction is mathematically correct for ECDSA
         */
        secp256k1_scalar_set_b32(&recover_data->z_values[i], current_message, &overflow);
        if (overflow) {
            printf("Message converted with overflow for entry %zu (reduced mod n)\n", i);
            /* This is not an error - overflow just means message >= curve_order */
        }
        
        /* Step 4: Recover R point from (r, recovery_id) */
        unsigned char r_bytes[32];
        memcpy(r_bytes, current_serialized_sig, 32);  /* r is bytes 0-31 */
        
        secp256k1_fe r_fe;
        if (!secp256k1_fe_set_b32_limit(&r_fe, r_bytes)) {
            printf("Invalid r value in signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* 
         * Verify recovery_id is valid for secp256k1 (should always be 0 or 1)
         * 
         * secp256k1-specific behavior:
         * - Bit 0: y-coordinate parity (0 = even, 1 = odd)
         * - Bit 1: Always 0 for secp256k1 (never 2 or 3)
         * 
         * This differs from generic ECDSA where recovery_id can be 0-3,
         * but secp256k1's specific parameters ensure the r coordinate
         * never requires the overflow cases that would set bit 1.
         */
        if (recovery_id > 1) {
            printf("Unexpected recovery_id %d for signature %zu (secp256k1 should only produce 0 or 1)\n", 
                   recovery_id, i);
            all_valid = 0;
            continue;
        }
        
        /* 
         * Recover the R point using x coordinate and y parity
         * 
         * Process:
         * 1. Use r_fe as x-coordinate of point R
         * 2. Calculate y-coordinate using curve equation: y² = x³ + 7
         * 3. Choose y or -y based on parity bit (recovery_id & 1)
         * 4. secp256k1_ge_set_xo_var handles the mathematical details
         */
        if (!secp256k1_ge_set_xo_var(&recover_data->r_points[i], &r_fe, recovery_id & 1)) {
            printf("Failed to recover R point for signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* Fill recovery flag from parity of R.y (0 for even, 1 for odd) */
        if (recover_data->recovery_flags) {
            recover_data->recovery_flags[i] = (unsigned char)(secp256k1_fe_is_odd(&recover_data->r_points[i].y) ? 1 : 0);
        }
        
        /* 
         * Step 5: Extract r value (x-coordinate) as scalar for verification efficiency
         * 
         * Convert the x-coordinate of the R point to a scalar for use in verification.
         * This avoids having to re-extract it later in batch verification.
         */
        secp256k1_scalar_set_b32(&recover_data->r_values[i], r_bytes, &overflow);
        if (overflow) {
            printf("Invalid r value in signature %zu (r >= curve order)\n", i);
            all_valid = 0;
            continue;
        }
        
        if (secp256k1_scalar_is_zero(&recover_data->r_values[i])) {
            printf("Invalid r value in signature %zu (r is zero)\n", i);
            all_valid = 0;
            continue;
        }
        
        if ((i + 1) % 100 == 0 || i == test_data->num_entries - 1) {
            printf("Processed %zu/%zu signatures\n", i + 1, test_data->num_entries);
        }
    }
    
    /* Step 6: Compare recovered public keys with original public keys */
    printf("Comparing recovered public keys with originals...\n");
    size_t mismatches = 0;
    for (size_t i = 0; i < test_data->num_entries; i++) {
        /* Convert original pubkey to ge for comparison */
        secp256k1_ge original_ge;
        if (!secp256k1_pubkey_load(ctx, &original_ge, &test_data->public_keys[i])) {
            printf("Failed to convert original public key to group element at index %zu\n", i);
            mismatches++;
            all_valid = 0;
            continue;
        }
        
        /* Compare the group elements */
        if (!secp256k1_ge_eq_var(&recover_data->recovered_pubkeys[i], &original_ge)) {
            printf("Public key mismatch at index %zu\n", i);
            mismatches++;
            all_valid = 0;
        }
    }
    
    if (mismatches > 0) {
        printf("Found %zu public key mismatches out of %zu signatures\n", 
               mismatches, test_data->num_entries);
    } else {
        printf("All recovered public keys match the originals!\n");
    }
    
    if (!all_valid) {
        printf("Some recovery operations failed or had mismatches\n");
        free_recover_data(recover_data);
        recover_data = NULL;
    } else {
        printf("All recovery operations completed successfully!\n");
    }
    
cleanup:
    if (ctx) secp256k1_context_destroy(ctx);
    return recover_data;
}

/**
 * print_recover_data_summary - Display comprehensive summary of recovered cryptographic data
 * 
 * This function provides a detailed overview of the recover_data_t structure,
 * including memory usage statistics and example data from the first entry.
 * Useful for debugging and understanding the recovered cryptographic components.
 * 
 * Information Displayed:
 * - Total number of entries processed
 * - Memory usage breakdown by component type
 * - Total memory consumption in bytes and megabytes
 * - Example data from the first entry (first 8 bytes of each scalar)
 * - Validation of R point integrity
 * 
 * Output Format:
 * The function formats output in a clear, readable summary with section headers
 * and consistent formatting for easy interpretation of the data.
 * 
 * @param data Pointer to recover_data_t structure to summarize (may be NULL)
 */
void print_recover_data_summary(const recover_data_t *data) {
    if (!data) return;
    
    printf("\n=== Recovery Data Summary ===\n");
    printf("Number of entries: %zu\n", data->num_entries);
    printf("Memory usage:\n");
    printf("  Recovered public keys: %zu bytes\n", data->num_entries * sizeof(secp256k1_ge));
    printf("  S scalars: %zu bytes\n", data->num_entries * sizeof(secp256k1_scalar));
    printf("  Z scalars: %zu bytes\n", data->num_entries * sizeof(secp256k1_scalar));
    printf("  R points: %zu bytes\n", data->num_entries * sizeof(secp256k1_ge));
    printf("  R scalars: %zu bytes\n", data->num_entries * sizeof(secp256k1_scalar));
    
    size_t total_size = data->num_entries * (2 * sizeof(secp256k1_ge) + 
                       3 * sizeof(secp256k1_scalar));
    printf("  Total: %zu bytes (%.2f MB)\n", total_size, (double)total_size / (1024 * 1024));
    
    if (data->num_entries > 0) {
        printf("\nFirst entry example:\n");
        
        /* Print first few bytes of s scalar */
        printf("  S scalar[0]: ");
        unsigned char s_bytes[32];
        secp256k1_scalar_get_b32(s_bytes, &data->s_values[0]);
        for (int i = 0; i < 8; i++) printf("%02x", s_bytes[i]);
        printf("...\n");
        
        /* Print first few bytes of z scalar */
        printf("  Z scalar[0]: ");
        unsigned char z_bytes[32];
        secp256k1_scalar_get_b32(z_bytes, &data->z_values[0]);
        for (int i = 0; i < 8; i++) printf("%02x", z_bytes[i]);
        printf("...\n");
        
        /* Print first few bytes of r scalar */
        printf("  R scalar[0]: ");
        unsigned char r_bytes[32];
        secp256k1_scalar_get_b32(r_bytes, &data->r_values[0]);
        for (int i = 0; i < 8; i++) printf("%02x", r_bytes[i]);
        printf("...\n");
        
        /* Print R point info */
        printf("  R point[0]: %s\n", secp256k1_ge_is_infinity(&data->r_points[0]) ? "infinity" : "valid point");
    }
    printf("=============================\n\n");
}

/**
 * sanity_check - Comprehensive validation of recovered cryptographic components
 * 
 * This function performs rigorous mathematical validation of all components
 * in the recover_data_t structure to ensure they satisfy secp256k1 curve
 * constraints and ECDSA signature validity requirements.
 * 
 * Validation Checks:
 * 1. R points: Valid curve points (on secp256k1 curve, not infinity)
 * 2. Q points: Valid curve points (proper public keys, not infinity)
 * 3. z values: 0 <= z < n (message hashes as valid scalars)
 * 4. r values: 1 <= r < n (extracted from R point x-coordinates)
 * 5. s values: 1 <= s < n/2 (canonical s values, low-s requirement)
 * 
 * Where n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * is the order of the secp256k1 base point G.
 * 
 * Mathematical Context:
 * - R points must lie on the secp256k1 curve: y² = x³ + 7 (mod p)
 * - Q points (public keys) must be valid curve points and not the point at infinity
 * - z values are message hashes reduced modulo n (can be 0)
 * - r values are x-coordinates of R points, must be non-zero and < n
 * - s values must be canonical (< n/2) to prevent signature malleability
 * 
 * @param data Recovered cryptographic data to validate
 * @return 1 if all validations pass, 0 if any validation fails
 */
int sanity_check(const recover_data_t *data) {
    if (!data) {
        printf("sanity_check: NULL data pointer\n");
        return 0;
    }
    
    printf("Performing sanity check on %zu recovered entries...\n", data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("sanity_check: Failed to create secp256k1 context\n");
        return 0;
    }
    
    int all_valid = 1;
    
    for (size_t i = 0; i < data->num_entries && all_valid; i++) {
        /* Check 1: Validate R points are valid curve points */
        if (!secp256k1_ge_is_valid_var(&data->r_points[i])) {
            printf("sanity_check: Invalid R point at index %zu (not on curve)\n", i);
            all_valid = 0;
            break;
        }
        
        if (secp256k1_ge_is_infinity(&data->r_points[i])) {
            printf("sanity_check: R point is infinity at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        /* Bind r to R: require r == x(R) mod n */
        {
            secp256k1_fe x_fe = data->r_points[i].x;
            unsigned char x_bytes[32];
            secp256k1_scalar r_from_R;
            int overflow_r_from_R;
            secp256k1_fe_normalize_var(&x_fe);
            secp256k1_fe_get_b32(x_bytes, &x_fe);
            secp256k1_scalar_set_b32(&r_from_R, x_bytes, &overflow_r_from_R);
            if (!secp256k1_scalar_eq(&r_from_R, &data->r_values[i])) {
                printf("sanity_check: r does not match x(R) mod n at index %zu\n", i);
                all_valid = 0;
                break;
            }
        }

        /* Check 2: Validate Q points (pubkeys) are valid curve points */
        if (!secp256k1_ge_is_valid_var(&data->recovered_pubkeys[i])) {
            printf("sanity_check: Invalid Q point (pubkey) at index %zu (not on curve)\n", i);
            all_valid = 0;
            break;
        }
        
        if (secp256k1_ge_is_infinity(&data->recovered_pubkeys[i])) {
            printf("sanity_check: Q point is infinity at index %zu\n", i);
            all_valid = 0;
            break;
        }

        /* Check recovery_flags[i] matches parity of R.y */
        if (data->recovery_flags) {
            unsigned char expected = (unsigned char)(secp256k1_fe_is_odd(&data->r_points[i].y) ? 1 : 0);
            if (data->recovery_flags[i] != expected) {
                printf("sanity_check: recovery_flags[%zu]=%u does not match R.y parity (%u)\n", i, data->recovery_flags[i], expected);
                all_valid = 0;
                break;
            }
        }
        
        /* Check 3: Validate z values (0 <= z < n) */
        /* Scalars are automatically reduced mod n when created via secp256k1_scalar_set_b32,
         * so any valid scalar satisfies 0 <= z < n. z can legitimately be 0. */
        
        /* Check 4: Validate r values (1 <= r < n) */
        /* Use pre-computed r values from recovery process */
        if (secp256k1_scalar_is_zero(&data->r_values[i])) {
            printf("sanity_check: r value is zero at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        /* Check 5: Validate s values (1 <= s < n/2) */
        if (secp256k1_scalar_is_zero(&data->s_values[i])) {
            printf("sanity_check: s value is zero at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        if (secp256k1_scalar_is_high(&data->s_values[i])) {
            printf("sanity_check: s value is not canonical (>= n/2) at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        if ((i + 1) % 1000 == 0 || i == data->num_entries - 1) {
            printf("Validated %zu/%zu entries\n", i + 1, data->num_entries);
        }
    }
    
    secp256k1_context_destroy(ctx);
    
    if (all_valid) {
        printf("All sanity checks passed! All cryptographic components are mathematically valid.\n");
    } else {
        printf("Sanity check failed! Invalid cryptographic components detected.\n");
    }
    
    return all_valid;
}

/**
 * verify_one_by_one - Verify signatures using the z*G + r*Q - s*R = 0 formula
 * 
 * This function verifies ECDSA signatures by directly computing the equation
 * z*G + r*Q - s*R = 0 using secp256k1's internal multi-scalar multiplication.
 * 
 * Mathematical Background:
 * The ECDSA verification equation can be rearranged as:
 * z*G + r*Q - s*R = 0 (point at infinity)
 * 
 * Where:
 * - z: message hash as scalar
 * - G: secp256k1 generator point  
 * - r: x-coordinate of R point as scalar
 * - Q: public key point
 * - s: signature s component as scalar
 * - R: signature R point
 * 
 * Implementation:
 * Uses secp256k1_ecmult_multi_var with three terms:
 * 1. z * G (generator multiplication)
 * 2. r * Q (public key multiplication) 
 * 3. (-s) * R (R point multiplication with negated s)
 * 
 * @param test_data Original test data containing public keys
 * @param recover_data Recovered cryptographic components to verify
 * @return 1 if all signatures verify, 0 if any verification fails
 */

/**
 * ecmult_multi_data - Callback data structure for secp256k1_ecmult_multi_var
 * 
 * This structure provides context data for the ecmult_multi_callback function
 * used during individual signature verification. It contains references to
 * all the cryptographic components needed for computing z*G + r*Q - s*R = 0.
 * 
 * Components:
 * - r_values: Array of signature 'r' x-coordinates as scalars
 * - s_values: Array of signature 's' components as scalars  
 * - q_points: Array of public key points (recovered from signatures)
 * - r_points: Array of signature R points
 * - current_index: Index of the signature currently being verified
 * 
 * Usage:
 * This structure is passed to secp256k1_ecmult_multi_var via the callback
 * mechanism to provide the scalar coefficients and points for multi-scalar
 * multiplication during ECDSA verification.
 */
typedef struct {
    const secp256k1_scalar *r_values;  
    const secp256k1_scalar *s_values;
    const secp256k1_ge *q_points;
    const secp256k1_ge *r_points;
    size_t current_index;
} ecmult_multi_data;

/**
 * ecmult_multi_callback - Callback function for secp256k1_ecmult_multi_var
 * 
 * This callback provides scalar coefficients and points for multi-scalar
 * multiplication during individual ECDSA signature verification. It implements
 * the verification equation z*G + r*Q - s*R = 0 by providing:
 * - Term 0: r * Q (public key multiplication)
 * - Term 1: (-s) * R (R point multiplication with negated s)
 * 
 * The z*G term is handled separately by secp256k1_ecmult_multi_var.
 * 
 * Mathematical Context:
 * This supports individual signature verification using the rearranged ECDSA equation:
 * z*G + r*Q - s*R = 0 (point at infinity)
 * 
 * Where for the current signature:
 * - z: message hash as scalar (handled separately)
 * - r: x-coordinate of R point as scalar  
 * - Q: public key point
 * - s: signature s component as scalar
 * - R: signature R point
 * 
 * @param sc Output scalar coefficient for the current term
 * @param pt Output point for the current term  
 * @param idx Term index (0 for r*Q, 1 for (-s)*R)
 * @param data Pointer to ecmult_multi_data structure with signature components
 * @return 1 on success, 0 on failure
 */
static int ecmult_multi_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    ecmult_multi_data *cb_data = (ecmult_multi_data *)data;
    
    switch (idx) {
        case 0: /* r * Q */
            *sc = cb_data->r_values[cb_data->current_index];
            *pt = cb_data->q_points[cb_data->current_index];
            return 1;
            
        case 1: /* (-s) * R */
            secp256k1_scalar_negate(sc, &cb_data->s_values[cb_data->current_index]);
            *pt = cb_data->r_points[cb_data->current_index];
            return 1;
            
        default:
            return 0;
    }
}

int verify_one_by_one(const test_data_t *test_data, const recover_data_t *recover_data) {
    if (!test_data || !recover_data) {
        printf("verify_one_by_one: NULL data pointer\n");
        return 0;
    }
    
    if (test_data->num_entries != recover_data->num_entries) {
        printf("verify_one_by_one: Entry count mismatch\n");
        return 0;
    }
    
    printf("Verifying %zu signatures using z*G + r*Q - s*R = 0 formula...\n", recover_data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("verify_one_by_one: Failed to create secp256k1 context\n");
        return 0;
    }

    /* Calculate scratch size - verify_one_by_one always uses Strauss (2 terms < ECMULT_PIPPENGER_THRESHOLD) */
    size_t num_terms = 2; /* 2 terms per signature: r*Q and (-s)*R */
    size_t scratch_size = secp256k1_strauss_scratch_size(num_terms) + STRAUSS_SCRATCH_OBJECTS*16;
    secp256k1_scratch *scratch = secp256k1_scratch_create(secp256k1_default_error_callback_fn, scratch_size);
    if (!scratch) {
        printf("verify_one_by_one: Failed to create scratch space\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    
    /* Set up callback data - use pre-computed r_values from recover_data */
    ecmult_multi_data cb_data = {
        .r_values = recover_data->r_values,
        .s_values = recover_data->s_values,
        .q_points = recover_data->recovered_pubkeys,
        .r_points = recover_data->r_points,
        .current_index = 0
    };
    
    int all_valid = 1;
    size_t verification_failures = 0;
    
    /* Verify each signature */
    for (size_t i = 0; i < recover_data->num_entries && all_valid; i++) {
        cb_data.current_index = i;
        
        secp256k1_gej result_gej;
        
        /* Compute z*G + r*Q + (-s)*R using multi-scalar multiplication */
        secp256k1_scalar *z_current = &recover_data->z_values[i];
        int ret = secp256k1_ecmult_multi_var(secp256k1_default_error_callback_fn, scratch, &result_gej, 
                                           z_current, ecmult_multi_callback, &cb_data, 2);
        if (!ret) {
            printf("verify_one_by_one: Multi-scalar multiplication failed at index %zu\n", i);
            verification_failures++;
            all_valid = 0;
            continue;
        }
        
        /* Check if result is point at infinity (representing zero) */
        if (!secp256k1_gej_is_infinity(&result_gej)) {
            printf("verify_one_by_one: Signature verification failed at index %zu (result not infinity)\n", i);
            verification_failures++;
            all_valid = 0;
            continue;
        }
        
        /* Progress reporting for large datasets */
        if ((i + 1) % 1000 == 0 || i == recover_data->num_entries - 1) {
            printf("Verified %zu/%zu signatures\n", i + 1, recover_data->num_entries);
        }
    }
    
    secp256k1_scratch_destroy(secp256k1_default_error_callback_fn, scratch);
    secp256k1_context_destroy(ctx);
    
    if (all_valid) {
        printf("All %zu signatures verified successfully using z*G + r*Q - s*R = 0!\n", recover_data->num_entries);
    } else {
        printf("Signature verification failed! %zu out of %zu signatures failed verification.\n", 
               verification_failures, recover_data->num_entries);
    }
    
    return all_valid;
}

/**
 * verify_sig_one_by_one - Verify all signatures in test data using standard ECDSA verification
 * 
 * This function provides an independent validation method for all signatures in the
 * test dataset using the standard secp256k1_ecdsa_verify function. It serves as a
 * comprehensive check to ensure all generated signatures are mathematically valid.
 * 
 * Verification Process:
 * For each signature in the test data:
 * 1. Extract the 64-byte signature (r||s) from the 65-byte serialized format
 * 2. Parse the signature using secp256k1_ecdsa_signature_parse_compact
 * 3. Verify the signature against the message and public key using secp256k1_ecdsa_verify
 * 4. Report any verification failures with detailed error information
 * 
 * Signature Format Handling:
 * - Input: 65-byte serialized signature (r||s||recovery_id)
 * - Extracted: 64-byte compact signature (r||s) for verification
 * - The recovery_id byte is ignored for standard verification
 * 
 * Mathematical Context:
 * Standard ECDSA verification checks that for signature (r,s), message z, and public key Q:
 * - u1 = z * s^(-1) mod n
 * - u2 = r * s^(-1) mod n  
 * - (x, y) = u1*G + u2*Q
 * - Verification succeeds if x ≡ r (mod n)
 * 
 * @param data Test data containing signatures, messages, and public keys to verify
 * @return 1 if all signatures verify successfully, 0 if any verification fails
 */
int verify_sig_one_by_one(const test_data_t *data) {
    if (!data) {
        printf("verify_sig_one_by_one: NULL data pointer\n");
        return 0;
    }
    
    printf("Verifying %zu signatures one by one using standard ECDSA verification...\n", data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("verify_sig_one_by_one: Failed to create secp256k1 context\n");
        return 0;
    }
    
    int all_valid = 1;
    size_t verification_failures = 0;
    
    for (size_t i = 0; i < data->num_entries && all_valid; i++) {
        /* Extract components for current entry */
        unsigned char *current_message = &data->messages[i * 32];
        unsigned char *current_serialized_sig = &data->serialized_signatures[i * 65];
        const secp256k1_pubkey *current_pubkey = &data->public_keys[i];
        
        /* 
         * Extract 64-byte signature from 65-byte serialized format
         * Format: [r (32 bytes)][s (32 bytes)][recovery_id (1 byte)]
         * We need only the first 64 bytes for standard verification
         */
        unsigned char signature_64[64];
        memcpy(signature_64, current_serialized_sig, 64);
        
        /* Parse the compact signature */
        secp256k1_ecdsa_signature signature;
        if (!secp256k1_ecdsa_signature_parse_compact(ctx, &signature, signature_64)) {
            printf("verify_sig_one_by_one: Failed to parse signature at index %zu\n", i);
            verification_failures++;
            all_valid = 0;
            continue;
        }
        
        /* Verify the signature against message and public key */
        int verify_result = secp256k1_ecdsa_verify(ctx, &signature, current_message, current_pubkey);
        if (!verify_result) {
            printf("verify_sig_one_by_one: Signature verification failed at index %zu\n", i);
            verification_failures++;
            all_valid = 0;
            continue;
        }
        
        /* Progress reporting for large datasets */
        if ((i + 1) % 1000 == 0 || i == data->num_entries - 1) {
            printf("Verified %zu/%zu signatures\n", i + 1, data->num_entries);
        }
    }
    
    secp256k1_context_destroy(ctx);
    
    if (all_valid) {
        printf("All %zu signatures verified successfully using standard ECDSA verification!\n", data->num_entries);
    } else {
        printf("Signature verification failed! %zu out of %zu signatures failed verification.\n", 
               verification_failures, data->num_entries);
    }
    
    return all_valid;
}

/**
 * lookup_ecrecover - Check the i-th entry matches (r,s,v,z) and return Q if so
 * 
 * This function compares the provided 32-byte big-endian r, s, z and 1-byte v
 * against the i-th entry in recover_data_t. If all match, it returns a pointer
 * to the corresponding recovered public key Q_i. Otherwise, returns NULL.
 *
 * Notes:
 * - r, s, z are parsed with secp256k1_scalar_set_b32 (mod n). This must match
 *   how values were stored in recover_data_t.
 * - If recover_data_t->recovery_flags is present, v is compared to that value;
 *   otherwise v is computed on-the-fly as parity(R_i.y).
 * - If verify_in_batch has already been called on this recover_data_t, the
 *   r_values and s_values may have been overwritten with combined terms and
 *   will no longer match the original r, s.
 */
const secp256k1_ge* lookup_ecrecover(
    const recover_data_t* rd,
    size_t i,
    const unsigned char r_be32[32],
    const unsigned char s_be32[32],
    unsigned char v,
    const unsigned char z_be32[32]
) {
    if (!rd || i >= rd->num_entries || !r_be32 || !s_be32 || !z_be32) {
        return NULL;
    }

    int overflow = 0;
    secp256k1_scalar r_in, s_in, z_in;
    secp256k1_scalar_set_b32(&r_in, r_be32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&r_in)) return NULL;
    secp256k1_scalar_set_b32(&s_in, s_be32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s_in)) return NULL;
    secp256k1_scalar_set_b32(&z_in, z_be32, &overflow);
    if (overflow) return NULL;

    unsigned char v_i;
    if (rd->recovery_flags) {
        v_i = rd->recovery_flags[i];
    } else {
        v_i = (unsigned char)(secp256k1_fe_is_odd(&rd->r_points[i].y) ? 1 : 0);
    }
    if (v_i != v) return NULL;

    if (!secp256k1_scalar_eq(&r_in, &rd->r_values[i])) return NULL;
    if (!secp256k1_scalar_eq(&s_in, &rd->s_values[i])) return NULL;
    if (!secp256k1_scalar_eq(&z_in, &rd->z_values[i])) return NULL;

    return &rd->recovered_pubkeys[i];
}

/**
 * generate_test_data - Generate complete cryptographic test dataset for ECDSA verification
 * 
 * This function creates a comprehensive test dataset containing all components
 * needed for ECDSA signature verification and recovery testing. The generation
 * process follows cryptographic best practices for secure key and signature creation.
 * 
 * Generation Process:
 * 1. Create cryptographically secure secp256k1 context with randomization
 * 2. For each entry (0 to num-1):
 *    a. Generate cryptographically secure random private key
 *    b. Validate private key using secp256k1_ec_seckey_verify
 *    c. Generate random 32-byte message hash
 *    d. Derive public key from private key using EC point multiplication
 *    e. Create recoverable ECDSA signature for message using private key
 *    f. Serialize signature to 65-byte format (64 bytes + recovery_id)
 * 
 * Data Organization:
 * - All data stored in flat arrays for optimal memory access patterns
 * - Private keys: 32 bytes each, stored sequentially
 * - Messages: 32 bytes each (simulating hash outputs)
 * - Public keys: secp256k1_pubkey structures
 * - Signatures: 65 bytes each (r||s||recovery_id format)
 * - Recovery IDs: Integer array for quick access
 * 
 * Security Considerations:
 * - Uses platform-specific secure random number generation
 * - Context randomization for side-channel attack protection
 * - Proper private key validation before use
 * - Deterministic signature creation (no additional entropy)
 * 
 * secp256k1 Signature Properties:
 * - Generated signatures always have recovery_id of 0 or 1
 * - Recovery enables public key reconstruction from signature + message
 * - Signature format compatible with Bitcoin and Ethereum standards
 * 
 * @param num Number of test entries to generate
 * @return test_data_t* Allocated structure with generated data, or NULL on failure
 * 
 * Memory: Caller must free returned structure using free_test_data()
 * Performance: O(num) time complexity, optimized for large datasets
 */
test_data_t* generate_test_data(size_t num) {
    secp256k1_context *ctx = NULL;
    test_data_t *data = NULL;
    unsigned char randomize[32];
    int ret;
    
    printf("Generating test data for %zu entries...\n", num);
    
    /* Create secp256k1 context */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return NULL;
    }
    
    /* Randomize context for side-channel protection */
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness for context\n");
        goto cleanup;
    }
    ret = secp256k1_context_randomize(ctx, randomize);
    assert(ret);
    
    /* Allocate data structure */
    data = allocate_test_data(num);
    if (!data) {
        printf("Failed to allocate memory for test data\n");
        goto cleanup;
    }
    
    /* Generate all the data */
    for (size_t i = 0; i < num; i++) {
        /* Calculate offsets for flat arrays */
        unsigned char *current_private_key = &data->private_keys[i * 32];
        unsigned char *current_message = &data->messages[i * 32];
        unsigned char *current_serialized_sig = &data->serialized_signatures[i * 65];
        
        /* Generate private key */
        do {
            if (!fill_random(current_private_key, 32)) {
                printf("Failed to generate randomness for private key %zu\n", i);
                goto cleanup;
            }
        } while (!secp256k1_ec_seckey_verify(ctx, current_private_key));
        
        /* Generate random message hash */
        if (!fill_random(current_message, 32)) {
            printf("Failed to generate randomness for message %zu\n", i);
            goto cleanup;
        }
        
        /* Derive public key from private key */
        ret = secp256k1_ec_pubkey_create(ctx, &data->public_keys[i], current_private_key);
        if (!ret) {
            printf("Failed to create public key %zu\n", i);
            goto cleanup;
        }
        
        /* Create recoverable signature */
        secp256k1_ecdsa_recoverable_signature temp_signature;
        ret = secp256k1_ecdsa_sign_recoverable(ctx, &temp_signature, 
                                             current_message, current_private_key, 
                                             NULL, NULL);
        if (!ret) {
            printf("Failed to create recoverable signature %zu\n", i);
            goto cleanup;
        }
        
        /* Serialize recoverable signature to 65 bytes (64 bytes + recovery ID) */
        ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx, current_serialized_sig, &data->recovery_ids[i], &temp_signature);
        if (!ret) {
            printf("Failed to serialize recoverable signature %zu\n", i);
            goto cleanup;
        }
        
        /* Store recovery ID in the 65th byte for convenience */
        current_serialized_sig[64] = (unsigned char)data->recovery_ids[i];
        
        if ((i + 1) % 100 == 0 || i == num - 1) {
            printf("Generated %zu/%zu entries\n", i + 1, num);
        }
    }
    
    printf("Successfully generated all test data!\n");
    secp256k1_context_destroy(ctx);
    return data;
    
cleanup:
    if (ctx) secp256k1_context_destroy(ctx);
    if (data) free_test_data(data);
    return NULL;
}

/**
 * print_test_data_summary - Display comprehensive summary of generated test data
 * 
 * This function provides a detailed overview of the test_data_t structure,
 * including memory usage statistics and example data from the first entry.
 * Useful for verifying test data generation and understanding data layout.
 * 
 * Information Displayed:
 * - Total number of entries generated
 * - Memory usage breakdown by component type
 * - Total memory consumption in bytes and megabytes
 * - Example data from the first entry (partial private key, message, recovery ID)
 * 
 * Output Format:
 * The function formats output in a clear, readable summary with section headers
 * and consistent formatting for easy interpretation of the generated data.
 * 
 * Security Note:
 * Only displays partial private key data (first 8 bytes) for security reasons,
 * providing enough information for verification without exposing full keys.
 * 
 * @param data Pointer to test_data_t structure to summarize (may be NULL)
 */
void print_test_data_summary(const test_data_t *data) {
    if (!data) return;
    
    printf("\n=== Test Data Summary ===\n");
    printf("Number of entries: %zu\n", data->num_entries);
    printf("Memory usage:\n");
    printf("  Private keys: %zu bytes\n", data->num_entries * 32);
    printf("  Messages: %zu bytes\n", data->num_entries * 32);
    printf("  Public keys: %zu bytes\n", data->num_entries * sizeof(secp256k1_pubkey));
    printf("  Serialized signatures: %zu bytes\n", data->num_entries * 65);
    printf("  Recovery IDs: %zu bytes\n", data->num_entries * sizeof(int));
    
    size_t total_size = data->num_entries * (32 + 32 + sizeof(secp256k1_pubkey) + 65 + sizeof(int));
    printf("  Total: %zu bytes (%.2f MB)\n", total_size, (double)total_size / (1024 * 1024));
    
    if (data->num_entries > 0) {
        printf("\nFirst entry example:\n");
        printf("  Private key: ");
        for (int i = 0; i < 8; i++) printf("%02x", data->private_keys[i]);
        printf("...\n");
        printf("  Message: ");
        for (int i = 0; i < 8; i++) printf("%02x", data->messages[i]);
        printf("...\n");
        printf("  Recovery ID: %d\n", data->recovery_ids[0]);
    }
    printf("========================\n\n");
}

#include "verify_in_batch.c"

/* Convert recover_data_t into a newly allocated array of secp256k1_batch_entry.
 * Caller must free(*entries_out) with free(). Returns 1 on success, 0 on failure. */
static int recover_data_to_entries(
    const recover_data_t* rd,
    secp256k1_batch_entry** entries_out,
    size_t* n_out
) {
    if (!rd || !entries_out || !n_out || rd->num_entries == 0) {
        return 0;
    }

    size_t n = rd->num_entries;
    secp256k1_batch_entry* entries = (secp256k1_batch_entry*)malloc(n * sizeof(*entries));
    if (!entries) {
        return 0;
    }

    for (size_t i = 0; i < n; i++) {
        size_t len;

        /* Q65: serialize recovered_pubkeys[i] to uncompressed (65 bytes) */
        len = 65;
        if (!secp256k1_eckey_pubkey_serialize(&rd->recovered_pubkeys[i], entries[i].Q65, &len, 0)) {
            free(entries);
            return 0;
        }
        if (len != 65) { free(entries); return 0; }

        /* R65: serialize r_points[i] to uncompressed (65 bytes) */
        len = 65;
        if (!secp256k1_eckey_pubkey_serialize(&rd->r_points[i], entries[i].R65, &len, 0)) {
            free(entries);
            return 0;
        }
        if (len != 65) { free(entries); return 0; }

        /* r32, s32, z32: export scalars to big-endian 32-byte */
        secp256k1_scalar_get_b32(entries[i].r32, &rd->r_values[i]);
        secp256k1_scalar_get_b32(entries[i].s32, &rd->s_values[i]);
        secp256k1_scalar_get_b32(entries[i].z32, &rd->z_values[i]);

        /* v: parity of R.y (or use precomputed recovery_flags if present) */
        if (rd->recovery_flags) {
            entries[i].v = rd->recovery_flags[i] ? 1 : 0;
        } else {
            entries[i].v = (unsigned char)(secp256k1_fe_is_odd(&rd->r_points[i].y) ? 1 : 0);
        }
    }

    *entries_out = entries;
    *n_out = n;
    return 1;
}

/**
 * compare_verification_performance - Benchmark library batch API path
 */
void compare_verification_performance(const recover_data_t *recover_data) {
    if (!recover_data) {
        printf("compare_verification_performance: Invalid input data\n");
        return;
    }

    /* Prepare entries via converter */
    secp256k1_batch_entry *entries = NULL;
    size_t n = 0;
    if (!recover_data_to_entries(recover_data, &entries, &n)) {
        printf("compare_verification_performance: Failed to build entries\n");
        return;
    }

    /* Create a context required by secp256k1_verify_in_batch */
    const secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("compare_verification_performance: Failed to create context\n");
        free(entries);
        return;
    }

    unsigned char mult_bytes[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };

    printf("\n=== Performance: Library batch API ===\n");
    clock_t start = clock();
    int ok = secp256k1_verify_in_batch(ctx, entries, n, mult_bytes);
    clock_t end = clock();
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("   Result: %s\n", ok ? "PASS" : "FAIL");
    printf("   Time: %.6f seconds\n", cpu_time_used);
    if (n > 0) {
        printf("   Time per signature: %.6f ms\n\n", (cpu_time_used * 1000.0) / n);
    }

    secp256k1_context_destroy((secp256k1_context*)ctx);
    free(entries);
}

/**
 * main - Demonstration program for ECDSA signature generation and recovery
 * 
 * This program demonstrates the complete ECDSA signature lifecycle:
 * 1. Generate test dataset with specified number of entries
 * 2. Create recoverable signatures for all test messages
 * 3. Recover all cryptographic components from the signatures
 * 4. Validate that recovered components match the originals
 * 5. Display comprehensive statistics and examples
 * 
 * Program Flow:
 * - Parse command line arguments for dataset size
 * - Generate cryptographically secure test data
 * - Perform component recovery and validation
 * - Display memory usage and performance statistics
 * - Show example data for verification
 * - Clean up all allocated memory
 * 
 * Usage: ./batch_verifier [num_entries]
 * Example: ./batch_verifier 5000
 * 
 * Performance Characteristics:
 * - Linear time complexity: O(n) for n signatures
 * - Memory usage: ~200 bytes per signature entry
 * - Optimized for batch processing with flat arrays
 * 
 * @param argc Argument count
 * @param argv Argument vector (argv[1] = optional number of entries)
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on error
 */
int main(int argc, char *argv[]) {
    size_t num_entries = 1000;  /* Default number of entries */
    
    /* Parse command line argument for number of entries */
    if (argc > 1) {
        num_entries = (size_t)atoi(argv[1]);
        if (num_entries == 0) {
            printf("Usage: %s [num_entries]\n", argv[0]);
            printf("Example: %s 5000\n", argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    printf("Starting test data generation with %zu entries...\n\n", num_entries);
    
    /* Generate test data */
    test_data_t *data = generate_test_data(num_entries);
    if (!data) {
        printf("Failed to generate test data\n");
        return EXIT_FAILURE;
    }
    
    /* Print summary of generated data */
    print_test_data_summary(data);
    
    /* Verify all signatures using standard ECDSA verification */
    if (!verify_sig_one_by_one(data)) {
        printf("Initial signature verification failed - cleaning up and exiting\n");
        free_test_data(data);
        return EXIT_FAILURE;
    }
    
    /* Recover cryptographic components from the signatures */
    recover_data_t *recover_data = recover_components(data);
    if (!recover_data) {
        printf("Failed to recover cryptographic components\n");
        free_test_data(data);
        return EXIT_FAILURE;
    }
    
    /* Print summary of recovered data */
    print_recover_data_summary(recover_data);
    
    /* Run performance comparison benchmarks (v2 first to avoid in-place mutation) */
    compare_verification_performance(recover_data);
    
    /* Clean up recover data */
    free_recover_data(recover_data);
    
    /* Access examples - showing how to use the generated data */
    printf("\n=== Usage Examples ===\n");
    if (data->num_entries > 0) {
        printf("Example: Accessing first entry:\n");
        printf("  Private key[0]: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", data->private_keys[i]);
        }
        printf("\n");
        
        printf("  Message[0]: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", data->messages[i]);
        }
        printf("\n");
        
        printf("  Serialized signature[0]: ");
        for (int i = 0; i < 65; i++) {
            printf("%02x", data->serialized_signatures[i]);
        }
        printf("\n");
        
        printf("  Recovery ID[0]: %d\n", data->recovery_ids[0]);
    }
    printf("=====================\n");
    
    /* Clean up memory */
    free_test_data(data);
    
    return EXIT_SUCCESS;
}
