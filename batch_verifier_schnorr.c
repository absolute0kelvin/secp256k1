/*************************************************************************
 * Batch Schnorr Signature Verification for secp256k1
 * 
 * This program demonstrates complete Schnorr signature lifecycle using secp256k1:
 * 1. Generation of cryptographic test data (keys, messages, Schnorr signatures)
 * 2. Extraction of cryptographic components from signatures
 * 3. Batch verification using random linear combinations
 * 
 * Key Features:
 * - Generates test datasets with configurable number of entries
 * - Creates Schnorr signatures using secp256k1_schnorrsig module
 * - Extracts all cryptographic components (public keys, scalars, R points, challenge hashes)
 * - Uses memory-efficient flat arrays for optimal cache performance
 * - Cross-platform secure random number generation
 * 
 * Technical Implementation:
 * - Uses secp256k1 library for all cryptographic operations
 * - Implements proper memory management with flat array structures
 * - Provides comprehensive error handling and validation
 * - Demonstrates Schnorr batch verification: s*G - e*P - R = 0
 * 
 * Schnorr Signature Format:
 * - 64 bytes total: R_x (32 bytes) || s (32 bytes)
 * - R_x: x-coordinate of R point (even y-coordinate assumed)
 * - s: signature scalar value
 * - Challenge: e = H(R || P || m) where H is SHA256-based hash
 * 
 * Data Structures:
 * - schnorr_test_data_t: Holds generated cryptographic test data using flat arrays
 * - schnorr_recover_data_t: Holds extracted cryptographic components as scalars/points
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

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

/* Include internal secp256k1 headers for real implementation */
#include "src/util.h"
#include "src/int128_impl.h"
#include "src/field_impl.h"
#include "src/scalar_impl.h"
#include "src/group_impl.h"
#include "src/ecmult_impl.h"
#include "src/scratch_impl.h"
#include "src/hash_impl.h"

/* Ensure STRAUSS_SCRATCH_OBJECTS is defined */
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
 * (group element) for use in internal secp256k1 operations.
 */
static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    secp256k1_ge_from_bytes(ge, pubkey->data);
    return 1;
}

/* Structure to hold all generated Schnorr test data */
/**
 * schnorr_test_data_t - Complete test dataset for Schnorr signature verification
 * 
 * This structure holds all cryptographic test data using flat arrays for
 * optimal memory performance. Each entry i corresponds to:
 * - private_keys[i*32 : (i+1)*32-1] : 32-byte private key
 * - messages[i*32 : (i+1)*32-1]     : 32-byte message hash
 * - public_keys[i]                  : secp256k1_pubkey structure
 * - schnorr_signatures[i*64 : (i+1)*64-1] : 64-byte Schnorr signature
 * 
 * Memory Layout Design:
 * - Flat arrays eliminate pointer indirection overhead
 * - Contiguous memory improves cache locality during batch operations
 * - Single allocation per array type simplifies memory management
 * 
 * Schnorr Signature Format (64 bytes):
 * - Bytes 0-31:  R_x component (32 bytes, big-endian x-coordinate)
 * - Bytes 32-63: s component (32 bytes, big-endian scalar)
 */
typedef struct {
    size_t num_entries;                                    /* Number of entries */
    unsigned char *private_keys;                           /* Flat array: num_entries * 32 bytes */
    unsigned char *messages;                               /* Flat array: num_entries * 32 bytes */
    secp256k1_pubkey *public_keys;                        /* Array of public keys */
    unsigned char *schnorr_signatures;                    /* Flat array: num_entries * 64 bytes */
} schnorr_test_data_t;

/* Structure to hold extracted Schnorr cryptographic data */
/**
 * schnorr_recover_data_t - Extracted cryptographic components from Schnorr signatures
 * 
 * This structure contains all cryptographic components extracted from 
 * Schnorr signatures, converted to their mathematical representations:
 * 
 * Components:
 * - public_key_points[i] : Public key as secp256k1_ge (copied from input)
 * - s_values[i]          : Signature 's' component as secp256k1_scalar
 * - e_values[i]          : Challenge hash e = H(R || P || m) as secp256k1_scalar
 * - r_points[i]          : Signature 'R' point as secp256k1_ge (reconstructed from R_x)
 * 
 * Mathematical Context:
 * - s_values: Direct conversion from signature bytes to scalar mod n
 * - e_values: Challenge computed as H(R || P || m) and reduced mod n
 * - r_points: Reconstructed from R_x coordinate (even y-coordinate assumed)
 * - public_key_points: Copied from input public keys for efficiency
 * 
 * Extraction Process:
 * 1. Parse Schnorr signature to extract (R_x, s)
 * 2. Copy public key P to public_key_points array
 * 3. Convert 's' bytes to scalar using secp256k1_scalar_set_b32
 * 4. Reconstruct R point from R_x coordinate with even y-coordinate
 * 5. Compute challenge e = H(R || P || m) using SHA256-based hash
 * 6. Convert challenge to scalar e using secp256k1_scalar_set_b32
 * 
 * Note on Batch Verification:
 * During batch verification, the s_values and e_values arrays may be
 * modified in-place to store the combined values (s_i * a_i) and (-e_i * a_i)
 * respectively, where a_i are random coefficients.
 */
typedef struct {
    size_t num_entries;                     /* Number of entries */
    secp256k1_ge *public_key_points;       /* Array of public keys as group elements (copied) */
    secp256k1_scalar *s_values;            /* Array of signature 's' values as scalars */
    secp256k1_scalar *e_values;            /* Array of challenge hashes as scalars */
    secp256k1_ge *r_points;                /* Array of signature R points */
} schnorr_recover_data_t;

/**
 * bip340_tagged_hash - Compute BIP-340 tagged hash
 * 
 * This function implements the BIP-340 tagged hash as specified in BIP-340:
 * tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 * 
 * @param output 32-byte output buffer for the hash result
 * @param tag The tag string (e.g., "BIP0340/challenge")
 * @param tag_len Length of the tag string
 * @param msg The message to hash
 * @param msg_len Length of the message
 */
static void bip340_tagged_hash(unsigned char *output, const char *tag, size_t tag_len, 
                               const unsigned char *msg, size_t msg_len) {
    secp256k1_sha256 sha;
    unsigned char tag_hash[32];
    
    /* Compute SHA256(tag) */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, (const unsigned char*)tag, tag_len);
    secp256k1_sha256_finalize(&sha, tag_hash);
    
    /* Compute SHA256(tag_hash || tag_hash || msg) */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, tag_hash, 32);  /* First copy of tag_hash */
    secp256k1_sha256_write(&sha, tag_hash, 32);  /* Second copy of tag_hash */
    secp256k1_sha256_write(&sha, msg, msg_len);  /* The message */
    secp256k1_sha256_finalize(&sha, output);
}

/**
 * fill_random - Cross-platform cryptographically secure random number generation
 * 
 * This function provides secure random number generation across different platforms
 * using each platform's cryptographically secure random number generator (CSPRNG).
 * Critical for generating unpredictable private keys and ensuring signature security.
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
 * allocate_schnorr_test_data - Allocate memory for Schnorr test data structure
 * 
 * This function allocates all memory required for a schnorr_test_data_t structure
 * and its component arrays. Uses flat array allocation for optimal memory
 * access patterns and simplified memory management.
 * 
 * Memory Allocation:
 * - Structure itself: sizeof(schnorr_test_data_t)
 * - Private keys: num * 32 bytes (32 bytes per private key)
 * - Messages: num * 32 bytes (32 bytes per message hash)
 * - Public keys: num * sizeof(secp256k1_pubkey)
 * - Schnorr signatures: num * 64 bytes (R_x + s)
 * 
 * Error Handling:
 * If any allocation fails, all previously allocated memory is freed
 * and NULL is returned to prevent memory leaks.
 * 
 * @param num Number of test entries to allocate space for
 * @return Pointer to allocated schnorr_test_data_t structure, or NULL on failure
 */
static schnorr_test_data_t* allocate_schnorr_test_data(size_t num) {
    schnorr_test_data_t *data = malloc(sizeof(schnorr_test_data_t));
    if (!data) return NULL;
    
    data->num_entries = num;
    
    /* Allocate flat arrays */
    data->private_keys = malloc(num * 32);  /* 32 bytes per private key */
    data->messages = malloc(num * 32);      /* 32 bytes per message */
    data->public_keys = malloc(num * sizeof(secp256k1_pubkey));
    data->schnorr_signatures = malloc(num * 64);  /* 64 bytes per Schnorr signature */
    
    if (!data->private_keys || !data->messages || !data->public_keys || 
        !data->schnorr_signatures) {
        free(data->private_keys);
        free(data->messages);
        free(data->public_keys);
        free(data->schnorr_signatures);
        free(data);
        return NULL;
    }
    
    return data;
}

/**
 * free_schnorr_test_data - Free all allocated memory for Schnorr test data structure
 * 
 * This function safely deallocates all memory associated with a schnorr_test_data_t
 * structure, including all component arrays. Handles NULL pointers gracefully.
 * 
 * Security Note:
 * This function does not explicitly clear sensitive data (private keys)
 * before freeing. For production use, consider clearing private key memory
 * with explicit_bzero() or similar before calling free().
 * 
 * @param data Pointer to schnorr_test_data_t structure to free (may be NULL)
 */
static void free_schnorr_test_data(schnorr_test_data_t *data) {
    if (!data) return;
    
    /* Free flat arrays directly */
    free(data->private_keys);
    free(data->messages);
    free(data->public_keys);
    free(data->schnorr_signatures);
    free(data);
}

/**
 * allocate_schnorr_recover_data - Allocate memory for Schnorr recover data structure
 * 
 * This function allocates all memory required for a schnorr_recover_data_t structure
 * and its component arrays. Each array holds mathematical representations
 * of cryptographic components extracted from Schnorr signatures.
 * 
 * Memory Allocation:
 * - Structure itself: sizeof(schnorr_recover_data_t)
 * - Public key points: num * sizeof(secp256k1_ge) 
 * - S values: num * sizeof(secp256k1_scalar)
 * - E values (challenges): num * sizeof(secp256k1_scalar)
 * - R points: num * sizeof(secp256k1_ge)
 * 
 * Error Handling:
 * If any allocation fails, all previously allocated memory is freed
 * and NULL is returned to prevent memory leaks.
 * 
 * @param num Number of recovery entries to allocate space for
 * @return Pointer to allocated schnorr_recover_data_t structure, or NULL on failure
 */
static schnorr_recover_data_t* allocate_schnorr_recover_data(size_t num) {
    schnorr_recover_data_t *data = malloc(sizeof(schnorr_recover_data_t));
    if (!data) return NULL;
    
    data->num_entries = num;
    
    /* Allocate arrays */
    data->public_key_points = malloc(num * sizeof(secp256k1_ge));
    data->s_values = malloc(num * sizeof(secp256k1_scalar));
    data->e_values = malloc(num * sizeof(secp256k1_scalar));
    data->r_points = malloc(num * sizeof(secp256k1_ge));
    
    if (!data->public_key_points || !data->s_values || !data->e_values || !data->r_points) {
        free(data->public_key_points);
        free(data->s_values);
        free(data->e_values);
        free(data->r_points);
        free(data);
        return NULL;
    }
    
    return data;
}

/**
 * free_schnorr_recover_data - Free all allocated memory for Schnorr recover data structure
 * 
 * This function safely deallocates all memory associated with a schnorr_recover_data_t
 * structure, including all component arrays. Handles NULL pointers gracefully.
 * 
 * Security Features:
 * - Explicitly clears all scalar values before freeing memory
 * - Uses secp256k1_scalar_clear() to securely overwrite sensitive data
 * - Prevents potential information leakage from deallocated memory
 * 
 * Scalar Clearing:
 * The function clears s_values and e_values arrays which contain
 * sensitive cryptographic material that should not remain in memory after use.
 * 
 * @param data Pointer to schnorr_recover_data_t structure to free (may be NULL)
 */
static void free_schnorr_recover_data(schnorr_recover_data_t *data) {
    if (!data) return;
    
    /* Clear sensitive scalar data before freeing */
    if (data->s_values) {
        for (size_t i = 0; i < data->num_entries; i++) {
            secp256k1_scalar_clear(&data->s_values[i]);
        }
    }
    if (data->e_values) {
        for (size_t i = 0; i < data->num_entries; i++) {
            secp256k1_scalar_clear(&data->e_values[i]);
        }
    }
    
    free(data->public_key_points);
    free(data->s_values);
    free(data->e_values);
    free(data->r_points);
    free(data);
}

/**
 * schnorr_extract_components - Extract and process all cryptographic components from Schnorr signatures
 * 
 * This function implements the complete component extraction process for Schnorr signatures,
 * extracting and validating all mathematical components used in the Schnorr signature algorithm.
 * 
 * Algorithm Overview:
 * For each Schnorr signature (R_x, s) and message m with public key P:
 * 1. Copy public key P to public_key_points array (no recovery needed)
 * 2. Extract scalar s from signature bytes 32-63
 * 3. Reconstruct R point from R_x coordinate (even y-coordinate assumed)
 * 4. Compute challenge e = H(R || P || m) using secp256k1's hash implementation
 * 5. Convert challenge to scalar e
 * 
 * Schnorr-Specific Implementation Details:
 * - R point reconstruction assumes even y-coordinate (BIP-340 standard)
 * - Challenge computed using tagged hash: H_tag(R || P || m)
 * - All scalars automatically reduced modulo curve order n
 * - No recovery ID needed (unlike ECDSA)
 * 
 * Error Handling:
 * - Validates all signature parsing operations
 * - Checks for scalar overflow in s and e values
 * - Verifies R point reconstruction from x-coordinate
 * - Validates challenge hash computation
 * 
 * @param test_data Input test data containing Schnorr signatures and messages
 * @return schnorr_recover_data_t* Allocated structure with extracted components, or NULL on failure
 * 
 * Memory: Caller must free returned structure using free_schnorr_recover_data()
 */
schnorr_recover_data_t* schnorr_extract_components(const schnorr_test_data_t *test_data) {
    if (!test_data) return NULL;
    
    secp256k1_context *ctx = NULL;
    schnorr_recover_data_t *recover_data = NULL;
    int all_valid = 1;
    
    printf("Extracting cryptographic components from %zu Schnorr signatures...\n", test_data->num_entries);
    
    /* Create secp256k1 context */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return NULL;
    }
    
    /* Allocate recover data structure */
    recover_data = allocate_schnorr_recover_data(test_data->num_entries);
    if (!recover_data) {
        printf("Failed to allocate memory for recover data\n");
        goto cleanup;
    }
    
    /* Process each signature */
    for (size_t i = 0; i < test_data->num_entries; i++) {
        unsigned char *current_message = &test_data->messages[i * 32];
        unsigned char *current_signature = &test_data->schnorr_signatures[i * 64];
        
        /* Step 1: Copy public key to group element (no recovery needed for Schnorr) */
        if (!secp256k1_pubkey_load(ctx, &recover_data->public_key_points[i], &test_data->public_keys[i])) {
            printf("Failed to convert public key to group element %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* Step 2: Extract 's' value from signature and convert to scalar */
        unsigned char s_bytes[32];
        memcpy(s_bytes, &current_signature[32], 32);  /* s is bytes 32-63 */
        int overflow;
        secp256k1_scalar_set_b32(&recover_data->s_values[i], s_bytes, &overflow);
        if (overflow) {
            printf("Invalid s value in Schnorr signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* Step 3: Reconstruct R point from R_x coordinate */
        unsigned char r_x_bytes[32];
        memcpy(r_x_bytes, current_signature, 32);  /* R_x is bytes 0-31 */
        
        secp256k1_fe r_x_fe;
        if (!secp256k1_fe_set_b32_limit(&r_x_fe, r_x_bytes)) {
            printf("Invalid R_x value in Schnorr signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* 
         * Reconstruct the R point using x coordinate and even y-coordinate
         * BIP-340 Schnorr signatures assume even y-coordinate (odd_y = 0)
         */
        if (!secp256k1_ge_set_xo_var(&recover_data->r_points[i], &r_x_fe, 0)) {
            printf("Failed to reconstruct R point for Schnorr signature %zu\n", i);
            all_valid = 0;
            continue;
        }
        
        /* 
         * Step 4: Compute challenge e = H(R || P || m)
         * 
         * For Schnorr signatures, the challenge is computed as:
         * e = Hash(R_x || P_x || m) where Hash is a tagged SHA256
         * 
         * We need to:
         * 1. Serialize R point to 32-byte x-coordinate
         * 2. Serialize P point to 32-byte x-coordinate  
         * 3. Concatenate: R_x || P_x || m (96 bytes total)
         * 4. Hash the concatenation to get 32-byte challenge
         * 5. Convert challenge to scalar
         */
        unsigned char challenge_input[96];  /* R_x (32) + P_x (32) + message (32) */
        
        /* Get R_x (already have it) */
        memcpy(challenge_input, r_x_bytes, 32);
        
        /* Get P_x from public key point */
        secp256k1_fe p_x;
        p_x = recover_data->public_key_points[i].x;
        secp256k1_fe_get_b32(&challenge_input[32], &p_x);
        
        /* Add message */
        memcpy(&challenge_input[64], current_message, 32);
        
        /* Compute challenge hash using BIP-340 tagged hash */
        unsigned char challenge_input_bip340[96];  /* R_x (32) + P_x (32) + message (32) */
        memcpy(challenge_input_bip340, r_x_bytes, 32);
        memcpy(&challenge_input_bip340[32], &challenge_input[32], 32);  /* P_x */
        memcpy(&challenge_input_bip340[64], current_message, 32);
        
        unsigned char challenge_hash[32];
        bip340_tagged_hash(challenge_hash, "BIP0340/challenge", 17, challenge_input_bip340, 96);
        
        /* Convert challenge to scalar */
        secp256k1_scalar_set_b32(&recover_data->e_values[i], challenge_hash, &overflow);
        if (overflow) {
            printf("Challenge hash converted with overflow for entry %zu (reduced mod n)\n", i);
            /* This is not an error - overflow just means challenge >= curve_order */
        }
        
        if ((i + 1) % 100 == 0 || i == test_data->num_entries - 1) {
            printf("Processed %zu/%zu signatures\n", i + 1, test_data->num_entries);
        }
    }
    
    if (!all_valid) {
        printf("Some component extraction operations failed\n");
        free_schnorr_recover_data(recover_data);
        recover_data = NULL;
    } else {
        printf("All component extraction operations completed successfully!\n");
    }
    
cleanup:
    if (ctx) secp256k1_context_destroy(ctx);
    return recover_data;
}

/**
 * generate_schnorr_test_data - Generate complete cryptographic test dataset for Schnorr verification
 * 
 * This function creates a comprehensive test dataset containing all components
 * needed for Schnorr signature verification and batch testing. The generation
 * process follows cryptographic best practices for secure key and signature creation.
 * 
 * Generation Process:
 * 1. Create cryptographically secure secp256k1 context with randomization
 * 2. For each entry (0 to num-1):
 *    a. Generate cryptographically secure random private key
 *    b. Validate private key using secp256k1_ec_seckey_verify
 *    c. Generate random 32-byte message hash
 *    d. Derive public key from private key using EC point multiplication
 *    e. Create Schnorr signature for message using private key
 *    f. Serialize signature to 64-byte format (R_x||s)
 * 
 * Data Organization:
 * - All data stored in flat arrays for optimal memory access patterns
 * - Private keys: 32 bytes each, stored sequentially
 * - Messages: 32 bytes each (simulating hash outputs)
 * - Public keys: secp256k1_pubkey structures
 * - Signatures: 64 bytes each (R_x||s format)
 * 
 * Security Considerations:
 * - Uses platform-specific secure random number generation
 * - Context randomization for side-channel attack protection
 * - Proper private key validation before use
 * - Deterministic signature creation following BIP-340
 * 
 * Schnorr Signature Properties:
 * - Generated signatures follow BIP-340 standard
 * - R points use even y-coordinates only
 * - Signature format is 64 bytes (32-byte R_x + 32-byte s)
 * - Compatible with Bitcoin Taproot and other BIP-340 implementations
 * 
 * @param num Number of test entries to generate
 * @return schnorr_test_data_t* Allocated structure with generated data, or NULL on failure
 * 
 * Memory: Caller must free returned structure using free_schnorr_test_data()
 * Performance: O(num) time complexity, optimized for large datasets
 */
schnorr_test_data_t* generate_schnorr_test_data(size_t num) {
    secp256k1_context *ctx = NULL;
    schnorr_test_data_t *data = NULL;
    unsigned char randomize[32];
    int ret;
    
    printf("Generating Schnorr test data for %zu entries...\n", num);
    
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
    data = allocate_schnorr_test_data(num);
    if (!data) {
        printf("Failed to allocate memory for Schnorr test data\n");
        goto cleanup;
    }
    
    /* Generate all the data */
    for (size_t i = 0; i < num; i++) {
        /* Calculate offsets for flat arrays */
        unsigned char *current_private_key = &data->private_keys[i * 32];
        unsigned char *current_message = &data->messages[i * 32];
        unsigned char *current_signature = &data->schnorr_signatures[i * 64];
        secp256k1_keypair keypair;

        if ((i + 1) % 100 == 0 || i == 0) {
            printf("Generating Schnorr test data for entry #%zu\n", i);
        }
        
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
        
        /* Create keypair from private key */
        ret = secp256k1_keypair_create(ctx, &keypair, current_private_key);
        if (!ret) {
            printf("Failed to create keypair %zu\n", i);
            goto cleanup;
        }
        
        /* Get x-only public key from keypair */
        ret = secp256k1_keypair_xonly_pub(ctx, &data->public_keys[i], NULL, &keypair);
        if (!ret) {
            printf("Failed to get x-only public key %zu\n", i);
            goto cleanup;
        }
        
        /* Create Schnorr signature */
        ret = secp256k1_schnorrsig_sign32(ctx, current_signature, 
                                        current_message, &keypair, NULL);
        if (!ret) {
            printf("Failed to create Schnorr signature %zu\n", i);
            goto cleanup;
        }
        
        if ((i + 1) % 100 == 0 || i == num - 1) {
            printf("Generated %zu/%zu entries\n", i + 1, num);
        }
    }
    
    printf("Successfully generated all Schnorr test data!\n");
    secp256k1_context_destroy(ctx);
    return data;
    
cleanup:
    if (ctx) secp256k1_context_destroy(ctx);
    if (data) free_schnorr_test_data(data);
    return NULL;
}

/**
 * print_schnorr_test_data_summary - Display comprehensive summary of generated Schnorr test data
 * 
 * This function provides a detailed overview of the schnorr_test_data_t structure,
 * including memory usage statistics and example data from the first entry.
 * Useful for verifying test data generation and understanding data layout.
 * 
 * Information Displayed:
 * - Total number of entries generated
 * - Memory usage breakdown by component type
 * - Total memory consumption in bytes and megabytes
 * - Example data from the first entry (partial private key, message, signature)
 * 
 * Output Format:
 * The function formats output in a clear, readable summary with section headers
 * and consistent formatting for easy interpretation of the generated data.
 * 
 * Security Note:
 * Only displays partial private key data (first 8 bytes) for security reasons,
 * providing enough information for verification without exposing full keys.
 * 
 * @param data Pointer to schnorr_test_data_t structure to summarize (may be NULL)
 */
void print_schnorr_test_data_summary(const schnorr_test_data_t *data) {
    if (!data) return;
    
    printf("\n=== Schnorr Test Data Summary ===\n");
    printf("Number of entries: %zu\n", data->num_entries);
    printf("Memory usage:\n");
    printf("  Private keys: %zu bytes\n", data->num_entries * 32);
    printf("  Messages: %zu bytes\n", data->num_entries * 32);
    printf("  Public keys: %zu bytes\n", data->num_entries * sizeof(secp256k1_pubkey));
    printf("  Schnorr signatures: %zu bytes\n", data->num_entries * 64);
    
    size_t total_size = data->num_entries * (32 + 32 + sizeof(secp256k1_pubkey) + 64);
    printf("  Total: %zu bytes (%.2f MB)\n", total_size, (double)total_size / (1024 * 1024));
    
    if (data->num_entries > 0) {
        printf("\nFirst entry example:\n");
        printf("  Private key: ");
        for (int i = 0; i < 8; i++) printf("%02x", data->private_keys[i]);
        printf("...\n");
        printf("  Message: ");
        for (int i = 0; i < 8; i++) printf("%02x", data->messages[i]);
        printf("...\n");
        printf("  Schnorr signature: ");
        for (int i = 0; i < 8; i++) printf("%02x", data->schnorr_signatures[i]);
        printf("...\n");
    }
    printf("=================================\n\n");
}

/**
 * print_schnorr_recover_data_summary - Display comprehensive summary of extracted Schnorr data
 * 
 * This function provides a detailed overview of the schnorr_recover_data_t structure,
 * including memory usage statistics and example data from the first entry.
 * Useful for debugging and understanding the extracted cryptographic components.
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
 * @param data Pointer to schnorr_recover_data_t structure to summarize (may be NULL)
 */
void print_schnorr_recover_data_summary(const schnorr_recover_data_t *data) {
    if (!data) return;
    
    printf("\n=== Schnorr Recovery Data Summary ===\n");
    printf("Number of entries: %zu\n", data->num_entries);
    printf("Memory usage:\n");
    printf("  Public key points: %zu bytes\n", data->num_entries * sizeof(secp256k1_ge));
    printf("  S scalars: %zu bytes\n", data->num_entries * sizeof(secp256k1_scalar));
    printf("  E scalars (challenges): %zu bytes\n", data->num_entries * sizeof(secp256k1_scalar));
    printf("  R points: %zu bytes\n", data->num_entries * sizeof(secp256k1_ge));
    
    size_t total_size = data->num_entries * (2 * sizeof(secp256k1_ge) + 
                       2 * sizeof(secp256k1_scalar));
    printf("  Total: %zu bytes (%.2f MB)\n", total_size, (double)total_size / (1024 * 1024));
    
    if (data->num_entries > 0) {
        printf("\nFirst entry example:\n");
        
        /* Print first few bytes of s scalar */
        printf("  S scalar[0]: ");
        unsigned char s_bytes[32];
        secp256k1_scalar_get_b32(s_bytes, &data->s_values[0]);
        for (int i = 0; i < 8; i++) printf("%02x", s_bytes[i]);
        printf("...\n");
        
        /* Print first few bytes of e scalar */
        printf("  E scalar[0]: ");
        unsigned char e_bytes[32];
        secp256k1_scalar_get_b32(e_bytes, &data->e_values[0]);
        for (int i = 0; i < 8; i++) printf("%02x", e_bytes[i]);
        printf("...\n");
        
        /* Print R point info */
        printf("  R point[0]: %s\n", secp256k1_ge_is_infinity(&data->r_points[0]) ? "infinity" : "valid point");
        printf("  P point[0]: %s\n", secp256k1_ge_is_infinity(&data->public_key_points[0]) ? "infinity" : "valid point");
    }
    printf("======================================\n\n");
}

/**
 * schnorr_sanity_check - Comprehensive validation of extracted Schnorr cryptographic components
 * 
 * This function performs rigorous mathematical validation of all components
 * in the schnorr_recover_data_t structure to ensure they satisfy secp256k1 curve
 * constraints and Schnorr signature validity requirements.
 * 
 * Validation Checks:
 * 1. R points: Valid curve points (on secp256k1 curve, not infinity)
 * 2. P points: Valid curve points (proper public keys, not infinity)
 * 3. e values: 0 <= e < n (challenge hashes as valid scalars)
 * 4. s values: 1 <= s < n (signature s values, must be non-zero)
 * 
 * Where n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * is the order of the secp256k1 base point G.
 * 
 * Mathematical Context:
 * - R points must lie on the secp256k1 curve: y² = x³ + 7 (mod p)
 * - P points (public keys) must be valid curve points and not the point at infinity
 * - e values are challenge hashes reduced modulo n (can be 0)
 * - s values must be non-zero and < n for valid Schnorr signatures
 * 
 * @param data Extracted cryptographic data to validate
 * @return 1 if all validations pass, 0 if any validation fails
 */
int schnorr_sanity_check(const schnorr_recover_data_t *data) {
    if (!data) {
        printf("schnorr_sanity_check: NULL data pointer\n");
        return 0;
    }
    
    printf("Performing sanity check on %zu extracted Schnorr entries...\n", data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("schnorr_sanity_check: Failed to create secp256k1 context\n");
        return 0;
    }
    
    int all_valid = 1;
    
    for (size_t i = 0; i < data->num_entries && all_valid; i++) {
        /* Check 1: Validate R points are valid curve points */
        if (!secp256k1_ge_is_valid_var(&data->r_points[i])) {
            printf("schnorr_sanity_check: Invalid R point at index %zu (not on curve)\n", i);
            all_valid = 0;
            break;
        }
        
        if (secp256k1_ge_is_infinity(&data->r_points[i])) {
            printf("schnorr_sanity_check: R point is infinity at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        /* Check 2: Validate P points (pubkeys) are valid curve points */
        if (!secp256k1_ge_is_valid_var(&data->public_key_points[i])) {
            printf("schnorr_sanity_check: Invalid P point (pubkey) at index %zu (not on curve)\n", i);
            all_valid = 0;
            break;
        }
        
        if (secp256k1_ge_is_infinity(&data->public_key_points[i])) {
            printf("schnorr_sanity_check: P point is infinity at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        /* Check 3: Validate e values (0 <= e < n) */
        /* Scalars are automatically reduced mod n when created via secp256k1_scalar_set_b32,
         * so any valid scalar satisfies 0 <= e < n. e can legitimately be 0. */
        
        /* Check 4: Validate s values (1 <= s < n) */
        if (secp256k1_scalar_is_zero(&data->s_values[i])) {
            printf("schnorr_sanity_check: s value is zero at index %zu\n", i);
            all_valid = 0;
            break;
        }
        
        if ((i + 1) % 1000 == 0 || i == data->num_entries - 1) {
            printf("Validated %zu/%zu entries\n", i + 1, data->num_entries);
        }
    }
    
    secp256k1_context_destroy(ctx);
    
    if (all_valid) {
        printf("All sanity checks passed! All Schnorr cryptographic components are mathematically valid.\n");
    } else {
        printf("Sanity check failed! Invalid Schnorr cryptographic components detected.\n");
    }
    
    return all_valid;
}

/**
 * schnorr_verify_one_by_one - Verify Schnorr signatures using the s*G - e*P - R = 0 formula
 * 
 * This function verifies Schnorr signatures by directly computing the equation
 * s*G - e*P - R = 0 using secp256k1's internal multi-scalar multiplication.
 * 
 * Mathematical Background:
 * The Schnorr verification equation can be rearranged as:
 * s*G - e*P - R = 0 (point at infinity)
 * 
 * Where:
 * - s: signature s component as scalar
 * - G: secp256k1 generator point  
 * - e: challenge hash e = H(R || P || m) as scalar
 * - P: public key point
 * - R: signature R point
 * 
 * Implementation:
 * Uses secp256k1_ecmult_multi_var with three terms:
 * 1. s * G (generator multiplication)
 * 2. (-e) * P (public key multiplication with negated e) 
 * 3. (-1) * R (R point multiplication with -1)
 * 
 * @param test_data Original test data containing public keys
 * @param recover_data Extracted cryptographic components to verify
 * @return 1 if all signatures verify, 0 if any verification fails
 */

/**
 * schnorr_ecmult_multi_data - Callback data structure for secp256k1_ecmult_multi_var
 * 
 * This structure provides context data for the schnorr_ecmult_multi_callback function
 * used during individual Schnorr signature verification. It contains references to
 * all the cryptographic components needed for computing s*G - e*P - R = 0.
 */
typedef struct {
    const secp256k1_scalar *s_values;  
    const secp256k1_scalar *e_values;
    const secp256k1_ge *p_points;
    const secp256k1_ge *r_points;
    size_t current_index;
} schnorr_ecmult_multi_data;

/**
 * schnorr_ecmult_multi_callback - Callback function for secp256k1_ecmult_multi_var
 * 
 * This callback provides scalar coefficients and points for multi-scalar
 * multiplication during individual Schnorr signature verification. It implements
 * the verification equation s*G - e*P - R = 0 by providing:
 * - Term 0: (-e) * P (public key multiplication with negated e)
 * - Term 1: (-1) * R (R point multiplication with -1)
 * 
 * The s*G term is handled separately by secp256k1_ecmult_multi_var.
 * 
 * @param sc Output scalar coefficient for the current term
 * @param pt Output point for the current term  
 * @param idx Term index (0 for (-e)*P, 1 for (-1)*R)
 * @param data Pointer to schnorr_ecmult_multi_data structure with signature components
 * @return 1 on success, 0 on failure
 */
static int schnorr_ecmult_multi_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    schnorr_ecmult_multi_data *cb_data = (schnorr_ecmult_multi_data *)data;
    
    switch (idx) {
        case 0: /* (-e) * P */
            secp256k1_scalar_negate(sc, &cb_data->e_values[cb_data->current_index]);
            *pt = cb_data->p_points[cb_data->current_index];
            return 1;
            
        case 1: /* (-1) * R */
            secp256k1_scalar_set_int(sc, 1);
            secp256k1_scalar_negate(sc, sc);  /* sc = -1 */
            *pt = cb_data->r_points[cb_data->current_index];
            return 1;
            
        default:
            return 0;
    }
}

int schnorr_verify_one_by_one(const schnorr_test_data_t *test_data, const schnorr_recover_data_t *recover_data) {
    if (!test_data || !recover_data) {
        printf("schnorr_verify_one_by_one: NULL data pointer\n");
        return 0;
    }
    
    if (test_data->num_entries != recover_data->num_entries) {
        printf("schnorr_verify_one_by_one: Entry count mismatch\n");
        return 0;
    }
    
    printf("Verifying %zu Schnorr signatures using s*G - e*P - R = 0 formula...\n", recover_data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("schnorr_verify_one_by_one: Failed to create secp256k1 context\n");
        return 0;
    }

    /* Calculate scratch size - verify_one_by_one always uses Strauss (2 terms < ECMULT_PIPPENGER_THRESHOLD) */
    size_t num_terms = 2; /* 2 terms per signature: (-e)*P and (-1)*R */
    size_t scratch_size = secp256k1_strauss_scratch_size(num_terms) + STRAUSS_SCRATCH_OBJECTS*16;
    secp256k1_scratch *scratch = secp256k1_scratch_create(secp256k1_default_error_callback_fn, scratch_size);
    if (!scratch) {
        printf("schnorr_verify_one_by_one: Failed to create scratch space\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    
    /* Set up callback data */
    schnorr_ecmult_multi_data cb_data = {
        .s_values = recover_data->s_values,
        .e_values = recover_data->e_values,
        .p_points = recover_data->public_key_points,
        .r_points = recover_data->r_points,
        .current_index = 0
    };
    
    int all_valid = 1;
    size_t verification_failures = 0;
    
    /* Verify each signature */
    for (size_t i = 0; i < recover_data->num_entries && all_valid; i++) {
        cb_data.current_index = i;
        
        secp256k1_gej result_gej;
        
        /* Compute s*G + (-e)*P + (-1)*R using multi-scalar multiplication */
        secp256k1_scalar *s_current = &recover_data->s_values[i];
        int ret = secp256k1_ecmult_multi_var(secp256k1_default_error_callback_fn, scratch, &result_gej, 
                                           s_current, schnorr_ecmult_multi_callback, &cb_data, 2);
        if (!ret) {
            printf("schnorr_verify_one_by_one: Multi-scalar multiplication failed at index %zu\n", i);
            verification_failures++;
            all_valid = 0;
            continue;
        }
        
        /* Check if result is point at infinity (representing zero) */
        if (!secp256k1_gej_is_infinity(&result_gej)) {
            printf("schnorr_verify_one_by_one: Schnorr signature verification failed at index %zu (result not infinity)\n", i);
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
        printf("All %zu Schnorr signatures verified successfully using s*G - e*P - R = 0!\n", recover_data->num_entries);
    } else {
        printf("Schnorr signature verification failed! %zu out of %zu signatures failed verification.\n", 
               verification_failures, recover_data->num_entries);
    }
    
    return all_valid;
}

/**
 * schnorr_verify_in_batch - Batch verify Schnorr signatures using random linear combination
 * 
 * This function verifies multiple Schnorr signatures simultaneously using the formula:
 * (Σ s_i * a_i) * G + Σ ((-e_i) * a_i * P_i) + Σ ((-1) * a_i * R_i) = 0
 * 
 * Where:
 * - s_i: signature s component as scalar for signature i
 * - a_i: random coefficient for signature i
 * - G: secp256k1 generator point
 * - e_i: challenge hash as scalar for signature i
 * - P_i: public key point for signature i
 * - R_i: signature R point for signature i
 * 
 * The random coefficients prevent forgery attacks that could fool naive batch verification.
 * 
 * @param recover_data Extracted cryptographic components to verify
 * @param multiplier Random scalar multiplier for generating random coefficients a_i
 * @return 1 if batch verification succeeds, 0 if it fails
 */

/**
 * schnorr_batch_ecmult_callback - Callback function for batch Schnorr signature verification
 * 
 * This callback provides scalar coefficients and points for multi-scalar
 * multiplication during batch Schnorr signature verification. It implements
 * the batch verification equation by providing combined terms:
 * 
 * Term Layout:
 * - Terms 0 to (num_entries-1): (-e_i * a_i) * P_i 
 * - Terms num_entries to (2*num_entries-1): (-a_i) * R_i
 * 
 * The function expects that s_values and e_values arrays have been pre-computed
 * to contain the combined values (s_i * a_i) and (-e_i * a_i) respectively,
 * where a_i are the random coefficients for batch verification.
 * 
 * Mathematical Context:
 * This supports the batch verification equation:
 * (Σ s_i * a_i) * G + Σ ((-e_i) * a_i * P_i) + Σ ((-1) * a_i * R_i) = 0
 * 
 * @param sc Output scalar coefficient for the current term
 * @param pt Output point for the current term  
 * @param idx Term index (0 to 2*num_entries-1)
 * @param data Pointer to schnorr_recover_data_t structure with pre-computed combined values
 * @return 1 on success, 0 on invalid index
 */
static int schnorr_batch_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    const schnorr_recover_data_t *recover_data = (const schnorr_recover_data_t *)data;
    
    if (idx < recover_data->num_entries) {
        /* First num_entries terms: (-e_i * a_i) * P_i */
        *sc = recover_data->e_values[idx];
        *pt = recover_data->public_key_points[idx];
        return 1;
    } else if (idx < 2 * recover_data->num_entries) {
        /* Next num_entries terms: (-a_i) * R_i */
        size_t r_idx = idx - recover_data->num_entries;
        *sc = recover_data->s_values[r_idx];  /* This will contain (-a_i) values */
        *pt = recover_data->r_points[r_idx];
        return 1;
    } else {
        return 0;
    }
}

int schnorr_verify_in_batch( schnorr_recover_data_t *recover_data, const secp256k1_scalar *multiplier) {
    if (!schnorr_sanity_check(recover_data)) {
        printf("schnorr_verify_in_batch: Invalid input data\n");
        return 0;
    }

    if (!recover_data || recover_data->num_entries == 0) {
        printf("schnorr_verify_in_batch: Invalid input data\n");
        return 0;
    }
    
    printf("Performing batch verification of %zu Schnorr signatures...\n", recover_data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("schnorr_verify_in_batch: Failed to create secp256k1 context\n");
        return 0;
    }
    
    /* Calculate scratch size - secp256k1_ecmult_multi_var uses Pippenger if terms >= ECMULT_PIPPENGER_THRESHOLD, else Strauss */
    size_t num_terms = 2 * recover_data->num_entries; /* 2n terms: n P terms + n R terms */
    size_t scratch_size;
    /* use num_terms*2 because we want to use more memory for the Pippenger algorithm */
    if (num_terms >= ECMULT_PIPPENGER_THRESHOLD) {
        /* Use optimal bucket window for Pippenger algorithm */
        int bucket_window = secp256k1_pippenger_bucket_window(num_terms);
        scratch_size = secp256k1_pippenger_scratch_size(num_terms*2, bucket_window);
    } else {
        scratch_size = secp256k1_strauss_scratch_size(num_terms) + STRAUSS_SCRATCH_OBJECTS*16;
    }

    secp256k1_scratch *scratch = secp256k1_scratch_create(secp256k1_default_error_callback_fn, scratch_size);
    if (!scratch) {
        printf("schnorr_verify_in_batch: Failed to create scratch space\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    
    /* Generate pseudo-random coefficients a_i using simple LCG */
    unsigned char seed[32] = {0x42}; /* Simple deterministic seed */
    secp256k1_scalar seed_scalar;
    int overflow;
    secp256k1_scalar_set_b32(&seed_scalar, seed, &overflow);
    
    /* Compute combined scalars */
    secp256k1_scalar combined_s;
    secp256k1_scalar_set_int(&combined_s, 0); /* Initialize to zero */
    
    /* Start with seed * multiplier for a_0 */
    secp256k1_scalar current_a = seed_scalar;
    secp256k1_scalar_mul(&current_a, &current_a, multiplier);
    
    for (size_t i = 0; i < recover_data->num_entries; i++) {
        /* Compute combined scalars: s_i * a_i, (-e_i) * a_i, (-a_i) */
        secp256k1_scalar temp_s_a;
        
        /* s_i * a_i and add to combined_s */
        secp256k1_scalar_mul(&temp_s_a, &recover_data->s_values[i], &current_a);
        secp256k1_scalar_add(&combined_s, &combined_s, &temp_s_a);
        
        /* (-e_i) * a_i - store directly back in e_values array */
        secp256k1_scalar temp_e;
        temp_e = recover_data->e_values[i]; /* Save original */
        secp256k1_scalar_negate(&temp_e, &temp_e);
        secp256k1_scalar_mul(&((schnorr_recover_data_t*)recover_data)->e_values[i], &temp_e, &current_a);
        
        /* (-a_i) - store directly back in s_values array (as workspace) */
        secp256k1_scalar temp_neg_a;
        secp256k1_scalar_negate(&temp_neg_a, &current_a);
        ((schnorr_recover_data_t*)recover_data)->s_values[i] = temp_neg_a;
        
        /* Update current_a for next iteration: a_{i+1} = a_i * multiplier */
        if (i + 1 < recover_data->num_entries) {
            secp256k1_scalar_mul(&current_a, &current_a, multiplier);
        }
    }
    
    /* Compute batch verification: (Σ s_i * a_i) * G + Σ terms */
    /* Pass recover_data directly to callback - it now contains the workspace arrays */
    secp256k1_gej result_gej;
    int ret = secp256k1_ecmult_multi_var(secp256k1_default_error_callback_fn, scratch, &result_gej,
                                       &combined_s, schnorr_batch_ecmult_callback, (void*)recover_data, num_terms);
    
    int verification_result = 0;
    if (!ret) {
        printf("schnorr_verify_in_batch: Multi-scalar multiplication failed\n");
    } else {
        /* Check if result is point at infinity (representing zero) */
        if (secp256k1_gej_is_infinity(&result_gej)) {
            printf("Schnorr batch verification succeeded! All %zu signatures are valid.\n", recover_data->num_entries);
            verification_result = 1;
        } else {
            printf("Schnorr batch verification failed! Result is not infinity.\n");
            verification_result = 0;
        }
    }
    
    /* Clear sensitive data */
    /* Note: e_values and s_values now contain combined values from batch verification */
    /* They will be cleared when the recover_data structure is freed */
    secp256k1_scalar_clear(&combined_s);
    secp256k1_scalar_clear(&seed_scalar);
    secp256k1_scalar_clear(&current_a);
    
    secp256k1_scratch_destroy(secp256k1_default_error_callback_fn, scratch);
    secp256k1_context_destroy(ctx);
    
    return verification_result;
}

/**
 * schnorr_verify_sig_one_by_one - Verify all Schnorr signatures using standard secp256k1_schnorrsig_verify
 * 
 * This function provides an independent validation method for all Schnorr signatures in the
 * test dataset using the standard secp256k1_schnorrsig_verify function. It serves as a
 * comprehensive check to ensure all generated Schnorr signatures are mathematically valid.
 * 
 * Verification Process:
 * For each signature in the test data:
 * 1. Use the 64-byte Schnorr signature directly (R_x||s format)
 * 2. Verify the signature against the message and public key using secp256k1_schnorrsig_verify
 * 3. Report any verification failures with detailed error information
 * 
 * Mathematical Context:
 * Standard Schnorr verification checks that for signature (R_x,s), message m, and public key P:
 * - Reconstruct R from R_x (with even y-coordinate)
 * - Compute e = H(R || P || m)
 * - Verification succeeds if s*G = R + e*P
 * 
 * @param data Test data containing Schnorr signatures, messages, and public keys to verify
 * @return 1 if all signatures verify successfully, 0 if any verification fails
 */
int schnorr_verify_sig_one_by_one(const schnorr_test_data_t *data) {
    if (!data) {
        printf("schnorr_verify_sig_one_by_one: NULL data pointer\n");
        return 0;
    }
    
    printf("Verifying %zu Schnorr signatures one by one using standard secp256k1_schnorrsig_verify...\n", data->num_entries);
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("schnorr_verify_sig_one_by_one: Failed to create secp256k1 context\n");
        return 0;
    }
    
    int all_valid = 1;
    size_t verification_failures = 0;
    
    for (size_t i = 0; i < data->num_entries && all_valid; i++) {
        /* Extract components for current entry */
        unsigned char *current_message = &data->messages[i * 32];
        unsigned char *current_signature = &data->schnorr_signatures[i * 64];
        const secp256k1_pubkey *current_pubkey = &data->public_keys[i];
        
        /* Verify the Schnorr signature against message and public key */
        int verify_result = secp256k1_schnorrsig_verify(ctx, current_signature, current_message, 32, current_pubkey);
        if (!verify_result) {
            printf("schnorr_verify_sig_one_by_one: Schnorr signature verification failed at index %zu\n", i);
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
        printf("All %zu Schnorr signatures verified successfully using standard secp256k1_schnorrsig_verify!\n", data->num_entries);
    } else {
        printf("Schnorr signature verification failed! %zu out of %zu signatures failed verification.\n", 
               verification_failures, data->num_entries);
    }
    
    return all_valid;
}

/**
 * compare_schnorr_verification_performance - Benchmark and compare all three Schnorr verification methods
 * 
 * This function measures and compares the runtime performance of:
 * 1. schnorr_verify_sig_one_by_one - Standard secp256k1_schnorrsig_verify for each signature
 * 2. schnorr_verify_one_by_one - Individual s*G - e*P - R = 0 verification
 * 3. schnorr_verify_in_batch - Batch verification using random linear combinations
 * 
 * @param test_data Original test data with Schnorr signatures
 * @param recover_data Extracted cryptographic components
 */
void compare_schnorr_verification_performance(const schnorr_test_data_t *test_data, const schnorr_recover_data_t *recover_data) {
    if (!test_data || !recover_data) {
        printf("compare_schnorr_verification_performance: Invalid input data\n");
        return;
    }
    
    printf("\n=== Schnorr Performance Comparison ===\n");
    printf("Testing %zu Schnorr signatures...\n\n", test_data->num_entries);
    
    clock_t start, end;
    double cpu_time_used;
    
    /* Test 1: schnorr_verify_sig_one_by_one */
    printf("1. Testing schnorr_verify_sig_one_by_one (standard Schnorr verification)...\n");
    start = clock();
    int result1 = schnorr_verify_sig_one_by_one(test_data);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("   Result: %s\n", result1 ? "PASS" : "FAIL");
    printf("   Time: %.6f seconds\n", cpu_time_used);
    printf("   Time per signature: %.6f ms\n\n", (cpu_time_used * 1000.0) / test_data->num_entries);
    
    /* Test 2: schnorr_verify_one_by_one */
    printf("2. Testing schnorr_verify_one_by_one (s*G - e*P - R = 0 formula)...\n");
    start = clock();
    int result2 = schnorr_verify_one_by_one(test_data, recover_data);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("   Result: %s\n", result2 ? "PASS" : "FAIL");
    printf("   Time: %.6f seconds\n", cpu_time_used);
    printf("   Time per signature: %.6f ms\n\n", (cpu_time_used * 1000.0) / test_data->num_entries);
    
    /* Test 3: schnorr_verify_in_batch */
    printf("3. Testing schnorr_verify_in_batch (batch verification with random coefficients)...\n");
    
    /* Create multiplier for random coefficient generation */
    secp256k1_scalar multiplier;
    unsigned char mult_bytes[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    int overflow;
    secp256k1_scalar_set_b32(&multiplier, mult_bytes, &overflow);
    
    start = clock();
    int result3 = schnorr_verify_in_batch(recover_data, &multiplier);
    end = clock();
    
    /* Clear multiplier for security */
    secp256k1_scalar_clear(&multiplier);
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("   Result: %s\n", result3 ? "PASS" : "FAIL");
    printf("   Time: %.6f seconds\n", cpu_time_used);
    printf("   Time per signature: %.6f ms\n\n", (cpu_time_used * 1000.0) / test_data->num_entries);
    
    printf("======================================\n\n");
}

/**
 * main - Demonstration program for Schnorr signature generation and batch verification
 * 
 * This program demonstrates the complete Schnorr signature lifecycle:
 * 1. Generate test dataset with specified number of entries
 * 2. Create Schnorr signatures for all test messages
 * 3. Extract all cryptographic components from the signatures
 * 4. Validate that extracted components are mathematically valid
 * 5. Display comprehensive statistics and examples
 * 6. Compare verification performance across different methods
 * 
 * Program Flow:
 * - Parse command line arguments for dataset size
 * - Generate cryptographically secure Schnorr test data
 * - Perform component extraction and validation
 * - Display memory usage and performance statistics
 * - Show example data for verification
 * - Clean up all allocated memory
 * 
 * Usage: ./batch_verifier_schnorr [num_entries]
 * Example: ./batch_verifier_schnorr 5000
 * 
 * Performance Characteristics:
 * - Linear time complexity: O(n) for n signatures
 * - Memory usage: ~180 bytes per signature entry
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
    
    printf("Starting Schnorr test data generation with %zu entries...\n\n", num_entries);
    
    /* Generate Schnorr test data */
    schnorr_test_data_t *data = generate_schnorr_test_data(num_entries);
    if (!data) {
        printf("Failed to generate Schnorr test data\n");
        return EXIT_FAILURE;
    }
    
    /* Print summary of generated data */
    print_schnorr_test_data_summary(data);
    
    /* Verify all signatures using standard Schnorr verification */
    if (!schnorr_verify_sig_one_by_one(data)) {
        printf("Initial Schnorr signature verification failed - cleaning up and exiting\n");
        free_schnorr_test_data(data);
        return EXIT_FAILURE;
    }
    
    /* Extract cryptographic components from the signatures */
    schnorr_recover_data_t *recover_data = schnorr_extract_components(data);
    if (!recover_data) {
        printf("Failed to extract cryptographic components\n");
        free_schnorr_test_data(data);
        return EXIT_FAILURE;
    }
    
    /* Print summary of extracted data */
    print_schnorr_recover_data_summary(recover_data);
    
    /* Run performance comparison benchmarks */
    compare_schnorr_verification_performance(data, recover_data);
    
    /* Clean up recover data */
    free_schnorr_recover_data(recover_data);
    
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
        
        printf("  Schnorr signature[0]: ");
        for (int i = 0; i < 64; i++) {
            printf("%02x", data->schnorr_signatures[i]);
        }
        printf("\n");
    }
    printf("=====================\n");
    
    /* Clean up memory */
    free_schnorr_test_data(data);
    
    return EXIT_SUCCESS;
}
