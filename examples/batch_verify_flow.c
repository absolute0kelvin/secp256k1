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

static int write_file(const char* path, const unsigned char* buf, size_t len) {
    FILE* f;
    size_t w;
    if (!path || !buf) return 0;
    f = fopen(path, "wb");
    if (!f) return 0;
    w = fwrite(buf, 1, len, f);
    fclose(f);
    return w == len;
}

static int read_file(const char* path, unsigned char** out_buf, size_t* out_len) {
    FILE* f;
    long sz;
    size_t r;
    unsigned char* buf;
    if (!path || !out_buf || !out_len) return 0;
    f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return 0; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
    buf = (unsigned char*)malloc((size_t)sz);
    if (!buf) { fclose(f); return 0; }
    r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz) { free(buf); return 0; }
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 1;
}

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --dump <out.rdat> --n <count>\n"
        "      Generate <count> random valid entries, serialize to RDAT.\n"
        "\n"
        "  %s --load <in.rdat>\n"
        "      Load RDAT, zero-copy verify the batch and run a sample lookup.\n"
        "\n"
        "  %s --from-hex <in.txt> --to-rdat <out.rdat>\n"
        "      Convert a hex text file to RDAT. Each non-comment line must be:\n"
        "        z_hex r_hex s_hex v\n"
        "      where z/r/s are 64 hex chars (32 bytes), v is 0 or 1 (or 00/01).\n"
        "\n"
        "  %s --from-rdat <in.rdat> --to-hex <out.txt>\n"
        "      Dump RDAT entries as lines of: z_hex r_hex s_hex v\n"
        "\n"
        "Examples:\n"
        "  %s --dump batch.rdat --n 128\n"
        "  %s --load batch.rdat\n"
        "  %s --from-hex inputs.txt --to-rdat batch.rdat\n"
        "  %s --from-rdat batch.rdat --to-hex dump.txt\n"
        , prog, prog, prog, prog, prog, prog, prog, prog);
}

static int hex_nibble(char c, unsigned char* out) {
    if (c >= '0' && c <= '9') { *out = (unsigned char)(c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned char)(10 + c - 'a'); return 1; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned char)(10 + c - 'A'); return 1; }
    return 0;
}

static int hex_to_bytes(const char* hex, size_t hex_len, unsigned char* out, size_t out_len) {
    size_t i;
    if (hex_len != out_len * 2) return 0;
    for (i = 0; i < out_len; i++) {
        unsigned char hi, lo;
        if (!hex_nibble(hex[2*i], &hi) || !hex_nibble(hex[2*i+1], &lo)) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* Read RDAT and dump lines of hex: z r s v */
static int dump_hex_from_rdat_file(const secp256k1_context* ctx, const char* in_rdat, const char* out_txt) {
    unsigned char* filebuf;
    size_t filelen;
    const secp256k1_batch_entry* entries_view;
    size_t n2, i;
    FILE* f;
    (void)ctx;
    if (!in_rdat || !out_txt) return 0;
    if (!read_file(in_rdat, &filebuf, &filelen)) return 0;
    if (!secp256k1_rdat_view_parse(filebuf, filelen, &entries_view, &n2)) { free(filebuf); return 0; }
    f = fopen(out_txt, "w");
    if (!f) { free(filebuf); return 0; }
    for (i = 0; i < n2; i++) {
        size_t j;
        /* z */
        for (j = 0; j < 32; j++) fprintf(f, "%02x", entries_view[i].z32[j]);
        fprintf(f, " ");
        /* r */
        for (j = 0; j < 32; j++) fprintf(f, "%02x", entries_view[i].r32[j]);
        fprintf(f, " ");
        /* s */
        for (j = 0; j < 32; j++) fprintf(f, "%02x", entries_view[i].s32[j]);
        fprintf(f, " ");
        /* v */
        fprintf(f, "%u\n", (unsigned)(entries_view[i].v ? 1 : 0));
    }
    fclose(f);
    free(filebuf);
    return 1;
}

/* Parse a text file with lines: z_hex r_hex s_hex v
 * - z_hex, r_hex, s_hex are 64 hex chars (32 bytes)
 * - v is 0 or 1
 * Generate entries and write RDAT to out_path.
 */
static int generate_entries_from_hex_file(const secp256k1_context* ctx, const char* in_path, const char* out_path) {
    FILE* f;
    char line[1024];
    size_t count = 0;
    size_t i;
    secp256k1_batch_entry* entries = NULL;
    unsigned char* out = NULL;
    size_t out_size;
    size_t written = 0;
    int ok = 0;
    if (!ctx || !in_path || !out_path) return 0;
    f = fopen(in_path, "r");
    if (!f) return 0;
    /* First pass: count valid lines */
    while (fgets(line, sizeof(line), f) != NULL) {
        char zhex[129], rhex[129], shex[129], vstr[16];
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, "%128s %128s %128s %15s", zhex, rhex, shex, vstr) == 4) {
            size_t zl = strlen(zhex), rl = strlen(rhex), sl = strlen(shex), vl = strlen(vstr);
            if (zl == 64 && rl == 64 && sl == 64 && (vl == 1 || vl == 2)) count++;
        }
    }
    if (count == 0) { fclose(f); return 0; }
    entries = (secp256k1_batch_entry*)malloc(count * sizeof(*entries));
    if (!entries) { fclose(f); return 0; }
    rewind(f);
    /* Second pass: fill entries */
    i = 0;
    while (i < count && fgets(line, sizeof(line), f) != NULL) {
        char zhex[129], rhex[129], shex[129], vstr[16];
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, "%128s %128s %128s %15s", zhex, rhex, shex, vstr) != 4) continue;
        if (!hex_to_bytes(zhex, strlen(zhex), entries[i].z32, 32)) { ok = 0; break; }
        if (!hex_to_bytes(rhex, strlen(rhex), entries[i].r32, 32)) { ok = 0; break; }
        if (!hex_to_bytes(shex, strlen(shex), entries[i].s32, 32)) { ok = 0; break; }
        {
            /* v parsing: accept 0/1 or 00/01 */
            if (strlen(vstr) == 1 && (vstr[0] == '0' || vstr[0] == '1')) entries[i].v = (unsigned char)(vstr[0] - '0');
            else if (strlen(vstr) == 2) {
                unsigned char byte;
                if (!hex_to_bytes(vstr, 2, &byte, 1)) { ok = 0; break; }
                entries[i].v = (unsigned char)(byte & 1);
            } else { ok = 0; break; }
        }
        /* Build R from (r,v) */
        {
            unsigned char comp33[33];
            secp256k1_pubkey R_pub, Q_pub;
            size_t len = 65;
            unsigned char sig64[64];
            secp256k1_ecdsa_recoverable_signature sig_rec;
            comp33[0] = (entries[i].v ? 0x03 : 0x02);
            memcpy(&comp33[1], entries[i].r32, 32);
            if (!secp256k1_ec_pubkey_parse(ctx, &R_pub, comp33, 33)) { ok = 0; break; }
            if (!secp256k1_ec_pubkey_serialize(ctx, entries[i].R65, &len, &R_pub, SECP256K1_EC_UNCOMPRESSED)) { ok = 0; break; }
            if (len != 65) { ok = 0; break; }
            /* Recover Q from (r,s,v,z) */
            memcpy(sig64, entries[i].r32, 32);
            memcpy(sig64 + 32, entries[i].s32, 32);
            if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig_rec, sig64, entries[i].v)) { ok = 0; break; }
            if (!secp256k1_ecdsa_recover(ctx, &Q_pub, &sig_rec, entries[i].z32)) { ok = 0; break; }
            len = 65;
            if (!secp256k1_ec_pubkey_serialize(ctx, entries[i].Q65, &len, &Q_pub, SECP256K1_EC_UNCOMPRESSED)) { ok = 0; break; }
            if (len != 65) { ok = 0; break; }
        }
        i++;
        ok = 1;
    }
    fclose(f);
    if (!ok || i != count) { free(entries); return 0; }
    out_size = secp256k1_recover_data_serialized_size(count);
    out = (unsigned char*)malloc(out_size);
    if (!out) { free(entries); return 0; }
    if (!secp256k1_recover_data_serialize(ctx, entries, count, out, out_size, &written)) {
        free(out); free(entries); return 0;
    }
    ok = write_file(out_path, out, written);
    free(out);
    free(entries);
    return ok;
}

/* Dump: generate entries, serialize to RDAT, write to file */
static int run_dump(const secp256k1_context* ctx, size_t n, const char* dump_path) {
    secp256k1_batch_entry *entries;
    size_t out_size;
    unsigned char *out;
    size_t written = 0;
    int ok;
    if (!dump_path) return 1;
    entries = (secp256k1_batch_entry*)malloc(n * sizeof(*entries));
    if (!entries) {
        fprintf(stderr, "OOM\n");
        return 1;
    }
    if (!generate_valid_entries((secp256k1_context*)ctx, entries, n)) {
        fprintf(stderr, "Failed to generate valid entries\n");
        free(entries);
        return 1;
    }
    out_size = secp256k1_recover_data_serialized_size(n);
    out = (unsigned char*)malloc(out_size);
    if (!out) {
        fprintf(stderr, "OOM\n");
        free(entries);
        return 1;
    }
    ok = secp256k1_recover_data_serialize(ctx, entries, n, out, out_size, &written);
    if (!ok) {
        fprintf(stderr, "recover_data_serialize failed\n");
        free(out);
        free(entries);
        return 1;
    }
    if (!write_file(dump_path, out, written)) {
        fprintf(stderr, "Failed to write RDAT to %s\n", dump_path);
        free(out);
        free(entries);
        return 1;
    }
    printf("Dumped RDAT (%zu bytes) to %s\n", written, dump_path);
    free(out);
    free(entries);
    return 0;
}

/* Load: read RDAT, zero-copy view, verify and lookup */
static int run_load(const secp256k1_context* ctx, const char* load_path) {
    unsigned char* filebuf;
    size_t filelen;
    const secp256k1_batch_entry* entries_view;
    size_t n2;
    unsigned char multiplier32[32];
    int ok;
    if (!load_path) return 1;
    fill_random(multiplier32, sizeof(multiplier32));
    if (!read_file(load_path, &filebuf, &filelen)) {
        fprintf(stderr, "Failed to read %s\n", load_path);
        return 1;
    }
    if (!secp256k1_rdat_view_parse(filebuf, filelen, &entries_view, &n2)) {
        fprintf(stderr, "Invalid RDAT in %s\n", load_path);
        free(filebuf);
        return 1;
    }
    ok = secp256k1_verify_in_batch(ctx, entries_view, n2, multiplier32);
    printf("verify_in_batch (from file): %s n=%zu\n", ok ? "success" : "failure", n2);
    {
        unsigned char Q65_out[65];
        int match = secp256k1_lookup_ecrecover_i(
            ctx, entries_view, n2, 0,
            entries_view[0].r32, entries_view[0].s32, entries_view[0].v, entries_view[0].z32,
            Q65_out
        );
        printf("lookup_ecrecover_i (i=0, file): %s\n", match ? "matched Q" : "no match");
    }
    free(filebuf);
    return 0;
}

int main(int argc, char** argv) {
    size_t n = 0;
    int do_dump = 0;
    int do_load = 0;
    const char* dump_path = NULL;
    const char* load_path = NULL;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    /* Parse options: require one of --dump <file> or --load <file>, and --n <count> for dump.
     * Also support conversion:
     *   --from-hex <in> --to-rdat <out>
     *   --from-rdat <in> --to-hex <out>
     */
    {
        int i = 1;
        const char* from_hex = NULL; const char* to_rdat = NULL;
        const char* from_rdat = NULL; const char* to_hex = NULL;
        while (i < argc) {
            if (strcmp(argv[i], "--dump") == 0 && i + 1 < argc) {
                do_dump = 1; dump_path = argv[i + 1]; i += 2; continue;
            }
            if (strcmp(argv[i], "--load") == 0 && i + 1 < argc) {
                do_load = 1; load_path = argv[i + 1]; i += 2; continue;
            }
            if (strcmp(argv[i], "--from-hex") == 0 && i + 1 < argc) {
                from_hex = argv[i + 1]; i += 2; continue;
            }
            if (strcmp(argv[i], "--to-rdat") == 0 && i + 1 < argc) {
                to_rdat = argv[i + 1]; i += 2; continue;
            }
            if (strcmp(argv[i], "--n") == 0 && i + 1 < argc) {
                long nn = strtol(argv[i + 1], NULL, 10);
                if (nn <= 0) {
                    fprintf(stderr, "Invalid --n value: %s\n", argv[i + 1]);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                n = (size_t)nn;
                i += 2; continue;
            }
            if (strcmp(argv[i], "--from-rdat") == 0 && i + 1 < argc) { from_rdat = argv[i + 1]; i += 2; continue; }
            if (strcmp(argv[i], "--to-hex") == 0 && i + 1 < argc) { to_hex = argv[i + 1]; i += 2; continue; }
            print_usage(argv[0]);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        /* Handle conversion mode */
        if (from_hex || to_rdat) {
            int rc;
            if (!from_hex || !to_rdat) {
                fprintf(stderr, "Error: Both --from-hex <in> and --to-rdat <out> are required for conversion.\n\n");
                print_usage(argv[0]);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            rc = generate_entries_from_hex_file(ctx, from_hex, to_rdat);
            if (!rc) { fprintf(stderr, "Failed to convert %s -> %s\n", from_hex, to_rdat); secp256k1_context_destroy(ctx); return 1; }
            printf("Converted %s to RDAT %s\n", from_hex, to_rdat);
            secp256k1_context_destroy(ctx);
            return 0;
        }
        if (from_rdat || to_hex) {
            int rc;
            if (!from_rdat || !to_hex) {
                fprintf(stderr, "Error: Both --from-rdat <in> and --to-hex <out> are required for conversion.\n\n");
                print_usage(argv[0]);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            rc = dump_hex_from_rdat_file(ctx, from_rdat, to_hex);
            if (!rc) { fprintf(stderr, "Failed to convert %s -> %s\n", from_rdat, to_hex); secp256k1_context_destroy(ctx); return 1; }
            printf("Converted RDAT %s to hex %s\n", from_rdat, to_hex);
            secp256k1_context_destroy(ctx);
            return 0;
        }
        if (!!do_dump == !!do_load) {
            fprintf(stderr, "Error: Select exactly one: --dump or --load\n\n");
            print_usage(argv[0]);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (do_dump && n == 0) {
            fprintf(stderr, "Error: --dump requires --n <count>\n\n");
            print_usage(argv[0]);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    if (do_load) {
        int rc = run_load(ctx, load_path);
        secp256k1_context_destroy(ctx);
        return rc;
    } else if (do_dump) {
        int rc = run_dump(ctx, n, dump_path);
        secp256k1_context_destroy(ctx);
        return rc;
    }
    /* Unreachable due to earlier parsing; keep for completeness */
    secp256k1_context_destroy(ctx);
    return 1;
}


