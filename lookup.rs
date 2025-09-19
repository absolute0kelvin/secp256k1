// A minimal Rust implementation that mirrors secp256k1_lookup_ecrecover_i,
// taking entries as a flat &[u8] array of concatenated entries.
// Each entry layout (227 bytes):
//   0..65   -> Q65
//   65..130 -> R65
//   130..162 -> r32
//   162..194 -> s32
//   194..226 -> z32
//   226      -> v (0 or 1)
//
// Differences vs C:
// - Uses raw byte equality instead of secp256k1_scalar_eq.
// - Validates r32/s32 are non-zero and < group order (to match scalar overflow/zero checks).
// - Returns Option<[u8;65]>: Some(Q65) on match, None otherwise.

const ENTRY_SIZE: usize = 227;
const OFF_Q65: usize = 0;
const OFF_R65: usize = 65;
const OFF_R32: usize = 130;
const OFF_S32: usize = 162;
const OFF_Z32: usize = 194;
const OFF_V: usize = 226;

// secp256k1 group order n in big-endian (n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141)
const ORDER_N: [u8; 32] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
];

fn is_zero32(x: &[u8; 32]) -> bool {
    x.iter().all(|&b| b == 0)
}

fn be_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // constant-time not required here; mirror functional behavior
    for i in 0..32 {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    false // equal is not < (treated as overflow in scalar_set_b32)
}

fn is_canonical_scalar_be32(x: &[u8; 32]) -> bool {
    if is_zero32(x) { return false; }
    be_less_than(x, &ORDER_N)
}

pub fn secp256k1_lookup_ecrecover_i(
    entries: &[u8],
    n: usize,
    i: usize,
    r32: &[u8; 32],
    s32: &[u8; 32],
    v: u8,
    z32: &[u8; 32],
) -> Option<[u8; 65]> {
    if i >= n { return None; }
    // Ensure we have at least the i-th entry
    let need = (i.checked_add(1)?) * ENTRY_SIZE;
    if entries.len() < need { return None; }

    // Check input r/s like scalar_set_b32 overflow/zero checks
    if !is_canonical_scalar_be32(r32) { return None; }
    if !is_canonical_scalar_be32(s32) { return None; }
    // z is allowed to be any 32-byte; no overflow rejection in C other than parse overflow.
    // We skip scalar parse; byte-compare only.

    let base = i * ENTRY_SIZE;
    let entry = &entries[base..base + ENTRY_SIZE];

    let q65 = &entry[OFF_Q65..OFF_Q65 + 65];
    let r_ref = &entry[OFF_R32..OFF_R32 + 32];
    let s_ref = &entry[OFF_S32..OFF_S32 + 32];
    let z_ref = &entry[OFF_Z32..OFF_Z32 + 32];
    let v_ref = entry[OFF_V];

    let v_norm = if v != 0 { 1 } else { 0 };
    if v_ref != v_norm { return None; }
    if r32 != r_ref { return None; }
    if s32 != s_ref { return None; }
    if z32 != z_ref { return None; }

    let mut out = [0u8; 65];
    out.copy_from_slice(q65);
    Some(out)
}

fn main() {
    // Example usage (with dummy buffers). Replace with real data.
    // entries must be a concatenation of n entries (n * 227 bytes).
    let entries: Vec<u8> = Vec::new();
    let n = 0usize;
    let i = 0usize;
    let r32 = [0u8; 32];
    let s32 = [0u8; 32];
    let z32 = [0u8; 32];
    let v = 0u8;

    let _ = (entries, n, i, r32, s32, z32, v);
    // Call secp256k1_lookup_ecrecover_i(...) with real inputs.
}
