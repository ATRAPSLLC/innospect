//! Streaming-friendly CRC32 / Adler32 helpers used across the
//! crate.
//!
//! Inno Setup uses both CRC32 (most modern paths) and Adler32 (some
//! legacy `exe_checksum` fields) over various small structures. This
//! module provides simple one-shot helpers - sufficient for the
//! offset-table and block-header checks; per-chunk content checksums
//! flow through the `crypto/` module instead.

/// CRC32 of `data` using the IEEE 802.3 polynomial.
///
/// Computed via a precomputed 256-entry table (built at compile time
/// inside this crate) - fast enough for the offset-table and block
/// header / sub-chunk checks without pulling in an extra dependency.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    crc32_finalize(crc32_update(crc32_init(), data))
}

/// Initial CRC32 state for streaming use.
pub(crate) fn crc32_init() -> u32 {
    0xFFFF_FFFF
}

/// Folds `data` into a streaming CRC32 state. Returns the new
/// pre-finalize state.
pub(crate) fn crc32_update(mut state: u32, data: &[u8]) -> u32 {
    for &byte in data {
        let idx = (state ^ u32::from(byte)) & 0xFF;
        let table_val = match TABLE.get(idx as usize) {
            Some(&v) => v,
            None => 0,
        };
        state = (state >> 8) ^ table_val;
    }
    state
}

/// Finalizes a streaming CRC32 state.
pub(crate) fn crc32_finalize(state: u32) -> u32 {
    state ^ 0xFFFF_FFFF
}

/// Precomputed CRC32 lookup table, IEEE 802.3 polynomial.
const TABLE: [u32; 256] = compute_table();

// Const-time polynomial expansion. Bounded by `i < 256` and `j < 8`,
// so neither overflow nor index-out-of-bounds is reachable; we
// silence the lints locally rather than restructure to avoid them.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
const fn compute_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut c = i;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            j += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_canonical_test_vector() {
        // "123456789" → 0xCBF43926 (canonical IEEE CRC-32 vector).
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn empty_input_is_zero_crc() {
        assert_eq!(crc32(b""), 0);
    }
}
