//! Bit-packed Pascal sets.

use std::{collections::HashSet, hash::Hash};

/// Decodes a bit-packed flag set: bit `i` of `raw` (LSB-first within
/// each byte) selects `table[i]`. Bits past `table.len()` are ignored;
/// trailing bytes past `raw.len()` contribute nothing.
pub fn decode_packed_flags<T: Copy + Eq + Hash>(raw: &[u8], table: &[T]) -> HashSet<T> {
    let mut out = HashSet::new();
    for (bit, flag) in table.iter().enumerate() {
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        if let Some(b) = raw.get(byte_idx)
            && (b >> bit_idx) & 1 == 1
        {
            out.insert(*flag);
        }
    }
    out
}
