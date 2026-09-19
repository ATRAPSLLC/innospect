//! Setup record parsing and iteration.
//!
//! Reads the typed record entries that follow `TSetupHeader` in the
//! decompressed `setup-0` stream. Each submodule maps to one Pascal
//! record type from `Shared.Struct.pas`. Cross-version conditionals
//! are documented per-record; the canonical reference is
//! `research-notes/04-setup-records.md`.
//!
//! [`windows`] holds the bit-packed-set helpers used by both the
//! fixed numeric tail of `TSetupHeader` and the per-record
//! `ItemBase`. [`item`] is the conditions section + version-range
//! bundle every record-with-conditions reads. The remaining modules
//! map one-to-one to Pascal record types - lightweight ones
//! ([`type_`], [`component`], [`task`], [`language`], [`message`],
//! [`permission`]) and heavier ones ([`directory`], [`mod@file`],
//! [`icon`], [`ini`], [`registry`], [`run`], [`delete`],
//! [`dataentry`], [`isssigkey`]).

pub mod component;
pub mod dataentry;
pub mod delete;
pub mod directory;
pub mod file;
pub mod icon;
pub mod ini;
pub mod isssigkey;
pub mod item;
pub mod language;
pub mod message;
pub mod permission;
pub mod registry;
pub mod run;
pub mod task;
pub mod type_;
pub mod windows;

use std::collections::HashSet;
use std::hash::Hash;

/// Decodes a bit-packed flag set: bit `i` of `raw` (LSB-first within
/// each byte) selects `table[i]`. Bits past `table.len()` are ignored;
/// trailing bytes past `raw.len()` contribute nothing.
pub(crate) fn decode_packed_flags<T: Copy + Eq + Hash>(raw: &[u8], table: &[T]) -> HashSet<T> {
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
