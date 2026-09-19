//! XChaCha20 stream-cipher wrapper used by Inno Setup 6.4+ for
//! chunk encryption (and 6.5+ `euFull` setup-0 encryption).
//!
//! Pascal source reference: `Components/ChaCha20.pas`. Audit doc:
//! `research-notes/08-issrc-encryption.md` §B–§E. Per-chunk nonce
//! derivation:
//!
//! ```text
//! nonce[0..7]  = BaseNonce[0..7]  XOR (chunk_start_offset as i64 LE)
//! nonce[8..11] = BaseNonce[8..11] XOR (first_slice as i32 LE)
//! nonce[12..23] = BaseNonce[12..23]   (unchanged)
//! ```
//!
//! For "special" crypt contexts (`sccPasswordTest = -1`,
//! `sccCompressedBlocks1 = -2`, `sccCompressedBlocks2 = -3`),
//! `chunk_start_offset = 0` and `first_slice = SpecialFirstSlice`.

use chacha20::{
    XChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};

/// XChaCha20 key (32 bytes).
pub(crate) type Key = [u8; 32];
/// XChaCha20 nonce (24 bytes).
pub(crate) type Nonce = [u8; 24];

/// Special crypt-context type per Pascal `TSpecialCryptContextType`
/// (`Shared.EncryptionFunc.pas:18`). Used to derive
/// `SpecialFirstSlice = -1 - typ_index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpecialContext {
    /// Verifier - `SpecialFirstSlice = -1`.
    PasswordTest,
    /// `euFull` setup-0 first block - `SpecialFirstSlice = -2`.
    CompressedBlocks1,
    /// `euFull` setup-0 second block - `SpecialFirstSlice = -3`.
    CompressedBlocks2,
}

impl SpecialContext {
    /// Returns the `FirstSlice` (i32) the context resolves to.
    pub(crate) fn first_slice(self) -> i32 {
        // SpecialFirstSlice = -1 - (Ord(Typ) - Ord(Low(Typ)))
        // PasswordTest=0 → -1, CompressedBlocks1=1 → -2,
        // CompressedBlocks2=2 → -3.
        match self {
            Self::PasswordTest => -1,
            Self::CompressedBlocks1 => -2,
            Self::CompressedBlocks2 => -3,
        }
    }
}

/// Derives the actual XChaCha20 nonce for a given chunk position
/// from the installer's `BaseNonce` plus the chunk's
/// `(start_offset, first_slice)` pair.
///
/// Matches `InitCryptContext`
/// (`Shared.EncryptionFunc.pas:50-60`):
///
/// ```pascal
/// Nonce.RandomXorStartOffset := Nonce.RandomXorStartOffset xor StartOffset;
/// Nonce.RandomXorFirstSlice  := Nonce.RandomXorFirstSlice  xor FirstSlice;
/// ```
pub(crate) fn chunk_nonce(base: &Nonce, start_offset: u64, first_slice: i32) -> Nonce {
    let mut out = *base;

    // Bytes 0..7: i64 LE XOR with `start_offset` (Inno treats as
    // signed Int64 - but XOR is bit-identical between the two).
    let off_bytes = start_offset.to_le_bytes();
    for i in 0..8 {
        let Some(dst) = out.get_mut(i) else {
            continue;
        };
        let src = off_bytes.get(i).copied().unwrap_or(0);
        *dst ^= src;
    }

    // Bytes 8..11: i32 LE XOR with `first_slice` (signed; XOR with
    // -1 / -2 / -3 corresponds to inverting the low 32 bits).
    #[allow(clippy::cast_sign_loss)]
    let slice_bytes = (first_slice as u32).to_le_bytes();
    for i in 0..4 {
        let dst_idx = 8usize.saturating_add(i);
        let Some(dst) = out.get_mut(dst_idx) else {
            continue;
        };
        let src = slice_bytes.get(i).copied().unwrap_or(0);
        *dst ^= src;
    }

    // Bytes 12..23: unchanged from `base`.
    out
}

/// Convenience: derive the nonce for one of the three "special"
/// contexts (verifier or `euFull` block).
pub(crate) fn special_nonce(base: &Nonce, ctx: SpecialContext) -> Nonce {
    chunk_nonce(base, 0, ctx.first_slice())
}

/// Decrypts (or equivalently encrypts) `buf` in place under the
/// given `(key, nonce)`. XChaCha20 is its own inverse.
pub(crate) fn apply_keystream(key: &Key, nonce: &Nonce, buf: &mut [u8]) {
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(buf);
}

/// Returns the 4-byte verifier value for a given derived key.
/// Matches Pascal `GeneratePasswordTest`
/// (`Shared.EncryptionFunc.pas:71-80`): encrypt 4 zero bytes under
/// the `sccPasswordTest`-derived nonce; the cipher output is the
/// verifier.
pub(crate) fn password_test_verifier(key: &Key, base: &Nonce) -> u32 {
    let nonce = special_nonce(base, SpecialContext::PasswordTest);
    let mut buf = [0u8; 4];
    apply_keystream(key, &nonce, &mut buf);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms our nonce-derivation matches the canonical
    /// `xor -1` shortcut for `sccPasswordTest`. With base = all
    /// zeros, the result should have bytes 8..11 = `0xFF` (i32 LE
    /// of -1) and everything else zero.
    #[test]
    fn special_nonce_password_test_xor_minus_one() {
        let base = [0u8; 24];
        let nonce = special_nonce(&base, SpecialContext::PasswordTest);
        let mut expected = [0u8; 24];
        expected[8] = 0xFF;
        expected[9] = 0xFF;
        expected[10] = 0xFF;
        expected[11] = 0xFF;
        assert_eq!(nonce, expected);
    }

    #[test]
    fn special_nonce_compressed_blocks_1_xor_minus_two() {
        let base = [0u8; 24];
        let nonce = special_nonce(&base, SpecialContext::CompressedBlocks1);
        // -2 as i32 LE = `FE FF FF FF`.
        assert_eq!(&nonce[8..12], &[0xFE, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn special_nonce_compressed_blocks_2_xor_minus_three() {
        let base = [0u8; 24];
        let nonce = special_nonce(&base, SpecialContext::CompressedBlocks2);
        // -3 as i32 LE = `FD FF FF FF`.
        assert_eq!(&nonce[8..12], &[0xFD, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn chunk_nonce_xors_offset_and_slice_into_base() {
        let mut base = [0u8; 24];
        // Mark base positions 8..11 with a known pattern.
        base[8] = 0xAA;
        base[9] = 0xBB;
        base[10] = 0xCC;
        base[11] = 0xDD;
        // Mark base positions 12..23 to verify they're untouched.
        for (i, b) in base.iter_mut().enumerate().take(24).skip(12) {
            *b = u8::try_from(i).unwrap_or(0xEE);
        }

        let nonce = chunk_nonce(&base, 0x01_02_03_04_05_06_07_08, 0x11_22_33_44);

        // Bytes 0..7: 0 XOR 0x0807060504030201 (LE) = 08,07,...,01.
        assert_eq!(
            &nonce[0..8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        // Bytes 8..11: AABBCCDD XOR 44332211 = EE 88 EE EE.
        assert_eq!(
            &nonce[8..12],
            &[0xAA ^ 0x44, 0xBB ^ 0x33, 0xCC ^ 0x22, 0xDD ^ 0x11]
        );
        // Bytes 12..23: untouched.
        for (i, b) in nonce.iter().enumerate().skip(12) {
            assert_eq!(*b, u8::try_from(i).unwrap_or(0));
        }
    }

    /// XChaCha20 IETF reference test vector from
    /// <https://tools.ietf.org/id/draft-arciszewski-xchacha-03.html#rfc.appendix.A.3.2>.
    /// Note the nonce's LAST byte is `0x58` (not the natural
    /// `0x57` sequence) - the draft's chosen nonce is
    /// `404142...5658`. Verbatim copy from the `chacha20` crate's
    /// own test (`tests/mod.rs::xchacha20::xchacha20_keystream`)
    /// so we get an end-to-end check that the bytes coming out of
    /// our [`apply_keystream`] wrapper match the well-known
    /// reference.
    #[test]
    fn xchacha20_rfc_sunscreen_vector() {
        let key: Key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: Nonce = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x58,
        ];

        // Skip the first 64 bytes of keystream, then take the
        // next 32 bytes and check they match the draft's
        // expected keystream prefix.
        let mut buf = [0u8; 64 + 32];
        apply_keystream(&key, &nonce, &mut buf);
        let expected_first_32: [u8; 32] = [
            0x29, 0x62, 0x4b, 0x4b, 0x1b, 0x14, 0x0a, 0xce, 0x53, 0x74, 0x0e, 0x40, 0x5b, 0x21,
            0x68, 0x54, 0x0f, 0xd7, 0xd6, 0x30, 0xc1, 0xf5, 0x36, 0xfe, 0xcd, 0x72, 0x2f, 0xc3,
            0xcd, 0xdb, 0xa7, 0xf4,
        ];
        assert_eq!(&buf[64..96], expected_first_32);
    }

    /// XChaCha20 round-trip: encrypt then decrypt yields the
    /// original.
    #[test]
    fn xchacha20_round_trip() {
        let key: Key = [0x42; 32];
        let nonce: Nonce = [0x37; 24];
        let original = b"Inno test payload v1\n";
        let mut buf = original.to_vec();
        apply_keystream(&key, &nonce, &mut buf);
        assert_ne!(buf.as_slice(), original);
        apply_keystream(&key, &nonce, &mut buf);
        assert_eq!(buf.as_slice(), original);
    }

    /// Validates the password-test verifier against an end-to-end
    /// computation: `key = PBKDF2-SHA256("test123" UTF-16LE, salt=
    /// zeros, iter=1)`, base nonce all zeros, expect the 4-byte
    /// XChaCha20 keystream output for the special context.
    #[test]
    fn password_test_verifier_round_trip() {
        // Set up a synthetic key via our pbkdf2 helper.
        let salt = [0u8; 16];
        let key = super::super::pbkdf2::derive_key("test123", &salt, 1);
        let base = [0u8; 24];
        let v = password_test_verifier(&key, &base);
        // Self-consistency: re-running gives the same result.
        let v2 = password_test_verifier(&key, &base);
        assert_eq!(v, v2);
        // Different password → different verifier.
        let key2 = super::super::pbkdf2::derive_key("hunter2", &salt, 1);
        let v3 = password_test_verifier(&key2, &base);
        assert_ne!(v, v3);
    }
}
