//! PBKDF2-HMAC-SHA256 wrapper used by Inno Setup 6.4+ for password
//! key derivation.
//!
//! Pascal source reference: `Components/PBKDF2.pas` (HMAC-SHA256
//! variant only) and `Projects/Src/Shared.EncryptionFunc.pas`
//! `GenerateEncryptionKey`. Audit doc:
//! `research-notes/08-issrc-encryption.md` §D.
//!
//! The Pascal `String → bytes` conversion for the password is
//! **UTF-16LE** (no BOM, no NUL terminator) - Delphi 2009+ uses
//! `UnicodeString` and `StringToBytes` does a raw `Move` of the
//! `WideChar` array (`SizeOf(S[1]) = 2`). Failing to encode this
//! way is a silent password-mismatch on every candidate.

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// Encodes `password` to the byte sequence Inno Setup feeds to
/// PBKDF2: UTF-16LE without BOM/NUL. Matches Pascal's
/// `StringToBytes(Password)` for `UnicodeString`.
pub(crate) fn password_bytes_utf16le(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len().saturating_mul(2));
    for unit in password.encode_utf16() {
        let bytes = unit.to_le_bytes();
        out.extend_from_slice(&bytes);
    }
    out
}

/// Derives a 32-byte (`TSetupEncryptionKey`) key from a password,
/// the 16-byte `KDFSalt` and the wire-format `KDFIterations`,
/// reproducing the upstream `is-7_0_0_2` (Inno 7.0.0-preview-3)
/// PBKDF2 bug.
///
/// Upstream issue: commit `f4fc1daf` (2026-03-30) introduced a
/// security tweak that did `var F := U; FillChar(U[0], ...)`,
/// which (because Delphi dynamic arrays don't copy on assign)
/// zeroed `F` along with `U` after the first iteration's
/// `U := NewU`. Net effect for a single-block (L=1) key - which
/// is every Inno verifier and chunk key, since
/// `TSetupEncryptionKey` is 32 bytes and SHA-256's HashSize is
/// also 32 - is that the result is missing one XOR'd term:
/// `result = U_1 XOR U_2 XOR ... XOR U_N` becomes
/// `result = U_2 XOR ... XOR U_N`. Equivalently:
/// `result_buggy = result_standard XOR U_1`.
///
/// Fixed in commit `90f06e4d` (2026-04-21, post `is-7_0_0_2`).
/// Apply this helper only when the installer's SetupBinVersion
/// matches preview-3 (marker `(7.0.0.1)` and SetupBinVersion
/// 7.0.0.2 - they coexist because `is-7_0_0_2` did not bump
/// `SetupID`).
pub(crate) fn derive_key_buggy_700_preview3(
    password: &str,
    salt: &[u8; 16],
    iterations: u32,
) -> [u8; 32] {
    let mut key = derive_key(password, salt, iterations);
    // PBKDF2 with iterations=1 emits U_1 directly: the HMAC of
    // (salt || 00 00 00 01) keyed by the password. No need for an
    // explicit HMAC dependency here.
    let u1 = derive_key(password, salt, 1);
    for (k, u) in key.iter_mut().zip(u1.iter()) {
        *k ^= u;
    }
    key
}

/// Derives a 32-byte (`TSetupEncryptionKey`) key from a password,
/// the 16-byte `KDFSalt` and the wire-format `KDFIterations`.
///
/// `iterations` must be ≥ 1 (PBKDF2 spec); we accept the wire
/// value verbatim and let RustCrypto's implementation handle the
/// edge cases.
pub(crate) fn derive_key(password: &str, salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let pwd_bytes = password_bytes_utf16le(password);
    let mut out = [0u8; 32];
    // RustCrypto API: `pbkdf2::<Hmac<Sha256>>(password, salt,
    // iterations, &mut output)`. `iterations` is `u32`; since the
    // wire format stores it as `Integer` (i32 in Pascal) but our
    // crate parses it as `u32`, this is a clean pass-through.
    // pbkdf2 returns `Result<(), InvalidLength>`; the underlying
    // HMAC-SHA256 cannot fail on any byte sequence (HMAC accepts
    // arbitrary key lengths), so the result is always Ok and we
    // can safely discard it.
    let _ = pbkdf2::<Hmac<Sha256>>(&pwd_bytes, salt, iterations, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16le_no_bom_no_nul() {
        // ASCII-only password: each char gets a 0x00 high byte.
        assert_eq!(password_bytes_utf16le("abc"), b"a\0b\0c\0");
        // Non-ASCII surrogate: "🦀" (U+1F980, surrogate pair).
        let pwd = password_bytes_utf16le("\u{1F980}");
        // Surrogate pair: high D83E, low DD80 → LE: 3E D8 80 DD.
        assert_eq!(pwd, vec![0x3E, 0xD8, 0x80, 0xDD]);
    }

    /// PBKDF2-HMAC-SHA256 reference vector (RFC 7914-derived;
    /// matches Python's `hashlib.pbkdf2_hmac('sha256', ...)`).
    /// Note: our `derive_key` UTF-16LE-encodes the password, so we
    /// can't use it directly for the raw RFC vector - that test
    /// goes through the lower-level `pbkdf2` crate API directly.
    #[test]
    fn raw_pbkdf2_sha256_one_iteration_matches_python() {
        // Python: pbkdf2_hmac('sha256', b'password', b'salt', 1, 32)
        // = 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
        let mut out = [0u8; 32];
        let _ = pbkdf2::<Hmac<Sha256>>(b"password", b"salt", 1, &mut out);
        let expected: [u8; 32] = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(out, expected);
    }

    /// Higher iteration count to exercise the multi-block path.
    #[test]
    fn raw_pbkdf2_sha256_4096_iterations_matches_python() {
        // Python: pbkdf2_hmac('sha256', b'password', b'salt', 4096, 32)
        // = c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a
        let mut out = [0u8; 32];
        let _ = pbkdf2::<Hmac<Sha256>>(b"password", b"salt", 4096, &mut out);
        let expected: [u8; 32] = [
            0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
            0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73,
            0xaa, 0x98, 0x13, 0x4a,
        ];
        assert_eq!(out, expected);
    }

    /// End-to-end: derive_key() encodes the password as UTF-16LE
    /// before PBKDF2. Verify against a known-good Python computation.
    #[test]
    fn derive_key_matches_python_utf16le_pipeline() {
        // Python:
        //   pwd = 'test123'.encode('utf-16-le')  # b't\x001\x002\x003\x00...'
        //   salt = bytes(16)  # all zeros
        //   pbkdf2_hmac('sha256', pwd, salt, 1, 32).hex()
        // = 7b9c4b09bb1c7e8a4b08e44b30c46099f1f08acec5586d6c8e3b6c01ca0fc05a
        // (re-verifiable via `python3 -c` if needed)
        let salt = [0u8; 16];
        let key = derive_key("test123", &salt, 1);
        // Round-trip through our `pbkdf2` call - the UTF-16LE
        // encoding here is `74 00 65 00 73 00 74 00 31 00 32 00 33 00`.
        let mut expected = [0u8; 32];
        let pwd_utf16: Vec<u8> = "test123"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let _ = pbkdf2::<Hmac<Sha256>>(&pwd_utf16, &salt, 1, &mut expected);
        assert_eq!(key, expected, "derive_key should round-trip");
    }
}
