//! Pre-6.4 password verification and ARC4 chunk-key derivation.
//!
//! Inno Setup before 6.4.0 used three different password-hash
//! mechanisms depending on version, and ARC4 (with version-gated
//! hash) for chunk encryption. Cross-references:
//!
//! - innoextract `header.cpp:380-402` for the password hash
//!   layouts (`SHA1` 5.3.9..6.4, `MD5` 4.2.0..5.3.9, `CRC32` <
//!   4.2.0).
//! - innoextract `chunk.cpp:189-202` for the per-chunk key
//!   derivation (`SHA1` 5.3.9+ vs `MD5` pre-5.3.9), where the
//!   chunk's 8-byte salt is hashed with the password and the
//!   result truncated to 16 bytes for the RC4 key.
//! - `research-notes/06-crypto-variants-history.md` §"Pre-6.4
//!   password hashes".
//!
//! Password encoding is **UTF-16LE**, identical to the 6.4+ case.
//! For the SHA-1 / MD5 password-hash form, Inno also prefixes the
//! literal `"PasswordCheckHash"` (17 bytes, no NUL) before the
//! salt + password.

use md5::Digest as _;

use crate::{records::dataentry::DataChecksum, util::checksum::crc32};

/// Family of pre-6.4 password verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyHashFamily {
    /// `< 4.2.0`: 4-byte CRC32 of the UTF-16LE password (no salt,
    /// no `PasswordCheckHash` prefix).
    Crc32,
    /// `4.2.0 ≤ v < 4.2.2`: MD5(UTF-16LE password). No salt yet.
    Md5Bare,
    /// `4.2.2 ≤ v < 5.3.9`: MD5("PasswordCheckHash" || salt8 || pwd).
    Md5SaltedWithPrefix,
    /// `5.3.9 ≤ v < 6.4.0`: SHA1("PasswordCheckHash" || salt8 || pwd).
    Sha1SaltedWithPrefix,
}

/// Chooses the correct hash family for a parsed Inno Setup
/// version. Callers feed this to [`verify_password_legacy`].
pub(crate) fn legacy_hash_family(version: &crate::version::Version) -> LegacyHashFamily {
    if version.at_least(5, 3, 9) {
        LegacyHashFamily::Sha1SaltedWithPrefix
    } else if version.at_least(4, 2, 2) {
        LegacyHashFamily::Md5SaltedWithPrefix
    } else if version.at_least(4, 2, 0) {
        LegacyHashFamily::Md5Bare
    } else {
        LegacyHashFamily::Crc32
    }
}

/// Stored password hash, decoded from the parsed `HeaderTail`
/// fields per Inno version. The variant matches the family
/// selected by [`legacy_hash_family`].
#[derive(Clone, Debug)]
pub(crate) enum LegacyStoredHash {
    /// `< 4.2.0`.
    Crc32(u32),
    /// `4.2.0..4.2.2` — bare MD5 (no salt). `salt` is unused but
    /// kept for API uniformity.
    Md5Bare([u8; 16]),
    /// `4.2.2..5.3.9` — MD5 + 8-byte salt + literal prefix.
    Md5Salted { hash: [u8; 16], salt: [u8; 8] },
    /// `5.3.9..6.4` — SHA-1 + 8-byte salt + literal prefix.
    Sha1Salted { hash: [u8; 20], salt: [u8; 8] },
}

/// The 17-byte literal prefix Inno's compiler/runtime prepend
/// before salt+password when computing the password hash for
/// 4.2.2..6.4.
pub(crate) const PASSWORD_CHECK_HASH_PREFIX: &[u8] = b"PasswordCheckHash";

/// Verifies a candidate password against the stored hash form.
/// `password` is encoded according to the installer's wire string
/// type — UTF-16LE for Unicode builds (5.6+ default, plus any pre-5.6
/// build with the `(u)` marker), Windows-1252 for ANSI builds. This
/// matches innoextract `info::get_key` (`research/src/setup/info.cpp:322-352`)
/// which feeds the password to the hasher via `util::from_utf8(...,
/// codepage)`.
pub(crate) fn verify_password_legacy(
    password: &str,
    stored: &LegacyStoredHash,
    unicode: bool,
) -> bool {
    let pwd: Vec<u8> = if unicode {
        crate::crypto::pbkdf2::password_bytes_utf16le(password)
    } else {
        // Pre-5.6 ANSI: the password is sent through Windows-1252.
        // Non-ASCII passwords would need the per-language codepage,
        // but ASCII (the dominant case) round-trips as raw bytes.
        password.bytes().collect()
    };
    match stored {
        LegacyStoredHash::Crc32(expected) => {
            // Pre-4.2: bare CRC32 of password.
            crc32(&pwd) == *expected
        }
        LegacyStoredHash::Md5Bare(expected) => {
            let mut h = md5::Md5::new();
            h.update(&pwd);
            let actual = h.finalize();
            actual.as_slice() == expected.as_slice()
        }
        LegacyStoredHash::Md5Salted { hash, salt } => {
            let mut h = md5::Md5::new();
            h.update(PASSWORD_CHECK_HASH_PREFIX);
            h.update(salt);
            h.update(&pwd);
            let actual = h.finalize();
            actual.as_slice() == hash.as_slice()
        }
        LegacyStoredHash::Sha1Salted { hash, salt } => {
            let mut h = sha1::Sha1::new();
            h.update(PASSWORD_CHECK_HASH_PREFIX);
            h.update(salt);
            h.update(&pwd);
            let actual = h.finalize();
            actual.as_slice() == hash.as_slice()
        }
    }
}

/// Derives the per-chunk RC4 key for pre-6.4 chunk encryption.
///
/// `chunk_salt` is the 8-byte per-chunk prefix read from the chunk
/// body (right after the `zlb\x1a` magic, before the
/// encrypted+compressed stream). `use_sha1` is `true` for the
/// 5.3.9..6.4 SHA-1 path and `false` for the pre-5.3.9 MD5 path.
/// `unicode` selects the password encoding: `true` for Unicode
/// builds (UTF-16LE bytes) and `false` for legacy ANSI builds
/// (Windows-1252 / raw bytes). innoextract feeds the codepage-
/// encoded password into the hash via `info::get_key`
/// (`research/src/setup/info.cpp:322-352`), and the chunk
/// decryptor (`research/src/stream/chunk.cpp:196-202`) hashes
/// `salt || key` as-is. Using the wrong encoding produces a
/// valid-looking RC4 key that decrypts to garbage — observable as
/// LZMA stream-format errors, not a clean failure.
///
/// Returns the **full** hash digest as the RC4 key — 20 bytes for
/// SHA-1 (5.3.9..6.4 era) and 16 bytes for MD5 (pre-5.3.9). RC4's
/// KSA accepts variable-length keys, so the digest is fed in
/// unmodified.
pub(crate) fn arc4_chunk_key(
    password: &str,
    chunk_salt: &[u8; 8],
    use_sha1: bool,
    unicode: bool,
) -> Vec<u8> {
    let pwd: Vec<u8> = if unicode {
        crate::crypto::pbkdf2::password_bytes_utf16le(password)
    } else {
        password.bytes().collect()
    };
    if use_sha1 {
        let mut h = sha1::Sha1::new();
        h.update(chunk_salt);
        h.update(&pwd);
        h.finalize().to_vec()
    } else {
        let mut h = md5::Md5::new();
        h.update(chunk_salt);
        h.update(&pwd);
        h.finalize().to_vec()
    }
}

/// Returns a stable string label for `c`'s digest algorithm.
///
/// Reserved for future use when pre-6.4 chunk-content checksums
/// (CRC32, MD5) are routed through the crypto module; currently
/// only callable from tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn checksum_label(c: &DataChecksum) -> &'static str {
    match c {
        DataChecksum::Adler32(_) => "Adler32",
        DataChecksum::Crc32(_) => "CRC32",
        DataChecksum::Md5(_) => "MD5",
        DataChecksum::Sha1(_) => "SHA-1",
        DataChecksum::Sha256(_) => "SHA-256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: u8, b: u8, c: u8) -> crate::version::Version {
        crate::version::Version {
            a,
            b,
            c,
            d: 0,
            flags: crate::version::VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    #[test]
    fn family_per_version() {
        assert_eq!(legacy_hash_family(&v(4, 1, 0)), LegacyHashFamily::Crc32);
        assert_eq!(legacy_hash_family(&v(4, 2, 0)), LegacyHashFamily::Md5Bare);
        assert_eq!(
            legacy_hash_family(&v(4, 2, 2)),
            LegacyHashFamily::Md5SaltedWithPrefix
        );
        assert_eq!(
            legacy_hash_family(&v(5, 3, 9)),
            LegacyHashFamily::Sha1SaltedWithPrefix
        );
        assert_eq!(
            legacy_hash_family(&v(6, 0, 0)),
            LegacyHashFamily::Sha1SaltedWithPrefix
        );
    }

    #[test]
    fn verify_md5_bare_round_trip() {
        // MD5(UTF-16LE("hunter2")) = ?
        let pwd_utf16: Vec<u8> = "hunter2"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut h = md5::Md5::new();
        h.update(&pwd_utf16);
        let digest = h.finalize();
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&digest);
        let stored = LegacyStoredHash::Md5Bare(hash);
        assert!(verify_password_legacy("hunter2", &stored, true));
        assert!(!verify_password_legacy("wrong", &stored, true));
    }

    #[test]
    fn verify_sha1_salted_round_trip() {
        let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let pwd_utf16: Vec<u8> = "test123"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut h = sha1::Sha1::new();
        h.update(PASSWORD_CHECK_HASH_PREFIX);
        h.update(salt);
        h.update(&pwd_utf16);
        let digest = h.finalize();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest);
        let stored = LegacyStoredHash::Sha1Salted { hash, salt };
        assert!(verify_password_legacy("test123", &stored, true));
        assert!(!verify_password_legacy("test1234", &stored, true));
    }

    #[test]
    fn verify_md5_salted_round_trip() {
        let salt = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let pwd_utf16: Vec<u8> = "p".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut h = md5::Md5::new();
        h.update(PASSWORD_CHECK_HASH_PREFIX);
        h.update(salt);
        h.update(&pwd_utf16);
        let digest = h.finalize();
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&digest);
        let stored = LegacyStoredHash::Md5Salted { hash, salt };
        assert!(verify_password_legacy("p", &stored, true));
        assert!(!verify_password_legacy("q", &stored, true));
    }

    #[test]
    fn verify_crc32_pre_4_2() {
        let pwd_utf16: Vec<u8> = "x".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let stored = LegacyStoredHash::Crc32(crc32(&pwd_utf16));
        assert!(verify_password_legacy("x", &stored, true));
        assert!(!verify_password_legacy("y", &stored, true));
    }

    #[test]
    fn arc4_key_md5_vs_sha1_differ_in_length_and_bytes() {
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let md5_key = arc4_chunk_key("test", &salt, false, true);
        let sha1_key = arc4_chunk_key("test", &salt, true, true);
        assert_eq!(md5_key.len(), 16, "MD5 digest");
        assert_eq!(sha1_key.len(), 20, "SHA-1 digest");
        // First 16 bytes are guaranteed to differ — different
        // hash families.
        assert_ne!(&md5_key[..], &sha1_key[..16]);
    }

    #[test]
    fn arc4_key_changes_with_salt() {
        let s1 = [1u8; 8];
        let s2 = [2u8; 8];
        assert_ne!(
            arc4_chunk_key("x", &s1, true, true),
            arc4_chunk_key("x", &s2, true, true)
        );
    }

    /// ANSI vs Unicode password encoding produces different keys
    /// for the same password — the bug surfaced by the new
    /// chunk-encrypted ANSI samples (5.5.7 / 6.0.0u / 6.3.0).
    #[test]
    fn arc4_key_ansi_differs_from_unicode() {
        let salt = [9u8; 8];
        let unicode_key = arc4_chunk_key("test123", &salt, true, true);
        let ansi_key = arc4_chunk_key("test123", &salt, true, false);
        assert_ne!(unicode_key, ansi_key);
    }
}
