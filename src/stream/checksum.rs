//! Streaming checksum verification for extracted file content.
//!
//! Each `DataEntry` records a content hash whose family depends on
//! the installer's Inno Setup version (per
//! innoextract `setup/data.cpp`):
//!
//! | Version range  | Family   |
//! | -------------- | -------- |
//! | < 4.0.1        | Adler32  |
//! | 4.0.1..4.2.0   | CRC32    |
//! | 4.2.0..5.3.9   | MD5      |
//! | 5.3.9..6.4.0   | SHA-1    |
//! | 6.4.0+         | SHA-256  |
//!
//! The `Hasher` here wraps each algorithm behind one streaming
//! interface so [`crate::stream::file::FileReader`] can feed bytes
//! through `update` and finalize at EOF without caring about the
//! family.

// All three RustCrypto crates re-export the same `digest::Digest`
// trait; importing it once suffices for `update` / `finalize`.
use md5::Digest as _;

use crate::{
    error::Error,
    records::dataentry::DataChecksum,
    util::checksum::{crc32_finalize, crc32_init, crc32_update},
};

/// Running hasher chosen by the [`DataChecksum`] family.
pub enum Hasher {
    Adler32 {
        state: Adler32State,
        expected: u32,
    },
    Crc32 {
        state: u32,
        expected: u32,
    },
    Md5 {
        state: md5::Md5,
        expected: [u8; 16],
    },
    Sha1 {
        state: sha1::Sha1,
        expected: [u8; 20],
    },
    Sha256 {
        state: sha2::Sha256,
        expected: [u8; 32],
    },
}

impl Hasher {
    /// Constructs the hasher matching the entry's recorded checksum.
    pub fn from_data_checksum(c: &DataChecksum) -> Self {
        match *c {
            DataChecksum::Adler32(expected) => Self::Adler32 {
                state: Adler32State::new(),
                expected,
            },
            DataChecksum::Crc32(expected) => Self::Crc32 {
                state: crc32_init(),
                expected,
            },
            DataChecksum::Md5(expected) => Self::Md5 {
                state: md5::Md5::new(),
                expected,
            },
            DataChecksum::Sha1(expected) => Self::Sha1 {
                state: sha1::Sha1::new(),
                expected,
            },
            DataChecksum::Sha256(expected) => Self::Sha256 {
                state: sha2::Sha256::new(),
                expected,
            },
        }
    }

    /// Feeds bytes into the running hash.
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Adler32 { state, .. } => state.update(bytes),
            Self::Crc32 { state, .. } => *state = crc32_update(*state, bytes),
            Self::Md5 { state, .. } => state.update(bytes),
            Self::Sha1 { state, .. } => state.update(bytes),
            Self::Sha256 { state, .. } => state.update(bytes),
        }
    }

    /// Finalizes and verifies. Returns `Err(Error::ChecksumMismatch)`
    /// if the hash differs from the expected value.
    pub fn finalize(self) -> Result<(), Error> {
        match self {
            Self::Adler32 { state, expected } => {
                let actual = state.finalize();
                if actual != expected {
                    return Err(mismatch_u32("Adler32", expected, actual));
                }
            }
            Self::Crc32 { state, expected } => {
                let actual = crc32_finalize(state);
                if actual != expected {
                    return Err(mismatch_u32("CRC32", expected, actual));
                }
            }
            Self::Md5 { state, expected } => {
                let actual = state.finalize();
                if actual.as_slice() != expected.as_slice() {
                    return Err(mismatch_bytes("MD5", &expected, actual.as_slice()));
                }
            }
            Self::Sha1 { state, expected } => {
                let actual = state.finalize();
                if actual.as_slice() != expected.as_slice() {
                    return Err(mismatch_bytes("SHA-1", &expected, actual.as_slice()));
                }
            }
            Self::Sha256 { state, expected } => {
                let actual = state.finalize();
                if actual.as_slice() != expected.as_slice() {
                    return Err(mismatch_bytes("SHA-256", &expected, actual.as_slice()));
                }
            }
        }
        Ok(())
    }
}

fn mismatch_u32(algorithm: &'static str, expected: u32, actual: u32) -> Error {
    Error::ChecksumMismatch {
        algorithm,
        expected: format!("{expected:#010x}"),
        actual: format!("{actual:#010x}"),
    }
}

fn mismatch_bytes(algorithm: &'static str, expected: &[u8], actual: &[u8]) -> Error {
    Error::ChecksumMismatch {
        algorithm,
        expected: hex(expected),
        actual: hex(actual),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(nibble((b >> 4) & 0xF));
        out.push(nibble(b & 0xF));
    }
    out
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0'.saturating_add(n)),
        10..=15 => char::from(b'a'.saturating_add(n.saturating_sub(10))),
        _ => '?',
    }
}

/// Adler-32 state machine. RFC 1950 §9, `Mod = 65521`.
pub struct Adler32State {
    a: u32,
    b: u32,
}

impl Adler32State {
    pub fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        const MOD: u32 = 65521;
        // Process in chunks of 5552 to defer the modulo step
        // (avoids overflow per the canonical Adler32 implementation).
        for chunk in bytes.chunks(5552) {
            for &byte in chunk {
                self.a = self.a.saturating_add(u32::from(byte));
                self.b = self.b.saturating_add(self.a);
            }
            self.a = self.a.checked_rem(MOD).unwrap_or(0);
            self.b = self.b.checked_rem(MOD).unwrap_or(0);
        }
    }

    pub fn finalize(self) -> u32 {
        // (b << 16) | a
        (self.b << 16) | self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn adler32_canonical_test_vector() {
        // Wikipedia: Adler32("Wikipedia") = 0x11E60398
        let mut s = Adler32State::new();
        s.update(b"Wikipedia");
        assert_eq!(s.finalize(), 0x11E60398);
    }

    #[test]
    fn hex_encoding_lowercase() {
        assert_eq!(hex(&[0x00, 0xFF, 0xAB, 0xCD]), "00ffabcd");
    }

    #[test]
    fn sha256_round_trip_against_known_value() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let c = DataChecksum::Sha256(expected);
        let mut h = Hasher::from_data_checksum(&c);
        h.update(b"abc");
        h.finalize().unwrap();
    }

    #[test]
    fn sha256_mismatch_surfaces_error() {
        let mut wrong = [0u8; 32];
        wrong[0] = 1;
        let c = DataChecksum::Sha256(wrong);
        let mut h = Hasher::from_data_checksum(&c);
        h.update(b"abc");
        let err = h.finalize().unwrap_err();
        let Error::ChecksumMismatch { algorithm, .. } = err else {
            panic!("expected ChecksumMismatch");
        };
        assert_eq!(algorithm, "SHA-256");
    }
}
