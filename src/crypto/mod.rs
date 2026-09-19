//! Crypto primitives for Inno Setup encryption.
//!
//! Layout:
//!
//! - [`pbkdf2`] - PBKDF2-HMAC-SHA256 KDF for 6.4+, with the
//!   UTF-16LE password encoding the Pascal source uses.
//! - [`xchacha20`] - XChaCha20 stream cipher used by 6.4+ for
//!   chunk encryption and `euFull` setup-0 encryption. Includes
//!   the per-chunk nonce derivation (`base XOR (start, slice)`)
//!   and the three "special" crypt contexts (`sccPasswordTest`,
//!   `sccCompressedBlocks1`, `sccCompressedBlocks2`).
//! - [`arc4`] - inline RC4 for pre-6.4 chunk encryption.
//! - [`kdflegacy`] - pre-6.4 password-verification families
//!   (CRC32 / MD5 / SHA-1) and ARC4 chunk-key derivation.
//!
//! Everything in this module is validated against published test
//! vectors (RFC 7914 / IETF XChaCha20 draft / RC4 reference)
//! independently of any installer integration. The parser-side
//! wiring lives in `extract::chunk`.

// Some primitives are validated against published test vectors
// but are not exercised by every code path; the dead-code lint
// is silenced module-wide so partial integration doesn't trip it.
#![allow(dead_code)]

pub(crate) mod arc4;
pub(crate) mod kdflegacy;
pub(crate) mod pbkdf2;
pub(crate) mod xchacha20;
