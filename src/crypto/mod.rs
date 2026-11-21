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
//! wiring lives in `stream::chunk`.

pub mod arc4;
pub mod kdflegacy;
pub mod pbkdf2;
pub mod xchacha20;
