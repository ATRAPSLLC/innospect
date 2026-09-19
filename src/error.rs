//! Error type for the `innospect` crate.

use std::{fmt, io};

/// Errors produced while locating, parsing, or decompressing an Inno Setup
/// installer.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The byte slice is not a recognizable PE executable.
    NotPe,
    /// Parsing the PE container failed (malformed headers, bad sections,
    /// etc.). Distinct from [`Error::NotPe`]: the bytes look like a PE
    /// but the structure could not be walked.
    PeParseFailed {
        /// goblin's diagnostic, captured as a string.
        reason: String,
    },
    /// The PE overlay does not contain a recognizable Inno Setup loader
    /// table (`SetupLdr`) or setup header signature.
    NotInnoSetup,
    /// A structural field (offset, length) points outside the input
    /// buffer.
    Truncated {
        /// Human-readable description of the field that ran past the end
        /// of the input.
        what: &'static str,
    },
    /// A length / offset produced an unsigned-integer overflow. Treated
    /// as truncation but distinguished for diagnostic purposes.
    Overflow {
        /// Human-readable description of the overflowing computation.
        what: &'static str,
    },
    /// The 12-byte SetupLdr magic at the offsets table did not match any
    /// known version family.
    UnknownSetupLdrMagic {
        /// The 12-byte magic that was actually read.
        magic: [u8; 12],
    },
    /// The data version string at the start of the setup header was
    /// recognized as Inno Setup but is not yet supported by this crate.
    UnsupportedVersion {
        /// The raw `Inno Setup Setup Data (X.Y.Z)` marker as read from
        /// the installer (up to 64 bytes, may include trailing nulls).
        marker: [u8; 64],
    },
    /// A CRC32 / Adler32 / table-CRC validation failed.
    BadChecksum {
        /// What was being validated (e.g. `"SetupLdr offset table"`).
        what: &'static str,
        /// The expected checksum from the file.
        expected: u32,
        /// The checksum we actually computed over the bytes.
        actual: u32,
    },
    /// A compressed stream failed to decode.
    Decompress {
        /// Which stream failed (e.g. `"setup header"`, `"file 0"`).
        stream: &'static str,
        /// Underlying I/O error from the decompressor.
        source: io::Error,
    },
    /// A UTF-16LE string field contained an invalid surrogate pair or
    /// odd byte count.
    InvalidUtf16 {
        /// Which field failed to decode.
        what: &'static str,
    },
    /// The `FileEntry` has no associated file-location slot
    /// (`location_index == u32::MAX`). Used by the embedded
    /// uninstaller stub which doesn't carry payload bytes.
    NoLocation,
    /// The chunk is encrypted (`ChunkEncrypted` flag set on the
    /// `DataEntry`) and no decryption key is available - typically
    /// because the caller didn't supply a password.
    Encrypted,
    /// The installer is encrypted but the candidate-password list
    /// passed to [`crate::InnoInstaller::from_bytes_with_passwords`]
    /// was empty.
    PasswordRequired,
    /// The installer is encrypted and none of the supplied
    /// candidate passwords matched the on-disk verifier.
    WrongPassword,
    /// The chunk references an external slice file (`setup-1.bin`,
    /// `setup-2.bin`, …) rather than embedded bytes within the
    /// installer EXE. External slices are not yet supported.
    ExternalSlice,
    /// The chunk spans multiple slice files
    /// (`first_slice != last_slice`).
    MultiSliceChunk {
        /// First slice index covered by the chunk.
        first: u32,
        /// Last slice index covered by the chunk.
        last: u32,
    },
    /// The chunk header magic (`zlb\x1a`) was missing or malformed.
    BadChunkMagic {
        /// The 4 bytes actually read.
        got: [u8; 4],
    },
    /// The chunk's compression method byte was outside the recognized
    /// set or the per-version dispatch table.
    UnsupportedCompression {
        /// Raw method byte / enum discriminant.
        method: u8,
    },
    /// The decompressor produced a different number of output bytes
    /// than the sum of `original_size` across files in the chunk.
    ChunkSizeMismatch {
        /// Total uncompressed bytes expected from the file-location
        /// table.
        expected: u64,
        /// Bytes actually produced by the decompressor.
        actual: u64,
    },
    /// A file's post-extraction checksum did not match the value
    /// recorded in its `DataEntry`.
    ChecksumMismatch {
        /// Which checksum family ran (`"SHA-256"`, etc.).
        algorithm: &'static str,
        /// The hex-encoded expected hash.
        expected: String,
        /// The hex-encoded computed hash.
        actual: String,
    },
    /// Wrapper for a parse failure inside the embedded
    /// PascalScript blob - surfaced through
    /// [`crate::InnoInstaller::compiledcode`]. The wrapped
    /// [`pascalscript::Error`] is fully self-contained;
    /// this variant exists so `innospect::Error` can be the single
    /// error type returned across the high-level API without the
    /// `pascalscript` crate taking a hard dependency on this
    /// enum.
    PascalScript(pascalscript::Error),
}

impl From<pascalscript::Error> for Error {
    fn from(e: pascalscript::Error) -> Self {
        Self::PascalScript(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPe => f.write_str("input is not a PE executable"),
            Self::PeParseFailed { reason } => write!(f, "PE parse failed: {reason}"),
            Self::NotInnoSetup => f.write_str("input is not an Inno Setup installer"),
            Self::Truncated { what } => {
                write!(f, "truncated input: {what} runs past end of buffer")
            }
            Self::Overflow { what } => write!(f, "integer overflow computing {what}"),
            Self::UnknownSetupLdrMagic { magic } => {
                write!(f, "unknown SetupLdr magic: {:02x?}", &magic[..])
            }
            Self::UnsupportedVersion { marker } => {
                let end = marker.iter().position(|&b| b == 0).unwrap_or(marker.len());
                let visible = marker.get(..end).unwrap_or(&[]);
                let s = String::from_utf8_lossy(visible);
                write!(f, "unsupported Inno Setup data version: {s}")
            }
            Self::BadChecksum {
                what,
                expected,
                actual,
            } => write!(
                f,
                "checksum mismatch on {what}: expected {expected:#010x}, got {actual:#010x}"
            ),
            Self::Decompress { stream, source } => {
                write!(f, "failed to decompress {stream}: {source}")
            }
            Self::InvalidUtf16 { what } => write!(f, "invalid UTF-16LE in {what}"),
            Self::NoLocation => f.write_str("FileEntry has no file-location slot"),
            Self::Encrypted => f.write_str("chunk is encrypted and no decryption key is available"),
            Self::PasswordRequired => {
                f.write_str("installer is encrypted but no candidate passwords were supplied")
            }
            Self::WrongPassword => {
                f.write_str("no candidate password matched the installer's verifier")
            }
            Self::ExternalSlice => {
                f.write_str("chunk lives in an external slice file (not supported)")
            }
            Self::MultiSliceChunk { first, last } => {
                write!(f, "chunk spans slices {first}..={last}")
            }
            Self::BadChunkMagic { got } => {
                write!(f, "bad chunk magic: expected `zlb\\x1a`, got {got:02x?}")
            }
            Self::UnsupportedCompression { method } => {
                write!(f, "unsupported chunk compression method: {method}")
            }
            Self::PascalScript(e) => write!(f, "PascalScript: {e}"),
            Self::ChunkSizeMismatch { expected, actual } => write!(
                f,
                "chunk size mismatch: expected {expected} uncompressed bytes, got {actual}"
            ),
            Self::ChecksumMismatch {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "{algorithm} checksum mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decompress { source, .. } => Some(source),
            Self::PascalScript(e) => Some(e),
            _ => None,
        }
    }
}
