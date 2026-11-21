//! Error type for the `innospect` crate.

use std::{fmt, io};

/// Errors produced while locating, parsing, or decompressing an Inno Setup
/// installer.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The byte slice is not an `MZ` executable: neither a PE nor the NE
    /// of a 16-bit (1.2.x) installer.
    NotPe,
    /// Parsing the PE container failed (malformed headers, bad sections,
    /// etc.). Distinct from [`Error::NotPe`]: the bytes look like a PE
    /// but the structure could not be walked.
    PeParseFailed {
        /// goblin's diagnostic, captured as a string.
        reason: String,
    },
    /// The executable has no setup loader offset table: neither the
    /// pre-5.1.5 pointer at `0x30` nor the 5.1.5+ table's magic was found.
    /// The usual answer for a PE that is not an Inno Setup installer.
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
    /// setup-0 does not begin with a SetupID marker this crate reads: not
    /// the stock or ISX `... Setup Data (x.y.z)` form, nor the 1.2.10
    /// legacy form.
    UnsupportedVersion {
        /// The raw `Inno Setup Setup Data (X.Y.Z)` marker as read from
        /// the installer (up to 64 bytes, may include trailing nulls).
        marker: [u8; 64],
    },
    /// A stored CRC-32 did not match the bytes it covers (the offset
    /// table, or a setup-0 block or sub-chunk).
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
    /// A UTF-16LE string has an odd byte length or an unpaired surrogate.
    InvalidUtf16 {
        /// Which field failed to decode.
        what: &'static str,
    },
    /// The file has no data in the installer (its `location_index` is
    /// `u32::MAX`): the uninstaller, which Setup writes from its own
    /// program (see [`crate::InnoInstaller::extract_uninstaller`]), or an
    /// external or downloaded file. `extract_uninstaller` also returns it
    /// when the installer has no uninstaller entry.
    NoLocation,
    /// The file's chunk is encrypted and the installer was opened without
    /// its password (see [`crate::InnoInstaller::from_bytes_with_passwords`]).
    Encrypted,
    /// The installer has a password (it is encrypted, or Setup asks for
    /// one) but the candidate-password list passed to
    /// [`crate::InnoInstaller::from_bytes_with_passwords`] was empty.
    PasswordRequired,
    /// The installer has a password and none of the supplied
    /// candidate passwords matched the on-disk verifier.
    WrongPassword,
    /// The file's chunk is in a slice file beside the installer
    /// (`setup-1.bin`, ..., `DiskSpanning=yes`) that was not supplied: see
    /// [`crate::InnoInstaller::with_slices`].
    ExternalSlice,
    /// A chunk is longer than the slice files it names hold: its bytes run
    /// past the end of `last`.
    MultiSliceChunk {
        /// First slice index covered by the chunk.
        first: u32,
        /// Last slice index covered by the chunk.
        last: u32,
    },
    /// A slice file supplied through [`crate::InnoInstaller::with_slices`]
    /// is not one: its ID is not the one the installer's release writes, or
    /// its stated size is not its length.
    BadSlice {
        /// The slice's index, 0-based.
        index: u32,
        /// What is wrong.
        reason: &'static str,
    },
    /// The chunk header magic (`zlb\x1a`) was missing or malformed.
    BadChunkMagic {
        /// The 4 bytes actually read.
        got: [u8; 4],
    },
    /// A compressed chunk needs the header's `CompressMethod`, and its
    /// byte is not one the version defines.
    UnsupportedCompression {
        /// The `CompressMethod` byte as stored.
        method: u8,
    },
    /// A chunk decompressed to fewer bytes than a file in it needs: the
    /// file's data entry ends past the chunk.
    ChunkSizeMismatch {
        /// Where the file ends in the chunk (`ChunkSubOffset` plus
        /// `OriginalSize`).
        expected: u64,
        /// The chunk's decompressed size.
        actual: u64,
    },
    /// A decompressed setup-0 block holds bytes past the last thing Setup
    /// reads from it: the records were read with the wrong layout.
    TrailingData {
        /// Which block.
        what: &'static str,
        /// How many bytes were left unread.
        len: usize,
    },
    /// Something would decompress past the limit the crate sets for it
    /// (a setup-0 block past 256 MiB), the mark of a decompression bomb.
    TooLarge {
        /// What.
        what: &'static str,
        /// The limit, in bytes.
        limit: u64,
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
                f.write_str("installer has a password but no candidate passwords were supplied")
            }
            Self::WrongPassword => {
                f.write_str("no candidate password matched the installer's verifier")
            }
            Self::ExternalSlice => f.write_str("chunk lives in a slice file that was not supplied"),
            Self::MultiSliceChunk { first, last } => {
                write!(f, "chunk runs past the end of slices {first}..={last}")
            }
            Self::BadSlice { index, reason } => write!(f, "slice {index}: {reason}"),
            Self::BadChunkMagic { got } => {
                write!(f, "bad chunk magic: expected `zlb\\x1a`, got {got:02x?}")
            }
            Self::UnsupportedCompression { method } => {
                write!(f, "unsupported chunk compression method: {method}")
            }
            Self::PascalScript(e) => write!(f, "PascalScript: {e}"),
            Self::ChunkSizeMismatch { expected, actual } => write!(
                f,
                "chunk too short: a file ends at byte {expected}, the chunk has {actual}"
            ),
            Self::TrailingData { what, len } => {
                write!(f, "{len} bytes left unread at the end of the {what}")
            }
            Self::TooLarge { what, limit } => {
                write!(f, "{what} would exceed the {limit}-byte limit")
            }
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
