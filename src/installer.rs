//! High-level [`InnoInstaller`] entry point.
//!
//! Parses an Inno Setup installer end-to-end: PE locator, offset
//! table, version marker, optional encryption header, setup-0
//! decompression (with `euFull` decryption when applicable), the
//! `TSetupHeader` block, the typed record streams, and on-demand
//! file-content extraction from `setup-1` chunks.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock},
};

use pascalscript::Container;

mod setupfiles;

use self::setupfiles::SetupFiles;
pub use self::setupfiles::WizardImageKind;

use crate::{
    analysis::{exec::ExecIter, registryop::RegistryOpIter, shortcut::ShortcutIter},
    crypto::{
        kdflegacy::{LegacyHashFamily, LegacyStoredHash, legacy_hash_family},
        xchacha20::{SpecialContext, special_nonce},
    },
    decompress::block::{BlockCompression, decompress_block},
    error::Error,
    extract::file::FileReader,
    header::{Architecture, HeaderAnsi, HeaderString, SetupHeader},
    loader::{
        marker::{later_layout, read_marker},
        pe,
    },
    overlay::{
        OffsetTable,
        offsettable::SetupLdrFamily,
        pe::{LocatorMode, OffsetTableLocation},
    },
    records::{
        component::ComponentEntry,
        dataentry::DataEntry,
        delete::DeleteEntry,
        directory::DirectoryEntry,
        file::{FileEntry, FileEntryType},
        icon::IconEntry,
        ini::IniEntry,
        isssigkey::ISSigKeyEntry,
        language::LanguageEntry,
        message::MessageEntry,
        permission::PermissionEntry,
        registry::RegistryEntry,
        run::RunEntry,
        task::TaskEntry,
        type_::TypeEntry,
    },
    stream::{chunk::decompress_chunk, slice::SliceReader},
    util::read::{FromReader, Reader, read_record},
    version::{Variant, Version},
};

/// How setup-0's blocks (the header and records, and the data entries) are
/// compressed. setup-1's file chunks have their own method,
/// [`crate::CompressMethod`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compression {
    /// Uncompressed.
    Stored,
    /// Zlib (Deflate). Used before 4.1.6.
    Zlib,
    /// LZMA1 with Inno's non-standard 5-byte properties header. Used
    /// by version ≥ 4.1.6.
    Lzma1,
    /// Compression flag byte was outside the recognized values, or
    /// the block could not be peeked because the full block stream
    /// is encrypted (`euFull`).
    Unknown,
}

stable_name_enum!(Compression, {
    Self::Stored => "stored",
    Self::Zlib => "zlib",
    Self::Lzma1 => "lzma1",
    Self::Unknown => "unknown",
});

impl Compression {
    fn from_block(c: BlockCompression) -> Self {
        match c {
            BlockCompression::Stored => Self::Stored,
            BlockCompression::Zlib => Self::Zlib,
            BlockCompression::Lzma1 => Self::Lzma1,
        }
    }
}

/// The installer's PBKDF2 / XChaCha20 password and encryption parameters
/// (6.4.0+). From 6.5.0 they are the `TSetupEncryptionHeader` that precedes
/// setup-0's blocks; in 6.4.x they sit in the header tail and this crate
/// gathers them here when the header's `Password` option is set. Older
/// installers use the legacy hashes in [`crate::HeaderTail`].
#[derive(Clone, Debug)]
pub struct EncryptionInfo {
    /// `EncryptionUse`: what is encrypted (6.5.0+; in 6.4.x
    /// [`EncryptionMode::Files`] when `Encryption=yes`, else
    /// [`EncryptionMode::None`]).
    pub mode: EncryptionMode,
    /// `KDFSalt`: the PBKDF2-HMAC-SHA256 salt.
    pub salt: [u8; 16],
    /// `KDFIterations`: PBKDF2 iterations, 220 000 by default.
    pub kdf_iterations: u32,
    /// `BaseNonce`: the XChaCha20 nonce each chunk's nonce is derived
    /// from.
    pub base_nonce: [u8; 24],
    /// `PasswordTest`: what the right password's key encrypts four zero
    /// bytes to, under a nonce of its own; how a password is checked
    /// without decrypting anything.
    pub password_test: u32,
}

/// `EncryptionUse` (`Encryption=`): what the installer encrypts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionMode {
    /// `euNone` (`Encryption=no`): nothing; a `Password=` is only asked
    /// for.
    None,
    /// `euFiles` (`Encryption=yes`): file chunks are encrypted, setup-0 is
    /// not.
    Files,
    /// `euFull` (`Encryption=full`, 6.5.0+): setup-0 is encrypted too, so
    /// nothing past the version can be read without the password.
    Full,
}

stable_name_enum!(EncryptionMode, {
    Self::None => "none",
    Self::Files => "files",
    Self::Full => "full",
});

/// High-level view of an Inno Setup installer.
///
/// Identification accessors ([`version`], [`variant`],
/// [`offset_table`], [`compression`], [`encryption`],
/// [`pe_locator_mode`]) work on every supported version. The
/// [`decompressed_setup0`] accessor exposes the decompressed
/// `setup-0` bytes; the typed-record iterators borrow from this
/// buffer.
///
/// [`version`]: InnoInstaller::version
/// [`variant`]: InnoInstaller::variant
/// [`offset_table`]: InnoInstaller::offset_table
/// [`compression`]: InnoInstaller::compression
/// [`encryption`]: InnoInstaller::encryption
/// [`pe_locator_mode`]: InnoInstaller::pe_locator_mode
/// [`decompressed_setup0`]: InnoInstaller::decompressed_setup0
#[derive(Debug)]
pub struct InnoInstaller<'a> {
    input: &'a [u8],
    pe_location: OffsetTableLocation,
    offset_table: OffsetTable,
    version: Version,
    variant: Variant,
    encryption: Option<EncryptionInfo>,
    compression: Compression,
    /// Decompressed setup-0 bytes. Empty when the block is encrypted
    /// with `euFull` and no key is available.
    decompressed_setup0: Box<[u8]>,
    /// Decompressed bytes of the second block stream that
    /// immediately follows the first one in `setup-0`. Holds the
    /// `TSetupFileLocationEntry` records (one per slot in
    /// `EntryCounts.file_locations`). Empty when no second block is
    /// present (when the first block was skipped).
    decompressed_data_block: Box<[u8]>,
    /// Parsed header. `None` when `decompressed_setup0` is empty
    /// (`euFull`-encrypted without a key).
    header: Option<SetupHeader>,
    /// Parsed typed records (`TSetupFileEntry`,
    /// `TSetupLanguageEntry`, etc.). Empty when `header` is `None`.
    records: ParsedRecords,
    /// Per-unique-chunk decompressed-bytes cache. One slot per
    /// distinct `(first_slice, start_offset)` chunk identified
    /// across all file-locations. `OnceLock` keeps this
    /// `Send + Sync` and ensures exactly-once decompression even
    /// across concurrent calls.
    chunk_cache: Box<[OnceLock<Arc<[u8]>>]>,
    /// Map: `file_locations` index → `chunk_cache` index.
    file_loc_to_chunk: Box<[u32]>,
    /// Per `chunk_cache` slot: how far its furthest file reaches, the
    /// most of the chunk worth decompressing.
    chunk_needed: Box<[u64]>,
    /// Derived 32-byte XChaCha20 key for 6.4+ encrypted installers
    /// when a candidate password matched the on-disk verifier.
    /// `None` for unencrypted installers, for legacy (pre-6.4)
    /// ARC4 paths (where the per-chunk key is derived on the fly
    /// from the password + chunk salt), and for encrypted
    /// installers that haven't been unlocked.
    encryption_key: Option<[u8; 32]>,
    /// Legacy (pre-6.4) password kept for per-chunk ARC4 key
    /// derivation. Each encrypted chunk has its own 8-byte salt
    /// inside the body; the chunk reader hashes
    /// `chunk_salt || password_utf16le` (SHA-1 for 5.3.9..6.4,
    /// MD5 for pre-5.3.9) to derive the per-chunk RC4 key.
    legacy_password: Option<String>,
    /// The password (verbatim from the candidate list) that
    /// produced [`Self::encryption_key`] / [`Self::legacy_password`].
    /// Reported to callers via [`Self::password_used`].
    password_used: Option<String>,
    /// The slice files the caller supplied ([`Self::with_slices`]).
    slices: Vec<&'a [u8]>,
}

/// Eagerly-parsed record sections - every record type stored in
/// the two block streams of `setup-0`.
#[derive(Clone, Debug, Default)]
struct ParsedRecords {
    languages: Vec<LanguageEntry>,
    messages: Vec<MessageEntry>,
    permissions: Vec<PermissionEntry>,
    types: Vec<TypeEntry>,
    components: Vec<ComponentEntry>,
    tasks: Vec<TaskEntry>,
    directories: Vec<DirectoryEntry>,
    iss_sig_keys: Vec<ISSigKeyEntry>,
    files: Vec<FileEntry>,
    icons: Vec<IconEntry>,
    ini_entries: Vec<IniEntry>,
    registry: Vec<RegistryEntry>,
    install_deletes: Vec<DeleteEntry>,
    uninstall_deletes: Vec<DeleteEntry>,
    run: Vec<RunEntry>,
    uninstall_run: Vec<RunEntry>,
    /// Block-2 file-location records.
    file_locations: Vec<DataEntry>,
    /// Where the wizard images and DLLs sit in the records block.
    setup_files: SetupFiles,
}

impl<'a> InnoInstaller<'a> {
    /// Parses an Inno Setup installer from a byte slice. **Does
    /// not attempt to decrypt** - encrypted chunks remain
    /// observable as `ChunkEncrypted` data-entry flags, and
    /// [`Self::extract`] returns [`Error::Encrypted`] for them.
    /// Use [`Self::from_bytes_with_passwords`] to additionally
    /// derive the decryption key from candidate passwords.
    ///
    /// # Errors
    ///
    /// See [`Error`] variants. The common "this isn't an Inno Setup
    /// installer" outcomes are [`Error::NotPe`] and
    /// [`Error::NotInnoSetup`]; everything else indicates broken or
    /// unfamiliar input.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, Error> {
        Self::parse(data, None)
    }

    /// Parses an Inno Setup installer **and tries each candidate
    /// password** against the on-disk verifier
    /// (`password_test`); the first match is recorded and used to
    /// decrypt file chunks during [`Self::extract`].
    ///
    /// The candidates are tried only when the installer has a password
    /// (the header's [`crate::HeaderOption::Password`], set for every
    /// encrypted installer and for a password-only one). An installer
    /// without one parses exactly as [`Self::from_bytes`] would, with
    /// [`Self::password_used`] `None`, so one candidate list can be passed
    /// for every input.
    ///
    /// # Errors
    ///
    /// - [`Error::PasswordRequired`] - installer has a password but
    ///   `passwords` is empty.
    /// - [`Error::WrongPassword`] - installer has a password and no
    ///   candidate matched.
    /// - All standard parse errors per [`Self::from_bytes`].
    pub fn from_bytes_with_passwords(data: &'a [u8], passwords: &[&str]) -> Result<Self, Error> {
        Self::parse(data, Some(passwords))
    }

    /// Internal parse path. `passwords = None` skips the
    /// password-trial entirely (the [`Self::from_bytes`] path);
    /// `Some(&[])` triggers `PasswordRequired` on encrypted
    /// installers; `Some(non-empty)` runs the trial.
    fn parse(data: &'a [u8], passwords: Option<&[&str]>) -> Result<Self, Error> {
        let pe_location = pe::locate(data)?;
        let offset_table = OffsetTable::parse(data, pe_location.start, pe_location.len)?;

        let setup0_start = usize_from_u64(offset_table.offset_setup0, "Offset0")?;
        let setup0 = data.get(setup0_start..).ok_or(Error::Truncated {
            what: "setup-0 region",
        })?;

        let (version, variant, marker_len) = read_marker(setup0)?;

        // Whatever follows the SetupID depends on version.
        //
        // - 6.5.0+: an unconditional 4-byte CRC32 + 49-byte
        //   `TSetupEncryptionHeader` precedes the compressed block.
        //   Introduced in commit `f7170990` (2025-08-03, ships in tag
        //   `is-6_5_0`).
        // - 6.4.x: encryption metadata exists but lives inside the
        //   compressed `TSetupHeader` struct. We can't surface it
        //   until the block is decompressed.
        // - pre-6.4: per-chunk encryption.
        let mut after_marker = Reader::at(setup0, marker_len)?;
        let encryption = if version.at_least(6, 5, 0) {
            parse_encryption_header(&mut after_marker)?
        } else {
            None
        };

        let block_start_in_setup0 = after_marker.pos();
        let block_is_encrypted = matches!(
            encryption.as_ref().map(|e| e.mode),
            Some(EncryptionMode::Full),
        );

        // 6.4+ password trial (modern). Has to run BEFORE block
        // decompression for `euFull`, since the setup-0 block
        // streams themselves are XChaCha20-encrypted and need the
        // derived key to decrypt. For `euFiles` the trial would
        // run the same way; for the no-encryption case it's a
        // no-op. The legacy (pre-6.4) trial sits below - that path
        // needs `HeaderTail.legacy_password_*` which only exists
        // post-decompression.
        let (mut encryption_key, mut password_used): (Option<[u8; 32]>, Option<String>) =
            (None, None);
        if let Some(candidates) = passwords
            && let Some(info) = encryption.as_ref()
            && matches!(info.mode, EncryptionMode::Files | EncryptionMode::Full)
        {
            if candidates.is_empty() {
                return Err(Error::PasswordRequired);
            }
            let (key, used) = try_passwords(info, candidates, &version)?;
            encryption_key = key;
            password_used = used;
        }

        // Decompress the setup-0 block streams. Two paths (the
        // block header itself differs before 4.0.9 and from 6.7.0,
        // which `decompress_block` handles):
        //   - euFull (6.5+) WITH a derived key: decrypt block 1
        //     with `sccCompressedBlocks1`, run decompress_block,
        //     then decrypt block 2 with `sccCompressedBlocks2`,
        //     run again.
        //   - plaintext OR euFull-without-key: read both blocks
        //     directly (or skip when encrypted-without-key).
        //
        // Block 1 holds the header and records, block 2 the data
        // entries; per-chunk decryption in setup-1 happens
        // independently in `stream::chunk`.
        let (decompressed_setup0, decompressed_data_block, compression) = if block_is_encrypted {
            if let (Some(info), Some(key)) = (encryption.as_ref(), encryption_key.as_ref()) {
                decompress_blocks_eufull(
                    setup0,
                    block_start_in_setup0,
                    &version,
                    &info.base_nonce,
                    key,
                )?
            } else {
                // Encrypted but no key supplied (caller went
                // through `from_bytes` or `from_bytes_with_passwords`
                // for an encrypted installer - the plain
                // `from_bytes` path lands here for euFull).
                (
                    Box::<[u8]>::default(),
                    Box::<[u8]>::default(),
                    Compression::Unknown,
                )
            }
        } else {
            let block1 = decompress_block(setup0, block_start_in_setup0, &version)?;
            let comp = Compression::from_block(block1.compression);
            let block2_start =
                block_start_in_setup0
                    .checked_add(block1.consumed)
                    .ok_or(Error::Overflow {
                        what: "second block start",
                    })?;
            let block2 = decompress_block(setup0, block2_start, &version)?;
            (block1.bytes, block2.bytes, comp)
        };

        // A few releases changed the records but kept the SetupID; an
        // installer that does not parse under its marker's layout is tried
        // under the later one, which `version()` then reports.
        let (header, records, version) = if decompressed_setup0.is_empty() {
            (None, ParsedRecords::default(), version)
        } else {
            match parse_setup0(&decompressed_setup0, &decompressed_data_block, &version) {
                Ok((h, r)) => (Some(h), r, version),
                Err(first) => {
                    let Some(later) = later_layout(&version) else {
                        return Err(first);
                    };
                    match parse_setup0(&decompressed_setup0, &decompressed_data_block, &later) {
                        Ok((h, r)) => (Some(h), r, later),
                        Err(_) => return Err(first),
                    }
                }
            }
        };

        let (chunk_cache, file_loc_to_chunk, chunk_needed) =
            build_chunk_index(&records.file_locations);

        // 6.4.x promotion. Encryption metadata for 6.4.0..6.5.0 lives
        // inline in `HeaderTail`. Promote it to an `EncryptionInfo`
        // (mode=Files when `shEncryptionUsed` is set, mode=None when
        // it's just password verification).
        let mut encryption = encryption;
        if encryption.is_none()
            && let Some(h) = header.as_ref()
            && version.at_least(6, 4, 0)
            && !version.at_least(6, 5, 0)
            && h.has_option(crate::HeaderOption::Password)
        {
            let tail = h.tail();
            if let (Some(test), Some(salt), Some(iters), Some(nonce)) = (
                tail.password_test,
                tail.encryption_kdf_salt,
                tail.encryption_kdf_iterations,
                tail.encryption_base_nonce,
            ) {
                encryption = Some(EncryptionInfo {
                    mode: if h.has_option(crate::HeaderOption::EncryptionUsed) {
                        EncryptionMode::Files
                    } else {
                        EncryptionMode::None
                    },
                    salt,
                    kdf_iterations: iters,
                    base_nonce: nonce,
                    password_test: test,
                });
            }
        }
        // Run the modern (PBKDF2 + XChaCha20) password trial when the
        // installer has a password and we haven't unlocked already. This
        // covers 6.5+ password-only installers (mode=None with the
        // verifier populated), 6.4.x with EncryptionUsed (mode=Files via
        // the promotion above), and 6.4.x password-only (mode=None via
        // the promotion above). Every 6.5+ installer carries an
        // `EncryptionInfo`, password or not, so its presence says nothing:
        // like Setup (`Setup.MainFunc.pas`, `shPassword in
        // SetupHeader.Options`), only the header's `Password` option does.
        if let Some(candidates) = passwords
            && encryption_key.is_none()
            && let Some(info) = encryption.as_ref()
            && header
                .as_ref()
                .is_some_and(|h| h.has_option(crate::HeaderOption::Password))
        {
            if candidates.is_empty() {
                return Err(Error::PasswordRequired);
            }
            let (key, used) = try_passwords(info, candidates, &version)?;
            encryption_key = key;
            password_used = used;
        }

        // Legacy (pre-6.4) password trial. The modern trial is
        // up above (it runs before block decompression so euFull
        // can decrypt setup-0). Pre-6.4 doesn't have euFull and
        // the legacy hash fields live in `HeaderTail`, so this
        // trial has to run AFTER the header parses.
        let mut legacy_password: Option<String> = None;
        if let Some(candidates) = passwords
            && encryption.is_none()
            && let Some(stored) = header
                .as_ref()
                .filter(|h| h.has_option(crate::HeaderOption::Password))
                .and_then(|h| legacy_stored_hash(h.tail(), &version))
        {
            if candidates.is_empty() {
                return Err(Error::PasswordRequired);
            }
            let used = try_passwords_legacy(&stored, candidates, &version)?;
            legacy_password = Some(used.clone());
            password_used = Some(used);
        }

        Ok(Self {
            input: data,
            pe_location,
            offset_table,
            version,
            variant,
            encryption,
            compression,
            decompressed_setup0,
            decompressed_data_block,
            header,
            records,
            chunk_cache,
            file_loc_to_chunk,
            chunk_needed,
            encryption_key,
            legacy_password,
            password_used,
            slices: Vec::new(),
        })
    }

    /// Returns the decompressed setup-0 bytes. Empty when the block
    /// could not be decrypted (`euFull` without a key).
    #[must_use]
    pub fn decompressed_setup0(&self) -> &[u8] {
        &self.decompressed_setup0
    }

    /// Returns the decompressed bytes of the **second** block stream
    /// in `setup-0`, which holds the `TSetupFileLocationEntry`
    /// records. Empty when [`Self::decompressed_setup0`] is empty.
    #[must_use]
    pub fn data_block(&self) -> &[u8] {
        &self.decompressed_data_block
    }

    /// Returns the parsed setup header, when available. Absent when
    /// `decompressed_setup0()` is empty.
    #[must_use]
    pub fn header(&self) -> Option<&SetupHeader> {
        self.header.as_ref()
    }

    /// Returns the setup data version: the one the installer's SetupID
    /// marker names, except under a marker a later release kept writing
    /// after it changed the records (`(1.3.21)`, `(2.0.1)`, `(3.0.3)`,
    /// `(4.2.3)`), where it is the version whose layout the records parsed
    /// with, e.g. 4.2.4 for a 4.2.4 installer. [`Version::marker_str`]
    /// keeps the marker as written.
    #[must_use]
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Returns the detected installer variant.
    #[must_use]
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Returns the parsed `SetupLdrOffsetTable`.
    #[must_use]
    pub fn offset_table(&self) -> &OffsetTable {
        &self.offset_table
    }

    /// Returns the SetupLdr 12-byte magic family.
    #[must_use]
    pub fn setup_ldr_family(&self) -> SetupLdrFamily {
        self.offset_table.source.family
    }

    /// Returns whether the offset table was found via PE resource
    /// (5.1.5+) or the legacy `0x30` file-offset path.
    #[must_use]
    pub fn pe_locator_mode(&self) -> LocatorMode {
        self.pe_location.mode
    }

    /// The PBKDF2 / XChaCha20 parameters (6.4.0+): from 6.5.0 always, in
    /// 6.4.x when the installer has a password. `None` before 6.4.0, whose
    /// password hashes are in [`crate::HeaderTail`]; which chunks are
    /// encrypted is each data entry's [`crate::records::dataentry::DataFlag::ChunkEncrypted`].
    #[must_use]
    pub fn encryption(&self) -> Option<&EncryptionInfo> {
        self.encryption.as_ref()
    }

    /// How setup-0's blocks are compressed; [`Compression::Unknown`] when
    /// they could not be read (an `euFull` installer without the password).
    #[must_use]
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Returns the set of processor architectures the installer
    /// permits via its `ArchitecturesAllowed` directive, or `None`
    /// when the field isn't on the wire (pre-5.1.0 installers).
    ///
    /// Two underlying wire forms are unified here:
    ///
    /// - 5.1.0..6.3 store the field as packed
    ///   [`Architecture`] flag bits on the [`crate::header::HeaderTail`]; this
    ///   accessor returns those bits verbatim.
    /// - 6.3+ store it as a boolean expression string (e.g.
    ///   `"x64compatible or arm64"`) which this accessor scans
    ///   **best-effort** for known architecture atoms
    ///   (`x86`, `x86os`, `x86compatible`, `x64`, `x64os`,
    ///   `x64compatible`, `arm32compatible`, `arm64`, `ia64`).
    ///   Boolean operators (`and`, `or`, `not`) are NOT evaluated -
    ///   any atom that appears in the expression produces its
    ///   architecture in the result, so `not x64` reports `Amd64`
    ///   the same as bare `x64`. Callers that need a faithful
    ///   evaluation should consume the raw expression via
    ///   [`SetupHeader::string`] with
    ///   [`HeaderString::ArchitecturesAllowed`].
    ///
    /// An empty set in the result means the installer left the
    /// directive at its Inno default, which Inno treats as "any
    /// architecture allowed". Callers that want this default
    /// expressed explicitly should treat `Some(set) where
    /// set.is_empty()` the same as "all architectures allowed".
    #[must_use]
    pub fn architecture(&self) -> Option<HashSet<Architecture>> {
        let header = self.header.as_ref()?;
        if let Some(set) = header.tail().architectures_allowed.clone() {
            return Some(set);
        }
        let raw = header.string(HeaderString::ArchitecturesAllowed)?;
        Some(parse_architecture_expression(raw))
    }

    /// Returns the original input slice.
    #[must_use]
    pub fn input(&self) -> &'a [u8] {
        self.input
    }

    /// Returns the `LicenseFile` blob (the `[Setup] LicenseFile=…`
    /// directive's contents, stored verbatim in the setup header),
    /// or `None` if the installer does not ship a license screen.
    ///
    /// Modern Inno builds always carry the `LicenseText` AnsiString
    /// slot, but populate it with an empty string when no license
    /// is configured. This accessor folds that empty case into
    /// `None` - `Some(bytes)` always has `bytes.len() > 0`.
    ///
    /// The bytes are codepage-encoded per the installer's language
    /// table; callers that need a `String` should run them through
    /// the appropriate decoder.
    ///
    /// These header text fields are length-prefixed setup-header blobs;
    /// current supported Inno Setup formats do not carry a per-field
    /// checksum for `LicenseText`, `InfoBeforeText`, or `InfoAfterText`.
    /// Integrity validation is therefore limited to what covers the whole
    /// setup-0 block: a CRC-32 over every 4 KiB of it as stored, checked
    /// when it is read, then decompression and parsing to the block's last
    /// byte.
    #[must_use]
    pub fn license_text(&self) -> Option<&[u8]> {
        self.header
            .as_ref()
            .and_then(|h| h.ansi(HeaderAnsi::LicenseText))
            .filter(|b| !b.is_empty())
    }

    /// Returns the `InfoBeforeFile` blob (text shown on the wizard
    /// page before installation), or `None` if absent or empty.
    ///
    /// See [`Self::license_text`] for the empty-folding rule and
    /// encoding notes.
    #[must_use]
    pub fn info_before(&self) -> Option<&[u8]> {
        self.header
            .as_ref()
            .and_then(|h| h.ansi(HeaderAnsi::InfoBeforeText))
            .filter(|b| !b.is_empty())
    }

    /// Returns the `InfoAfterFile` blob (text shown on the wizard
    /// page after installation), or `None` if absent or empty.
    ///
    /// See [`Self::license_text`] for the empty-folding rule and
    /// encoding notes.
    #[must_use]
    pub fn info_after(&self) -> Option<&[u8]> {
        self.header
            .as_ref()
            .and_then(|h| h.ansi(HeaderAnsi::InfoAfterText))
            .filter(|b| !b.is_empty())
    }

    /// Returns the compiled `[Code]` PascalScript blob, or `None`
    /// if the installer does not ship a `[Code]` section.
    ///
    /// The blob is an IFPS container - `IFPS`-magic followed by a
    /// header, name table, type table, globals, procedures, and
    /// bytecode. This accessor surfaces the raw bytes; the parsed
    /// container view lives at [`Self::compiledcode`]. Empty
    /// blobs fold into `None` per the same rule as
    /// [`Self::license_text`].
    #[must_use]
    pub fn compiled_code_bytes(&self) -> Option<&[u8]> {
        self.header
            .as_ref()
            .and_then(|h| h.ansi(HeaderAnsi::CompiledCodeText))
            .filter(|b| !b.is_empty())
    }

    /// Returns a parsed [`Container`] view over the IFPS blob at
    /// [`Self::compiled_code_bytes`], or `None` if no `[Code]`
    /// blob is present.
    ///
    /// The full
    /// [`pascalscript::Container`] surface is exposed -
    /// header, types, procs (script-defined and imported
    /// externals), vars. The container's API is Inno-agnostic
    /// (designed for an eventual standalone-crate split); see
    /// [`Self::inno_api_description`] for the Inno-side name
    /// lookup.
    ///
    /// # Errors
    ///
    /// `Some(Err(_))` when the blob is present but malformed -
    /// bad magic, unsupported `PSBuildNo`, truncated table, or
    /// out-of-range type / bytecode reference. The error wraps a
    /// [`pascalscript::Error`] inside
    /// [`Error::PascalScript`].
    #[must_use]
    pub fn compiledcode(&self) -> Option<Result<Container<'_>, Error>> {
        self.compiled_code_bytes()
            .map(|bytes| Container::parse(bytes).map_err(Error::from))
    }

    /// Looks up an imported PascalScript external name (as it
    /// appears in [`pascalscript::Container::procs`]
    /// entries that are [`pascalscript::ProcKind::External`])
    /// against Inno's runtime-registered API table.
    ///
    /// Returns a one-line description for the security-relevant
    /// subset of registered functions (registry mutations, command
    /// execution, file operations, network downloads, privilege
    /// checks). Returns `None` for names outside that subset -
    /// see [`crate::analysis::compiledcode::INNO_API`] for the
    /// curated list.
    #[must_use]
    pub fn inno_api_description(&self, name: &str) -> Option<&'static str> {
        crate::analysis::compiledcode::inno_api_description(name)
    }

    /// Parsed `[Languages]` entries, in declaration order.
    #[must_use]
    pub fn languages(&self) -> &[LanguageEntry] {
        &self.records.languages
    }

    /// Parsed `[CustomMessages]` entries.
    #[must_use]
    pub fn messages(&self) -> &[MessageEntry] {
        &self.records.messages
    }

    /// Parsed `[Permissions]` entries (raw `TGrantPermissionEntry[]`
    /// blobs).
    #[must_use]
    pub fn permissions(&self) -> &[PermissionEntry] {
        &self.records.permissions
    }

    /// Parsed `[Types]` entries.
    #[must_use]
    pub fn types(&self) -> &[TypeEntry] {
        &self.records.types
    }

    /// Parsed `[Components]` entries.
    #[must_use]
    pub fn components(&self) -> &[ComponentEntry] {
        &self.records.components
    }

    /// Parsed `[Tasks]` entries.
    #[must_use]
    pub fn tasks(&self) -> &[TaskEntry] {
        &self.records.tasks
    }

    /// Parsed `[Dirs]` entries.
    #[must_use]
    pub fn directories(&self) -> &[DirectoryEntry] {
        &self.records.directories
    }

    /// Parsed `[ISSigKeys]` entries (6.5.0+; empty on older
    /// installers).
    #[must_use]
    pub fn iss_sig_keys(&self) -> &[ISSigKeyEntry] {
        &self.records.iss_sig_keys
    }

    /// Parsed `[Files]` entries.
    #[must_use]
    pub fn files(&self) -> &[FileEntry] {
        &self.records.files
    }

    /// Parsed `[Icons]` entries.
    #[must_use]
    pub fn icons(&self) -> &[IconEntry] {
        &self.records.icons
    }

    /// Parsed `[INI]` entries.
    #[must_use]
    pub fn ini_entries(&self) -> &[IniEntry] {
        &self.records.ini_entries
    }

    /// Parsed `[Registry]` entries.
    #[must_use]
    pub fn registry_entries(&self) -> &[RegistryEntry] {
        &self.records.registry
    }

    /// Parsed `[InstallDelete]` entries.
    #[must_use]
    pub fn install_deletes(&self) -> &[DeleteEntry] {
        &self.records.install_deletes
    }

    /// Parsed `[UninstallDelete]` entries.
    #[must_use]
    pub fn uninstall_deletes(&self) -> &[DeleteEntry] {
        &self.records.uninstall_deletes
    }

    /// Parsed `[Run]` entries.
    #[must_use]
    pub fn run_entries(&self) -> &[RunEntry] {
        &self.records.run
    }

    /// Parsed `[UninstallRun]` entries.
    #[must_use]
    pub fn uninstall_runs(&self) -> &[RunEntry] {
        &self.records.uninstall_run
    }

    /// Parsed file-location records - bookkeeping for the chunks of
    /// `setup-1` payload (one per file-content slot, including
    /// embedded files like the uninstaller). Lives in setup-0's
    /// second decompressed block.
    #[must_use]
    pub fn file_locations(&self) -> &[DataEntry] {
        &self.records.file_locations
    }

    /// The wizard's pictures of `kind`, as stored (BMP, or PNG from 6.5.2),
    /// for light mode: one large image (and from 2.0.0 one small one) before
    /// 5.6.0, from 5.6.0 any number, in the sizes the script lists for
    /// Setup to pick the closest to its DPI from. Empty when the installer
    /// has none of the kind, and when setup-0 could not be decrypted.
    #[must_use]
    pub fn wizard_images(&self, kind: WizardImageKind) -> Vec<&[u8]> {
        self.slices(self.records.setup_files.images(kind))
    }

    /// The wizard's dark-mode pictures of `kind` (6.6.0+), or `None` when
    /// the installer has none of its own and uses the light ones
    /// ([`Self::wizard_images`]).
    #[must_use]
    pub fn wizard_images_dark(&self, kind: WizardImageKind) -> Option<Vec<&[u8]>> {
        self.records
            .setup_files
            .dark_images(kind)
            .map(|ranges| self.slices(ranges))
    }

    /// The decompressor DLL Setup extracts and loads to decompress the
    /// files (`isbunzip.dll`, `isunzlib.dll`, before 4.1.6 also
    /// `isunlzma.dll`): stored for bzip2 compression, in 4.1.5 for LZMA,
    /// and from 4.2.6 for zip.
    #[must_use]
    pub fn decompressor_dll(&self) -> Option<&[u8]> {
        self.slice(self.records.setup_files.decompressor_dll())
    }

    /// The decryption DLL (`ISCrypt.dll`) Setup loads to decrypt the files
    /// of an encrypted installer from 4.2.2 to 6.4.0; later releases
    /// decrypt without one.
    #[must_use]
    pub fn decryption_dll(&self) -> Option<&[u8]> {
        self.slice(self.records.setup_files.decryption_dll())
    }

    /// The 7-Zip library Setup loads to extract archives (6.5.0+), stored
    /// when the script names one ([`HeaderString::SevenZipLibraryName`]).
    #[must_use]
    pub fn seven_zip_dll(&self) -> Option<&[u8]> {
        self.slice(self.records.setup_files.seven_zip_dll())
    }

    fn slice(&self, range: Option<std::ops::Range<usize>>) -> Option<&[u8]> {
        range.and_then(|r| self.decompressed_setup0.get(r))
    }

    fn slices(&self, ranges: &[std::ops::Range<usize>]) -> Vec<&[u8]> {
        ranges
            .iter()
            .filter_map(|r| self.decompressed_setup0.get(r.clone()))
            .collect()
    }

    /// Whether the files are in slice files beside the installer
    /// (`DiskSpanning=yes`) rather than embedded in it: then
    /// [`Self::extract`] needs them, through [`Self::with_slices`].
    #[must_use]
    pub fn uses_slice_files(&self) -> bool {
        self.offset_table.offset_setup1 == 0 && !self.records.file_locations.is_empty()
    }

    /// How many slice files the data entries name (the highest
    /// `last_slice`, plus one); 0 when the files are embedded.
    #[must_use]
    pub fn slice_count(&self) -> u32 {
        if !self.uses_slice_files() {
            return 0;
        }
        self.records
            .file_locations
            .iter()
            .map(|d| d.last_slice.saturating_add(1))
            .max()
            .unwrap_or(0)
    }

    /// The file name Setup looks for slice `slice` (0-based) under, for an
    /// installer named `installer_name` (`mysetup.exe`). By release
    /// (issrc `FindDisk` / `FindSliceFilename`):
    ///
    /// - before 2.0: `<BaseFilename>.<disk>` (`setup.1`), the header's
    ///   [`HeaderString::BaseFilename`];
    /// - 2.0 to 4.x: `<BaseFilename>-<disk>.bin`;
    /// - from 5.0: the installer's own name without its extension,
    ///   `<name>-<disk>.bin`.
    ///
    /// From 4.0, with more than one slice per disk
    /// ([`crate::HeaderTail::slices_per_disk`]), a letter follows the disk:
    /// `-1a.bin`, `-1b.bin`, `-2a.bin`.
    #[must_use]
    pub fn slice_file_name(&self, slice: u32, installer_name: &str) -> String {
        let per_disk = self
            .header
            .as_ref()
            .map_or(1, |h| h.tail().slices_per_disk)
            .max(1);
        let disk = slice.checked_div(per_disk).unwrap_or(0).saturating_add(1);
        let letter = slice.checked_rem(per_disk).unwrap_or(0);
        let base_filename = || {
            self.header
                .as_ref()
                .and_then(|h| h.string(HeaderString::BaseFilename))
                .unwrap_or("setup")
                .to_owned()
        };
        if !self.version.at_least(2, 0, 0) {
            return format!("{}.{disk}", base_filename());
        }
        let prefix = if self.version.at_least(5, 0, 0) {
            match installer_name.rsplit_once('.') {
                Some((stem, _)) => stem.to_owned(),
                None => installer_name.to_owned(),
            }
        } else {
            base_filename()
        };
        if per_disk == 1 {
            format!("{prefix}-{disk}.bin")
        } else {
            let letter = char::from_u32(u32::from('a').saturating_add(letter)).unwrap_or('a');
            format!("{prefix}-{disk}{letter}.bin")
        }
    }

    /// Supplies the slice files of a disk-spanning installer, in order
    /// (slice 0 first; see [`Self::slice_file_name`]), for extraction.
    /// Each is checked: the slice ID the release writes, and the total size
    /// its header states.
    ///
    /// # Errors
    ///
    /// [`Error::BadSlice`] for a slice that is not one.
    pub fn with_slices(mut self, slices: &[&'a [u8]]) -> Result<Self, Error> {
        SliceReader::new(&[], 0, slices, &self.version)?;
        self.slices = slices.to_vec();
        Ok(self)
    }

    /// Returns the file-location record referenced by a file entry.
    #[must_use]
    pub fn file_location_for(&self, file: &FileEntry) -> Option<&DataEntry> {
        usize::try_from(file.location_index)
            .ok()
            .and_then(|idx| self.records.file_locations.get(idx))
    }

    /// Iterates the install + uninstall command-execution stream
    /// as a single sequence, with each item tagged
    /// [`crate::analysis::ExecPhase::Install`] or
    /// [`crate::analysis::ExecPhase::Uninstall`].
    ///
    /// Visit order is `[Run]` declaration order followed by
    /// `[UninstallRun]` declaration order. See
    /// [`crate::analysis::exec`] for the view shape.
    #[must_use]
    pub fn exec_commands(&self) -> ExecIter<'_> {
        ExecIter::new(self.run_entries(), self.uninstall_runs())
    }

    /// Iterates `[Registry]` entries, each with the
    /// [`crate::analysis::RegistryOpKind`] Setup carries out for it at
    /// install time, from its flags and value type.
    ///
    /// Uninstall-time effects are not classified here - inspect
    /// the underlying entry's `flags` for `UninsDeleteValue`,
    /// `UninsDeleteEntireKey`, etc.
    #[must_use]
    pub fn registry_ops(&self) -> RegistryOpIter<'_> {
        RegistryOpIter::new(self.registry_entries())
    }

    /// Iterates `[Icons]` entries joined to their target
    /// `[Files]` entry where the icon's `filename` matches a
    /// file's `destination`. Icons that point at system paths or
    /// arbitrary URIs surface as a [`crate::analysis::Shortcut`]
    /// with `target = None`.
    #[must_use]
    pub fn shortcuts(&self) -> ShortcutIter<'_> {
        ShortcutIter::new(self.icons(), self.files())
    }

    /// Whether the installer's data is encrypted: file chunks (and from
    /// 6.5.0 possibly setup-0 itself; [`EncryptionMode`]) under XChaCha20 from
    /// 6.4.0, or under ARC4 before (`Encryption=yes`, the header's
    /// [`crate::HeaderOption::EncryptionUsed`], 4.2.2+). Extracting such a
    /// file needs the password. An installer that only asks for a password
    /// is not encrypted; see [`Self::has_password`].
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        match self.encryption.as_ref().map(|e| e.mode) {
            Some(EncryptionMode::Files | EncryptionMode::Full) => true,
            _ => self
                .header
                .as_ref()
                .is_some_and(|h| h.has_option(crate::HeaderOption::EncryptionUsed)),
        }
    }

    /// Whether Setup asks for a password (`Password=`, the header's
    /// [`crate::HeaderOption::Password`]), with or without encrypting
    /// anything. Every encrypted installer has one. For an `euFull`
    /// installer opened without the password the header cannot be read;
    /// this is then true by its encryption alone.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.is_encrypted()
            || self
                .header
                .as_ref()
                .is_some_and(|h| h.has_option(crate::HeaderOption::Password))
    }

    /// Returns the password (verbatim from the candidate list
    /// passed to [`Self::from_bytes_with_passwords`]) that matched
    /// the on-disk verifier, or `None` if the installer is not
    /// encrypted (or wasn't unlocked).
    #[must_use]
    pub fn password_used(&self) -> Option<&str> {
        self.password_used.as_deref()
    }

    /// Streaming primary extraction API. Returns a [`FileReader`]
    /// that yields the file's post-BCJ, post-decompression bytes
    /// and verifies the recorded checksum at EOF (mismatch surfaces
    /// as `io::Error` on the next `read` call after exhaustion).
    ///
    /// # Errors
    ///
    /// - [`Error::NoLocation`] for the embedded uninstaller
    ///   (`location_index == u32::MAX`).
    /// - [`Error::Encrypted`] when the chunk is encrypted and no
    ///   key has been supplied via
    ///   [`InnoInstaller::from_bytes_with_passwords`].
    /// - [`Error::ExternalSlice`] when the chunk lives in an
    ///   external `setup-N.bin` file.
    /// - [`Error::MultiSliceChunk`] when the chunk spans slices.
    /// - [`Error::Decompress`], [`Error::BadChunkMagic`], etc. on
    ///   format errors.
    pub fn extract(&self, file: &FileEntry) -> Result<FileReader<'_>, Error> {
        if file.location_index == u32::MAX {
            return Err(Error::NoLocation);
        }
        self.extract_by_location(file.location_index)
    }

    /// Extract by file-location index (for advanced callers
    /// inspecting the raw `FileEntry → DataEntry` mapping).
    pub fn extract_by_location(&self, location_index: u32) -> Result<FileReader<'_>, Error> {
        let data = self
            .records
            .file_locations
            .get(location_index as usize)
            .ok_or(Error::Truncated {
                what: "file_locations index",
            })?;
        let chunk_bytes = self.chunk_bytes_for(location_index)?;
        crate::stream::file::open(chunk_bytes, data, &self.version)
    }

    /// Eager convenience: drains the streaming reader into a
    /// `Vec<u8>`. The returned vector is exactly
    /// `data.original_size` bytes and has been checksum-verified.
    ///
    /// # Errors
    ///
    /// Same as [`Self::extract`].
    pub fn extract_to_vec(&self, file: &FileEntry) -> Result<Vec<u8>, Error> {
        let mut reader = self.extract(file)?;
        let mut out = Vec::with_capacity(reader.len());
        std::io::Read::read_to_end(&mut reader, &mut out).map_err(|e| Error::Decompress {
            stream: "extract_to_vec",
            source: e,
        })?;
        Ok(out)
    }

    /// Reconstructs the uninstaller (`unins000.exe`): from 5.0.0 by
    /// duplicating the input bytes and patching the `SetupExeMode` slot to
    /// the uninstaller magic, before 5.0.0 by extracting it.
    ///
    /// Before 5.0.0 the uninstaller is a program of its own, `Uninst.e32`,
    /// which the compiler stores like any other file under the `[Files]`
    /// entry of type [`FileEntryType::UninstExe`] (issrc-4.0.8
    /// `Install.pas`); this returns its bytes, which
    /// [`Self::extract_files`] yields too.
    ///
    /// From 5.0.0 the uninstaller stub isn't a separately-packaged file in
    /// the chunk stream - at install time `Setup.exe` copies its
    /// own bytes (`NewParamStr(0)` in
    /// `Setup.Install.pas:1629-1631`) and overwrites the four-byte
    /// mode marker at offset `0x30` with `0x6E556E49`
    /// (LE: `b"InUn"`) via `MarkExeHeader`
    /// (`Setup.Install.HelperFunc.pas:469-473`). On launch the
    /// same EXE reads that marker (`Setup.Start.pas:148`) and
    /// dispatches into uninstaller mode rather than installer
    /// mode. Both constants - `SetupExeModeOffset = $30` and
    /// `SetupExeModeUninstaller = $6E556E49` - have been stable
    /// across the version range we cover (verified at `is-5_5_5`
    /// through `is-7_0_0_2`, `Shared.Struct.pas`).
    ///
    /// What this method does **not** do: append the localized-
    /// messages tail (`BindUninstallMsgDataToExe`,
    /// `Setup.Install.pas:485-503`). Real installs append a
    /// `TUninstallerMsgTail` record on top of the patched bytes
    /// using runtime state (selected language, expanded `AppId`)
    /// that we can't fully reconstruct from a static parse. The
    /// produced binary is still a valid uninstaller for
    /// inspection / triage; it just won't display Inno's localized
    /// "Are you sure you want to uninstall…?" prompts the way an
    /// installed-and-bound copy would.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let bytes = std::fs::read("setup.exe")?;
    /// let inst = innospect::InnoInstaller::from_bytes(&bytes)?;
    /// let uninstaller = inst.extract_uninstaller()?;
    /// if inst.version().at_least(5, 0, 0) {
    ///     // The installer itself, with its mode slot marked `InUn`.
    ///     assert_eq!(uninstaller.len(), bytes.len());
    ///     assert_eq!(&uninstaller[0x30..0x34], b"InUn");
    /// }
    /// std::fs::write("unins000.exe", &uninstaller)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::NoLocation`] when the installer ships no
    ///   uninstaller stub (`Uninstallable=no` builds; older
    ///   installers without an `ftUninstExe` `[Files]` entry).
    /// - [`Error::Truncated`] when the input is too short to
    ///   contain the mode marker at offset `0x30`.
    /// - Before 5.0.0, whatever extracting the file returns (see
    ///   [`Self::extract_to_vec`]).
    pub fn extract_uninstaller(&self) -> Result<Vec<u8>, Error> {
        let Some(uninstaller) = self
            .files()
            .iter()
            .find(|f| f.file_type == Some(FileEntryType::UninstExe))
        else {
            return Err(Error::NoLocation);
        };
        if !self.version.at_least(5, 0, 0) {
            return self.extract_to_vec(uninstaller);
        }
        const MODE_OFFSET: usize = 0x30;
        const MODE_UNINSTALLER: u32 = 0x6E55_6E49;
        let mut bytes = self.input.to_vec();
        let end = MODE_OFFSET.saturating_add(4);
        let slot = bytes.get_mut(MODE_OFFSET..end).ok_or(Error::Truncated {
            what: "SetupExeMode slot at offset 0x30",
        })?;
        slot.copy_from_slice(&MODE_UNINSTALLER.to_le_bytes());
        Ok(bytes)
    }

    /// Bulk extraction iterator over every file entry that carries
    /// a chunk payload.
    ///
    /// Yields `(file, bytes)` for each [`FileEntry`] whose
    /// `location_index` resolves to a real `setup-1` chunk; entries
    /// with `location_index == u32::MAX` (the embedded uninstaller
    /// stub, certain external-file placeholders) are filtered out
    /// rather than producing [`Error::NoLocation`] mid-stream.
    ///
    /// Iteration order matches [`Self::files`] declaration order.
    /// When solid-LZMA mode places multiple files in the same
    /// chunk, the per-chunk `OnceLock` cache makes the second and
    /// subsequent extractions from that chunk free - i.e. running
    /// the iterator end-to-end touches each chunk's decompression
    /// path exactly once even though there are many file
    /// extractions.
    ///
    /// Each item is a [`Result`] so a single malformed chunk
    /// doesn't poison the rest of the stream.
    pub fn extract_files(&self) -> impl Iterator<Item = Result<(&FileEntry, Vec<u8>), Error>> + '_ {
        self.files()
            .iter()
            .filter(|f| f.location_index != u32::MAX)
            .map(move |f| self.extract_to_vec(f).map(|bytes| (f, bytes)))
    }

    /// Returns the currently-armed encryption context (key +
    /// base nonce, or password) for chunk decryption, or `None`
    /// for plaintext installers / installers that haven't been
    /// unlocked.
    fn encryption_context(&self) -> Option<crate::stream::chunk::EncryptionContext<'_>> {
        // Modern (6.4+) - derived 32-byte key + base nonce.
        if let (Some(key), Some(info)) = (self.encryption_key.as_ref(), self.encryption.as_ref()) {
            return Some(crate::stream::chunk::EncryptionContext::Modern {
                key,
                base_nonce: &info.base_nonce,
            });
        }
        // Legacy (pre-6.4) - keep the password verbatim (per-chunk
        // RC4 keys are derived from password + each chunk's salt).
        // 5.3.9..6.4 uses SHA-1 keying; pre-5.3.9 uses MD5.
        if let Some(password) = self.legacy_password.as_deref() {
            return Some(crate::stream::chunk::EncryptionContext::Legacy {
                password,
                use_sha1: self.version.at_least(5, 3, 9),
                unicode: crate::util::encoding::is_unicode_for_version(&self.version),
            });
        }
        None
    }

    fn chunk_bytes_for(&self, location_index: u32) -> Result<&[u8], Error> {
        let chunk_id =
            *self
                .file_loc_to_chunk
                .get(location_index as usize)
                .ok_or(Error::Truncated {
                    what: "file_loc_to_chunk lookup",
                })?;
        let slot = self
            .chunk_cache
            .get(chunk_id as usize)
            .ok_or(Error::Truncated {
                what: "chunk_cache lookup",
            })?;

        // OnceLock::get_or_init can't return Result, so we match
        // ourselves: try the cached value first; if absent, run the
        // fallible decompression and `set` the slot on success.
        if let Some(arc) = slot.get() {
            return Ok(arc.as_ref());
        }
        let data = self
            .records
            .file_locations
            .get(location_index as usize)
            .ok_or(Error::Truncated {
                what: "file_locations index",
            })?;
        let header = self.header.as_ref().ok_or(Error::Truncated {
            what: "setup header",
        })?;
        let slice = SliceReader::new(
            self.input,
            self.offset_table.offset_setup1,
            &self.slices,
            &self.version,
        )?;
        let needed = self
            .chunk_needed
            .get(chunk_id as usize)
            .copied()
            .unwrap_or(u64::MAX);
        let bytes = decompress_chunk(
            &slice,
            data,
            header.tail(),
            self.encryption_context().as_ref(),
            needed,
        )?;
        // If another thread raced ahead, `set` will fail - fall
        // back to whatever value got installed.
        let bytes = match slot.set(bytes) {
            Ok(()) => slot.get().ok_or(Error::Truncated {
                what: "OnceLock raced",
            })?,
            Err(_) => slot.get().ok_or(Error::Truncated {
                what: "OnceLock raced",
            })?,
        };
        Ok(bytes.as_ref())
    }
}

/// Tries each candidate password against the on-disk verifier and
/// returns the derived 32-byte key plus the matching password on
/// success.
///
/// The verifier check follows upstream's `TestPassword`
/// (issrc `Projects/Src/Shared.EncryptionFunc.pas`):
///
/// 1. Derive the 32-byte key via PBKDF2-HMAC-SHA256 with the
///    UTF-16LE-encoded password, the `KDFSalt`, and `KDFIterations`.
/// 2. Encrypt 4 zero bytes under XChaCha20 with the
///    `sccPasswordTest` nonce.
/// 3. Compare the cipher output to `password_test`.
///
/// `version` selects the PBKDF2 implementation: marker `(7,0,0,1)`
/// (Inno 7.0.0-preview-3 = `is-7_0_0_2`) routes through
/// [`crate::crypto::pbkdf2::derive_key_buggy_700_preview3`] to
/// reproduce the upstream PBKDF2 bug; everything else uses the
/// standard [`crate::crypto::pbkdf2::derive_key`].
///
/// # Errors
///
/// Returns [`Error::WrongPassword`] when no candidate matches the
/// stored verifier.
fn try_passwords(
    info: &EncryptionInfo,
    passwords: &[&str],
    version: &Version,
) -> Result<(Option<[u8; 32]>, Option<String>), Error> {
    // SetupID 7.0.0.1 is written by 7.0.0 preview 2 (`is-7_0_0_1`), whose
    // PBKDF2 is standard, and preview 3 (`is-7_0_0_2`), whose PBKDF2 drops
    // the first block's first term (issrc `f4fc1daf`, fixed by `90f06e4d`
    // before 7.0.0, which writes 7.0.0.3). Nothing stored tells the two
    // apart, so under that marker both are tried, and the verifier decides.
    type Derive = fn(&str, &[u8; 16], u32) -> [u8; 32];
    let standard: Derive = crate::crypto::pbkdf2::derive_key;
    let preview3: Derive = crate::crypto::pbkdf2::derive_key_buggy_700_preview3;
    let derivations: &[Derive] = if (version.a, version.b, version.c, version.d) == (7, 0, 0, 1) {
        &[standard, preview3]
    } else {
        &[standard]
    };
    for &password in passwords {
        for derive in derivations {
            let key = derive(password, &info.salt, info.kdf_iterations);
            let actual = crate::crypto::xchacha20::password_test_verifier(&key, &info.base_nonce);
            if actual == info.password_test {
                return Ok((Some(key), Some(password.to_owned())));
            }
        }
    }
    Err(Error::WrongPassword)
}

/// `euFull` (6.5+) decryption + decompression of the two setup-0
/// block streams.
///
/// Wire format per upstream's `TCompressedBlockWriter.FlushOutputBuffer`
/// (issrc `Projects/Src/Compression.Base.pas`):
///
/// ```text
/// [outer header: plaintext CRC + StoredSize + flag]
/// [for each 4 KiB sub-chunk:
///     [4-byte CRC32 of ENCRYPTED bytes]
///     [encrypted: compressed-data XOR'd with XChaCha20 keystream]
/// ]
/// ```
///
/// The XChaCha20 state runs continuously across the sub-chunks
/// within a single block. Block 1 uses the `sccCompressedBlocks1`
/// nonce; block 2 uses `sccCompressedBlocks2`. Both with counter 0
/// (a fresh cipher per block).
/// `(decompressed_setup0, decompressed_data_block, compression)`.
type DecryptedBlocks = (Box<[u8]>, Box<[u8]>, Compression);

fn decompress_blocks_eufull(
    setup0: &[u8],
    block_start: usize,
    version: &Version,
    base_nonce: &[u8; 24],
    key: &[u8; 32],
) -> Result<DecryptedBlocks, Error> {
    let nonce1 = special_nonce(base_nonce, SpecialContext::CompressedBlocks1);
    let block1 =
        crate::stream::block::decompress(setup0, block_start, version, Some((key, &nonce1)))?;
    let comp = Compression::from_block(block1.compression);

    let block2_start = block_start
        .checked_add(block1.consumed)
        .ok_or(Error::Overflow {
            what: "second block start",
        })?;
    let nonce2 = special_nonce(base_nonce, SpecialContext::CompressedBlocks2);
    let block2 =
        crate::stream::block::decompress(setup0, block2_start, version, Some((key, &nonce2)))?;

    Ok((block1.bytes, block2.bytes, comp))
}

/// Best-effort scan of an Inno 6.3+ architecture expression for
/// known atom names. Mirrors the canonical set in issrc
/// `Setup.MainFunc.pas:ArchIdentifiers`: `arm32compatible`,
/// `arm64`, `x64`, `x64os`, `x64compatible`, `x86`, `x86os`,
/// `x86compatible`, plus the deprecated `ia64` from older releases.
///
/// Every atom that substring-matches the expression contributes
/// its [`Architecture`] to the result. Boolean operators (`and`,
/// `or`, `not`) are not evaluated, so `not x64` reports `Amd64`
/// just like a bare `x64` would. This is sufficient for an
/// "architectures the author considered" view; faithful
/// per-machine evaluation is the runtime's job.
fn parse_architecture_expression(s: &str) -> HashSet<Architecture> {
    let lower = s.to_ascii_lowercase();
    let mut set = HashSet::new();
    // Order doesn't matter - duplicate hits collapse in the set.
    let atoms: &[(&str, Architecture)] = &[
        ("x86compatible", Architecture::X86),
        ("x86os", Architecture::X86),
        ("x86", Architecture::X86),
        ("x64compatible", Architecture::Amd64),
        ("x64os", Architecture::Amd64),
        ("x64", Architecture::Amd64),
        ("arm32compatible", Architecture::Arm32),
        ("arm64", Architecture::Arm64),
        ("ia64", Architecture::IA64),
    ];
    for (atom, arch) in atoms {
        if lower.contains(atom) {
            set.insert(*arch);
        }
    }
    set
}

/// Picks the right [`crate::crypto::kdflegacy::LegacyStoredHash`]
/// for a parsed pre-6.4 header. Returns `None` when the installer
/// has no `shPassword` flag (i.e. is not actually encrypted) or
/// when the relevant `HeaderTail` field is absent for that
/// version.
fn legacy_stored_hash(
    tail: &crate::header::HeaderTail,
    version: &Version,
) -> Option<LegacyStoredHash> {
    // The `shPassword` Options bit is the discriminator for
    // pre-6.4 encryption - without it, the legacy hash fields are
    // either absent or zero. Since options decoding is per-version
    // and exposed via header.has_option, we check via the parsed
    // tail's options bytes directly to avoid a dependency cycle.
    // Easier: inspect the field availability - every encrypted
    // pre-6.4 installer populates the relevant hash field per
    // its version family.
    match legacy_hash_family(version) {
        LegacyHashFamily::Crc32 => tail.legacy_password_crc32.map(LegacyStoredHash::Crc32),
        LegacyHashFamily::Md5Bare => tail.legacy_password_md5.map(LegacyStoredHash::Md5Bare),
        LegacyHashFamily::Md5SaltedWithPrefix => {
            match (tail.legacy_password_md5, tail.legacy_password_salt) {
                (Some(hash), Some(salt)) => Some(LegacyStoredHash::Md5Salted { hash, salt }),
                _ => None,
            }
        }
        LegacyHashFamily::Sha1SaltedWithPrefix => {
            match (tail.legacy_password_sha1, tail.legacy_password_salt) {
                (Some(hash), Some(salt)) => Some(LegacyStoredHash::Sha1Salted { hash, salt }),
                _ => None,
            }
        }
    }
}

/// Tries each candidate password against the legacy
/// [`crate::crypto::kdflegacy::verify_password_legacy`] verifier.
/// Returns the matched password (verbatim) on success, or
/// [`Error::WrongPassword`] when none match.
fn try_passwords_legacy(
    stored: &crate::crypto::kdflegacy::LegacyStoredHash,
    passwords: &[&str],
    version: &Version,
) -> Result<String, Error> {
    let unicode = crate::util::encoding::is_unicode_for_version(version);
    for &candidate in passwords {
        if crate::crypto::kdflegacy::verify_password_legacy(candidate, stored, unicode) {
            return Ok(candidate.to_owned());
        }
    }
    Err(Error::WrongPassword)
}

/// `(chunk_cache, file_loc_to_chunk, chunk_needed)` - return type of
/// [`build_chunk_index`]. Aliased here for clippy.
type ChunkIndex = (Box<[OnceLock<Arc<[u8]>>]>, Box<[u32]>, Box<[u64]>);

/// Group `file_locations` by their `(first_slice, start_offset)`
/// chunk key, returning:
///   - `chunk_cache`: one empty `OnceLock` slot per unique chunk.
///   - `file_loc_to_chunk`: parallel array mapping each file-loc
///     index to its chunk slot index.
///   - `chunk_needed`: per slot, how far into the decompressed chunk its
///     furthest file reaches.
fn build_chunk_index(file_locations: &[DataEntry]) -> ChunkIndex {
    // (first_slice, start_offset) → chunk slot index.
    let mut keys: HashMap<(u32, u64), u32> = HashMap::new();
    let mut next_id: u32 = 0;
    let mut mapping: Vec<u32> = Vec::with_capacity(file_locations.len());

    let mut needed: Vec<u64> = Vec::new();
    for d in file_locations {
        let key = (d.first_slice, d.start_offset);
        let id = *keys.entry(key).or_insert_with(|| {
            let id = next_id;
            next_id = next_id.saturating_add(1);
            id
        });
        mapping.push(id);
        let reach = d.chunk_sub_offset.saturating_add(d.original_size);
        let slot = usize::try_from(id).unwrap_or(usize::MAX);
        if needed.len() <= slot {
            needed.resize(slot.saturating_add(1), 0);
        }
        if let Some(n) = needed.get_mut(slot) {
            *n = (*n).max(reach);
        }
    }

    let cache_len = next_id as usize;
    let mut cache: Vec<OnceLock<Arc<[u8]>>> = Vec::with_capacity(cache_len);
    for _ in 0..cache_len {
        cache.push(OnceLock::new());
    }

    (
        cache.into_boxed_slice(),
        mapping.into_boxed_slice(),
        needed.into_boxed_slice(),
    )
}

/// Parses the decompressed setup-0 blocks: the header and the records of
/// block 1, the data entries of block 2.
fn parse_setup0(
    setup0: &[u8],
    data_block: &[u8],
    version: &Version,
) -> Result<(SetupHeader, ParsedRecords), Error> {
    let header = SetupHeader::parse(setup0, version)?;
    let records = parse_records(setup0, data_block, &header, version)?;
    Ok((header, records))
}

fn parse_records(
    setup0: &[u8],
    data_block: &[u8],
    header: &SetupHeader,
    version: &Version,
) -> Result<ParsedRecords, Error> {
    let mut reader = Reader::at(setup0, header.records_offset())?;
    let counts = header.counts();

    let languages = read_n::<LanguageEntry>(&mut reader, counts.languages, version)?;
    // Before 4.0.0 the wizard images and the decompressor DLL come here,
    // between the language options and the rest; later they follow the
    // uninstall-run entries and end the block (see `setupfiles`).
    let mut setup_files = if version.at_least(4, 0, 0) {
        None
    } else {
        Some(setupfiles::read(&mut reader, header, version)?)
    };
    let messages = read_n::<MessageEntry>(&mut reader, counts.custom_messages, version)?;
    let permissions = read_n::<PermissionEntry>(&mut reader, counts.permissions, version)?;
    let types = read_n::<TypeEntry>(&mut reader, counts.types, version)?;
    let components = read_n::<ComponentEntry>(&mut reader, counts.components, version)?;
    let tasks = read_n::<TaskEntry>(&mut reader, counts.tasks, version)?;
    let directories = read_n::<DirectoryEntry>(&mut reader, counts.directories, version)?;
    // 6.5+ ISSigKeys: 3 String fields per entry (PublicX, PublicY,
    // RuntimeID). See `records::isssigkey`.
    let iss_sig_keys = if let Some(n) = counts.iss_sig_keys {
        read_n::<ISSigKeyEntry>(&mut reader, n, version)?
    } else {
        Vec::new()
    };
    let files = read_n::<FileEntry>(&mut reader, counts.files, version)?;
    let icons = read_n::<IconEntry>(&mut reader, counts.icons, version)?;
    let ini_entries = read_n::<IniEntry>(&mut reader, counts.ini_entries, version)?;
    let registry = read_n::<RegistryEntry>(&mut reader, counts.registry, version)?;
    let install_deletes = read_n::<DeleteEntry>(&mut reader, counts.install_deletes, version)?;
    let uninstall_deletes = read_n::<DeleteEntry>(&mut reader, counts.uninstall_deletes, version)?;
    let run = read_n::<RunEntry>(&mut reader, counts.run, version)?;
    let uninstall_run = read_n::<RunEntry>(&mut reader, counts.uninstall_run, version)?;

    // From 4.0.0 the wizard images and DLLs end the block, which
    // `setupfiles::read` checks. Before, nothing follows the uninstall-run
    // entries; a byte left over means a wrong layout either way.
    let setup_files = match setup_files.take() {
        Some(files) => {
            if reader.remaining() != 0 {
                return Err(Error::TrailingData {
                    what: "setup-0 records block",
                    len: reader.remaining(),
                });
            }
            files
        }
        None => setupfiles::read(&mut reader, header, version)?,
    };

    // Block 2: file-location records. Even when count is 0 the
    // block is well-formed; we just don't read anything from it.
    let mut data_reader = Reader::new(data_block);
    let file_locations = read_n::<DataEntry>(&mut data_reader, counts.file_locations, version)?;
    // Block 2 holds the data entries and nothing else.
    if data_reader.remaining() != 0 {
        return Err(Error::TrailingData {
            what: "setup-0 data entries block",
            len: data_reader.remaining(),
        });
    }

    Ok(ParsedRecords {
        languages,
        messages,
        permissions,
        types,
        components,
        tasks,
        directories,
        iss_sig_keys,
        files,
        icons,
        ini_entries,
        registry,
        install_deletes,
        uninstall_deletes,
        run,
        uninstall_run,
        file_locations,
        setup_files,
    })
}

fn read_n<T: FromReader>(
    reader: &mut Reader<'_>,
    count: u32,
    version: &Version,
) -> Result<Vec<T>, Error> {
    let cap = usize::try_from(count).map_err(|_| Error::Overflow {
        what: "record count",
    })?;
    // A count comes from the file: every record is at least a byte, so
    // never reserve more than the bytes left could hold.
    let mut out = Vec::with_capacity(cap.min(reader.remaining()));
    for _ in 0..cap {
        out.push(read_record::<T>(reader, version)?);
    }
    Ok(out)
}

fn usize_from_u64(value: u64, what: &'static str) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::Overflow { what })
}

fn parse_encryption_header(reader: &mut Reader<'_>) -> Result<Option<EncryptionInfo>, Error> {
    // Layout per Shared.Struct.pas:108-114:
    //   CRC32 (4) | EncryptionUse (1) | KDFSalt (16) | KDFIterations (4)
    //   | BaseNonce (24) | PasswordTest (4)
    let _crc = reader.u32_le("encryption header CRC")?;
    let mode_byte = reader.u8("EncryptionUse")?;
    let salt = reader.array::<16>("KDFSalt")?;
    let kdf_iterations = reader.u32_le("KDFIterations")?;
    let base_nonce = reader.array::<24>("BaseNonce")?;
    let password_test = reader.u32_le("PasswordTest")?;

    let mode = match mode_byte {
        0 => EncryptionMode::None,
        1 => EncryptionMode::Files,
        2 => EncryptionMode::Full,
        // Forward-compatibility: unknown values fall back to None
        // rather than rejecting the installer outright.
        _ => EncryptionMode::None,
    };

    // Even when chunks aren't encrypted (`euNone`), the compiler
    // populates KDFSalt / BaseNonce / PasswordTest whenever
    // `Password=` is set. Surface the verifier so callers can
    // password-test the installer.
    Ok(Some(EncryptionInfo {
        mode,
        salt,
        kdf_iterations,
        base_nonce,
        password_test,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{MARKERS, encode_strings, version};

    /// A 1.3.25 setup-0 with no records: the header as upstream declares
    /// it, every count zero, and the one wizard image, empty.
    fn empty_setup0_1_3_25() -> (Vec<u8>, Version) {
        let header = MARKERS
            .iter()
            .find(|m| m.id == "1.3.25")
            .and_then(|m| {
                m.variants[0].builds[0]
                    .records
                    .iter()
                    .find(|r| r.name == "TSetupHeader")
            })
            .expect("1.3.25 TSetupHeader");
        let mut setup0 = Vec::new();
        encode_strings(header, false, &version("1.3.25", false), &mut setup0);
        setup0.resize(setup0.len() + header.tail, 0);
        setup0.extend_from_slice(&0u32.to_le_bytes());
        (setup0, version("1.3.25", false))
    }

    #[test]
    fn bytes_past_the_records_are_trailing_data() {
        let (setup0, version) = empty_setup0_1_3_25();
        parse_setup0(&setup0, &[], &version).expect("empty 1.3.25 setup-0 parses");

        let mut longer = setup0.clone();
        longer.push(0);
        assert!(matches!(
            parse_setup0(&longer, &[], &version),
            Err(Error::TrailingData { len: 1, .. })
        ));
        assert!(matches!(
            parse_setup0(&setup0, &[0], &version),
            Err(Error::TrailingData { len: 1, .. })
        ));
    }
}
