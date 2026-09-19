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

use crate::{
    analysis::{exec::ExecIter, registryop::RegistryOpIter, shortcut::ShortcutIter},
    crypto::{
        kdflegacy::{LegacyHashFamily, LegacyStoredHash, legacy_hash_family},
        xchacha20::{SpecialContext, special_nonce},
    },
    decompress::block::{BlockCompression, decompress_block, decompress_block_with_decryption},
    error::Error,
    extract::{chunk::decompress_chunk, file::FileReader, slice::SliceReader},
    header::{Architecture, HeaderAnsi, HeaderString, SetupHeader},
    overlay::{
        OffsetTable,
        offsettable::SetupLdrFamily,
        pe::{self, OffsetTableLocation},
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
    util::read::Reader,
    version::{Variant, Version, read_marker},
};

/// Block-compression method for the setup-0 header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compression {
    /// Uncompressed.
    Stored,
    /// Zlib (Deflate). Used by 4.0.9 ≤ version < 4.1.6.
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

/// Per-installer encryption metadata, parsed from the optional
/// `TSetupEncryptionHeader` that precedes the compressed block in
/// 6.4.0+ installers. Older installers store encryption metadata
/// per-chunk.
#[derive(Clone, Debug)]
pub struct EncryptionInfo {
    /// `EncryptionUse` from `Shared.Struct.pas:108-114`.
    pub mode: EncryptionMode,
    /// PBKDF2-SHA256 salt.
    pub salt: [u8; 16],
    /// PBKDF2 iteration count (variable; default `220_000`).
    pub kdf_iterations: u32,
    /// XChaCha20 base nonce.
    pub base_nonce: [u8; 24],
    /// Password verifier value (compared against XChaCha20-of-zero
    /// after key derivation).
    pub password_test: u32,
}

/// Whether (and how) the installer is encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionMode {
    /// `euNone`: no encryption.
    None,
    /// `euFiles`: only file payload chunks are encrypted; setup-0
    /// remains plaintext.
    Files,
    /// `euFull` (6.5+): the entire setup-0 stream after the
    /// encryption header is XChaCha20-encrypted.
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
    /// with `euFull` and no key is available, or when the installer
    /// pre-dates the 4.0.9 block-header layout.
    decompressed_setup0: Box<[u8]>,
    /// Decompressed bytes of the second block stream that
    /// immediately follows the first one in `setup-0`. Holds the
    /// `TSetupFileLocationEntry` records (one per slot in
    /// `EntryCounts.file_locations`). Empty when no second block is
    /// present (older versions, or when the first block was skipped).
    decompressed_data_block: Box<[u8]>,
    /// Parsed header. `None` when `decompressed_setup0` is empty
    /// (`euFull`-encrypted or pre-4.0.9 layout).
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
    /// # Errors
    ///
    /// - [`Error::PasswordRequired`] - installer is encrypted but
    ///   `passwords` is empty.
    /// - [`Error::WrongPassword`] - no candidate matched.
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

        let (version, variant) = read_marker(setup0)?;

        // Whatever follows the 64-byte SetupID depends on version.
        //
        // - 6.5.0+: an unconditional 4-byte CRC32 + 49-byte
        //   `TSetupEncryptionHeader` precedes the compressed block.
        //   Introduced in commit `f7170990` (2025-08-03, ships in tag
        //   `is-6_5_0`).
        // - 6.4.x: encryption metadata exists but lives inside the
        //   compressed `TSetupHeader` struct. We can't surface it
        //   until the block is decompressed.
        // - pre-6.4: per-chunk encryption.
        let mut after_marker = Reader::at(setup0, 64)?;
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

        // Decompress the setup-0 block streams. Three paths:
        //   - pre-4.0.9: skipped (older block-header layout we
        //     don't yet support).
        //   - euFull (6.5+) WITH a derived key: decrypt block 1
        //     with `sccCompressedBlocks1`, run decompress_block,
        //     then decrypt block 2 with `sccCompressedBlocks2`,
        //     run again.
        //   - plaintext OR euFull-without-key: read both blocks
        //     directly (or skip when encrypted-without-key).
        //
        // The two-block layout matches
        // `research-notes/05-streams-and-compression.md` §"Two-
        // block layout"; per-chunk decryption in setup-1 fires
        // independently in `extract::chunk`.
        let (decompressed_setup0, decompressed_data_block, compression) =
            if !version.at_least(4, 0, 9) {
                (
                    Box::<[u8]>::default(),
                    Box::<[u8]>::default(),
                    Compression::Unknown,
                )
            } else if block_is_encrypted {
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

        let header = if decompressed_setup0.is_empty() {
            None
        } else {
            Some(SetupHeader::parse(&decompressed_setup0, &version)?)
        };

        let records = match header.as_ref() {
            Some(h) => parse_records(&decompressed_setup0, &decompressed_data_block, h, &version)?,
            None => ParsedRecords::default(),
        };

        let (chunk_cache, file_loc_to_chunk) = build_chunk_index(&records.file_locations);

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
        // Run the modern (PBKDF2 + XChaCha20) password trial whenever
        // an `EncryptionInfo` is in scope and we haven't unlocked
        // already. This covers 6.5+ password-only installers (mode=None
        // with the verifier populated), 6.4.x with EncryptionUsed
        // (mode=Files via the promotion above), and 6.4.x password-only
        // (mode=None via the promotion above).
        if let Some(candidates) = passwords
            && encryption_key.is_none()
            && let Some(info) = encryption.as_ref()
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
            encryption_key,
            legacy_password,
            password_used,
        })
    }

    /// Returns the decompressed setup-0 bytes. Empty when the block
    /// could not be decompressed (encrypted-`euFull`, or older
    /// pre-4.0.9 layout pending full support).
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

    /// Returns the parsed Inno Setup version.
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
    pub fn pe_locator_mode(&self) -> pe::LocatorMode {
        self.pe_location.mode
    }

    /// Returns the encryption metadata for 6.4.0+ installers, or
    /// `None` if not encrypted (or if the version is older than 6.4 -
    /// pre-6.4 encryption is per-chunk, surfaced through the
    /// `DataEntry::ChunkEncrypted` flag on each affected chunk).
    #[must_use]
    pub fn encryption(&self) -> Option<&EncryptionInfo> {
        self.encryption.as_ref()
    }

    /// Block-compression method for the setup-0 header block.
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
    /// Integrity validation is therefore limited to successful setup-0
    /// decompression and structural parsing.
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

    /// Iterates `[Registry]` entries with each one classified as
    /// [`crate::analysis::RegistryOpKind::Write`],
    /// [`WriteIfMissing`](crate::analysis::RegistryOpKind::WriteIfMissing),
    /// [`DeleteValue`](crate::analysis::RegistryOpKind::DeleteValue),
    /// or [`DeleteKey`](crate::analysis::RegistryOpKind::DeleteKey)
    /// based on the entry's flag bitset.
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

    /// Returns `true` when the installer carries any kind of
    /// encryption - modern (6.4+ XChaCha20) or legacy (pre-6.4
    /// ARC4-via-`shPassword` flag).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        match self.encryption.as_ref().map(|e| e.mode) {
            Some(EncryptionMode::Files | EncryptionMode::Full) => true,
            _ => self
                .header
                .as_ref()
                .is_some_and(|h| h.has_option(crate::HeaderOption::Password)),
        }
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
        FileReader::new(chunk_bytes, data, &self.version)
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

    /// Reconstructs the embedded uninstaller (`unins000.exe`) by
    /// duplicating the input bytes and patching the
    /// `SetupExeMode` slot to the uninstaller magic.
    ///
    /// Inno's uninstaller stub isn't a separately-packaged file in
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
    /// # Errors
    ///
    /// - [`Error::NoLocation`] when the installer ships no
    ///   uninstaller stub (`Uninstallable=no` builds; older
    ///   installers without an `ftUninstExe` `[Files]` entry).
    /// - [`Error::Truncated`] when the input is too short to
    ///   contain the mode marker at offset `0x30`.
    pub fn extract_uninstaller(&self) -> Result<Vec<u8>, Error> {
        if !self
            .files()
            .iter()
            .any(|f| f.file_type == Some(FileEntryType::UninstExe))
        {
            return Err(Error::NoLocation);
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
    fn encryption_context(&self) -> Option<crate::extract::chunk::EncryptionContext<'_>> {
        // Modern (6.4+) - derived 32-byte key + base nonce.
        if let (Some(key), Some(info)) = (self.encryption_key.as_ref(), self.encryption.as_ref()) {
            return Some(crate::extract::chunk::EncryptionContext::Modern {
                key,
                base_nonce: &info.base_nonce,
                mode: info.mode,
            });
        }
        // Legacy (pre-6.4) - keep the password verbatim (per-chunk
        // RC4 keys are derived from password + each chunk's salt).
        // 5.3.9..6.4 uses SHA-1 keying; pre-5.3.9 uses MD5.
        if let Some(password) = self.legacy_password.as_deref() {
            return Some(crate::extract::chunk::EncryptionContext::Legacy {
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
        let compression = self
            .header
            .as_ref()
            .and_then(|h| h.tail().compress_method)
            .ok_or(Error::Truncated {
                what: "header compression method",
            })?;
        let slice = SliceReader::embedded(self.input, self.offset_table.offset_setup1)?;
        let bytes = decompress_chunk(
            &slice,
            data,
            compression,
            self.encryption_context().as_ref(),
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
/// The verifier check follows the canonical Pascal `TestPassword`
/// algorithm (`research-notes/08-issrc-encryption.md` §C):
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
    let derive: fn(&str, &[u8; 16], u32) -> [u8; 32] =
        if (version.a, version.b, version.c, version.d) == (7, 0, 0, 1) {
            crate::crypto::pbkdf2::derive_key_buggy_700_preview3
        } else {
            crate::crypto::pbkdf2::derive_key
        };
    for &password in passwords {
        let key = derive(password, &info.salt, info.kdf_iterations);
        let actual = crate::crypto::xchacha20::password_test_verifier(&key, &info.base_nonce);
        if actual == info.password_test {
            return Ok((Some(key), Some(password.to_owned())));
        }
    }
    Err(Error::WrongPassword)
}

/// `euFull` (6.5+) decryption + decompression of the two setup-0
/// block streams.
///
/// Wire format per `research-notes/08-issrc-encryption.md` and
/// the Pascal `TCompressedBlockWriter.FlushOutputBuffer`
/// implementation:
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
    let block1 = decompress_block_with_decryption(setup0, block_start, version, key, &nonce1)?;
    let comp = Compression::from_block(block1.compression);

    let block2_start = block_start
        .checked_add(block1.consumed)
        .ok_or(Error::Overflow {
            what: "second block start",
        })?;
    let nonce2 = special_nonce(base_nonce, SpecialContext::CompressedBlocks2);
    let block2 = decompress_block_with_decryption(setup0, block2_start, version, key, &nonce2)?;

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

/// `(chunk_cache, file_loc_to_chunk)` - return type of
/// [`build_chunk_index`]. Aliased here for clippy.
type ChunkIndex = (Box<[OnceLock<Arc<[u8]>>]>, Box<[u32]>);

/// Group `file_locations` by their `(first_slice, start_offset)`
/// chunk key, returning:
///   - `chunk_cache`: one empty `OnceLock` slot per unique chunk.
///   - `file_loc_to_chunk`: parallel array mapping each file-loc
///     index to its chunk slot index.
fn build_chunk_index(file_locations: &[DataEntry]) -> ChunkIndex {
    // (first_slice, start_offset) → chunk slot index.
    let mut keys: HashMap<(u32, u32), u32> = HashMap::new();
    let mut next_id: u32 = 0;
    let mut mapping: Vec<u32> = Vec::with_capacity(file_locations.len());

    for d in file_locations {
        let key = (d.first_slice, d.start_offset);
        let id = *keys.entry(key).or_insert_with(|| {
            let id = next_id;
            next_id = next_id.saturating_add(1);
            id
        });
        mapping.push(id);
    }

    let cache_len = next_id as usize;
    let mut cache: Vec<OnceLock<Arc<[u8]>>> = Vec::with_capacity(cache_len);
    for _ in 0..cache_len {
        cache.push(OnceLock::new());
    }

    (cache.into_boxed_slice(), mapping.into_boxed_slice())
}

fn parse_records(
    setup0: &[u8],
    data_block: &[u8],
    header: &SetupHeader,
    version: &Version,
) -> Result<ParsedRecords, Error> {
    let mut reader = Reader::at(setup0, header.records_offset())?;
    let counts = header.counts();

    let languages = read_n(&mut reader, counts.languages, version, LanguageEntry::read)?;
    let messages = read_n(
        &mut reader,
        counts.custom_messages,
        version,
        MessageEntry::read,
    )?;
    let permissions = read_n(
        &mut reader,
        counts.permissions,
        version,
        PermissionEntry::read,
    )?;
    let types = read_n(&mut reader, counts.types, version, TypeEntry::read)?;
    let components = read_n(
        &mut reader,
        counts.components,
        version,
        ComponentEntry::read,
    )?;
    let tasks = read_n(&mut reader, counts.tasks, version, TaskEntry::read)?;
    let directories = read_n(
        &mut reader,
        counts.directories,
        version,
        DirectoryEntry::read,
    )?;
    // 6.5+ ISSigKeys: 3 String fields per entry (PublicX, PublicY,
    // RuntimeID). See `records::isssigkey`.
    let iss_sig_keys = if let Some(n) = counts.iss_sig_keys {
        read_n(&mut reader, n, version, ISSigKeyEntry::read)?
    } else {
        Vec::new()
    };
    let files = read_n(&mut reader, counts.files, version, FileEntry::read)?;
    let icons = read_n(&mut reader, counts.icons, version, IconEntry::read)?;
    let ini_entries = read_n(&mut reader, counts.ini_entries, version, IniEntry::read)?;
    let registry = read_n(&mut reader, counts.registry, version, RegistryEntry::read)?;
    let install_deletes = read_n(
        &mut reader,
        counts.install_deletes,
        version,
        DeleteEntry::read,
    )?;
    let uninstall_deletes = read_n(
        &mut reader,
        counts.uninstall_deletes,
        version,
        DeleteEntry::read,
    )?;
    let run = read_n(&mut reader, counts.run, version, RunEntry::read)?;
    let uninstall_run = read_n(&mut reader, counts.uninstall_run, version, RunEntry::read)?;

    // Block 2: file-location records. Even when count is 0 the
    // block is well-formed; we just don't read anything from it.
    let mut data_reader = Reader::new(data_block);
    let file_locations = read_n(
        &mut data_reader,
        counts.file_locations,
        version,
        DataEntry::read,
    )?;

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
    })
}

fn read_n<T, F>(
    reader: &mut Reader<'_>,
    count: u32,
    version: &Version,
    mut read_one: F,
) -> Result<Vec<T>, Error>
where
    F: FnMut(&mut Reader<'_>, &Version) -> Result<T, Error>,
{
    let cap = usize::try_from(count).map_err(|_| Error::Overflow {
        what: "record count",
    })?;
    let mut out = Vec::with_capacity(cap);
    for _ in 0..cap {
        out.push(read_one(reader, version)?);
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
