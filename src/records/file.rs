//! `TSetupFileEntry` - `[Files]` directive entry.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupFileEntry = packed record
//!     SourceFilename, DestName, InstallFontName,
//!         StrongAssemblyName: AnsiString;     // strong_asm 5.2.5+
//!     [ItemConditions]
//!     [WindowsVersionRange]
//!     LocationEntry: Integer;
//!     Attribs: Cardinal;
//!     ExternalSize: Integer64;                // u32 pre-4.0
//!     CopyMode: TSetupFileCopyMode;          // pre-3.0.5 only
//!     PermissionsEntry: SmallInt;             // since 4.1.0
//!     Options: TSetupFileOptions;             // variable bits
//!     FileType: TSetupFileType;               // u8 enum
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/file.cpp`.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{
        item::{ItemBase, ItemConditions},
        windows::{Bitness, WindowsVersionRange},
    },
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::Reader,
    },
    version::Version,
};

/// `TSetupFileType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileEntryType {
    /// `ftUserFile` - regular file from `[Files]`.
    UserFile,
    /// `ftUninstExe` - the uninstaller binary.
    UninstExe,
    /// `ftRegSvrExe` - the embedded RegSvr (pre-5.0 win32 only).
    RegSvrExe,
}

stable_name_enum!(FileEntryType, {
    Self::UserFile => "user_file",
    Self::UninstExe => "uninst_exe",
    Self::RegSvrExe => "reg_svr_exe",
});

/// `TSetupFileOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum FileFlag {
    ConfirmOverwrite,
    NeverUninstall,
    RestartReplace,
    DeleteAfterInstall,
    RegisterServer,
    RegisterTypeLib,
    SharedFile,
    /// Pre-2.0.0 only.
    IsReadmeFile,
    CompareTimeStamp,
    FontIsNotTrueType,
    SkipIfSourceDoesntExist,
    OverwriteReadOnly,
    OverwriteSameVersion,
    CustomDestName,
    OnlyIfDestFileExists,
    NoRegError,
    UninsRestartDelete,
    OnlyIfDoesntExist,
    IgnoreVersion,
    PromptIfOlder,
    DontCopy,
    UninsRemoveReadOnly,
    RecurseSubDirsExternal,
    ReplaceSameVersionIfContentsDiffer,
    DontVerifyChecksum,
    UninsNoSharedFilePrompt,
    CreateAllSubDirs,
    Bits32,
    Bits64,
    ExternalSizePreset,
    SetNtfsCompression,
    UnsetNtfsCompression,
    GacInstall,
    /// 6.5.0+ - file content fetched at install time.
    Download,
    /// 6.5.0+ - payload is a 7-Zip archive to extract.
    ExtractArchive,
}

stable_flag_enum!(FileFlag, {
    ConfirmOverwrite => "confirm_overwrite",
    NeverUninstall => "never_uninstall",
    RestartReplace => "restart_replace",
    DeleteAfterInstall => "delete_after_install",
    RegisterServer => "register_server",
    RegisterTypeLib => "register_type_lib",
    SharedFile => "shared_file",
    IsReadmeFile => "is_readme_file",
    CompareTimeStamp => "compare_time_stamp",
    FontIsNotTrueType => "font_is_not_true_type",
    SkipIfSourceDoesntExist => "skip_if_source_doesnt_exist",
    OverwriteReadOnly => "overwrite_read_only",
    OverwriteSameVersion => "overwrite_same_version",
    CustomDestName => "custom_dest_name",
    OnlyIfDestFileExists => "only_if_dest_file_exists",
    NoRegError => "no_reg_error",
    UninsRestartDelete => "unins_restart_delete",
    OnlyIfDoesntExist => "only_if_doesnt_exist",
    IgnoreVersion => "ignore_version",
    PromptIfOlder => "prompt_if_older",
    DontCopy => "dont_copy",
    UninsRemoveReadOnly => "unins_remove_read_only",
    RecurseSubDirsExternal => "recurse_subdirs_external",
    ReplaceSameVersionIfContentsDiffer => "replace_same_version_if_contents_differ",
    DontVerifyChecksum => "dont_verify_checksum",
    UninsNoSharedFilePrompt => "unins_no_shared_file_prompt",
    CreateAllSubDirs => "create_all_subdirs",
    Bits32 => "bits32",
    Bits64 => "bits64",
    ExternalSizePreset => "external_size_preset",
    SetNtfsCompression => "set_ntfs_compression",
    UnsetNtfsCompression => "unset_ntfs_compression",
    GacInstall => "gac_install",
    Download => "download",
    ExtractArchive => "extract_archive",
});

/// Parsed `TSetupFileEntry`.
#[derive(Clone, Debug)]
pub struct FileEntry {
    /// `Source:` directive - path on the build machine where the
    /// file came from (with Inno constants like `{tmp}`).
    pub source: String,
    /// `DestName:` directive - installation path.
    pub destination: String,
    /// `FontInstall:` directive - empty unless this is a font.
    pub install_font_name: String,
    /// `StrongAssemblyName:` directive (5.2.5+).
    pub strong_assembly_name: String,
    /// Shared conditions + Windows version range.
    pub item: ItemBase,
    /// `Excludes:` directive (6.5.0+) - empty on older versions.
    pub excludes: String,
    /// `DownloadISSigSource:` directive (6.5.0+).
    pub download_iss_sig_source: String,
    /// `DownloadUserName:` directive (6.5.0+).
    pub download_user_name: String,
    /// `DownloadPassword:` directive (6.5.0+).
    pub download_password: String,
    /// `ExtractArchivePassword:` directive (6.5.0+).
    pub extract_archive_password: String,
    /// `Verification` field (6.5.0+). Empty
    /// [`FileVerification::iss_sig_allowed_keys`] etc. on older versions.
    pub verification: FileVerification,
    /// Index into the file-location list (block-2 `data_entries`).
    pub location_index: u32,
    /// Win32 file attributes mask.
    pub attributes: u32,
    /// `ExternalSize:` (`Source: external` directive). 0 for embedded
    /// files.
    pub external_size: u64,
    /// Index into [`crate::InnoInstaller::permissions`]; `-1` =
    /// no entry. 4.1.0+.
    pub permission_index: i16,
    /// `Bitness` enum (6.7.0+; replaces the `Bits32`/`Bits64` flag
    /// bits). On older versions the field stays `None`.
    pub bitness: Option<Bitness>,
    /// Raw bitness byte (or 0 when absent).
    pub bitness_raw: u8,
    /// Decoded options. May include synthetic
    /// [`FileFlag::PromptIfOlder`] / [`FileFlag::IgnoreVersion`] /
    /// [`FileFlag::OnlyIfDoesntExist`] derived from the pre-3.0.5
    /// `CopyMode` byte; raw bits are still in [`Self::options_raw`].
    pub flags: HashSet<FileFlag>,
    /// Raw `Options` bytes.
    pub options_raw: Vec<u8>,
    /// `FileType:` enum.
    pub file_type: Option<FileEntryType>,
    /// Raw file-type byte.
    pub file_type_raw: u8,
}

/// `TSetupFileVerification` - added at Inno Setup 6.5.0. Holds the
/// signing-key allowlist and the file content hash.
#[derive(Clone, Debug, Default)]
pub struct FileVerification {
    /// `ISSigAllowedKeys` - newline-separated list of allowed
    /// signature keys (raw bytes; 6.5.0+).
    pub iss_sig_allowed_keys: Vec<u8>,
    /// SHA-256 of the file content. All zeros when verification
    /// type is `None`.
    pub hash: [u8; 32],
    /// Verification type byte.
    pub kind: Option<FileVerificationKind>,
    /// Raw verification-type byte.
    pub kind_raw: u8,
}

/// `TSetupFileVerificationType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileVerificationKind {
    /// `fvNone` - no verification.
    None,
    /// `fvHash` - SHA-256 hash check.
    Hash,
    /// `fvISSig` - Inno Setup signature check.
    IsSig,
}

stable_name_enum!(FileVerificationKind, {
    Self::None => "none",
    Self::Hash => "hash",
    Self::IsSig => "issig",
});

impl FileEntry {
    /// Reads one `TSetupFileEntry`. Dispatches on version since the
    /// 6.5.0 release inlined 5 new String fields between the
    /// conditions and the version range, and added a `Verification`
    /// nested record (1 AnsiString + 32-byte hash + 1-byte enum).
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let source = read_setup_string(reader, version, "File.Source")?;
        let destination = read_setup_string(reader, version, "File.Destination")?;
        let install_font_name = read_setup_string(reader, version, "File.FontName")?;
        let strong_assembly_name = if version.at_least(5, 2, 5) {
            read_setup_string(reader, version, "File.StrongAssemblyName")?
        } else {
            String::new()
        };

        // Wire format per `Shared.SetupEntFunc.pas:SECompressedBlockRead`:
        // ALL String fields are read in declaration order, THEN all
        // AnsiString fields, THEN the packed numeric/enum/set tail.
        // For 6.5.0+ the file entry inlines 5 new String fields
        // between the conditions and the Verification block.
        let (
            item_conds,
            excludes,
            download_iss_sig_source,
            download_user_name,
            download_password,
            extract_archive_password,
            verification,
        ) = if version.at_least(6, 5, 0) {
            let conditions = ItemConditions::read(reader, version)?;
            let excludes = read_setup_string(reader, version, "File.Excludes")?;
            let dl_src = read_setup_string(reader, version, "File.DownloadISSigSource")?;
            let dl_user = read_setup_string(reader, version, "File.DownloadUserName")?;
            let dl_pw = read_setup_string(reader, version, "File.DownloadPassword")?;
            let extract_pw = read_setup_string(reader, version, "File.ExtractArchivePassword")?;
            // Verification: 1 AnsiString + 32 hash + 1 enum, in
            // that on-disk order (the AnsiString counts toward
            // `SetupFileEntryAnsiStrings = 1`).
            let iss_keys = read_ansi_bytes(reader, "File.Verification.ISSigAllowedKeys")?;
            let hash = reader.array::<32>("File.Verification.Hash")?;
            let kind_raw = reader.u8("File.Verification.Typ")?;
            let verification = FileVerification {
                iss_sig_allowed_keys: iss_keys,
                hash,
                kind: decode_verification_kind(kind_raw),
                kind_raw,
            };
            (
                conditions,
                excludes,
                dl_src,
                dl_user,
                dl_pw,
                extract_pw,
                verification,
            )
        } else {
            let conditions = ItemConditions::read(reader, version)?;
            (
                conditions,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                FileVerification::default(),
            )
        };

        let winver = WindowsVersionRange::read(reader, version)?;
        let item = ItemBase {
            conditions: item_conds,
            winver,
        };

        let location_index = reader.u32_le("File.LocationIndex")?;
        let attributes = reader.u32_le("File.Attributes")?;
        let external_size = if version.at_least(4, 0, 0) {
            reader.u64_le("File.ExternalSize")?
        } else {
            u64::from(reader.u32_le("File.ExternalSize")?)
        };

        // Synthetic flags from the pre-3.0.5 copy-mode byte.
        let mut synthetic = HashSet::new();
        if !version.at_least(3, 0, 5) {
            let copy_mode = reader.u8("File.CopyMode")?;
            match copy_mode {
                0 => {
                    synthetic.insert(FileFlag::PromptIfOlder);
                }
                1 => {
                    synthetic.insert(FileFlag::OnlyIfDoesntExist);
                    synthetic.insert(FileFlag::PromptIfOlder);
                }
                2 => {
                    synthetic.insert(FileFlag::IgnoreVersion);
                    synthetic.insert(FileFlag::PromptIfOlder);
                }
                _ => {}
            }
        }

        let permission_index = if version.at_least(4, 1, 0) {
            reader
                .array::<2>("File.PermissionIndex")
                .map(i16::from_le_bytes)?
        } else {
            -1
        };

        // Format 7.0.0+ adds a `Bitness` byte BEFORE Options
        // (issrc commit `3553e3b7`, 2026-04-05). Format 6.7.0 still
        // uses the old `fo32Bit`/`fo64Bit` flag bits.
        let (bitness, bitness_raw) = if version.at_least_4(7, 0, 0, 3) {
            // `Bitness: TSetupEntryBitness` was added at SetupBinVersion
            // 7.0.0.3 (issrc commit `3553e3b7`, "Replace xx32Bit/xx64Bit
            // Options with new Bitness fields"). 7.0.0.0..7.0.0.2 still
            // use the legacy fo32Bit / fo64Bit flag bits.
            let raw = reader.u8("File.Bitness")?;
            (Bitness::from_raw(raw), raw)
        } else {
            (None, 0)
        };

        let table = file_flag_table(version);
        let bit_count = file_flag_bit_count(version, table.len());
        let raw = reader.set_bytes(bit_count, true, "File.Options")?;
        let mut flags = super::decode_packed_flags(&raw, &table);
        flags.extend(synthetic);

        let file_type_raw = reader.u8("File.FileType")?;
        let file_type = decode_file_type(file_type_raw, version);

        Ok(Self {
            source,
            destination,
            install_font_name,
            strong_assembly_name,
            item,
            excludes,
            download_iss_sig_source,
            download_user_name,
            download_password,
            extract_archive_password,
            verification,
            location_index,
            attributes,
            external_size,
            permission_index,
            bitness,
            bitness_raw,
            flags,
            options_raw: raw,
            file_type,
            file_type_raw,
        })
    }
}

fn decode_verification_kind(b: u8) -> Option<FileVerificationKind> {
    match b {
        0 => Some(FileVerificationKind::None),
        1 => Some(FileVerificationKind::Hash),
        2 => Some(FileVerificationKind::IsSig),
        _ => None,
    }
}

impl FileEntryType {
    /// Resolves the persisted on-disk discriminant byte back to a
    /// [`FileEntryType`], or [`None`] for an unknown value.
    ///
    /// Maps the full byte range regardless of format version, unlike the
    /// version-gated decode applied at parse time: byte `2` (`RegSvrExe`) only
    /// appears in pre-5.0.0 installers, but since the stored `file_type_raw`
    /// was already validated against its own version when parsed, re-deriving
    /// the label here needs no format version.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::UserFile),
            1 => Some(Self::UninstExe),
            2 => Some(Self::RegSvrExe),
            _ => None,
        }
    }
}

fn decode_file_type(b: u8, version: &Version) -> Option<FileEntryType> {
    // Byte→variant mapping lives in `FileEntryType::from_raw`; this only
    // applies the version gate: `RegSvrExe` (byte 2) was dropped in 5.0.0.
    match FileEntryType::from_raw(b)? {
        FileEntryType::RegSvrExe if version.at_least(5, 0, 0) => None,
        kind => Some(kind),
    }
}

fn file_flag_table(version: &Version) -> Vec<FileFlag> {
    let mut t = vec![
        FileFlag::ConfirmOverwrite,
        FileFlag::NeverUninstall,
        FileFlag::RestartReplace,
        FileFlag::DeleteAfterInstall,
        FileFlag::RegisterServer,
        FileFlag::RegisterTypeLib,
        FileFlag::SharedFile,
    ];
    if !version.at_least(2, 0, 0) && !version.is_isx() {
        t.push(FileFlag::IsReadmeFile);
    }
    t.push(FileFlag::CompareTimeStamp);
    t.push(FileFlag::FontIsNotTrueType);
    if version.at_least(1, 2, 5) {
        t.push(FileFlag::SkipIfSourceDoesntExist);
    }
    if version.at_least(1, 2, 6) {
        t.push(FileFlag::OverwriteReadOnly);
    }
    if version.at_least(1, 3, 21) {
        t.push(FileFlag::OverwriteSameVersion);
        t.push(FileFlag::CustomDestName);
    }
    if version.at_least(1, 3, 25) {
        t.push(FileFlag::OnlyIfDestFileExists);
    }
    if version.at_least(2, 0, 5) {
        t.push(FileFlag::NoRegError);
    }
    if version.at_least(3, 0, 1) {
        t.push(FileFlag::UninsRestartDelete);
    }
    if version.at_least(3, 0, 5) {
        t.push(FileFlag::OnlyIfDoesntExist);
        t.push(FileFlag::IgnoreVersion);
        t.push(FileFlag::PromptIfOlder);
    }
    if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least_4(3, 0, 6, 1)) {
        t.push(FileFlag::DontCopy);
    }
    if version.at_least(4, 0, 5) {
        t.push(FileFlag::UninsRemoveReadOnly);
    }
    if version.at_least(4, 1, 8) {
        t.push(FileFlag::RecurseSubDirsExternal);
    }
    if version.at_least(4, 2, 1) {
        t.push(FileFlag::ReplaceSameVersionIfContentsDiffer);
    }
    if version.at_least(4, 2, 5) {
        t.push(FileFlag::DontVerifyChecksum);
    }
    if version.at_least(5, 0, 3) {
        t.push(FileFlag::UninsNoSharedFilePrompt);
    }
    if version.at_least(5, 1, 0) {
        t.push(FileFlag::CreateAllSubDirs);
    }
    // SetupBinVersion 7.0.0.3 (issrc commit `3553e3b7`) moves the
    // bitness from these flag bits into a separate `Bitness` byte.
    // 7.0.0.0..7.0.0.2 (including the 7.0 preview-3 sample) and
    // earlier still keep `fo32Bit` / `fo64Bit` as flag bits 27/28.
    if version.at_least(5, 1, 2) && !version.at_least_4(7, 0, 0, 3) {
        t.push(FileFlag::Bits32);
        t.push(FileFlag::Bits64);
    }
    if version.at_least(5, 2, 0) {
        t.push(FileFlag::ExternalSizePreset);
        t.push(FileFlag::SetNtfsCompression);
        t.push(FileFlag::UnsetNtfsCompression);
    }
    if version.at_least(5, 2, 5) {
        t.push(FileFlag::GacInstall);
    }
    if version.at_least(6, 5, 0) {
        t.push(FileFlag::Download);
        t.push(FileFlag::ExtractArchive);
    }
    t
}

/// Total bit-width of `TSetupFileEntryOption` for the given version.
/// Format 6.7.0+ pads the enum to 57 bits via `foUnusedPadding = 56`
/// so the set is exactly 8 bytes; older versions report the
/// named-flag count (no padding).
fn file_flag_bit_count(version: &Version, named: usize) -> usize {
    if version.at_least(6, 7, 0) { 57 } else { named }
}
