//! `TSetupFileEntry`: one file Setup installs, from a `[Files]` entry, or
//! the uninstaller itself ([`FileEntryType::UninstExe`]). A wildcard or
//! `recursesubdirs` entry is expanded by the compiler, so each matched file
//! has an entry of its own. The bytes live elsewhere: [`FileEntry::location_index`]
//! names the [`crate::records::dataentry::DataEntry`] that says where in
//! setup-1 they are, and [`crate::InnoInstaller::extract`] reads them.
//!
//! On disk (`SECompressedBlockWrite`): the string fields in the order below,
//! each a u32 byte length and its data (UTF-16LE in Unicode builds); from
//! 6.5.0 the `Verification` record (an `AnsiString`, a SHA-256 and a type
//! byte); the Windows version range; then `LocationEntry`, `Attribs`,
//! `ExternalSize`, before 3.0.5 a `CopyMode` byte, from 4.1.0
//! `PermissionsEntry`, from SetupID 7.0.0.3 `Bitness`, the `Options` set
//! and `FileType`. Reader reference: innoextract `setup/file.cpp`; every
//! layout is checked against upstream's own declarations by the
//! `crate::upstream` tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{
        item::{ItemBase, ItemConditions},
        windows::{Bitness, WindowsVersionRange},
    },
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `FileType`: what an entry installs (`TSetupFileEntry.FileType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileEntryType {
    /// `ftUserFile`: a file from a `[Files]` entry.
    UserFile,
    /// `ftUninstExe`: the uninstaller, `unins000.exe`, which the compiler
    /// adds itself. Its bytes are Setup's own executable, rebuilt by
    /// [`crate::InnoInstaller::extract_uninstaller`]; it has no data entry.
    UninstExe,
    /// `ftRegSvrExe`: the helper that registers DLLs after a restart (32-bit
    /// builds before 5.0.0).
    RegSvrExe,
}

stable_name_enum!(FileEntryType, {
    Self::UserFile => "user_file",
    Self::UninstExe => "uninst_exe",
    Self::RegSvrExe => "reg_svr_exe",
});

/// `TSetupFileEntry.Options`: the entry's `Flags:` that reach Setup. Flags
/// only the compiler acts on (`nocompression`, `solidbreak`, `sign`, the
/// sort flags, ...) are not stored here; `touch`, `noencryption` and the
/// signing state are on the file's
/// [`crate::records::dataentry::DataEntry`] instead.
///
/// Each variant names its Pascal member and the script flag that sets it.
/// The version is when the bit appeared.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileFlag {
    /// `foConfirmOverwrite` (`confirmoverwrite`): ask before replacing an
    /// existing file.
    ConfirmOverwrite,
    /// `foUninsNeverUninstall` (`uninsneveruninstall`): never remove the
    /// file at uninstall.
    NeverUninstall,
    /// `foRestartReplace` (`restartreplace`): a file in use is replaced at
    /// the next restart (`MoveFileEx`) instead of failing.
    RestartReplace,
    /// `foDeleteAfterInstall` (`deleteafterinstall`): install the file, then
    /// delete it when Setup finishes, for temporary helpers.
    DeleteAfterInstall,
    /// `foRegisterServer` (`regserver`): call `DllRegisterServer` after
    /// installing, `DllUnregisterServer` at uninstall.
    RegisterServer,
    /// `foRegisterTypeLib` (`regtypelib`): register the type library.
    RegisterTypeLib,
    /// `foSharedFile` (`sharedfile`): reference-counted under `SharedDLLs`;
    /// removed only when no application uses it.
    SharedFile,
    /// `foIsReadmeFile` (`isreadme`): offer to open the file on the Setup
    /// Completed page (before 2.0.0; later releases make `isreadme` a
    /// `[Run]` entry).
    IsReadmeFile,
    /// `foCompareTimeStamp` (`comparetimestamp`; `foCompareTimeStampAlso`
    /// before 3.0.5): replace an existing file by comparing time stamps
    /// when version information does not decide.
    CompareTimeStamp,
    /// `foFontIsntTrueType` (`fontisnttruetype`): the `FontInstall` font is
    /// not TrueType.
    FontIsNotTrueType,
    /// `foSkipIfSourceDoesntExist` (`skipifsourcedoesntexist`): with
    /// `external`, silently skip a missing source (1.2.5+).
    SkipIfSourceDoesntExist,
    /// `foOverwriteReadOnly` (`overwritereadonly`): replace a read-only file
    /// without asking (1.2.6+).
    OverwriteReadOnly,
    /// `foOverwriteSameVersion`: replace an existing file of the same version
    /// without comparing contents (1.3.21+). The compiler sets it on the
    /// uninstaller's own entry, which Setup modifies after extracting.
    OverwriteSameVersion,
    /// `foCustomDestName`: the entry gave `DestName:`, so
    /// [`FileEntry::destination`] ends in that name rather than the source
    /// file's (1.3.21+).
    CustomDestName,
    /// `foOnlyIfDestFileExists` (`onlyifdestfileexists`): install only over
    /// an existing file of the same name, for patches (1.3.25+).
    OnlyIfDestFileExists,
    /// `foNoRegError` (`noregerror`): no error message when `regserver` /
    /// `regtypelib` fails (2.0.5+).
    NoRegError,
    /// `foUninsRestartDelete` (`uninsrestartdelete`): a file in use at
    /// uninstall is deleted at the next restart (3.0.1+).
    UninsRestartDelete,
    /// `foOnlyIfDoesntExist` (`onlyifdoesntexist`): install only if no such
    /// file exists (3.0.5+; before, the `CopyMode` byte, which this crate
    /// maps to the same flag).
    OnlyIfDoesntExist,
    /// `foIgnoreVersion` (`ignoreversion`): replace an existing file whatever
    /// its version (3.0.5+, or from `CopyMode` before).
    IgnoreVersion,
    /// `foPromptIfOlder` (`promptifolder`): ask before replacing a newer file
    /// with an older one (3.0.5+, or from `CopyMode` before).
    PromptIfOlder,
    /// `foDontCopy` (`dontcopy`): compile the file in but do not install it;
    /// `[Code]` extracts it with `ExtractTemporaryFile` (4.0.0+).
    DontCopy,
    /// `foUninsRemoveReadOnly` (`uninsremovereadonly`): clear the read-only
    /// attribute before deleting at uninstall (4.0.5+).
    UninsRemoveReadOnly,
    /// `foRecurseSubDirsExternal` (`recursesubdirs` with `external`): Setup,
    /// not the compiler, searches the source's subdirectories (4.1.8+).
    RecurseSubDirsExternal,
    /// `foReplaceSameVersionIfContentsDiffer` (`replacesameversion`): replace
    /// a file of the same version when the contents differ (4.2.1+).
    ReplaceSameVersionIfContentsDiffer,
    /// `foDontVerifyChecksum` (`dontverifychecksum`): skip the checksum after
    /// extraction, for files patched after compiling (4.2.5+).
    DontVerifyChecksum,
    /// `foUninsNoSharedFilePrompt` (`uninsnosharedfileprompt`): remove a
    /// shared file whose count reaches zero without asking (5.0.3+).
    UninsNoSharedFilePrompt,
    /// `foCreateAllSubDirs` (`createallsubdirs`): create the empty
    /// directories `recursesubdirs` finds (SetupID 5.0.4+).
    CreateAllSubDirs,
    /// `fo32Bit` (`32bit`): install to the 32-bit view of the file system
    /// (5.1.2 to SetupID 7.0.0.2; then [`FileEntry::bitness`]).
    Bits32,
    /// `fo64Bit` (`64bit`): install to the 64-bit view (5.1.2 to 7.0.0.2;
    /// then [`FileEntry::bitness`]).
    Bits64,
    /// `foExternalSizePreset`: the entry gives `ExternalSize`, so Setup does
    /// not measure the external file (5.2.0+).
    ExternalSizePreset,
    /// `foSetNTFSCompression` (`setntfscompression`): turn NTFS compression
    /// on for the file (5.2.0+).
    SetNtfsCompression,
    /// `foUnsetNTFSCompression` (`unsetntfscompression`): turn it off
    /// (5.2.0+).
    UnsetNtfsCompression,
    /// `foGacInstall` (`gacinstall`): install into the .NET Global Assembly
    /// Cache (5.2.5+).
    GacInstall,
    /// `foDownload` (`download`): Setup downloads `Source`, a URL, instead of
    /// copying a file (6.5.0+).
    Download,
    /// `foExtractArchive` (`extractarchive`): Setup extracts the archive
    /// into `DestDir` instead of copying it (6.5.0+).
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

/// One `[Files]` entry (`TSetupFileEntry`). A string field the version does
/// not have is empty; paths and names may contain constants such as `{app}`,
/// unexpanded.
#[derive(Clone, Debug)]
pub struct FileEntry {
    /// `Source:` (Pascal `SourceFilename`): for an `external` file the path
    /// Setup copies from at install time, or with [`FileFlag::Download`] the
    /// URL. Empty for a file compiled into the installer.
    pub source: String,
    /// `DestDir:` plus the file name (Pascal `DestName`): where the file is
    /// installed, e.g. `{app}\MyProg.exe`, with literal braces in the name
    /// doubled (`{{`). The name is `DestName:` when given
    /// ([`FileFlag::CustomDestName`]), else the source file's. An `external`
    /// entry without `DestName:` stores only the directory: Setup appends
    /// the name of each file it finds at install time.
    pub destination: String,
    /// `FontInstall:`: the font's registry name when the file is a font to
    /// register; empty otherwise.
    pub install_font_name: String,
    /// `StrongAssemblyName:`: the strong name the uninstaller removes from
    /// the Global Assembly Cache, with [`FileFlag::GacInstall`] (5.2.5+).
    pub strong_assembly_name: String,
    /// `Components:` .. `AfterInstall:` and `MinVersion:` /
    /// `OnlyBelowVersion:`.
    pub item: ItemBase,
    /// `Excludes:`: comma-separated patterns `recursesubdirs` skips for an
    /// `external` source (6.5.0+).
    pub excludes: String,
    /// `DownloadISSigSource:`: URL of the `.issig` signature that verifies a
    /// download (6.5.0+).
    pub download_iss_sig_source: String,
    /// `DownloadUserName:`: basic-authentication user for the download
    /// (6.5.0+).
    pub download_user_name: String,
    /// `DownloadPassword:`: basic-authentication password for the download,
    /// stored in clear even in an encrypted installer (6.5.0+).
    pub download_password: String,
    /// `ExtractArchivePassword:`: password of the archive
    /// [`FileFlag::ExtractArchive`] extracts, stored in clear (6.5.0+).
    pub extract_archive_password: String,
    /// `Verification`: how Setup checks the file before installing it
    /// (6.5.0+; default before).
    pub verification: FileVerification,
    /// `LocationEntry`: index into [`crate::InnoInstaller::file_locations`]
    /// of the data entry holding the bytes; `u32::MAX` (-1) when there is
    /// none (the uninstaller, external and downloaded files). See
    /// [`crate::InnoInstaller::file_location_for`].
    pub location_index: u32,
    /// `Attribs:`: Windows file attributes Setup sets after installing
    /// (`FILE_ATTRIBUTE_READONLY` 0x1, `_HIDDEN` 0x2, `_SYSTEM` 0x4,
    /// `_NOT_CONTENT_INDEXED` 0x2000); 0 for none.
    pub attributes: u32,
    /// `ExternalSize:`: the size in bytes an `external` or downloaded file
    /// counts toward the disk space shown (32-bit before 4.0.0); 0 for a
    /// compiled-in file.
    pub external_size: u64,
    /// `PermissionsEntry`: index into [`crate::InnoInstaller::permissions`]
    /// of the ACL `Permissions:` grants; -1 for none (4.1.0+; -1 before).
    pub permission_index: i16,
    /// `Bitness`: the file-system view the file goes to (SetupID 7.0.0.3+,
    /// replacing [`FileFlag::Bits32`] / [`FileFlag::Bits64`]). `None` before,
    /// or for a value this crate does not know.
    pub bitness: Option<Bitness>,
    /// `Bitness` as stored; 0 when the version has no such byte.
    pub bitness_raw: u8,
    /// `Options`, decoded. Before 3.0.5 the copy behaviour was the
    /// `CopyMode` byte, which adds [`FileFlag::PromptIfOlder`],
    /// [`FileFlag::IgnoreVersion`] or [`FileFlag::OnlyIfDoesntExist`] here;
    /// [`Self::options_raw`] holds only the set as stored.
    pub flags: HashSet<FileFlag>,
    /// `Options` as stored: the set's bytes, whose size grows with the
    /// number of flags the version defines.
    pub options_raw: Vec<u8>,
    /// `FileType`, decoded; `None` for a value this crate does not know.
    pub file_type: Option<FileEntryType>,
    /// `FileType` as stored.
    pub file_type_raw: u8,
}

/// `TSetupFileVerification` (6.5.0+): how Setup checks a file's bytes
/// before installing it, beyond the data entry's checksum. Used for
/// external and downloaded files, whose bytes the compiler never saw.
#[derive(Clone, Debug, Default)]
pub struct FileVerification {
    /// `ISSigAllowedKeys:`: which `[ISSigKeys]` entries may have signed the
    /// file, as stored by the compiler (an `AnsiString`; empty means any).
    pub iss_sig_allowed_keys: Vec<u8>,
    /// `Hash:`: the SHA-256 the file must have with
    /// [`FileVerificationKind::Hash`]; zeros otherwise.
    pub hash: [u8; 32],
    /// `Typ`, decoded; `None` for a value this crate does not know.
    pub kind: Option<FileVerificationKind>,
    /// `Typ` as stored.
    pub kind_raw: u8,
}

/// `TSetupFileVerificationType`: which check [`FileVerification`] makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileVerificationKind {
    /// `fvNone`: no check beyond the checksum.
    None,
    /// `fvHash` (`Hash:` parameter): the file's SHA-256 must be
    /// [`FileVerification::hash`].
    Hash,
    /// `fvISSig` (`issigverify` flag): the file must carry a valid `.issig`
    /// signature by one of the allowed `[ISSigKeys]`.
    IsSig,
}

stable_name_enum!(FileVerificationKind, {
    Self::None => "none",
    Self::Hash => "hash",
    Self::IsSig => "issig",
});

impl FromReader for FileEntry {
    /// Reads one `TSetupFileEntry`. Dispatches on version since the
    /// 6.5.0 release inlined 5 new String fields between the
    /// conditions and the version range, and added a `Verification`
    /// nested record (1 AnsiString + 32-byte hash + 1-byte enum).
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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

        // `Integer`s: -1 for no location is `u32::MAX` here whatever the
        // build's width.
        let location_index = reader
            .native_i32(version, "File.LocationIndex")?
            .cast_unsigned();
        let attributes = reader.native_u32(version, "File.Attributes")?;
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
        let raw = reader.set_bytes(bit_count, version, "File.Options")?;
        let mut flags = crate::util::flags::decode_packed_flags(&raw, &table);
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
    // A 16-bit installer (1.2.x) has no `ftRegSvrExe` either.
    match FileEntryType::from_raw(b)? {
        FileEntryType::RegSvrExe if version.at_least(5, 0, 0) || version.is_16bit() => None,
        kind => Some(kind),
    }
}

fn file_flag_table(version: &Version) -> Vec<FileFlag> {
    let mut t = vec![
        FileFlag::ConfirmOverwrite,
        FileFlag::NeverUninstall,
        FileFlag::RestartReplace,
        FileFlag::DeleteAfterInstall,
    ];
    // COM registration and shared-DLL counts are Win32; a 16-bit installer
    // (1.2.x) has neither.
    if !version.is_16bit() {
        t.extend([
            FileFlag::RegisterServer,
            FileFlag::RegisterTypeLib,
            FileFlag::SharedFile,
        ]);
    }
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
    // 5.0.6 appended `foCreateAllSubDirs` but kept SetupID 5.0.4; the set
    // keeps its size, so 5.0.4 and 5.0.5 simply never set the bit.
    if version.at_least(5, 0, 4) {
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
