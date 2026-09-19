//! Parsed view of the `TSetupHeader` record.
//!
//! Wire format reference: `Shared.SetupEntFunc.pas:97-118`. The
//! `TSetupHeader` record is laid out on disk as:
//!
//! ```text
//! [ String_1_len  | String_1_bytes ]    × NumStrings  (UTF-16LE on Unicode builds)
//! [ AnsiStr_1_len | AnsiStr_1_bytes ]   × NumAnsiStrings  (raw bytes)
//! [ counters: u32 × N ]
//! [ fixed numeric / enum / set tail ]
//! ```
//!
//! The set of String fields, the set of AnsiString fields, the count
//! list, and the shape of the fixed numeric tail all evolve with
//! version. The fixed-tail layout per version is documented
//! byte-by-byte in `research-notes/11-fixed-tail.md`; the parser in
//! this module follows that document and matches innoextract's
//! `header::load` (`research/src/setup/header.cpp:340-547`).
//!
//! See `RESEARCH.md` §6, `research-notes/03-setup-header.md`, and
//! `research-notes/10-version-evolution.md` §B for the cross-version
//! reference.

use std::collections::{HashMap, HashSet};

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::Reader,
    },
    version::Version,
};

/// Identifier for a single `TSetupHeader` `String` field.
///
/// Fields are listed in **declaration order** as they appear in the
/// canonical `Shared.Struct.pas`, but not every variant is present in
/// every Inno Setup version. The per-version layout helper
/// `header_string_fields` returns only the variants that exist in
/// a given version.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderString {
    /// `AppName` directive.
    AppName,
    /// `AppVerName` directive.
    AppVerName,
    /// `AppId` directive.
    AppId,
    /// `AppCopyright` directive.
    AppCopyright,
    /// `AppPublisher` directive.
    AppPublisher,
    /// `AppPublisherURL` directive.
    AppPublisherUrl,
    /// `AppSupportPhone` directive.
    AppSupportPhone,
    /// `AppSupportURL` directive.
    AppSupportUrl,
    /// `AppUpdatesURL` directive.
    AppUpdatesUrl,
    /// `AppVersion` directive.
    AppVersion,
    /// `DefaultDirName` directive.
    DefaultDirName,
    /// `DefaultGroupName` directive.
    DefaultGroupName,
    /// `BaseFilename` directive (= the produced setup .exe filename).
    BaseFilename,
    /// `UninstallFilesDir` directive.
    UninstallFilesDir,
    /// `UninstallDisplayName` directive.
    UninstallDisplayName,
    /// `UninstallDisplayIcon` directive.
    UninstallDisplayIcon,
    /// `AppMutex` directive.
    AppMutex,
    /// `DefaultUserInfoName` directive.
    DefaultUserInfoName,
    /// `DefaultUserInfoOrg` directive.
    DefaultUserInfoOrg,
    /// `DefaultUserInfoSerial` directive.
    DefaultUserInfoSerial,
    /// `AppReadmeFile` directive.
    AppReadmeFile,
    /// `AppContact` directive.
    AppContact,
    /// `AppComments` directive.
    AppComments,
    /// `AppModifyPath` directive.
    AppModifyPath,
    /// `CreateUninstallRegKey` directive.
    CreateUninstallRegKey,
    /// `Uninstallable` directive.
    Uninstallable,
    /// `CloseApplicationsFilter` directive.
    CloseApplicationsFilter,
    /// `SetupMutex` directive.
    SetupMutex,
    /// `ChangesEnvironment` directive.
    ChangesEnvironment,
    /// `ChangesAssociations` directive.
    ChangesAssociations,
    /// `ArchitecturesAllowed` (added at 6.4 as a `String` - earlier
    /// versions stored this as a packed enum-set in the fixed
    /// portion).
    ArchitecturesAllowed,
    /// `ArchitecturesInstallIn64BitMode` (added at 6.4 as a
    /// `String`; earlier as a packed enum-set).
    ArchitecturesInstallIn64BitMode,
    /// `CloseApplicationsFilterExcludes` (added at 6.4.3, commit
    /// `72756e57`).
    CloseApplicationsFilterExcludes,
    /// `SevenZipLibraryName` (7-Zip integration; added in the 6.5
    /// series).
    SevenZipLibraryName,
    /// `UsePreviousAppDir` directive (string-typed since 6.5+).
    UsePreviousAppDir,
    /// `UsePreviousGroup` directive (string-typed since 6.5+).
    UsePreviousGroup,
    /// `UsePreviousSetupType` directive (string-typed since 6.5+).
    UsePreviousSetupType,
    /// `UsePreviousTasks` directive (string-typed since 6.5+).
    UsePreviousTasks,
    /// `UsePreviousUserInfo` directive (string-typed since 6.5+).
    UsePreviousUserInfo,
}

/// Identifier for a `TSetupHeader` `AnsiString` field.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderAnsi {
    /// License text shown on the wizard's license page (raw bytes;
    /// caller decodes per the relevant language codepage).
    LicenseText,
    /// Info text shown before installation.
    InfoBeforeText,
    /// Info text shown after installation.
    InfoAfterText,
    /// Compiled PascalScript bytecode blob - opaque from this
    /// crate's perspective; the IFPS container is not parsed.
    CompiledCodeText,
}

/// Counts of follow-on records, read after the string section.
///
/// Each counter says how many records of that type live further
/// into the decompressed setup-0 buffer; the typed-record iterators
/// use these to bound their reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct EntryCounts {
    /// `NumLanguageEntries`.
    pub languages: u32,
    /// `NumCustomMessageEntries`.
    pub custom_messages: u32,
    /// `NumPermissionEntries`.
    pub permissions: u32,
    /// `NumTypeEntries`.
    pub types: u32,
    /// `NumComponentEntries`.
    pub components: u32,
    /// `NumTaskEntries`.
    pub tasks: u32,
    /// `NumDirEntries`.
    pub directories: u32,
    /// `NumISSigKeyEntries` - only present in Inno Setup 6.5.0+
    /// (commit `ac2b262d`, ships in tag `is-6_5_0`).
    pub iss_sig_keys: Option<u32>,
    /// `NumFileEntries`.
    pub files: u32,
    /// `NumFileLocationEntries` (file-data pointers into setup-1
    /// chunks).
    pub file_locations: u32,
    /// `NumIconEntries`.
    pub icons: u32,
    /// `NumIniEntries`.
    pub ini_entries: u32,
    /// `NumRegistryEntries`.
    pub registry: u32,
    /// `NumInstallDeleteEntries`.
    pub install_deletes: u32,
    /// `NumUninstallDeleteEntries`.
    pub uninstall_deletes: u32,
    /// `NumRunEntries`.
    pub run: u32,
    /// `NumUninstallRunEntries`.
    pub uninstall_run: u32,
}

/// `TSetupHeaderOption` - declared options bit. The numeric value of
/// each variant has no on-wire meaning; bit positions are
/// version-dependent and resolved by [`SetupHeader::options`].
///
/// The variant set is the union of all known versions' enums.
/// `Shared.Struct.pas` is authoritative; see
/// `research-notes/11-fixed-tail.md` §"`TSetupHeaderOption` enum"
/// for the per-version bit-position tables.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)] // Each variant is a directive name; the names self-document.
pub enum HeaderOption {
    DisableStartupPrompt,
    CreateAppDir,
    AllowNoIcons,
    AlwaysRestart,
    AlwaysUsePersonalGroup,
    WindowVisible,
    WindowShowCaption,
    WindowResizable,
    WindowStartMaximized,
    EnableDirDoesntExistWarning,
    Password,
    AllowRootDirectory,
    DisableFinishedPage,
    UsePreviousAppDir,
    BackColorHorizontal,
    UsePreviousGroup,
    UpdateUninstallLogAppName,
    UsePreviousSetupType,
    DisableReadyMemo,
    AlwaysShowComponentsList,
    FlatComponentsList,
    ShowComponentSizes,
    UsePreviousTasks,
    DisableReadyPage,
    AlwaysShowDirOnReadyPage,
    AlwaysShowGroupOnReadyPage,
    AllowUNCPath,
    UserInfoPage,
    UsePreviousUserInfo,
    UninstallRestartComputer,
    RestartIfNeededByRun,
    ShowTasksTreeLines,
    AllowCancelDuringInstall,
    WizardImageStretch,
    AppendDefaultDirName,
    AppendDefaultGroupName,
    EncryptionUsed,
    SetupLogging,
    SignedUninstaller,
    UsePreviousLanguage,
    DisableWelcomePage,
    CloseApplications,
    RestartApplications,
    AllowNetworkDrive,
    ForceCloseApplications,
    AppNameHasConsts,
    UsePreviousPrivileges,
    WizardResizable,
    UninstallLogging,
}

stable_flag_enum!(HeaderOption, {
    DisableStartupPrompt => "disable_startup_prompt",
    CreateAppDir => "create_app_dir",
    AllowNoIcons => "allow_no_icons",
    AlwaysRestart => "always_restart",
    AlwaysUsePersonalGroup => "always_use_personal_group",
    WindowVisible => "window_visible",
    WindowShowCaption => "window_show_caption",
    WindowResizable => "window_resizable",
    WindowStartMaximized => "window_start_maximized",
    EnableDirDoesntExistWarning => "enable_dir_doesnt_exist_warning",
    Password => "password",
    AllowRootDirectory => "allow_root_directory",
    DisableFinishedPage => "disable_finished_page",
    UsePreviousAppDir => "use_previous_app_dir",
    BackColorHorizontal => "back_color_horizontal",
    UsePreviousGroup => "use_previous_group",
    UpdateUninstallLogAppName => "update_uninstall_log_app_name",
    UsePreviousSetupType => "use_previous_setup_type",
    DisableReadyMemo => "disable_ready_memo",
    AlwaysShowComponentsList => "always_show_components_list",
    FlatComponentsList => "flat_components_list",
    ShowComponentSizes => "show_component_sizes",
    UsePreviousTasks => "use_previous_tasks",
    DisableReadyPage => "disable_ready_page",
    AlwaysShowDirOnReadyPage => "always_show_dir_on_ready_page",
    AlwaysShowGroupOnReadyPage => "always_show_group_on_ready_page",
    AllowUNCPath => "allow_unc_path",
    UserInfoPage => "user_info_page",
    UsePreviousUserInfo => "use_previous_user_info",
    UninstallRestartComputer => "uninstall_restart_computer",
    RestartIfNeededByRun => "restart_if_needed_by_run",
    ShowTasksTreeLines => "show_tasks_tree_lines",
    AllowCancelDuringInstall => "allow_cancel_during_install",
    WizardImageStretch => "wizard_image_stretch",
    AppendDefaultDirName => "append_default_dir_name",
    AppendDefaultGroupName => "append_default_group_name",
    EncryptionUsed => "encryption_used",
    SetupLogging => "setup_logging",
    SignedUninstaller => "signed_uninstaller",
    UsePreviousLanguage => "use_previous_language",
    DisableWelcomePage => "disable_welcome_page",
    CloseApplications => "close_applications",
    RestartApplications => "restart_applications",
    AllowNetworkDrive => "allow_network_drive",
    ForceCloseApplications => "force_close_applications",
    AppNameHasConsts => "app_name_has_consts",
    UsePreviousPrivileges => "use_previous_privileges",
    WizardResizable => "wizard_resizable",
    UninstallLogging => "uninstall_logging",
});

/// `TSetupWizardStyle`: visual presentation style of the wizard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WizardStyle {
    /// `wsClassic` - classic Inno Setup wizard look.
    Classic,
    /// `wsModern` - modern Inno Setup wizard look (Inno Setup 6+).
    Modern,
}

stable_name_enum!(WizardStyle, { Self::Classic => "classic", Self::Modern => "modern" });

/// `TSetupImageAlphaFormat`: alpha-channel handling for wizard images.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageAlphaFormat {
    /// `afIgnored` - alpha channel ignored.
    Ignored,
    /// `afDefined` - alpha defined but not premultiplied.
    Defined,
    /// `afPremultiplied` - alpha premultiplied.
    Premultiplied,
}

stable_name_enum!(ImageAlphaFormat, {
    Self::Ignored => "ignored",
    Self::Defined => "defined",
    Self::Premultiplied => "premultiplied",
});

/// `TSetupLogMode` for the uninstall log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UninstallLogMode {
    /// `lmAppend` - append to existing log.
    Append,
    /// `lmNew` - create new log file.
    New,
    /// `lmOverwrite` - overwrite existing log.
    Overwrite,
}

stable_name_enum!(UninstallLogMode, {
    Self::Append => "append",
    Self::New => "new",
    Self::Overwrite => "overwrite",
});

/// `TSetupBoolAutoNoYes` (used for `dir_exists_warning`,
/// `disable_dir_page`, `disable_program_group_page`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AutoNoYes {
    /// `ddAuto`.
    Auto,
    /// `ddNo`.
    No,
    /// `ddYes`.
    Yes,
}

stable_name_enum!(AutoNoYes, { Self::Auto => "auto", Self::No => "no", Self::Yes => "yes" });

/// `TSetupBoolYesNoAuto` (used for `show_language_dialog`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum YesNoAuto {
    /// `slYes`.
    Yes,
    /// `slNo`.
    No,
    /// `slAuto`.
    Auto,
}

stable_name_enum!(YesNoAuto, { Self::Yes => "yes", Self::No => "no", Self::Auto => "auto" });

/// `TSetupPrivilegesRequired` - privilege level required to install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegesRequired {
    /// `prNone` - no special privileges.
    None,
    /// `prPowerUser` - power-user (legacy).
    PowerUser,
    /// `prAdmin` - administrator privileges.
    Admin,
    /// `prLowest` - lowest available privileges (5.7.0+).
    Lowest,
}

stable_name_enum!(PrivilegesRequired, {
    Self::None => "none",
    Self::PowerUser => "power_user",
    Self::Admin => "admin",
    Self::Lowest => "lowest",
});

/// `TSetupLanguageDetectionMethod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LanguageDetectionMethod {
    /// `ldUILanguage`.
    UiLanguage,
    /// `ldLocale`.
    Locale,
    /// `ldNone`.
    None,
}

stable_name_enum!(LanguageDetectionMethod, {
    Self::UiLanguage => "ui_language",
    Self::Locale => "locale",
    Self::None => "none",
});

/// `TSetupCompressMethod` - compression method for `setup-1` chunks
/// (note: distinct from the `setup-0` block compression discovered at
/// runtime via [`crate::Compression`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressMethod {
    /// `cmStored`.
    Stored,
    /// `cmZlib`.
    Zlib,
    /// `cmBzip`.
    Bzip2,
    /// `cmLzma`.
    Lzma1,
    /// `cmLzma2` (5.3.9+).
    Lzma2,
}

stable_name_enum!(CompressMethod, {
    Self::Stored => "stored",
    Self::Zlib => "zlib",
    Self::Bzip2 => "bzip2",
    Self::Lzma1 => "lzma1",
    Self::Lzma2 => "lzma2",
});

/// Processor architectures Inno Setup recognizes on the wire.
///
/// Used in two distinct forms depending on installer version:
///
/// - 5.1.0..6.3 store `ArchitecturesAllowed` /
///   `ArchitecturesInstallIn64BitMode` as packed `TSetupArchitecture`
///   flag bits in the [`HeaderTail`].
/// - 6.3+ store them as a boolean-expression `String`
///   ([`HeaderString::ArchitecturesAllowed`] / `…InstallIn64BitMode`)
///   over atoms like `x86compatible`, `x64compatible`, `arm64`.
///
/// `Arm32` is reachable only via the 6.4+ string-expression form
/// (`arm32compatible`); the pre-6.4 packed-set wire format had no
/// bit position for it. The [`crate::InnoInstaller::architecture`]
/// accessor unifies both forms - see its docs for the parsing
/// semantics.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Architecture {
    Unknown,
    X86,
    Amd64,
    IA64,
    Arm32,
    Arm64,
}

stable_name_enum!(Architecture, {
    Self::Unknown => "unknown",
    Self::X86 => "x86",
    Self::Amd64 => "amd64",
    Self::IA64 => "ia64",
    Self::Arm32 => "arm32",
    Self::Arm64 => "arm64",
});

/// `TSetupPrivilegesRequiredOverride` flag bits (6.0.0+).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum PrivilegesRequiredOverride {
    Commandline,
    Dialog,
}

/// Parsed fixed numeric / enum / set tail of `TSetupHeader`.
///
/// Field membership and on-disk encoding both vary with version;
/// see `research-notes/11-fixed-tail.md` for the byte-exact layout
/// per version family. Fields that don't exist for a given version
/// are `Option::None`.
///
/// Per the user's "expose everything" directive, every value the
/// header carries is surfaced here in some form: typed enum where
/// the on-disk byte falls in the documented range, raw byte
/// otherwise. Bit-set values keep both a typed
/// [`HashSet`]-decoded form and the raw bytes.
#[derive(Clone, Debug, Default)]
pub struct HeaderTail {
    /// `CompiledCodeVersion` - the compiler's `SetupBinVersion`
    /// constant, written into the header at 7.0.0.3 and later (issrc
    /// commit `f9095e91`, 2026-04-15). The low 31 bits are a packed
    /// `(major,minor,patch,build)` quad - same layout as
    /// [`crate::Version::a`]/`b`/`c`/`d` - and bit 31 is set when
    /// the producing compiler ran in 64-bit mode.
    ///
    /// `None` for every release older than 7.0.0.3, including the
    /// 7.0.0-preview-2 (`(7,0,0,1)`) and 7.0.0-preview-3
    /// (`(7,0,0,2)`) builds whose SetupID still reads
    /// `(7.0.0.1)`. Disambiguating those previews from a
    /// fix-bearing 7.x release that keeps the same SetupID
    /// requires reading this field.
    pub compiled_code_version: Option<u32>,

    /// `MinVersion` + `OnlyBelowVersion` (`windows_version_range`).
    pub windows_version_range: WindowsVersionRange,

    // --- pre-6.4 wizard colors ---
    /// `BackColor` - wizard background (pre-6.4 only).
    pub back_color: Option<u32>,
    /// `BackColor2` - wizard background gradient (pre-6.4 only).
    pub back_color2: Option<u32>,

    // --- wizard layout ---
    /// `WizardStyle` - `Classic` or `Modern`. Raw byte preserved as
    /// `wizard_style_raw` for forward-compatibility.
    pub wizard_style: Option<WizardStyle>,
    /// Raw `WizardStyle` byte as read.
    pub wizard_style_raw: u8,
    /// `WizardSizePercentX`.
    pub wizard_size_percent_x: u32,
    /// `WizardSizePercentY`.
    pub wizard_size_percent_y: u32,
    /// `WizardImageAlphaFormat` (5.5.7+).
    pub wizard_image_alpha_format: Option<ImageAlphaFormat>,
    /// Raw alpha-format byte.
    pub wizard_image_alpha_format_raw: u8,

    // --- inline encryption metadata (pre-6.5) ---
    /// `PasswordHash`: SHA1 (20 bytes) for 5.3.9..6.3.x.
    pub legacy_password_sha1: Option<[u8; 20]>,
    /// `PasswordHash`: MD5 (16 bytes) for 4.2.0..5.3.9.
    pub legacy_password_md5: Option<[u8; 16]>,
    /// `PasswordHash`: CRC32 verifier for pre-4.2.0.
    pub legacy_password_crc32: Option<u32>,
    /// `PasswordSalt`: 8 bytes for 4.2.2..6.3.x.
    pub legacy_password_salt: Option<[u8; 8]>,
    /// `PasswordTest` (PBKDF2-SHA256-XChaCha20 verifier; 6.4.x only -
    /// at 6.5.0 this moved into [`crate::EncryptionInfo`]).
    pub password_test: Option<u32>,
    /// `EncryptionKDFSalt` (16 bytes; 6.4.x only).
    pub encryption_kdf_salt: Option<[u8; 16]>,
    /// `EncryptionKDFIterations` (6.4.x only).
    pub encryption_kdf_iterations: Option<u32>,
    /// `EncryptionBaseNonce` (24 bytes; 6.4.x only).
    pub encryption_base_nonce: Option<[u8; 24]>,

    // --- disk / install metadata ---
    /// `ExtraDiskSpaceRequired`.
    pub extra_disk_space_required: i64,
    /// `SlicesPerDisk` (4.0.0+).
    pub slices_per_disk: u32,

    // --- user-visible config ---
    /// `UninstallLogMode`.
    pub uninstall_log_mode: Option<UninstallLogMode>,
    /// Raw uninstall-log-mode byte.
    pub uninstall_log_mode_raw: u8,
    /// `DirExistsWarning`.
    pub dir_exists_warning: Option<AutoNoYes>,
    /// Raw dir-exists-warning byte.
    pub dir_exists_warning_raw: u8,
    /// `PrivilegesRequired` (5.3.7+).
    pub privileges_required: Option<PrivilegesRequired>,
    /// Raw privileges-required byte.
    pub privileges_required_raw: u8,
    /// `PrivilegesRequiredOverridesAllowed` (6.0.0+).
    pub privileges_required_overrides: HashSet<PrivilegesRequiredOverride>,
    /// Raw privileges-overrides bitfield.
    pub privileges_required_overrides_raw: Vec<u8>,
    /// `ShowLanguageDialog` (4.0.10+).
    pub show_language_dialog: Option<YesNoAuto>,
    /// Raw show-language-dialog byte.
    pub show_language_dialog_raw: u8,
    /// `LanguageDetectionMethod` (4.0.10+).
    pub language_detection_method: Option<LanguageDetectionMethod>,
    /// Raw language-detection byte.
    pub language_detection_method_raw: u8,
    /// `CompressMethod` (4.1.5+).
    pub compress_method: Option<CompressMethod>,
    /// Raw compress-method byte.
    pub compress_method_raw: u8,

    // --- pre-6.3 architecture sets ---
    /// `ArchitecturesAllowed` (5.1.0..6.3 packed-set form). At 6.3+
    /// this is replaced by a string expression in the header strings;
    /// at 6.4+ that expression is itself a header `String` field.
    pub architectures_allowed: Option<HashSet<Architecture>>,
    /// Raw `architectures_allowed` byte (5.1.0..6.3 only).
    pub architectures_allowed_raw: Option<u8>,
    /// `ArchitecturesInstallIn64BitMode`. Same versioning as
    /// [`Self::architectures_allowed`].
    pub architectures_install_in_64bit_mode: Option<HashSet<Architecture>>,
    /// Raw `architectures_install_in_64bit_mode` byte.
    pub architectures_install_in_64bit_mode_raw: Option<u8>,

    // --- wizard pages ---
    /// `DisableDirPage` (5.3.3+).
    pub disable_dir_page: Option<AutoNoYes>,
    /// Raw disable-dir-page byte.
    pub disable_dir_page_raw: u8,
    /// `DisableProgramGroupPage` (5.3.3+).
    pub disable_program_group_page: Option<AutoNoYes>,
    /// Raw disable-program-group-page byte.
    pub disable_program_group_page_raw: u8,

    // --- post-install ---
    /// `UninstallDisplaySize` (5.3.6+; widened to u64 at 5.5.0).
    pub uninstall_display_size: u64,

    // --- options bitset ---
    /// Decoded `Options` set with version-mapped bit positions.
    /// Unrecognized bits are dropped silently - the raw bytes remain
    /// available via [`Self::options_raw`].
    pub options: HashSet<HeaderOption>,
    /// Raw `Options` bitfield bytes.
    pub options_raw: Vec<u8>,
}

/// Owned, parsed view of the `TSetupHeader` record.
///
/// Exposes the strings, AnsiStrings, counters, **and** the fixed
/// numeric tail. The `records_offset` accessor points at the first
/// byte after the tail, where the typed-record streams begin.
#[derive(Clone, Debug)]
pub struct SetupHeader {
    strings: HashMap<HeaderString, String>,
    ansi: HashMap<HeaderAnsi, Vec<u8>>,
    counts: EntryCounts,
    tail: HeaderTail,
    /// Byte offset within the decompressed setup-0 buffer where the
    /// records section begins (immediately after the fixed numeric
    /// tail).
    records_offset: usize,
    /// Byte offset within the decompressed setup-0 buffer of the
    /// **start** of the fixed numeric tail (i.e. immediately after
    /// the last counter). Useful for verifying the tail-size
    /// invariants documented in `research-notes/11-fixed-tail.md`.
    tail_start_offset: usize,
}

impl SetupHeader {
    /// Parses the header from the start of the decompressed setup-0
    /// buffer.
    ///
    /// # Errors
    ///
    /// Standard truncation / overflow / encoding errors. See
    /// [`Error`].
    pub fn parse(setup0: &[u8], version: &Version) -> Result<Self, Error> {
        let mut reader = Reader::new(setup0);
        let mut strings: HashMap<HeaderString, String> = HashMap::with_capacity(40);
        let mut ansi: HashMap<HeaderAnsi, Vec<u8>> = HashMap::with_capacity(4);
        read_header_strings_and_ansi(&mut reader, version, &mut strings, &mut ansi)?;

        // ANSI-build LeadBytes set (`set of AnsiChar` = 256 bits = 32
        // bytes). Present for non-Unicode installers from 2.0.6 onward;
        // removed at 6.3.0 when the ANSI build was dropped (innoextract
        // `setup/header.cpp:283-287`; research-notes/10-version-evolution.md
        // §B.2.b "LeadBytes"). Read past - not yet exposed.
        if version.at_least(2, 0, 6) && !version.at_least(6, 3, 0) && !version.is_unicode() {
            reader.skip(32, "LeadBytes")?;
        }

        let counts = read_counts(&mut reader, version)?;
        let tail_start_offset = reader.pos();
        let tail = parse_tail(&mut reader, version)?;
        let records_offset = reader.pos();

        Ok(Self {
            strings,
            ansi,
            counts,
            tail,
            records_offset,
            tail_start_offset,
        })
    }

    /// Returns the value of a header `String` field, if present in
    /// the parsed installer's version.
    pub fn string(&self, field: HeaderString) -> Option<&str> {
        self.strings.get(&field).map(String::as_str)
    }

    /// Returns the raw bytes of a header `AnsiString` field. Always
    /// `Some` for the four fields defined in the modern era.
    pub fn ansi(&self, field: HeaderAnsi) -> Option<&[u8]> {
        self.ansi.get(&field).map(Vec::as_slice)
    }

    /// Convenience: returns the `AppName` directive value, when set.
    #[must_use]
    pub fn app_name(&self) -> Option<&str> {
        self.string(HeaderString::AppName)
    }

    /// Convenience: returns the `AppVersion` directive value.
    #[must_use]
    pub fn app_version(&self) -> Option<&str> {
        self.string(HeaderString::AppVersion)
    }

    /// Convenience: returns the `AppPublisher` directive value.
    #[must_use]
    pub fn app_publisher(&self) -> Option<&str> {
        self.string(HeaderString::AppPublisher)
    }

    /// Convenience: returns the `AppId` directive value.
    #[must_use]
    pub fn app_id(&self) -> Option<&str> {
        self.string(HeaderString::AppId)
    }

    /// Convenience: returns the `DefaultDirName` directive value.
    #[must_use]
    pub fn default_dir_name(&self) -> Option<&str> {
        self.string(HeaderString::DefaultDirName)
    }

    /// Returns the parsed entry counts.
    #[must_use]
    pub fn counts(&self) -> &EntryCounts {
        &self.counts
    }

    /// Returns the parsed fixed numeric / enum / set tail.
    #[must_use]
    pub fn tail(&self) -> &HeaderTail {
        &self.tail
    }

    /// Returns the byte offset within the decompressed setup-0
    /// buffer where downstream record iteration should begin
    /// (immediately after the fixed numeric tail).
    #[must_use]
    pub fn records_offset(&self) -> usize {
        self.records_offset
    }

    /// Returns the byte offset of the start of the fixed numeric
    /// tail. `records_offset() - tail_start_offset()` gives the tail
    /// size in bytes, which the validation table in
    /// `research-notes/11-fixed-tail.md` lists per version.
    #[must_use]
    pub fn tail_start_offset(&self) -> usize {
        self.tail_start_offset
    }

    /// Convenience: returns the decoded options set.
    #[must_use]
    pub fn options(&self) -> &HashSet<HeaderOption> {
        &self.tail.options
    }

    /// Returns `true` if the given option bit is set.
    #[must_use]
    pub fn has_option(&self, option: HeaderOption) -> bool {
        self.tail.options.contains(&option)
    }
}

/// Walks the `TSetupHeader` `String` and `AnsiString` fields per
/// `version` and inserts each parsed value into `strings` / `ansi`.
///
/// The on-disk shape evolves field-by-field across the entire 1.x..7.x
/// history. `SECompressedBlockRead` (`Shared.SetupEntFunc.pas`) serializes
/// `TSetupHeader` by walking every `String` field first, then every
/// `AnsiString` field - so the string table is always contiguous and the
/// ansi blobs always trail it. Any `String` field added in a later release
/// therefore reads *before* the ansi tail even when its version gate is
/// higher; see the `CloseApplicationsFilterExcludes` note below. Three
/// structural quirks live inside this walker rather than the post-hoc
/// field-list approach the prior implementation used:
///
/// 1. The four `AnsiString` fields (`LicenseText`, `InfoBefore`,
///    `InfoAfter`, `CompiledCodeText`) **moved** at 5.2.5. Pre-5.2.5
///    they are interleaved with the `String` fields (right after
///    `BaseFilename` for the three info blobs and right after
///    `DefaultUserInfoSerial` for the compiled-code blob); 5.2.5+
///    moved them to the tail, after the whole string table.
/// 2. `UninstallerSignature` is a `String` field that exists only in
///    the narrow 5.2.1..5.3.10 window - read past, not exposed.
/// 3. The `String` fields added at 6.4.3+ (`CloseApplicationsFilterExcludes`,
///    `SevenZipLibraryName`, `UsePrevious*`) come after the architecture
///    expressions but still ahead of the ansi tail. innoextract's reference
///    predates them, so this part is validated against `Shared.Struct.pas`.
///
/// See `research-notes/12-format-evolution-audit.md` for the
/// per-version field-set table and `research/src/setup/header.cpp:146-281`
/// for the upstream reference.
fn read_header_strings_and_ansi(
    reader: &mut Reader<'_>,
    version: &Version,
    strings: &mut HashMap<HeaderString, String>,
    ansi: &mut HashMap<HeaderAnsi, Vec<u8>>,
) -> Result<(), Error> {
    let put_str = |reader: &mut Reader<'_>,
                   field: HeaderString,
                   strings: &mut HashMap<HeaderString, String>|
     -> Result<(), Error> {
        let s = read_setup_string(reader, version, field_label(field))?;
        strings.insert(field, s);
        Ok(())
    };
    let put_ansi = |reader: &mut Reader<'_>,
                    field: HeaderAnsi,
                    ansi: &mut HashMap<HeaderAnsi, Vec<u8>>|
     -> Result<(), Error> {
        let bytes = read_ansi_bytes(reader, ansi_label(field))?;
        ansi.insert(field, bytes);
        Ok(())
    };

    put_str(reader, HeaderString::AppName, strings)?;
    put_str(reader, HeaderString::AppVerName, strings)?;
    if version.at_least(1, 3, 0) {
        put_str(reader, HeaderString::AppId, strings)?;
    }
    put_str(reader, HeaderString::AppCopyright, strings)?;
    if version.at_least(1, 3, 0) {
        put_str(reader, HeaderString::AppPublisher, strings)?;
        put_str(reader, HeaderString::AppPublisherUrl, strings)?;
    }
    if version.at_least(5, 1, 13) {
        put_str(reader, HeaderString::AppSupportPhone, strings)?;
    }
    if version.at_least(1, 3, 0) {
        put_str(reader, HeaderString::AppSupportUrl, strings)?;
        put_str(reader, HeaderString::AppUpdatesUrl, strings)?;
        put_str(reader, HeaderString::AppVersion, strings)?;
    }
    put_str(reader, HeaderString::DefaultDirName, strings)?;
    put_str(reader, HeaderString::DefaultGroupName, strings)?;
    // Pre-3.0.0 had a separate `UninstallIconName: AnsiString`. None
    // of our supported samples land in this range, but read past for
    // completeness.
    if !version.at_least(3, 0, 0) {
        let _ = read_ansi_bytes(reader, "UninstallIconName")?;
    }
    put_str(reader, HeaderString::BaseFilename, strings)?;
    // 1.3.0..5.2.5: license/info blobs interleaved here.
    if version.at_least(1, 3, 0) && !version.at_least(5, 2, 5) {
        put_ansi(reader, HeaderAnsi::LicenseText, ansi)?;
        put_ansi(reader, HeaderAnsi::InfoBeforeText, ansi)?;
        put_ansi(reader, HeaderAnsi::InfoAfterText, ansi)?;
    }
    if version.at_least(1, 3, 3) {
        put_str(reader, HeaderString::UninstallFilesDir, strings)?;
    }
    if version.at_least(1, 3, 6) {
        put_str(reader, HeaderString::UninstallDisplayName, strings)?;
        put_str(reader, HeaderString::UninstallDisplayIcon, strings)?;
    }
    if version.at_least(1, 3, 14) {
        put_str(reader, HeaderString::AppMutex, strings)?;
    }
    if version.at_least(3, 0, 0) {
        put_str(reader, HeaderString::DefaultUserInfoName, strings)?;
        put_str(reader, HeaderString::DefaultUserInfoOrg, strings)?;
    }
    if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least_4(3, 0, 6, 1)) {
        put_str(reader, HeaderString::DefaultUserInfoSerial, strings)?;
    }
    // 4.0.0..5.2.5 (and ISX 1.3.24+): compiled-code blob interleaved.
    if (version.at_least(4, 0, 0) && !version.at_least(5, 2, 5))
        || (version.is_isx() && version.at_least(1, 3, 24))
    {
        put_ansi(reader, HeaderAnsi::CompiledCodeText, ansi)?;
    }
    if version.at_least(4, 2, 4) {
        put_str(reader, HeaderString::AppReadmeFile, strings)?;
        put_str(reader, HeaderString::AppContact, strings)?;
        put_str(reader, HeaderString::AppComments, strings)?;
        put_str(reader, HeaderString::AppModifyPath, strings)?;
    }
    if version.at_least(5, 3, 8) {
        put_str(reader, HeaderString::CreateUninstallRegKey, strings)?;
    }
    if version.at_least(5, 3, 10) {
        put_str(reader, HeaderString::Uninstallable, strings)?;
    }
    if version.at_least(5, 5, 0) {
        put_str(reader, HeaderString::CloseApplicationsFilter, strings)?;
    }
    if version.at_least(5, 5, 6) {
        put_str(reader, HeaderString::SetupMutex, strings)?;
    }
    if version.at_least(5, 6, 1) {
        put_str(reader, HeaderString::ChangesEnvironment, strings)?;
        put_str(reader, HeaderString::ChangesAssociations, strings)?;
    }
    // 6.3.0+ promoted ArchitecturesAllowed / ArchitecturesInstallIn64BitMode
    // from packed enum-sets in the tail to string-expression fields here.
    if version.at_least(6, 3, 0) {
        put_str(reader, HeaderString::ArchitecturesAllowed, strings)?;
        put_str(
            reader,
            HeaderString::ArchitecturesInstallIn64BitMode,
            strings,
        )?;
    }
    // 6.4.3+: CloseApplicationsFilterExcludes (issrc commit `72756e57`).
    if version.at_least(6, 4, 3) {
        put_str(
            reader,
            HeaderString::CloseApplicationsFilterExcludes,
            strings,
        )?;
    }
    // 6.5.0+: SevenZipLibraryName.
    if version.at_least(6, 5, 0) {
        put_str(reader, HeaderString::SevenZipLibraryName, strings)?;
    }
    // 6.7.0+: UsePrevious* directives (formerly Options bits).
    if version.at_least(6, 7, 0) {
        put_str(reader, HeaderString::UsePreviousAppDir, strings)?;
        put_str(reader, HeaderString::UsePreviousGroup, strings)?;
        put_str(reader, HeaderString::UsePreviousSetupType, strings)?;
        put_str(reader, HeaderString::UsePreviousTasks, strings)?;
        put_str(reader, HeaderString::UsePreviousUserInfo, strings)?;
    }
    // 5.2.5+: license/info blobs - the first three `AnsiString` fields,
    // read after the entire string table (see note above).
    if version.at_least(5, 2, 5) {
        put_ansi(reader, HeaderAnsi::LicenseText, ansi)?;
        put_ansi(reader, HeaderAnsi::InfoBeforeText, ansi)?;
        put_ansi(reader, HeaderAnsi::InfoAfterText, ansi)?;
    }
    // 5.2.1..5.3.10: UninstallerSignature String - read past. This narrow
    // legacy window predates the 5.2.5 tail move, so in that era the ansi
    // blobs are interleaved and the signature lands between InfoAfter and
    // CompiledCode; every version in the window is < 6.4.3, so the string
    // fields added above never coexist with it.
    if version.at_least(5, 2, 1) && !version.at_least(5, 3, 10) {
        let _ = read_setup_string(reader, version, "UninstallerSignature")?;
    }
    // 5.2.5+: compiled-code blob - the fourth `AnsiString` field.
    if version.at_least(5, 2, 5) {
        put_ansi(reader, HeaderAnsi::CompiledCodeText, ansi)?;
    }

    Ok(())
}

fn field_label(f: HeaderString) -> &'static str {
    match f {
        HeaderString::AppName => "AppName",
        HeaderString::AppVerName => "AppVerName",
        HeaderString::AppId => "AppId",
        HeaderString::AppCopyright => "AppCopyright",
        HeaderString::AppPublisher => "AppPublisher",
        HeaderString::AppPublisherUrl => "AppPublisherURL",
        HeaderString::AppSupportPhone => "AppSupportPhone",
        HeaderString::AppSupportUrl => "AppSupportURL",
        HeaderString::AppUpdatesUrl => "AppUpdatesURL",
        HeaderString::AppVersion => "AppVersion",
        HeaderString::DefaultDirName => "DefaultDirName",
        HeaderString::DefaultGroupName => "DefaultGroupName",
        HeaderString::BaseFilename => "BaseFilename",
        HeaderString::UninstallFilesDir => "UninstallFilesDir",
        HeaderString::UninstallDisplayName => "UninstallDisplayName",
        HeaderString::UninstallDisplayIcon => "UninstallDisplayIcon",
        HeaderString::AppMutex => "AppMutex",
        HeaderString::DefaultUserInfoName => "DefaultUserInfoName",
        HeaderString::DefaultUserInfoOrg => "DefaultUserInfoOrg",
        HeaderString::DefaultUserInfoSerial => "DefaultUserInfoSerial",
        HeaderString::AppReadmeFile => "AppReadmeFile",
        HeaderString::AppContact => "AppContact",
        HeaderString::AppComments => "AppComments",
        HeaderString::AppModifyPath => "AppModifyPath",
        HeaderString::CreateUninstallRegKey => "CreateUninstallRegKey",
        HeaderString::Uninstallable => "Uninstallable",
        HeaderString::CloseApplicationsFilter => "CloseApplicationsFilter",
        HeaderString::SetupMutex => "SetupMutex",
        HeaderString::ChangesEnvironment => "ChangesEnvironment",
        HeaderString::ChangesAssociations => "ChangesAssociations",
        HeaderString::ArchitecturesAllowed => "ArchitecturesAllowed",
        HeaderString::ArchitecturesInstallIn64BitMode => "ArchitecturesInstallIn64BitMode",
        HeaderString::CloseApplicationsFilterExcludes => "CloseApplicationsFilterExcludes",
        HeaderString::SevenZipLibraryName => "SevenZipLibraryName",
        HeaderString::UsePreviousAppDir => "UsePreviousAppDir",
        HeaderString::UsePreviousGroup => "UsePreviousGroup",
        HeaderString::UsePreviousSetupType => "UsePreviousSetupType",
        HeaderString::UsePreviousTasks => "UsePreviousTasks",
        HeaderString::UsePreviousUserInfo => "UsePreviousUserInfo",
    }
}

fn ansi_label(f: HeaderAnsi) -> &'static str {
    match f {
        HeaderAnsi::LicenseText => "LicenseText",
        HeaderAnsi::InfoBeforeText => "InfoBeforeText",
        HeaderAnsi::InfoAfterText => "InfoAfterText",
        HeaderAnsi::CompiledCodeText => "CompiledCodeText",
    }
}

fn read_counts(reader: &mut Reader<'_>, version: &Version) -> Result<EntryCounts, Error> {
    Ok(EntryCounts {
        languages: reader.u32_le("NumLanguageEntries")?,
        custom_messages: reader.u32_le("NumCustomMessageEntries")?,
        permissions: reader.u32_le("NumPermissionEntries")?,
        types: reader.u32_le("NumTypeEntries")?,
        components: reader.u32_le("NumComponentEntries")?,
        tasks: reader.u32_le("NumTaskEntries")?,
        directories: reader.u32_le("NumDirEntries")?,
        iss_sig_keys: if version.at_least(6, 5, 0) {
            Some(reader.u32_le("NumISSigKeyEntries")?)
        } else {
            None
        },
        files: reader.u32_le("NumFileEntries")?,
        file_locations: reader.u32_le("NumFileLocationEntries")?,
        icons: reader.u32_le("NumIconEntries")?,
        ini_entries: reader.u32_le("NumIniEntries")?,
        registry: reader.u32_le("NumRegistryEntries")?,
        install_deletes: reader.u32_le("NumInstallDeleteEntries")?,
        uninstall_deletes: reader.u32_le("NumUninstallDeleteEntries")?,
        run: reader.u32_le("NumRunEntries")?,
        uninstall_run: reader.u32_le("NumUninstallRunEntries")?,
    })
}

/// Parses the fixed numeric / enum / set tail of `TSetupHeader` per
/// `research-notes/11-fixed-tail.md`. The conditional ladder
/// mirrors innoextract's `header::load`
/// (`research/src/setup/header.cpp:340-547`) and covers every
/// version from the 1.x..7.x history we recognize.
fn parse_tail(reader: &mut Reader<'_>, version: &Version) -> Result<HeaderTail, Error> {
    // Format 7.0.0.3+ inserted `CompiledCodeVersion: Cardinal` between
    // the 18 counts and `MinVersion`. The cutover landed at issrc
    // commit `f9095e91` (2026-04-15) which also bumped SetupID from
    // `(7.0.0.1)` to `(7.0.0.3)`. Earlier 7.0.0.x previews and 6.7.0
    // do NOT have this field.
    let compiled_code_version = if version.at_least_4(7, 0, 0, 3) {
        Some(reader.u32_le("CompiledCodeVersion")?)
    } else {
        None
    };

    let mut tail = HeaderTail {
        compiled_code_version,
        windows_version_range: WindowsVersionRange::read(reader, version)?,
        ..HeaderTail::default()
    };

    // Wizard background colors. Removed at 6.4.0.1.
    if !version.at_least_4(6, 4, 0, 1) {
        tail.back_color = Some(reader.u32_le("BackColor")?);
        if version.at_least(1, 3, 3) {
            tail.back_color2 = Some(reader.u32_le("BackColor2")?);
        }
    }

    // 5.5.7+ removed image_back_color; pre-5.5.7 reads a u32 here.
    if !version.at_least(5, 5, 7) {
        // Parsed only to keep the cursor correct for older installers
        // that ship this field; not yet exposed.
        let _image_back_color = reader.u32_le("ImageBackColor")?;
    }

    // 6.0+ wizard layout (Inno Setup 6 introduced WizardStyle and
    // resize percentages). At 6.6.0 `WizardStyle` was renamed
    // `WizardDarkStyle` (different enum semantics, same byte slot)
    // - kept under `wizard_style_raw` for both eras since the
    // typed `WizardStyle::Classic`/`Modern` mapping no longer
    // applies. Also at 6.6.0 the field is moved to AFTER
    // wizard_size_percent_*; we follow the per-version order
    // strictly.
    if version.at_least(6, 6, 0) {
        // 6.6.0+: WizardSizePercentX/Y come BEFORE WizardDarkStyle.
        tail.wizard_size_percent_x = reader.u32_le("WizardSizePercentX")?;
        tail.wizard_size_percent_y = reader.u32_le("WizardSizePercentY")?;
        let raw = reader.u8("WizardDarkStyle")?;
        tail.wizard_style_raw = raw;
        // The 6.6.0 enum is `wdsAuto / wdsClassic / wdsModern / wdsDark`;
        // we leave `wizard_style` as None (decoder is for the older
        // `wsClassic / wsModern` enum) and surface only the raw byte.
        tail.wizard_style = None;
    } else if version.at_least(6, 0, 0) {
        let raw = reader.u8("WizardStyle")?;
        tail.wizard_style_raw = raw;
        tail.wizard_style = decode_wizard_style(raw);
        tail.wizard_size_percent_x = reader.u32_le("WizardSizePercentX")?;
        tail.wizard_size_percent_y = reader.u32_le("WizardSizePercentY")?;
    }

    // 5.5.7+ alpha format.
    if version.at_least(5, 5, 7) {
        let raw = reader.u8("WizardImageAlphaFormat")?;
        tail.wizard_image_alpha_format_raw = raw;
        tail.wizard_image_alpha_format = ImageAlphaFormat::from_raw(raw);
    }

    // Wizard background colors. Declaration-order layout:
    //   6.5.0+:   ImageBack, SmallImageBack: Integer
    //   6.7.0+:    + BackColor: Integer (interspersed inside the
    //              first triple)
    //   6.6.0+:   + ImageBackDynamicDark, SmallImageBackDynamicDark: Integer
    //   6.7.0+:    + BackColorDynamicDark: Integer (same triple
    //              insertion)
    //   6.6.1+:   + ImageOpacity: Byte
    //   6.7.0+:    + BackImageOpacity: Byte; LightControlStyling: Byte
    // We read past these to keep the cursor aligned; downstream
    // typed accessors land when callers ask for them.
    if version.at_least(6, 5, 0) {
        let _wiz_image_back = reader.u32_le("WizardImageBackColor")?;
        let _wiz_small_image_back = reader.u32_le("WizardSmallImageBackColor")?;
        if version.at_least(6, 7, 0) {
            let _wiz_back_color = reader.u32_le("WizardBackColor")?;
        }
    }
    if version.at_least(6, 6, 0) {
        let _wiz_image_back_dyn = reader.u32_le("WizardImageBackColorDynamicDark")?;
        let _wiz_small_image_back_dyn = reader.u32_le("WizardSmallImageBackColorDynamicDark")?;
        if version.at_least(6, 7, 0) {
            let _wiz_back_color_dyn = reader.u32_le("WizardBackColorDynamicDark")?;
        }
    }
    if version.at_least(6, 6, 1) {
        let _wiz_image_opacity = reader.u8("WizardImageOpacity")?;
        if version.at_least(6, 7, 0) {
            let _wiz_back_image_opacity = reader.u8("WizardBackImageOpacity")?;
            let _wiz_light_control_styling = reader.u8("WizardLightControlStyling")?;
        }
    }

    // Inline encryption metadata. Three layouts:
    //   - 6.4.0..6.5.0: PasswordTest (4) + KDF salt (16) + iter (4) + nonce (24)
    //   - 5.3.9..6.4.0: SHA1 (20) + 8-byte salt
    //   - 4.2.0..5.3.9: MD5 (16) + (4.2.2+) 8-byte salt - not exposed
    //   - <4.2.0:       CRC32 (4) - not exposed
    //   - 6.5.0+:       moved to TSetupEncryptionHeader; nothing here.
    if version.at_least(6, 5, 0) {
        // No inline encryption fields.
    } else if version.at_least(6, 4, 0) {
        tail.password_test = Some(reader.u32_le("PasswordTest")?);
        tail.encryption_kdf_salt = Some(reader.array::<16>("EncryptionKDFSalt")?);
        tail.encryption_kdf_iterations = Some(reader.u32_le("EncryptionKDFIterations")?);
        tail.encryption_base_nonce = Some(reader.array::<24>("EncryptionBaseNonce")?);
    } else if version.at_least(5, 3, 9) {
        tail.legacy_password_sha1 = Some(reader.array::<20>("PasswordHash")?);
        if version.at_least(4, 2, 2) {
            tail.legacy_password_salt = Some(reader.array::<8>("PasswordSalt")?);
        }
    } else if version.at_least(4, 2, 0) {
        tail.legacy_password_md5 = Some(reader.array::<16>("PasswordHashMD5")?);
        if version.at_least(4, 2, 2) {
            tail.legacy_password_salt = Some(reader.array::<8>("PasswordSalt")?);
        }
    } else {
        tail.legacy_password_crc32 = Some(reader.u32_le("PasswordHashCRC32")?);
    }

    // Disk space + slices.
    if version.at_least(4, 0, 0) {
        tail.extra_disk_space_required = reader.i64_le("ExtraDiskSpaceRequired")?;
        tail.slices_per_disk = reader.u32_le("SlicesPerDisk")?;
    } else {
        // pre-4.0.0: i32 ExtraDiskSpaceRequired, no SlicesPerDisk
        // (defaulted to 1 by innoextract).
        let v = reader.i32_le("ExtraDiskSpaceRequired")?;
        tail.extra_disk_space_required = i64::from(v);
        tail.slices_per_disk = 1;
    }

    // Pre-3.0.3 install-mode byte (skipped past).
    if version.at_least(3, 0, 0) && !version.at_least(3, 0, 3) {
        let _install_mode = reader.u8("InstallMode")?;
    }

    // Uninstall log mode (1.3.0+).
    if version.at_least(1, 3, 0) {
        let raw = reader.u8("UninstallLogMode")?;
        tail.uninstall_log_mode_raw = raw;
        tail.uninstall_log_mode = decode_uninstall_log_mode(raw);
    }

    // Pre-5.0 uninstall_style. From 5.0 the value is forced to
    // `Modern` and not on the wire.
    if !version.at_least(5, 0, 0) && version.at_least(2, 0, 0) {
        let _uninstall_style = reader.u8("UninstallStyle")?;
    }

    // 1.3.6+ DirExistsWarning.
    if version.at_least(1, 3, 6) {
        let raw = reader.u8("DirExistsWarning")?;
        tail.dir_exists_warning_raw = raw;
        tail.dir_exists_warning = AutoNoYes::from_raw(raw);
    }

    // 3.0.0..3.0.3 has a u8 (auto-no-yes) for AlwaysRestart vs
    // RestartIfNeededByRun - encoded in Options on later versions.
    if version.at_least(3, 0, 0) && !version.at_least(3, 0, 3) {
        let _val = reader.u8("RestartMode")?;
    }

    // 5.3.7+ PrivilegesRequired (1 byte). 3.0.4..5.3.7 uses an older
    // mapping.
    if version.at_least(5, 3, 7) {
        let raw = reader.u8("PrivilegesRequired")?;
        tail.privileges_required_raw = raw;
        tail.privileges_required = decode_privileges_required_v1(raw);
    } else if version.at_least(3, 0, 4) {
        let raw = reader.u8("PrivilegesRequired")?;
        tail.privileges_required_raw = raw;
        tail.privileges_required = decode_privileges_required_v0(raw);
    }

    // 5.7.0+ PrivilegesRequiredOverridesAllowed (set of 2 bits → 1 byte).
    if version.at_least(5, 7, 0) {
        let raw = reader.set_bytes(2, true, "PrivilegesRequiredOverridesAllowed")?;
        tail.privileges_required_overrides = decode_overrides_set(&raw);
        tail.privileges_required_overrides_raw = raw;
    }

    // 4.0.10+ ShowLanguageDialog + LanguageDetectionMethod.
    if version.at_least(4, 0, 10) {
        let raw = reader.u8("ShowLanguageDialog")?;
        tail.show_language_dialog_raw = raw;
        tail.show_language_dialog = decode_yes_no_auto(raw);
        let raw = reader.u8("LanguageDetectionMethod")?;
        tail.language_detection_method_raw = raw;
        tail.language_detection_method = decode_language_detection(raw);
    }

    // 4.1.5+ CompressMethod.
    if version.at_least(4, 1, 5) {
        let raw = reader.u8("CompressMethod")?;
        tail.compress_method_raw = raw;
        tail.compress_method = decode_compress_method(raw, version);
    }

    // Architectures. 5.1.0..5.6.0 uses 4-arch flags; 5.6.0..6.3.0
    // uses 5-arch flags. From 6.3.0 these are encoded as String
    // expressions in the header strings (already read above).
    if version.at_least(6, 3, 0) {
        // String expressions; nothing on the wire here.
    } else if version.at_least(5, 6, 0) {
        let raw = reader.set_bytes(5, true, "ArchitecturesAllowed")?;
        tail.architectures_allowed_raw = raw.first().copied();
        tail.architectures_allowed = Some(decode_arch_set_v1(&raw));
        let raw = reader.set_bytes(5, true, "ArchitecturesInstallIn64BitMode")?;
        tail.architectures_install_in_64bit_mode_raw = raw.first().copied();
        tail.architectures_install_in_64bit_mode = Some(decode_arch_set_v1(&raw));
    } else if version.at_least(5, 1, 0) {
        let raw = reader.set_bytes(4, true, "ArchitecturesAllowed")?;
        tail.architectures_allowed_raw = raw.first().copied();
        tail.architectures_allowed = Some(decode_arch_set_v0(&raw));
        let raw = reader.set_bytes(4, true, "ArchitecturesInstallIn64BitMode")?;
        tail.architectures_install_in_64bit_mode_raw = raw.first().copied();
        tail.architectures_install_in_64bit_mode = Some(decode_arch_set_v0(&raw));
    }

    // 5.2.1..5.3.10 has signed-uninstaller fields - read past.
    if version.at_least(5, 2, 1) && !version.at_least(5, 3, 10) {
        let _sz = reader.u32_le("SignedUninstallerOriginalSize")?;
        let _crc = reader.u32_le("SignedUninstallerHeaderChecksum")?;
    }

    // 5.3.3+ DisableDirPage / DisableProgramGroupPage.
    if version.at_least(5, 3, 3) {
        let raw = reader.u8("DisableDirPage")?;
        tail.disable_dir_page_raw = raw;
        tail.disable_dir_page = AutoNoYes::from_raw(raw);
        let raw = reader.u8("DisableProgramGroupPage")?;
        tail.disable_program_group_page_raw = raw;
        tail.disable_program_group_page = AutoNoYes::from_raw(raw);
    }

    // 5.3.6+ UninstallDisplaySize (u32 until 5.5.0; u64 from 5.5.0).
    if version.at_least(5, 5, 0) {
        tail.uninstall_display_size = reader.u64_le("UninstallDisplaySize")?;
    } else if version.at_least(5, 3, 6) {
        let v = reader.u32_le("UninstallDisplaySize")?;
        tail.uninstall_display_size = u64::from(v);
    }

    // BlackBox-variant pad byte for three exact format-version values.
    if matches!(
        (version.a, version.b, version.c, version.d),
        (5, 3, 10, 1) | (5, 4, 2, 1) | (5, 5, 0, 1)
    ) {
        let _pad = reader.u8("BlackBoxPad")?;
    }

    // Options bitset (always present).
    let bit_count = options_bit_count(version);
    let raw = reader.set_bytes(bit_count, true, "Options")?;
    tail.options = decode_options(&raw, version);
    tail.options_raw = raw;

    Ok(tail)
}

// --- Enum decoders -----------------------------------------------------------

fn decode_wizard_style(b: u8) -> Option<WizardStyle> {
    match b {
        0 => Some(WizardStyle::Classic),
        1 => Some(WizardStyle::Modern),
        _ => None,
    }
}

impl ImageAlphaFormat {
    /// Resolves the persisted on-disk discriminant byte back to an
    /// [`ImageAlphaFormat`], or [`None`] for an unknown value. Used to
    /// re-derive the label from a stored `wizard_image_alpha_format_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ignored),
            1 => Some(Self::Defined),
            2 => Some(Self::Premultiplied),
            _ => None,
        }
    }
}

fn decode_uninstall_log_mode(b: u8) -> Option<UninstallLogMode> {
    match b {
        0 => Some(UninstallLogMode::Append),
        1 => Some(UninstallLogMode::New),
        2 => Some(UninstallLogMode::Overwrite),
        _ => None,
    }
}

impl AutoNoYes {
    /// Resolves the persisted on-disk discriminant byte back to an
    /// [`AutoNoYes`], or [`None`] for an unknown value. Used to re-derive the
    /// label from a stored `disable_dir_page_raw` /
    /// `disable_program_group_page_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Auto),
            1 => Some(Self::No),
            2 => Some(Self::Yes),
            _ => None,
        }
    }
}

fn decode_yes_no_auto(b: u8) -> Option<YesNoAuto> {
    match b {
        0 => Some(YesNoAuto::Yes),
        1 => Some(YesNoAuto::No),
        2 => Some(YesNoAuto::Auto),
        _ => None,
    }
}

/// 5.3.7+ privileges-required mapping (innoextract `stored_privileges_1`).
fn decode_privileges_required_v1(b: u8) -> Option<PrivilegesRequired> {
    match b {
        0 => Some(PrivilegesRequired::None),
        1 => Some(PrivilegesRequired::PowerUser),
        2 => Some(PrivilegesRequired::Admin),
        3 => Some(PrivilegesRequired::Lowest),
        _ => None,
    }
}

/// 3.0.4..5.3.7 mapping (innoextract `stored_privileges_0`).
fn decode_privileges_required_v0(b: u8) -> Option<PrivilegesRequired> {
    match b {
        0 => Some(PrivilegesRequired::None),
        1 => Some(PrivilegesRequired::PowerUser),
        2 => Some(PrivilegesRequired::Admin),
        _ => None,
    }
}

fn decode_language_detection(b: u8) -> Option<LanguageDetectionMethod> {
    match b {
        0 => Some(LanguageDetectionMethod::UiLanguage),
        1 => Some(LanguageDetectionMethod::Locale),
        2 => Some(LanguageDetectionMethod::None),
        _ => None,
    }
}

fn decode_compress_method(b: u8, version: &Version) -> Option<CompressMethod> {
    // 5.3.9+ table includes LZMA2; older tables stop earlier.
    if version.at_least(5, 3, 9) {
        match b {
            0 => Some(CompressMethod::Stored),
            1 => Some(CompressMethod::Zlib),
            2 => Some(CompressMethod::Bzip2),
            3 => Some(CompressMethod::Lzma1),
            4 => Some(CompressMethod::Lzma2),
            _ => None,
        }
    } else if version.at_least(4, 2, 6) {
        match b {
            0 => Some(CompressMethod::Stored),
            1 => Some(CompressMethod::Zlib),
            2 => Some(CompressMethod::Bzip2),
            3 => Some(CompressMethod::Lzma1),
            _ => None,
        }
    } else if version.at_least(4, 2, 5) {
        match b {
            0 => Some(CompressMethod::Stored),
            1 => Some(CompressMethod::Bzip2),
            2 => Some(CompressMethod::Lzma1),
            _ => None,
        }
    } else if version.at_least(4, 1, 5) {
        match b {
            0 => Some(CompressMethod::Zlib),
            1 => Some(CompressMethod::Bzip2),
            2 => Some(CompressMethod::Lzma1),
            _ => None,
        }
    } else {
        None
    }
}

fn decode_overrides_set(raw: &[u8]) -> HashSet<PrivilegesRequiredOverride> {
    let mut out = HashSet::new();
    if bit_at(raw, 0) {
        out.insert(PrivilegesRequiredOverride::Commandline);
    }
    if bit_at(raw, 1) {
        out.insert(PrivilegesRequiredOverride::Dialog);
    }
    out
}

/// 5.6.0+ (5-arch) layout: Unknown, X86, Amd64, IA64, Arm64.
fn decode_arch_set_v1(raw: &[u8]) -> HashSet<Architecture> {
    let table = [
        Architecture::Unknown,
        Architecture::X86,
        Architecture::Amd64,
        Architecture::IA64,
        Architecture::Arm64,
    ];
    decode_arch_with_table(raw, &table)
}

/// 5.1.0..5.6.0 (4-arch) layout: Unknown, X86, Amd64, IA64.
fn decode_arch_set_v0(raw: &[u8]) -> HashSet<Architecture> {
    let table = [
        Architecture::Unknown,
        Architecture::X86,
        Architecture::Amd64,
        Architecture::IA64,
    ];
    decode_arch_with_table(raw, &table)
}

fn decode_arch_with_table(raw: &[u8], table: &[Architecture]) -> HashSet<Architecture> {
    let mut out = HashSet::new();
    for (i, &arch) in table.iter().enumerate() {
        if bit_at(raw, i) {
            out.insert(arch);
        }
    }
    out
}

fn bit_at(raw: &[u8], bit: usize) -> bool {
    let byte_idx = bit / 8;
    let bit_idx = bit % 8;
    raw.get(byte_idx)
        .copied()
        .is_some_and(|b| (b >> bit_idx) & 1 == 1)
}

/// Returns the on-wire member count of `TSetupHeaderOption` for
/// `version`. Derived from the same per-version slot table the
/// decoder walks ([`static_options_bit_table`] for 5.5.0+,
/// [`dynamic_options_bit_table`] for older), so the count and the
/// decode are guaranteed to agree.
fn options_bit_count(version: &Version) -> usize {
    if version.at_least(5, 5, 0) {
        static_options_bit_table(version).len()
    } else {
        dynamic_options_bit_table(version).len()
    }
}

fn decode_options(raw: &[u8], version: &Version) -> HashSet<HeaderOption> {
    let mut out = HashSet::new();
    if version.at_least(5, 5, 0) {
        // 5.5.0+ uses one of the curated static slot tables - preferred
        // because the bit positions are stable and easy to audit.
        for (i, slot) in static_options_bit_table(version).iter().enumerate() {
            if bit_at(raw, i)
                && let Some(opt) = slot
            {
                out.insert(*opt);
            }
        }
    } else {
        // Pre-5.5.0: build the slot table on the fly from the same
        // version-conditional walk as `options_bit_count`, mirroring
        // innoextract's `header::load_flags`.
        for (i, slot) in dynamic_options_bit_table(version).into_iter().enumerate() {
            if bit_at(raw, i)
                && let Some(opt) = slot
            {
                out.insert(opt);
            }
        }
    }
    out
}

/// Returns the curated bit table for 5.5.0+ versions. The table maps
/// each on-wire bit index to a [`HeaderOption`] (or `None` for slots
/// reserved for flags that don't have a public name in our union).
fn static_options_bit_table(version: &Version) -> &'static [Option<HeaderOption>] {
    if version.at_least(6, 7, 0) {
        OPTIONS_V6_7
    } else if version.at_least(6, 5, 0) {
        OPTIONS_V6_5
    } else if version.at_least(6, 4, 0) {
        OPTIONS_V6_4
    } else if version.at_least(6, 3, 0) {
        OPTIONS_V6_3
    } else if version.at_least(6, 0, 0) {
        OPTIONS_V6_1
    } else if version.at_least(5, 5, 7) {
        // 5.5.7..6.0.0. Ordering mirrors innoextract `header::load_flags`
        // for that range. The ANSI build adds `ShowUndisplayableLanguages`
        // at bit 39; Unicode builds skip that bit and shift the tail down
        // by one. We model the ANSI variant - bits 0..38 are identical
        // for both, which covers the Password (bit 10) and
        // EncryptionUsed (bit 37) lookups callers actually care about.
        OPTIONS_V5_5_7
    } else {
        // 5.5.0..5.5.7: same as `OPTIONS_V5_5_7` minus the trailing
        // `ForceCloseApplications` slot.
        OPTIONS_V5_5_0
    }
}

/// Builds the bit-to-[`HeaderOption`] mapping for pre-5.5.0 versions
/// by walking innoextract's `header::load_flags` (`research/src/setup/header.cpp:569-733`)
/// in declaration order. Each gated `flagreader.add(...)` call
/// contributes one slot, with `None` for flag names that don't have
/// a [`HeaderOption`] counterpart in our union (legacy bits like
/// `BackSolid` or `BzipUsed`).
///
/// Kept in lock-step with [`options_bit_count`] so the two functions
/// always agree on the number of slots.
fn dynamic_options_bit_table(version: &Version) -> Vec<Option<HeaderOption>> {
    let mut t: Vec<Option<HeaderOption>> = Vec::with_capacity(48);

    t.push(Some(HeaderOption::DisableStartupPrompt));
    if !version.at_least(5, 3, 10) {
        t.push(None); // Uninstallable (no HeaderOption counterpart pre-5.3.10)
    }
    t.push(Some(HeaderOption::CreateAppDir));
    if !version.at_least(5, 3, 3) {
        t.push(None); // DisableDirPage
    }
    if !version.at_least(1, 3, 6) {
        t.push(None); // DisableDirExistsWarning
    }
    if !version.at_least(5, 3, 3) {
        t.push(None); // DisableProgramGroupPage
    }
    t.push(Some(HeaderOption::AllowNoIcons));
    if !version.at_least(3, 0, 0) || version.at_least(3, 0, 3) {
        t.push(Some(HeaderOption::AlwaysRestart));
    }
    if !version.at_least(1, 3, 3) {
        t.push(None); // BackSolid
    }
    t.push(Some(HeaderOption::AlwaysUsePersonalGroup));
    if !version.at_least_4(6, 4, 0, 1) {
        t.push(Some(HeaderOption::WindowVisible));
        t.push(Some(HeaderOption::WindowShowCaption));
        t.push(Some(HeaderOption::WindowResizable));
        t.push(Some(HeaderOption::WindowStartMaximized));
    }
    t.push(Some(HeaderOption::EnableDirDoesntExistWarning));
    if !version.at_least(4, 1, 2) {
        t.push(None); // DisableAppendDir
    }
    t.push(Some(HeaderOption::Password));
    if version.at_least(1, 2, 6) {
        t.push(Some(HeaderOption::AllowRootDirectory));
    }
    if version.at_least(1, 2, 14) {
        t.push(Some(HeaderOption::DisableFinishedPage));
    }
    if !version.at_least(3, 0, 4) {
        t.push(None); // AdminPrivilegesRequired
    }
    if !version.at_least(3, 0, 0) {
        t.push(None); // AlwaysCreateUninstallIcon
    }
    if !version.at_least(1, 3, 6) {
        t.push(None); // OverwriteUninstRegEntries
    }
    if !version.at_least(5, 6, 1) {
        t.push(None); // ChangesAssociations (flag-only pre-5.6.1)
    }
    if version.at_least(1, 3, 0) && !version.at_least(5, 3, 8) {
        t.push(None); // CreateUninstallRegKey
    }
    if version.at_least(1, 3, 1) {
        t.push(Some(HeaderOption::UsePreviousAppDir));
    }
    if version.at_least(1, 3, 3) && !version.at_least_4(6, 4, 0, 1) {
        t.push(Some(HeaderOption::BackColorHorizontal));
    }
    if version.at_least(1, 3, 10) {
        t.push(Some(HeaderOption::UsePreviousGroup));
    }
    if version.at_least(1, 3, 20) {
        t.push(Some(HeaderOption::UpdateUninstallLogAppName));
    }
    if version.at_least(2, 0, 0) || (version.is_isx() && version.at_least(1, 3, 10)) {
        t.push(Some(HeaderOption::UsePreviousSetupType));
    }
    if version.at_least(2, 0, 0) {
        t.push(Some(HeaderOption::DisableReadyMemo));
        t.push(Some(HeaderOption::AlwaysShowComponentsList));
        t.push(Some(HeaderOption::FlatComponentsList));
        t.push(Some(HeaderOption::ShowComponentSizes));
        t.push(Some(HeaderOption::UsePreviousTasks));
        t.push(Some(HeaderOption::DisableReadyPage));
    }
    if version.at_least(2, 0, 7) {
        t.push(Some(HeaderOption::AlwaysShowDirOnReadyPage));
        t.push(Some(HeaderOption::AlwaysShowGroupOnReadyPage));
    }
    if version.at_least(2, 0, 17) && !version.at_least(4, 1, 5) {
        t.push(None); // BzipUsed
    }
    if version.at_least(2, 0, 18) {
        t.push(Some(HeaderOption::AllowUNCPath));
    }
    if version.at_least(3, 0, 0) {
        t.push(Some(HeaderOption::UserInfoPage));
        t.push(Some(HeaderOption::UsePreviousUserInfo));
    }
    if version.at_least(3, 0, 1) {
        t.push(Some(HeaderOption::UninstallRestartComputer));
    }
    if version.at_least(3, 0, 3) {
        t.push(Some(HeaderOption::RestartIfNeededByRun));
    }
    if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(3, 0, 3)) {
        t.push(Some(HeaderOption::ShowTasksTreeLines));
    }
    if version.at_least(4, 0, 0) && !version.at_least(4, 0, 10) {
        t.push(None); // ShowLanguageDialog
    }
    if version.at_least(4, 0, 1) && !version.at_least(4, 0, 10) {
        t.push(None); // DetectLanguageUsingLocale
    }
    if version.at_least(4, 0, 9) {
        t.push(Some(HeaderOption::AllowCancelDuringInstall));
    }
    if version.at_least(4, 1, 3) {
        t.push(Some(HeaderOption::WizardImageStretch));
    }
    if version.at_least(4, 1, 8) {
        t.push(Some(HeaderOption::AppendDefaultDirName));
        t.push(Some(HeaderOption::AppendDefaultGroupName));
    }
    if version.at_least(4, 2, 2) {
        t.push(Some(HeaderOption::EncryptionUsed));
    }
    if version.at_least(5, 0, 4) && !version.at_least(5, 6, 1) {
        t.push(None); // ChangesEnvironment (flag-only pre-5.6.1)
    }
    if version.at_least(5, 1, 7) && !version.is_unicode() {
        t.push(None); // ShowUndisplayableLanguages (ANSI-only)
    }
    if version.at_least(5, 1, 13) {
        t.push(Some(HeaderOption::SetupLogging));
    }
    if version.at_least(5, 2, 1) {
        t.push(Some(HeaderOption::SignedUninstaller));
    }
    if version.at_least(5, 3, 8) {
        t.push(Some(HeaderOption::UsePreviousLanguage));
    }
    if version.at_least(5, 3, 9) {
        t.push(Some(HeaderOption::DisableWelcomePage));
    }
    // 5.5.0+ slots are unreachable here - the static tables cover that
    // range - but include them for symmetry with `options_bit_count`.
    if version.at_least(5, 5, 0) {
        t.push(Some(HeaderOption::CloseApplications));
        t.push(Some(HeaderOption::RestartApplications));
        t.push(Some(HeaderOption::AllowNetworkDrive));
    }
    if version.at_least(5, 5, 7) {
        t.push(Some(HeaderOption::ForceCloseApplications));
    }
    if version.at_least(6, 0, 0) {
        t.push(Some(HeaderOption::AppNameHasConsts));
        t.push(Some(HeaderOption::UsePreviousPrivileges));
        t.push(Some(HeaderOption::WizardResizable));
    }
    if version.at_least(6, 3, 0) {
        t.push(Some(HeaderOption::UninstallLogging));
    }
    t
}

/// 5.5.0..5.5.7 flag table. Same as `OPTIONS_V5_5_7` minus the
/// final `ForceCloseApplications` slot (added at 5.5.7).
const OPTIONS_V5_5_0: &[Option<HeaderOption>] = &[
    Some(HeaderOption::DisableStartupPrompt),
    Some(HeaderOption::CreateAppDir),
    Some(HeaderOption::AllowNoIcons),
    Some(HeaderOption::AlwaysRestart),
    Some(HeaderOption::AlwaysUsePersonalGroup),
    Some(HeaderOption::WindowVisible),
    Some(HeaderOption::WindowShowCaption),
    Some(HeaderOption::WindowResizable),
    Some(HeaderOption::WindowStartMaximized),
    Some(HeaderOption::EnableDirDoesntExistWarning),
    Some(HeaderOption::Password),
    Some(HeaderOption::AllowRootDirectory),
    Some(HeaderOption::DisableFinishedPage),
    None, // ChangesAssociations (flag-only pre-5.6.1)
    Some(HeaderOption::UsePreviousAppDir),
    Some(HeaderOption::BackColorHorizontal),
    Some(HeaderOption::UsePreviousGroup),
    Some(HeaderOption::UpdateUninstallLogAppName),
    Some(HeaderOption::UsePreviousSetupType),
    Some(HeaderOption::DisableReadyMemo),
    Some(HeaderOption::AlwaysShowComponentsList),
    Some(HeaderOption::FlatComponentsList),
    Some(HeaderOption::ShowComponentSizes),
    Some(HeaderOption::UsePreviousTasks),
    Some(HeaderOption::DisableReadyPage),
    Some(HeaderOption::AlwaysShowDirOnReadyPage),
    Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    Some(HeaderOption::AllowUNCPath),
    Some(HeaderOption::UserInfoPage),
    Some(HeaderOption::UsePreviousUserInfo),
    Some(HeaderOption::UninstallRestartComputer),
    Some(HeaderOption::RestartIfNeededByRun),
    Some(HeaderOption::ShowTasksTreeLines),
    Some(HeaderOption::AllowCancelDuringInstall),
    Some(HeaderOption::WizardImageStretch),
    Some(HeaderOption::AppendDefaultDirName),
    Some(HeaderOption::AppendDefaultGroupName),
    Some(HeaderOption::EncryptionUsed),
    None, // ChangesEnvironment (flag-only pre-5.6.1)
    None, // ShowUndisplayableLanguages (ANSI-only)
    Some(HeaderOption::SetupLogging),
    Some(HeaderOption::SignedUninstaller),
    Some(HeaderOption::UsePreviousLanguage),
    Some(HeaderOption::DisableWelcomePage),
    Some(HeaderOption::CloseApplications),
    Some(HeaderOption::RestartApplications),
    Some(HeaderOption::AllowNetworkDrive),
];

/// 5.5.7..6.0.0 ANSI flag bit table. Ordering follows innoextract
/// `setup/header.cpp:569-733` (`header::load_flags`) - every
/// `flagreader.add(...)` call that's gated on a version range
/// covering 5.5.7 contributes one bit slot in declaration order.
const OPTIONS_V5_5_7: &[Option<HeaderOption>] = &[
    Some(HeaderOption::DisableStartupPrompt),
    Some(HeaderOption::CreateAppDir),
    Some(HeaderOption::AllowNoIcons),
    Some(HeaderOption::AlwaysRestart),
    Some(HeaderOption::AlwaysUsePersonalGroup),
    Some(HeaderOption::WindowVisible),
    Some(HeaderOption::WindowShowCaption),
    Some(HeaderOption::WindowResizable),
    Some(HeaderOption::WindowStartMaximized),
    Some(HeaderOption::EnableDirDoesntExistWarning),
    Some(HeaderOption::Password),
    Some(HeaderOption::AllowRootDirectory),
    Some(HeaderOption::DisableFinishedPage),
    None, // ChangesAssociations (flag-only pre-5.6.1; not in HeaderOption union)
    Some(HeaderOption::UsePreviousAppDir),
    Some(HeaderOption::BackColorHorizontal),
    Some(HeaderOption::UsePreviousGroup),
    Some(HeaderOption::UpdateUninstallLogAppName),
    Some(HeaderOption::UsePreviousSetupType),
    Some(HeaderOption::DisableReadyMemo),
    Some(HeaderOption::AlwaysShowComponentsList),
    Some(HeaderOption::FlatComponentsList),
    Some(HeaderOption::ShowComponentSizes),
    Some(HeaderOption::UsePreviousTasks),
    Some(HeaderOption::DisableReadyPage),
    Some(HeaderOption::AlwaysShowDirOnReadyPage),
    Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    Some(HeaderOption::AllowUNCPath),
    Some(HeaderOption::UserInfoPage),
    Some(HeaderOption::UsePreviousUserInfo),
    Some(HeaderOption::UninstallRestartComputer),
    Some(HeaderOption::RestartIfNeededByRun),
    Some(HeaderOption::ShowTasksTreeLines),
    Some(HeaderOption::AllowCancelDuringInstall),
    Some(HeaderOption::WizardImageStretch),
    Some(HeaderOption::AppendDefaultDirName),
    Some(HeaderOption::AppendDefaultGroupName),
    Some(HeaderOption::EncryptionUsed),
    None, // ChangesEnvironment (flag-only pre-5.6.1; not in HeaderOption union)
    None, // ShowUndisplayableLanguages (ANSI-only; absent on Unicode but
    // bits 0..38 are stable, so callers reading Password / EncryptionUsed
    // are unaffected by this slot's identity)
    Some(HeaderOption::SetupLogging),
    Some(HeaderOption::SignedUninstaller),
    Some(HeaderOption::UsePreviousLanguage),
    Some(HeaderOption::DisableWelcomePage),
    Some(HeaderOption::CloseApplications),
    Some(HeaderOption::RestartApplications),
    Some(HeaderOption::AllowNetworkDrive),
    Some(HeaderOption::ForceCloseApplications),
];

const OPTIONS_V6_1: &[Option<HeaderOption>] = &[
    Some(HeaderOption::DisableStartupPrompt),
    Some(HeaderOption::CreateAppDir),
    Some(HeaderOption::AllowNoIcons),
    Some(HeaderOption::AlwaysRestart),
    Some(HeaderOption::AlwaysUsePersonalGroup),
    Some(HeaderOption::WindowVisible),
    Some(HeaderOption::WindowShowCaption),
    Some(HeaderOption::WindowResizable),
    Some(HeaderOption::WindowStartMaximized),
    Some(HeaderOption::EnableDirDoesntExistWarning),
    Some(HeaderOption::Password),
    Some(HeaderOption::AllowRootDirectory),
    Some(HeaderOption::DisableFinishedPage),
    Some(HeaderOption::UsePreviousAppDir),
    Some(HeaderOption::BackColorHorizontal),
    Some(HeaderOption::UsePreviousGroup),
    Some(HeaderOption::UpdateUninstallLogAppName),
    Some(HeaderOption::UsePreviousSetupType),
    Some(HeaderOption::DisableReadyMemo),
    Some(HeaderOption::AlwaysShowComponentsList),
    Some(HeaderOption::FlatComponentsList),
    Some(HeaderOption::ShowComponentSizes),
    Some(HeaderOption::UsePreviousTasks),
    Some(HeaderOption::DisableReadyPage),
    Some(HeaderOption::AlwaysShowDirOnReadyPage),
    Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    Some(HeaderOption::AllowUNCPath),
    Some(HeaderOption::UserInfoPage),
    Some(HeaderOption::UsePreviousUserInfo),
    Some(HeaderOption::UninstallRestartComputer),
    Some(HeaderOption::RestartIfNeededByRun),
    Some(HeaderOption::ShowTasksTreeLines),
    Some(HeaderOption::AllowCancelDuringInstall),
    Some(HeaderOption::WizardImageStretch),
    Some(HeaderOption::AppendDefaultDirName),
    Some(HeaderOption::AppendDefaultGroupName),
    Some(HeaderOption::EncryptionUsed),
    Some(HeaderOption::SetupLogging),
    Some(HeaderOption::SignedUninstaller),
    Some(HeaderOption::UsePreviousLanguage),
    Some(HeaderOption::DisableWelcomePage),
    Some(HeaderOption::CloseApplications),
    Some(HeaderOption::RestartApplications),
    Some(HeaderOption::AllowNetworkDrive),
    Some(HeaderOption::ForceCloseApplications),
    Some(HeaderOption::AppNameHasConsts),
    Some(HeaderOption::UsePreviousPrivileges),
    Some(HeaderOption::WizardResizable),
];

/// 6.3.0..6.4.0 - same shape as `OPTIONS_V6_1` plus `UninstallLogging`
/// at slot 48 (innoextract `header.cpp:729-731`). 49 bits → 7 bytes
/// on wire.
const OPTIONS_V6_3: &[Option<HeaderOption>] = &[
    Some(HeaderOption::DisableStartupPrompt),
    Some(HeaderOption::CreateAppDir),
    Some(HeaderOption::AllowNoIcons),
    Some(HeaderOption::AlwaysRestart),
    Some(HeaderOption::AlwaysUsePersonalGroup),
    Some(HeaderOption::WindowVisible),
    Some(HeaderOption::WindowShowCaption),
    Some(HeaderOption::WindowResizable),
    Some(HeaderOption::WindowStartMaximized),
    Some(HeaderOption::EnableDirDoesntExistWarning),
    Some(HeaderOption::Password),
    Some(HeaderOption::AllowRootDirectory),
    Some(HeaderOption::DisableFinishedPage),
    Some(HeaderOption::UsePreviousAppDir),
    Some(HeaderOption::BackColorHorizontal),
    Some(HeaderOption::UsePreviousGroup),
    Some(HeaderOption::UpdateUninstallLogAppName),
    Some(HeaderOption::UsePreviousSetupType),
    Some(HeaderOption::DisableReadyMemo),
    Some(HeaderOption::AlwaysShowComponentsList),
    Some(HeaderOption::FlatComponentsList),
    Some(HeaderOption::ShowComponentSizes),
    Some(HeaderOption::UsePreviousTasks),
    Some(HeaderOption::DisableReadyPage),
    Some(HeaderOption::AlwaysShowDirOnReadyPage),
    Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    Some(HeaderOption::AllowUNCPath),
    Some(HeaderOption::UserInfoPage),
    Some(HeaderOption::UsePreviousUserInfo),
    Some(HeaderOption::UninstallRestartComputer),
    Some(HeaderOption::RestartIfNeededByRun),
    Some(HeaderOption::ShowTasksTreeLines),
    Some(HeaderOption::AllowCancelDuringInstall),
    Some(HeaderOption::WizardImageStretch),
    Some(HeaderOption::AppendDefaultDirName),
    Some(HeaderOption::AppendDefaultGroupName),
    Some(HeaderOption::EncryptionUsed),
    Some(HeaderOption::SetupLogging),
    Some(HeaderOption::SignedUninstaller),
    Some(HeaderOption::UsePreviousLanguage),
    Some(HeaderOption::DisableWelcomePage),
    Some(HeaderOption::CloseApplications),
    Some(HeaderOption::RestartApplications),
    Some(HeaderOption::AllowNetworkDrive),
    Some(HeaderOption::ForceCloseApplications),
    Some(HeaderOption::AppNameHasConsts),
    Some(HeaderOption::UsePreviousPrivileges),
    Some(HeaderOption::WizardResizable),
    Some(HeaderOption::UninstallLogging),
];

const OPTIONS_V6_4: &[Option<HeaderOption>] = &[
    Some(HeaderOption::DisableStartupPrompt),
    Some(HeaderOption::CreateAppDir),
    Some(HeaderOption::AllowNoIcons),
    Some(HeaderOption::AlwaysRestart),
    Some(HeaderOption::AlwaysUsePersonalGroup),
    Some(HeaderOption::EnableDirDoesntExistWarning),
    Some(HeaderOption::Password),
    Some(HeaderOption::AllowRootDirectory),
    Some(HeaderOption::DisableFinishedPage),
    Some(HeaderOption::UsePreviousAppDir),
    Some(HeaderOption::UsePreviousGroup),
    Some(HeaderOption::UpdateUninstallLogAppName),
    Some(HeaderOption::UsePreviousSetupType),
    Some(HeaderOption::DisableReadyMemo),
    Some(HeaderOption::AlwaysShowComponentsList),
    Some(HeaderOption::FlatComponentsList),
    Some(HeaderOption::ShowComponentSizes),
    Some(HeaderOption::UsePreviousTasks),
    Some(HeaderOption::DisableReadyPage),
    Some(HeaderOption::AlwaysShowDirOnReadyPage),
    Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    Some(HeaderOption::AllowUNCPath),
    Some(HeaderOption::UserInfoPage),
    Some(HeaderOption::UsePreviousUserInfo),
    Some(HeaderOption::UninstallRestartComputer),
    Some(HeaderOption::RestartIfNeededByRun),
    Some(HeaderOption::ShowTasksTreeLines),
    Some(HeaderOption::AllowCancelDuringInstall),
    Some(HeaderOption::WizardImageStretch),
    Some(HeaderOption::AppendDefaultDirName),
    Some(HeaderOption::AppendDefaultGroupName),
    Some(HeaderOption::EncryptionUsed),
    Some(HeaderOption::SetupLogging),
    Some(HeaderOption::SignedUninstaller),
    Some(HeaderOption::UsePreviousLanguage),
    Some(HeaderOption::DisableWelcomePage),
    Some(HeaderOption::CloseApplications),
    Some(HeaderOption::RestartApplications),
    Some(HeaderOption::AllowNetworkDrive),
    Some(HeaderOption::ForceCloseApplications),
    Some(HeaderOption::AppNameHasConsts),
    Some(HeaderOption::UsePreviousPrivileges),
    Some(HeaderOption::WizardResizable),
    Some(HeaderOption::UninstallLogging),
];

const OPTIONS_V6_5: &[Option<HeaderOption>] = &[
    Some(HeaderOption::DisableStartupPrompt),
    Some(HeaderOption::CreateAppDir),
    Some(HeaderOption::AllowNoIcons),
    Some(HeaderOption::AlwaysRestart),
    Some(HeaderOption::AlwaysUsePersonalGroup),
    Some(HeaderOption::EnableDirDoesntExistWarning),
    Some(HeaderOption::Password),
    Some(HeaderOption::AllowRootDirectory),
    Some(HeaderOption::DisableFinishedPage),
    Some(HeaderOption::UsePreviousAppDir),
    Some(HeaderOption::UsePreviousGroup),
    Some(HeaderOption::UpdateUninstallLogAppName),
    Some(HeaderOption::UsePreviousSetupType),
    Some(HeaderOption::DisableReadyMemo),
    Some(HeaderOption::AlwaysShowComponentsList),
    Some(HeaderOption::FlatComponentsList),
    Some(HeaderOption::ShowComponentSizes),
    Some(HeaderOption::UsePreviousTasks),
    Some(HeaderOption::DisableReadyPage),
    Some(HeaderOption::AlwaysShowDirOnReadyPage),
    Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    Some(HeaderOption::AllowUNCPath),
    Some(HeaderOption::UserInfoPage),
    Some(HeaderOption::UsePreviousUserInfo),
    Some(HeaderOption::UninstallRestartComputer),
    Some(HeaderOption::RestartIfNeededByRun),
    Some(HeaderOption::ShowTasksTreeLines),
    Some(HeaderOption::AllowCancelDuringInstall),
    Some(HeaderOption::WizardImageStretch),
    Some(HeaderOption::AppendDefaultDirName),
    Some(HeaderOption::AppendDefaultGroupName),
    Some(HeaderOption::SetupLogging),
    Some(HeaderOption::SignedUninstaller),
    Some(HeaderOption::UsePreviousLanguage),
    Some(HeaderOption::DisableWelcomePage),
    Some(HeaderOption::CloseApplications),
    Some(HeaderOption::RestartApplications),
    Some(HeaderOption::AllowNetworkDrive),
    Some(HeaderOption::ForceCloseApplications),
    Some(HeaderOption::AppNameHasConsts),
    Some(HeaderOption::UsePreviousPrivileges),
    Some(HeaderOption::WizardResizable),
    Some(HeaderOption::UninstallLogging),
];

/// 6.7.0+ Options bit table. The 5 `shUsePrevious*` bits were
/// removed (those directives became `String` fields instead);
/// `shWizardResizable` was also removed (replaced by
/// `shWizardModern`/`shWizardBorderStyled`/`shWizardKeepAspectRatio`/
/// `shWizardBevelsHidden`). Bits 42..55 are reserved padding;
/// bit 56 is `shUnusedPadding` itself. Total 57 bits = 8 bytes.
const OPTIONS_V6_7: &[Option<HeaderOption>] = &[
    /* 0  */ Some(HeaderOption::DisableStartupPrompt),
    /* 1  */ Some(HeaderOption::CreateAppDir),
    /* 2  */ Some(HeaderOption::AllowNoIcons),
    /* 3  */ Some(HeaderOption::AlwaysRestart),
    /* 4  */ Some(HeaderOption::AlwaysUsePersonalGroup),
    /* 5  */ Some(HeaderOption::EnableDirDoesntExistWarning),
    /* 6  */ Some(HeaderOption::Password),
    /* 7  */ Some(HeaderOption::AllowRootDirectory),
    /* 8  */ Some(HeaderOption::DisableFinishedPage),
    /* 9  */ Some(HeaderOption::UpdateUninstallLogAppName),
    /* 10 */ Some(HeaderOption::DisableReadyMemo),
    /* 11 */ Some(HeaderOption::AlwaysShowComponentsList),
    /* 12 */ Some(HeaderOption::FlatComponentsList),
    /* 13 */ Some(HeaderOption::ShowComponentSizes),
    /* 14 */ Some(HeaderOption::DisableReadyPage),
    /* 15 */ Some(HeaderOption::AlwaysShowDirOnReadyPage),
    /* 16 */ Some(HeaderOption::AlwaysShowGroupOnReadyPage),
    /* 17 */ Some(HeaderOption::AllowUNCPath),
    /* 18 */ Some(HeaderOption::UserInfoPage),
    /* 19 */ Some(HeaderOption::UninstallRestartComputer),
    /* 20 */ Some(HeaderOption::RestartIfNeededByRun),
    /* 21 */ Some(HeaderOption::ShowTasksTreeLines),
    /* 22 */ Some(HeaderOption::AllowCancelDuringInstall),
    /* 23 */ Some(HeaderOption::WizardImageStretch),
    /* 24 */ Some(HeaderOption::AppendDefaultDirName),
    /* 25 */ Some(HeaderOption::AppendDefaultGroupName),
    /* 26 */ Some(HeaderOption::SetupLogging),
    /* 27 */ Some(HeaderOption::SignedUninstaller),
    /* 28 */ Some(HeaderOption::UsePreviousLanguage),
    /* 29 */ Some(HeaderOption::DisableWelcomePage),
    /* 30 */ Some(HeaderOption::CloseApplications),
    /* 31 */ Some(HeaderOption::RestartApplications),
    /* 32 */ Some(HeaderOption::AllowNetworkDrive),
    /* 33 */ Some(HeaderOption::ForceCloseApplications),
    /* 34 */ Some(HeaderOption::AppNameHasConsts),
    /* 35 */ Some(HeaderOption::UsePreviousPrivileges),
    /* 36 */ Some(HeaderOption::UninstallLogging),
    /* 37..41: shWizardModern, shWizardBorderStyled,
    shWizardKeepAspectRatio, shRedirectionGuard, shWizardBevelsHidden */
    None,
    None,
    None,
    None,
    None,
    /* 42..56: reserved padding (and shUnusedPadding) */
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    fn push_utf16(buf: &mut Vec<u8>, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (units.len() as u32).saturating_mul(2);
        buf.extend_from_slice(&byte_len.to_le_bytes());
        for u in units {
            buf.extend_from_slice(&u.to_le_bytes());
        }
    }

    fn push_ansi(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    fn version_6_4_3() -> Version {
        Version {
            a: 6,
            b: 4,
            c: 3,
            d: 0,
            flags: VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    /// Regression for GitHub #1: on a 6.4.3+ installer the `String` field
    /// `CloseApplicationsFilterExcludes` must be read *before* the
    /// license/info/compiled-code `AnsiString` tail, matching Inno's
    /// all-strings-then-all-ansistrings serialization. When it was read
    /// after the tail, a non-empty `CompiledCode` blob (present whenever the
    /// script has a `[Code]` section) landed in the UTF-16 decode and failed
    /// with "invalid UTF-16LE in CloseApplicationsFilterExcludes". The
    /// synthetic sample installers have no `[Code]` section, so every tail
    /// field is empty and the misordering stayed invisible to them - hence
    /// this byte-level fixture with a deliberately non-empty, odd-length
    /// compiled-code blob (odd length is never valid UTF-16, so a regression
    /// re-surfaces as the exact original error rather than a silent shift).
    #[test]
    fn issue_1_close_applications_filter_excludes_precedes_ansi_tail() {
        let version = version_6_4_3();

        // The 32 `String` fields that precede `CloseApplicationsFilterExcludes`
        // for a 6.4.3 Unicode (non-ISX) installer, all left empty.
        let mut buf = Vec::new();
        for _ in 0..32 {
            push_utf16(&mut buf, "");
        }
        // Field 33: CloseApplicationsFilterExcludes - a real string.
        push_utf16(&mut buf, "notepad.exe,calc.exe");
        // AnsiString tail: License / InfoBefore / InfoAfter / CompiledCode.
        push_ansi(&mut buf, b"LICENSE TEXT");
        push_ansi(&mut buf, b"");
        push_ansi(&mut buf, b"");
        // Compiled Pascal-Script bytecode: arbitrary binary, odd length so
        // that mis-decoding it as UTF-16 reproduces the reported failure.
        let compiled = [0x01u8, 0x02, 0x03];
        push_ansi(&mut buf, &compiled);

        let mut reader = Reader::new(&buf);
        let mut strings = HashMap::new();
        let mut ansi = HashMap::new();
        read_header_strings_and_ansi(&mut reader, &version, &mut strings, &mut ansi)
            .expect("6.4.3 header with a [Code] section must parse (issue #1)");

        assert_eq!(
            strings
                .get(&HeaderString::CloseApplicationsFilterExcludes)
                .map(String::as_str),
            Some("notepad.exe,calc.exe"),
        );
        assert_eq!(
            ansi.get(&HeaderAnsi::LicenseText).map(Vec::as_slice),
            Some(b"LICENSE TEXT".as_slice()),
        );
        assert_eq!(
            ansi.get(&HeaderAnsi::CompiledCodeText).map(Vec::as_slice),
            Some(compiled.as_slice()),
        );
        // Every byte consumed: strings and ansi tail line up exactly.
        assert_eq!(reader.remaining(), 0);
    }
}
