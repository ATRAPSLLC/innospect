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
//! The string fields, the counts and the fixed tail all change with the
//! version; each field documents when it exists. Reader reference:
//! innoextract `setup/header.cpp`. The layout of every SetupID marker whose
//! source is available is checked against upstream's own `TSetupHeader` by
//! the `crate::upstream` tests: field order, kinds, sizes, set bits and
//! enum values.

use std::collections::{HashMap, HashSet};

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::{FromReader, Reader},
    },
    version::Version,
};

/// A string field of the setup header (`TSetupHeader`), read with
/// [`SetupHeader::string`]. Each is a `[Setup]` directive's value as the
/// compiler stored it, constants such as `{app}` unexpanded; a field the
/// version does not have is absent. Variants are in declaration order.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderString {
    /// `AppName`: the application's name, without version.
    AppName,
    /// `AppVerName`: name and version, shown on the Welcome page and used
    /// for the Add/Remove Programs entry by default.
    AppVerName,
    /// `AppId`: the identity stored in the uninstall log and in the
    /// uninstall registry key's name (`<AppId>_is1`); defaults to `AppName`
    /// (1.3.0+).
    AppId,
    /// `AppCopyright`: the copyright line.
    AppCopyright,
    /// `AppPublisher`: shown in Add/Remove Programs (1.3.0+).
    AppPublisher,
    /// `AppPublisherURL`: the publisher's link in Add/Remove Programs
    /// (1.3.0+).
    AppPublisherUrl,
    /// `AppSupportPhone`: shown in Add/Remove Programs (5.1.13+).
    AppSupportPhone,
    /// `AppSupportURL`: the support link in Add/Remove Programs (1.3.0+).
    AppSupportUrl,
    /// `AppUpdatesURL`: the updates link in Add/Remove Programs (1.3.0+).
    AppUpdatesUrl,
    /// `AppVersion`: the version shown in Add/Remove Programs (1.3.0+).
    AppVersion,
    /// `DefaultDirName`: the default installation directory, e.g.
    /// `{autopf}\My Program`.
    DefaultDirName,
    /// `DefaultGroupName`: the default Start menu folder.
    DefaultGroupName,
    /// `UninstallIconName`: the name of the uninstaller shortcut Setup
    /// itself put in the Start menu folder (before 3.0.0; later scripts
    /// add one in `[Icons]` with `{uninstallexe}`).
    UninstallIconName,
    /// `BaseFilename`: never filled by any release whose source is
    /// available, so always empty; 7.1.1 dropped it.
    BaseFilename,
    /// `UninstallFilesDir`: where the uninstaller's `unins*` files go,
    /// `{app}` by default (1.3.3+).
    UninstallFilesDir,
    /// `UninstallDisplayName`: the Add/Remove Programs name; empty means
    /// `AppVerName` (1.3.6+).
    UninstallDisplayName,
    /// `UninstallDisplayIcon`: the Add/Remove Programs icon file, with an
    /// optional `,index` (1.3.6+).
    UninstallDisplayIcon,
    /// `AppMutex`: comma-separated mutex names; Setup and the uninstaller
    /// refuse to run while any exists (1.3.14+).
    AppMutex,
    /// `DefaultUserInfoName`: the User Information page's default name
    /// (3.0.0+).
    DefaultUserInfoName,
    /// `DefaultUserInfoOrg`: its default organization (3.0.0+).
    DefaultUserInfoOrg,
    /// `DefaultUserInfoSerial`: its default serial number (4.0.0+).
    DefaultUserInfoSerial,
    /// `AppReadmeFile`: a file or URL shown in Add/Remove Programs (4.2.4+).
    AppReadmeFile,
    /// `AppContact`: shown in Add/Remove Programs (4.2.4+).
    AppContact,
    /// `AppComments`: shown in Add/Remove Programs (4.2.4+).
    AppComments,
    /// `AppModifyPath`: the command a "Modify" button in Add/Remove Programs
    /// runs (4.2.4+).
    AppModifyPath,
    /// `CreateUninstallRegKey`: `yes`, `no` or a `[Code]` expression;
    /// whether Setup creates the Add/Remove Programs entry (5.3.8+; a flag
    /// before).
    CreateUninstallRegKey,
    /// `Uninstallable`: `yes`, `no` or a `[Code]` expression; whether the
    /// uninstaller is installed (5.3.10+; a flag before).
    Uninstallable,
    /// `CloseApplicationsFilter`: wildcards of the files whose users Setup
    /// offers to close (5.5.0+).
    CloseApplicationsFilter,
    /// `SetupMutex`: comma-separated mutexes Setup creates so a second Setup
    /// refuses to start (5.5.6+).
    SetupMutex,
    /// `ChangesEnvironment`: `yes`, `no` or a `[Code]` expression; whether
    /// Setup broadcasts an environment change at the end (5.6.1+; a flag
    /// before).
    ChangesEnvironment,
    /// `ChangesAssociations`: likewise, for refreshing file associations
    /// (5.6.1+; a flag before).
    ChangesAssociations,
    /// `ArchitecturesAllowed`: the architecture expression Setup may run
    /// on, e.g. `x64compatible` (6.3.0+; a set in [`HeaderTail`] before).
    ArchitecturesAllowed,
    /// `ArchitecturesInstallIn64BitMode`: the expression enabling 64-bit
    /// install mode (6.3.0+; a set in [`HeaderTail`] before).
    ArchitecturesInstallIn64BitMode,
    /// `CloseApplicationsFilterExcludes`: wildcards excluded from
    /// `CloseApplicationsFilter` (6.4.2+).
    CloseApplicationsFilterExcludes,
    /// The 7-Zip DLL `ArchiveExtraction` selects, e.g. `is7zxa.dll`; empty
    /// for the built-in `basic` decoder (6.5.0+).
    SevenZipLibraryName,
    /// `UsePreviousAppDir`: `yes`, `no` or a `[Code]` expression; whether a
    /// reinstall defaults to the previous directory (6.7.0+; a flag
    /// before).
    UsePreviousAppDir,
    /// `UsePreviousGroup`: likewise for the Start menu folder (6.7.0+; a
    /// flag before).
    UsePreviousGroup,
    /// `UsePreviousSetupType`: likewise for the setup type and components
    /// (6.7.0+; a flag before).
    UsePreviousSetupType,
    /// `UsePreviousTasks`: likewise for the tasks (6.7.0+; a flag before).
    UsePreviousTasks,
    /// `UsePreviousUserInfo`: likewise for the user information (6.7.0+; a
    /// flag before).
    UsePreviousUserInfo,
}

/// A raw-bytes field of the setup header, read with [`SetupHeader::ansi`].
/// Before 5.2.5 these sit among the strings; from 5.2.5 they follow them.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderAnsi {
    /// `LicenseFile`'s contents, RTF or plain text, as stored. Languages may
    /// have their own ([`crate::records::language::LanguageEntry`]).
    LicenseText,
    /// `InfoBeforeFile`'s contents, shown before installing.
    InfoBeforeText,
    /// `InfoAfterFile`'s contents, shown after installing.
    InfoAfterText,
    /// `SignedUninstallerSignature`: the uninstaller's Authenticode
    /// signature, which Setup attaches to the uninstaller it writes
    /// (`SignedUninstaller=yes`, 5.2.1 to 5.3.9; a `String` before 5.2.5,
    /// bytes either way).
    SignedUninstallerSignature,
    /// The compiled `[Code]` section, an IFPS container
    /// ([`crate::InnoInstaller::compiledcode`] parses it) (4.0.0+).
    CompiledCodeText,
}

/// How many records of each type follow the header in setup-0
/// (`Num*Entries`). A count the version does not have is 0.
#[derive(Clone, Copy, Debug, Default)]
pub struct EntryCounts {
    /// `NumLanguageEntries` (4.0.0+).
    pub languages: u32,
    /// `NumCustomMessageEntries` (4.2.1+).
    pub custom_messages: u32,
    /// `NumPermissionEntries` (4.1.0+).
    pub permissions: u32,
    /// `NumTypeEntries` (2.0.0+).
    pub types: u32,
    /// `NumComponentEntries` (2.0.0+).
    pub components: u32,
    /// `NumTaskEntries` (2.0.0+).
    pub tasks: u32,
    /// `NumDirEntries`.
    pub directories: u32,
    /// `NumISSigKeyEntries` (6.5.0+; `None` before).
    pub iss_sig_keys: Option<u32>,
    /// `NumFileEntries`.
    pub files: u32,
    /// `NumFileLocationEntries`: the data entries in setup-0's second
    /// block.
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

/// One `TSetupHeaderOption` flag: a yes/no `[Setup]` directive, or a fact
/// the compiler records, set in `TSetupHeader.Options`. The bit each
/// occupies varies by version; [`SetupHeader::options`] decodes them. The
/// variants are the union over every release, each documented with the
/// directive that sets it and the releases that have it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderOption {
    /// `shDisableStartupPrompt` (`DisableStartupPrompt=yes`): no "This will
    /// install..." prompt at startup.
    DisableStartupPrompt,
    /// `shCreateAppDir` (`CreateAppDir=yes`, the default): there is an
    /// application directory; without it `{app}` is `{win}` and no directory
    /// page is shown.
    CreateAppDir,
    /// `shAllowNoIcons` (`AllowNoIcons=yes`): the Start menu page offers "Don't
    /// create a Start menu folder".
    AllowNoIcons,
    /// `shAlwaysRestart` (`AlwaysRestart=yes`): ask to restart Windows after
    /// every successful install (absent in 3.0.0 to 3.0.2).
    AlwaysRestart,
    /// `shAlwaysUsePersonalGroup` (`AlwaysUsePersonalGroup=yes`): `{group}` is
    /// always the current user's Start menu.
    AlwaysUsePersonalGroup,
    /// `shWindowVisible` (`WindowVisible=yes`): show the full-screen background
    /// window (before SetupID 6.4.0.1).
    WindowVisible,
    /// `shWindowShowCaption` (`WindowShowCaption=yes`): the background window
    /// has a caption (before 6.4.0.1).
    WindowShowCaption,
    /// `shWindowResizable` (`WindowResizable=yes`): the background window can
    /// be resized (before 6.4.0.1).
    WindowResizable,
    /// `shWindowStartMaximized` (`WindowStartMaximized=yes`): the background
    /// window starts maximized (before 6.4.0.1).
    WindowStartMaximized,
    /// `shEnableDirDoesntExistWarning` (`EnableDirDoesntExistWarning=yes`):
    /// warn when the chosen directory does not exist.
    EnableDirDoesntExistWarning,
    /// `shPassword` (`Password=`): Setup asks for a password. The verifier is
    /// in [`HeaderTail`] or [`crate::EncryptionInfo`]; see
    /// [`crate::InnoInstaller::from_bytes_with_passwords`].
    Password,
    /// `shAllowRootDirectory` (`AllowRootDirectory=yes`): a drive's root may be
    /// the installation directory (1.2.6+).
    AllowRootDirectory,
    /// `shDisableFinishedPage` (`DisableFinishedPage=yes`): no Setup Completed
    /// page (1.2.14+).
    DisableFinishedPage,
    /// `shUsePreviousAppDir` (`UsePreviousAppDir=yes`): a reinstall defaults to
    /// the previous directory (1.3.1 to 6.7.0; then
    /// [`HeaderString::UsePreviousAppDir`]).
    UsePreviousAppDir,
    /// `shBackColorHorizontal` (`BackColorDirection=lefttoright`): the
    /// background window's gradient runs horizontally (1.3.3 to 6.4.0.1).
    BackColorHorizontal,
    /// `shUsePreviousGroup` (`UsePreviousGroup=yes`): a reinstall defaults to
    /// the previous Start menu folder (1.3.10 to 6.7.0; then
    /// [`HeaderString::UsePreviousGroup`]).
    UsePreviousGroup,
    /// `shUpdateUninstallLogAppName` (`UpdateUninstallLogAppName=yes`):
    /// appending to an uninstall log replaces its `AppName` (1.3.20+).
    UpdateUninstallLogAppName,
    /// `shUsePreviousSetupType` (`UsePreviousSetupType=yes`): a reinstall
    /// defaults to the previous setup type and components (2.0.0 to 6.7.0; then
    /// a string).
    UsePreviousSetupType,
    /// `shDisableReadyMemo` (`DisableReadyMemo=yes`): the Ready to Install page
    /// shows no settings list (2.0.0+).
    DisableReadyMemo,
    /// `shAlwaysShowComponentsList` (`AlwaysShowComponentsList=yes`): always
    /// show the components list (2.0.0+).
    AlwaysShowComponentsList,
    /// `shFlatComponentsList` (`FlatComponentsList=yes`): flat rather than 3D
    /// checkboxes in the components list (2.0.0+).
    FlatComponentsList,
    /// `shShowComponentSizes` (`ShowComponentSizes=yes`): show each component's
    /// size (2.0.0+).
    ShowComponentSizes,
    /// `shUsePreviousTasks` (`UsePreviousTasks=yes`): a reinstall defaults to
    /// the previous tasks (2.0.0 to 6.7.0; then a string).
    UsePreviousTasks,
    /// `shDisableReadyPage` (`DisableReadyPage=yes`): no Ready to Install page
    /// (2.0.0+).
    DisableReadyPage,
    /// `shAlwaysShowDirOnReadyPage` (`AlwaysShowDirOnReadyPage=yes`): the Ready
    /// to Install page always lists the directory (2.0.7+).
    AlwaysShowDirOnReadyPage,
    /// `shAlwaysShowGroupOnReadyPage` (`AlwaysShowGroupOnReadyPage=yes`): it
    /// always lists the Start menu folder (2.0.7+).
    AlwaysShowGroupOnReadyPage,
    /// `shAllowUNCPath` (`AllowUNCPath=yes`, the default): the directory may be
    /// a UNC path (2.0.18+).
    AllowUNCPath,
    /// `shUserInfoPage` (`UserInfoPage=yes`): show the User Information page
    /// (3.0.0+).
    UserInfoPage,
    /// `shUsePreviousUserInfo` (`UsePreviousUserInfo=yes`): a reinstall
    /// defaults to the previous user information (3.0.0 to 6.7.0; then a
    /// string).
    UsePreviousUserInfo,
    /// `shUninstallRestartComputer` (`UninstallRestartComputer=yes`): the
    /// uninstaller always asks to restart (3.0.1+).
    UninstallRestartComputer,
    /// `shRestartIfNeededByRun` (`RestartIfNeededByRun=yes`): ask to restart
    /// when a `[Run]` program queued files for replacement at reboot (3.0.3+).
    RestartIfNeededByRun,
    /// `shShowTasksTreeLines` (`ShowTasksTreeLines=yes`): tree lines between
    /// parent and child tasks (4.0.0+).
    ShowTasksTreeLines,
    /// `shAllowCancelDuringInstall` (`AllowCancelDuringInstall=yes`): the user
    /// may cancel while files are installed (4.0.9+; always allowed before, so
    /// [`SetupHeader::options`] includes it).
    AllowCancelDuringInstall,
    /// `shWizardImageStretch` (`WizardImageStretch=yes`): wizard images are
    /// scaled to fit (4.1.3+).
    WizardImageStretch,
    /// `shAppendDefaultDirName` (`AppendDefaultDirName=yes`): browsing for a
    /// directory appends `DefaultDirName`'s last part (4.1.8+).
    AppendDefaultDirName,
    /// `shAppendDefaultGroupName` (`AppendDefaultGroupName=yes`): browsing for
    /// a Start menu folder appends `DefaultGroupName`'s last part (4.1.8+).
    AppendDefaultGroupName,
    /// `shEncryptionUsed` (`Encryption=yes`): files are stored encrypted (4.2.2
    /// to 6.5.0; then [`crate::EncryptionInfo`]).
    EncryptionUsed,
    /// `shSetupLogging` (`SetupLogging=yes`): Setup always writes a log, as
    /// `/LOG` does (5.1.13+).
    SetupLogging,
    /// `shSignedUninstaller` (`SignedUninstaller=yes`): the uninstaller carries
    /// the signature the compiler made for it (5.2.1+).
    SignedUninstaller,
    /// `shUsePreviousLanguage` (`UsePreviousLanguage=yes`): a reinstall
    /// defaults to the previous language (5.3.8+).
    UsePreviousLanguage,
    /// `shDisableWelcomePage` (`DisableWelcomePage=yes`): no Welcome page
    /// (5.3.9+).
    DisableWelcomePage,
    /// `shCloseApplications` (`CloseApplications=yes` or `force`): offer to
    /// close applications using files Setup replaces (5.5.0+).
    CloseApplications,
    /// `shRestartApplications` (`RestartApplications=yes`): restart the
    /// applications closed (5.5.0+).
    RestartApplications,
    /// `shAllowNetworkDrive` (`AllowNetworkDrive=yes`, the default): the
    /// directory may be on a network drive (5.5.0+; always allowed before, so
    /// [`SetupHeader::options`] includes it).
    AllowNetworkDrive,
    /// `shForceCloseApplications` (`CloseApplications=force`): close them
    /// without asking in a silent install (5.5.7+).
    ForceCloseApplications,
    /// `shAppNameHasConsts`: the compiler found constants in `AppName`, so
    /// Setup expands it (6.0.0+).
    AppNameHasConsts,
    /// `shUsePreviousPrivileges` (`UsePreviousPrivileges=yes`): a reinstall
    /// uses the previous install mode, administrative or per-user (6.0.0+).
    UsePreviousPrivileges,
    /// `shWizardResizable` (`WizardResizable=yes`): the wizard window can be
    /// resized (6.0.0 to 6.6.0).
    WizardResizable,
    /// `shUninstallLogging` (`UninstallLogging=yes`): the uninstaller always
    /// writes a log (6.3.0+).
    UninstallLogging,
    /// `shUninstallable` (before 5.3.10; then the `Uninstallable` string).
    Uninstallable,
    /// `shDisableDirPage` (before 5.3.3; then the `DisableDirPage` enum).
    DisableDirPage,
    /// `shDisableDirExistsWarning` (before 1.3.6).
    DisableDirExistsWarning,
    /// `shDisableProgramGroupPage` (before 5.3.3; then an enum).
    DisableProgramGroupPage,
    /// `shBackSolid` (before 1.3.3).
    BackSolid,
    /// `shDisableAppendDir` (before 4.1.2).
    DisableAppendDir,
    /// `shAdminPrivilegesRequired` (32-bit builds before 3.0.4; then `PrivilegesRequired`).
    AdminPrivilegesRequired,
    /// `shAlwaysCreateUninstallIcon` (32-bit builds before 3.0.0).
    AlwaysCreateUninstallIcon,
    /// `shOverwriteUninstRegEntries` (32-bit builds before 1.3.6).
    OverwriteUninstRegEntries,
    /// `shChangesAssociations` (32-bit builds before 6.0; then a string).
    ChangesAssociations,
    /// `shCreateUninstallRegKey` (1.3.0 to 5.3.8; then a string).
    CreateUninstallRegKey,
    /// `shBzipUsed` (2.0.17 to 4.1.5).
    BzipUsed,
    /// `shShowLanguageDialog` (4.0.0 to 4.0.10; then an enum).
    ShowLanguageDialog,
    /// `shDetectLanguageUsingLocale` (4.0.1 to 4.0.10).
    DetectLanguageUsingLocale,
    /// `shChangesEnvironment` (5.0.4 to 6.0; then a string).
    ChangesEnvironment,
    /// `shShowUndisplayableLanguages` (ANSI builds, 5.1.7 to 6.0).
    ShowUndisplayableLanguages,
    /// `shWizardModern` (6.6.0+).
    WizardModern,
    /// `shWizardBorderStyled` (6.6.0+).
    WizardBorderStyled,
    /// `shWizardKeepAspectRatio` (6.6.0+).
    WizardKeepAspectRatio,
    /// `shWizardLightButtonsUnstyled` (6.6.x).
    WizardLightButtonsUnstyled,
    /// `shRedirectionGuard` (6.7.0+).
    RedirectionGuard,
    /// `shWizardBevelsHidden` (6.7.0+).
    WizardBevelsHidden,
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
    Uninstallable => "uninstallable",
    DisableDirPage => "disable_dir_page",
    DisableDirExistsWarning => "disable_dir_exists_warning",
    DisableProgramGroupPage => "disable_program_group_page",
    BackSolid => "back_solid",
    DisableAppendDir => "disable_append_dir",
    AdminPrivilegesRequired => "admin_privileges_required",
    AlwaysCreateUninstallIcon => "always_create_uninstall_icon",
    OverwriteUninstRegEntries => "overwrite_uninst_reg_entries",
    ChangesAssociations => "changes_associations",
    CreateUninstallRegKey => "create_uninstall_reg_key",
    BzipUsed => "bzip_used",
    ShowLanguageDialog => "show_language_dialog",
    DetectLanguageUsingLocale => "detect_language_using_locale",
    ChangesEnvironment => "changes_environment",
    ShowUndisplayableLanguages => "show_undisplayable_languages",
    WizardModern => "wizard_modern",
    WizardBorderStyled => "wizard_border_styled",
    WizardKeepAspectRatio => "wizard_keep_aspect_ratio",
    WizardLightButtonsUnstyled => "wizard_light_buttons_unstyled",
    RedirectionGuard => "redirection_guard",
    WizardBevelsHidden => "wizard_bevels_hidden",
});

/// `WizardStyle` (`TSetupWizardStyle`, 6.0.0 to 6.6.0): the wizard's look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WizardStyle {
    /// `wsClassic` (`classic`): the Inno Setup 5 look.
    Classic,
    /// `wsModern` (`modern`): the larger Inno Setup 6 look.
    Modern,
}

stable_name_enum!(WizardStyle, { Self::Classic => "classic", Self::Modern => "modern" });

/// `WizardStyle`'s light/dark part (`TSetupWizardDarkStyle`, 6.6.0+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WizardDarkStyle {
    /// `wdsLight` (`light`, the default).
    Light,
    /// `wdsDark` (`dark`).
    Dark,
    /// `wdsDynamic` (`dynamic`): follow the Windows app theme.
    Dynamic,
}

stable_name_enum!(WizardDarkStyle, {
    Self::Light => "light",
    Self::Dark => "dark",
    Self::Dynamic => "dynamic",
});

/// How much of the wizard the light theme styles
/// (`TSetupWizardLightControlStyling`, 6.7.0+; `WizardStyle` modifiers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WizardLightControlStyling {
    /// `wcsAll`: every control.
    All,
    /// `wcsAllButButtons` (`excludelightbuttons`): all but the buttons.
    AllButButtons,
    /// `wcsOnlyRequired` (`excludelightcontrols`): only what must be.
    OnlyRequired,
}

stable_name_enum!(WizardLightControlStyling, {
    Self::All => "all",
    Self::AllButButtons => "all_but_buttons",
    Self::OnlyRequired => "only_required",
});

/// `InstallMode` (2.0.0 to 5.0.0): how Setup ran by default before the
/// `/SILENT` switches took over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallMode {
    /// `imNormal`: the wizard.
    Normal,
    /// `imSilent`: a progress window only.
    Silent,
    /// `imVerySilent`: nothing shown.
    VerySilent,
}

stable_name_enum!(InstallMode, {
    Self::Normal => "normal",
    Self::Silent => "silent",
    Self::VerySilent => "very_silent",
});

/// `UninstallStyle` (2.0.0 to 5.0.0): the uninstaller's look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UninstallStyle {
    /// `usClassic`.
    Classic,
    /// `usModern`; every release from 5.0.0 on.
    Modern,
}

stable_name_enum!(UninstallStyle, {
    Self::Classic => "classic",
    Self::Modern => "modern",
});

/// `WizardImageAlphaFormat`: how 32-bit wizard images' alpha channel is
/// read (5.5.7+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageAlphaFormat {
    /// `afIgnored` (`none`): no alpha.
    Ignored,
    /// `afDefined` (`defined`): straight alpha.
    Defined,
    /// `afPremultiplied` (`premultiplied`): premultiplied alpha.
    Premultiplied,
}

stable_name_enum!(ImageAlphaFormat, {
    Self::Ignored => "ignored",
    Self::Defined => "defined",
    Self::Premultiplied => "premultiplied",
});

/// `UninstallLogMode`: what Setup does with an existing uninstall log
/// (1.3.0+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UninstallLogMode {
    /// `lmAppend` (`append`, the default): add to it, so one uninstall
    /// removes every installation.
    Append,
    /// `lmNew` (`new`): start a new log, `unins001` and so on.
    New,
    /// `lmOverwrite` (`overwrite`): replace it.
    Overwrite,
}

stable_name_enum!(UninstallLogMode, {
    Self::Append => "append",
    Self::New => "new",
    Self::Overwrite => "overwrite",
});

/// `auto` / `no` / `yes`, the values of `DirExistsWarning` (`ddAuto`, ...)
/// and of `DisableDirPage` / `DisableProgramGroupPage` (`dpAuto`, ...).
/// `auto` means: decided at install time, e.g. shown only on a first
/// installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AutoNoYes {
    /// `auto`.
    Auto,
    /// `no`.
    No,
    /// `yes`.
    Yes,
}

stable_name_enum!(AutoNoYes, { Self::Auto => "auto", Self::No => "no", Self::Yes => "yes" });

/// `ShowLanguageDialog`'s values (`slYes`, `slNo`, `slAuto`): `auto`
/// shows the language dialog only when no language matches the user's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum YesNoAuto {
    /// `yes`.
    Yes,
    /// `no`.
    No,
    /// `auto`.
    Auto,
}

stable_name_enum!(YesNoAuto, { Self::Yes => "yes", Self::No => "no", Self::Auto => "auto" });

/// `PrivilegesRequired`: the privileges Setup runs with (3.0.4+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegesRequired {
    /// `prNone` (`none`): whatever the user has.
    None,
    /// `prPowerUser` (`poweruser`): Power Users or administrators; removed
    /// in 7.2.0.
    PowerUser,
    /// `prAdmin` (`admin`): administrators, elevating on Vista and later.
    Admin,
    /// `prLowest` (`lowest`): never elevate; installs per user (5.3.7+).
    Lowest,
}

stable_name_enum!(PrivilegesRequired, {
    Self::None => "none",
    Self::PowerUser => "power_user",
    Self::Admin => "admin",
    Self::Lowest => "lowest",
});

/// `LanguageDetectionMethod`: how Setup picks the default language
/// (4.0.10+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LanguageDetectionMethod {
    /// `ldUILanguage` (`uilanguage`): match the user's UI language.
    UiLanguage,
    /// `ldLocale` (`locale`): match the user's locale.
    Locale,
    /// `ldNone` (`none`): the first language.
    None,
}

stable_name_enum!(LanguageDetectionMethod, {
    Self::UiLanguage => "ui_language",
    Self::Locale => "locale",
    Self::None => "none",
});

/// `CompressMethod` (`TSetupCompressMethod`, 4.1.5+): how setup-1's chunks
/// are compressed. Setup-0's own blocks are reported by
/// [`crate::Compression`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressMethod {
    /// `cmStored` (`none`): not compressed (4.2.5+).
    Stored,
    /// `cmZip` (`zip`): zlib.
    Zlib,
    /// `cmBzip` (`bzip`): bzip2.
    Bzip2,
    /// `cmLZMA` (`lzma`): LZMA.
    Lzma1,
    /// `cmLZMA2` (`lzma2`, 5.3.9+).
    Lzma2,
}

stable_name_enum!(CompressMethod, {
    Self::Stored => "stored",
    Self::Zlib => "zlib",
    Self::Bzip2 => "bzip2",
    Self::Lzma1 => "lzma1",
    Self::Lzma2 => "lzma2",
});

/// A processor architecture of `ArchitecturesAllowed` /
/// `ArchitecturesInstallIn64BitMode`. From 5.1.0 to 6.3.0 those directives
/// are a set of `TSetupProcessorArchitecture` in [`HeaderTail`]; from 6.3.0
/// boolean expressions over identifiers such as `x64compatible`
/// ([`HeaderString::ArchitecturesAllowed`]).
/// [`crate::InnoInstaller::architecture`] reads either.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum Architecture {
    /// `paUnknown`: a processor Setup does not recognize.
    Unknown,
    /// `paX86` (`x86`).
    X86,
    /// `paX64` (`x64`; `paAMD64` in 5.1.0 and 5.1.1).
    Amd64,
    /// `paIA64` (`ia64`, before 6.3.0).
    IA64,
    /// `arm32compatible`: 32-bit Arm, only in the 6.3.0+ expressions.
    Arm32,
    /// `paARM64` (`arm64`, SetupID 5.5.7+).
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
pub enum PrivilegesRequiredOverride {
    /// `proCommandLine` - the `/ALLUSERS` / `/CURRENTUSER` command-line
    /// switches may override `PrivilegesRequired`.
    Commandline,
    /// `proDialog` - Setup may ask the user which install mode to use.
    Dialog,
}

stable_name_enum!(PrivilegesRequiredOverride, {
    Self::Commandline => "command_line",
    Self::Dialog => "dialog",
});

/// The setup header's fixed part (`TSetupHeader` after its strings and
/// counts): versions, colours, wizard layout, password verifiers, the
/// choices behind several wizard pages, and the `Options` flags. A field
/// the version does not have is `None`, empty or 0, as each says. An enum
/// field this crate decodes has a `*_raw` twin with the byte as stored,
/// and is `None` for a value it does not know.
#[derive(Clone, Debug, Default)]
pub struct HeaderTail {
    /// `CompiledCodeVersion` (SetupID 7.0.0.3+): the compiler's
    /// `SetupBinVersion`, a `(major << 24) | (minor << 16) | (patch << 8) |
    /// build` quad, with bit 31 set when the compiled `[Code]` targets a
    /// 64-bit Setup (`SetupArchitecture=x64`); 0 when there is no `[Code]`,
    /// since Setup checks it only before running compiled code. `None`
    /// before 7.0.0.3, including the 7.0 previews that write `(7.0.0.1)`.
    pub compiled_code_version: Option<u32>,

    /// `MinVersion` / `OnlyBelowVersion`: the Windows versions Setup runs
    /// on.
    pub windows_version_range: WindowsVersionRange,

    /// `BackColor`: the background window's colour, a `TColor`
    /// (`0x00BBGGRR`) (before SetupID 6.4.0.1).
    pub back_color: Option<u32>,
    /// `BackColor2`: its gradient's second colour (1.3.3 to 6.4.0.1).
    pub back_color2: Option<u32>,
    /// `WizardImageBackColor`: the colour behind the wizard image, a
    /// `TColor` (before 5.5.7, and again from 6.5.2).
    pub wizard_image_back_color: Option<u32>,
    /// `WizardSmallImageBackColor`: the colour behind the small wizard
    /// image (2.0.0 to 5.0.4, and again from 6.5.2).
    pub wizard_small_image_back_color: Option<u32>,
    /// `WizardBackColor`: the wizard window's background colour (6.7.0+).
    pub wizard_back_color: Option<u32>,
    /// `WizardImageBackColor` in dark mode (`...DynamicDark`, 6.6.0+).
    pub wizard_image_back_color_dynamic_dark: Option<u32>,
    /// `WizardSmallImageBackColor` in dark mode (6.6.0+).
    pub wizard_small_image_back_color_dynamic_dark: Option<u32>,
    /// `WizardBackColor` in dark mode (6.7.0+).
    pub wizard_back_color_dynamic_dark: Option<u32>,
    /// `WizardImageOpacity`: 0 to 255 (6.6.1+).
    pub wizard_image_opacity: Option<u8>,
    /// `WizardBackImageOpacity`: 0 to 255 (6.7.0+).
    pub wizard_back_image_opacity: Option<u8>,

    /// `WizardStyle` (`classic` or `modern`, 6.0.0 to 6.6.0); `None` from
    /// 6.6.0, where the byte is [`Self::wizard_dark_style`].
    pub wizard_style: Option<WizardStyle>,
    /// `WizardStyle` (6.0.0 to 6.6.0) or `WizardDarkStyle` (6.6.0+) as
    /// stored; 0 before 6.0.0.
    pub wizard_style_raw: u8,
    /// `WizardDarkStyle`: `light`, `dark` or `dynamic` (6.6.0+).
    pub wizard_dark_style: Option<WizardDarkStyle>,
    /// `WizardLightControlStyling`, decoded (6.7.0+).
    pub wizard_light_control_styling: Option<WizardLightControlStyling>,
    /// `WizardLightControlStyling` as stored; 0 before 6.7.0.
    pub wizard_light_control_styling_raw: u8,
    /// `WizardSizePercent`'s horizontal part: the wizard's width as a
    /// percentage of its default (6.0.0+; 0 before).
    pub wizard_size_percent_x: u32,
    /// `WizardSizePercent`'s vertical part (6.0.0+; 0 before).
    pub wizard_size_percent_y: u32,
    /// `WizardImageAlphaFormat`, decoded (5.5.7+).
    pub wizard_image_alpha_format: Option<ImageAlphaFormat>,
    /// `WizardImageAlphaFormat` as stored; 0 before 5.5.7.
    pub wizard_image_alpha_format_raw: u8,

    /// `PasswordHash`: SHA-1 of `PasswordCheckHash` + salt + password
    /// (5.3.9 to 6.4.0).
    pub legacy_password_sha1: Option<[u8; 20]>,
    /// `PasswordHash`: MD5 of the password, salted from 4.2.2 (4.2.0 to
    /// 5.3.9).
    pub legacy_password_md5: Option<[u8; 16]>,
    /// `Password`: CRC-32 of the password (before 4.2.0).
    pub legacy_password_crc32: Option<u32>,
    /// `PasswordSalt` (4.2.2 to 6.4.0).
    pub legacy_password_salt: Option<[u8; 8]>,
    /// `PasswordTest`: the PBKDF2/XChaCha20 verifier (6.4.x; from 6.5.0 in
    /// [`crate::EncryptionInfo`]).
    pub password_test: Option<u32>,
    /// `EncryptionKDFSalt` (6.4.x).
    pub encryption_kdf_salt: Option<[u8; 16]>,
    /// `EncryptionKDFIterations` (6.4.x).
    pub encryption_kdf_iterations: Option<u32>,
    /// `EncryptionBaseNonce` (6.4.x).
    pub encryption_base_nonce: Option<[u8; 24]>,

    /// `ExtraDiskSpaceRequired`: bytes Setup needs beyond the files (64-bit
    /// from 4.0.0).
    pub extra_disk_space_required: i64,
    /// `SlicesPerDisk`: with `DiskSpanning`, the number of slices per disk
    /// (4.0.0+; 1 before).
    pub slices_per_disk: u32,

    /// `InstallMode`, decoded (2.0.0 to 5.0.0).
    pub install_mode: Option<InstallMode>,
    /// `InstallMode` as stored; 0 when the version has no such byte.
    pub install_mode_raw: u8,
    /// `UninstallLogMode`: `append`, `new` or `overwrite` (1.3.0+).
    pub uninstall_log_mode: Option<UninstallLogMode>,
    /// `UninstallLogMode` as stored; 0 before 1.3.0.
    pub uninstall_log_mode_raw: u8,
    /// `UninstallStyle`, decoded (2.0.0 to 5.0.0).
    pub uninstall_style: Option<UninstallStyle>,
    /// `UninstallStyle` as stored; 0 when the version has no such byte.
    pub uninstall_style_raw: u8,
    /// `DirExistsWarning`: whether choosing an existing directory warns
    /// (1.3.6+).
    pub dir_exists_warning: Option<AutoNoYes>,
    /// `DirExistsWarning` as stored; 0 before 1.3.6.
    pub dir_exists_warning_raw: u8,
    /// `PrivilegesRequired`: the privileges Setup asks for (3.0.4+; the
    /// [`HeaderOption::AdminPrivilegesRequired`] flag before).
    pub privileges_required: Option<PrivilegesRequired>,
    /// `PrivilegesRequired` as stored; 0 before 3.0.4.
    pub privileges_required_raw: u8,
    /// `PrivilegesRequiredOverridesAllowed`, decoded (6.0.0+).
    pub privileges_required_overrides: HashSet<PrivilegesRequiredOverride>,
    /// `PrivilegesRequiredOverridesAllowed` as stored; empty before 6.0.0.
    pub privileges_required_overrides_raw: Vec<u8>,
    /// `ShowLanguageDialog` (4.0.10+; flags before).
    pub show_language_dialog: Option<YesNoAuto>,
    /// `ShowLanguageDialog` as stored; 0 before 4.0.10.
    pub show_language_dialog_raw: u8,
    /// `LanguageDetectionMethod` (4.0.10+).
    pub language_detection_method: Option<LanguageDetectionMethod>,
    /// `LanguageDetectionMethod` as stored; 0 before 4.0.10.
    pub language_detection_method_raw: u8,
    /// `CompressMethod`: how setup-1's compressed chunks are compressed
    /// (stored from 4.1.5; before, bzip2 when [`HeaderOption::BzipUsed`] is
    /// set and zlib otherwise). A chunk whose data entry lacks
    /// [`crate::records::dataentry::DataFlag::ChunkCompressed`] is stored
    /// as is. `None` for a byte this crate does not know.
    pub compress_method: Option<CompressMethod>,
    /// `CompressMethod` as stored; 0 before 4.1.5.
    pub compress_method_raw: u8,

    /// `ArchitecturesAllowed` as a set (5.1.0 to 6.3.0; then
    /// [`HeaderString::ArchitecturesAllowed`]). Empty means any.
    pub architectures_allowed: Option<HashSet<Architecture>>,
    /// That set as stored.
    pub architectures_allowed_raw: Option<u8>,
    /// `ArchitecturesInstallIn64BitMode` as a set (5.1.0 to 6.3.0; then a
    /// string). Empty means never.
    pub architectures_install_in_64bit_mode: Option<HashSet<Architecture>>,
    /// That set as stored.
    pub architectures_install_in_64bit_mode_raw: Option<u8>,

    /// `SignedUninstallerOrigSize`: the size of the uninstaller before
    /// signing (5.2.1 to 5.3.10).
    pub signed_uninstaller_original_size: Option<u32>,
    /// `SignedUninstallerHdrChecksum`: its PE header checksum (5.2.1 to
    /// 5.3.10).
    pub signed_uninstaller_header_checksum: Option<u32>,

    /// `DisableDirPage`: whether the Select Destination Location page is
    /// skipped (5.3.3+; a flag before).
    pub disable_dir_page: Option<AutoNoYes>,
    /// `DisableDirPage` as stored; 0 before 5.3.3.
    pub disable_dir_page_raw: u8,
    /// `DisableProgramGroupPage`: likewise for the Start menu page (5.3.3+;
    /// a flag before).
    pub disable_program_group_page: Option<AutoNoYes>,
    /// `DisableProgramGroupPage` as stored; 0 before 5.3.3.
    pub disable_program_group_page_raw: u8,

    /// `UninstallDisplaySize`: the size Add/Remove Programs shows, in bytes;
    /// 0 lets Setup compute it (5.3.6+; 64-bit from 5.5.0).
    pub uninstall_display_size: u64,

    /// `LeadBytes`: the ANSI code page's double-byte lead bytes, a 256-bit
    /// set (ANSI builds from 2.0.6 to 6.3.0).
    pub lead_bytes: Option<[u8; 32]>,

    /// `Options`, decoded; see [`HeaderOption`]. Includes the flags innoextract
    /// adds for old versions and the 3.0.0 to 3.0.2 restart byte.
    pub options: HashSet<HeaderOption>,
    /// `Options` as stored: the set's bytes, whose size grows with the
    /// number of flags the version defines.
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
    /// the last counter).
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
        if version.at_least(1, 3, 0) {
            let (mut header, _) = Self::read_record(&mut reader, version)?;
            header.records_offset = reader.pos();
            return Ok(header);
        }
        // Before 1.3.0 the header follows a u32 holding its size, and the
        // license and info texts follow it, their sizes in the header
        // (1.2.16 `MAIN.PAS`). They are what later releases keep in the
        // `AnsiString` fields, and are exposed as those.
        let size = reader.u32_le("TSetupHeader size")?;
        let size = usize::try_from(size).map_err(|_| Error::Overflow {
            what: "TSetupHeader size",
        })?;
        let start = reader.pos();
        let mut record = Reader::new(reader.take(size, "TSetupHeader")?);
        let (mut header, text_sizes) = Self::read_record(&mut record, version)?;
        if record.remaining() != 0 {
            return Err(Error::TrailingData {
                what: "setup header",
                len: record.remaining(),
            });
        }
        header.tail_start_offset = header.tail_start_offset.saturating_add(start);
        for (field, size) in [
            HeaderAnsi::LicenseText,
            HeaderAnsi::InfoBeforeText,
            HeaderAnsi::InfoAfterText,
        ]
        .into_iter()
        .zip(text_sizes)
        {
            let size = usize::try_from(size).map_err(|_| Error::Overflow {
                what: "header text size",
            })?;
            header
                .ansi
                .insert(field, reader.take(size, "header text")?.to_vec());
        }
        header.records_offset = reader.pos();
        Ok(header)
    }

    /// Reads the `TSetupHeader` record itself; `records_offset` is left
    /// for [`Self::parse`]. Also returns the sizes of the license and info
    /// texts that follow the record before 1.3.0 (zero later).
    fn read_record(reader: &mut Reader<'_>, version: &Version) -> Result<(Self, [u32; 3]), Error> {
        let mut strings: HashMap<HeaderString, String> = HashMap::with_capacity(40);
        let mut ansi: HashMap<HeaderAnsi, Vec<u8>> = HashMap::with_capacity(4);
        read_header_strings_and_ansi(reader, version, &mut strings, &mut ansi)?;

        // ANSI-build LeadBytes set (`set of AnsiChar` = 256 bits = 32
        // bytes). Present for non-Unicode installers from 2.0.6 onward;
        // removed at 6.3.0 when the ANSI build was dropped (innoextract
        // `setup/header.cpp`).
        let lead_bytes =
            if version.at_least(2, 0, 6) && !version.at_least(6, 3, 0) && !version.is_unicode() {
                Some(reader.array::<32>("LeadBytes")?)
            } else {
                None
            };

        let counts = read_counts(reader, version)?;
        let tail_start_offset = reader.pos();
        // `LicenseSize`, `InfoBeforeSize`, `InfoAfterSize` (before 1.3.0).
        let mut text_sizes = [0u32; 3];
        if !version.at_least(1, 3, 0) {
            for (size, what) in
                text_sizes
                    .iter_mut()
                    .zip(["LicenseSize", "InfoBeforeSize", "InfoAfterSize"])
            {
                *size = reader.native_u32(version, what)?;
            }
        }
        let mut tail = parse_tail(reader, version)?;
        tail.lead_bytes = lead_bytes;

        Ok((
            Self {
                strings,
                ansi,
                counts,
                tail,
                records_offset: 0,
                tail_start_offset,
            },
            text_sizes,
        ))
    }

    /// Returns the value of a header `String` field, if present in
    /// the parsed installer's version.
    pub fn string(&self, field: HeaderString) -> Option<&str> {
        self.strings.get(&field).map(String::as_str)
    }

    /// Returns the raw bytes of a header `AnsiString` field (or of
    /// [`HeaderAnsi::SignedUninstallerSignature`], a `String` before 5.2.5),
    /// if the version has it.
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
    /// (immediately after the fixed numeric tail; before 1.3.0 after the
    /// license and info texts that follow the header).
    #[must_use]
    pub fn records_offset(&self) -> usize {
        self.records_offset
    }

    /// Returns the byte offset of the start of the fixed numeric
    /// tail. `records_offset() - tail_start_offset()` is the tail's size
    /// in bytes; before 1.3.0 it also counts the license and info texts.
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
/// 2. `SignedUninstallerSignature` exists only in the narrow
///    5.2.1..5.3.10 window - read past as bytes, not exposed.
/// 3. The `String` fields added at 6.4.2+ (`CloseApplicationsFilterExcludes`,
///    `SevenZipLibraryName`, `UsePrevious*`) come after the architecture
///    expressions but still ahead of the ansi tail. innoextract's reference
///    predates them.
///
/// The `header::upstream` tests check this walker against the
/// `TSetupHeader` declaration of every release whose source is available,
/// SetupID markers 1.3.25 through 7.1.1 (`crate::upstream`, generated by
/// `tests/samples/build/gen-layouts.py`): for each marker it must read
/// exactly the declared fields, in order, as the declared kind.
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
    // Before 3.0.0 Setup made the uninstaller's shortcut itself.
    if !version.at_least(3, 0, 0) {
        put_str(reader, HeaderString::UninstallIconName, strings)?;
    }
    // 7.1.1 dropped `BaseFilename`, by then empty and unused (issrc
    // commit `f52ff3b2`, which set SetupID `7.1.1`).
    if !version.at_least(7, 1, 1) {
        put_str(reader, HeaderString::BaseFilename, strings)?;
    }
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
    // 6.4.2+: CloseApplicationsFilterExcludes (issrc commit `72756e57`,
    // the one that set SetupID `6.4.2`).
    if version.at_least(6, 4, 2) {
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
    // 5.2.1..5.3.10: `SignedUninstallerSignature`. Before 5.2.5 it is the
    // last `String` field; from 5.2.5 it is an `AnsiString` between
    // InfoAfter and CompiledCode, raw bytes even in a Unicode build. Either
    // way it is length-prefixed bytes, which a 5.2.1..5.2.4 ANSI build
    // reads the same, so it is read as bytes throughout.
    if version.at_least(5, 2, 1) && !version.at_least(5, 3, 10) {
        put_ansi(reader, HeaderAnsi::SignedUninstallerSignature, ansi)?;
    }
    // 5.2.5+: compiled-code blob - the fourth `AnsiString` field.
    if version.at_least(5, 2, 5) {
        put_ansi(reader, HeaderAnsi::CompiledCodeText, ansi)?;
    }

    Ok(())
}

impl HeaderString {
    /// Returns this field's stable identifier: its name in upstream's
    /// `TSetupHeader` (`AppName`, `DefaultDirName`, ...), which does not
    /// change.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        field_label(*self)
    }
}

impl core::fmt::Display for HeaderString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HeaderAnsi {
    /// Returns this field's stable identifier: its name in upstream's
    /// `TSetupHeader` (`LicenseText`, ...), which does not change.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        ansi_label(*self)
    }
}

impl core::fmt::Display for HeaderAnsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
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
        HeaderString::UninstallIconName => "UninstallIconName",
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
        HeaderAnsi::SignedUninstallerSignature => "SignedUninstallerSignature",
        HeaderAnsi::CompiledCodeText => "CompiledCodeText",
    }
}

/// Reads the `Num*Entries` counts. Each exists from the release that
/// introduced its record type (innoextract `setup/header.cpp`, checked
/// against every `TSetupHeader` declaration by `crate::upstream`); a count
/// the version does not carry is zero.
fn read_counts(reader: &mut Reader<'_>, version: &Version) -> Result<EntryCounts, Error> {
    // Before 4.0.0 there is no count: from 2.0.1 one `TSetupLangOptions`
    // record follows the header (innoextract `setup/header.cpp`; the 2.0.0
    // boundary is innoextract's, no 2.0.0 source survives), before that none.
    let languages = if version.at_least(4, 0, 0) {
        reader.u32_le("NumLanguageEntries")?
    } else {
        u32::from(version.at_least(2, 0, 1))
    };
    let mut count = |present: bool, what: &'static str| -> Result<u32, Error> {
        if present { reader.u32_le(what) } else { Ok(0) }
    };
    let isx = version.is_isx();
    let custom_messages = count(version.at_least(4, 2, 1), "NumCustomMessageEntries")?;
    let permissions = count(version.at_least(4, 1, 0), "NumPermissionEntries")?;
    let types = count(version.at_least(2, 0, 0) || isx, "NumTypeEntries")?;
    let components = count(version.at_least(2, 0, 0) || isx, "NumComponentEntries")?;
    let tasks = count(
        version.at_least(2, 0, 0) || (isx && version.at_least(1, 3, 17)),
        "NumTaskEntries",
    )?;
    Ok(EntryCounts {
        languages,
        custom_messages,
        permissions,
        types,
        components,
        tasks,
        directories: reader.native_u32(version, "NumDirEntries")?,
        iss_sig_keys: if version.at_least(6, 5, 0) {
            Some(reader.u32_le("NumISSigKeyEntries")?)
        } else {
            None
        },
        files: reader.native_u32(version, "NumFileEntries")?,
        file_locations: reader.native_u32(version, "NumFileLocationEntries")?,
        icons: reader.native_u32(version, "NumIconEntries")?,
        ini_entries: reader.native_u32(version, "NumIniEntries")?,
        registry: reader.native_u32(version, "NumRegistryEntries")?,
        install_deletes: reader.native_u32(version, "NumInstallDeleteEntries")?,
        uninstall_deletes: reader.native_u32(version, "NumUninstallDeleteEntries")?,
        run: reader.native_u32(version, "NumRunEntries")?,
        uninstall_run: reader.native_u32(version, "NumUninstallRunEntries")?,
    })
}

/// Parses the fixed numeric / enum / set tail of `TSetupHeader`. The
/// conditional ladder follows innoextract's `header::load`, extended past
/// it with upstream's own declarations, and is checked for every marker by
/// the `crate::upstream` tests.
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

    // 5.5.7 removed WizardImageBackColor; before, a u32 here.
    if !version.at_least(5, 5, 7) {
        tail.wizard_image_back_color = Some(reader.u32_le("WizardImageBackColor")?);
    }
    // 2.0.0..5.0.4: WizardSmallImageBackColor, dropped with SetupID 5.0.4
    // (innoextract `setup/header.cpp`; ISX builds keep it).
    if (version.at_least(2, 0, 0) && !version.at_least(5, 0, 4)) || version.is_isx() {
        tail.wizard_small_image_back_color = Some(reader.u32_le("WizardSmallImageBackColor")?);
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
        tail.wizard_dark_style = WizardDarkStyle::from_raw(raw);
        // The 6.6.0 enum is `wdsLight / wdsDark / wdsDynamic`, a different
        // type in the same slot; `wizard_style` stays None.
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
    //   6.5.2+:   ImageBack, SmallImageBack: Integer (SetupID 6.5.2; 6.5.0
    //             and 6.5.1 have neither)
    //   6.7.0+:    + BackColor: Integer (interspersed inside the
    //              first triple)
    //   6.6.0+:   + ImageBackDynamicDark, SmallImageBackDynamicDark: Integer
    //   6.7.0+:    + BackColorDynamicDark: Integer (same triple
    //              insertion)
    //   6.6.1+:   + ImageOpacity: Byte
    //   6.7.0+:    + BackImageOpacity: Byte; LightControlStyling: Byte
    // We read past these to keep the cursor aligned; downstream
    // typed accessors land when callers ask for them.
    if version.at_least(6, 5, 2) {
        tail.wizard_image_back_color = Some(reader.u32_le("WizardImageBackColor")?);
        tail.wizard_small_image_back_color = Some(reader.u32_le("WizardSmallImageBackColor")?);
        if version.at_least(6, 7, 0) {
            tail.wizard_back_color = Some(reader.u32_le("WizardBackColor")?);
        }
    }
    if version.at_least(6, 6, 0) {
        tail.wizard_image_back_color_dynamic_dark =
            Some(reader.u32_le("WizardImageBackColorDynamicDark")?);
        tail.wizard_small_image_back_color_dynamic_dark =
            Some(reader.u32_le("WizardSmallImageBackColorDynamicDark")?);
        if version.at_least(6, 7, 0) {
            tail.wizard_back_color_dynamic_dark =
                Some(reader.u32_le("WizardBackColorDynamicDark")?);
        }
    }
    if version.at_least(6, 6, 1) {
        tail.wizard_image_opacity = Some(reader.u8("WizardImageOpacity")?);
        if version.at_least(6, 7, 0) {
            tail.wizard_back_image_opacity = Some(reader.u8("WizardBackImageOpacity")?);
            let raw = reader.u8("WizardLightControlStyling")?;
            tail.wizard_light_control_styling_raw = raw;
            tail.wizard_light_control_styling = WizardLightControlStyling::from_raw(raw);
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

    // 2.0.0..5.0.0 install-mode byte (skipped past): `InstallMode:
    // (imNormal, imSilent, imVerySilent)` in every TSetupHeader of that
    // range (innoextract `setup/header.cpp`; ISX from 1.3.4).
    if (version.at_least(2, 0, 0) && !version.at_least(5, 0, 0))
        || (version.is_isx() && version.at_least(1, 3, 4))
    {
        let raw = reader.u8("InstallMode")?;
        tail.install_mode_raw = raw;
        tail.install_mode = InstallMode::from_raw(raw);
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
        let raw = reader.u8("UninstallStyle")?;
        tail.uninstall_style_raw = raw;
        tail.uninstall_style = UninstallStyle::from_raw(raw);
    }

    // 1.3.6+ DirExistsWarning.
    if version.at_least(1, 3, 6) {
        let raw = reader.u8("DirExistsWarning")?;
        tail.dir_exists_warning_raw = raw;
        tail.dir_exists_warning = AutoNoYes::from_raw(raw);
    }

    // 3.0.0..3.0.3: one auto/no/yes byte stands for the two restart flags
    // later releases store in Options; applied to them below
    // (innoextract `setup/header.cpp`).
    let restart = if version.at_least(3, 0, 0) && !version.at_least(3, 0, 3) {
        AutoNoYes::from_raw(reader.u8("AlwaysRestart")?)
    } else {
        None
    };

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

    // 6.0.0+ PrivilegesRequiredOverridesAllowed (set of 2 bits, 1 byte).
    if version.at_least(6, 0, 0) {
        let raw = reader.set_bytes(2, version, "PrivilegesRequiredOverridesAllowed")?;
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

    // Architectures. 5.1.0..5.5.7 uses 4-arch flags; from 5.5.7 5-arch
    // flags: 5.6.0 appended `paARM64` but kept SetupID 5.5.7, and the set
    // is one byte either way, so the earlier releases simply never set it.
    // From 6.3.0 these are String expressions in the header strings
    // (already read above).
    if version.at_least(6, 3, 0) {
        // String expressions; nothing on the wire here.
    } else if version.at_least(5, 5, 7) {
        let raw = reader.set_bytes(5, version, "ArchitecturesAllowed")?;
        tail.architectures_allowed_raw = raw.first().copied();
        tail.architectures_allowed = Some(decode_arch_set_v1(&raw));
        let raw = reader.set_bytes(5, version, "ArchitecturesInstallIn64BitMode")?;
        tail.architectures_install_in_64bit_mode_raw = raw.first().copied();
        tail.architectures_install_in_64bit_mode = Some(decode_arch_set_v1(&raw));
    } else if version.at_least(5, 1, 0) {
        let raw = reader.set_bytes(4, version, "ArchitecturesAllowed")?;
        tail.architectures_allowed_raw = raw.first().copied();
        tail.architectures_allowed = Some(decode_arch_set_v0(&raw));
        let raw = reader.set_bytes(4, version, "ArchitecturesInstallIn64BitMode")?;
        tail.architectures_install_in_64bit_mode_raw = raw.first().copied();
        tail.architectures_install_in_64bit_mode = Some(decode_arch_set_v0(&raw));
    }

    // 5.2.1..5.3.10 has signed-uninstaller fields - read past.
    if version.at_least(5, 2, 1) && !version.at_least(5, 3, 10) {
        tail.signed_uninstaller_original_size = Some(reader.u32_le("SignedUninstallerOrigSize")?);
        tail.signed_uninstaller_header_checksum =
            Some(reader.u32_le("SignedUninstallerHdrChecksum")?);
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

    // Options bitset (always present). `shUnusedPadding = 56` is the last
    // member's ordinal, so the set is that many bits plus one.
    let mut bit_count = options_bit_table(version).len();
    if version.at_least(6, 7, 0) {
        bit_count = 57;
    }
    let raw = reader.set_bytes(bit_count, version, "Options")?;
    tail.options = decode_options(&raw, version);
    match restart {
        Some(AutoNoYes::Yes) => {
            tail.options.insert(HeaderOption::AlwaysRestart);
        }
        Some(AutoNoYes::Auto) => {
            tail.options.insert(HeaderOption::RestartIfNeededByRun);
        }
        _ => {}
    }
    tail.options_raw = raw;

    // Before 4.1.5 there is no CompressMethod: setup-1 is bzip2 when the
    // compiler set `shBzipUsed` (2.0.17+), zlib otherwise (innoextract
    // `setup/header.cpp`).
    if !version.at_least(4, 1, 5) {
        tail.compress_method = Some(if tail.options.contains(&HeaderOption::BzipUsed) {
            CompressMethod::Bzip2
        } else {
            CompressMethod::Zlib
        });
    }

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

impl WizardDarkStyle {
    /// The variant for a stored byte (`wizard_style_raw`), or [`None`] for a value
    /// this crate does not know.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Light),
            1 => Some(Self::Dark),
            2 => Some(Self::Dynamic),
            _ => None,
        }
    }
}

impl WizardLightControlStyling {
    /// The variant for a stored byte (`wizard_light_control_styling_raw`), or [`None`] for a value
    /// this crate does not know.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::All),
            1 => Some(Self::AllButButtons),
            2 => Some(Self::OnlyRequired),
            _ => None,
        }
    }
}

impl InstallMode {
    /// The variant for a stored byte (`install_mode_raw`), or [`None`] for a value
    /// this crate does not know.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Normal),
            1 => Some(Self::Silent),
            2 => Some(Self::VerySilent),
            _ => None,
        }
    }
}

impl UninstallStyle {
    /// The variant for a stored byte (`uninstall_style_raw`), or [`None`] for a value
    /// this crate does not know.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Classic),
            1 => Some(Self::Modern),
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

/// 5.5.7+ (5-arch) layout: Unknown, X86, Amd64, IA64, Arm64.
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

/// Decodes `TSetupHeader.Options`. Before 4.0.9 cancelling during the
/// install was always allowed and before 5.5.0 network drives always were;
/// neither had a flag yet, so both are added, as innoextract does, and the
/// set reads as Setup behaves.
fn decode_options(raw: &[u8], version: &Version) -> HashSet<HeaderOption> {
    let mut out: HashSet<HeaderOption> = options_bit_table(version)
        .into_iter()
        .enumerate()
        .filter_map(|(bit, slot)| slot.filter(|_| bit_at(raw, bit)))
        .collect();
    if !version.at_least(4, 0, 9) {
        out.insert(HeaderOption::AllowCancelDuringInstall);
    }
    if !version.at_least(5, 5, 0) {
        out.insert(HeaderOption::AllowNetworkDrive);
    }
    out
}

/// The `TSetupHeaderOption` members `version` declares, in declaration
/// order: member `i` is bit `i` of `Options`. `None` is padding.
///
/// One ladder covers every format. Its gates are where each member enters
/// and leaves `Struct.pas` / `Shared.Struct.pas`, read from every release
/// whose source is available (the `crate::upstream` tests check each bit of
/// every marker against those declarations), refined between those releases
/// by innoextract's `header::load_flags`. Members never move relative to
/// one another, so the order alone places each bit.
fn options_bit_table(version: &Version) -> Vec<Option<HeaderOption>> {
    use HeaderOption as O;
    let v = |a, b, c| version.at_least(a, b, c);
    let v4 = |a, b, c, d| version.at_least_4(a, b, c, d);
    let not16 = !version.is_16bit();
    let ladder: &[(bool, Option<HeaderOption>)] = &[
        (true, Some(O::DisableStartupPrompt)),
        (!v(5, 3, 10), Some(O::Uninstallable)),
        (true, Some(O::CreateAppDir)),
        (!v(5, 3, 3), Some(O::DisableDirPage)),
        (!v(1, 3, 6), Some(O::DisableDirExistsWarning)),
        (!v(5, 3, 3), Some(O::DisableProgramGroupPage)),
        (true, Some(O::AllowNoIcons)),
        (!v(3, 0, 0) || v(3, 0, 3), Some(O::AlwaysRestart)),
        (!v(1, 3, 3), Some(O::BackSolid)),
        (true, Some(O::AlwaysUsePersonalGroup)),
        (!v4(6, 4, 0, 1), Some(O::WindowVisible)),
        (!v4(6, 4, 0, 1), Some(O::WindowShowCaption)),
        (!v4(6, 4, 0, 1), Some(O::WindowResizable)),
        (!v4(6, 4, 0, 1), Some(O::WindowStartMaximized)),
        (true, Some(O::EnableDirDoesntExistWarning)),
        (!v(4, 1, 2), Some(O::DisableAppendDir)),
        (true, Some(O::Password)),
        (v(1, 2, 6), Some(O::AllowRootDirectory)),
        // 1.2.14 added it, but 1.2.10 to 1.2.16 all write SetupID 1.2.10,
        // the oldest there is; an earlier release just never sets the bit.
        (true, Some(O::DisableFinishedPage)),
        (not16 && !v(3, 0, 4), Some(O::AdminPrivilegesRequired)),
        (not16 && !v(3, 0, 0), Some(O::AlwaysCreateUninstallIcon)),
        (not16 && !v(1, 3, 6), Some(O::OverwriteUninstRegEntries)),
        (not16 && !v(6, 0, 0), Some(O::ChangesAssociations)),
        (v(1, 3, 0) && !v(5, 3, 8), Some(O::CreateUninstallRegKey)),
        (v(1, 3, 1) && !v(6, 7, 0), Some(O::UsePreviousAppDir)),
        (v(1, 3, 3) && !v4(6, 4, 0, 1), Some(O::BackColorHorizontal)),
        (v(1, 3, 10) && !v(6, 7, 0), Some(O::UsePreviousGroup)),
        (v(1, 3, 20), Some(O::UpdateUninstallLogAppName)),
        (
            (v(2, 0, 0) || (version.is_isx() && v(1, 3, 10))) && !v(6, 7, 0),
            Some(O::UsePreviousSetupType),
        ),
        (v(2, 0, 0), Some(O::DisableReadyMemo)),
        (v(2, 0, 0), Some(O::AlwaysShowComponentsList)),
        (v(2, 0, 0), Some(O::FlatComponentsList)),
        (v(2, 0, 0), Some(O::ShowComponentSizes)),
        (v(2, 0, 0) && !v(6, 7, 0), Some(O::UsePreviousTasks)),
        (v(2, 0, 0), Some(O::DisableReadyPage)),
        (v(2, 0, 7), Some(O::AlwaysShowDirOnReadyPage)),
        (v(2, 0, 7), Some(O::AlwaysShowGroupOnReadyPage)),
        (v(2, 0, 17) && !v(4, 1, 5), Some(O::BzipUsed)),
        (v(2, 0, 18), Some(O::AllowUNCPath)),
        (v(3, 0, 0), Some(O::UserInfoPage)),
        (v(3, 0, 0) && !v(6, 7, 0), Some(O::UsePreviousUserInfo)),
        (v(3, 0, 1), Some(O::UninstallRestartComputer)),
        (v(3, 0, 3), Some(O::RestartIfNeededByRun)),
        (
            v(4, 0, 0) || (version.is_isx() && v(3, 0, 3)),
            Some(O::ShowTasksTreeLines),
        ),
        (v(4, 0, 0) && !v(4, 0, 10), Some(O::ShowLanguageDialog)),
        (
            v(4, 0, 1) && !v(4, 0, 10),
            Some(O::DetectLanguageUsingLocale),
        ),
        (v(4, 0, 9), Some(O::AllowCancelDuringInstall)),
        (v(4, 1, 3), Some(O::WizardImageStretch)),
        (v(4, 1, 8), Some(O::AppendDefaultDirName)),
        (v(4, 1, 8), Some(O::AppendDefaultGroupName)),
        (v(4, 2, 2) && !v(6, 5, 0), Some(O::EncryptionUsed)),
        (v(5, 0, 4) && !v(6, 0, 0), Some(O::ChangesEnvironment)),
        (
            v(5, 1, 7) && !v(6, 0, 0) && !version.is_unicode(),
            Some(O::ShowUndisplayableLanguages),
        ),
        (v(5, 1, 13), Some(O::SetupLogging)),
        (v(5, 2, 1), Some(O::SignedUninstaller)),
        (v(5, 3, 8), Some(O::UsePreviousLanguage)),
        (v(5, 3, 9), Some(O::DisableWelcomePage)),
        (v(5, 5, 0), Some(O::CloseApplications)),
        (v(5, 5, 0), Some(O::RestartApplications)),
        (v(5, 5, 0), Some(O::AllowNetworkDrive)),
        (v(5, 5, 7), Some(O::ForceCloseApplications)),
        (v(6, 0, 0), Some(O::AppNameHasConsts)),
        (v(6, 0, 0), Some(O::UsePreviousPrivileges)),
        (v(6, 0, 0) && !v(6, 6, 0), Some(O::WizardResizable)),
        (v(6, 3, 0), Some(O::UninstallLogging)),
        (v(6, 6, 0), Some(O::WizardModern)),
        (v(6, 6, 0), Some(O::WizardBorderStyled)),
        (v(6, 6, 0), Some(O::WizardKeepAspectRatio)),
        (
            v(6, 6, 0) && !v(6, 7, 0),
            Some(O::WizardLightButtonsUnstyled),
        ),
        (v(6, 7, 0), Some(O::RedirectionGuard)),
        (v(6, 7, 0), Some(O::WizardBevelsHidden)),
        // `shUnusedPadding = 56`: pads the set to eight bytes so 32- and
        // 64-bit compilers agree on its size.
        (v(6, 7, 0), None),
    ];
    ladder
        .iter()
        .filter_map(|&(present, slot)| present.then_some(slot))
        .collect()
}

#[cfg(test)]
mod upstream;

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
