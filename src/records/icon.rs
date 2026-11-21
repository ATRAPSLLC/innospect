//! `TSetupIconEntry`: one `[Icons]` entry, a shortcut Setup creates in
//! the Start menu, on the desktop or elsewhere.
//!
//! On disk (`SECompressedBlockWrite`): the string fields (the six below,
//! the condition strings, from 5.3.5 `AppUserModelID`), from 6.1.0 the
//! 16-byte `AppUserModelToastActivatorCLSID`, the Windows version range,
//! `IconIndex`, from 1.3.24 `ShowCmd`, from 1.3.15 `CloseOnExit`, from 2.0.7
//! `HotKey`, and the `Options` set. The conditions and the version range
//! are split by the fields between them, so they are read apart rather
//! than as an [`crate::records::item::ItemBase`]. Reader reference:
//! innoextract `setup/icon.cpp`; every layout is checked against
//! upstream's own declarations by the `crate::upstream` tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{item::ItemConditions, windows::WindowsVersionRange},
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `CloseOnExit` (`TSetupIconCloseOnExit`): the "Close on exit" property
/// of a shortcut to an MS-DOS program (`.pif`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseOnExit {
    /// `icNoSetting`: neither flag; Windows decides.
    NoSetting,
    /// `icYes` (`closeonexit` flag): the console window closes.
    Close,
    /// `icNo` (`dontcloseonexit` flag): it stays open.
    DontClose,
}

stable_name_enum!(CloseOnExit, {
    Self::NoSetting => "no_setting",
    Self::Close => "close",
    Self::DontClose => "dont_close",
});

/// `TSetupIconEntry.Options`: the entry's `Flags:` that have a bit of
/// their own. `runminimized` / `runmaximized` set [`IconEntry::show_command`]
/// and `closeonexit` / `dontcloseonexit` [`IconEntry::close_on_exit`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum IconFlag {
    /// `ioUninsNeverUninstall` (`uninsneveruninstall`): the uninstaller
    /// leaves the shortcut.
    NeverUninstall,
    /// `ioRunMinimized` (`runminimized`): before `ShowCmd`, the shortcut
    /// starts its program minimized (before SetupID 1.3.25).
    RunMinimized,
    /// `ioCreateOnlyIfFileExists` (`createonlyiffileexists`): create the
    /// shortcut only if `Filename` exists.
    CreateOnlyIfFileExists,
    /// `ioUseAppPaths` (`useapppaths`): `Filename` is a bare name whose path
    /// comes from the `App Paths` registry key.
    UseAppPaths,
    /// `ioFolderShortcut` (`foldershortcut`): a shortcut to a folder that
    /// opens as the folder itself (5.0.3 to 6.3.0).
    FolderShortcut,
    /// `ioExcludeFromShowInNewInstall` (`excludefromshowinnewinstall`): no
    /// new-program highlight in the Start menu (5.4.2+).
    ExcludeFromShowInNewInstall,
    /// `ioPreventPinning` (`preventpinning`): the Start menu entry cannot be
    /// pinned (5.5.0+).
    PreventPinning,
    /// `ioHasAppUserModelToastActivatorCLSID`: the entry gave
    /// `AppUserModelToastActivatorCLSID:` (6.1.0+).
    HasAppUserModelToastActivatorCLSID,
}

stable_flag_enum!(IconFlag, {
    NeverUninstall => "never_uninstall",
    RunMinimized => "run_minimized",
    CreateOnlyIfFileExists => "create_only_if_file_exists",
    UseAppPaths => "use_app_paths",
    FolderShortcut => "folder_shortcut",
    ExcludeFromShowInNewInstall => "exclude_from_show_in_new_install",
    PreventPinning => "prevent_pinning",
    HasAppUserModelToastActivatorCLSID => "has_app_user_model_toast_activator_clsid",
});

/// One `[Icons]` entry (`TSetupIconEntry`). A string field the version does
/// not have is empty; paths may contain constants such as `{group}`,
/// unexpanded.
#[derive(Clone, Debug)]
pub struct IconEntry {
    /// `Name:` (Pascal `IconName`): the shortcut's path without extension,
    /// e.g. `{group}\My Program`; Setup adds `.lnk`, or `.url` when
    /// `Filename` is a URL.
    pub name: String,
    /// `Filename:`: what the shortcut opens, a file, folder or URL.
    pub filename: String,
    /// `Parameters:`: the command-line arguments.
    pub parameters: String,
    /// `WorkingDir:`: the "Start in" directory; empty means the directory
    /// of `Filename`.
    pub working_dir: String,
    /// `IconFilename:`: the file holding the icon; empty means `Filename`'s
    /// own.
    pub icon_file: String,
    /// `Comment:`: the shortcut's description, shown as its tooltip.
    pub comment: String,
    /// `Components:` .. `AfterInstall:`.
    pub conditions: ItemConditions,
    /// `AppUserModelID:`: the shortcut's Application User Model ID, for
    /// taskbar grouping (5.3.5+).
    pub app_user_model_id: String,
    /// `AppUserModelToastActivatorCLSID:` as its 16 `TGUID` bytes (6.1.0+;
    /// `None` before). All zeros unless
    /// [`IconFlag::HasAppUserModelToastActivatorCLSID`] is set.
    pub app_user_model_toast_activator_clsid: Option<[u8; 16]>,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
    /// `IconIndex:`: which icon in `IconFilename`, zero-based.
    pub icon_index: i32,
    /// `ShowCmd`: the `ShowWindow` command the program starts with:
    /// `SW_SHOWNORMAL` (1) by default, `SW_SHOWMINNOACTIVE` (7) with
    /// `runminimized`, `SW_SHOWMAXIMIZED` (3) with `runmaximized` (1.3.24+; 1
    /// before).
    pub show_command: i32,
    /// `CloseOnExit`, decoded (1.3.15+; `None` before, or for a value this
    /// crate does not know).
    pub close_on_exit: Option<CloseOnExit>,
    /// `CloseOnExit` as stored; 0 when the version has no such byte.
    pub close_on_exit_raw: u8,
    /// `HotKey:` in `IShellLink::SetHotkey` form: the virtual-key code in
    /// the low byte, `HOTKEYF_SHIFT` (1), `HOTKEYF_CONTROL` (2) and
    /// `HOTKEYF_ALT` (4) in the high byte; 0 for none (2.0.7+).
    pub hotkey: u16,
    /// `Options`, decoded.
    pub flags: HashSet<IconFlag>,
    /// `Options` as stored: the set's bytes, whose size grows with the
    /// number of flags the version defines.
    pub options_raw: Vec<u8>,
}

impl FromReader for IconEntry {
    /// Reads one `TSetupIconEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Icon.Name")?;
        let filename = read_setup_string(reader, version, "Icon.Filename")?;
        let parameters = read_setup_string(reader, version, "Icon.Parameters")?;
        let working_dir = read_setup_string(reader, version, "Icon.WorkingDir")?;
        let icon_file = read_setup_string(reader, version, "Icon.IconFile")?;
        let comment = read_setup_string(reader, version, "Icon.Comment")?;

        let conditions = ItemConditions::read(reader, version)?;

        let app_user_model_id = if version.at_least(5, 3, 5) {
            read_setup_string(reader, version, "Icon.AppUserModelID")?
        } else {
            String::new()
        };

        let app_user_model_toast_activator_clsid = if version.at_least(6, 1, 0) {
            Some(reader.array::<16>("Icon.ToastActivatorCLSID")?)
        } else {
            None
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        let icon_index = reader.native_i32(version, "Icon.IconIndex")?;

        let show_command = if version.at_least(1, 3, 24) {
            reader.i32_le("Icon.ShowCmd")?
        } else {
            1
        };

        let (close_on_exit, close_on_exit_raw) = if version.at_least(1, 3, 15) {
            let raw = reader.u8("Icon.CloseOnExit")?;
            (CloseOnExit::from_raw(raw), raw)
        } else {
            (None, 0)
        };

        let hotkey = if version.at_least(2, 0, 7) {
            reader.u16_le("Icon.HotKey")?
        } else {
            0
        };

        let table = icon_flag_table(version);
        let raw = reader.set_bytes(table.len(), version, "Icon.Options")?;
        let flags = crate::util::flags::decode_packed_flags(&raw, &table);

        Ok(Self {
            name,
            filename,
            parameters,
            working_dir,
            icon_file,
            comment,
            conditions,
            app_user_model_id,
            app_user_model_toast_activator_clsid,
            winver,
            icon_index,
            show_command,
            close_on_exit,
            close_on_exit_raw,
            hotkey,
            flags,
            options_raw: raw,
        })
    }
}

impl CloseOnExit {
    /// Resolves the persisted on-disk discriminant byte back to a
    /// [`CloseOnExit`], or [`None`] for an unknown value. Used to re-derive the
    /// label from a stored `close_on_exit_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::NoSetting),
            1 => Some(Self::Close),
            2 => Some(Self::DontClose),
            _ => None,
        }
    }
}

fn icon_flag_table(version: &Version) -> Vec<IconFlag> {
    let mut t = vec![IconFlag::NeverUninstall];
    // `ioRunMinimized` went when `ShowCmd` arrived. Releases 1.3.25 and
    // 1.3.26 both write SetupID 1.3.25, and innoextract has 1.3.25 still
    // carrying the flag; only 1.3.26's source is available, and it has
    // none. The marker cannot tell them apart, so 1.3.25 installers follow
    // 1.3.26 here and a 1.3.25 release's flags 1 and 2 read one bit late.
    if !version.at_least(1, 3, 25) {
        t.push(IconFlag::RunMinimized);
    }
    t.push(IconFlag::CreateOnlyIfFileExists);
    // App Paths are a Win32 registry key; a 16-bit installer has no flag.
    if !version.is_16bit() {
        t.push(IconFlag::UseAppPaths);
    }
    if version.at_least(5, 0, 3) && !version.at_least(6, 3, 0) {
        t.push(IconFlag::FolderShortcut);
    }
    if version.at_least(5, 4, 2) {
        t.push(IconFlag::ExcludeFromShowInNewInstall);
    }
    if version.at_least(5, 5, 0) {
        t.push(IconFlag::PreventPinning);
    }
    if version.at_least(6, 1, 0) {
        t.push(IconFlag::HasAppUserModelToastActivatorCLSID);
    }
    t
}
