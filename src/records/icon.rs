//! `TSetupIconEntry` - `[Icons]` directive entry (Start Menu /
//! desktop shortcut).
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupIconEntry = packed record
//!     IconName, Filename, Parameters, WorkingDir, IconFilename,
//!         Comment: AnsiString;
//!     [ItemConditions]
//!     AppUserModelID: AnsiString;        // since 5.3.5
//!     AppUserModelToastActivatorCLSID: TGUID;  // since 6.1.0 (16 bytes)
//!     [WindowsVersionRange]
//!     IconIndex: Integer;
//!     ShowCmd: Integer;        // since 1.3.24
//!     CloseOnExit: TSetupCloseOnExit; // u8 enum, since 1.3.15
//!     HotKey: Word;            // since 2.0.7
//!     Options: TSetupIconOptions;
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/icon.cpp`. The conditions
//! and version range are split by per-version `app_user_model_id` /
//! CLSID fields, so we read [`ItemConditions`] and
//! [`WindowsVersionRange`] separately rather than via `ItemBase`.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{item::ItemConditions, windows::WindowsVersionRange},
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupCloseOnExit` - wizard close-on-exit policy for the
/// shortcut's launched process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseOnExit {
    /// `coNoSetting`.
    NoSetting,
    /// `coCloseOnExit`.
    Close,
    /// `coDontCloseOnExit`.
    DontClose,
}

stable_name_enum!(CloseOnExit, {
    Self::NoSetting => "no_setting",
    Self::Close => "close",
    Self::DontClose => "dont_close",
});

/// `TSetupIconOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum IconFlag {
    NeverUninstall,
    /// Pre-1.3.26 only - replaced by `ShowCmd` later.
    RunMinimized,
    CreateOnlyIfFileExists,
    UseAppPaths,
    /// 5.0.3..6.3.0 only.
    FolderShortcut,
    ExcludeFromShowInNewInstall,
    PreventPinning,
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

/// Parsed `TSetupIconEntry`.
#[derive(Clone, Debug)]
pub struct IconEntry {
    /// `Name:` directive - full shortcut path including `.lnk`.
    pub name: String,
    /// `Filename:` directive.
    pub filename: String,
    /// `Parameters:` directive.
    pub parameters: String,
    /// `WorkingDir:` directive.
    pub working_dir: String,
    /// `IconFilename:` directive.
    pub icon_file: String,
    /// `Comment:` directive.
    pub comment: String,
    /// `[ItemConditions]`.
    pub conditions: ItemConditions,
    /// `AppUserModelID:` directive (5.3.5+).
    pub app_user_model_id: String,
    /// `AppUserModelToastActivatorCLSID:` 16-byte GUID (6.1.0+).
    pub app_user_model_toast_activator_clsid: Option<[u8; 16]>,
    /// `[WindowsVersionRange]`.
    pub winver: WindowsVersionRange,
    /// `IconIndex:` directive.
    pub icon_index: i32,
    /// `ShowCmd:` directive. Defaults to 1 (`SW_SHOWNORMAL`) on
    /// pre-1.3.24 versions.
    pub show_command: i32,
    /// `CloseOnExit:` directive (1.3.15+).
    pub close_on_exit: Option<CloseOnExit>,
    /// Raw close-on-exit byte (0 if absent in version).
    pub close_on_exit_raw: u8,
    /// `HotKey:` directive (2.0.7+).
    pub hotkey: u16,
    /// Decoded options.
    pub flags: HashSet<IconFlag>,
    /// Raw `Options` bytes.
    pub options_raw: Vec<u8>,
}

impl IconEntry {
    /// Reads one `TSetupIconEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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

        let icon_index = reader.i32_le("Icon.IconIndex")?;

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
        let raw = reader.set_bytes(table.len(), true, "Icon.Options")?;
        let flags = super::decode_packed_flags(&raw, &table);

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
    if !version.at_least(1, 3, 26) {
        t.push(IconFlag::RunMinimized);
    }
    t.push(IconFlag::CreateOnlyIfFileExists);
    t.push(IconFlag::UseAppPaths);
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
