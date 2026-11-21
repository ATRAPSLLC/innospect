//! `TSetupDeleteEntry`: one `[InstallDelete]` or `[UninstallDelete]`
//! entry, files or directories Setup deletes before installing
//! (`[InstallDelete]`) or the uninstaller deletes besides what it installed
//! (`[UninstallDelete]`). Both sections share the record; the installer
//! keeps them in separate lists ([`crate::InnoInstaller::install_deletes`],
//! [`crate::InnoInstaller::uninstall_deletes`]).
//!
//! On disk (`SECompressedBlockWrite`): `Name`, the condition strings, the
//! Windows version range and `DeleteType`. Reader reference: innoextract
//! `setup/delete.cpp`; every layout is checked against upstream's own
//! declarations by the `crate::upstream` tests.

use crate::{
    error::Error,
    records::item::ItemBase,
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `Type:` (`TSetupDeleteType`): what [`DeleteEntry::name`] matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteTargetType {
    /// `dtFiles` (`files`): files matching the name, which may contain
    /// wildcards.
    Files,
    /// `dtFilesAndSubdirs` (`filesandordirs`): files and directories
    /// matching it, directories with everything in them.
    FilesAndSubdirs,
    /// `dtDirIfEmpty` (`dirifempty`): the named directory, no wildcards,
    /// only if it is empty.
    DirIfEmpty,
}

stable_name_enum!(DeleteTargetType, {
    Self::Files => "files",
    Self::FilesAndSubdirs => "files_and_subdirs",
    Self::DirIfEmpty => "dir_if_empty",
});

/// One `[InstallDelete]` / `[UninstallDelete]` entry (`TSetupDeleteEntry`).
#[derive(Clone, Debug)]
pub struct DeleteEntry {
    /// `Name:`: what to delete, a path that may contain wildcards (see
    /// [`Self::target_type`]) and constants such as `{app}`, unexpanded.
    pub name: String,
    /// `Components:` .. `AfterInstall:` and `MinVersion:` /
    /// `OnlyBelowVersion:`.
    pub item: ItemBase,
    /// `Type:`, decoded; `None` for a value this crate does not know.
    pub target_type: Option<DeleteTargetType>,
    /// `Type` as stored.
    pub target_type_raw: u8,
}

impl FromReader for DeleteEntry {
    /// Reads one `TSetupDeleteEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Delete.Name")?;
        let item = ItemBase::read(reader, version)?;
        let target_type_raw = reader.u8("Delete.Type")?;
        Ok(Self {
            name,
            item,
            target_type: DeleteTargetType::from_raw(target_type_raw),
            target_type_raw,
        })
    }
}

impl DeleteTargetType {
    /// Resolves the persisted on-disk discriminant byte back to a
    /// [`DeleteTargetType`], or [`None`] for an unknown value. Used to
    /// re-derive the label from a stored `target_type_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Files),
            1 => Some(Self::FilesAndSubdirs),
            2 => Some(Self::DirIfEmpty),
            _ => None,
        }
    }
}
