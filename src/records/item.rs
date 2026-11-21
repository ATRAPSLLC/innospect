//! Conditions section ([`ItemConditions`]) and the convenience
//! [`ItemBase`] bundle that pairs it with a [`WindowsVersionRange`].
//!
//! Most record types in the setup-0 stream that carry conditions
//! follow the same on-disk template, captured here once:
//!
//! ```text
//! [ record-specific header strings ]
//! [ ItemConditions: components, tasks, languages, check,
//!                   after_install, before_install ]   // version-gated
//! [ optional record-specific fields, sometimes ]      // e.g. directory perms
//! [ WindowsVersionRange: MinVersion + OnlyBelowVersion ]
//! [ record-specific options + flags ]
//! ```
//!
//! Most records (file, ini, run, icon, registry, delete) read the
//! conditions and the version range back-to-back. `directory_entry`
//! is the known exception - it interposes `permissions` and
//! `attributes` between the two - so the readers are split: callers
//! that need the back-to-back form use `ItemBase::read`, callers
//! that interpose use `ItemConditions::read` and
//! `WindowsVersionRange::read` separately.
//!
//! Wire-format reference: innoextract `setup/item.cpp`
//! `item::load_condition_data` and `item::load_version_data`. Pascal
//! source: the `T*Entry = packed record` declarations in
//! `Shared.Struct.pas`.

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// The conditions an entry is processed under, which every file, directory,
/// icon, INI, registry, delete and run entry carries in these six strings.
/// An empty one is no condition. A field the version does not have is
/// empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemConditions {
    /// `Components:`: the components the entry belongs to, as a
    /// space-separated list (any selected one will do) or a boolean
    /// expression with `not`, `and`, `or` (2.0.0+, or ISX 1.3.8+).
    pub components: String,
    /// `Tasks:`: the tasks it belongs to, in the same form (2.0.0+, or ISX
    /// 1.3.17+).
    pub tasks: String,
    /// `Languages:`: the languages it belongs to, in the same form
    /// (4.0.1+).
    pub languages: String,
    /// `Check:`: a `[Code]` function call, e.g. `IsWin64`; the entry is
    /// processed only if it returns true (4.0.0+, or ISX 1.3.24+).
    pub check: String,
    /// `AfterInstall:`: a `[Code]` procedure call run after the entry is
    /// processed. Stored before `BeforeInstall` (4.1.0+).
    pub after_install: String,
    /// `BeforeInstall:`: a `[Code]` procedure call run before (4.1.0+).
    pub before_install: String,
}

impl FromReader for ItemConditions {
    /// Reads the conditions section from the reader.
    ///
    /// Reads zero bytes when the parsed `version` predates all six
    /// fields (very old installers).
    ///
    /// # Errors
    ///
    /// String-decoding errors per [`read_setup_string`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let mut out = Self::default();

        if version.at_least(2, 0, 0) || (version.is_isx() && version.at_least(1, 3, 8)) {
            out.components = read_setup_string(reader, version, "Item.Components")?;
        }
        if version.at_least(2, 0, 0) || (version.is_isx() && version.at_least(1, 3, 17)) {
            out.tasks = read_setup_string(reader, version, "Item.Tasks")?;
        }
        if version.at_least(4, 0, 1) {
            out.languages = read_setup_string(reader, version, "Item.Languages")?;
        }
        if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(1, 3, 24)) {
            out.check = read_setup_string(reader, version, "Item.Check")?;
        }
        if version.at_least(4, 1, 0) {
            out.after_install = read_setup_string(reader, version, "Item.AfterInstall")?;
            out.before_install = read_setup_string(reader, version, "Item.BeforeInstall")?;
        }

        Ok(out)
    }
}

/// An entry's [`ItemConditions`] and its Windows version range together.
/// File, INI, delete and run entries store the two next to each other;
/// directory, icon and registry entries have fields between them, so they
/// keep the parts apart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemBase {
    /// `Components:` .. `AfterInstall:`.
    pub conditions: ItemConditions,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
}

impl FromReader for ItemBase {
    /// Reads conditions then the version range. See struct-level
    /// docs for the limits of this convenience.
    ///
    /// # Errors
    ///
    /// Same as [`ItemConditions::read`] / [`WindowsVersionRange::read`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let conditions = ItemConditions::read(reader, version)?;
        let winver = WindowsVersionRange::read(reader, version)?;
        Ok(Self { conditions, winver })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    fn unicode_v(a: u8, b: u8, c: u8) -> Version {
        Version {
            a,
            b,
            c,
            d: 0,
            flags: VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    /// Encode a UTF-16LE length-prefixed string (Inno's "String"
    /// wire form on Unicode builds).
    fn put_str(buf: &mut Vec<u8>, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let byte_len = u32::try_from(utf16.len() * 2).unwrap();
        buf.extend_from_slice(&byte_len.to_le_bytes());
        for u in utf16 {
            buf.extend_from_slice(&u.to_le_bytes());
        }
    }

    #[test]
    fn item_conditions_reads_6_strings_at_v6_4() {
        let v = unicode_v(6, 4, 0);
        let mut bytes = Vec::new();
        put_str(&mut bytes, "comp_a");
        put_str(&mut bytes, "task_a");
        put_str(&mut bytes, "en");
        put_str(&mut bytes, "IsAdmin");
        put_str(&mut bytes, "Post"); // after_install
        put_str(&mut bytes, "Pre"); // before_install
        let mut r = Reader::new(&bytes);
        let cond = ItemConditions::read(&mut r, &v).unwrap();
        assert_eq!(cond.components, "comp_a");
        assert_eq!(cond.tasks, "task_a");
        assert_eq!(cond.languages, "en");
        assert_eq!(cond.check, "IsAdmin");
        assert_eq!(cond.after_install, "Post");
        assert_eq!(cond.before_install, "Pre");
        assert_eq!(r.pos(), bytes.len(), "no leftover bytes");
    }

    #[test]
    fn item_conditions_pre_4_1_skips_install_hooks() {
        // 4.0.5 has components/tasks/languages/check but not the
        // before/after_install pair.
        let v = unicode_v(4, 0, 5);
        let mut bytes = Vec::new();
        put_str(&mut bytes, "c");
        put_str(&mut bytes, "t");
        put_str(&mut bytes, "l");
        put_str(&mut bytes, "k");
        let mut r = Reader::new(&bytes);
        let cond = ItemConditions::read(&mut r, &v).unwrap();
        assert_eq!(cond.components, "c");
        assert_eq!(cond.check, "k");
        assert_eq!(cond.after_install, "");
        assert_eq!(cond.before_install, "");
        assert_eq!(r.pos(), bytes.len());
    }

    #[test]
    fn item_conditions_pre_4_0_skips_languages_and_check() {
        // Inno Setup 3.0.0 has components+tasks; languages (4.0.1)
        // and check (4.0.0) are absent.
        let v = unicode_v(3, 0, 0);
        let mut bytes = Vec::new();
        put_str(&mut bytes, "c");
        put_str(&mut bytes, "t");
        let mut r = Reader::new(&bytes);
        let cond = ItemConditions::read(&mut r, &v).unwrap();
        assert_eq!(cond.components, "c");
        assert_eq!(cond.tasks, "t");
        assert_eq!(cond.languages, "");
        assert_eq!(cond.check, "");
        assert_eq!(r.pos(), bytes.len());
    }

    #[test]
    fn item_conditions_empty_strings_round_trip() {
        // All six fields present but each zero-length.
        let v = unicode_v(6, 0, 0);
        let mut bytes = Vec::new();
        for _ in 0..6 {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut r = Reader::new(&bytes);
        let cond = ItemConditions::read(&mut r, &v).unwrap();
        assert_eq!(cond, ItemConditions::default());
        assert_eq!(r.pos(), 24);
    }

    #[test]
    fn item_base_reads_conditions_then_winver() {
        let v = unicode_v(6, 4, 0);
        let mut bytes = Vec::new();
        for _ in 0..6 {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        // 20 zero bytes for the windows_version_range.
        bytes.extend_from_slice(&[0u8; 20]);
        let mut r = Reader::new(&bytes);
        let base = ItemBase::read(&mut r, &v).unwrap();
        assert_eq!(base.conditions, ItemConditions::default());
        assert_eq!(base.winver, WindowsVersionRange::default());
        assert_eq!(r.pos(), bytes.len());
    }

    #[test]
    fn item_conditions_propagates_truncation() {
        let v = unicode_v(6, 0, 0);
        // Length says 4 bytes but only 2 are present.
        let bytes = [4u8, 0, 0, 0, b'A', 0];
        let mut r = Reader::new(&bytes);
        let err = ItemConditions::read(&mut r, &v).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }
}
