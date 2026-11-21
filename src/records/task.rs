//! `TSetupTaskEntry`: one `[Tasks]` entry, an optional action the user
//! checks on the wizard's Select Additional Tasks page, such as "create a
//! desktop icon". Tasks form a tree by their names, like components.
//!
//! On disk (`SECompressedBlockWrite`): `Name`, `Description`,
//! `GroupDescription`, `Components`, from 4.0.1 `Languages`, from 4.0.0
//! `Check`, from 4.0.0 `Level` and `Used`, the Windows version range and the
//! `Options` set. Reader reference: innoextract `setup/task.cpp`; every
//! layout is checked against upstream's own declarations by the
//! `crate::upstream` tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `TSetupTaskEntry.Options`: the entry's `Flags:`. `checkablealone` has
/// no bit; it sets [`TaskEntry::used`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskFlag {
    /// `toExclusive` (`exclusive`): mutually exclusive with its exclusive
    /// siblings, shown as a radio button.
    Exclusive,
    /// `toUnchecked` (`unchecked`): starts unchecked.
    Unchecked,
    /// `toRestart` (`restart`): ask to restart Windows when the task is
    /// selected (2.0.5+).
    Restart,
    /// `toCheckedOnce` (`checkedonce`): starts unchecked when a previous
    /// installation of the application is found (2.0.6+).
    CheckedOnce,
    /// `toDontInheritCheck` (`dontinheritcheck`): not checked automatically
    /// when its parent is (4.2.3+).
    DontInheritCheck,
}

stable_flag_enum!(TaskFlag, {
    Exclusive => "exclusive",
    Unchecked => "unchecked",
    Restart => "restart",
    CheckedOnce => "checked_once",
    DontInheritCheck => "dont_inherit_check",
});

/// One `[Tasks]` entry (`TSetupTaskEntry`). A string field the version does
/// not have is empty.
#[derive(Clone, Debug)]
pub struct TaskEntry {
    /// `Name:`: the task's internal name, `\`-separated by level, which
    /// `Tasks:` parameters name.
    pub name: String,
    /// `Description:`: the checkbox text, constants unexpanded.
    pub description: String,
    /// `GroupDescription:`: the heading consecutive tasks with the same
    /// value are grouped under.
    pub group_description: String,
    /// `Components:`: space-separated components the task belongs to; it is
    /// shown only when one of them is selected. Empty means always.
    pub components: String,
    /// `Languages:`: the languages the task is offered in (4.0.1+).
    pub languages: String,
    /// `Check:`: the `[Code]` function deciding whether it is offered
    /// (4.0.0+, or any ISX build).
    pub check: String,
    /// The entry's depth in the tree: the number of `\` or `/` in its
    /// name, 0 for a top-level entry (a byte from 6.7.0; 4.0.0+, 0 before).
    pub level: i32,
    /// `Used`: some entry names the task in `Tasks:`, or it has the
    /// `checkablealone` flag; the wizard then keeps it checkable when all its
    /// children are unchecked (4.0.0+; `true` before).
    pub used: bool,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
    /// `Options`, decoded.
    pub flags: HashSet<TaskFlag>,
    /// `Options` as stored.
    pub options_raw: u8,
}

impl FromReader for TaskEntry {
    /// Reads one `TSetupTaskEntry`.
    ///
    /// # Errors
    ///
    /// String decoding / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Task.Name")?;
        let description = read_setup_string(reader, version, "Task.Description")?;
        let group_description = read_setup_string(reader, version, "Task.GroupDescription")?;
        let components = read_setup_string(reader, version, "Task.Components")?;
        let languages = if version.at_least(4, 0, 1) {
            read_setup_string(reader, version, "Task.Languages")?
        } else {
            String::new()
        };
        let check = if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(1, 3, 24))
        {
            read_setup_string(reader, version, "Task.Check")?
        } else {
            String::new()
        };

        // 6.7.0+ narrows `Level` from Integer (i32) to Byte (1
        // byte). Pre-4.0.0 has no Level field at all.
        let level = if version.at_least(6, 7, 0) {
            i32::from(reader.u8("Task.Level")?)
        } else if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(3, 0, 3)) {
            reader.i32_le("Task.Level")?
        } else {
            0
        };

        let used = if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(3, 0, 4)) {
            reader.u8("Task.Used")? != 0
        } else {
            true
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        let options_raw = reader.u8("Task.Options")?;
        let flags = decode_task_flags(options_raw, version);

        Ok(Self {
            name,
            description,
            group_description,
            components,
            languages,
            check,
            level,
            used,
            winver,
            flags,
            options_raw,
        })
    }
}

fn decode_task_flags(raw: u8, version: &Version) -> HashSet<TaskFlag> {
    let mut table: Vec<TaskFlag> = vec![TaskFlag::Exclusive, TaskFlag::Unchecked];
    if version.at_least(2, 0, 5) {
        table.push(TaskFlag::Restart);
    }
    if version.at_least(2, 0, 6) {
        table.push(TaskFlag::CheckedOnce);
    }
    if version.at_least(4, 2, 3) {
        table.push(TaskFlag::DontInheritCheck);
    }
    crate::util::flags::decode_packed_flags(&[raw], &table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    fn v6_4() -> Version {
        Version {
            a: 6,
            b: 4,
            c: 0,
            d: 0,
            flags: VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    fn put_str(buf: &mut Vec<u8>, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let byte_len = u32::try_from(utf16.len() * 2).unwrap();
        buf.extend_from_slice(&byte_len.to_le_bytes());
        for u in utf16 {
            buf.extend_from_slice(&u.to_le_bytes());
        }
    }

    #[test]
    fn parses_desktop_icon_task() {
        let v = v6_4();
        let mut bytes = Vec::new();
        put_str(&mut bytes, "desktopicon");
        put_str(&mut bytes, "Create a &desktop icon");
        put_str(&mut bytes, "Additional shortcuts:");
        put_str(&mut bytes, ""); // components
        put_str(&mut bytes, ""); // languages
        put_str(&mut bytes, ""); // check
        bytes.extend_from_slice(&0i32.to_le_bytes()); // level
        bytes.push(1); // used
        bytes.extend_from_slice(&[0u8; 20]); // winver
        bytes.push(0b00010); // Unchecked

        let mut r = Reader::new(&bytes);
        let t = TaskEntry::read(&mut r, &v).unwrap();
        assert_eq!(t.name, "desktopicon");
        assert!(t.flags.contains(&TaskFlag::Unchecked));
        assert!(!t.flags.contains(&TaskFlag::Exclusive));
        assert_eq!(r.pos(), bytes.len());
    }
}
