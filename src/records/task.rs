//! `TSetupTaskEntry` - installable task definition (`[Tasks]`
//! section directives).
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupTaskEntry = packed record
//!     Name, Description, GroupDescription, Components,
//!         Languages, Check: String;
//!     Level: Integer;          // since 4.0.0
//!     Used: Boolean;           // since 4.0.0
//!     MinVersion, OnlyBelowVersion: TSetupVersionData;
//!     Options: TSetupTaskOptions;  // 1-byte flag set
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/task.cpp`. Flag layout:
//! - 0: Exclusive (always)
//! - 1: Unchecked (always)
//! - 2: Restart (2.0.5+)
//! - 3: CheckedOnce (2.0.6+)
//! - 4: DontInheritCheck (4.2.3+)

use std::collections::HashSet;

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupTaskOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum TaskFlag {
    Exclusive,
    Unchecked,
    Restart,
    CheckedOnce,
    DontInheritCheck,
}

stable_flag_enum!(TaskFlag, {
    Exclusive => "exclusive",
    Unchecked => "unchecked",
    Restart => "restart",
    CheckedOnce => "checked_once",
    DontInheritCheck => "dont_inherit_check",
});

/// Parsed `TSetupTaskEntry`.
#[derive(Clone, Debug)]
pub struct TaskEntry {
    /// `Name:` directive.
    pub name: String,
    /// `Description:` directive.
    pub description: String,
    /// `GroupDescription:` directive - section header in the wizard's
    /// task list.
    pub group_description: String,
    /// `Components:` filter (semicolon-separated).
    pub components: String,
    /// `Languages:` filter. 4.0.1+.
    pub languages: String,
    /// `Check:` directive. 4.0.0+ (or ISX 1.3.24+).
    pub check: String,
    /// `Level:` directive - task priority.
    pub level: i32,
    /// `Used:` boolean. Defaults to `true` on older versions.
    pub used: bool,
    /// MinVersion + OnlyBelowVersion.
    pub winver: WindowsVersionRange,
    /// Decoded options.
    pub flags: HashSet<TaskFlag>,
    /// Raw `Options` byte.
    pub options_raw: u8,
}

impl TaskEntry {
    /// Reads one `TSetupTaskEntry`.
    ///
    /// # Errors
    ///
    /// String decoding / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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
    super::decode_packed_flags(&[raw], &table)
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
