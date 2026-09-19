//! `TSetupComponentEntry` - installable component definition.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupComponentEntry = packed record
//!     Name, Description, Types, Languages, Check: String;
//!     ExtraDiskSpaceRequired: Integer64;     // u32 pre-4.0
//!     Level: Integer;                        // since 4.0.0
//!     Used: Boolean;                         // since 4.0.0
//!     MinVersion, OnlyBelowVersion: TSetupVersionData;
//!     Options: TSetupComponentOptions;       // 1 byte (3..5 bits)
//!     Size: Integer64;                       // u64; was u32 pre-4.0
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/component.cpp`. Pascal flag
//! ordering (matches innoextract's `STORED_FLAGS_MAP`):
//! - 0..2 always: Fixed, Restart, DisableNoUninstallWarning
//! - +3 (3.0.8+): Exclusive
//! - +4 (4.2.3+): DontInheritCheck

use std::collections::HashSet;

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupComponentOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ComponentFlag {
    Fixed,
    Restart,
    DisableNoUninstallWarning,
    Exclusive,
    DontInheritCheck,
}

stable_flag_enum!(ComponentFlag, {
    Fixed => "fixed",
    Restart => "restart",
    DisableNoUninstallWarning => "disable_no_uninstall_warning",
    Exclusive => "exclusive",
    DontInheritCheck => "dont_inherit_check",
});

/// Parsed `TSetupComponentEntry`.
#[derive(Clone, Debug)]
pub struct ComponentEntry {
    /// `Name:` directive.
    pub name: String,
    /// `Description:` directive.
    pub description: String,
    /// `Types:` directive (semicolon-separated type names this
    /// component is included by).
    pub types: String,
    /// `Languages:` filter. 4.0.1+.
    pub languages: String,
    /// `Check:` directive. 4.0.0+ (or ISX 1.3.24+).
    pub check: String,
    /// `ExtraDiskSpaceRequired` - disk usage attributable to this
    /// component beyond the file payload sum.
    pub extra_disk_space_required: i64,
    /// `Level:` directive (component priority). 4.0.0+ (or ISX 3.0.3+).
    pub level: i32,
    /// `Used:` boolean (4.0.0+ / ISX 3.0.4+). Defaults to `true`.
    pub used: bool,
    /// MinVersion + OnlyBelowVersion.
    pub winver: WindowsVersionRange,
    /// Decoded options.
    pub flags: HashSet<ComponentFlag>,
    /// Raw `Options` byte.
    pub options_raw: u8,
    /// `Size` - total file size when this component is selected.
    /// `u64` from 4.0.0+; `u32`-promoted from earlier versions.
    pub size: u64,
}

impl ComponentEntry {
    /// Reads one `TSetupComponentEntry`.
    ///
    /// # Errors
    ///
    /// String decoding / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Component.Name")?;
        let description = read_setup_string(reader, version, "Component.Description")?;
        let types = read_setup_string(reader, version, "Component.Types")?;
        let languages = if version.at_least(4, 0, 1) {
            read_setup_string(reader, version, "Component.Languages")?
        } else {
            String::new()
        };
        let check = if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(1, 3, 24))
        {
            read_setup_string(reader, version, "Component.Check")?
        } else {
            String::new()
        };

        let extra_disk_space_required = if version.at_least(4, 0, 0) {
            reader.i64_le("Component.ExtraDiskSpaceRequired")?
        } else {
            i64::from(reader.i32_le("Component.ExtraDiskSpaceRequired")?)
        };

        // 6.7.0+ narrows `Level` from Integer (i32) to Byte.
        let level = if version.at_least(6, 7, 0) {
            i32::from(reader.u8("Component.Level")?)
        } else if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(3, 0, 3)) {
            reader.i32_le("Component.Level")?
        } else {
            0
        };

        let used = if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(3, 0, 4)) {
            reader.u8("Component.Used")? != 0
        } else {
            true
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        // Options bit layout per innoextract version table.
        let options_raw = reader.u8("Component.Options")?;
        let flags = decode_component_flags(options_raw, version);

        let size = if version.at_least(4, 0, 0) {
            reader.u64_le("Component.Size")?
        } else if version.at_least(2, 0, 0) || (version.is_isx() && version.at_least(1, 3, 24)) {
            u64::from(reader.u32_le("Component.Size")?)
        } else {
            0
        };

        Ok(Self {
            name,
            description,
            types,
            languages,
            check,
            extra_disk_space_required,
            level,
            used,
            winver,
            flags,
            options_raw,
            size,
        })
    }
}

fn decode_component_flags(raw: u8, version: &Version) -> HashSet<ComponentFlag> {
    let table: &[ComponentFlag] = if version.at_least(4, 2, 3) {
        &[
            ComponentFlag::Fixed,
            ComponentFlag::Restart,
            ComponentFlag::DisableNoUninstallWarning,
            ComponentFlag::Exclusive,
            ComponentFlag::DontInheritCheck,
        ]
    } else if version.at_least(3, 0, 8) || (version.is_isx() && version.at_least_4(3, 0, 6, 1)) {
        &[
            ComponentFlag::Fixed,
            ComponentFlag::Restart,
            ComponentFlag::DisableNoUninstallWarning,
            ComponentFlag::Exclusive,
        ]
    } else {
        &[
            ComponentFlag::Fixed,
            ComponentFlag::Restart,
            ComponentFlag::DisableNoUninstallWarning,
        ]
    };
    super::decode_packed_flags(&[raw], table)
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
    fn parses_minimal_component() {
        let v = v6_4();
        let mut bytes = Vec::new();
        put_str(&mut bytes, "core");
        put_str(&mut bytes, "Core program files");
        put_str(&mut bytes, ""); // types
        put_str(&mut bytes, ""); // languages
        put_str(&mut bytes, ""); // check
        bytes.extend_from_slice(&0i64.to_le_bytes()); // extra_disk_space
        bytes.extend_from_slice(&1i32.to_le_bytes()); // level
        bytes.push(1); // used = true
        bytes.extend_from_slice(&[0u8; 20]); // winver
        bytes.push(0b0_0001); // options: Fixed
        bytes.extend_from_slice(&999u64.to_le_bytes()); // size

        let mut r = Reader::new(&bytes);
        let c = ComponentEntry::read(&mut r, &v).unwrap();
        assert_eq!(c.name, "core");
        assert_eq!(c.level, 1);
        assert!(c.used);
        assert_eq!(c.size, 999);
        assert!(c.flags.contains(&ComponentFlag::Fixed));
        assert!(!c.flags.contains(&ComponentFlag::Exclusive));
        assert_eq!(r.pos(), bytes.len());
    }
}
