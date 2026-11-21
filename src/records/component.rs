//! `TSetupComponentEntry`: one `[Components]` entry, a part of the
//! application the user can choose to install. Components form a tree by
//! their names: `help\english` is a child of `help`.
//!
//! On disk (`SECompressedBlockWrite`): `Name`, `Description`, `Types`,
//! from 4.0.1 `Languages`, from 4.0.0 `Check` (`CheckOnce` from 6.5.0),
//! `ExtraDiskSpaceRequired`, from 4.0.0 `Level` and `Used`, the Windows
//! version range, the `Options` set and `Size`. Reader reference:
//! innoextract `setup/component.cpp`; every layout is checked against
//! upstream's own declarations by the `crate::upstream` tests.

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

/// `TSetupComponentEntry.Options`: the entry's `Flags:`. `checkablealone`
/// has no bit; it sets [`ComponentEntry::used`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComponentFlag {
    /// `coFixed` (`fixed`): the user cannot change the component's
    /// selection.
    Fixed,
    /// `coRestart` (`restart`): ask to restart Windows when the component is
    /// installed.
    Restart,
    /// `coDisableNoUninstallWarning` (`disablenouninstallwarning`): no
    /// warning that deselecting an installed component does not uninstall
    /// it.
    DisableNoUninstallWarning,
    /// `coExclusive` (`exclusive`): mutually exclusive with its exclusive
    /// siblings, shown as a radio button (3.0.8+).
    Exclusive,
    /// `coDontInheritCheck` (`dontinheritcheck`): not checked automatically
    /// when its parent is (4.2.3+).
    DontInheritCheck,
}

stable_flag_enum!(ComponentFlag, {
    Fixed => "fixed",
    Restart => "restart",
    DisableNoUninstallWarning => "disable_no_uninstall_warning",
    Exclusive => "exclusive",
    DontInheritCheck => "dont_inherit_check",
});

/// One `[Components]` entry (`TSetupComponentEntry`). A string field the
/// version does not have is empty.
#[derive(Clone, Debug)]
pub struct ComponentEntry {
    /// `Name:`: the component's internal name, `\`-separated by level,
    /// which `Components:` parameters name.
    pub name: String,
    /// `Description:`: the text the wizard shows, constants unexpanded.
    pub description: String,
    /// `Types:`: space-separated names of the setup types that include the
    /// component.
    pub types: String,
    /// `Languages:`: the languages the component is offered in (4.0.1+).
    pub languages: String,
    /// `Check:`: the `[Code]` function deciding whether it is offered
    /// (4.0.0+, or any ISX build; `CheckOnce` from 6.5.0, evaluated once).
    pub check: String,
    /// `ExtraDiskSpaceRequired:`: bytes the component needs beyond its files
    /// (64-bit from 4.0.0).
    pub extra_disk_space_required: i64,
    /// The entry's depth in the tree: the number of `\` or `/` in its
    /// name, 0 for a top-level entry (a byte from 6.7.0; 4.0.0+, 0 before).
    pub level: i32,
    /// `Used`: some entry names the component in `Components:`, or it has
    /// the `checkablealone` flag; the wizard then keeps it checkable when
    /// all its children are unchecked (4.0.0+; `true` before).
    pub used: bool,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
    /// `Options`, decoded.
    pub flags: HashSet<ComponentFlag>,
    /// `Options` as stored.
    pub options_raw: u8,
    /// `Size`: the bytes the component's files install, which the compiler
    /// computes (64-bit from 4.0.0; 2.0.0+).
    pub size: u64,
}

impl FromReader for ComponentEntry {
    /// Reads one `TSetupComponentEntry`.
    ///
    /// # Errors
    ///
    /// String decoding / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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
    crate::util::flags::decode_packed_flags(&[raw], table)
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
