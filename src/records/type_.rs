//! `TSetupTypeEntry`: one setup type, a named selection of components the
//! user picks on the wizard's Select Components page. The compiler adds
//! the three default types when the script has components but no
//! `[Types]` section.
//!
//! On disk (`SECompressedBlockWrite`): `Name`, `Description`, from 4.0.1
//! `Languages`, from 4.0.0 `Check` (`CheckOnce` from 6.5.0), the Windows
//! version range, the `Options` set, from 4.0.3 `Typ`, and `Size` (64-bit
//! from 4.0.0). Reader reference: innoextract `setup/type.cpp`; every
//! layout is checked against upstream's own declarations by the
//! `crate::upstream` tests.

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `Typ` (`TSetupTypeType`): where a setup type came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupTypeKind {
    /// `ttUser`: a `[Types]` entry.
    User,
    /// `ttDefaultFull`: the compiler's default "full" type.
    DefaultFull,
    /// `ttDefaultCompact`: the compiler's default "compact" type.
    DefaultCompact,
    /// `ttDefaultCustom`: the compiler's default "custom" type.
    DefaultCustom,
}

stable_name_enum!(SetupTypeKind, {
    Self::User => "user",
    Self::DefaultFull => "default_full",
    Self::DefaultCompact => "default_compact",
    Self::DefaultCustom => "default_custom",
});

/// One setup type (`TSetupTypeEntry`). A string field the version does not
/// have is empty.
#[derive(Clone, Debug)]
pub struct TypeEntry {
    /// `Name:`: the type's internal name, which `[Components]` entries list
    /// in `Types:`.
    pub name: String,
    /// `Description:`: the text the wizard shows, constants unexpanded.
    pub description: String,
    /// `Languages:`: the languages the type is offered in (4.0.1+).
    pub languages: String,
    /// `Check:`: the `[Code]` function deciding whether the type is offered
    /// (4.0.0+, or any ISX build). From 6.5.0 upstream calls it `CheckOnce`:
    /// Setup evaluates it once.
    pub check: String,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
    /// `Options` as stored; bit 0 is `toIsCustom`.
    pub options_raw: u8,
    /// `toIsCustom` (`iscustom` flag): the type Setup switches to when the
    /// user changes the component selection by hand.
    pub is_custom: bool,
    /// `Typ`, decoded (4.0.3+; [`SetupTypeKind::User`] before). `None` for a
    /// value this crate does not know.
    pub kind: Option<SetupTypeKind>,
    /// `Typ` as stored; 0 when the version has no such byte.
    pub kind_raw: u8,
    /// `Size`: the bytes the type's components install, which the compiler
    /// computes (64-bit from 4.0.0; 2.0.0+).
    pub size: i64,
}

const FLAG_IS_CUSTOM: u8 = 1;

impl FromReader for TypeEntry {
    /// Reads one `TSetupTypeEntry`.
    ///
    /// # Errors
    ///
    /// String decoding / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Type.Name")?;
        let description = read_setup_string(reader, version, "Type.Description")?;
        let languages = if version.at_least(4, 0, 1) {
            read_setup_string(reader, version, "Type.Languages")?
        } else {
            String::new()
        };
        let check = if version.at_least(4, 0, 0) || (version.is_isx() && version.at_least(1, 3, 24))
        {
            read_setup_string(reader, version, "Type.Check")?
        } else {
            String::new()
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        let options_raw = reader.u8("Type.Options")?;
        let is_custom = (options_raw & FLAG_IS_CUSTOM) != 0;

        let (kind, kind_raw) = if version.at_least(4, 0, 3) {
            let raw = reader.u8("Type.Typ")?;
            (SetupTypeKind::from_raw(raw), raw)
        } else {
            (Some(SetupTypeKind::User), 0)
        };

        let size = if version.at_least(4, 0, 0) {
            reader.i64_le("Type.Size")?
        } else if version.at_least(2, 0, 0) || (version.is_isx() && version.at_least(1, 3, 24)) {
            i64::from(reader.i32_le("Type.Size")?)
        } else {
            0
        };

        Ok(Self {
            name,
            description,
            languages,
            check,
            winver,
            options_raw,
            is_custom,
            kind,
            kind_raw,
            size,
        })
    }
}

impl SetupTypeKind {
    /// Resolves the persisted on-disk discriminant byte back to a
    /// [`SetupTypeKind`], or [`None`] for an unknown value. Used to re-derive
    /// the label from a stored `kind_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::User),
            1 => Some(Self::DefaultFull),
            2 => Some(Self::DefaultCompact),
            3 => Some(Self::DefaultCustom),
            _ => None,
        }
    }
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
    fn parses_default_full_type() {
        let v = v6_4();
        let mut bytes = Vec::new();
        put_str(&mut bytes, "full");
        put_str(&mut bytes, "Full installation");
        put_str(&mut bytes, ""); // languages
        put_str(&mut bytes, ""); // check
        bytes.extend_from_slice(&[0u8; 20]); // winver
        bytes.push(0); // options (no iscustom)
        bytes.push(1); // Typ = DefaultFull
        bytes.extend_from_slice(&123_456_789i64.to_le_bytes()); // size

        let mut r = Reader::new(&bytes);
        let entry = TypeEntry::read(&mut r, &v).unwrap();
        assert_eq!(entry.name, "full");
        assert_eq!(entry.description, "Full installation");
        assert!(!entry.is_custom);
        assert_eq!(entry.kind, Some(SetupTypeKind::DefaultFull));
        assert_eq!(entry.size, 123_456_789);
        assert_eq!(r.pos(), bytes.len());
    }

    #[test]
    fn parses_user_custom_type() {
        let v = v6_4();
        let mut bytes = Vec::new();
        put_str(&mut bytes, "myCustom");
        put_str(&mut bytes, "");
        put_str(&mut bytes, "");
        put_str(&mut bytes, "");
        bytes.extend_from_slice(&[0u8; 20]);
        bytes.push(FLAG_IS_CUSTOM);
        bytes.push(0); // Typ = User
        bytes.extend_from_slice(&0i64.to_le_bytes());

        let mut r = Reader::new(&bytes);
        let entry = TypeEntry::read(&mut r, &v).unwrap();
        assert!(entry.is_custom);
        assert_eq!(entry.kind, Some(SetupTypeKind::User));
    }
}
