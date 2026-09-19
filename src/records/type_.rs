//! `TSetupTypeEntry` - install-type definition (full / compact /
//! custom / user-named) read from setup-0 block 1.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupTypeEntry = packed record
//!     Name, Description, Languages, Check: String;
//!     MinVersion, OnlyBelowVersion: TSetupVersionData;
//!     Options: TSetupTypeOptions;     // 1 bit → 1 byte
//!     Typ: TSetupTypeType;            // u8 enum
//!     Size: Integer64;                // i64 (was i32 before 4.0)
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/type.cpp`.

use crate::{
    error::Error,
    records::windows::WindowsVersionRange,
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupTypeType` - kind of install type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupTypeKind {
    /// `User` - user-named type defined in `[Types]`.
    User,
    /// `DefaultFull` - compiler-emitted "Full installation" entry.
    DefaultFull,
    /// `DefaultCompact` - compiler-emitted "Compact installation"
    /// entry.
    DefaultCompact,
    /// `DefaultCustom` - compiler-emitted "Custom installation" entry.
    DefaultCustom,
}

stable_name_enum!(SetupTypeKind, {
    Self::User => "user",
    Self::DefaultFull => "default_full",
    Self::DefaultCompact => "default_compact",
    Self::DefaultCustom => "default_custom",
});

/// Parsed `TSetupTypeEntry`.
#[derive(Clone, Debug)]
pub struct TypeEntry {
    /// `Name:` directive value - the type's identifier.
    pub name: String,
    /// `Description:` directive value - wizard-shown label.
    pub description: String,
    /// `Languages:` filter (semicolon-separated). Inno Setup 4.0.1+.
    pub languages: String,
    /// `Check:` Pascal-expression / function name. Inno Setup 4.0.0+.
    pub check: String,
    /// MinVersion + OnlyBelowVersion.
    pub winver: WindowsVersionRange,
    /// Raw options byte (`set of TSetupTypeOption`).
    pub options_raw: u8,
    /// `True` when `iscustom` flag bit is set.
    pub is_custom: bool,
    /// `Typ` enum (4.0.3+; defaulted to `User` on older versions).
    pub kind: Option<SetupTypeKind>,
    /// Raw `Typ` byte.
    pub kind_raw: u8,
    /// `Size` - uncompressed-files total when this type is selected.
    /// `i64` from 4.0.0+; promoted from `i32` on earlier versions.
    pub size: i64,
}

const FLAG_IS_CUSTOM: u8 = 1;

impl TypeEntry {
    /// Reads one `TSetupTypeEntry`.
    ///
    /// # Errors
    ///
    /// String decoding / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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
