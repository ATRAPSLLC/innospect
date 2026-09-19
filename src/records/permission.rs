//! `TSetupPermissionEntry` - opaque permissions blob.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupPermissionEntry = packed record
//!     Permissions: AnsiString;     // an array of TGrantPermissionEntry
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/permission.cpp`. The inner
//! `TGrantPermissionEntry[]` (each entry: 16-byte SID + 4-byte mask
//! = 20 bytes) is surfaced as raw bytes for callers to dump or
//! hash; typed access can be layered on without changing the wire
//! shape.
//!
//! See `research-notes/07-issrc-shared-struct.md` §B for the inner
//! struct's full byte layout.

use crate::{
    error::Error,
    util::{encoding::read_ansi_bytes, read::Reader},
    version::Version,
};

/// Parsed `TSetupPermissionEntry`. Inno Setup 4.1.0+.
#[derive(Clone, Debug, Default)]
pub struct PermissionEntry {
    /// Raw bytes of the inner `TGrantPermissionEntry[]` blob, as
    /// stored on disk. Length is always a multiple of 20 in
    /// well-formed installers.
    pub permissions: Vec<u8>,
}

impl PermissionEntry {
    /// Reads one `TSetupPermissionEntry`.
    ///
    /// # Errors
    ///
    /// Truncation per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, _version: &Version) -> Result<Self, Error> {
        let permissions = read_ansi_bytes(reader, "Permission.Permissions")?;
        Ok(Self { permissions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    #[test]
    fn parses_empty_permissions_blob() {
        let bytes = [0u8; 4];
        let mut r = Reader::new(&bytes);
        let p = PermissionEntry::read(
            &mut r,
            &Version {
                a: 6,
                b: 4,
                c: 0,
                d: 0,
                flags: VersionFlags::UNICODE,
                raw_marker: [0u8; 64],
            },
        )
        .unwrap();
        assert!(p.permissions.is_empty());
        assert_eq!(r.pos(), 4);
    }

    #[test]
    fn parses_two_grant_entries() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&40u32.to_le_bytes()); // length
        bytes.extend(std::iter::repeat_n(0xAB, 40));
        let mut r = Reader::new(&bytes);
        let p = PermissionEntry::read(
            &mut r,
            &Version {
                a: 6,
                b: 4,
                c: 0,
                d: 0,
                flags: VersionFlags::UNICODE,
                raw_marker: [0u8; 64],
            },
        )
        .unwrap();
        assert_eq!(p.permissions.len(), 40);
        assert_eq!(r.pos(), bytes.len());
    }
}
