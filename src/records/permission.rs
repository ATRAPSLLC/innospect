//! `TSetupPermissionEntry`: one access-control list a `Permissions:`
//! parameter grants, shared by the entries that index it (4.1.0+).
//!
//! On disk (`SECompressedBlockWrite`): `Permissions`, an `AnsiString`
//! holding an array of `TGrantPermissionEntry`. Each element is 20 bytes:
//! the SID as a 6-byte identifier authority, a sub-authority count and up
//! to two 32-bit sub-authorities (with alignment, 16 bytes), then the
//! 32-bit access mask. Reader reference: innoextract
//! `setup/permission.cpp`.

use crate::{
    error::Error,
    util::{
        encoding::read_ansi_bytes,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// One shared ACL (`TSetupPermissionEntry`, 4.1.0+).
#[derive(Clone, Debug, Default)]
pub struct PermissionEntry {
    /// `Permissions` as stored: the `TGrantPermissionEntry` array, 20 bytes
    /// per grant (see the module documentation).
    pub permissions: Vec<u8>,
}

impl FromReader for PermissionEntry {
    /// Reads one `TSetupPermissionEntry`.
    ///
    /// # Errors
    ///
    /// Truncation per [`Error`].
    fn read(reader: &mut Reader<'_>, _version: &Version) -> Result<Self, Error> {
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
