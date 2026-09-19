//! Windows version structures: [`WindowsVersion`], [`TargetWindows`],
//! and [`WindowsVersionRange`].
//!
//! On-disk layout from `Shared.Struct.pas`:
//!
//! ```text
//! TSetupVersionDataVersion = packed record   // 4 bytes - also used as `Cardinal`
//!     Build:  Word;                          //   u16_le (2)
//!     Minor:  Byte;                          //   u8     (1)
//!     Major:  Byte;                          //   u8     (1)
//! end;
//!
//! TSetupVersionData = packed record          // 10 bytes
//!     WinVersion:    Cardinal;               //   u32 (4) - same shape as the triple above
//!     NTVersion:     Cardinal;               //   u32 (4) - likewise
//!     NTServicePack: Word;                   //   u16 (2) - { minor: u8, major: u8 } on disk
//! end;
//!
//! windows_version_range = [ MinVersion (10) | OnlyBelowVersion (10) ]   // 20 bytes
//! ```
//!
//! See `research-notes/11-fixed-tail.md` and innoextract
//! `research/src/setup/windows.cpp` for cross-references.

use crate::{error::Error, util::read::Reader, version::Version};

/// Windows kernel/NT version triple. Pascal `TSetupVersionDataVersion`,
/// also the on-disk shape of the `Cardinal` halves of
/// `TSetupVersionData` (4 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowsVersion {
    /// `Build` - minor build number (e.g. 19045 for Windows 10 22H2).
    pub build: u16,
    /// `Minor` - Windows minor version.
    pub minor: u8,
    /// `Major` - Windows major version.
    pub major: u8,
}

impl WindowsVersion {
    /// Reads 4 bytes for a Windows version triple.
    ///
    /// Inno Setup format ≥ 1.3.19 stores a leading `u16` build;
    /// earlier versions omit it (build defaults to 0).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] / [`Error::Overflow`] on EOF.
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let build = if version.at_least(1, 3, 19) {
            reader.u16_le("WindowsVersion.Build")?
        } else {
            0
        };
        let minor = reader.u8("WindowsVersion.Minor")?;
        let major = reader.u8("WindowsVersion.Major")?;
        Ok(Self {
            build,
            minor,
            major,
        })
    }
}

/// `nt_service_pack` - major / minor service pack number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServicePack {
    /// `NTServicePack.Minor`.
    pub minor: u8,
    /// `NTServicePack.Major`.
    pub major: u8,
}

/// `TSetupEntryBitness` - Inno Setup 6.7.0+ replacement for the
/// pre-6.7 `*32Bit` / `*64Bit` flag bits on file / registry / run
/// entries. One byte on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bitness {
    /// `ebInstallDefault` - match the installer's default bitness.
    InstallDefault,
    /// `eb32Bit`.
    Bits32,
    /// `eb64Bit`.
    Bits64,
    /// `ebNativeBit` - the native bitness of the running OS.
    Native,
    /// `ebCurrentProcessBit` - the bitness of the currently-running
    /// installer process.
    CurrentProcess,
}

stable_name_enum!(Bitness, {
    Self::InstallDefault => "install_default",
    Self::Bits32 => "bits32",
    Self::Bits64 => "bits64",
    Self::Native => "native",
    Self::CurrentProcess => "current_process",
});

impl Bitness {
    /// Decodes a raw `TSetupEntryBitness` byte, or [`None`] for an unknown
    /// value. Used both during parsing and to re-derive the label from a
    /// stored `bitness_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::InstallDefault),
            1 => Some(Self::Bits32),
            2 => Some(Self::Bits64),
            3 => Some(Self::Native),
            4 => Some(Self::CurrentProcess),
            _ => None,
        }
    }
}

/// Pascal `TSetupVersionData` - a target Windows version pinning the
/// underlying kernel + NT version + service pack. 10 bytes on disk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TargetWindows {
    /// `WinVersion`.
    pub windows: WindowsVersion,
    /// `NTVersion`.
    pub nt: WindowsVersion,
    /// `NTServicePack`.
    pub service_pack: ServicePack,
}

impl TargetWindows {
    /// Reads a `TSetupVersionData` from the reader. 10 bytes for
    /// versions ≥ 1.3.19; 8 bytes for older versions (no service-pack
    /// field).
    ///
    /// # Errors
    ///
    /// Same as [`WindowsVersion::read`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let windows = WindowsVersion::read(reader, version)?;
        let nt = WindowsVersion::read(reader, version)?;
        let service_pack = if version.at_least(1, 3, 19) {
            ServicePack {
                minor: reader.u8("ServicePack.Minor")?,
                major: reader.u8("ServicePack.Major")?,
            }
        } else {
            ServicePack::default()
        };
        Ok(Self {
            windows,
            nt,
            service_pack,
        })
    }
}

/// Min / OnlyBelow version range. 20 bytes on disk (two
/// [`TargetWindows`] back to back). Used by both `TSetupHeader` and
/// every per-record `ItemBase`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowsVersionRange {
    /// Minimum supported Windows version (`MinVersion` /
    /// `WindowsVersionRange.begin` per innoextract).
    pub min: TargetWindows,
    /// Upper-exclusive bound (`OnlyBelowVersion` / `.end`).
    pub only_below: TargetWindows,
}

impl WindowsVersionRange {
    /// Reads 20 bytes (two [`TargetWindows`]).
    ///
    /// # Errors
    ///
    /// Same as [`TargetWindows::read`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let min = TargetWindows::read(reader, version)?;
        let only_below = TargetWindows::read(reader, version)?;
        Ok(Self { min, only_below })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    fn modern_version() -> Version {
        Version {
            a: 6,
            b: 4,
            c: 0,
            d: 1,
            flags: VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    #[test]
    fn windows_version_decodes_4_bytes() {
        // Build = 19045, Minor = 0, Major = 10.
        let bytes = [0x65, 0x4A, 0x00, 0x0A];
        let mut r = Reader::new(&bytes);
        let v = WindowsVersion::read(&mut r, &modern_version()).unwrap();
        assert_eq!(v.build, 19045);
        assert_eq!(v.minor, 0);
        assert_eq!(v.major, 10);
        assert_eq!(r.pos(), 4);
    }

    #[test]
    fn target_windows_decodes_10_bytes() {
        // win = (build=22000, 0, 10), nt = (10240, 0, 10), sp = (1, 2)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&22000u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 10]);
        bytes.extend_from_slice(&10240u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 10]);
        bytes.extend_from_slice(&[1, 2]);
        assert_eq!(bytes.len(), 10);
        let mut r = Reader::new(&bytes);
        let t = TargetWindows::read(&mut r, &modern_version()).unwrap();
        assert_eq!(t.windows.build, 22000);
        assert_eq!(t.nt.build, 10240);
        assert_eq!(t.service_pack.minor, 1);
        assert_eq!(t.service_pack.major, 2);
        assert_eq!(r.pos(), 10);
    }

    #[test]
    fn windows_version_range_decodes_20_bytes() {
        let bytes = vec![0u8; 20];
        let mut r = Reader::new(&bytes);
        let _range = WindowsVersionRange::read(&mut r, &modern_version()).unwrap();
        assert_eq!(r.pos(), 20);
    }
}
