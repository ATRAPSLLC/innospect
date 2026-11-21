//! The Inno Setup version an installer's setup data was written by: the
//! [`Version`] / [`Variant`] / [`VersionFlags`] types, decoded from the
//! SetupID marker that begins setup-0.
//!
//! The 64-byte ASCII marker that begins setup-0 (`SetupID` in upstream's
//! `Struct.pas`) takes one of three forms across the format's history:
//!
//! - **Stock**, e.g. `Inno Setup Setup Data (6.4.0.1) (u)\0...`
//! - **ISX** (My Inno Setup Extensions), e.g.
//!   `My Inno Setup Extensions Setup Data (3.0.4)\0...`
//! - **Legacy 1.2.10**, the 12-byte form `i1.2.10--16\x1a` or
//!   `i1.2.10--32\x1a`
//!
//! The stock and 1.2.10 forms are verified against upstream's source and
//! real installers (the 32-bit 1.2.10 build against the source only). ISX
//! markers are recognised and their known layout differences applied, but
//! no ISX installer is tested; the BlackBox / GOG / GOG Galaxy repackagings
//! are not detected (see [`Variant`]).

/// A parsed Inno Setup version, including variant flags and the raw
/// 64-byte marker bytes for diagnostic display.
///
/// Version components follow the standard Inno Setup numbering:
/// `a.b.c[.d]` where `d` is the optional fourth qualifier byte used
/// for point releases like `6.4.0.1`.
#[derive(Clone, Debug)]
pub struct Version {
    /// Major version (e.g. `6` in `6.4.0.1`).
    pub a: u8,
    /// Minor version (e.g. `4` in `6.4.0.1`).
    pub b: u8,
    /// Patch version (e.g. `0` in `6.4.0.1`).
    pub c: u8,
    /// Fourth qualifier (e.g. `1` in `6.4.0.1`); `0` when absent.
    pub d: u8,
    /// Variant flags decoded from the marker.
    pub flags: VersionFlags,
    /// The raw 64-byte marker as it appeared on disk, including any
    /// trailing null padding.
    pub raw_marker: [u8; 64],
}

impl Version {
    /// Returns `true` if this version is at least `(a, b, c)`.
    ///
    /// The fourth qualifier `d` is ignored. Use [`Version::at_least_4`]
    /// when the comparison must consider it (e.g. distinguishing
    /// `7.0.0.3` from `7.0.0.0`).
    #[must_use]
    pub fn at_least(&self, a: u8, b: u8, c: u8) -> bool {
        (self.a, self.b, self.c) >= (a, b, c)
    }

    /// Returns `true` if this version is at least `(a, b, c, d)`.
    #[must_use]
    pub fn at_least_4(&self, a: u8, b: u8, c: u8, d: u8) -> bool {
        (self.a, self.b, self.c, self.d) >= (a, b, c, d)
    }

    /// `true` when the installer uses UTF-16LE strings (the `(u)` /
    /// `(U)` marker suffix).
    #[must_use]
    pub fn is_unicode(&self) -> bool {
        self.flags.contains(VersionFlags::UNICODE)
    }

    /// `true` when the installer is the My Inno Setup Extensions
    /// variant.
    #[must_use]
    pub fn is_isx(&self) -> bool {
        self.flags.contains(VersionFlags::ISX)
    }

    /// `true` when the installer is the legacy 16-bit
    /// (`i1.2.10--16\x1a`) variant.
    #[must_use]
    pub fn is_16bit(&self) -> bool {
        self.flags.contains(VersionFlags::BITS16)
    }

    /// Returns the marker as a `&str`, trimming trailing null padding.
    /// Falls back to `""` if the visible portion isn't valid UTF-8.
    #[must_use]
    pub fn marker_str(&self) -> &str {
        let end = self
            .raw_marker
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.raw_marker.len());
        let visible = self.raw_marker.get(..end).unwrap_or(&[]);
        core::str::from_utf8(visible).unwrap_or("")
    }
}

/// `a.b.c`, `.d` when it is not 0, then ` (u)` for a Unicode build, ` (ISX)`
/// for My Inno Setup Extensions and ` (16-bit)` for a 16-bit one: `6.4.0.1
/// (u)`, `5.5.7`, `1.2.10 (16-bit)`. The marker as written is
/// [`Version::marker_str`].
impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.a, self.b, self.c)?;
        if self.d != 0 {
            write!(f, ".{}", self.d)?;
        }
        if self.is_unicode() {
            f.write_str(" (u)")?;
        }
        if self.is_isx() {
            f.write_str(" (ISX)")?;
        }
        if self.is_16bit() {
            f.write_str(" (16-bit)")?;
        }
        Ok(())
    }
}

/// Which kind of installer the SetupID marker says this is.
///
/// The parser reports [`Variant::Stock`], [`Variant::Isx`] or
/// [`Variant::Legacy1210`], from the marker alone. [`Variant::BlackBox`],
/// [`Variant::Gog`] and [`Variant::GogGalaxy`] name repackagings this crate
/// does not detect or support; it never reports them, and they are kept so
/// a future detector does not change the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Variant {
    /// An installer built by upstream's Inno Setup compiler.
    Stock,
    /// My Inno Setup Extensions, Martijn Laan's fork that merged into
    /// Inno Setup 4.0. Recognised, not tested.
    Isx,
    /// The 12-byte `i1.2.10--16\x1a` / `--32\x1a` marker 1.2.10 to 1.2.16
    /// write, for their 16-bit and 32-bit builds. The 16-bit build is
    /// tested against 1.2.16's own package; no 32-bit 1.2 compiler
    /// survives, so that build is checked against upstream's record
    /// layouts only.
    Legacy1210,
    /// An installer whose marker was stripped or replaced but whose layout
    /// is otherwise Inno Setup's. Not detected; never reported.
    BlackBox,
    /// A GOG.com installer, with the `info.script.json` side file. Not
    /// detected; never reported.
    Gog,
    /// A GOG Galaxy installer, with multi-volume RAR file parts. Not
    /// detected; never reported.
    GogGalaxy,
}

stable_name_enum!(Variant, {
    Self::Stock => "stock",
    Self::Isx => "isx",
    Self::Legacy1210 => "legacy_1_2_10",
    Self::BlackBox => "blackbox",
    Self::Gog => "gog",
    Self::GogGalaxy => "gog_galaxy",
});

bitflags::bitflags! {
    /// Boolean modifiers on the parsed [`Version`], decoded from the
    /// marker. Stored as a small bitset for cheap copying.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct VersionFlags: u8 {
        /// 16-bit installer layout. Set only by the legacy
        /// `i1.2.10--16\x1a` marker.
        const BITS16 = 1 << 0;
        /// UTF-16LE strings. Set by `(u)` or `(U)` after the version
        /// number.
        const UNICODE = 1 << 1;
        /// My Inno Setup Extensions variant. Set by the
        /// `My Inno Setup Extensions Setup Data` marker prefix.
        const ISX = 1 << 2;
    }
}
