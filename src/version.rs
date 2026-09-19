//! Inno Setup version marker parsing and the [`Version`] / [`Variant`]
//! / [`VersionFlags`] types.
//!
//! The 64-byte ASCII marker that begins setup-0 takes one of three
//! forms across the format's history (see `RESEARCH.md` §3 and
//! `research-notes/02-loader-and-version.md` for the canonical
//! reference):
//!
//! - **Stock**, e.g. `Inno Setup Setup Data (6.4.0.1) (u)\0...`
//! - **ISX** (My Inno Setup Extensions), e.g.
//!   `My Inno Setup Extensions Setup Data (3.0.4)\0...`
//! - **Legacy 1.2.10**, the 12-byte form `i1.2.10--16\x1a` or
//!   `i1.2.10--32\x1a`
//!
//! BlackBox / GOG / GOG Galaxy modifications are detected at later
//! stages of the parse and reported via [`Variant`].

use crate::{error::Error, util::read::Reader};

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

/// Variant of an Inno Setup installer, beyond the core version numbers.
///
/// Detection happens in stages: the marker tells us [`Variant::Stock`]
/// vs [`Variant::Isx`] vs [`Variant::Legacy1210`] up front; downstream
/// parsing may upgrade the result to [`Variant::BlackBox`],
/// [`Variant::Gog`], or [`Variant::GogGalaxy`] if those modifications
/// are detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Variant {
    /// Standard upstream Inno Setup installer.
    Stock,
    /// My Inno Setup Extensions (Martijn Laan's pre-merger fork).
    Isx,
    /// Legacy 12-byte `i1.2.10--16\x1a` / `--32\x1a` marker.
    Legacy1210,
    /// Marker stripped or replaced with garbage but the layout is
    /// otherwise valid Inno Setup. Reported by later parsing stages.
    BlackBox,
    /// GOG.com installer with the `info.script.json` side file.
    /// Reported by later parsing stages.
    Gog,
    /// GOG Galaxy installer with multi-volume RAR file parts.
    /// Reported by later parsing stages.
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

const STOCK_PREFIX: &[u8] = b"Inno Setup Setup Data (";
const ISX_PREFIX: &[u8] = b"My Inno Setup Extensions Setup Data (";
const LEGACY_1210_16: &[u8] = b"i1.2.10--16\x1a";
const LEGACY_1210_32: &[u8] = b"i1.2.10--32\x1a";

/// Parses the 64-byte marker at the start of setup-0 and returns the
/// decoded [`Version`] + initial [`Variant`] guess.
///
/// # Errors
///
/// Returns [`Error::UnsupportedVersion`] if the marker matches neither
/// the stock, ISX, nor legacy 1.2.10 form.
pub(crate) fn parse_marker(marker: &[u8; 64]) -> Result<(Version, Variant), Error> {
    if let Some(v) = parse_legacy_1210(marker) {
        return Ok((v, Variant::Legacy1210));
    }
    if let Some(v) = parse_modern(marker, ISX_PREFIX, VersionFlags::ISX) {
        return Ok((v, Variant::Isx));
    }
    if let Some(v) = parse_modern(marker, STOCK_PREFIX, VersionFlags::empty()) {
        return Ok((v, Variant::Stock));
    }
    Err(Error::UnsupportedVersion { marker: *marker })
}

fn parse_legacy_1210(marker: &[u8; 64]) -> Option<Version> {
    let prefix = marker.get(..LEGACY_1210_16.len())?;
    if prefix == LEGACY_1210_16 {
        return Some(Version {
            a: 1,
            b: 2,
            c: 10,
            d: 0,
            flags: VersionFlags::BITS16,
            raw_marker: *marker,
        });
    }
    if prefix == LEGACY_1210_32 {
        return Some(Version {
            a: 1,
            b: 2,
            c: 10,
            d: 0,
            flags: VersionFlags::empty(),
            raw_marker: *marker,
        });
    }
    None
}

fn parse_modern(marker: &[u8; 64], prefix: &[u8], extra_flags: VersionFlags) -> Option<Version> {
    if !marker.starts_with(prefix) {
        return None;
    }
    let after_prefix = marker.get(prefix.len()..)?;
    // After the opening `(` is `X.Y.Z[.D]) [(u)]\0...`
    let close = after_prefix.iter().position(|&b| b == b')')?;
    let inside = after_prefix.get(..close)?;
    let (a, b, c, d) = parse_dotted(inside)?;

    // Look for an optional trailing `(u)` or `(U)` flag block.
    let mut flags = extra_flags;
    let after_close = after_prefix.get(close.checked_add(1)?..).unwrap_or(&[]);
    if has_unicode_flag(after_close) {
        flags |= VersionFlags::UNICODE;
    }

    Some(Version {
        a,
        b,
        c,
        d,
        flags,
        raw_marker: *marker,
    })
}

fn parse_dotted(s: &[u8]) -> Option<(u8, u8, u8, u8)> {
    // Drop a trailing `a` qualifier - innoextract observes this on
    // some pre-release Inno Setup builds (e.g. `5.5.7a`). It does not
    // affect binary layout, so we discard it.
    let core = match s.last().copied() {
        Some(b'a') => s.get(..s.len().checked_sub(1)?)?,
        _ => s,
    };
    let mut parts = core.split(|&b| b == b'.');
    let a = parse_u8(parts.next()?)?;
    let b = parse_u8(parts.next()?)?;
    let c = parse_u8(parts.next()?)?;
    let d = match parts.next() {
        Some(p) => parse_u8(p)?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c, d))
}

fn parse_u8(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        // byte - b'0' is in 0..=9; saturating + checked_mul protect
        // against malformed multi-byte fields.
        let digit = u32::from(byte.saturating_sub(b'0'));
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    if value > u32::from(u8::MAX) {
        return None;
    }
    Some(value as u8)
}

fn has_unicode_flag(after_close: &[u8]) -> bool {
    // Trim leading whitespace, then expect `(u)` or `(U)`.
    let mut i = 0usize;
    while let Some(&b) = after_close.get(i) {
        if b != b' ' {
            break;
        }
        i = i.saturating_add(1);
    }
    let tail = after_close.get(i..).unwrap_or(&[]);
    matches!(tail.get(..3), Some(b"(u)" | b"(U)"))
}

/// Reads a [`Version`] from the beginning of the given setup-0 buffer
/// (which begins with the 64-byte SetupID marker).
///
/// # Errors
///
/// - [`Error::Truncated`] if `setup0` is shorter than 64 bytes.
/// - [`Error::UnsupportedVersion`] from [`parse_marker`].
pub(crate) fn read_marker(setup0: &[u8]) -> Result<(Version, Variant), Error> {
    let mut r = Reader::new(setup0);
    let marker = r.array::<64>("SetupID marker")?;
    parse_marker(&marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pad_marker(s: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let take = s.len().min(out.len());
        out[..take].copy_from_slice(&s[..take]);
        out
    }

    #[test]
    fn stock_marker_with_unicode() {
        let m = pad_marker(b"Inno Setup Setup Data (6.4.0.1) (u)");
        let (v, variant) = parse_marker(&m).unwrap();
        assert_eq!((v.a, v.b, v.c, v.d), (6, 4, 0, 1));
        assert!(v.is_unicode());
        assert!(!v.is_isx());
        assert_eq!(variant, Variant::Stock);
        assert_eq!(v.marker_str(), "Inno Setup Setup Data (6.4.0.1) (u)");
    }

    #[test]
    fn stock_marker_no_qualifier() {
        let m = pad_marker(b"Inno Setup Setup Data (6.1.0) (u)");
        let (v, _) = parse_marker(&m).unwrap();
        assert_eq!((v.a, v.b, v.c, v.d), (6, 1, 0, 0));
        assert!(v.is_unicode());
    }

    #[test]
    fn isx_marker() {
        let m = pad_marker(b"My Inno Setup Extensions Setup Data (3.0.4)");
        let (v, variant) = parse_marker(&m).unwrap();
        assert_eq!((v.a, v.b, v.c, v.d), (3, 0, 4, 0));
        assert!(v.is_isx());
        assert!(!v.is_unicode());
        assert_eq!(variant, Variant::Isx);
    }

    #[test]
    fn legacy_1210_32() {
        let m = pad_marker(b"i1.2.10--32\x1a");
        let (v, variant) = parse_marker(&m).unwrap();
        assert_eq!((v.a, v.b, v.c), (1, 2, 10));
        assert!(!v.is_16bit());
        assert_eq!(variant, Variant::Legacy1210);
    }

    #[test]
    fn legacy_1210_16() {
        let m = pad_marker(b"i1.2.10--16\x1a");
        let (v, _) = parse_marker(&m).unwrap();
        assert!(v.is_16bit());
    }

    #[test]
    fn marker_with_trailing_a() {
        let m = pad_marker(b"Inno Setup Setup Data (5.5.7a) (u)");
        let (v, _) = parse_marker(&m).unwrap();
        assert_eq!((v.a, v.b, v.c, v.d), (5, 5, 7, 0));
    }

    #[test]
    fn unrecognized_marker_is_unsupported() {
        let m = pad_marker(b"Some Other Installer 1.2.3");
        let err = parse_marker(&m).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion { .. }));
    }

    #[test]
    fn at_least_compares_first_three_components() {
        let m = pad_marker(b"Inno Setup Setup Data (6.4.0.1) (u)");
        let (v, _) = parse_marker(&m).unwrap();
        assert!(v.at_least(6, 4, 0));
        assert!(v.at_least(5, 1, 5));
        assert!(!v.at_least(7, 0, 0));
        assert!(v.at_least_4(6, 4, 0, 1));
        assert!(!v.at_least_4(6, 4, 0, 2));
    }
}
