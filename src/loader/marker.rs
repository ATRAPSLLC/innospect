//! Decoding the 64-byte SetupID marker at the start of setup-0 into a
//! [`Version`] and an initial [`Variant`] guess.

use crate::{
    error::Error,
    util::read::Reader,
    version::{Variant, Version, VersionFlags},
};

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
pub fn parse_marker(marker: &[u8; 64]) -> Result<(Version, Variant), Error> {
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
    // The marker is these 12 bytes; what follows is the setup data.
    let mut raw_marker = [0u8; 64];
    raw_marker.get_mut(..prefix.len())?.copy_from_slice(prefix);
    if prefix == LEGACY_1210_16 {
        return Some(Version {
            a: 1,
            b: 2,
            c: 10,
            d: 0,
            flags: VersionFlags::BITS16,
            raw_marker,
        });
    }
    if prefix == LEGACY_1210_32 {
        return Some(Version {
            a: 1,
            b: 2,
            c: 10,
            d: 0,
            flags: VersionFlags::empty(),
            raw_marker,
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
/// (which begins with the SetupID marker), with the marker's length: 64
/// bytes, 12 for the 1.2.10 form (1.2.16 `STRUCT.PAS`, `TSetupID`).
///
/// # Errors
///
/// - [`Error::Truncated`] if `setup0` is shorter than 64 bytes.
/// - [`Error::UnsupportedVersion`] from [`parse_marker`].
pub fn read_marker(setup0: &[u8]) -> Result<(Version, Variant, usize), Error> {
    let mut r = Reader::new(setup0);
    let marker = r.array::<64>("SetupID marker")?;
    let (version, variant) = parse_marker(&marker)?;
    let len = if variant == Variant::Legacy1210 {
        LEGACY_1210_32.len()
    } else {
        marker.len()
    };
    Ok((version, variant, len))
}

/// A version without its fourth part.
type Triple = (u8, u8, u8);

/// SetupIDs a later release kept writing after it changed the setup-0
/// layout, each with the version whose layout that release wrote
/// (innoextract `setup/version.cpp`, `version::is_ambiguous`; for 4.2.3
/// also issrc-4.2.4 `Struct.pas`, which adds four header strings and
/// still declares `(4.2.3)`).
const SHARED_MARKERS: [(Triple, Triple); 4] = [
    ((1, 3, 21), (1, 3, 24)),
    ((2, 0, 1), (2, 0, 2)),
    ((3, 0, 3), (3, 0, 4)),
    ((4, 2, 3), (4, 2, 4)),
];

/// The other layout a stock installer with `version`'s marker may have:
/// the later release's, when a release changed the setup-0 records but
/// kept the SetupID. `None` for every marker only one layout is written
/// under, and for ISX markers, which are not supported.
#[must_use]
pub fn later_layout(version: &Version) -> Option<Version> {
    if version.d != 0 || version.is_isx() {
        return None;
    }
    let (_, (a, b, c)) = SHARED_MARKERS
        .iter()
        .find(|(marker, _)| *marker == (version.a, version.b, version.c))?;
    Some(Version {
        a: *a,
        b: *b,
        c: *c,
        ..version.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_layout_covers_the_shared_markers_only() {
        for (marker, later) in [
            ("1.3.21", (1, 3, 24)),
            ("2.0.1", (2, 0, 2)),
            ("3.0.3", (3, 0, 4)),
            ("4.2.3", (4, 2, 4)),
        ] {
            let text = format!("Inno Setup Setup Data ({marker})");
            let (v, _) = parse_marker(&pad_marker(text.as_bytes())).unwrap();
            let next = later_layout(&v).unwrap_or_else(|| panic!("{marker}: no later layout"));
            assert_eq!(
                (next.a, next.b, next.c, next.d),
                (later.0, later.1, later.2, 0)
            );
            assert_eq!(next.raw_marker, v.raw_marker, "{marker}: marker kept");
            assert!(later_layout(&next).is_none(), "{marker}: chained");
        }
        for text in [
            &b"Inno Setup Setup Data (4.2.4)"[..],
            b"Inno Setup Setup Data (5.5.7) (u)",
            b"My Inno Setup Extensions Setup Data (3.0.3)",
            b"i1.2.10--32\x1a",
        ] {
            let (v, _) = parse_marker(&pad_marker(text)).unwrap();
            assert!(later_layout(&v).is_none(), "{v:?}");
        }
    }

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
    fn version_displays_its_numbers_and_build() {
        let shown = |m: &[u8]| parse_marker(&pad_marker(m)).unwrap().0.to_string();
        assert_eq!(shown(b"Inno Setup Setup Data (6.4.0.1) (u)"), "6.4.0.1 (u)");
        assert_eq!(shown(b"Inno Setup Setup Data (5.5.7)"), "5.5.7");
        assert_eq!(
            shown(b"My Inno Setup Extensions Setup Data (3.0.4)"),
            "3.0.4 (ISX)"
        );
        assert_eq!(shown(b"i1.2.10--16\x1a"), "1.2.10 (16-bit)");
    }

    #[test]
    fn legacy_marker_is_twelve_bytes() {
        // The setup data follows the 12-byte marker directly.
        let mut setup0 = b"i1.2.10--16\x1a".to_vec();
        setup0.extend_from_slice(&[0xAB; 60]);
        let (v, variant, len) = read_marker(&setup0).unwrap();
        assert_eq!((variant, len), (Variant::Legacy1210, 12));
        assert_eq!(v.marker_str(), "i1.2.10--16\x1a");
        let modern = pad_marker(b"Inno Setup Setup Data (4.0.5)");
        assert_eq!(read_marker(&modern).unwrap().2, 64);
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
