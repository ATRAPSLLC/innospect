//! Where in the PE container the `SetupLdrOffsetTable` was found.
//!
//! [`crate::InnoInstaller::pe_locator_mode`] reports the strategy; the
//! locator itself is internal.

/// How the offset table was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocatorMode {
    /// By scanning the file for the table's 12-byte magic (5.1.5+, where
    /// the table is the PE resource `11111`).
    SignatureScan,
    /// Through the pre-5.1.5 pointer at file offset `0x30`: the `'Inno'`
    /// magic, the table's offset, and that offset's complement.
    LegacyFileOffset,
}

stable_name_enum!(LocatorMode, {
    Self::SignatureScan => "signature_scan",
    Self::LegacyFileOffset => "legacy_file_offset",
});

/// Span of bytes inside the input slice that contains the offset
/// table.
#[derive(Clone, Copy, Debug)]
pub struct OffsetTableLocation {
    /// Byte offset into the original input.
    pub start: usize,
    /// Byte length of the located region (whatever remains of the
    /// input after `start`; the actual record is shorter).
    pub len: usize,
    /// Which locator strategy succeeded.
    pub mode: LocatorMode,
}
