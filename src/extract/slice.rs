//! Slice reader for `setup-1` payload bytes.
//!
//! Inno Setup stores the payload chunks either:
//! - **Embedded** - appended after the PE sections inside the
//!   installer EXE (when `OffsetTable.offset_setup1 != 0`).
//! - **External** - in sibling files `setup-1.bin`, `setup-2.bin`,
//!   ... (when `offset_setup1 == 0`). Not currently supported.
//!
//! The embedded path is implemented here. Each chunk lives at
//! `offset_setup1 + chunk.start_offset` for `chunk_compressed_size`
//! bytes (plus the 4-byte `zlb\x1a` magic).

use crate::error::Error;

/// Reads bytes from `setup-1` slices.
///
/// Currently a view over the embedded portion of the input EXE;
/// reads against any non-zero slice index, or against an empty
/// embedded region, surface [`Error::ExternalSlice`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct SliceReader<'a> {
    /// Embedded `setup-1` bytes - the slice of the input EXE
    /// starting at `offset_setup1` and running to end-of-payload.
    /// Empty when external slices are in use.
    setup1: &'a [u8],
}

impl<'a> SliceReader<'a> {
    /// Wraps the input EXE for embedded-slice reads.
    ///
    /// `offset_setup1 == 0` means external slices, in which case
    /// the reader returns [`Error::ExternalSlice`] for any
    /// non-trivial read.
    pub(crate) fn embedded(input: &'a [u8], offset_setup1: u64) -> Result<Self, Error> {
        if offset_setup1 == 0 {
            return Ok(Self { setup1: &[] });
        }
        let start = usize::try_from(offset_setup1).map_err(|_| Error::Overflow {
            what: "offset_setup1",
        })?;
        let setup1 = input.get(start..).ok_or(Error::Truncated {
            what: "setup-1 region",
        })?;
        Ok(Self { setup1 })
    }

    /// Reads `len` bytes from `slice` index `slice_idx` starting at
    /// byte offset `offset`. Only `slice_idx == 0` against the
    /// embedded region is supported; other indices return
    /// [`Error::ExternalSlice`].
    pub(crate) fn read_at(&self, slice_idx: u32, offset: u32, len: u64) -> Result<&'a [u8], Error> {
        if slice_idx != 0 {
            return Err(Error::ExternalSlice);
        }
        if self.setup1.is_empty() {
            return Err(Error::ExternalSlice);
        }
        let off = usize::try_from(offset).map_err(|_| Error::Overflow {
            what: "slice offset",
        })?;
        let len_us = usize::try_from(len).map_err(|_| Error::Overflow {
            what: "slice length",
        })?;
        let end = off
            .checked_add(len_us)
            .ok_or(Error::Overflow { what: "slice end" })?;
        self.setup1.get(off..end).ok_or(Error::Truncated {
            what: "setup-1 chunk bytes",
        })
    }
}
