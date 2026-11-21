//! Slice reader for `setup-1` payload bytes.
//!
//! Inno Setup stores the payload chunks either:
//! - **Embedded** - appended to the installer EXE, from
//!   `OffsetTable.offset_setup1`, when that is not 0.
//! - **In slice files** - `<name>-1.bin`, `<name>-2.bin`, ... beside the
//!   installer (`DiskSpanning=yes`), when it is 0. Each starts with an
//!   8-byte ID and the file's total size (issrc `Setup.FileExtractor.pas`,
//!   `OpenSlice`): `idska16\x1a` and a `Longint` in a 16-bit installer,
//!   `idska32\x1a` and a `Cardinal` to 6.5.1, `idskb32\x1a` and an `Int64`
//!   from 6.5.2 (`Shared.Struct.pas`, `DiskSliceID`, `TDiskSliceHeader`).
//!
//! A chunk lives at its slice's `start_offset`, counted from the start of
//! the slice file (from `offset_setup1` when embedded), for its magic and
//! `chunk_compressed_size` bytes. In slice files it runs on past the end of
//! one file into the next, after that file's header, up to `last_slice`
//! (`TFileExtractor.ReadProc`).

use std::borrow::Cow;

use crate::{error::Error, version::Version};

/// Reads bytes from `setup-1`: the installer's embedded payload, or the
/// slice files the caller supplied.
#[derive(Debug, Clone)]
pub struct SliceReader<'a> {
    source: Source<'a>,
}

#[derive(Debug, Clone)]
enum Source<'a> {
    /// The installer from `offset_setup1` on.
    Embedded(&'a [u8]),
    /// Each slice file whole, with the length of its header.
    Files(Vec<(&'a [u8], usize)>),
    /// Slice files are needed and none were supplied.
    Missing,
}

impl<'a> SliceReader<'a> {
    /// The reader for an installer: its embedded payload when
    /// `offset_setup1` is not 0, else `slices` (empty when the caller
    /// supplied none, which reads fail with [`Error::ExternalSlice`]).
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] / [`Error::Overflow`] when `offset_setup1` lies
    /// past the input; [`Error::BadSlice`] for a slice whose header is not
    /// the one `version` writes or whose size is not its length.
    pub fn new(
        input: &'a [u8],
        offset_setup1: u64,
        slices: &[&'a [u8]],
        version: &Version,
    ) -> Result<Self, Error> {
        if offset_setup1 != 0 {
            return Self::embedded(input, offset_setup1);
        }
        if slices.is_empty() {
            return Ok(Self {
                source: Source::Missing,
            });
        }
        let mut files = Vec::with_capacity(slices.len());
        for (index, &slice) in slices.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| Error::Overflow {
                what: "slice index",
            })?;
            files.push((slice, slice_header_len(slice, index, version)?));
        }
        Ok(Self {
            source: Source::Files(files),
        })
    }

    /// Wraps the input EXE for embedded-slice reads. `offset_setup1 == 0`
    /// means slice files, none supplied: reads fail with
    /// [`Error::ExternalSlice`].
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] / [`Error::Overflow`] when `offset_setup1` lies
    /// past the input.
    pub fn embedded(input: &'a [u8], offset_setup1: u64) -> Result<Self, Error> {
        if offset_setup1 == 0 {
            return Ok(Self {
                source: Source::Missing,
            });
        }
        let start = usize::try_from(offset_setup1).map_err(|_| Error::Overflow {
            what: "offset_setup1",
        })?;
        let setup1 = input.get(start..).ok_or(Error::Truncated {
            what: "setup-1 region",
        })?;
        Ok(Self {
            source: Source::Embedded(setup1),
        })
    }

    /// Reads `len` bytes of the chunk at `offset` in slice `first`, running
    /// on into the following slice files up to `last`. Borrowed when the
    /// bytes lie in one place, copied when they span slices.
    ///
    /// # Errors
    ///
    /// - [`Error::ExternalSlice`] when the chunk is in slice files and none
    ///   (or too few) were supplied, or an embedded chunk names a slice.
    /// - [`Error::MultiSliceChunk`] when the chunk is longer than slices
    ///   `first..=last` hold.
    /// - [`Error::Truncated`] when an embedded chunk runs past the input.
    pub fn read_at(
        &self,
        first: u32,
        last: u32,
        offset: u64,
        len: u64,
    ) -> Result<Cow<'a, [u8]>, Error> {
        let off = usize::try_from(offset).map_err(|_| Error::Overflow {
            what: "slice offset",
        })?;
        let len = usize::try_from(len).map_err(|_| Error::Overflow {
            what: "slice length",
        })?;
        match &self.source {
            Source::Missing => Err(Error::ExternalSlice),
            Source::Embedded(setup1) => {
                if first != 0 || last != 0 {
                    return Err(Error::ExternalSlice);
                }
                let end = off
                    .checked_add(len)
                    .ok_or(Error::Overflow { what: "slice end" })?;
                setup1
                    .get(off..end)
                    .map(Cow::Borrowed)
                    .ok_or(Error::Truncated {
                        what: "setup-1 chunk bytes",
                    })
            }
            Source::Files(files) => read_across(files, first, last, off, len),
        }
    }
}

fn read_across<'a>(
    files: &[(&'a [u8], usize)],
    first: u32,
    last: u32,
    offset: usize,
    len: usize,
) -> Result<Cow<'a, [u8]>, Error> {
    let file = |index: u32| -> Result<(&'a [u8], usize), Error> {
        let index = usize::try_from(index).map_err(|_| Error::Overflow {
            what: "slice index",
        })?;
        files.get(index).copied().ok_or(Error::ExternalSlice)
    };
    let (bytes, header_len) = file(first)?;
    if offset < header_len {
        return Err(Error::Truncated {
            what: "chunk inside a slice header",
        });
    }
    let here = bytes.get(offset..).ok_or(Error::Truncated {
        what: "chunk offset past its slice",
    })?;
    if let Some(whole) = here.get(..len) {
        return Ok(Cow::Borrowed(whole));
    }
    // `len` comes from the file: reserve no more than the slices hold.
    let available: usize = files.iter().map(|(bytes, _)| bytes.len()).sum();
    let mut out = Vec::with_capacity(len.min(available));
    out.extend_from_slice(here);
    let mut slice = first;
    while out.len() < len {
        if slice >= last {
            return Err(Error::MultiSliceChunk { first, last });
        }
        slice = slice.checked_add(1).ok_or(Error::Overflow {
            what: "slice index",
        })?;
        let (bytes, header_len) = file(slice)?;
        let data = bytes.get(header_len..).unwrap_or(&[]);
        let want = len.saturating_sub(out.len());
        out.extend_from_slice(data.get(..want).unwrap_or(data));
    }
    Ok(Cow::Owned(out))
}

/// The header length of slice `index`, after checking its ID and size.
fn slice_header_len(slice: &[u8], index: u32, version: &Version) -> Result<usize, Error> {
    let (id, wide): (&[u8; 8], bool) = if version.is_16bit() {
        (b"idska16\x1a", false)
    } else if version.at_least(6, 5, 2) {
        (b"idskb32\x1a", true)
    } else {
        (b"idska32\x1a", false)
    };
    if slice.get(..8) != Some(&id[..]) {
        return Err(Error::BadSlice {
            index,
            reason: "slice ID is not the one this release writes",
        });
    }
    let (size, header_len) = if wide {
        let raw: [u8; 8] =
            slice
                .get(8..16)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::BadSlice {
                    index,
                    reason: "slice header truncated",
                })?;
        (u64::try_from(i64::from_le_bytes(raw)).ok(), 16)
    } else {
        let raw: [u8; 4] =
            slice
                .get(8..12)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::BadSlice {
                    index,
                    reason: "slice header truncated",
                })?;
        (Some(u64::from(u32::from_le_bytes(raw))), 12)
    };
    if size != u64::try_from(slice.len()).ok() {
        return Err(Error::BadSlice {
            index,
            reason: "slice size is not the file's length",
        });
    }
    Ok(header_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::version;

    /// A pre-6.5.2 slice file: `idska32\x1a`, its total size, `data`.
    fn slice32(data: &[u8]) -> Vec<u8> {
        let mut out = b"idska32\x1a".to_vec();
        out.extend_from_slice(&((12 + data.len()) as u32).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn a_chunk_runs_on_into_the_next_slices() {
        let v = version("5.5.7", false);
        let (a, b, c) = (slice32(b"..ABC"), slice32(b"DEF"), slice32(b"GH.."));
        let reader = SliceReader::new(&[], 0, &[&a, &b, &c], &v).unwrap();
        // Offsets count from the start of the file, header included.
        assert_eq!(&*reader.read_at(0, 2, 14, 8).unwrap(), b"ABCDEFGH");
        // Within one slice, borrowed.
        assert!(matches!(
            reader.read_at(0, 0, 14, 3).unwrap(),
            Cow::Borrowed(b"ABC")
        ));
        // Past the last slice the entry names.
        assert!(matches!(
            reader.read_at(0, 1, 14, 8),
            Err(Error::MultiSliceChunk { first: 0, last: 1 })
        ));
        // A slice that was not supplied.
        let short = SliceReader::new(&[], 0, &[&a], &v).unwrap();
        assert!(matches!(
            short.read_at(0, 2, 14, 8),
            Err(Error::ExternalSlice)
        ));
        // None supplied.
        let none = SliceReader::new(&[], 0, &[], &v).unwrap();
        assert!(matches!(
            none.read_at(0, 0, 14, 1),
            Err(Error::ExternalSlice)
        ));
    }

    #[test]
    fn a_slice_header_is_the_one_the_release_writes() {
        let v = version("5.5.7", false);
        assert!(SliceReader::new(&[], 0, &[&slice32(b"x")], &v).is_ok());
        // 6.5.2 on: `idskb32` and a 64-bit size.
        let wide = {
            let mut out = b"idskb32\x1a".to_vec();
            out.extend_from_slice(&17u64.to_le_bytes());
            out.push(b'x');
            out
        };
        assert!(SliceReader::new(&[], 0, &[&wide], &version("6.5.2", true)).is_ok());
        assert!(matches!(
            SliceReader::new(&[], 0, &[&wide], &v),
            Err(Error::BadSlice { index: 0, .. })
        ));
        // A size that is not the file's length.
        let mut wrong = slice32(b"x");
        wrong.push(0);
        assert!(matches!(
            SliceReader::new(&[], 0, &[&slice32(b"y"), &wrong], &v),
            Err(Error::BadSlice { index: 1, .. })
        ));
    }
}
