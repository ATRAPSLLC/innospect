//! Cursor-style reader over a byte slice with checked reads.
//!
//! Designed for parsing adversarial input under the crate's deny set
//! (no `[i]` indexing, no `unwrap`, no arithmetic side effects). Every
//! operation that could fail returns [`Error`] instead of panicking.

use crate::{error::Error, version::Version};

/// A setup-0 record: read from `reader` in the layout `version` writes.
///
/// Every record type implements this. The trait lives in this private
/// module, so the constructors are reachable inside the crate and nowhere
/// else.
pub trait FromReader: Sized {
    /// Reads one record.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when the record runs past the input, or the
    /// record's own decoding errors.
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error>;

    /// Whether Setup reads the record, before 1.3.0, behind a u32 holding
    /// its size. Every record is except a data entry, which it reads raw
    /// (1.2.16 `MAIN.PAS`).
    const SIZED_BEFORE_1_3: bool = true;
}

/// Reads one setup-0 record as Setup does. Before 1.3.0 a record (see
/// [`FromReader::SIZED_BEFORE_1_3`]) follows a u32 holding its size
/// (1.2.16 `SETUPENT.PAS`, `SEInflateBlockRead`); it is read from exactly
/// that many bytes, every one of which it must use.
///
/// # Errors
///
/// The record's own errors, [`Error::Truncated`] when the size runs past
/// the input, and [`Error::TrailingData`] when the record is shorter than
/// its size.
pub fn read_record<T: FromReader>(reader: &mut Reader<'_>, version: &Version) -> Result<T, Error> {
    if !T::SIZED_BEFORE_1_3 || version.at_least(1, 3, 0) {
        return T::read(reader, version);
    }
    let size = reader.u32_le("record size")?;
    let size = usize::try_from(size).map_err(|_| Error::Overflow {
        what: "record size",
    })?;
    let mut record = Reader::new(reader.take(size, "record")?);
    let value = T::read(&mut record, version)?;
    if record.remaining() != 0 {
        return Err(Error::TrailingData {
            what: "record",
            len: record.remaining(),
        });
    }
    Ok(value)
}

/// Forward-only cursor over a byte slice. A clone is a second cursor at
/// the same position, for reading ahead.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wraps `buf` with the cursor positioned at offset 0.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Wraps `buf` with the cursor positioned at the given offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if `start` is past the end of `buf`.
    pub fn at(buf: &'a [u8], start: usize) -> Result<Self, Error> {
        if start > buf.len() {
            return Err(Error::Truncated { what: "Reader::at" });
        }
        Ok(Self { buf, pos: start })
    }

    /// Current byte offset into the underlying slice.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes still available beyond the cursor.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Advances the cursor by `n` bytes without yielding them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Overflow`] if `pos + n` overflows `usize`,
    /// [`Error::Truncated`] if it runs past the end of the buffer.
    pub fn skip(&mut self, n: usize, what: &'static str) -> Result<(), Error> {
        let new_pos = self.pos.checked_add(n).ok_or(Error::Overflow { what })?;
        if new_pos > self.buf.len() {
            return Err(Error::Truncated { what });
        }
        self.pos = new_pos;
        Ok(())
    }

    /// Yields the next `n` bytes as a borrowed sub-slice and advances
    /// the cursor.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let new_pos = self.pos.checked_add(n).ok_or(Error::Overflow { what })?;
        let slice = self
            .buf
            .get(self.pos..new_pos)
            .ok_or(Error::Truncated { what })?;
        self.pos = new_pos;
        Ok(slice)
    }

    /// Reads an exactly-`N`-byte fixed-length array and advances the
    /// cursor.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], Error> {
        let bytes = self.take(N, what)?;
        let mut out = [0u8; N];
        // bytes.len() == N is guaranteed by `take` returning the
        // requested length on success. copy_from_slice with matching
        // lengths cannot panic.
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads one unsigned byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the buffer is exhausted.
    pub fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or(Error::Truncated { what })?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    /// Reads a little-endian `u16` and advances 2 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn u16_le(&mut self, what: &'static str) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array::<2>(what)?))
    }

    /// Reads a little-endian `u32` and advances 4 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn u32_le(&mut self, what: &'static str) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array::<4>(what)?))
    }

    /// Reads a little-endian `i32` and advances 4 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn i32_le(&mut self, what: &'static str) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.array::<4>(what)?))
    }

    /// Reads a little-endian `u64` and advances 8 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn u64_le(&mut self, what: &'static str) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array::<8>(what)?))
    }

    /// Reads a little-endian `i64` and advances 8 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub fn i64_le(&mut self, what: &'static str) -> Result<i64, Error> {
        Ok(i64::from_le_bytes(self.array::<8>(what)?))
    }

    /// Reads a Delphi `Integer` or `Cardinal` as unsigned: four bytes, two
    /// in a 16-bit installer (1.2.x, Delphi 1), zero-extended.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if the value runs past the buffer.
    pub fn native_u32(&mut self, version: &Version, what: &'static str) -> Result<u32, Error> {
        if version.is_16bit() {
            self.u16_le(what).map(u32::from)
        } else {
            self.u32_le(what)
        }
    }

    /// Reads a Delphi `Integer`: four bytes, two in a 16-bit installer
    /// (1.2.x, Delphi 1), sign-extended.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if the value runs past the buffer.
    pub fn native_i32(&mut self, version: &Version, what: &'static str) -> Result<i32, Error> {
        if version.is_16bit() {
            self.u16_le(what).map(|v| i32::from(v.cast_signed()))
        } else {
            self.i32_le(what)
        }
    }

    /// Reads a Pascal `set` / `flags` bitfield as raw bytes.
    ///
    /// As Delphi stores them, and as innoextract's
    /// `stored_bitfield<Bits, PadBits>` (innoextract `util/storedenum.hpp`) reads them,
    /// Inno Setup encodes a `set` of `bit_count` flags as
    /// `ceil(bit_count / 8)` bytes, with one special case: when
    /// the result is exactly 3 bytes, the 32-bit Delphi compilers pad it
    /// to 4, so one trailing padding byte is consumed and dropped, except
    /// in a 16-bit installer (1.2.x), whose Delphi 1 does not pad. The
    /// padding byte is **not** returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] / [`Error::Overflow`] if the
    /// requested run of bytes runs past the buffer.
    pub fn set_bytes(
        &mut self,
        bit_count: usize,
        version: &Version,
        what: &'static str,
    ) -> Result<Vec<u8>, Error> {
        let bytes_needed = bit_count
            .checked_add(7)
            .and_then(|n| n.checked_div(8))
            .ok_or(Error::Overflow { what })?;
        let primary = self.take(bytes_needed, what)?.to_vec();
        if bytes_needed == 3 && !version.is_16bit() {
            self.skip(1, what)?;
        }
        Ok(primary)
    }
}

/// Convenience: read a little-endian `u32` from a fixed offset of `buf`
/// without constructing a [`Reader`]. Used in narrow probes (e.g. PE
/// magic checks).
///
/// # Errors
///
/// Returns [`Error::Truncated`] / [`Error::Overflow`] on out-of-bounds.
pub fn u32_le_at(buf: &[u8], offset: usize, what: &'static str) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Overflow { what })?;
    let bytes = buf.get(offset..end).ok_or(Error::Truncated { what })?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(arr))
}
