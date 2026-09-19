//! [`FileReader`] - streaming `std::io::Read` for one extracted
//! file's content.
//!
//! Pipeline (per `research/src/stream/file.cpp`):
//!
//! ```text
//! [ chunk decompressed bytes (cached) ]
//!         │
//!         │  (slice [chunk_sub_offset .. chunk_sub_offset + original_size])
//!         ▼
//! [ raw file bytes ]
//!         │
//!         │  (optional BCJ inverse if CallInstructionOptimized flag set)
//!         ▼
//! [ post-filter bytes ]  ──▶  running checksum hasher
//!         │
//!         ▼
//!   caller's `Read::read` buffer
//! ```
//!
//! BCJ runs on the **whole file** before the first `read` call -
//! we copy the slice into an owned buffer (so we can mutate it in
//! place) and apply the filter once. Streaming `read` then drains
//! that buffer, feeding the hasher incrementally and verifying at
//! EOF.

use std::io::{self, Read};

use crate::{
    error::Error,
    extract::{bcj, checksum::Hasher},
    records::dataentry::{DataEntry, DataFlag},
    version::Version,
};

/// Streaming reader for one extracted file. Implements
/// [`std::io::Read`].
///
/// On EOF (the file's final byte yielded), the recorded checksum is
/// verified. A mismatch surfaces as `io::Error` on the **next**
/// `read` call after exhaustion (per the `Read` trait contract:
/// finite reads succeed, errors surface separately).
pub struct FileReader<'a> {
    /// Source bytes. Owned when BCJ ran (we mutated in-place);
    /// borrowed otherwise.
    bytes: FileBytes<'a>,
    pos: usize,
    hasher: Option<Hasher>,
    /// Set once finalized; kept so a duplicate `read` after error
    /// keeps returning the same error rather than panicking.
    finalize_error: Option<Error>,
}

enum FileBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> FileBytes<'a> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(s) => s,
            Self::Owned(v) => v.as_slice(),
        }
    }
}

impl<'a> FileReader<'a> {
    /// Constructs a reader by slicing the chunk's decompressed
    /// bytes to this file's range, applying BCJ if the flag is set,
    /// and arming the checksum hasher.
    pub(crate) fn new(
        chunk_bytes: &'a [u8],
        data: &DataEntry,
        version: &Version,
    ) -> Result<Self, Error> {
        let start = usize::try_from(data.chunk_sub_offset).map_err(|_| Error::Overflow {
            what: "chunk_sub_offset",
        })?;
        let len = usize::try_from(data.original_size).map_err(|_| Error::Overflow {
            what: "original_size",
        })?;
        let end = start.checked_add(len).ok_or(Error::Overflow {
            what: "file end offset",
        })?;
        let slice = chunk_bytes.get(start..end).ok_or(Error::Truncated {
            what: "file slice within chunk",
        })?;

        let bytes = if data.flags.contains(&DataFlag::CallInstructionOptimized) {
            let mut owned = slice.to_vec();
            let filter = bcj::Filter::for_version(version);
            filter.apply(&mut owned)?;
            FileBytes::Owned(owned)
        } else {
            FileBytes::Borrowed(slice)
        };

        Ok(Self {
            bytes,
            pos: 0,
            hasher: Some(Hasher::from_data_checksum(&data.checksum)),
            finalize_error: None,
        })
    }

    /// Length of the file content (uncompressed, post-filter).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.as_slice().len()
    }

    /// Whether the file has zero content.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> Read for FileReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we already finalized with an error, surface it again.
        if let Some(err) = self.finalize_error.as_ref() {
            return Err(io::Error::other(err.to_string()));
        }

        let src = self.bytes.as_slice();
        let remaining = src.get(self.pos..).unwrap_or(&[]);
        if remaining.is_empty() {
            // Already at EOF. Finalize the hasher if we haven't yet.
            if let Some(h) = self.hasher.take()
                && let Err(e) = h.finalize()
            {
                let msg = e.to_string();
                self.finalize_error = Some(e);
                return Err(io::Error::other(msg));
            }
            return Ok(0);
        }

        let n = remaining.len().min(buf.len());
        let chunk = remaining.get(..n).unwrap_or(&[]);
        let dst = buf.get_mut(..n).unwrap_or(&mut []);
        dst.copy_from_slice(chunk);

        if let Some(h) = self.hasher.as_mut() {
            h.update(chunk);
        }

        self.pos = self.pos.saturating_add(n);
        Ok(n)
    }
}

impl<'a> std::fmt::Debug for FileReader<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileReader")
            .field("len", &self.len())
            .field("pos", &self.pos)
            .field("hasher_active", &self.hasher.is_some())
            .field(
                "finalize_error",
                &self.finalize_error.as_ref().map(ToString::to_string),
            )
            .finish()
    }
}
