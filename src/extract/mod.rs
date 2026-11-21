//! File-content extraction.
//!
//! Resolves a `[Files]` entry's `location_index` into the
//! corresponding `setup-1` chunk, decompresses the chunk (cached
//! via `OnceLock` so solid LZMA chunks are decoded exactly once
//! per installer), slices to the file's byte range, applies the
//! optional BCJ inverse filter, and verifies the recorded
//! checksum on the streaming `Read`'s EOF.
//!
//! Public entry points live as methods on
//! [`crate::InnoInstaller`]: [`crate::InnoInstaller::extract`],
//! [`crate::InnoInstaller::extract_to_vec`], and
//! [`crate::InnoInstaller::extract_by_location`].

pub mod file;

pub use file::FileReader;
