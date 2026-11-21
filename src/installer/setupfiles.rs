//! The files setup-0 carries besides the records: the wizard images and the
//! DLLs Setup extracts and loads before it installs anything.
//!
//! From 4.0.0 they follow the uninstall-run entries and end the records
//! block; before, they sit between the language options and the other
//! records. Each is a 32-bit length and that many bytes (issrc
//! `Setup.MainFunc.pas`, `ReadFileIntoStream`). What is there follows
//! Setup's reading code release by release (issrc tags and the
//! `issrc-*.zip` archives, `Main.pas` / `Setup.MainFunc.pas`):
//!
//! | Releases       | After the records |
//! | -------------- | ----------------- |
//! | before 2.0.0   | one wizard image |
//! | 2.0.0..5.6.0   | a large and a small wizard image |
//! | 5.6.0..6.6.0   | a count of large images and the images, likewise small ones |
//! | 6.6.0..6.7.0   | those two lists, then the same two for dark mode |
//! | 6.7.0 on       | large, small and back images, then the same three for dark mode |
//!
//! then the decompressor DLL, for bzip2 before 4.1.5 (the `BzipUsed`
//! option) and from 4.1.6, for bzip2 or LZMA in 4.1.5, and from 4.2.6 for
//! zip or bzip2; from 4.2.2 to 6.4.0 the decryption DLL (`ISCrypt.dll`)
//! when the header's `EncryptionUsed` is set; and from 6.5.0 the 7-Zip DLL
//! when the header names one (`SevenZipLibraryName`). A dark-mode count of
//! -1 means the dark images are the light ones.
//!
//! 5.6.0 introduced the counts but kept 5.5.7's SetupID, whose records are
//! laid out the same; under that marker both forms are tried, and the one
//! that ends where the block ends is taken.

use std::ops::Range;

use crate::{
    error::Error,
    header::{CompressMethod, HeaderOption, HeaderString, SetupHeader},
    util::read::Reader,
    version::Version,
};

/// Which of the wizard's pictures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WizardImageKind {
    /// `WizardImageFile`: the large picture on the welcome and finished
    /// pages.
    Large,
    /// `WizardSmallImageFile`: the small picture at the top of the other
    /// pages (2.0.0+).
    Small,
    /// `WizardBackImageFile`: the wizard's background picture (6.7.0+).
    Back,
}

stable_name_enum!(WizardImageKind, {
    Self::Large => "large",
    Self::Small => "small",
    Self::Back => "back",
});

impl WizardImageKind {
    fn index(self) -> usize {
        match self {
            Self::Large => 0,
            Self::Small => 1,
            Self::Back => 2,
        }
    }
}

/// Where each of those files sits in the decompressed records block.
#[derive(Clone, Debug, Default)]
pub struct SetupFiles {
    /// Indexed by [`WizardImageKind::index`].
    images: [Vec<Range<usize>>; 3],
    /// Likewise, for dark mode; `None` when there are none of their own.
    dark_images: [Option<Vec<Range<usize>>>; 3],
    decompressor_dll: Option<Range<usize>>,
    decryption_dll: Option<Range<usize>>,
    seven_zip_dll: Option<Range<usize>>,
}

impl SetupFiles {
    /// The ranges of the light-mode images of `kind`.
    pub fn images(&self, kind: WizardImageKind) -> &[Range<usize>] {
        self.images.get(kind.index()).map_or(&[], Vec::as_slice)
    }

    /// The ranges of the dark-mode images of `kind`, when there are any of
    /// their own.
    pub fn dark_images(&self, kind: WizardImageKind) -> Option<&[Range<usize>]> {
        self.dark_images
            .get(kind.index())
            .and_then(Option::as_deref)
    }

    /// The decompressor DLL's range.
    pub fn decompressor_dll(&self) -> Option<Range<usize>> {
        self.decompressor_dll.clone()
    }

    /// The decryption DLL's range.
    pub fn decryption_dll(&self) -> Option<Range<usize>> {
        self.decryption_dll.clone()
    }

    /// The 7-Zip DLL's range.
    pub fn seven_zip_dll(&self) -> Option<Range<usize>> {
        self.seven_zip_dll.clone()
    }
}

/// Reads the wizard images and DLLs at `reader`'s position. From 4.0.0
/// they end the block, and anything after them is an error; under SetupID
/// 5.5.7 the uncounted and the counted image form are both tried.
///
/// # Errors
///
/// [`Error::Truncated`] when a length runs past the block, and from 4.0.0
/// [`Error::TrailingData`] when bytes are left after the last file.
pub fn read(
    reader: &mut Reader<'_>,
    header: &SetupHeader,
    version: &Version,
) -> Result<SetupFiles, Error> {
    let ends_block = version.at_least(4, 0, 0);
    let shared_marker =
        (version.a, version.b, version.c, version.d) == (5, 5, 7, 0) && !version.is_isx();
    if !shared_marker {
        return read_form(reader, header, version, counted(version), ends_block);
    }
    let mut first = reader.clone();
    match read_form(&mut first, header, version, false, true) {
        Ok(files) => {
            *reader = first;
            Ok(files)
        }
        Err(error) => {
            let mut second = reader.clone();
            let files = read_form(&mut second, header, version, true, true).map_err(|_| error)?;
            *reader = second;
            Ok(files)
        }
    }
}

/// Whether each image kind is a count and that many images (5.6.0+).
fn counted(version: &Version) -> bool {
    version.at_least(5, 6, 0)
}

fn read_form(
    reader: &mut Reader<'_>,
    header: &SetupHeader,
    version: &Version,
    counted: bool,
    ends_block: bool,
) -> Result<SetupFiles, Error> {
    let mut files = SetupFiles::default();
    let kinds: &[WizardImageKind] = if version.at_least(6, 7, 0) {
        &[
            WizardImageKind::Large,
            WizardImageKind::Small,
            WizardImageKind::Back,
        ]
    } else if version.at_least(2, 0, 0) {
        &[WizardImageKind::Large, WizardImageKind::Small]
    } else {
        &[WizardImageKind::Large]
    };
    for &kind in kinds {
        let list = if counted {
            read_list(reader, "wizard image count")?.unwrap_or_default()
        } else {
            vec![blob(reader, "wizard image")?]
        };
        if let Some(slot) = files.images.get_mut(kind.index()) {
            *slot = list;
        }
    }
    if version.at_least(6, 6, 0) {
        for &kind in kinds {
            let list = read_list(reader, "dark wizard image count")?;
            if let Some(slot) = files.dark_images.get_mut(kind.index()) {
                *slot = list;
            }
        }
    }

    let method = header.tail().compress_method;
    let decompressor = if version.at_least(4, 2, 6) {
        matches!(method, Some(CompressMethod::Zlib | CompressMethod::Bzip2))
    } else if version.at_least(4, 1, 5) && !version.at_least(4, 1, 6) {
        method != Some(CompressMethod::Zlib)
    } else {
        method == Some(CompressMethod::Bzip2)
    };
    if decompressor {
        files.decompressor_dll = Some(blob(reader, "decompressor DLL")?);
    }
    if version.at_least(4, 2, 2)
        && !version.at_least(6, 4, 0)
        && header.has_option(HeaderOption::EncryptionUsed)
    {
        files.decryption_dll = Some(blob(reader, "decryption DLL")?);
    }
    if version.at_least(6, 5, 0)
        && header
            .string(HeaderString::SevenZipLibraryName)
            .is_some_and(|name| !name.is_empty())
    {
        files.seven_zip_dll = Some(blob(reader, "7-Zip DLL")?);
    }

    if ends_block && reader.remaining() != 0 {
        return Err(Error::TrailingData {
            what: "setup-0 records block",
            len: reader.remaining(),
        });
    }
    Ok(files)
}

/// A count and that many files; `None` for a count of -1, which a dark
/// list uses for "the same as the light one".
fn read_list(
    reader: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<Vec<Range<usize>>>, Error> {
    let count = reader.i32_le(what)?;
    if count == -1 {
        return Ok(None);
    }
    let count = usize::try_from(count).map_err(|_| Error::Overflow { what })?;
    // Each file is at least its four-byte length: a count past what the
    // block can hold is refused before anything is allocated.
    if count > reader.remaining().checked_div(4).unwrap_or(0) {
        return Err(Error::Truncated { what });
    }
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        list.push(blob(reader, "wizard image")?);
    }
    Ok(Some(list))
}

/// A 32-bit length and that many bytes; their range in the block.
fn blob(reader: &mut Reader<'_>, what: &'static str) -> Result<Range<usize>, Error> {
    let len = reader.u32_le(what)?;
    let len = usize::try_from(len).map_err(|_| Error::Overflow { what })?;
    let start = reader.pos();
    reader.skip(len, what)?;
    Ok(start..reader.pos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{MARKERS, encode_strings, version};

    /// A 5.5.7 ANSI header with every tail field zero: stored, unencrypted.
    fn header_5_5_7() -> (SetupHeader, Version) {
        let version = version("5.5.7", false);
        let record = MARKERS
            .iter()
            .find(|m| m.id == "5.5.7")
            .and_then(|m| m.variants[0].builds.iter().find(|b| !b.unicode))
            .and_then(|b| b.records.iter().find(|r| r.name == "TSetupHeader"))
            .expect("5.5.7 TSetupHeader");
        let mut buf = Vec::new();
        encode_strings(record, false, &version, &mut buf);
        buf.resize(buf.len() + record.tail, 0);
        (SetupHeader::parse(&buf, &version).expect("header"), version)
    }

    fn file(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    #[test]
    fn shared_5_5_7_marker_takes_the_form_that_ends_the_block() {
        let (header, version) = header_5_5_7();

        // 5.5.7 to 5.5.9: one image of each size.
        let mut uncounted = Vec::new();
        file(&mut uncounted, b"BMlarge");
        file(&mut uncounted, b"BMsmall");
        let files = read(&mut Reader::new(&uncounted), &header, &version).unwrap();
        assert_eq!(
            files.images(WizardImageKind::Large),
            [Range { start: 4, end: 11 }]
        );
        assert_eq!(
            files.images(WizardImageKind::Small),
            [Range { start: 15, end: 22 }]
        );

        // 5.6.x: a count before each size's images.
        let mut counted = 1u32.to_le_bytes().to_vec();
        file(&mut counted, b"BMlarge");
        counted.extend_from_slice(&2u32.to_le_bytes());
        file(&mut counted, b"BMs1");
        file(&mut counted, b"BMs2");
        let files = read(&mut Reader::new(&counted), &header, &version).unwrap();
        assert_eq!(
            files.images(WizardImageKind::Large),
            [Range { start: 8, end: 15 }]
        );
        assert_eq!(files.images(WizardImageKind::Small), [23..27, 31..35]);

        // Neither form ends the block: the first form's error.
        let mut neither = uncounted.clone();
        neither.push(0);
        assert!(matches!(
            read(&mut Reader::new(&neither), &header, &version),
            Err(Error::TrailingData { len: 1, .. })
        ));
    }

    #[test]
    fn an_image_count_past_the_block_is_refused() {
        let (header, _) = header_5_5_7();
        let version = version("6.0.0", true);
        let mut buf = i32::MAX.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0; 16]);
        assert!(matches!(
            read(&mut Reader::new(&buf), &header, &version),
            Err(Error::Truncated { .. })
        ));
    }
}
