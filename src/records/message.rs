//! `TSetupCustomMessageEntry`: one `[CustomMessages]` entry, a message the
//! script defines for its own use (`{cm:Name}`), for one language or all.
//!
//! On disk (`SECompressedBlockWrite`): `Name`, `Value` (strings, UTF-16LE in
//! Unicode builds) and `LangIndex`. Reader reference: innoextract
//! `setup/message.cpp`; every layout is checked against upstream's own
//! declarations by the `crate::upstream` tests.

use crate::{
    error::Error,
    util::{
        encoding::read_ansi_bytes,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// One `[CustomMessages]` entry (`TSetupCustomMessageEntry`). The fields are
/// the bytes as stored: UTF-16LE in Unicode builds, else the code page of
/// the entry's language.
#[derive(Clone, Debug)]
pub struct MessageEntry {
    /// `Name`: the message's name, e.g. `Greeting`, which `{cm:Greeting}`
    /// expands.
    pub name: Vec<u8>,
    /// `Value`: the text; `%1`, `%2`, ... are filled from `{cm:...}`
    /// arguments.
    pub value: Vec<u8>,
    /// `LangIndex` as an index into [`crate::InnoInstaller::languages`], or
    /// `None` for a message all languages share (`LangIndex` -1).
    pub language: Option<i32>,
    /// `LangIndex` as stored.
    pub language_raw: i32,
}

impl FromReader for MessageEntry {
    /// Reads one `TSetupCustomMessageEntry`.
    ///
    /// # Errors
    ///
    /// Truncation per [`Error`].
    fn read(reader: &mut Reader<'_>, _version: &Version) -> Result<Self, Error> {
        let name = read_ansi_bytes(reader, "Message.Name")?;
        let value = read_ansi_bytes(reader, "Message.Value")?;
        let raw = reader.i32_le("Message.LangIndex")?;
        let language = if raw < 0 { None } else { Some(raw) };
        Ok(Self {
            name,
            value,
            language,
            language_raw: raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    fn v6_4() -> Version {
        Version {
            a: 6,
            b: 4,
            c: 0,
            d: 0,
            flags: VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    fn put_blob(buf: &mut Vec<u8>, b: &[u8]) {
        let len = u32::try_from(b.len()).unwrap();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(b);
    }

    #[test]
    fn parses_message_with_language_index() {
        let mut bytes = Vec::new();
        put_blob(&mut bytes, b"WelcomeLabel1");
        put_blob(&mut bytes, b"Welcome");
        bytes.extend_from_slice(&3i32.to_le_bytes());
        let mut r = Reader::new(&bytes);
        let m = MessageEntry::read(&mut r, &v6_4()).unwrap();
        assert_eq!(m.name, b"WelcomeLabel1");
        assert_eq!(m.value, b"Welcome");
        assert_eq!(m.language, Some(3));
        assert_eq!(m.language_raw, 3);
        assert_eq!(r.pos(), bytes.len());
    }

    #[test]
    fn negative_language_means_default() {
        let mut bytes = Vec::new();
        put_blob(&mut bytes, b"X");
        put_blob(&mut bytes, b"Y");
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        let mut r = Reader::new(&bytes);
        let m = MessageEntry::read(&mut r, &v6_4()).unwrap();
        assert_eq!(m.language, None);
        assert_eq!(m.language_raw, -1);
    }
}
