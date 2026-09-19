//! `TSetupCustomMessageEntry` - `[CustomMessages]` localized
//! string overrides.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupCustomMessageEntry = packed record
//!     Name: AnsiString;
//!     Value: AnsiString;
//!     LangIndex: Integer;     // -1 = default (any language)
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/message.cpp`. The `Value`
//! bytes are encoded in the codepage of `languages[LangIndex]` (or
//! the per-installer default codepage when `LangIndex == -1`).
//! Decoding to a Rust `String` happens above this layer; we surface
//! the raw bytes here.

use crate::{
    error::Error,
    util::{encoding::read_ansi_bytes, read::Reader},
    version::Version,
};

/// Parsed `TSetupCustomMessageEntry`.
#[derive(Clone, Debug)]
pub struct MessageEntry {
    /// `Name:` directive (the message ID, e.g. `"WelcomeLabel1"`).
    /// Encoded in the per-installer default codepage (UTF-8 in
    /// modern Unicode builds).
    pub name: Vec<u8>,
    /// `Value:` directive - localized message body. Encoded in the
    /// codepage of the entry's language; see [`Self::language`].
    pub value: Vec<u8>,
    /// Language index into the parsed [`crate::records::language`]
    /// list, or `None` when `LangIndex == -1` (default for all
    /// languages).
    pub language: Option<i32>,
    /// Raw `LangIndex` value as it appeared on the wire.
    pub language_raw: i32,
}

impl MessageEntry {
    /// Reads one `TSetupCustomMessageEntry`.
    ///
    /// # Errors
    ///
    /// Truncation per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, _version: &Version) -> Result<Self, Error> {
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
