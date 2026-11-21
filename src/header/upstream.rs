//! The header string walker checked against upstream's own declarations.
//!
//! [`crate::upstream`] lists the `String` and `AnsiString` fields of every
//! `TSetupHeader` whose source is available, in declaration order, which is
//! the order setup-0 carries them in. For each SetupID marker the walker is
//! fed one entry per declared field, each tagged with its position and name,
//! and must read exactly those entries: every tagged entry lands on the field
//! of the same name and nothing is left over. An `AnsiString` entry in a
//! Unicode build has an odd length, so reading one as a UTF-16 `String` fails
//! instead of passing unnoticed.

use std::collections::{BTreeMap, HashMap};

use super::{ansi_label, field_label, read_header_strings_and_ansi};
use crate::{
    upstream::{Kind, build_name, builds},
    util::read::Reader,
    version::Version,
};

fn push(buf: &mut Vec<u8>, kind: Kind, unicode: bool, content: &str) {
    let bytes: Vec<u8> = if kind == Kind::Str && unicode {
        content.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        let mut bytes = content.as_bytes().to_vec();
        if kind == Kind::Ansi && bytes.len().is_multiple_of(2) {
            bytes.push(b'!');
        }
        bytes
    };
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&bytes);
}

fn check(version: &Version, fields: &[(&str, Kind)], unicode: bool) -> Result<(), String> {
    let mut buf = Vec::new();
    let mut expected = BTreeMap::new();
    for (i, &(name, kind)) in fields.iter().enumerate() {
        let content = format!("{i:02}{name}");
        push(&mut buf, kind, unicode, &content);
        expected.insert(name.to_owned(), content);
    }

    let mut reader = Reader::new(&buf);
    let mut strings = HashMap::new();
    let mut ansi = HashMap::new();
    read_header_strings_and_ansi(&mut reader, version, &mut strings, &mut ansi)
        .map_err(|e| format!("walker failed: {e}"))?;

    let mut actual = BTreeMap::new();
    for (field, value) in &strings {
        actual.insert(field_label(*field).to_owned(), value.clone());
    }
    for (field, bytes) in &ansi {
        let mut value = String::from_utf8_lossy(bytes).into_owned();
        if !value.len().is_multiple_of(2) && value.ends_with('!') {
            value.pop();
        }
        actual.insert(ansi_label(*field).to_owned(), value);
    }
    if actual != expected {
        return Err(format!("read {actual:?}\nexpected {expected:?}"));
    }
    if reader.remaining() != 0 {
        return Err(format!("{} bytes left unread", reader.remaining()));
    }
    Ok(())
}

#[test]
fn header_strings_match_upstream_declaration_for_every_marker() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for (marker, variant, build, version) in builds() {
        let Some(header) = build.records.iter().find(|r| r.name == "TSetupHeader") else {
            continue;
        };
        checked += 1;
        if let Err(e) = check(&version, header.strings, build.unicode) {
            let name = build_name(build);
            failures.push(format!(
                "({}) {name}, as declared by {}: {e}",
                marker.id, variant.origins
            ));
        }
    }
    assert!(checked >= 70, "only {checked} marker builds checked");
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
