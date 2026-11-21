//! `TSetupISSigKeyEntry`: one `[ISSigKeys]` entry, an ECDSA P-256 public
//! key that `issigverify` files may be signed with (6.5.0+).
//!
//! On disk (`SECompressedBlockWrite`): `PublicX`, `PublicY` and
//! `RuntimeID`, strings. Key names and groups stay in the script; only these
//! reach Setup. Every layout is checked against upstream's own
//! declarations by the `crate::upstream` tests.

use crate::{
    error::Error,
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// One `[ISSigKeys]` entry (`TSetupISSigKeyEntry`).
#[derive(Clone, Debug, Default)]
pub struct ISSigKeyEntry {
    /// `PublicX`: the public key's x coordinate, 64 hex digits.
    pub public_x: String,
    /// `PublicY`: its y coordinate, 64 hex digits.
    pub public_y: String,
    /// `RuntimeID`: the ID `[Code]`'s `ISSigVerify` names the key by; may be
    /// empty.
    pub runtime_id: String,
}

impl FromReader for ISSigKeyEntry {
    /// Reads one entry. Caller is expected to skip when
    /// `EntryCounts.iss_sig_keys` is `Some(0)` / absent.
    ///
    /// # Errors
    ///
    /// String / truncation errors per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let public_x = read_setup_string(reader, version, "ISSigKey.PublicX")?;
        let public_y = read_setup_string(reader, version, "ISSigKey.PublicY")?;
        let runtime_id = read_setup_string(reader, version, "ISSigKey.RuntimeID")?;
        Ok(Self {
            public_x,
            public_y,
            runtime_id,
        })
    }
}
