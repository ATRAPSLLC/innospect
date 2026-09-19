//! `TSetupISSigKeyEntry` - Inno Setup signing-key entry (6.5.0+).
//!
//! Pascal layout (`is-6_5_0:Projects/Src/Shared.Struct.pas` and
//! identical at HEAD):
//!
//! ```text
//! TSetupISSigKeyEntry = packed record
//!     PublicX, PublicY, RuntimeID: String;
//! end;
//! ```
//!
//! Three String fields written in declaration order via
//! `SECompressedBlockWrite` (`SetupISSigKeyEntryStrings = 3`,
//! `SetupISSigKeyEntryAnsiStrings = 0`).

use crate::{
    error::Error,
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// Parsed `TSetupISSigKeyEntry`.
#[derive(Clone, Debug, Default)]
pub struct ISSigKeyEntry {
    /// X-coordinate of the public key (hex / opaque per Inno).
    pub public_x: String,
    /// Y-coordinate of the public key.
    pub public_y: String,
    /// Runtime identifier - installer-side correlation token.
    pub runtime_id: String,
}

impl ISSigKeyEntry {
    /// Reads one entry. Caller is expected to skip when
    /// `EntryCounts.iss_sig_keys` is `Some(0)` / absent.
    ///
    /// # Errors
    ///
    /// String / truncation errors per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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
