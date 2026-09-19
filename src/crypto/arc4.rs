//! Inline RC4 (Alleged RC4 / "ARC4") used by Inno Setup pre-6.4
//! for chunk encryption.
//!
//! ARC4 is a stream cipher with a 1-256 byte key, a 256-byte
//! state, and an XOR-with-keystream operation that's its own
//! inverse. We implement it locally (~30 LoC) rather than pulling
//! in a separate crate because:
//!
//! - The algorithm is tiny and trivially auditable.
//! - It's only used for legacy chunk decryption - no other crate
//!   in our dep graph wants it.
//! - Innoextract takes the same approach (`research/src/crypto/arc4.cpp`).
//!
//! Per Inno Setup's 5.3.9..6.4 implementation: the chunk's per-
//! chunk salt + password is hashed (SHA-1 or MD5 per version) and
//! the first 16 bytes of the hash are used as the RC4 key.

/// RC4 cipher state. Construct with [`Self::new`], then call
/// [`Self::apply`] one or more times to XOR the keystream over a
/// buffer in place.
pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initializes the cipher state via RC4's Key Scheduling
    /// Algorithm (KSA). `key` must be 1..=256 bytes; longer keys
    /// are accepted but only the first 256 bytes affect the state.
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            // i is bounded by 256 (loop length), so the cast is
            // exact.
            #[allow(clippy::cast_possible_truncation)]
            {
                *slot = i as u8;
            }
        }

        if !key.is_empty() {
            let mut j: u8 = 0;
            for i in 0..256usize {
                // Safe index because i < 256.
                let key_byte = match key.get(i.checked_rem(key.len()).unwrap_or(0)) {
                    Some(b) => *b,
                    None => 0,
                };
                let s_i = match s.get(i) {
                    Some(b) => *b,
                    None => 0,
                };
                j = j.wrapping_add(s_i).wrapping_add(key_byte);
                let j_us = usize::from(j);
                if let (Some(_), Some(_)) = (s.get(i), s.get(j_us)) {
                    s.swap(i, j_us);
                }
            }
        }

        Self { s, i: 0, j: 0 }
    }

    /// Advances the keystream by `n` bytes without applying them
    /// to any buffer. Inno's pre-6.4 chunk decryption discards the
    /// first 1000 bytes of the keystream after KSA - biased early
    /// bytes were the WEP attack surface, and ISCrypt.dll mirrors
    /// the standard RC4-drop hardening (`research/src/stream/chunk.cpp:72`,
    /// `arc4.discard(1000)`). Skipping the discard produces a
    /// keystream that XORs cleanly through password verification
    /// (which doesn't use the chunk RC4) but yields garbage at the
    /// chunk-decrypt step - observable as malformed LZMA streams.
    pub(crate) fn discard(&mut self, n: usize) {
        for _ in 0..n {
            self.i = self.i.wrapping_add(1);
            let s_i = match self.s.get(usize::from(self.i)) {
                Some(b) => *b,
                None => 0,
            };
            self.j = self.j.wrapping_add(s_i);
            let i_us = usize::from(self.i);
            let j_us = usize::from(self.j);
            if let (Some(_), Some(_)) = (self.s.get(i_us), self.s.get(j_us)) {
                self.s.swap(i_us, j_us);
            }
        }
    }

    /// Applies the keystream to `buf` in place (XOR). Symmetric:
    /// calling `apply` twice with the same key restores the
    /// original bytes.
    pub(crate) fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            let s_i = match self.s.get(usize::from(self.i)) {
                Some(b) => *b,
                None => 0,
            };
            self.j = self.j.wrapping_add(s_i);
            let i_us = usize::from(self.i);
            let j_us = usize::from(self.j);
            if let (Some(_), Some(_)) = (self.s.get(i_us), self.s.get(j_us)) {
                self.s.swap(i_us, j_us);
            }
            let s_i_new = match self.s.get(i_us) {
                Some(b) => *b,
                None => 0,
            };
            let s_j_new = match self.s.get(j_us) {
                Some(b) => *b,
                None => 0,
            };
            let k = match self.s.get(usize::from(s_i_new.wrapping_add(s_j_new))) {
                Some(b) => *b,
                None => 0,
            };
            *byte ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector from the original RC4 spec / RFC 6229
    /// (informational): `Key`/`Plaintext` → `BBF316E8D940AF0AD3`.
    #[test]
    fn rc4_canonical_key_plaintext_vector() {
        let mut buf = b"Plaintext".to_vec();
        let mut cipher = Rc4::new(b"Key");
        cipher.apply(&mut buf);
        assert_eq!(
            buf,
            vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
        );
    }

    /// `Wiki`/`pedia` → `1021BF0420`.
    #[test]
    fn rc4_canonical_wiki_vector() {
        let mut buf = b"pedia".to_vec();
        let mut cipher = Rc4::new(b"Wiki");
        cipher.apply(&mut buf);
        assert_eq!(buf, vec![0x10, 0x21, 0xBF, 0x04, 0x20]);
    }

    /// `Secret`/`Attack at dawn` → `45A01F645FC35B383552544B9BF5`.
    #[test]
    fn rc4_canonical_secret_vector() {
        let mut buf = b"Attack at dawn".to_vec();
        let mut cipher = Rc4::new(b"Secret");
        cipher.apply(&mut buf);
        assert_eq!(
            buf,
            vec![
                0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5,
            ]
        );
    }

    /// Round-trip: applying the same keystream twice restores the
    /// original.
    #[test]
    fn rc4_round_trip() {
        let original = b"Inno test payload v1\n";
        let mut buf = original.to_vec();
        Rc4::new(b"Key").apply(&mut buf);
        assert_ne!(buf.as_slice(), original);
        Rc4::new(b"Key").apply(&mut buf);
        assert_eq!(buf.as_slice(), original);
    }

    /// Streaming: applying in two halves produces the same result
    /// as applying in one shot.
    #[test]
    fn rc4_streaming_matches_one_shot() {
        let one_shot = {
            let mut buf = b"hello world hello world".to_vec();
            Rc4::new(b"k").apply(&mut buf);
            buf
        };
        let streamed = {
            let mut buf = b"hello world hello world".to_vec();
            let mut cipher = Rc4::new(b"k");
            let mid = buf.len() / 2;
            let (left, right) = buf.split_at_mut(mid);
            cipher.apply(left);
            cipher.apply(right);
            buf
        };
        assert_eq!(one_shot, streamed);
    }
}
