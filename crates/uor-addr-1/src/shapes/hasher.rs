//! `Sha256Hasher` — `uor-addr-1`'s foundation `Hasher` implementation.
//!
//! ADR-010 defines the `Hasher` substitution-axis contract:
//! determinism, fixed output width, distinct identifier, idempotence
//! under truncation. The trait permits arbitrary Rust in the body —
//! foundation does not mandate that the body be a `PrimitiveOp`
//! composition. `uor-addr-1`, as the prism implementor, provides the
//! body as pure-Rust FIPS-180-4 SHA-256 (single-pass).
//!
//! Used by foundation's pipeline at certificate-emission time to
//! compute the `ContentFingerprint` over the canonical CompileUnit
//! byte layout, and consumed inside
//! [`crate::resolvers::AddressKInvariantResolver::resolve`] at the
//! terminal ψ_9 stage to derive the 32-byte content-address from the
//! canonicalised JSON bytes.
//!
//! Output width: 32 bytes — matches the foundation-recommended
//! secondary algorithm per `Element::digest_algorithm` (BLAKE3 primary,
//! SHA-256 secondary).

use uor_foundation::enforcement::Hasher;

use crate::ops::sha256::{compress, SHA256_INITIAL_STATE};

/// Streaming SHA-256. Maintains the running compression state online
/// across `fold_byte` / `fold_bytes` calls; finalises with FIPS-180-4
/// padding plus 64-bit big-endian bit-length.
///
/// Heap-free: bookkeeping fits in a fixed-size struct (state + 64-byte
/// partial-block buffer + counters).
#[derive(Debug, Clone)]
pub struct Sha256Hasher {
    /// Running SHA-256 state.
    state: [u32; 8],
    /// Bytes accumulated since the last block compression.
    partial: [u8; 64],
    /// Active byte count in `partial` (always < 64).
    partial_len: u8,
    /// Total bytes folded so far (used in the FIPS-180-4 length pad).
    total_bytes: u64,
}

impl Sha256Hasher {
    #[inline]
    fn compress_block(&mut self, block: &[u8; 64]) {
        compress(&mut self.state, block);
    }
}

impl Hasher for Sha256Hasher {
    const OUTPUT_BYTES: usize = 32;

    fn initial() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            partial: [0u8; 64],
            partial_len: 0,
            total_bytes: 0,
        }
    }

    fn fold_byte(mut self, byte: u8) -> Self {
        self.partial[self.partial_len as usize] = byte;
        self.partial_len += 1;
        self.total_bytes = self.total_bytes.wrapping_add(1);
        if self.partial_len == 64 {
            let block = self.partial;
            self.compress_block(&block);
            self.partial_len = 0;
        }
        self
    }

    fn fold_bytes(mut self, bytes: &[u8]) -> Self {
        // Fast path: copy whole 64-byte chunks once the partial is empty.
        let mut i = 0;
        while i < bytes.len() {
            let need = 64 - self.partial_len as usize;
            let take = core::cmp::min(need, bytes.len() - i);
            self.partial[self.partial_len as usize..self.partial_len as usize + take]
                .copy_from_slice(&bytes[i..i + take]);
            self.partial_len += take as u8;
            self.total_bytes = self.total_bytes.wrapping_add(take as u64);
            i += take;
            if self.partial_len == 64 {
                let block = self.partial;
                self.compress_block(&block);
                self.partial_len = 0;
            }
        }
        self
    }

    fn finalize(mut self) -> [u8; 32] {
        // FIPS-180-4 padding: 0x80 sentinel, zero-pad to 56 mod 64,
        // append big-endian 64-bit total bit length.
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.partial[self.partial_len as usize] = 0x80;
        self.partial_len += 1;
        if self.partial_len > 56 {
            // Fill out current block, compress, then start a fresh padding block.
            for i in self.partial_len as usize..64 {
                self.partial[i] = 0;
            }
            let block = self.partial;
            self.compress_block(&block);
            self.partial = [0u8; 64];
            self.partial_len = 0;
        } else {
            for i in self.partial_len as usize..56 {
                self.partial[i] = 0;
            }
        }
        self.partial[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.partial;
        self.compress_block(&block);

        // Emit final 32-byte digest (big-endian word concatenation).
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::sha256::sha256;

    #[test]
    fn sha256_hasher_empty_matches_one_shot() {
        let from_hasher = Sha256Hasher::initial().finalize();
        let from_one_shot = sha256(b"");
        assert_eq!(from_hasher, from_one_shot);
    }

    #[test]
    fn sha256_hasher_streaming_equals_one_shot() {
        let bytes = b"uor-addr-1 test vector for streaming";
        let one_shot = sha256(bytes);
        let from_hasher = Sha256Hasher::initial().fold_bytes(bytes).finalize();
        assert_eq!(from_hasher, one_shot);

        let mut streaming = Sha256Hasher::initial();
        for &b in bytes.iter() {
            streaming = streaming.fold_byte(b);
        }
        assert_eq!(streaming.finalize(), one_shot);
    }

    #[test]
    fn sha256_hasher_against_jcs_canonical_form_of_simple_object() {
        // The canonical JCS+NFC form of {"foo":"bar"} is the 13 ASCII
        // bytes `{"foo":"bar"}`. Per Maura Clark's harvested fixture,
        // SHA-256 of those bytes is
        // 7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b.
        let canonical = br#"{"foo":"bar"}"#;
        let from_hasher = Sha256Hasher::initial().fold_bytes(canonical).finalize();
        let expected: [u8; 32] = [
            0x7a, 0x38, 0xbf, 0x81, 0xf3, 0x83, 0xf6, 0x94, 0x33, 0xad, 0x6e, 0x90, 0x0d, 0x35,
            0xb3, 0xe2, 0x38, 0x55, 0x93, 0xf7, 0x6a, 0x7b, 0x7a, 0xb5, 0xd4, 0x35, 0x5b, 0x8b,
            0xa4, 0x1e, 0xe2, 0x4b,
        ];
        assert_eq!(from_hasher, expected);
    }
}
