//! `crate::hash` — the pluggable σ-axis hash family (wiki ADR-007 /
//! ADR-010: the substrate ships no hasher; the application selects one).
//!
//! UOR-ADDR's κ-label is `<algorithm>:<lowercase-hex-digest>`. The
//! algorithm is the realization's selected σ-axis `H`; ψ₉ folds the
//! canonical carrier through `H` and formats the label
//! ([`crate::resolvers`]). [`AddrHash`] is the small extension of prism's
//! [`Hasher`] that carries the wire prefix (`"sha256"`, `"blake3"`, …) and
//! the derived κ-label byte width.
//!
//! ## Admissible axes
//!
//! foundation 0.5.1's resolver tower is pinned to `H: Hasher` =
//! `Hasher<32>` (the default 32-byte fingerprint width — see
//! [`prism::pipeline::NerveResolver`] and friends). The admissible σ-axes
//! are therefore exactly prism's **32-byte** hashers:
//!
//! | axis | `LABEL_PREFIX` | `LABEL_BYTES` | authority |
//! |------|----------------|---------------|-----------|
//! | [`Sha256Hasher`]    | `sha256`    | 71 | FIPS 180-4 §6.2 |
//! | [`Blake3Hasher`]    | `blake3`    | 71 | BLAKE3 §2 (the reference spec) |
//! | [`Sha3_256Hasher`]  | `sha3-256`  | 73 | FIPS 202 §6.1 |
//! | [`Keccak256Hasher`] | `keccak256` | 74 | Keccak SHA-3 submission (pre-FIPS padding) |
//!
//! The 64-byte `Sha512Hasher` (`Hasher<64>`) is **not** admissible on
//! prism 0.3.1: the resolver traits would have to be generalized over the
//! fingerprint-width const generic upstream first. Once that lands, a
//! `sha512` axis is one [`AddrHash`] impl plus its `AddressLabelSha512`
//! output shape (135 sites).
//!
//! [`Hasher`]: prism::vocabulary::Hasher
//! [`Sha256Hasher`]: prism::crypto::Sha256Hasher
//! [`Blake3Hasher`]: prism::crypto::Blake3Hasher
//! [`Sha3_256Hasher`]: prism::crypto::Sha3_256Hasher
//! [`Keccak256Hasher`]: prism::crypto::Keccak256Hasher

use prism::crypto::{Blake3Hasher, Keccak256Hasher, Sha256Hasher, Sha3_256Hasher};
use prism::vocabulary::Hasher;

/// The κ-label ASCII byte width for a `<prefix>:<hex>` label over a
/// `digest_bytes`-wide digest: `prefix.len() + 1 (':') + 2 × digest_bytes`.
#[must_use]
pub const fn label_bytes(prefix: &str, digest_bytes: usize) -> usize {
    prefix.len() + 1 + 2 * digest_bytes
}

/// The widest admissible κ-label (`keccak256:` + 64 hex = 74). The κ-label
/// formatter ([`crate::resolvers`]) sizes its stack scratch to this and
/// writes the active axis's `LABEL_BYTES` prefix.
pub const MAX_LABEL_BYTES: usize = label_bytes(Keccak256Hasher::LABEL_PREFIX, 32);

/// A prism [`Hasher`] usable as a UOR-ADDR σ-axis: it carries the κ-label
/// wire prefix and the derived label byte width.
///
/// [`Hasher`]: prism::vocabulary::Hasher
pub trait AddrHash: Hasher {
    /// The lowercase algorithm token at the head of the κ-label
    /// (`"sha256"`, `"blake3"`, `"sha3-256"`, `"keccak256"`).
    const LABEL_PREFIX: &'static str;

    /// Total κ-label ASCII width = `LABEL_PREFIX.len() + 1 + 2 ×
    /// OUTPUT_BYTES`. The realization's output shape declares exactly this
    /// many `Site` constraints, and the entry point returns
    /// [`KappaLabel`](crate::label::KappaLabel)`<{LABEL_BYTES}>`.
    const LABEL_BYTES: usize = label_bytes(Self::LABEL_PREFIX, <Self as Hasher>::OUTPUT_BYTES);
}

impl AddrHash for Sha256Hasher {
    const LABEL_PREFIX: &'static str = "sha256";
}
impl AddrHash for Blake3Hasher {
    const LABEL_PREFIX: &'static str = "blake3";
}
impl AddrHash for Sha3_256Hasher {
    const LABEL_PREFIX: &'static str = "sha3-256";
}
impl AddrHash for Keccak256Hasher {
    const LABEL_PREFIX: &'static str = "keccak256";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_widths_match_the_specification() {
        assert_eq!(Sha256Hasher::LABEL_BYTES, 71);
        assert_eq!(Blake3Hasher::LABEL_BYTES, 71);
        assert_eq!(Sha3_256Hasher::LABEL_BYTES, 73);
        assert_eq!(Keccak256Hasher::LABEL_BYTES, 74);
        assert_eq!(MAX_LABEL_BYTES, 74);
    }

    #[test]
    fn every_admissible_axis_is_thirty_two_bytes_wide() {
        // foundation 0.5.1's resolver tower admits only `Hasher<32>`.
        assert_eq!(<Sha256Hasher as Hasher>::OUTPUT_BYTES, 32);
        assert_eq!(<Blake3Hasher as Hasher>::OUTPUT_BYTES, 32);
        assert_eq!(<Sha3_256Hasher as Hasher>::OUTPUT_BYTES, 32);
        assert_eq!(<Keccak256Hasher as Hasher>::OUTPUT_BYTES, 32);
    }
}
