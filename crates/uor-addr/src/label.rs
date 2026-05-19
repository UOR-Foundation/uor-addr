//! `AddressLabel` — UOR-ADDR's **common output shape** (ARCHITECTURE.md
//! "Common output shape").
//!
//! The κ-label's wire-format byte layout follows the architecture
//! document's structural formula
//!
//! ```text
//! SITE_COUNT = H::IDENTIFIER.len() + 1 + 2 × H::DIGEST_BYTES
//! ```
//!
//! parameterized on the realization's selected hash axis `H: Hasher`.
//! The output space is **π_0-only** by structural property of the
//! σ-projection + hex-serialization composition; `χ(N(C)) = SITE_COUNT`;
//! `β_0 = SITE_COUNT`; `β_k = 0` for `k ≥ 1`.
//!
//! For UOR-ADDR's first-published realizations (which bind
//! `H = prism::crypto::Sha256Hasher` per ADR-047's Hardening
//! Principle), the specialization is the **71-Site shape** declared
//! below. Per-realization specializations for alternate hash axes
//! (e.g. `H = Sha512Hasher` would yield `6 + 1 + 128 = 135` sites)
//! land via additional `output_shape!` invocations in future module
//! versions of this file once those axes are needed; per ADR-031's
//! demand-driven clause, only the SHA-256 specialization is shipped
//! today because every documented format-specific realization
//! (`uor-addr-json`, `uor-addr-xml`, `uor-addr-sexp`, …) binds
//! `H = Sha256Hasher`.
//!
//! ## Per-axis IRI suffix
//!
//! The content-addressed IRI is
//! `https://uor.foundation/addr/AddressLabel/<H::IDENTIFIER>`. The
//! IRI specializes per axis so that two realizations binding
//! different `H` selections produce distinct typed reference
//! vocabularies at the IRI level (the framework's typed-iso
//! commitment per ADR-001 + ADR-017). For the SHA-256 specialization
//! shipped today, the suffix is `/sha256`.
//!
//! ## What this shape carries
//!
//! - 7 bytes for `b"sha256"` + `b":"` (the algorithm prefix, sites
//!   0..7),
//! - 64 bytes for the lowercase-hex serialization of the SHA-256
//!   σ-projection's 32-byte digest (sites 7..71),
//! - total = 71 ASCII bytes — the wire-format `sha256:<64hex>` width.
//!
//! The constraint geometry declares 71 disjoint `ConstraintRef::Site`
//! constraints — one per byte position. The wiki's
//! iterative-resolution discipline converges in 0 residual rank at
//! ψ_9 because all 71 sites pin simultaneously to the κ-derivation.

use prism::pipeline::{output_shape, ConstraintRef};

/// **The wire-format address byte width** under
/// `H = prism::crypto::Sha256Hasher`:
/// `len("sha256") + 1 + 2 × 32 = 71`.
pub const ADDRESS_LABEL_BYTES: usize = 71;

/// **The runtime κ-label carrier** — the 71-byte ASCII
/// `sha256:<64-lowercase-hex>` wire-format byte sequence.
///
/// `KappaLabel` carries the κ-derivation output of the ψ-pipeline:
/// 7 ASCII bytes for `b"sha256:"` plus 64 ASCII bytes for the
/// lowercase-hex serialization of the SHA-256 σ-projection's
/// 32-byte digest. The constructor [`KappaLabel::from_bytes`]
/// validates length (= [`ADDRESS_LABEL_BYTES`]) and ASCII purity;
/// downstream methods can therefore project to `&str` infallibly.
///
/// `Copy + Eq + Hash` — callers may freely thread the κ-label
/// through hash maps, identity comparisons, and pass-by-value
/// contexts without any allocator. `Deref<Target = str>` provides
/// the usual `&str` methods (`starts_with`, indexing, `len`, etc.)
/// without going through an intermediate carrier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KappaLabel([u8; ADDRESS_LABEL_BYTES]);

impl KappaLabel {
    /// Build a `KappaLabel` from a 71-byte ASCII slice. Returns
    /// `LabelDecodeError` if `bytes.len() != ADDRESS_LABEL_BYTES` or
    /// `bytes` contains a non-ASCII byte.
    ///
    /// The ψ-pipeline emits ASCII-only bytes by construction (the
    /// algorithm prefix `b"sha256:"` plus lowercase-hex from
    /// `crate::canonical::hex::encode_lower_into`). Defense-in-depth:
    /// the constructor still validates so a substrate-corrupted byte
    /// sequence cannot smuggle a non-ASCII `KappaLabel` into the
    /// typed surface.
    ///
    /// # Errors
    ///
    /// - [`LabelDecodeError::WrongLength`] — `bytes.len() != 71`.
    /// - [`LabelDecodeError::NonAscii`] — `bytes` contains a byte ≥ 0x80.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LabelDecodeError> {
        if bytes.len() != ADDRESS_LABEL_BYTES {
            return Err(LabelDecodeError::WrongLength);
        }
        let mut buf = [0u8; ADDRESS_LABEL_BYTES];
        for (dst, &src) in buf.iter_mut().zip(bytes.iter()) {
            if !src.is_ascii() {
                return Err(LabelDecodeError::NonAscii);
            }
            *dst = src;
        }
        Ok(Self(buf))
    }

    /// Borrow the κ-label as a 71-byte array.
    #[must_use]
    pub fn as_array(&self) -> &[u8; ADDRESS_LABEL_BYTES] {
        &self.0
    }

    /// Borrow the κ-label as a `&str`. Infallible — the carrier is
    /// ASCII by construction (validated at [`KappaLabel::from_bytes`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The constructor validates ASCII purity; `from_utf8` is
        // therefore total over `self.0` and the `expect` is
        // unreachable.
        core::str::from_utf8(&self.0).expect("KappaLabel is ASCII by construction")
    }

    /// Borrow the κ-label as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for KappaLabel {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for KappaLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for KappaLabel {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for KappaLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Debug for KappaLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("KappaLabel").field(&self.as_str()).finish()
    }
}

impl PartialEq<str> for KappaLabel {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for KappaLabel {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<KappaLabel> for str {
    fn eq(&self, other: &KappaLabel) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<KappaLabel> for &str {
    fn eq(&self, other: &KappaLabel) -> bool {
        *self == other.as_str()
    }
}

/// Decoding failures from [`KappaLabel::from_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelDecodeError {
    /// `bytes.len() != ADDRESS_LABEL_BYTES`.
    WrongLength,
    /// `bytes` contains a non-ASCII byte (≥ 0x80).
    NonAscii,
}

output_shape! {
    pub struct AddressLabel;
    impl ConstrainedTypeShape for AddressLabel {
        const IRI: &'static str = "https://uor.foundation/addr/AddressLabel/sha256";
        const SITE_COUNT: usize = 71;
        const CONSTRAINTS: &'static [ConstraintRef] = &[
            // 71 disjoint Site constraints — one per wire-format
            // address byte position. The prefix bytes pinned to
            // `b"sha256"`'s byte values, the separator byte pinned to
            // `:`, the hex digits pinned to the lowercase-hex
            // character set (the ψ_9 resolver body enforces the
            // character-set constraint by construction).
            ConstraintRef::Site { position: 0 }, ConstraintRef::Site { position: 1 },
            ConstraintRef::Site { position: 2 }, ConstraintRef::Site { position: 3 },
            ConstraintRef::Site { position: 4 }, ConstraintRef::Site { position: 5 },
            ConstraintRef::Site { position: 6 }, ConstraintRef::Site { position: 7 },
            ConstraintRef::Site { position: 8 }, ConstraintRef::Site { position: 9 },
            ConstraintRef::Site { position: 10 }, ConstraintRef::Site { position: 11 },
            ConstraintRef::Site { position: 12 }, ConstraintRef::Site { position: 13 },
            ConstraintRef::Site { position: 14 }, ConstraintRef::Site { position: 15 },
            ConstraintRef::Site { position: 16 }, ConstraintRef::Site { position: 17 },
            ConstraintRef::Site { position: 18 }, ConstraintRef::Site { position: 19 },
            ConstraintRef::Site { position: 20 }, ConstraintRef::Site { position: 21 },
            ConstraintRef::Site { position: 22 }, ConstraintRef::Site { position: 23 },
            ConstraintRef::Site { position: 24 }, ConstraintRef::Site { position: 25 },
            ConstraintRef::Site { position: 26 }, ConstraintRef::Site { position: 27 },
            ConstraintRef::Site { position: 28 }, ConstraintRef::Site { position: 29 },
            ConstraintRef::Site { position: 30 }, ConstraintRef::Site { position: 31 },
            ConstraintRef::Site { position: 32 }, ConstraintRef::Site { position: 33 },
            ConstraintRef::Site { position: 34 }, ConstraintRef::Site { position: 35 },
            ConstraintRef::Site { position: 36 }, ConstraintRef::Site { position: 37 },
            ConstraintRef::Site { position: 38 }, ConstraintRef::Site { position: 39 },
            ConstraintRef::Site { position: 40 }, ConstraintRef::Site { position: 41 },
            ConstraintRef::Site { position: 42 }, ConstraintRef::Site { position: 43 },
            ConstraintRef::Site { position: 44 }, ConstraintRef::Site { position: 45 },
            ConstraintRef::Site { position: 46 }, ConstraintRef::Site { position: 47 },
            ConstraintRef::Site { position: 48 }, ConstraintRef::Site { position: 49 },
            ConstraintRef::Site { position: 50 }, ConstraintRef::Site { position: 51 },
            ConstraintRef::Site { position: 52 }, ConstraintRef::Site { position: 53 },
            ConstraintRef::Site { position: 54 }, ConstraintRef::Site { position: 55 },
            ConstraintRef::Site { position: 56 }, ConstraintRef::Site { position: 57 },
            ConstraintRef::Site { position: 58 }, ConstraintRef::Site { position: 59 },
            ConstraintRef::Site { position: 60 }, ConstraintRef::Site { position: 61 },
            ConstraintRef::Site { position: 62 }, ConstraintRef::Site { position: 63 },
            ConstraintRef::Site { position: 64 }, ConstraintRef::Site { position: 65 },
            ConstraintRef::Site { position: 66 }, ConstraintRef::Site { position: 67 },
            ConstraintRef::Site { position: 68 }, ConstraintRef::Site { position: 69 },
            ConstraintRef::Site { position: 70 },
        ];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism::pipeline::ConstrainedTypeShape;

    #[test]
    fn site_count_matches_wire_format_byte_width_for_sha256() {
        assert_eq!(
            <AddressLabel as ConstrainedTypeShape>::SITE_COUNT,
            ADDRESS_LABEL_BYTES
        );
    }

    #[test]
    fn iri_carries_axis_suffix_per_architecture() {
        assert_eq!(
            <AddressLabel as ConstrainedTypeShape>::IRI,
            "https://uor.foundation/addr/AddressLabel/sha256"
        );
    }

    #[test]
    fn carries_seventy_one_disjoint_site_constraints() {
        let cs = <AddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
        assert_eq!(cs.len(), 71);
        for (i, c) in cs.iter().enumerate() {
            match c {
                ConstraintRef::Site { position } => assert_eq!(*position, i as u32),
                _ => panic!("expected Site constraint at index {i}"),
            }
        }
    }

    #[test]
    fn kappa_label_from_bytes_round_trips_valid_input() {
        let bytes = b"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let label = KappaLabel::from_bytes(bytes).expect("valid");
        assert_eq!(label.as_str(), core::str::from_utf8(bytes).unwrap());
        assert_eq!(label.as_bytes(), bytes);
        assert_eq!(label.as_array(), bytes);
        // Deref<Target=str> brings str methods into scope.
        assert!(label.starts_with("sha256:"));
        assert_eq!(label.len(), ADDRESS_LABEL_BYTES);
    }

    #[test]
    fn kappa_label_rejects_wrong_length() {
        let err = KappaLabel::from_bytes(b"too short").expect_err("rejects");
        assert_eq!(err, LabelDecodeError::WrongLength);
    }

    #[test]
    fn kappa_label_rejects_non_ascii_byte() {
        let mut bytes = [b'a'; ADDRESS_LABEL_BYTES];
        bytes[3] = 0x80;
        let err = KappaLabel::from_bytes(&bytes).expect_err("rejects");
        assert_eq!(err, LabelDecodeError::NonAscii);
    }

    #[test]
    fn kappa_label_equality_against_str() {
        let bytes = b"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let label = KappaLabel::from_bytes(bytes).expect("valid");
        let s: &str = core::str::from_utf8(bytes).unwrap();
        assert_eq!(label, *s);
        assert_eq!(label, s);
        assert_eq!(s, label);
    }
}
