//! Substitution-axis selections for the CBOR realization.
//!
//! - [`crate::bounds::AddrBounds`] — the `HostBounds` profile.
//! - [`Blake3Hasher`] — the default `Hasher<32>` σ-axis, and [`Sha256Hasher`], re-exported from
//!   `prism::crypto`. The other admissible axes ([`crate::hash`]) are
//!   selected via the `address_<algorithm>` entry points.
//!
//! `HostTypes` is bound to `prism::vocabulary::DefaultHostTypes` at the
//! `AddressModel` declaration site; `ResolverTuple` lives in
//! [`crate::resolvers`] as `AddressResolverTuple`.

pub mod bounds;

pub use bounds::MAX_CBOR_DEPTH;
/// `Hasher<32>` selections for the CBOR address-derivation pipeline; BLAKE3 is the default.
pub use prism::crypto::{Blake3Hasher, Sha256Hasher};
