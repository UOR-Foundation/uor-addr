//! Substitution-axis selections.
//!
//! - [`crate::bounds::AddrBounds`] — the `HostBounds` profile.
//! - [`Blake3Hasher`] — the default `HashAxis` / `Hasher` axis body, and
//!   [`Sha256Hasher`], both re-exported from `prism::crypto` (the wiki
//!   ADR-031 standard-library cryptography sub-crate). This crate carries
//!   no bespoke hash code of its own.
//!
//! `HostTypes` is bound to `prism::vocabulary::DefaultHostTypes` at the
//! `AddressModel` declaration site directly. `ResolverTuple` lives in
//! [`crate::resolvers`] as `AddressResolverTuple`.

pub mod bounds;

pub use bounds::MAX_JSON_DEPTH;
/// `Hasher<32>` selections for the address-derivation pipeline: BLAKE3 is the
/// default axis. Re-exported from the Prism standard library; see wiki ADR-031.
pub use prism::crypto::{Blake3Hasher, Sha256Hasher};
