//! Foundation substitution-axis selections.
//!
//! - [`bounds::AddrBounds`] — the `HostBounds` profile.
//! - [`hasher::Sha256Hasher`] — the `Hasher` axis body (pure-Rust
//!   FIPS-180-4 SHA-256). The canonical content-addressing primitive
//!   for `uor-addr-1`.
//!
//! `HostTypes` is bound to `uor_foundation::DefaultHostTypes` at the
//! `AddressModel` declaration site directly. `ResolverTuple` lives in
//! [`crate::resolvers`] as `AddressResolverTuple`.

pub mod bounds;
pub mod hasher;

pub use bounds::AddrBounds;
pub use hasher::Sha256Hasher;
