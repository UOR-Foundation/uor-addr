//! `AddressResolverTuple` — the single eight-resolver tower shared by
//! every UOR-ADDR realization (ADR-036).
//!
//! Under ADR-060 the realization's canonical form flows through the
//! pipeline as a source-polymorphic [`TermValue`] carrier produced by the
//! input's `as_binding_value` (see [`crate::common::AddressInput`]). The
//! ψ-tower is therefore **format-independent**: ψ₁ (nerve) … ψ₈ thread the
//! carrier through unchanged, and ψ₉ (k-invariants) folds the carrier
//! through the σ-axis `H` chunk-by-chunk — never materializing it — and
//! emits the 71-byte ASCII κ-label `sha256:<64hex>` as an `Inline` carrier.
//!
//! Because canonicalization happens at carrier production (the input
//! streams its canonical bytes), no resolver holds format state and there
//! is no per-realization resolver code.

use core::marker::PhantomData;

use prism::operation::TermValue;
use prism::pipeline::{
    resolver, ChainComplexResolver, CochainComplexResolver, CohomologyGroupResolver,
    HomologyGroupResolver, HomotopyGroupResolver, KInvariantResolver, NerveResolver,
    PostnikovResolver,
};
use prism::vocabulary::Hasher;

use crate::label::ADDRESS_LABEL_BYTES;

const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

/// Fold `bytes` into the hasher behind a `&mut` (the consuming
/// `fold_bytes` API is awkward inside the `for_each_chunk` `FnMut`).
#[inline]
fn fold_into<H: Hasher>(h: &mut H, bytes: &[u8]) {
    let cur = core::mem::replace(h, H::initial());
    *h = cur.fold_bytes(bytes);
}

/// Fold the carrier through `H` (streaming, bounded memory) and format the
/// 71-byte κ-label into an `Inline` carrier.
fn kappa_label_carrier<const N: usize, H: Hasher>(
    input: &TermValue<'_, N>,
) -> TermValue<'static, N> {
    let mut h = H::initial();
    input.for_each_chunk(&mut |chunk| fold_into(&mut h, chunk));
    let digest = h.finalize();

    let mut out = [0u8; ADDRESS_LABEL_BYTES];
    out[..7].copy_from_slice(b"sha256:");
    for (i, byte) in digest.iter().enumerate().take(32) {
        out[7 + 2 * i] = HEX_LOWER[(byte >> 4) as usize];
        out[7 + 2 * i + 1] = HEX_LOWER[(byte & 0x0F) as usize];
    }
    TermValue::inline_from_slice(&out)
}

macro_rules! sealed_resolver {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name<H>(PhantomData<H>);
        impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed for $name<H> {}
        impl<H: Hasher> Default for $name<H> {
            #[inline]
            fn default() -> Self {
                Self(PhantomData)
            }
        }
    };
}

sealed_resolver!(AddressNerveResolver);
sealed_resolver!(AddressChainComplexResolver);
sealed_resolver!(AddressHomologyGroupResolver);
sealed_resolver!(AddressCochainComplexResolver);
sealed_resolver!(AddressCohomologyGroupResolver);
sealed_resolver!(AddressPostnikovResolver);
sealed_resolver!(AddressHomotopyGroupResolver);
sealed_resolver!(AddressKInvariantResolver);

impl<const N: usize, H: Hasher> NerveResolver<N, H> for AddressNerveResolver<H> {
    #[inline]
    fn resolve<'a>(
        &self,
        input: TermValue<'a, N>,
    ) -> Result<TermValue<'a, N>, prism::pipeline::ShapeViolation> {
        Ok(input)
    }
}

macro_rules! passthrough_resolver {
    ($trait:ident, $name:ident) => {
        impl<const N: usize, H: Hasher> $trait<N, H> for $name<H> {
            #[inline]
            fn resolve<'a>(
                &self,
                input: TermValue<'a, N>,
            ) -> Result<TermValue<'a, N>, prism::pipeline::ShapeViolation> {
                Ok(input)
            }
        }
    };
}

passthrough_resolver!(ChainComplexResolver, AddressChainComplexResolver);
passthrough_resolver!(HomologyGroupResolver, AddressHomologyGroupResolver);
passthrough_resolver!(CochainComplexResolver, AddressCochainComplexResolver);
passthrough_resolver!(CohomologyGroupResolver, AddressCohomologyGroupResolver);
passthrough_resolver!(PostnikovResolver, AddressPostnikovResolver);
passthrough_resolver!(HomotopyGroupResolver, AddressHomotopyGroupResolver);

impl<const N: usize, H: Hasher> KInvariantResolver<N, H> for AddressKInvariantResolver<H> {
    #[inline]
    fn resolve<'a>(
        &self,
        input: TermValue<'a, N>,
    ) -> Result<TermValue<'a, N>, prism::pipeline::ShapeViolation> {
        // ψ₉ σ-projection: fold the (streamed) canonical carrier through H
        // and emit the formatted κ-label. The `'static` Inline carrier is
        // valid for any `'a`.
        Ok(kappa_label_carrier::<N, H>(&input))
    }
}

resolver! {
    pub struct AddressResolverTuple<H: ::prism::vocabulary::Hasher> {
        nerve: AddressNerveResolver<H>,
        chain_complex: AddressChainComplexResolver<H>,
        homology_groups: AddressHomologyGroupResolver<H>,
        cochain_complex: AddressCochainComplexResolver<H>,
        cohomology_groups: AddressCohomologyGroupResolver<H>,
        postnikov: AddressPostnikovResolver<H>,
        homotopy_groups: AddressHomotopyGroupResolver<H>,
        k_invariants: AddressKInvariantResolver<H>,
    }
}
