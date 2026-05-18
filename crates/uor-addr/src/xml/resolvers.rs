//! XML realization's `ResolverTuple` — the eight ψ-stage
//! resolver impls (ADR-036 + ARCHITECTURE.md "Common resolver tuple
//! shape").
//!
//! Architectural parallel to [`crate::json::resolvers`]: every
//! resolver is the algebraic-closure-shape-preserving identity
//! through the ψ_1 + ψ_2..ψ_6 (off-path) + ψ_7 + ψ_8 stages, then
//! ψ_9 invokes [`crate::common::AddressInput::canonicalize_into`] on
//! [`crate::xml::XmlValue`] inside its resolver body (ADR-046
//! sanctioned σ-residual scope) and projects through the canonical
//! hash axis (`H: Hasher`) to derive the κ-label.
//!
//! For the algebraic-closure shape declared on [`crate::AddressLabel`]
//! (71 disjoint Sites), every ψ-stage carrier carries 71 isolated
//! vertices — the same geometry as the JSON realization.

extern crate alloc;

use core::marker::PhantomData;

use prism::pipeline::{
    resolver, ChainComplexResolver, CochainComplexResolver, CohomologyGroupResolver,
    ConstrainedTypeShape, ConstraintRef, HomologyGroupResolver, HomotopyGroupResolver,
    KInvariantResolver, NerveResolver, PostnikovResolver, ShapeViolation, ViolationKind,
};
use prism::uor_foundation::pipeline::{
    ChainComplexBytes, CochainComplexBytes, HomotopyGroupsBytes, PostnikovTowerBytes,
    SimplicialComplexBytes,
};
use prism::vocabulary::{Hasher, HostBounds};

use crate::common::AddressInput;
use crate::label::{AddressLabel, ADDRESS_LABEL_BYTES};
use crate::xml::shapes::bounds::{XmlAddrBounds, XML_VALUE_MAX_BYTES};
use crate::xml::value::XmlValue;

// ─── Carrier layout constants — mirrors json::resolvers ────────────────

const WIRE_FORMAT_ADDRESS_BYTES: usize = ADDRESS_LABEL_BYTES;
const CARRIER_BYTES: usize = <XmlAddrBounds as HostBounds>::TERM_VALUE_MAX_BYTES;
const NERVE_VERTEX_COUNT: u32 = 71;
const NERVE_HIGHEST_DIM: u32 = 0;
const GEOMETRY_TAIL_BYTES: usize = 8 + 4 + 4 + 4 + NERVE_VERTEX_COUNT as usize;
const LENGTH_PREFIX_BYTES: usize = 4;

#[allow(dead_code)]
const CARRIER_PAYLOAD_MAX: usize = CARRIER_BYTES - LENGTH_PREFIX_BYTES - GEOMETRY_TAIL_BYTES;

const _: () = {
    assert!(
        XML_VALUE_MAX_BYTES <= CARRIER_PAYLOAD_MAX,
        "XML_VALUE_MAX_BYTES must fit within CARRIER_BYTES - LENGTH_PREFIX_BYTES - GEOMETRY_TAIL_BYTES"
    );
};

const OFFSET_GEOMETRY_TAIL: usize = CARRIER_BYTES - GEOMETRY_TAIL_BYTES;
const OFFSET_STAGE_TAG: usize = OFFSET_GEOMETRY_TAIL;
const OFFSET_VERTEX_COUNT: usize = OFFSET_STAGE_TAG + 8;
const OFFSET_HIGHEST_DIM: usize = OFFSET_VERTEX_COUNT + 4;
const OFFSET_RESERVED: usize = OFFSET_HIGHEST_DIM + 4;

const PSI_1_NERVE_TAG: u64 = 1;
const PSI_2_CHAIN_COMPLEX_TAG: u64 = 2;
const PSI_3_HOMOLOGY_GROUPS_TAG: u64 = 3;
const PSI_5_COCHAIN_COMPLEX_TAG: u64 = 5;
const PSI_6_COHOMOLOGY_GROUPS_TAG: u64 = 6;
const PSI_7_POSTNIKOV_TOWER_TAG: u64 = 7;
const PSI_8_HOMOTOPY_GROUPS_TAG: u64 = 8;

const INPUT_LEN_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/xml/resolver/XmlValueBytes",
    constraint_iri: "https://uor.foundation/addr/xml/resolver/XmlValueBytes/maxBytes",
    property_iri: "https://uor.foundation/addr/xml/resolver/XmlValueBytes/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: XML_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

const CARRIER_INPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/xml/resolver/CarrierInput",
    constraint_iri: "https://uor.foundation/addr/xml/resolver/CarrierInput/expectedCarrierBytes",
    property_iri: "https://uor.foundation/addr/xml/resolver/CarrierInput/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: CARRIER_BYTES as u32,
    max_count: CARRIER_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

const CARRIER_BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/xml/resolver/CarrierBuffer",
    constraint_iri: "https://uor.foundation/addr/xml/resolver/CarrierBuffer/minBytes",
    property_iri: "https://uor.foundation/addr/xml/resolver/CarrierBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: CARRIER_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

const ADDR_OUTPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/xml/resolver/AddressLabelBuffer",
    constraint_iri: "https://uor.foundation/addr/xml/resolver/AddressLabelBuffer/minBytes",
    property_iri: "https://uor.foundation/addr/xml/resolver/AddressLabelBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: WIRE_FORMAT_ADDRESS_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

const UPSTREAM_TAG_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/xml/resolver/UpstreamStageTag",
    constraint_iri: "https://uor.foundation/addr/xml/resolver/UpstreamStageTag/expectedTag",
    property_iri: "https://uor.foundation/addr/xml/resolver/UpstreamStageTag/stageTag",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedLong",
    min_count: 1,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const GEOMETRY_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/xml/resolver/CarrierGeometry",
    constraint_iri:
        "https://uor.foundation/addr/xml/resolver/CarrierGeometry/seventyOneVerticesDiscrete",
    property_iri: "https://uor.foundation/addr/xml/resolver/CarrierGeometry/vertexCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: NERVE_VERTEX_COUNT,
    max_count: NERVE_VERTEX_COUNT,
    kind: ViolationKind::ValueCheck,
};

const _: () = {
    let cs = <AddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
    assert!(cs.len() == NERVE_VERTEX_COUNT as usize);
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            ConstraintRef::Site { position } => assert!(position as usize == i),
            _ => panic!("AddressLabel::CONSTRAINTS may only contain ConstraintRef::Site instances"),
        }
        i += 1;
    }
};

const GEOMETRY_TAIL_AFTER_STAGE_TAG: [u8; GEOMETRY_TAIL_BYTES - 8] = {
    let mut t = [0u8; GEOMETRY_TAIL_BYTES - 8];
    let vc = NERVE_VERTEX_COUNT.to_be_bytes();
    t[0] = vc[0];
    t[1] = vc[1];
    t[2] = vc[2];
    t[3] = vc[3];
    let mut i = 0;
    while i < NERVE_VERTEX_COUNT as usize {
        t[12 + i] = i as u8;
        i += 1;
    }
    t
};

struct DecodedCarrier<'a> {
    canonical: &'a [u8],
    stage_tag: u64,
    vertex_count: u32,
    highest_dim: u32,
}

#[inline]
fn decode_carrier(bytes: &[u8]) -> Result<DecodedCarrier<'_>, ShapeViolation> {
    if bytes.len() != CARRIER_BYTES {
        return Err(CARRIER_INPUT_VIOLATION);
    }
    let canonical_len =
        u32::from_be_bytes(bytes[..LENGTH_PREFIX_BYTES].try_into().unwrap_or([0; 4])) as usize;
    if canonical_len > XML_VALUE_MAX_BYTES {
        return Err(INPUT_LEN_VIOLATION);
    }
    let canonical = &bytes[LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + canonical_len];
    let stage_tag = u64::from_be_bytes(
        bytes[OFFSET_STAGE_TAG..OFFSET_VERTEX_COUNT]
            .try_into()
            .unwrap_or([0; 8]),
    );
    let vertex_count = u32::from_be_bytes(
        bytes[OFFSET_VERTEX_COUNT..OFFSET_HIGHEST_DIM]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let highest_dim = u32::from_be_bytes(
        bytes[OFFSET_HIGHEST_DIM..OFFSET_RESERVED]
            .try_into()
            .unwrap_or([0; 4]),
    );
    Ok(DecodedCarrier {
        canonical,
        stage_tag,
        vertex_count,
        highest_dim,
    })
}

#[inline]
fn validate_upstream(
    carrier: &DecodedCarrier<'_>,
    expected_upstream_tag: u64,
) -> Result<(), ShapeViolation> {
    if carrier.stage_tag != expected_upstream_tag {
        return Err(UPSTREAM_TAG_VIOLATION);
    }
    if carrier.vertex_count != NERVE_VERTEX_COUNT {
        return Err(GEOMETRY_VIOLATION);
    }
    if carrier.highest_dim != NERVE_HIGHEST_DIM {
        return Err(GEOMETRY_VIOLATION);
    }
    Ok(())
}

#[inline]
fn emit_carrier(canonical: &[u8], stage_tag: u64, out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if out.len() < CARRIER_BYTES {
        return Err(CARRIER_BUFFER_VIOLATION);
    }
    if canonical.len() > XML_VALUE_MAX_BYTES {
        return Err(INPUT_LEN_VIOLATION);
    }
    let len_bytes = (canonical.len() as u32).to_be_bytes();
    out[..LENGTH_PREFIX_BYTES].copy_from_slice(&len_bytes);
    out[LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + canonical.len()].copy_from_slice(canonical);
    let zero_start = LENGTH_PREFIX_BYTES + canonical.len();
    out[zero_start..OFFSET_GEOMETRY_TAIL].fill(0);
    out[OFFSET_STAGE_TAG..OFFSET_VERTEX_COUNT].copy_from_slice(&stage_tag.to_be_bytes());
    out[OFFSET_VERTEX_COUNT..].copy_from_slice(&GEOMETRY_TAIL_AFTER_STAGE_TAG);
    Ok(CARRIER_BYTES)
}

// ─── Resolvers ─────────────────────────────────────────────────────────

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

impl<H: Hasher> NerveResolver<H> for AddressNerveResolver<H> {
    #[inline]
    fn resolve(&self, input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if input.len() > XML_VALUE_MAX_BYTES {
            return Err(INPUT_LEN_VIOLATION);
        }
        emit_carrier(input, PSI_1_NERVE_TAG, out)
    }
}

impl<H: Hasher> ChainComplexResolver<H> for AddressChainComplexResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_1_NERVE_TAG)?;
        emit_carrier(carrier.canonical, PSI_2_CHAIN_COMPLEX_TAG, out)
    }
}

impl<H: Hasher> HomologyGroupResolver<H> for AddressHomologyGroupResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_2_CHAIN_COMPLEX_TAG)?;
        emit_carrier(carrier.canonical, PSI_3_HOMOLOGY_GROUPS_TAG, out)
    }
}

impl<H: Hasher> CochainComplexResolver<H> for AddressCochainComplexResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_2_CHAIN_COMPLEX_TAG)?;
        emit_carrier(carrier.canonical, PSI_5_COCHAIN_COMPLEX_TAG, out)
    }
}

impl<H: Hasher> CohomologyGroupResolver<H> for AddressCohomologyGroupResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: CochainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_5_COCHAIN_COMPLEX_TAG)?;
        emit_carrier(carrier.canonical, PSI_6_COHOMOLOGY_GROUPS_TAG, out)
    }
}

impl<H: Hasher> PostnikovResolver<H> for AddressPostnikovResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_1_NERVE_TAG)?;
        emit_carrier(carrier.canonical, PSI_7_POSTNIKOV_TOWER_TAG, out)
    }
}

impl<H: Hasher> HomotopyGroupResolver<H> for AddressHomotopyGroupResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: PostnikovTowerBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_7_POSTNIKOV_TOWER_TAG)?;
        emit_carrier(carrier.canonical, PSI_8_HOMOTOPY_GROUPS_TAG, out)
    }
}

impl<H: Hasher> KInvariantResolver<H> for AddressKInvariantResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: HomotopyGroupsBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        if out.len() < WIRE_FORMAT_ADDRESS_BYTES {
            return Err(ADDR_OUTPUT_VIOLATION);
        }

        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_8_HOMOTOPY_GROUPS_TAG)?;

        // Dispatch canonicalization through the AddressInput trait —
        // the architectural commitment per ADR-046 and ARCHITECTURE.md.
        let mut canonical = alloc::vec![0u8; XML_VALUE_MAX_BYTES];
        let canonical_len =
            <XmlValue as AddressInput>::canonicalize_into(carrier.canonical, &mut canonical)?;

        let digest: [u8; 32] = H::initial()
            .fold_bytes(&canonical[..canonical_len])
            .finalize_to_32();

        out[..7].copy_from_slice(b"sha256:");
        for (i, byte) in digest.iter().enumerate() {
            out[7 + 2 * i] = HEX_LOWER[(byte >> 4) as usize];
            out[7 + 2 * i + 1] = HEX_LOWER[(byte & 0x0F) as usize];
        }

        Ok(WIRE_FORMAT_ADDRESS_BYTES)
    }
}

const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

trait FinalizeTo32 {
    fn finalize_to_32(self) -> [u8; 32];
}

impl<H: Hasher> FinalizeTo32 for H {
    #[inline]
    fn finalize_to_32(self) -> [u8; 32] {
        let buf = <H as Hasher>::finalize(self);
        let mut out = [0u8; 32];
        out.copy_from_slice(&buf[..32]);
        out
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

const _: () = {
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::NERVE_OUTPUT_BYTES_MAX);
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::CHAIN_COMPLEX_OUTPUT_BYTES_MAX);
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX);
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::COCHAIN_COMPLEX_OUTPUT_BYTES_MAX);
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX);
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::POSTNIKOV_TOWER_OUTPUT_BYTES_MAX);
    assert!(CARRIER_BYTES <= <XmlAddrBounds as HostBounds>::HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX);
    assert!(
        WIRE_FORMAT_ADDRESS_BYTES <= <XmlAddrBounds as HostBounds>::K_INVARIANTS_OUTPUT_BYTES_MAX
    );
};
