//! `uor-addr`'s `ResolverTuple` — the eight ψ-stage substitution-axis
//! realizations for the JSON content-address typed feature hierarchy
//! (wiki ADR-036).
//!
//! Each resolver realizes its named mathematical role over the typed
//! feature hierarchy's structural geometry. The ψ-chain is a
//! deterministic, parametric, structure-preserving transformation;
//! each stage's emitted bytes describe its mathematical content for
//! the constraint geometry declared on `AddressLabel`.
//!
//! ## The constraint geometry
//!
//! `AddressLabel::CONSTRAINTS` declares 71 disjoint
//! `ConstraintRef::Site` instances — one per wire-format-label byte
//! (wiki ADR-024 / ADR-026 algebraic closure). For this geometry,
//! the ψ-chain's stage outputs are fully determined:
//!
//! | ψ-stage | Mathematical content |
//! |---|---|
//! | ψ_1 Nerve N(C)            | 71 isolated vertices, no higher simplices |
//! | ψ_2 ChainComplex C_•      | C_0 = ℤ^71, C_k = 0 for k ≥ 1; all ∂ = 0 |
//! | ψ_3 HomologyGroups H_k    | H_0 = ℤ^71, H_k = 0 for k ≥ 1 |
//! | ψ_5 CochainComplex C^•    | C^0 = ℤ^71, C^k = 0 for k ≥ 1; all δ = 0 |
//! | ψ_6 CohomologyGroups H^k  | H^0 = ℤ^71, H^k = 0 for k ≥ 1 |
//! | ψ_7 PostnikovTower P_n    | P_n = the discrete 71-set for all n ≥ 0 |
//! | ψ_8 HomotopyGroups π_k    | π_0 = the 71-element set, π_k = 0 for k ≥ 1 |
//! | ψ_9 KInvariants κ_n       | trivial signature + the wire-format κ-label |
//!
//! ## Carrier layout
//!
//! Each non-terminal ψ-stage emits a structural carrier:
//!
//! ```text
//! [0..4)               u32 BE: canonical_len (length of canonical JSON bytes; ≤ 4092)
//! [4..4+canonical_len) canonical-form JCS+NFC JSON bytes (threaded forward)
//! [carrier_max - 95..carrier_max - 87)  u64 BE: ψ-stage tag
//! [carrier_max - 87..carrier_max - 83)  u32 BE: vertex_count = 71
//! [carrier_max - 83..carrier_max - 79)  u32 BE: highest_nontrivial_dim = 0
//! [carrier_max - 79..carrier_max - 75)  u32 BE: reserved = 0
//! [carrier_max - 75..carrier_max - 4)   71 × u8: per-vertex Site positions
//! ```
//!
//! Carriers are fixed-width 4096 bytes (= `AddrBounds::TERM_VALUE_MAX_BYTES`)
//! so the catamorphism's per-fold-rule scratch buffer suffices. The
//! variable-length canonical-form prefix lives at the front; the
//! constant-geometry tail at the back.
//!
//! ## ψ_9 KInvariant — the terminal label
//!
//! ψ_9 consumes the ψ_8 HomotopyGroups carrier and emits exactly 71
//! bytes — the wire-format `sha256:<64hex>`. The k-invariant signature
//! itself is trivial for π_0-only spaces (no obstruction classes), so
//! the structural content reduces to π_0's 71 generators. ψ_9's
//! load-bearing computation is the **structural κ-derivation**: the
//! typed canonical-form JSON bytes project via the canonical hash axis
//! to a 32-byte content-address; the 7-byte ASCII prefix `"sha256:"`
//! plus the 64 lowercase-hex digits of the digest pin all 71 sites
//! simultaneously. One σ-projection per `forward()` — deterministic
//! in the typed input, no enumeration, no search.
//!
//! ## Pure-prism commitment — wiki ADR-035 + ADR-046
//!
//! The verb body composes only ψ-Term variants (`Term::Nerve /
//! PostnikovTower / HomotopyGroups / KInvariants`) per ADR-035's
//! ψ-residuals discipline. Resolver bodies admit σ-residuals per
//! ADR-046's resolver-body iterative-resolution discipline — that is
//! the wiki-sanctioned layer where the canonical hash axis is
//! consumed (see [`AddressKInvariantResolver`] below). The non-
//! terminal resolvers do not enumerate; they thread the canonical-
//! form bytes forward through the structural ψ-functor each realises.
//! From outside, `forward()` is one structural inference per
//! `JsonValue` — the ψ-pipeline maps typed `JsonValue` tagged bytes to
//! the κ-label by structural transformation, never by search.

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
use crate::json::shapes::bounds::{AddrBounds, JSON_VALUE_MAX_BYTES};
use crate::json::value::JsonValue;
use crate::label::{AddressLabel, ADDRESS_LABEL_BYTES};

// ─── Carrier layout constants ──────────────────────────────────────────

/// Wire-format `sha256:<64hex>` byte width — the ψ_9 output width.
const WIRE_FORMAT_ADDRESS_BYTES: usize = ADDRESS_LABEL_BYTES;

/// Maximum canonical-form JSON byte width carried in a ψ-stage carrier.
/// Bounded by `JSON_VALUE_MAX_BYTES` minus the 4-byte length prefix and
/// the geometry-tail header reserved at the back.
const CARRIER_BYTES: usize = <AddrBounds as HostBounds>::TERM_VALUE_MAX_BYTES;

/// Nerve-vertex count — matches `AddressLabel::SITE_COUNT`.
const NERVE_VERTEX_COUNT: u32 = 71;
/// Highest-nontrivial-dim for the discrete 71-vertex space.
const NERVE_HIGHEST_DIM: u32 = 0;

/// Geometry-tail layout at the back of every non-terminal carrier:
/// `stage_tag(8) ‖ vertex_count(4) ‖ highest_dim(4) ‖ reserved(4) ‖
///  vertex_positions(71)` = 91 bytes total.
const GEOMETRY_TAIL_BYTES: usize = 8 + 4 + 4 + 4 + NERVE_VERTEX_COUNT as usize;

/// Length prefix at the front: 4-byte u32 BE.
const LENGTH_PREFIX_BYTES: usize = 4;

/// Maximum canonical-form payload width that fits in the carrier.
/// Used by the compile-time invariant below.
#[allow(dead_code)]
const CARRIER_PAYLOAD_MAX: usize = CARRIER_BYTES - LENGTH_PREFIX_BYTES - GEOMETRY_TAIL_BYTES;

/// Compile-time invariant: the typed `JsonValue` cap must fit within
/// the carrier-payload region.
const _: () = {
    assert!(
        JSON_VALUE_MAX_BYTES <= CARRIER_PAYLOAD_MAX,
        "JSON_VALUE_MAX_BYTES must fit within CARRIER_BYTES - LENGTH_PREFIX_BYTES - GEOMETRY_TAIL_BYTES"
    );
};

/// Offset of the geometry tail's start within a carrier.
const OFFSET_GEOMETRY_TAIL: usize = CARRIER_BYTES - GEOMETRY_TAIL_BYTES;
/// Offset of the stage_tag within the geometry tail.
const OFFSET_STAGE_TAG: usize = OFFSET_GEOMETRY_TAIL;
/// Offset of the vertex_count within the geometry tail.
const OFFSET_VERTEX_COUNT: usize = OFFSET_STAGE_TAG + 8;
/// Offset of the highest_dim within the geometry tail.
const OFFSET_HIGHEST_DIM: usize = OFFSET_VERTEX_COUNT + 4;
/// Offset of the reserved word within the geometry tail.
const OFFSET_RESERVED: usize = OFFSET_HIGHEST_DIM + 4;
/// Offset of the per-vertex Site positions within the geometry tail.
#[allow(dead_code)]
const OFFSET_VERTEX_POSITIONS: usize = OFFSET_RESERVED + 4;

// ─── ψ-stage tags ──────────────────────────────────────────────────────

const PSI_1_NERVE_TAG: u64 = 1;
const PSI_2_CHAIN_COMPLEX_TAG: u64 = 2;
const PSI_3_HOMOLOGY_GROUPS_TAG: u64 = 3;
const PSI_5_COCHAIN_COMPLEX_TAG: u64 = 5;
const PSI_6_COHOMOLOGY_GROUPS_TAG: u64 = 6;
const PSI_7_POSTNIKOV_TOWER_TAG: u64 = 7;
const PSI_8_HOMOTOPY_GROUPS_TAG: u64 = 8;

// ─── ShapeViolation IRIs ───────────────────────────────────────────────

const INPUT_LEN_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/resolver/JsonValueBytes",
    constraint_iri: "https://uor.foundation/addr/resolver/JsonValueBytes/maxBytes",
    property_iri: "https://uor.foundation/addr/resolver/JsonValueBytes/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: JSON_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

const CARRIER_INPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/resolver/CarrierInput",
    constraint_iri: "https://uor.foundation/addr/resolver/CarrierInput/expectedCarrierBytes",
    property_iri: "https://uor.foundation/addr/resolver/CarrierInput/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: CARRIER_BYTES as u32,
    max_count: CARRIER_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

const CARRIER_BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/resolver/CarrierBuffer",
    constraint_iri: "https://uor.foundation/addr/resolver/CarrierBuffer/minBytes",
    property_iri: "https://uor.foundation/addr/resolver/CarrierBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: CARRIER_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

const ADDR_OUTPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/resolver/AddressLabelBuffer",
    constraint_iri: "https://uor.foundation/addr/resolver/AddressLabelBuffer/minBytes",
    property_iri: "https://uor.foundation/addr/resolver/AddressLabelBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: WIRE_FORMAT_ADDRESS_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

const UPSTREAM_TAG_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/resolver/UpstreamStageTag",
    constraint_iri: "https://uor.foundation/addr/resolver/UpstreamStageTag/expectedTag",
    property_iri: "https://uor.foundation/addr/resolver/UpstreamStageTag/stageTag",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedLong",
    min_count: 1,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const GEOMETRY_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/resolver/CarrierGeometry",
    constraint_iri:
        "https://uor.foundation/addr/resolver/CarrierGeometry/seventyOneVerticesDiscrete",
    property_iri: "https://uor.foundation/addr/resolver/CarrierGeometry/vertexCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: NERVE_VERTEX_COUNT,
    max_count: NERVE_VERTEX_COUNT,
    kind: ViolationKind::ValueCheck,
};

// ─── Compile-time validation of AddressLabel::CONSTRAINTS ──────────────

// The 71-disjoint-Site algebraic-closure shape is a compile-time
// invariant of `AddressLabel`. Any malformed CONSTRAINTS declaration
// fails the build before reaching ψ_1.
const _: () = {
    let cs = <AddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
    assert!(
        cs.len() == NERVE_VERTEX_COUNT as usize,
        "AddressLabel::CONSTRAINTS must declare exactly 71 Site instances (algebraic-closure)"
    );
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            ConstraintRef::Site { position } => {
                assert!(
                    position as usize == i,
                    "AddressLabel::CONSTRAINTS: Site_i must pin position i for i ∈ [0, 71)"
                );
            }
            _ => panic!("AddressLabel::CONSTRAINTS may only contain ConstraintRef::Site instances"),
        }
        i += 1;
    }
};

// ─── Const geometry-tail template ──────────────────────────────────────

/// The constant geometry-tail bytes minus the stage_tag (which varies
/// per stage). Layout within the slice:
/// `vertex_count(4) ‖ highest_dim(4) ‖ reserved(4) ‖ vertex_positions(71)`
/// = 83 bytes. Lifted to a `const` so emitting a carrier is bit-copy.
const GEOMETRY_TAIL_AFTER_STAGE_TAG: [u8; GEOMETRY_TAIL_BYTES - 8] = {
    let mut t = [0u8; GEOMETRY_TAIL_BYTES - 8];
    let vc = NERVE_VERTEX_COUNT.to_be_bytes();
    t[0] = vc[0];
    t[1] = vc[1];
    t[2] = vc[2];
    t[3] = vc[3];
    // highest_dim @ [4..8) and reserved @ [8..12) are zero-init.
    let mut i = 0;
    while i < NERVE_VERTEX_COUNT as usize {
        t[12 + i] = i as u8;
        i += 1;
    }
    t
};

// ─── Carrier encode/decode ─────────────────────────────────────────────

/// Decoded view of a structural ψ-stage carrier.
struct DecodedCarrier<'a> {
    /// Canonical-form JCS+NFC JSON bytes (length carried in
    /// `canonical_len`; live within `[LENGTH_PREFIX_BYTES,
    /// LENGTH_PREFIX_BYTES + canonical_len)` of the original buffer).
    canonical: &'a [u8],
    /// Upstream ψ-stage tag.
    stage_tag: u64,
    /// Nerve vertex count — invariant 71.
    vertex_count: u32,
    /// Highest nontrivial dimension — invariant 0.
    highest_dim: u32,
}

#[inline]
fn decode_carrier(bytes: &[u8]) -> Result<DecodedCarrier<'_>, ShapeViolation> {
    if bytes.len() != CARRIER_BYTES {
        return Err(CARRIER_INPUT_VIOLATION);
    }
    let canonical_len =
        u32::from_be_bytes(bytes[..LENGTH_PREFIX_BYTES].try_into().unwrap_or([0; 4])) as usize;
    if canonical_len > JSON_VALUE_MAX_BYTES {
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

/// Validate the upstream carrier: stage tag matches what this
/// downstream ψ-functor expects; structural geometry is the
/// 71-isolated-vertices algebraic-closure shape `AddressLabel::CONSTRAINTS`
/// declares.
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

/// Emit a structural carrier with the given stage tag. The canonical-
/// form JSON bytes preserve the typed `JsonValue` data; the geometry
/// data (vertex_count = 71, highest_dim = 0, positions = [0..71))
/// lives in [`GEOMETRY_TAIL_AFTER_STAGE_TAG`] as a compile-time
/// constant and is bit-copied into the carrier as-is.
#[inline]
fn emit_carrier(canonical: &[u8], stage_tag: u64, out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if out.len() < CARRIER_BYTES {
        return Err(CARRIER_BUFFER_VIOLATION);
    }
    if canonical.len() > JSON_VALUE_MAX_BYTES {
        return Err(INPUT_LEN_VIOLATION);
    }

    // Length prefix.
    let len_bytes = (canonical.len() as u32).to_be_bytes();
    out[..LENGTH_PREFIX_BYTES].copy_from_slice(&len_bytes);
    // Canonical-form bytes.
    out[LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + canonical.len()].copy_from_slice(canonical);
    // Zero-pad between canonical region and geometry tail.
    let zero_start = LENGTH_PREFIX_BYTES + canonical.len();
    out[zero_start..OFFSET_GEOMETRY_TAIL].fill(0);
    // Stage tag (8 bytes, big-endian).
    out[OFFSET_STAGE_TAG..OFFSET_VERTEX_COUNT].copy_from_slice(&stage_tag.to_be_bytes());
    // Geometry tail (vertex_count, highest_dim, reserved, vertex_positions).
    out[OFFSET_VERTEX_COUNT..].copy_from_slice(&GEOMETRY_TAIL_AFTER_STAGE_TAG);

    Ok(CARRIER_BYTES)
}

// ─── ψ_1 Nerve — Constraints → SimplicialComplex ───────────────────────

/// ψ_1 `Nerve` resolver — `Constraints → SimplicialComplex`.
///
/// Builds N(C) for `AddressLabel::CONSTRAINTS`. For uor-addr's 71
/// disjoint `ConstraintRef::Site` declarations, N(C) is 71 isolated
/// vertices with no higher simplices.
#[derive(Debug)]
pub struct AddressNerveResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed for AddressNerveResolver<H> {}

impl<H: Hasher> NerveResolver<H> for AddressNerveResolver<H> {
    #[inline]
    fn resolve(&self, input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if input.len() > JSON_VALUE_MAX_BYTES {
            return Err(INPUT_LEN_VIOLATION);
        }
        emit_carrier(input, PSI_1_NERVE_TAG, out)
    }
}

// ─── ψ_2 ChainComplex — SimplicialComplex → ChainComplex ───────────────

/// ψ_2 `ChainComplex` resolver — `SimplicialComplex → ChainComplex`.
/// Off-path on the address-derivation transform.
#[derive(Debug)]
pub struct AddressChainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressChainComplexResolver<H>
{
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

// ─── ψ_3 HomologyGroups — ChainComplex → HomologyGroups ────────────────

/// ψ_3 `HomologyGroups` resolver. Off-path.
#[derive(Debug)]
pub struct AddressHomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressHomologyGroupResolver<H>
{
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

// ─── ψ_5 CochainComplex — ChainComplex → CochainComplex ────────────────

/// ψ_5 `CochainComplex` resolver. Off-path.
#[derive(Debug)]
pub struct AddressCochainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressCochainComplexResolver<H>
{
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

// ─── ψ_6 CohomologyGroups — CochainComplex → CohomologyGroups ──────────

/// ψ_6 `CohomologyGroups` resolver. Off-path.
#[derive(Debug)]
pub struct AddressCohomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressCohomologyGroupResolver<H>
{
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

// ─── ψ_7 PostnikovTower — SimplicialComplex → PostnikovTower ───────────

/// ψ_7 `PostnikovTower` resolver. On the address-derivation transform
/// (ψ_1 → ψ_7 → ψ_8 → ψ_9).
#[derive(Debug)]
pub struct AddressPostnikovResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressPostnikovResolver<H>
{
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

// ─── ψ_8 HomotopyGroups — PostnikovTower → HomotopyGroups ──────────────

/// ψ_8 `HomotopyGroups` resolver. On the address-derivation transform.
#[derive(Debug)]
pub struct AddressHomotopyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressHomotopyGroupResolver<H>
{
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

// ─── ψ_9 KInvariants — the terminal label ──────────────────────────────

/// ψ_9 `KInvariant` resolver — the terminal ψ-stage that materialises
/// the 71-byte wire-format content address.
///
/// **The κ-derivation, in two stages per ADR-046's resolver-body
/// iterative-resolution discipline.**
///
/// 1. **Canonicalisation** — decode the carrier's structurally-tagged
///    `JsonValue` bytes (see [`crate::json::value`] for the layout grammar)
///    via `value::canonicalize_into`, emitting JCS-RFC8785 + Unicode
///    NFC canonical-form bytes **inside the typed-iso surface**. This
///    is the σ-projection ADR-035 forbids in the verb body but
///    ADR-046 explicitly admits in resolver bodies. Object keys are
///    re-ordered per JCS §3.2.3; string values are NFC-normalised.
///
/// 2. **Hash-axis invocation** — project the canonical bytes through
///    the canonical hash axis (`H: Hasher` — the substitution-axis
///    selection per ADR-030):
///
///    ```text
///    digest = H::initial().fold_bytes(canonical_bytes).finalize()
///    label  = b"sha256:" ‖ hex_lower(digest)
///    ```
///
/// One σ-projection of the hash axis total per `forward()` —
/// deterministic in the typed input, no enumeration. The wiki's
/// iterative-resolution discipline converges here: all 71 free sites
/// pin simultaneously to the κ-derivation; `FreeRank` over
/// `AddressLabel` drops from 71 to 0 in this single terminal stage.
///
/// This is the ONE place in the crate where the canonical hash axis is
/// consumed. The verb body's term composition never invokes the axis
/// (no `Term::AxisInvocation`); the axis flows as a type parameter
/// only, reaching the resolver body through the model's substrate-axis
/// selection (`Sha256Hasher` per [`crate::json::pipeline::address`]).
#[derive(Debug)]
pub struct AddressKInvariantResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for AddressKInvariantResolver<H>
{
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

        // Stage 1 — dispatch canonicalization through the
        // [`AddressInput`] trait. For the JSON realization,
        // `V = JsonValue` is implicit; the trait method emits
        // JCS-RFC8785 + Unicode-NFC canonical bytes from the typed
        // input's parser-emitted byte sequence. ADR-046 admits the
        // σ-residuals this step needs (object-key comparison,
        // byte-level NFC normalisation of strings) inside the
        // resolver body; ADR-035 continues to forbid them in the
        // verb body. Per the architecture, format-specific
        // realizations parameterize the resolver over `V: AddressInput`
        // and dispatch through `V::canonicalize_into`; the
        // first-published realization fixes `V = JsonValue` to keep
        // the resolver-tuple shape concrete for the SDK macros.
        let mut canonical = [0u8; JSON_VALUE_MAX_BYTES];
        let canonical_len =
            <JsonValue as AddressInput>::canonicalize_into(carrier.canonical, &mut canonical)?;

        // Stage 2 — structural κ-derivation: project the canonical-form
        // bytes via the canonical hash axis to a 32-byte digest. One
        // σ-projection of the hash axis — no enumeration.
        let digest: [u8; 32] = H::initial()
            .fold_bytes(&canonical[..canonical_len])
            .finalize_to_32();

        // Emit `"sha256:"` (7 bytes) + 64-lowercase-hex digest = 71 bytes.
        out[..7].copy_from_slice(b"sha256:");
        for (i, byte) in digest.iter().enumerate() {
            out[7 + 2 * i] = HEX_LOWER[(byte >> 4) as usize];
            out[7 + 2 * i + 1] = HEX_LOWER[(byte & 0x0F) as usize];
        }

        Ok(WIRE_FORMAT_ADDRESS_BYTES)
    }
}

const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

/// Extension trait to take a `Hasher::finalize()` output of arbitrary
/// `FP_MAX` and view its first 32 bytes (the SHA-256 active width per
/// `Sha256Hasher::OUTPUT_BYTES = 32`). Foundation's `Hasher::finalize`
/// returns `[u8; FP_MAX]` for the const-generic `FP_MAX`; this helper
/// names the W32 slot the κ-derivation reads.
trait FinalizeTo32 {
    fn finalize_to_32(self) -> [u8; 32];
}

impl<H: Hasher> FinalizeTo32 for H {
    #[inline]
    fn finalize_to_32(self) -> [u8; 32] {
        let buf = <H as Hasher>::finalize(self);
        let mut out = [0u8; 32];
        // The active width is `H::OUTPUT_BYTES` (= 32 for Sha256Hasher);
        // foundation guarantees bytes [OUTPUT_BYTES..FP_MAX] are zero,
        // so this is a straight copy of the first 32 bytes.
        out.copy_from_slice(&buf[..32]);
        out
    }
}

// ─── Default impls + ResolverTuple ─────────────────────────────────────

macro_rules! impl_default_for_resolver {
    ($resolver:ident) => {
        impl<H: Hasher> Default for $resolver<H> {
            #[inline]
            fn default() -> Self {
                Self(PhantomData)
            }
        }
    };
}

impl_default_for_resolver!(AddressNerveResolver);
impl_default_for_resolver!(AddressChainComplexResolver);
impl_default_for_resolver!(AddressHomologyGroupResolver);
impl_default_for_resolver!(AddressCochainComplexResolver);
impl_default_for_resolver!(AddressCohomologyGroupResolver);
impl_default_for_resolver!(AddressPostnikovResolver);
impl_default_for_resolver!(AddressHomotopyGroupResolver);
impl_default_for_resolver!(AddressKInvariantResolver);

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

// ─── Compile-time invariants ───────────────────────────────────────────

const _: () = {
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::NERVE_OUTPUT_BYTES_MAX,
        "ψ_1 carrier exceeds NERVE_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::CHAIN_COMPLEX_OUTPUT_BYTES_MAX,
        "ψ_2 carrier exceeds CHAIN_COMPLEX_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
        "ψ_3 carrier exceeds HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::COCHAIN_COMPLEX_OUTPUT_BYTES_MAX,
        "ψ_5 carrier exceeds COCHAIN_COMPLEX_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
        "ψ_6 carrier exceeds COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::POSTNIKOV_TOWER_OUTPUT_BYTES_MAX,
        "ψ_7 carrier exceeds POSTNIKOV_TOWER_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <AddrBounds as HostBounds>::HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX,
        "ψ_8 carrier exceeds HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX"
    );
    assert!(
        WIRE_FORMAT_ADDRESS_BYTES <= <AddrBounds as HostBounds>::K_INVARIANTS_OUTPUT_BYTES_MAX,
        "ψ_9 label exceeds K_INVARIANTS_OUTPUT_BYTES_MAX"
    );
};
