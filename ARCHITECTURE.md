# Architecture — `uor-addr-1`

> Normative architectural specification. The vocabulary defined here is
> referenced by [CONFORMANCE.md](CONFORMANCE.md), [VERIFICATION.md](VERIFICATION.md),
> and [ANALYSIS.md](ANALYSIS.md). Wiki ADRs cited below live at
> <https://github.com/UOR-Foundation/UOR-Framework/wiki>.

## 1. Position in the Prism stack

`uor-addr-1` is a Prism application of the UOR Foundation, declared as a
single `PrismModel<H, B, A, R, C>` over the **`uor-prism` standard
library façade** (wiki ADR-031) with the following substitution-axis
selections:

| Position             | Selection                                                                                                  |
|----------------------|------------------------------------------------------------------------------------------------------------|
| `HostTypes`          | `prism::vocabulary::DefaultHostTypes`                                                                      |
| `HostBounds`         | `AddrBounds` — 24 ADR-037 capacity ceilings + 6 typed-input bounds (`MAX_JSON_DEPTH` etc.)                |
| `AxisTuple + Hasher` | `prism::crypto::Sha256Hasher` — Prism-published HashAxis (re-exported from [`crate::shapes`])             |
| `ResolverTuple`      | `AddressResolverTuple<H>` — eight ψ-stage resolvers                                                        |
| `TypedCommitment`    | `prism::pipeline::EmptyCommitment` — wiki ADR-048; no auxiliary cost-model surface beyond the κ-derivation |

There is no second model, no auxiliary axis, no out-of-band side
channel. The crate is the model and nothing else.

The dependency posture follows ADR-031: `uor-prism` is the canonical
public surface, but `uor-foundation` and `uor-foundation-sdk` remain
direct dependencies because the SDK macros (`prism_model!`, `verb!`,
`resolver!`, `output_shape!`) expand to absolute `::uor_foundation::*`
paths. The verifier-side dev-dependency is `uor-prism-verify` — see §6
below.

## 2. The typed-iso surface

```text
JsonValue  (typed JSON value, structurally-tagged bytes, ≤ JSON_VALUE_MAX_BYTES)
   ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
   ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
   ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
   ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants — JCS+NFC canonicalisation + κ-derivation)
AddressLabel  (the κ-label, 71 ASCII bytes — `sha256:<64hex>`)
```

The verb body is exactly the wiki's **canonical k-invariants branch**
(ADR-035): the longest discriminating ψ-chain that reaches `KInvariants`
through `Nerve → PostnikovTower → HomotopyGroups`. Off-path resolver
positions (`ChainComplex`, `HomologyGroups`, `CochainComplex`,
`CohomologyGroups`) are populated for `ResolverTuple` completeness but
never appear in the verb's term arena.

The PrismModel's `Input` is [`crate::JsonValue`] — an RFC 8259 JSON
value of bounded depth and width, carried as a structurally-tagged
byte serialization (one tag byte per case + length-prefixed payloads).
The 1-byte tags distinguish the six JSON cases (null = `0x00`, false
= `0x01`, true = `0x02`, number = `0x03`, string = `0x04`, array =
`0x05`, object = `0x06`); recursive children live in the same flat
buffer. The host-boundary parser [`crate::JsonValue::parse`] performs
the only structural σ-projection — JSON tokenisation — and validates
every typed-input bound (depth, per-value width, container arity,
total serialised size) before construction; failure surfaces as a
[`prism::pipeline::ShapeViolation`] keyed to the violated bound's IRI.

Canonicalisation moves from the host boundary into the **typed-iso
surface**. ψ_9's `AddressKInvariantResolver` decodes the tagged
bytes, applies JCS-RFC8785 + Unicode NFC, and feeds the canonical
bytes to the canonical hash axis — all inside the resolver body per
ADR-046. The verb body composes only ψ-Term variants; no σ-residual
leaks into the verb arena (CS-V01 preserved).

## 3. Discipline-scope boundaries

Three orthogonal disciplines partition the implementation surface; each
admits a distinct class of operation and is enforced at a distinct layer.

### 3.1 Host-boundary transforms (pre-`Input`)

Lives at: `crates/uor-addr-1/src/value.rs`.

The host boundary performs exactly **one** σ-projection — JSON
tokenisation — and validates every typed-input bound before
construction. There is no second host-boundary path; in particular
the crate carries **no parallel canonicalisation implementation**
of its own.

- `JsonValue::parse(raw)` — the **only** host-boundary transform.
  Parses raw bytes as RFC 8259 JSON, validates every typed-input
  bound declared in [`crate::shapes::bounds`], and emits the
  structurally-tagged byte form the typed-iso surface carries.
  Failure surfaces as a `ShapeViolation` keyed to the violated
  bound's IRI.
- `value::canonicalize(raw)` — a convenience helper that internally
  routes through `JsonValue::parse` + the typed-iso canonicalizer
  and returns the JCS-RFC8785 + Unicode NFC canonical-form bytes.
  This is the same code path ψ_9 invokes — no second implementation
  is carried.

The SHA-256 implementation is **not** carried in this module: it lives
in `prism::crypto::Sha256Hasher` (re-exported via [`crate::shapes`])
and is invoked only inside the ψ_9 resolver body. Boundary code
performs no hashing.

The parser's output is a typed `JsonValue` — no canonicalisation has
happened yet; the byte form is the structurally-tagged
parse-tree-shaped serialisation. The typed-iso surface owns the
canonicalisation step.

### 3.2 Verb body — ψ-residuals discipline (ADR-035)

Lives at: `crates/uor-addr-1/src/verbs.rs`.

The verb body composes only ψ-Term variants. **Forbidden** in the verb
arena: `Term::AxisInvocation`, `Term::FirstAdmit`, and
`PrimitiveOp::{Le, Lt, Ge, Gt, Concat}`. Enforced by the
[CL-V01](CONFORMANCE.md#cl-formal-class--lean-mechanised-theorems) /
[CS-V01](CONFORMANCE.md#cs-structural-class--shape-and-typed-surface)
invariants.

### 3.3 Resolver bodies — iterative-resolution discipline (ADR-046)

Lives at: `crates/uor-addr-1/src/resolvers.rs`.

Resolver bodies **admit** σ-residuals; this is the wiki-sanctioned layer
where the canonical hash axis is consumed **and** where canonicalisation
runs. The terminal ψ_9 resolver `AddressKInvariantResolver::resolve`
performs two σ-residual-bearing steps per dispatch:

1. **Canonicalisation** — decode the carrier's structurally-tagged
   `JsonValue` bytes via [`crate::value::canonicalize_into`],
   producing JCS-RFC8785 + Unicode NFC canonical-form bytes. Object
   keys are re-ordered per JCS §3.2.3 (lexicographic by UTF-16 code
   unit); string values are NFC-normalised. The σ-residuals this
   step carries (key comparison, byte-level NFC) are admissible at
   the resolver layer per ADR-046; they are forbidden in the verb
   body per ADR-035.
2. **Hash-axis invocation** —
   `H::initial().fold_bytes(canonical).finalize()` produces the
   32-byte SHA-256 digest. Exactly one σ-projection of the hash axis
   per `forward()` — deterministic in the typed input, no
   enumeration.

The non-terminal resolvers (ψ_1 / ψ_7 / ψ_8 — on-path; ψ_2 / ψ_3 /
ψ_5 / ψ_6 — off-path for ResolverTuple completeness) thread the
typed `JsonValue` tagged bytes forward through the structural
ψ-functor each realises without modifying them.

## 4. Algebraic-closure encoding

`AddressLabel` is the ψ-pipeline label. Its `ConstrainedTypeShape` declares
71 disjoint `ConstraintRef::Site` instances — one per wire-format-address
byte position. The constraint nerve N(C) is 71 isolated vertices with no
higher simplices:

```
β_0 = 71,        β_k = 0 for k ≥ 1
χ(N(C)) = β_0 − β_1 + … = 71 = SITE_COUNT
```

This satisfies the wiki's canonical closure criterion (ADR-024 substrate
closure / ADR-026 prism closure) at the declaration level. The criterion
is asserted at **compile time** via a `const _: () = { … }` block in
`resolvers.rs`; the runtime resolver bodies emit carriers directly
without re-validating. The Lean theorem
`UorAddr1.AlgebraicClosure.euler_char_eq_site_count` mechanises the
arithmetic identity.

## 5. Seal regime

`AddressLabel` reaches the typed-iso surface only through
`AddressModel::forward` per constraint **TC-02** (no
`Grounded<AddressLabel>` construction outside the foundation pipeline).
The `AddressWitness` newtype carries the foundation-sealed
`Grounded<AddressLabel>` by borrow. Downstream consumers replay it
through `prism_verify::certify_from_trace` per **TC-05** to obtain a
`Certified<GroundingCertificate>` **without** re-invoking the canonical
hash axis on the original input — the verifier reads the
`ContentFingerprint` from the trace and re-packages it. The round-trip
is exercised by [CL-R01](CONFORMANCE.md#cl-r--replay-class--tc-05-round-trip-via-uor-prism-verify).

## 6. Verifier surface (TC-05, ADR-019 anamorphism)

The verifier-side dev-dependency `uor-prism-verify` exposes a single
function — `certify_from_trace<TR_MAX>(&Trace<TR_MAX>) ->
Result<Certified<GroundingCertificate>, ReplayError>` — and the
wire-format types (`Trace`, `TraceEvent`, `ContentFingerprint`,
`GroundingCertificate`, `Certified`). The full TC-05 round-trip used by
`tests/replay.rs` is:

```rust
let outcome  = uor_addr_1::address(input_bytes)?;     // mint
let grounded = outcome.witness.grounded();
let trace    = grounded.derivation().replay::<256>(); // anamorphism
let certified = prism_verify::certify_from_trace(&trace)?;
assert_eq!(certified.certificate().content_fingerprint(),
           grounded.content_fingerprint());           // QS-05 equivalence
```

QS-05 (replay equivalence — bit-identical certificate) is what the test
asserts. The verifier path makes **zero** calls into
`prism::crypto::Sha256Hasher` and observes neither the canonical-form
bytes nor the JCS+NFC transform — only the trace and the original
`ContentFingerprint` carried inside it.

## 7. The κ-derivation identity

ψ_9 is the load-bearing terminal stage. Given a typed `JsonValue`
whose structurally-tagged bytes are `t : [u8]`, its emitted 71-byte
κ-label is structurally determined by the composition:

```
canonical(t) = jcs_nfc_canonicalise(decode_tagged(t))
κ(t)         = b"sha256:" ‖ hex_lower(H::initial().fold_bytes(canonical(t)).finalize())
```

where `decode_tagged` reverses the structurally-tagged serialisation
to an RFC 8259 JSON value, `jcs_nfc_canonicalise` is the JCS-RFC8785
+ Unicode-NFC canonicalisation step (executed inside the resolver
body per ADR-046 — exposed publicly as
[`crate::canonicalize`] for callers that want the canonical bytes
outside the κ-derivation), `‖` is byte concatenation, and
`hex_lower` emits two lowercase ASCII hex digits per input byte. The Lean theorem
`UorAddr1.KappaDerivation.kappa_determined_by_digest` pins the
restricted identity at the type level (given a digest, the κ-label
is determined); `UorAddr1.AddressShape.address_label_width_is_seventy_one`
pins the 71-byte width; `UorAddr1.HexEncoding.encode_byte_injective`
proves no two distinct digests map to the same κ-label.

Two `JsonValue` inputs that decode to **canonicalisation-equivalent**
JSON values produce identical κ-labels (CT-E* tests pin this at the
sample). Two `JsonValue` inputs that decode to canonicalisation-distinct
JSON values — in particular, values whose typed cases differ even when
their textual rendering looks alike — produce distinct κ-labels with
the SHA-256 sensitivity bound (CT-T* tests).

## 8. What this crate deliberately is not

- **Not** a custom axis. The earlier framing of UOR-ADDR-1 as a
  `ContentAddressingAxis` violates ADR-035's ψ-residuals discipline —
  axis invocations belong inside resolver bodies per ADR-046, not in
  the typed-iso surface.
- **Not** an enumerator. There is no σ-enumeration anywhere. The
  ψ-pipeline maps typed canonical-form bytes to the κ-label by
  structural transformation in exactly one σ-projection.
- **Not** chain-coupled. The output is a chain-agnostic
  `sha256:<64hex>`; there is no chain-fork mediation, no consensus
  artefact, no block-header interaction.
- **Not** differential against a second implementation. The
  cross-validation fixtures harvested from
  `mcp.uor.foundation/tools/encode_address` (v0.2.1, algorithm
  `uor-sha256-v1`) are the byte-identity baseline; the V&V approach
  is spec-in-Lean + invariant-grep + parametric runtime tests +
  empirical analysis, **not** A/B comparison against a reference impl.

## 9. Outstanding reconciliation

The canonical-form bytes this crate hashes (plain UTF-8 JCS-RFC8785
JSON bytes) differ structurally from what `uor-foundation@0.4`'s
`Element::canonical_bytes` docstring specifies — Amendment 43 §2:
`header(k) ‖ le_bytes(x, k+1)`, the byte layout of a ring element in
R_n. Two parties speaking UOR-ADDR-1 (this crate) agree with each other;
a UOR-ADDR-1 party and a foundation-grounded party computing
`Element::digest` over the same JSON value disagree even when both name
`sha256` as the algorithm.

Closing that gap is an upstream wiki/foundation decision. This crate is
byte-identical to the reference and to itself across every input in its
domain; the reconciliation is orthogonal to the Prism grounding and is
tracked as [CN-RC01](CONFORMANCE.md#cn-network-class--cross-validation-against-reference).
