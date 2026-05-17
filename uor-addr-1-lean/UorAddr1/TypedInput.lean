import UOR.Enforcement

/-!
# Typed JSON-Value Input — type-distinction and depth bound

The `JsonValue` typed input shape is a coproduct over the six RFC 8259
JSON cases (object, array, string, number, boolean, null). Each
construction goes through `JsonValue::parse` which validates depth and
width bounds before any ψ-pipeline dispatch.

This file pins three universally-quantified statements about the
typed-input surface:

- `CT-T` — different JSON cases produce structurally-distinct inputs.
  In particular, scalar types (integer vs string, null vs false) carry
  distinct tag bytes in the structurally-tagged serialization the
  parser emits, so the κ-derivation distinguishes them by typing
  alone, not just by canonical-form serialization.
- `CT-B` — the parse-time depth bound is a *hard* bound: any input of
  depth > `MAX_JSON_DEPTH` is rejected; any input of depth
  ≤ `MAX_JSON_DEPTH` is accepted (subject to width bounds).
- `CT-C` — the cost-model commitment is `EmptyCommitment` per
  ADR-048's default; no auxiliary cost surface is in scope.

Pinned conformance IDs:
- `CL-CT01` — `case_tags_are_pairwise_distinct`
- `CL-CT02` — `depth_bound_is_strict`
- `CL-CT03` — `empty_commitment_is_the_cost_surface`
-/

namespace UorAddr1.TypedInput

/-- The six JSON cases, as the typed coproduct represents them. -/
inductive JsonCase
  | null
  | falseLit
  | trueLit
  | number
  | string
  | array
  | object
  deriving DecidableEq, Repr

/-- The 1-byte tag stamped into the structurally-tagged
serialization. Mirrors the Rust constants in `value.rs`. -/
def caseTag : JsonCase → UInt8
  | .null     => 0x00
  | .falseLit => 0x01
  | .trueLit  => 0x02
  | .number   => 0x03
  | .string   => 0x04
  | .array    => 0x05
  | .object   => 0x06

/-- CL-CT01 — different JSON cases carry pairwise-distinct tag
bytes. Decidable across the 7 × 7 case table. -/
theorem case_tags_are_pairwise_distinct
    (a b : JsonCase) (h : a ≠ b) : caseTag a ≠ caseTag b := by
  cases a <;> cases b <;> simp_all [caseTag]

/-- The seven case tags are exactly `{0x00, 0x01, …, 0x06}`. -/
theorem case_tag_range :
    ∀ c : JsonCase, caseTag c ≤ 0x06 := by
  intro c
  cases c <;> decide

/-- The depth bound from `crate::shapes::bounds::MAX_JSON_DEPTH`.
Mirrored at the Lean level as a const so the universal statement
references the same value the runtime parser enforces. -/
def maxJsonDepth : Nat := 32

/-- CL-CT02 — the depth-bound check is a strict ≤ comparison. A JSON
value of depth `d` is admissible iff `d ≤ maxJsonDepth`. -/
def depthAdmissible (d : Nat) : Bool := d ≤ maxJsonDepth

theorem depth_bound_is_strict (d : Nat) :
    depthAdmissible d = true ↔ d ≤ maxJsonDepth := by
  unfold depthAdmissible
  exact decide_eq_true_iff

/-- Exactly-at-bound depth is admissible. -/
theorem at_bound_depth_admissible :
    depthAdmissible maxJsonDepth = true := by
  decide

/-- Over-bound depth is inadmissible. -/
theorem over_bound_depth_inadmissible :
    depthAdmissible (maxJsonDepth + 1) = false := by
  decide

/-- The cost-model commitment selected by `AddressModel` — wiki
ADR-048. UOR-ADDR-1 carries no auxiliary cost surface beyond the
κ-derivation; the model's 5th parameter `C` is bound to the closed
canonical no-op `EmptyCommitment`. We tag the selection with a
type-level marker so the Lean statement is decidable. -/
inductive CostCommitment
  | empty
  | singleton
  | conjunction
  deriving DecidableEq, Repr

/-- The selected commitment. -/
def selectedCommitment : CostCommitment := .empty

/-- CL-CT03 — the cost-model commitment is `EmptyCommitment`. -/
theorem empty_commitment_is_the_cost_surface :
    selectedCommitment = .empty := rfl

end UorAddr1.TypedInput
