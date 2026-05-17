# Conformance Contract — `uor-addr-1`

> Normative conformance contract. Each invariant has a stable ID
> (e.g. `CS-V01`) referenced by tests, code comments, and PR
> descriptions. Adding, retiring, or renumbering an ID is a contract
> change. See [ARCHITECTURE.md](ARCHITECTURE.md) for the architectural
> vocabulary and [VERIFICATION.md](VERIFICATION.md) for the
> reproducible acceptance gate.

## The contract — what `uor-addr-1` claims

For every well-formed JSON byte sequence `b` of length ≤ 3968 bytes
after JCS+NFC canonicalisation:

1. **Address determinism (CD-D01).** `address(b)` produces exactly one
   ASCII byte sequence — the κ-label — and the same `b` always produces
   the same κ-label.
2. **κ-derivation identity (CL-K01).** The κ-label is byte-equal to
   `b"sha256:" ‖ hex_lower(SHA-256(jcs_nfc_canonicalise(b)))`, computed by exactly
   **one** σ-projection of the canonical hash axis inside the ψ_9
   resolver — never inside the verb body.
3. **Algebraic-closure shape (CL-A01).** The output shape
   `AddressLabel` carries 71 disjoint `Site` constraints whose Euler
   characteristic is `χ(N(C)) = 71 = SITE_COUNT`. The closure-rank
   residual is 0; the ψ-pipeline converges in `n − χ(N(C)) = 0` residual
   stages.
4. **Invariance under canonicalisation (CD-I01).** Inputs that
   differ only in (i) JSON key ordering, (ii) JSON whitespace, or
   (iii) Unicode normalisation form (NFC vs NFD vs NFKC vs NFKD)
   yield the same κ-label.
5. **Sensitivity (CD-S01).** Distinct canonical-form byte sequences
   yield distinct κ-labels with probability ≥ `1 − 2^{-128}` over any
   fixed N ≤ `2^64` collision-resistance window (the SHA-256 security
   assumption).
6. **Wire-format width (CL-W01).** The κ-label is exactly 71 bytes,
   begins with the 7-byte ASCII prefix `"sha256:"`, and continues with
   64 ASCII bytes drawn from `{'0'..'9', 'a'..'f'}`.
7. **TC-05 replay round-trip (CL-R01).** Every `Grounded<AddressLabel>`
   the pipeline emits is replayable through `prism_verify::certify_from_trace`
   into a `Certified<GroundingCertificate>` carrying the **same**
   `ContentFingerprint` (QS-05 — bit-identical round-trip), without the
   verifier re-invoking the canonical hash axis.
8. **Typed-input case distinction (CT-T*).** Different JSON cases —
   `null`, `false`, `true`, number, string, array, object — produce
   structurally-distinct `JsonValue` instances and therefore distinct
   κ-labels, even when the input texts look similar (`42` ≠ `"42"`,
   `null` ≠ `false`).
9. **Typed-input bound enforcement (CT-B*).** Any input that violates a
   typed-input bound declared in `crate::shapes::bounds`
   (`MAX_JSON_DEPTH`, `MAX_STRING_BYTES`, `MAX_NUMBER_DIGITS`,
   `MAX_OBJECT_KEYS`, `MAX_ARRAY_ELEMENTS`, `JSON_VALUE_MAX_BYTES`)
   is rejected at `JsonValue::parse` with a `ShapeViolation` keyed to
   the violated bound's IRI; the constructor never silently truncates.
10. **Cost-model selection (CT-C01).** The PrismModel's 5th parameter
    `C` is explicitly bound to `prism::pipeline::EmptyCommitment`
    (wiki ADR-048). UOR-ADDR-1 carries no auxiliary cost surface.

## Conformance classes

Each class fixes an enforcement mechanism. Invariant IDs use the
two-letter class prefix.

### CS — Structural class — shape and typed surface

Verified by **source-grep + compile-time invariants + unit tests** under
`crates/uor-addr-1/src/`. CI fails if any structural claim drifts.

| ID       | Invariant                                                                                 | Pinned by                                                                                       |
|----------|-------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| CS-T01   | `AddressLabel::SITE_COUNT = 71`                                                          | `model::tests::address_label_site_count_matches_wire_format_width`                              |
| CS-T02   | `AddressLabel::CONSTRAINTS` is exactly 71 disjoint `ConstraintRef::Site` instances        | `model::tests::address_label_carries_seventy_one_disjoint_site_constraints` + `const _` in `resolvers.rs` |
| CS-T03   | `AddressLabel::CONSTRAINTS[i]` pins position `i` for `i ∈ [0, 71)`                        | `model::tests::address_label_constraints_pin_every_wire_format_site` + `const _` in `resolvers.rs` |
| CS-B01   | `AddrBounds::NERVE_SITES_MAX = 71`, `FINGERPRINT_*_BYTES = 32`, `WITT_LEVEL_MAX_BITS = 32`| `shapes::bounds::tests::bounds_constants_match_addr_label_width`                                |
| CS-B02   | All 8 per-ψ-stage `*_OUTPUT_BYTES_MAX` ceilings equal `TERM_VALUE_MAX_BYTES = 4096`       | `shapes::bounds::tests::psi_stage_output_ceilings_uniform`                                      |
| CS-V01   | The verb arena contains no `Term::FirstAdmit` / `Term::AxisInvocation` / `Le`/`Lt`/`Ge`/`Gt`/`Concat` | `verbs::tests::verb_arena_contains_no_sigma_residuals`                              |
| CS-V02   | The verb arena contains each of ψ_1, ψ_7, ψ_8, ψ_9                                       | `verbs::tests::verb_arena_contains_psi_{1,7,8,9}_*`                                             |
| CS-S01   | `unsafe` blocks: zero                                                                     | `#![forbid(unsafe_code)]` at lib root + `tests::conformance::no_unsafe_anywhere`                |
| CS-S02   | `unwrap()` / `expect()` in non-test code paths: zero in `src/{verbs,resolvers,pipeline}.rs` | `tests::conformance::no_panic_paths_in_pipeline`                                              |

### CD — Deterministic class — per-input byte identity

Verified by **runtime tests over a fixed fixture set** under
`crates/uor-addr-1/tests/byte_identity.rs` and
`crates/uor-addr-1/tests/conformance.rs`. The fixture baseline is the
12 cases harvested from `mcp.uor.foundation/tools/encode_address`
(mcp-uor-server v0.2.1, algorithm `uor-sha256-v1`).

| ID       | Invariant                                                                                 | Pinned by                                                                  |
|----------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| CD-D01   | `address(b)` is a pure function: idempotent across N repeated calls                       | `tests::conformance::address_is_pure_function`                             |
| CD-D02   | The 12 reference fixtures reproduce byte-for-byte                                         | `tests::byte_identity::shim_layer_reproduces_harvested_fixtures`           |
| CD-D03   | `canonicalize(raw)` (the in-surface canonicalizer) reproduces the reference canonical-form bytes for each fixture | `tests::byte_identity::canonicalize_kernel_matches_expected_canonical_form`|
| CD-I01a  | Key-order invariance: `{"a":1,"b":2}` ≡ `{"b":2,"a":1}` under `address`                  | `tests::byte_identity::pipeline_key_order_invariant`                       |
| CD-I01b  | Whitespace invariance: `{"foo": "bar"}` ≡ `{"foo":"bar"}` under `address`                | `tests::conformance::whitespace_invariance`                                |
| CD-I01c  | NFC invariance: composed `caf\u{E9}` ≡ decomposed `cafe\u{301}` under `address`          | `tests::byte_identity::pipeline_nfc_invariant`                             |
| CD-I01d  | NFKC equivalence: full-width digits ≡ ASCII digits under `address` (NFKC compatibility)   | `tests::conformance::nfkc_compatibility_class_holds` (informational)       |
| CD-S01a  | Single-byte mutation changes the κ-label                                                  | `tests::byte_identity::pipeline_distinct_inputs_yield_distinct_addresses`  |
| CD-S01b  | Avalanche: mutating one byte of the canonical form changes ≥ 100 of the 256 digest bits   | `tests::conformance::single_byte_avalanche_balanced`                       |
| CD-W01   | Every emitted κ-label is 71 ASCII bytes, begins `"sha256:"`, hex is lowercase             | `tests::byte_identity::pipeline_address_is_seventy_one_ascii_bytes`        |
| CD-G01   | `AddressOutcome::witness.grounded().output_bytes()` matches `outcome.address.as_bytes()`  | `tests::byte_identity::pipeline_witness_borrows_grounded`                  |

### CP — Probabilistic class — empirical scaling

Verified by **parametric large-sample runtime tests** in release mode
under `crates/uor-addr-1/tests/analysis.rs`. Failures are statistical;
each test names its sample size, significance level, and reference
distribution. See [ANALYSIS.md](ANALYSIS.md) for derivations.

| ID       | Invariant                                                                                                              | Pinned by                                                              | N (samples) | α       |
|----------|------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|-------------|---------|
| CP-U01   | Digest byte 0 is uniform across `[0, 256)` under uniform JSON-leaf inputs                                              | `tests::analysis::digest_byte_uniformity_chi_squared`                  | 1 000 000   | 0.001   |
| CP-U02   | Digest hex character class `[0-9a-f]` is uniform across the 64 hex positions of the κ-label                            | `tests::analysis::hex_position_uniformity_chi_squared`                 | 100 000     | 0.001   |
| CP-C01   | Pairwise κ-label collisions are absent across N distinct synthetic JSON inputs (birthday bound ≪ `2^{-100}` at N=1e6) | `tests::analysis::no_collisions_at_scale`                              | 1 000 000   | n/a     |
| CP-A01   | Single-byte-mutation Hamming distance to baseline ≥ 100 bits for ≥ 99% of trials                                       | `tests::analysis::avalanche_distance_distribution`                     | 10 000      | 0.001   |
| CP-N01   | NFC round-trip stability: `nfc(nfc(s)) = nfc(s)` for arbitrary Unicode-string JSON leaf inputs                          | `tests::analysis::nfc_idempotent_at_scale`                             | 100 000     | exact   |
| CP-K01   | JCS+NFC canonical form has fixed point: `canonicalize(canonicalize(b)) = canonicalize(b)` for already-canonical inputs | `tests::analysis::cp_k01__canonicalize_idempotent_at_scale`            | 100 000     | exact   |
| CP-K02   | Permuting object keys at depth ≤ 4 leaves the κ-label unchanged                                                        | `tests::analysis::deep_key_permutation_invariance`                     | 10 000      | exact   |

### CT — Typed-input class — `JsonValue` shape claims

Verified by **runtime parser + pipeline tests** at
`crates/uor-addr-1/tests/typed_input.rs`. The typed `JsonValue` input
shape lets us distinguish JSON cases structurally (not just by
canonical-form serialisation), reject violators of any typed-input
bound at construction, and collapse structural-equivalence classes
to one κ-label.

| ID       | Invariant                                                                                          | Pinned by                                                              |
|----------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| CT-T01   | `42` and `"42"` produce distinct κ-labels (integer ≠ string of same digits)                       | `tests::typed_input::ct_t01__integer_distinct_from_string_of_same_digits` |
| CT-T02   | `null` and `false` produce distinct κ-labels                                                      | `tests::typed_input::ct_t02__null_distinct_from_false`                 |
| CT-T03   | `true`, `false`, `null` are pairwise distinct                                                     | `tests::typed_input::ct_t03__three_scalars_pairwise_distinct`          |
| CT-T04   | `{}` and `[]` produce distinct κ-labels                                                           | `tests::typed_input::ct_t04__empty_object_distinct_from_empty_array`   |
| CT-T05   | `[1,2,3]` (numbers) and `["1","2","3"]` (strings) produce distinct κ-labels                       | `tests::typed_input::ct_t05__number_array_distinct_from_string_array`  |
| CT-E01   | Key-order invariance (structural equivalence; restatement of CD-I01a at the typed-input layer)    | `tests::typed_input::ct_e01__key_ordering_invariance`                  |
| CT-E02   | Whitespace invariance (structural equivalence; restatement of CD-I01b)                            | `tests::typed_input::ct_e02__whitespace_invariance`                    |
| CT-E03   | NFC invariance (composed `caf\u{E9}` ≡ decomposed `cafe\u{301}`; restatement of CD-I01c)         | `tests::typed_input::ct_e03__nfc_invariance`                           |
| CT-E04   | Nested key-order invariance through depth 3                                                       | `tests::typed_input::ct_e04__nested_key_ordering_invariance`           |
| CT-B01   | Over-deep nesting (> `MAX_JSON_DEPTH`) is rejected at parse with `TooLarge`                       | `tests::typed_input::ct_b01__over_deep_nesting_rejected_at_parse`      |
| CT-B02   | Over-wide string (> `MAX_STRING_BYTES`) is rejected at parse with `TooLarge`                      | `tests::typed_input::ct_b02__over_wide_string_rejected_at_parse`       |
| CT-B03   | Exactly-at-bound depth is accepted (the bound is `≤`, not `<`)                                    | `tests::typed_input::ct_b03__exactly_at_depth_bound_accepted`          |
| CT-B04   | Invalid JSON syntax is rejected with `InvalidJson` (distinct from typed-input size violations)    | `tests::typed_input::ct_b04__invalid_json_rejected_distinct_from_size_bound` |
| CT-C01   | The PrismModel's `TypedCommitment` is `EmptyCommitment` (wiki ADR-048; no auxiliary cost surface) | `tests::typed_input::ct_c01__cost_model_is_empty_commitment`           |
| CT-P01   | `JsonValue::parse` returns Ok with non-empty tagged bytes for a valid input                       | `tests::typed_input::ct_p01__parse_returns_tagged_bytes`               |
| CT-P02   | `JsonValue::parse` rejects invalid JSON with the `validUtf8Json` violation IRI                    | `tests::typed_input::ct_p02__parse_rejects_invalid_json`               |

### CN — Network class — cross-validation against reference

Verified by **live HTTP calls to `mcp.uor.foundation`** at
`crates/uor-addr-1/tests/cross_validation.rs`. Gated behind `#[ignore]`;
runs only under `just cn` (CI optional).

| ID       | Invariant                                                                                  | Pinned by                                          |
|----------|--------------------------------------------------------------------------------------------|----------------------------------------------------|
| CN-RC01  | This crate's κ-label matches `mcp.uor.foundation/tools/encode_address` for the 12 fixtures | `tests::cross_validation::live_fixture_agreement` |
| CN-RC02  | This crate's κ-label matches the reference for 100 freshly-generated random JSON values     | `tests::cross_validation::live_random_agreement`  |

### CL — Formal class — Lean mechanised theorems

Verified by **`lake build`** under `uor-addr-1-lean/`. Theorems pin
universally quantified claims that no finite sample suite can establish
on its own. The Lean library depends only on the
[UOR-Framework Lean library](https://github.com/UOR-Foundation/UOR-Framework)
(no Mathlib).

| ID       | Theorem name                                                                       | File                                          | Statement                                                       |
|----------|------------------------------------------------------------------------------------|-----------------------------------------------|-----------------------------------------------------------------|
| CL-W01   | `UorAddr1.AddressShape.address_label_width_is_seventy_one`                         | `UorAddr1/AddressShape.lean`                  | `kappaLabel.size = 71` for every digest input                   |
| CL-W02   | `UorAddr1.AddressShape.address_prefix_is_sha256_colon`                             | `UorAddr1/AddressShape.lean`                  | `kappaLabel[0..7] = "sha256:".toUInt8Array`                     |
| CL-W03   | `UorAddr1.AddressShape.address_hex_digits_are_lowercase`                           | `UorAddr1/AddressShape.lean`                  | `∀ i ∈ [7, 71), kappaLabel[i] ∈ {'0'..'9', 'a'..'f'}`           |
| CL-H01   | `UorAddr1.HexEncoding.hex_lower_injective`                                         | `UorAddr1/HexEncoding.lean`                   | `hexLower` is injective on `[0, 16)`                            |
| CL-H02   | `UorAddr1.HexEncoding.hex_byte_pair_roundtrip`                                     | `UorAddr1/HexEncoding.lean`                   | `decodeNibble (hexLower n) = n` for `n < 16`                    |
| CL-K01   | `UorAddr1.KappaDerivation.kappa_determined_by_digest`                              | `UorAddr1/KappaDerivation.lean`               | Equal digests ⟹ equal κ-labels                                 |
| CL-K02   | `UorAddr1.KappaDerivation.distinct_digests_yield_distinct_labels`                  | `UorAddr1/KappaDerivation.lean`               | Unequal digests ⟹ unequal κ-labels (hex injectivity lifted)    |
| CL-A01   | `UorAddr1.AlgebraicClosure.euler_char_eq_site_count`                               | `UorAddr1/AlgebraicClosure.lean`              | `β_0 − β_1 + … = 71`                                            |
| CL-A02   | `UorAddr1.AlgebraicClosure.free_rank_residual_zero`                                | `UorAddr1/AlgebraicClosure.lean`              | After ψ_9 the FreeRank residual is 0                            |
| CL-N01   | `UorAddr1.NfcIdempotence.nfc_is_idempotent`                                        | `UorAddr1/NfcIdempotence.lean`                | `nfc (nfc s) = nfc s` (axiomatised — Unicode-spec lemma)        |
| CL-V01   | `UorAddr1.VerbDiscipline.verb_arena_psi_residuals_only`                            | `UorAddr1/VerbDiscipline.lean`                | The verb's term-arena coproduct contains only ψ-Term variants   |
| CL-CT01  | `UorAddr1.TypedInput.case_tags_are_pairwise_distinct`                              | `UorAddr1/TypedInput.lean`                    | Different JSON cases carry pairwise-distinct structural tag bytes |
| CL-CT02  | `UorAddr1.TypedInput.depth_bound_is_strict`                                        | `UorAddr1/TypedInput.lean`                    | Admissibility iff `depth ≤ MAX_JSON_DEPTH` (at-bound accepted; over-bound rejected) |
| CL-CT03  | `UorAddr1.TypedInput.empty_commitment_is_the_cost_surface`                         | `UorAddr1/TypedInput.lean`                    | The PrismModel's `C` is bound to `EmptyCommitment` (ADR-048)    |

### CL-R — Replay class — TC-05 round-trip via `uor-prism-verify`

Verified by **runtime round-trip tests** at
`crates/uor-addr-1/tests/replay.rs` exercising the wiki TC-05
commitment: every `Grounded<AddressLabel>` the address pipeline emits
can be replayed by a downstream verifier through
`prism_verify::certify_from_trace` to produce a
`Certified<GroundingCertificate>` **without** re-invoking the canonical
hash axis on the original input. The replayed certificate's
`ContentFingerprint` is bit-identical to the source (QS-05 replay
equivalence). See [ARCHITECTURE.md §6](ARCHITECTURE.md#6-verifier-surface-tc-05-adr-019-anamorphism)
for the architectural framing.

| ID       | Invariant                                                                                  | Pinned by                                                       |
|----------|--------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| CL-R00   | `prism_verify::certify_from_trace(Trace::empty())` returns `ReplayError::EmptyTrace`       | `tests::replay::cl_r00__verifier_facade_is_wired`               |
| CL-R01   | Single-input round-trip: replayed `ContentFingerprint` equals source                       | `tests::replay::cl_r01__grounded_address_label_round_trips_through_verifier` |
| CL-R02   | All 12 reference fixtures round-trip: replayed `ContentFingerprint` equals source per input | `tests::replay::cl_r02__every_reference_fixture_round_trips`    |

## Contract evolution

- **Adding an ID.** Append; do not renumber. The PR description must
  cite the new ID and either a Lean theorem, a test path, or both.
- **Retiring an ID.** Mark `(retired @ vX.Y)` inline; do not delete.
  Tests pinning a retired ID may move to `#[ignore]` with a comment.
- **Tightening or loosening N/α.** Treat as a contract change: the PR
  must justify the new bound and update `tests/analysis.rs` consts.
- **All conformance changes pass through [VERIFICATION.md](VERIFICATION.md)
  §1's `just vv` gate.**
