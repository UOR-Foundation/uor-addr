# Verification & Validation — `uor-addr-1`

> V&V index. This document maps the conformance contract
> ([CONFORMANCE.md](CONFORMANCE.md)) onto a single reproducible
> acceptance gate: `just vv`. Each axis below names what is checked,
> how to reproduce it locally, and which conformance class IDs are
> satisfied by passing it.

## 1. The acceptance gate — `just vv`

`just vv` is the normative acceptance gate. PRs that fail any axis are
not mergeable. It runs the following in sequence, halting on the first
failure:

| #  | Axis                              | Command                                                | Classes covered           |
|----|-----------------------------------|--------------------------------------------------------|---------------------------|
| 1  | Format                            | `just fmt-check`                                       | (hygiene)                 |
| 2  | Lint (`-D warnings`)              | `just lint`                                            | (hygiene)                 |
| 3  | Workspace unit + integration tests| `just test`                                            | CS-*, CD-*, CT-*, CL-R-*  |
| 4  | Conformance suite (release)       | `just conformance`                                     | CD-*, CS-S01, CS-S02      |
| 5  | Analysis suite (release)          | `just analysis`                                        | CP-*                      |
| 6  | Replay round-trip (release)       | `just replay`                                          | CL-R-*                    |
| 7  | Runnable use-case examples        | `just examples`                                        | CT-T*, CT-E*, CL-R*       |
| 8  | Rustdoc (broken-intra-doc-links)  | `just doc-check`                                       | (hygiene)                 |
| 9  | Lean proofs                       | `just verify`                                          | CL-W,H,K,A,N,V,CT (formal)|
| 10 | Optional: live cross-validation   | `just cn` (skipped if `UOR_ADDR_LIVE` is unset)        | CN-*                      |

Total wall-clock budget on a 4-core dev machine: ≈ 4 minutes (axes 1–9).
Axis 5 runs at sample sizes pinned in [CONFORMANCE.md §CP](CONFORMANCE.md#cp--probabilistic-class--empirical-scaling)
(up to 1 000 000 samples) — the release profile keeps it under 60 s in
practice. Axis 6 (replay) runs in milliseconds; it exercises the TC-05
round-trip through `prism_verify::certify_from_trace` for one input
plus the 12-fixture baseline.

## 2. The V&V axes — what each one proves

### 2.1 Architecture (axes 1, 2, 8)

Format, lint, and rustdoc cross-link checks. `clippy --all-targets -- -D warnings`
denies all warnings, so any drift in idiom or doc cross-references fails
the gate. The rustdoc step uses
`RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links"` to catch the most
common doc-rot.

### 2.2 Typed-surface invariants (axis 3)

`cargo test --workspace` runs the 27 lib unit tests and the integration
suites — `byte_identity.rs` (8), `conformance.rs` (14), `typed_input.rs`
(16), `analysis.rs` (8), `replay.rs` (3). This axis pins:

- The ψ-residuals discipline (`CS-V01`, `CS-V02`) — the verb's term
  arena contains exactly the ψ_1/ψ_7/ψ_8/ψ_9 variants and no
  σ-residual primitive ops.
- The algebraic-closure shape (`CS-T01`–`CS-T03`, `CS-B01`–`CS-B02`) —
  71 disjoint Site constraints with the right capacity ceilings.
- Byte identity against the 12 reference fixtures (`CD-D02`, `CD-D03`).
- The pipeline invariants (`CD-D01`, `CD-I01a–d`, `CD-S01a`, `CD-W01`,
  `CD-G01`).
- Typed-input case distinction, structural equivalence, and bound
  enforcement (`CT-T01`–`CT-T05`, `CT-E01`–`CT-E04`, `CT-B01`–`CT-B04`,
  `CT-C01`, `CT-P01`–`CT-P02`).
- TC-05 replay round-trip (`CL-R00`–`CL-R02`).

If `cargo test` passes, the typed-iso surface is structurally correct
for every input in the fixture set.

### 2.3 Conformance — runtime invariant suite (axis 4)

`just conformance` runs `cargo test -p uor-addr-1 --release --test conformance`.
This axis re-runs the byte-identity fixtures at release-mode speed (so
parametric extensions are tractable) and adds the source-grep
invariants (`CS-S01`, `CS-S02`, plus the source-greps for `verbs.rs`
that confirm the verb body matches `ARCHITECTURE.md` §3.2 verbatim).
Tests in this suite are named `<id>__<short_description>` so failures
trace back to a CONFORMANCE.md row by ID.

### 2.4 Analysis — empirical scaling (axis 5)

`just analysis` runs `cargo test -p uor-addr-1 --release --test analysis`
covering the CP class. See [ANALYSIS.md](ANALYSIS.md) for the
mathematical statement, derivation of the sample sizes, and the
significance level for each test. The tests use a deterministic PRNG
seed so failures are reproducible.

### 2.5 Use-case examples — executable conformance demos (axis 7)

`just examples` runs the four `cargo run --example` invocations
under `crates/uor-addr-1/examples/`. Each example panics on a failed
invariant, so passing the axis is a structural requirement — the
examples function as runnable conformance demos for the use cases
in [README.md §Use-case examples](README.md#use-case-examples).
The four examples cover content-address minting (CT-T*), structural
equivalence (CT-E*), typed distinction (CT-T*), and TC-05 replay
round-trip (CL-R*).

### 2.6 Lean proofs — universally quantified guarantees (axis 9)

`just verify` runs `cd uor-addr-1-lean && lake build`. The Lean library
imports `UOR.Prelude` from the
[UOR-Framework](https://github.com/UOR-Foundation/UOR-Framework) at
revision `main`. Theorems are listed in
[CONFORMANCE.md §CL](CONFORMANCE.md#cl--formal-class--lean-mechanised-theorems).
Two flagship theorems:

- **`UorAddr1.KappaDerivation.kappa_determined_by_digest`**: the
  κ-label is a *function* of the digest — universally quantified
  over all 32-byte digest values. This pins
  [CD-D01](CONFORMANCE.md#cd--deterministic-class--per-input-byte-identity)
  to *every* possible canonical-form byte sequence, not just the
  empirical sample.
- **`UorAddr1.AlgebraicClosure.euler_char_eq_site_count`**: the
  Euler-characteristic identity is mechanically verified — not just
  asserted at compile time via the `const _: () = { … }` block in
  `resolvers.rs`.

Lean theorems extend the conformance guarantee from "true at the
sample" to "true for all valid inputs" (universal quantification
over the typed-input domain).

### 2.7 Cross-validation — network axis (axis 10)

`just cn` is gated behind `UOR_ADDR_LIVE=1`. It runs the
`crates/uor-addr-1/tests/cross_validation.rs` integration tests, which
issue HTTP requests to `mcp.uor.foundation/tools/encode_address` and
compare the κ-labels byte-for-byte. CI does not require this axis (the
reference may be down) but the gate is provided so external operators
can re-establish CN-RC01/CN-RC02 confidence on demand.

## 3. Precision policy

`uor-addr-1` is verified to be valid for **arbitrary use cases to
arbitrary precision** in three converging senses:

1. **Universal quantification** (axis 9, Lean). The κ-derivation
   identity and algebraic-closure encoding are proved for *every*
   well-formed input by mechanically checked theorems — not by
   sampling. The Lean axis is the ceiling of precision: the property
   holds without bound on input domain or precision threshold.

2. **Cryptographic precision** (axis 4 + axis 5, sensitivity tests).
   CD-S01 and CP-A01 establish that distinct canonical-form bytes
   yield distinct κ-labels with collision probability ≤ `2^{-128}`
   across any feasible-N input set — i.e. SHA-256's full standard
   security margin. Tighter precision requires a different HashAxis
   selection from `prism::crypto` (e.g. `Sha512Hasher`,
   `Sha3_256Hasher`, or `Blake3Hasher`); each is a separate
   PrismModel declaration with its own κ-label width and a separate
   conformance contract.

3. **Empirical precision** (axis 5). The CP class establishes
   distributional uniformity of digest bytes at α = 0.001 over
   N = 10⁶ samples. Larger N tightens the achievable α toward
   `2^{-128}` asymptotically; the CP test consts in
   `tests/analysis.rs` are the dial. Sample sizes can be raised
   without a contract change provided the test still passes.

The composition of (1) and (2) is the operative answer to "is this
implementation correct for an arbitrary downstream use case at any
precision the downstream cares about?" — yes, up to the security of
SHA-256 itself, and universally quantified by the Lean axis.

## 4. Reproducing locally

```bash
# Full gate (≈ 4 min)
just vv

# Individual axes
just fmt-check
just lint
just test
just conformance
just replay
just analysis
just examples
just doc-check
just verify
UOR_ADDR_LIVE=1 just cn   # optional, requires network
```

The Lean step requires `lake` (provided by `elan`) and pins
`leanprover/lean4:v4.16.0` via `uor-addr-1-lean/lean-toolchain`. The
devcontainer at [.devcontainer/devcontainer.json](.devcontainer/devcontainer.json)
ships `elan` and `just`; running `just verify` once will install the
pinned toolchain on first use.

## 5. CI coverage

Mirror `just vv` in CI. The recommended pipeline:

| Job          | Command            | Required for merge?            |
|--------------|--------------------|--------------------------------|
| lint+test    | `just ci`          | yes                            |
| conformance  | `just conformance` | yes                            |
| analysis     | `just analysis`    | yes (release-mode, ≤ 60 s)     |
| replay       | `just replay`      | yes (TC-05 round-trip)         |
| examples     | `just examples`    | yes (runnable use-case demos)  |
| doc-check    | `just doc-check`   | yes                            |
| verify       | `just verify`      | yes (Lean build is hermetic)   |
| cn           | `just cn`          | no (live external dep)         |

If any required job fails, the contract has drifted. The PR must either
update [CONFORMANCE.md](CONFORMANCE.md) (declaring an explicit contract
change) or fix the code.
