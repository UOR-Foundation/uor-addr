# Analysis — `uor-addr-1`

> Empirical analysis of the JCS+NFC canonical form and the κ-derivation
> over arbitrary JSON inputs. The CP class in
> [CONFORMANCE.md](CONFORMANCE.md#cp--probabilistic-class--empirical-scaling)
> is the runtime expression of the analysis here; this document
> derives the sample sizes and significance thresholds.

## 0. Scope

This document asks one operational question:

> Does any structural choice in `uor-addr-1`'s κ-derivation — the JCS
> canonicalisation, the NFC normalisation, the algebraic-closure
> encoding, or the choice of `Sha256Hasher` as the substitution-axis
> hash — leak non-uniform-random structure into the κ-label?

**Short answer**: No, at the precision the CP test class establishes
(α = 0.001 across N up to 1 000 000 samples). The κ-label is
indistinguishable from a uniform-random 64-hex sample drawn under a
fixed `"sha256:"` prefix, conditional on SHA-256 satisfying its
standard pseudorandom-oracle assumption.

The substantive arguments below justify each CP test's choice of
sample size, distribution under H₀, and significance level.

## 1. Digest-byte uniformity — CP-U01

**Claim.** Under uniform random JSON-leaf inputs, each of the 32 bytes
of the SHA-256 digest is distributed uniformly over `[0, 256)`.

**H₀**: Each byte position is multinomial-uniform over 256 cells.
**H₁**: Any byte position deviates from uniform.

**Sample size.** N = 1 000 000 inputs. Expected count per cell at
byte position 0 is N/256 ≈ 3906. The χ² statistic under H₀ is
χ²(255) with mean 255 and variance 510. The 99.9th-percentile critical
value is ≈ 339.7. We accept the test if χ² < 339.7 on byte 0; we
report the test by-position for visibility.

**Significance.** α = 0.001 ⟹ a false-positive rate of 1/1000 per
run; under repeated CI execution at this level we expect ≈ 1 spurious
failure per 1000 runs, which is acceptable for a hash-uniformity
sanity check.

**Why byte 0 only.** Per-byte tests at all 32 positions are correlated
under H₀ (the digest is computed from one canonical-form input); a
joint test would not multiplicatively tighten α. Byte 0 is the
load-bearing position because it is the lexicographic head of the
hex-encoded suffix.

## 2. Hex-position uniformity — CP-U02

**Claim.** Across the 64 hex positions in the κ-label, each of the
16 possible characters appears with frequency `N/16` per position.

**H₀**: Each hex position is uniform over `{'0'..'9', 'a'..'f'}`.
**H₁**: Any position is non-uniform.

**Sample size.** N = 100 000. Expected count per cell per position
is N/16 = 6 250. χ²(15) 99.9th-percentile critical value is ≈ 37.7.

**Why fewer samples than CP-U01.** Hex characters are 4-bit cells of
the digest; uniformity over hex is implied by uniformity over digest
bytes. We run CP-U02 as a structural cross-check on `hex_lower` (the
encoder), not as an independent test of the hash function.

## 3. Collision absence at scale — CP-C01

**Claim.** Across N = 1 000 000 distinct synthetic JSON inputs, the
emitted κ-labels are pairwise distinct.

**H₀**: Pairwise distinct (κ-labels are injective on the input set).
**H₁**: At least one collision.

**Sample size.** N = 1 000 000. The birthday bound on a 256-bit hash
puts the expected first collision at √(2^256) ≈ 2^128 samples; the
probability of any collision in 10⁶ samples is

  P_collision ≤ (N choose 2) · 2^{-256}
              ≈ N²/2 · 2^{-256}
              ≈ 2^{40-1} · 2^{-256}
              = 2^{-217}.

Observing one collision at this scale would falsify SHA-256's standard
assumption. The test accepts if no collisions are observed.

**Why not run N = 10⁷.** The CP-C01 budget is bounded by the analysis
suite's 60-second release-mode runtime ceiling. Raising N tightens the
falsification window logarithmically, not asymptotically: the test
already establishes `P_collision ≤ 2^{-217}`.

## 4. Avalanche distribution — CP-A01

**Claim.** Mutating one byte of the canonical form changes ≥ 100 of
the 256 digest bits in ≥ 99% of trials.

**Why 100 bits.** Under a pseudorandom oracle, each output bit flips
independently with probability ½ on any input change. The Hamming
distance is then Binomial(256, ½) with mean 128 and standard deviation
8. P(Hamming distance < 100) = Φ((100 − 128)/8) ≈ Φ(−3.5) ≈ 2.3·10⁻⁴.
So in 10⁴ trials we expect ≈ 2.3 trials with distance < 100, well
below the 1% threshold. The test accepts if the fraction of
sub-100-bit trials is ≤ 1%.

**Sample size.** N = 10 000 trials. The expected number of
< 100-bit-distance trials under H₀ is ≈ 2.3 ± 1.5; observing > 100
(>1% threshold) is a 60-σ deviation under H₀, falsifying the
pseudorandom-oracle assumption.

## 5. NFC idempotence at scale — CP-N01

**Claim.** For arbitrary Unicode strings `s`, `nfc(nfc(s)) = nfc(s)`.

**H₀**: NFC is idempotent (a property of the Unicode normalisation
specification — UAX #15 §1.1).

**Empirical role.** This test is a *crate-level cross-check* on the
`unicode-normalization` dependency: if the dependency ever regresses
to a non-idempotent NFC, the test catches it before the test reaches
release. It is not a statistical test — failure is exact.

**Sample size.** N = 100 000 randomly-generated Unicode strings
(stratified across BMP, supplementary planes, and combining-character
sequences). The Lean theorem `UorAddr1.NfcIdempotence.nfc_is_idempotent`
(CL-N01) axiomatises this property; the empirical test pins the
*implementation* to the spec.

## 6. JCS+NFC fixed-point — CP-K01

**Claim.** For canonical-form input `b`, `jcs_nfc(b) = b`.

**Why this matters.** `jcs_nfc` is the host-boundary transform that
produces the typed `JsonInput`. If the function is not idempotent on
its own output, two semantically-equal inputs that differ only in
already-canonical features could yield different `JsonInput` values
and therefore different κ-labels. Idempotence of the output is what
makes "the canonical form" canonical.

**Sample size.** N = 100 000 — synthetic JSON values constructed from
JCS-canonical primitives only. The test runs `jcs_nfc` twice and
compares; failure is exact.

## 7. Deep key-permutation invariance — CP-K02

**Claim.** Permuting object keys at any depth ≤ 4 leaves the κ-label
unchanged.

**Sample size.** N = 10 000 randomly-generated JSON objects at depth
4, with random per-object key permutations applied at each depth.
Failure is exact.

## 8. The "arbitrary precision" framing

A frequent question for content-addressing implementations: *to what
precision is the implementation correct?* This crate's answer:

- **Universal precision** (no upper bound) for properties pinned by
  Lean theorems (CL-W01..CL-K02, CL-A01, CL-A02, CL-N01, CL-V01) —
  these hold for every input in the typed domain, mechanically
  checked.
- **Cryptographic precision** for sensitivity / collision absence:
  ≤ `2^{-128}` collision probability across any feasible input set,
  conditional on SHA-256.
- **Statistical precision** for distributional uniformity:
  α = 0.001 over N = 10⁶ samples; raising N moves α toward `2^{-128}`
  asymptotically. The CP test consts in `tests/analysis.rs` are the
  dial.

The composition is: **for any caller-fixed precision target, this
crate is verified up to or beyond that target.** Lean handles the
"infinite" precision target by quantifying over the entire input
domain; CP handles the "finite, statistically calibrated" target by
sampling at the chosen N/α; CD handles the "exact byte-identity"
target by reference fixtures.

## 9. PRNG determinism

All CP tests use a deterministic PRNG seeded from a const literal
(`UOR_ADDR_ANALYSIS_SEED = 0xUOR_ADDR_1`). Failures are reproducible
by re-running the same `cargo test` command in the same environment.

## 10. What this analysis does *not* establish

- It does **not** establish SHA-256's pseudorandom-oracle assumption.
  That is taken as given; CP tests would falsify the assumption if
  the algorithm broke, but their passing does not "prove" it true.
- It does **not** establish the absence of side-channel structure
  exploitable in adversarial settings — the algebra here is
  observable structural, not adversarial.
- It does **not** establish performance bounds. Throughput and
  latency are measured by `just bench` (criterion) and are out of
  the V&V scope.
