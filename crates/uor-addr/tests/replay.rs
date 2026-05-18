//! CL-R — TC-05 replay round-trip via `uor-prism-verify`.
//!
//! Demonstrates the wiki TC-05 commitment: every `Grounded<AddressLabel>`
//! the address pipeline emits can be replayed by a downstream verifier
//! through `prism_verify::certify_from_trace` to produce a
//! `Certified<GroundingCertificate>`, **without** re-invoking the
//! canonical hash axis on the original input. The verifier reads the
//! `ContentFingerprint` from the `Trace` data and re-packages it; no
//! `Sha256Hasher::fold_bytes` call is made on the verifier side.
//!
//! This is the load-bearing demonstration of the discipline-scope
//! separation between minting (which requires the substrate hasher)
//! and verification (which requires only the trace + the wire-format
//! certificate types).
//!
//! See [CONFORMANCE.md §CL](../../../CONFORMANCE.md#cl--formal-class--lean-mechanised-theorems)
//! and [ARCHITECTURE.md §5](../../../ARCHITECTURE.md#5-seal-regime).

#![allow(non_snake_case)]

use prism_verify::{certify_from_trace, ReplayError, Trace};
use uor_addr::address;

/// CL-R00 — façade wiring is correct: an empty `Trace` is rejected by
/// `certify_from_trace` with `ReplayError::EmptyTrace`. Mirrors the
/// minimal `prism_verify` rustdoc-pinned behaviour and confirms the
/// dev-dep is reachable and the four re-exports (`certify_from_trace`,
/// `Trace`, `ReplayError`, and implicitly `Certified`) compose.
#[test]
fn cl_r00__verifier_facade_is_wired() {
    let trace: Trace = Trace::empty();
    assert!(matches!(
        certify_from_trace(&trace),
        Err(ReplayError::EmptyTrace)
    ));
}

/// CL-R01 — round-trip: take the `Grounded<AddressLabel>` an
/// `address(b)` invocation produced, ask its `derivation()` to
/// `replay()` itself into a `Trace<256>`, and feed that `Trace` to
/// `certify_from_trace`. The re-derived `Certified<GroundingCertificate>`
/// must carry the **same** `ContentFingerprint` the original
/// `Grounded<AddressLabel>` reported (QS-05 replay equivalence —
/// bit-identical round-trip).
#[test]
fn cl_r01__grounded_address_label_round_trips_through_verifier() {
    // Mint: forward the canonical address pipeline end-to-end.
    let outcome = address(br#"{"foo":"bar"}"#).expect("valid JSON");
    let grounded = outcome.witness.grounded();
    let original_fingerprint = grounded.content_fingerprint();

    // Replay: convert the substrate-private `Grounded` into the wire
    // format the verifier consumes (a `Trace`).
    let trace: Trace<256> = grounded.derivation().replay();

    // Verify: re-derive a `Certified<GroundingCertificate>` without
    // invoking the canonical hash axis.
    let certified = certify_from_trace(&trace).expect("trace must verify");
    let recert_fingerprint = certified.certificate().content_fingerprint();

    assert_eq!(
        recert_fingerprint, original_fingerprint,
        "CL-R01: replayed certificate must carry the source fingerprint \
         (QS-05 replay equivalence). Got {recert_fingerprint:?} vs \
         {original_fingerprint:?}"
    );
}

/// CL-R02 — every reference fixture's `Grounded<AddressLabel>` replays
/// through the verifier and reproduces the source `ContentFingerprint`.
/// Establishes that round-trip equivalence holds across the entire
/// byte-identity baseline, not just one input.
#[test]
fn cl_r02__every_reference_fixture_round_trips() {
    let fixtures: &[&[u8]] = &[
        br#"{"foo": "bar"}"#,
        b"{}",
        b"[]",
        br#"{"b": 1, "a": 2}"#,
        "{\"name\": \"Müller\"}".as_bytes(),
        "{\"city\": \"São Paulo\"}".as_bytes(),
        "{\"name\": \"caf\u{00E9}\"}".as_bytes(),
        "{\"name\": \"cafe\u{0301}\"}".as_bytes(),
        br#"{"int": 42, "bool": true, "null_val": null}"#,
        br#"{"nested": {"deep": {"value": "found"}}}"#,
        br#"["a", "b", "c"]"#,
        br#"[1, 2, 3]"#,
    ];
    for raw in fixtures {
        let outcome = address(raw).expect("valid fixture");
        let grounded = outcome.witness.grounded();
        let trace: Trace<256> = grounded.derivation().replay();
        let certified = certify_from_trace(&trace).expect("trace must verify");
        assert_eq!(
            certified.certificate().content_fingerprint(),
            grounded.content_fingerprint(),
            "CL-R02: round-trip fingerprint mismatch for {:?}",
            std::str::from_utf8(raw).unwrap_or("(non-utf8)")
        );
    }
}
