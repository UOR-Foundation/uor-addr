//! 04 — TC-05 replay verification (anamorphism).
//!
//! The mint path runs the full ψ-pipeline and the SHA-256 axis. The
//! verify path runs neither — it consumes a `Trace` (the canonical
//! wire form of the ψ-pipeline's execution record) and replays it
//! through `prism_verify::certify_from_trace`, re-deriving a
//! `Certified<GroundingCertificate>` whose `ContentFingerprint` is
//! bit-identical to what the mint path produced.
//!
//! This is the wiki TC-05 round-trip a third-party verifier exercises
//! without re-invoking the canonical hash axis on the original input.
//!
//! Demonstrates conformance contract `CL-R01` / `CL-R02`.
//!
//! Run:
//!
//! ```bash
//! cargo run -p uor-addr --example replay_verification
//! ```

use prism_verify::{certify_from_trace, Trace};
use uor_addr::address;

fn main() {
    let payload =
        br#"{"agent":"researcher","output":{"timestamp":1700000000,"summary":"signal detected"}}"#;
    println!("uor-addr — TC-05 replay round-trip\n");
    println!("  payload:  {}\n", std::str::from_utf8(payload).unwrap());

    // ─── Mint path ────────────────────────────────────────────────
    let outcome = address(payload).expect("valid JSON within bounds");
    let grounded = outcome.witness.grounded();
    let mint_fingerprint = grounded.content_fingerprint();
    println!("  mint:     address = {}", outcome.address);
    println!("            content_fingerprint = {mint_fingerprint:?}\n");

    // ─── Wire form ────────────────────────────────────────────────
    // The grounded value's `derivation().replay()` returns a `Trace`
    // — the canonical record a verifier consumes off the wire.
    let trace: Trace<256> = grounded.derivation().replay();
    println!(
        "  wire:     trace carries {} event(s) + the source fingerprint\n",
        trace.len()
    );

    // ─── Verify path ─────────────────────────────────────────────
    // `certify_from_trace` re-derives the `Certified<GroundingCertificate>`
    // **without** invoking the canonical hash axis. The bit-identical
    // round-trip is QS-05 (replay equivalence).
    let certified = certify_from_trace(&trace).expect("trace must verify");
    let recert_fingerprint = certified.certificate().content_fingerprint();
    println!("  verify:   replayed content_fingerprint = {recert_fingerprint:?}");

    assert_eq!(
        recert_fingerprint, mint_fingerprint,
        "QS-05 replay equivalence broken"
    );
    println!("\nOK — verifier re-derived the bit-identical certificate without hashing.");
}
