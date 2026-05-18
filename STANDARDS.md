# Authoritative source references

UOR-ADDR's realizations each cite the authoritative source for the
standard the realization conforms to. This document is the single
index; the individual modules carry the same citation inline (the
module-level docstring of each realization).

## Common architectural layer

| Concern | Authoritative source |
|---|---|
| UOR-ADDR architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| UOR-Framework wiki (normative substrate) | <https://github.com/UOR-Foundation/UOR-Framework/wiki> |
| ADR-001 (typed-iso surface) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-001> |
| ADR-017 (canonical UOR-address mapping) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-017> |
| ADR-020 (`PrismModel<H, B, A, R, C>`) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-020> |
| ADR-023 (typed-iso input shape) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-023> |
| ADR-031 (standard-library Layer-3 sub-crate) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-031> |
| ADR-035 (canonical k-invariants branch) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-035> |
| ADR-036 (`ResolverCategory` enumeration) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-036> |
| ADR-037 (`HostBounds` capacity profile) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-037> |
| ADR-046 (resolver-body discipline) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-046> |
| ADR-047 (σ-Projection Hardening Principle) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-047> |
| ADR-048 (`TypedCommitment` cost-model surface) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-048> |
| ADR-054 (fold-fusion principle) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-054> |
| ADR-057 (bounded recursive structural typing) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-057> |
| TC-05 (replay round-trip) | <https://github.com/UOR-Foundation/UOR-Framework/wiki/TC-05> |
| FIPS 180-4 (SHA-256) | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf> |

## JSON realization (`uor_addr::json`)

| Concern | Authoritative source |
|---|---|
| JSON syntax | RFC 8259 — <https://datatracker.ietf.org/doc/rfc8259/> |
| Canonical form (JCS) | RFC 8785 — <https://datatracker.ietf.org/doc/rfc8785/> |
| Unicode normalization (NFC) | UAX #15 — <https://www.unicode.org/reports/tr15/> |
| ECMA-262 numeric serialization | <https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.2.3> |
| `mcp.uor.foundation/tools/encode_address` reference baseline | <https://mcp.uor.foundation/tools/encode_address> |

Conformance corpus: 12 fixtures from the
`mcp.uor.foundation/tools/encode_address` baseline plus an 8-fixture
Maura Clark reference baseline plus the JCS-RFC8785 published test
vectors. See [crates/uor-addr/tests/byte_identity.rs](crates/uor-addr/tests/byte_identity.rs),
[crates/uor-addr/tests/conformance.rs](crates/uor-addr/tests/conformance.rs),
[crates/uor-addr/tests/cross_validation.rs](crates/uor-addr/tests/cross_validation.rs).

## S-expression realization (`uor_addr::sexp`)

| Concern | Authoritative source |
|---|---|
| Canonical S-expressions (Rivest, 1997) | <https://people.csail.mit.edu/rivest/Sexp.txt> |
| I-D form (draft-rivest-sexp-00) | <https://datatracker.ietf.org/doc/html/draft-rivest-sexp-00> |
| RFC 2693 §3 ("Canonical S-Expressions") | <https://datatracker.ietf.org/doc/html/rfc2693#section-3> |
| SPKI test vectors (RFC 2693 §11) | <https://datatracker.ietf.org/doc/html/rfc2693#section-11> |

Conformance corpus: [crates/uor-addr/tests/sexp_conformance.rs](crates/uor-addr/tests/sexp_conformance.rs)
pins the Rivest §4.2/§4.3 canonical-form rules — flat-list form for
proper lists, `<length>:<bytes>` for atoms, `()` for the empty list,
whitespace-invariance under token-list sugar, idempotence on canonical
input — plus the typed-distinction theorem from ARCHITECTURE.md's V&V
framework over atom/list/nil cases.

## Storage cost-model variant (`uor_addr::variant::storage`)

| Concern | Authoritative source |
|---|---|
| ADR-048 typed-commitment surface | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-048> |
| ADR-047 U6 bandwidth-additivity | <https://github.com/UOR-Foundation/UOR-Framework/wiki/ADR-047> |
| QS-06 storage-tier admission exemplar | <https://github.com/UOR-Foundation/UOR-Framework/wiki/QS-06> |

Conformance corpus: [crates/uor-addr/tests/variant_storage.rs](crates/uor-addr/tests/variant_storage.rs)
pins the threshold-predicate evaluation, the 1-bit bandwidth measure
(50% accept_prob ↔ 1-bit bandwidth per ADR-048), the
`TypedCommitment` trait conformance, the `PrismModel` declaration
shape with a non-default `C`.

## Deferred realizations

Per ADR-031's demand-driven clause, the following format-specific
realizations and schema-pinned descendants land as additional modules
when their reference baselines are ready for V&V instantiation:

- `uor-addr-xml` — XML under W3C
  [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) or
  [XML-C14N2](https://www.w3.org/TR/xml-c14n2/).
- `uor-addr-asn1` — ASN.1 under
  [ITU-T X.690 DER](https://www.itu.int/rec/T-REC-X.690).
- `uor-addr-ring` — ring elements under UOR-Framework
  Amendment 43 §2's `Element::canonical_bytes`.
- `uor-addr-codemodule` — code-module AST under a
  format-specific canonical AST serialization.
- `uor-addr-photo`, `uor-addr-document`, `uor-addr-codemodule-signed`
  — schema-pinned descendants per ADR-007 + ADR-030 + ADR-052.
- `uor-addr-signed` — signature-required-on-emission variant pending
  publication of a signature `ObservablePredicate` in
  `prism::pipeline`.
