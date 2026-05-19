# @uor-foundation/uor-addr

JavaScript / TypeScript bindings for [`uor-addr`](https://github.com/UOR-Foundation/uor-addr) — typed content-addressing producing deterministic `sha256:<64hex>` κ-labels from JSON, S-expressions, XML, ASN.1 DER, schema.org, in-toto, and more.

Wraps the [`uor-addr-wasm`](https://github.com/UOR-Foundation/uor-addr/tree/main/crates/uor-addr-wasm) WASM Component Model artifact via [`jco`](https://github.com/bytecodealliance/jco). The produced κ-label is **byte-for-byte identical** to the Rust crate's output.

## Install

```bash
npm install @uor-foundation/uor-addr
```

Requires Node 20+ (uses the WASI Preview 2 + Component Model bindings jco emits).

## Quickstart

```typescript
import { kappa } from "@uor-foundation/uor-addr";

const label = kappa.jsonAddress(new TextEncoder().encode('{"foo":"bar"}'));
console.log(label);
// sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b
```

## API

Nine `*-address` functions, one per realization. Each takes a `Uint8Array` and returns a 71-byte ASCII string of the form `sha256:<64-lowercase-hex>`. Failures throw with a wasm-runtime error carrying the realization's `address-error` variant (`invalid-input` / `too-large` / `pipeline-failure`).

| Function | Realization | Imported spec |
|---|---|---|
| `kappa.jsonAddress` | JSON | RFC 8259 + RFC 8785 JCS + UAX #15 NFC |
| `kappa.sexpAddress` | S-expressions | Rivest 1997 canonical form |
| `kappa.xmlAddress` | XML | W3C XML-C14N 1.1 (subset) |
| `kappa.asn1Address` | ASN.1 | ITU-T X.690 DER |
| `kappa.ringAddress` | Ring elements | UOR-Framework Amendment 43 §2 |
| `kappa.codemoduleAddress` | Code-module AST | CCMAS |
| `kappa.schemaPhotoAddress` | schema.org/Photograph | schema.org/Photograph |
| `kappa.schemaDocumentAddress` | schema.org/Article (+ subtypes) | schema.org/Article |
| `kappa.schemaCodemoduleSignedAddress` | in-toto Statement v1 | in-toto Statement v1 |

## Determinism + canonical-form invariance

The κ-label is **deterministic** — the same input bytes always produce the same label. It is also **invariant** under each format's canonical-form rules:

```typescript
const enc = new TextEncoder();

// JSON: whitespace, key order, NFC vs NFD all collapse.
const a = kappa.jsonAddress(enc.encode('{"a":1,"b":2}'));
const b = kappa.jsonAddress(enc.encode('{ "b" : 2 , "a" : 1 }'));
console.assert(a === b);

// But it DISTINGUISHES typed values that look similar.
const intLabel = kappa.jsonAddress(enc.encode("42"));
const strLabel = kappa.jsonAddress(enc.encode('"42"'));
console.assert(intLabel !== strLabel);
```

## Byte identity with the Rust crate

The κ-label this package produces is **byte-for-byte identical** to `uor_addr::<realization>::address(input).address` from the [Rust crate](https://crates.io/crates/uor-addr). Cross-validation is pinned by the **CF-W\*** invariant class in [CONFORMANCE.md](https://github.com/UOR-Foundation/uor-addr/blob/main/CONFORMANCE.md).

## Building from source

```bash
# From the workspace root:
cargo build -p uor-addr-wasm --target wasm32-wasip2 --release

# Then in this directory:
cd bindings/npm
npm install
npm run build      # transpiles the wasm component via jco
npm test           # smoke-tests every realization
```

## License

Apache-2.0. See [LICENSE](LICENSE).
