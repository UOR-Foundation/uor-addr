/-!
# GGUF typed input + canonical commitment byte form.

The realization reduces a GGUF v3 file to a fixed-width two-level
commitment (see `crates/uor-addr/src/gguf/value.rs`): a header followed
by the streamed `metadata_root` and `tensor_root` digests. Modelled here
as the commitment byte sequence.
-/
namespace UorAddr.Gguf

/-- The canonical commitment the ψ-pipeline hashes — a byte sequence. -/
abbrev Commitment := List UInt8

/-- A 32-byte streamed section digest (metadata_root / tensor_root). -/
abbrev SectionRoot := Fin 32 → UInt8

end UorAddr.Gguf
